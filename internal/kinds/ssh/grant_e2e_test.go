package ssh_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// grantBastion is a bastion that admits nothing without a live grant, with the
// ledger it reads them from.
func grantBastion(t *testing.T, extra string) (*proxy.Server, string, cssh.Signer, *targetSSH) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "access.log")
	top := fmt.Sprintf(`
access:
  ledger: %s
  max_duration: 4h
`, ledger)
	return bastionWith(t, "        require_grant: true\n"+extra, top)
}

// ask requests and approves a grant, which is the whole four-eyes round trip an
// operator goes through before touching a machine.
func ask(t *testing.T, s *proxy.Server, subject, target string, window time.Duration) *access.Grant {
	t.Helper()
	l := s.Access()
	if l == nil {
		t.Fatal("the daemon has no access ledger")
	}
	g, err := l.Request(access.Request{Subject: subject, Listener: "bastion", Target: target,
		Reason: "incident 4711", By: "carol", Expires: time.Now().Add(window)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(g.ID, "bob", "spoke to the requester"); err != nil {
		t.Fatal(err)
	}
	return g
}

// Without a grant the session never reaches a machine: authentication succeeds,
// because the key is the key, and the bastion then refuses -- which is the point
// of the arrangement. The target must see nothing at all.
func TestWithoutAGrantTheTargetIsNeverReached(t *testing.T) {
	s, addr, key, tg := grantBastion(t, "")

	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("a session opened with no grant")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the target saw %v", got)
	}
	if n := refusals(s, "no_grant"); n == 0 {
		t.Errorf("no no_grant refusal was counted: %v", s.Stats().Refusals["ssh"])
	}
}

// A request nobody has approved yet is not access. The refusal names it, so an
// operator on the phone knows they are waiting for a person rather than for a
// fix.
func TestAnUnapprovedRequestDoesNotOpenTheDoor(t *testing.T) {
	s, addr, key, tg := grantBastion(t, "")
	l := s.Access()
	if _, err := l.Request(access.Request{Subject: "alice", Listener: "bastion", Target: "hosts",
		Reason: "incident", By: "alice", Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("a session opened against a request nobody approved")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the target saw %v", got)
	}
	if n := refusals(s, "grant_pending"); n == 0 {
		t.Errorf("the refusal was not counted as pending: %v", s.Stats().Refusals["ssh"])
	}
}

// With a grant somebody else approved, the session runs -- and the ledger
// records that this grant opened it, which is the line that ties a recording to
// the approval that allowed it.
func TestAnApprovedGrantOpensTheSessionAndIsRecorded(t *testing.T) {
	s, addr, key, tg := grantBastion(t, "")
	g := ask(t, s, "alice", "hosts", time.Hour)

	sess, err := sshSession(t, addr, key)
	if err != nil {
		t.Fatalf("with a grant: %v", err)
	}
	out, err := sess.Output("uptime")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "ran uptime" {
		t.Errorf("got %q", out)
	}
	if got := tg.seen(); len(got) == 0 {
		t.Error("the target saw nothing")
	}
	v, ok := s.Access().Get(g.ID)
	if !ok || v.Uses != 1 {
		t.Errorf("the use was not recorded: %+v", v)
	}
}

// A grant naming one machine does not follow the balancer to another. Here the
// pool holds one endpoint and the grant names a different address, so there is
// nothing the session may reach.
func TestAGrantForAnotherMachineReachesNothing(t *testing.T) {
	s, addr, key, tg := grantBastion(t, "")
	ask(t, s, "alice", "10.255.255.1:22", time.Hour)

	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("a session opened against a grant for another machine")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the target saw %v", got)
	}
	if n := refusals(s, "grant_wrong_target"); n == 0 {
		t.Errorf("the refusal did not say the target was wrong: %v", s.Stats().Refusals["ssh"])
	}
}

// A grant is for one person. Somebody else's approved window is not a door.
func TestAnotherPersonsGrantIsNotYours(t *testing.T) {
	s, addr, key, _ := grantBastion(t, "")
	ask(t, s, "dave", "hosts", time.Hour)
	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("alice used dave's grant")
	}
}

// The window ends the session that is running, not only the next one somebody
// opens. Without that, a four-hour grant used at the last minute is a session
// that lasts as long as the operator likes.
func TestTheWindowClosingEndsALiveSession(t *testing.T) {
	s, addr, key, _ := grantBastion(t, "")
	ask(t, s, "alice", "hosts", 2*time.Second)

	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("with a grant: %v", err)
	}
	if _, err := sess.Output("uptime"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Error("the session outlived its window")
	}
	// And a fresh session is refused, with the reason saying the window
	// closed rather than that there was never a grant.
	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("a session opened after the window closed")
	}
	if n := refusals(s, "grant_expired"); n == 0 {
		t.Errorf("no expiry refusal was counted: %v", s.Stats().Refusals["ssh"])
	}
}

// Revoking ends it too, which is the control that matters when a laptop is
// stolen in the middle of a change window.
func TestRevokingAGrantRefusesTheNextSession(t *testing.T) {
	s, addr, key, _ := grantBastion(t, "")
	g := ask(t, s, "alice", "hosts", time.Hour)
	if _, err := sshSession(t, addr, key); err != nil {
		t.Fatalf("with a grant: %v", err)
	}
	if _, err := s.Access().Revoke(g.ID, "dave", "laptop stolen"); err != nil {
		t.Fatal(err)
	}
	if _, err := sshSession(t, addr, key); err == nil {
		t.Error("a session opened after the grant was revoked")
	}
	if n := refusals(s, "grant_revoked"); n == 0 {
		t.Errorf("no revocation refusal was counted: %v", s.Stats().Refusals["ssh"])
	}
}

// A shadowed listener records what it would have refused and carries on, which
// is how an estate turns this on without locking its operators out on the first
// evening.
func TestAShadowedListenerRecordsWhatItWouldHaveRefused(t *testing.T) {
	s, addr, key, tg := grantBastion(t, "      policy: {mode: shadow}")
	sess, err := sshSession(t, addr, key)
	if err != nil {
		t.Fatalf("a shadowed listener refused: %v", err)
	}
	if _, err := sess.Output("uptime"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := tg.seen(); len(got) == 0 {
		t.Error("the target saw nothing, so the session was refused after all")
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Reason == "no_grant" {
			found = true
		}
	}
	if !found {
		t.Errorf("the shadow ledger does not name the refusal: %+v", s.Shadow().Report())
	}
}

// sshSession dials and opens a session, which is where a refused connection
// shows up: the handshake itself succeeds, because the key was right.
func sshSession(t *testing.T, addr string, signer cssh.Signer) (*cssh.Session, error) {
	t.Helper()
	c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User:            "alice",
		Auth:            []cssh.AuthMethod{cssh.PublicKeys(signer)},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close() })
	sess, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess, nil
}

// refusals counts one reason in the ssh listener's refusal counters.
func refusals(s *proxy.Server, reason string) uint64 {
	return s.Stats().Refusals["ssh"][reason]
}

// A grant that names one machine pins the dial to it. This is the case the
// single-endpoint tests above cannot reach: with two machines behind the
// listener, the balancer is free to offer either, and the grant has to decide.
// Otherwise "alice may reach db-2 to restart a service" would be access to
// whichever machine the pool felt like.
func TestAGrantForOneMachinePinsTheDial(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, clientSigner, clientAuthorized := sshKey(t, dir, "client")
	_, aHostKey, _ := sshKey(t, dir, "a_host")
	_, bHostKey, _ := sshKey(t, dir, "b_host")

	a := startTargetSSH(t, aHostKey)
	b := startTargetSSH(t, bHostKey)

	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(clientAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	lines := fmt.Sprintf("%s %s\n%s %s\n",
		a.addr(), strings.TrimSpace(string(cssh.MarshalAuthorizedKey(aHostKey.PublicKey()))),
		b.addr(), strings.TrimSpace(string(cssh.MarshalAuthorizedKey(bHostKey.PublicKey()))))
	if err := os.WriteFile(known, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(dir, "access.log")

	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        require_grant: true
        host_keys: [%s]
        authorized_keys: %s
        upstream_key_file: %s
        upstream_known_hosts: %s
        upstream_user: operator
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: %s}, {address: %s}]
access:
  ledger: %s
`, hostKeyPath, authorized, upKeyPath, known, a.addr(), b.addr(), ledger))

	// The grant names the second machine, and the balancer is round robin, so
	// without the pin the first session would land on the first machine.
	ask(t, s, "alice", b.addr(), time.Hour)
	sess, err := sshSession(t, s.Addrs()["bastion"], clientSigner)
	if err != nil {
		t.Fatalf("with a grant for %s: %v", b.addr(), err)
	}
	if _, err := sess.Output("uptime"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := b.seen(); len(got) == 0 {
		t.Errorf("the granted machine saw nothing")
	}
	if got := a.seen(); len(got) != 0 {
		t.Errorf("the machine the grant did not name saw %v", got)
	}
}

// The session's access log line names the grant it was opened under. Without it
// a reviewer holding a recording has to guess which window produced it, and the
// tie between the two records -- the ledger's use naming the session, the log
// line naming the grant -- only works in one direction.
func TestTheAccessLogLineNamesTheGrant(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, clientSigner, clientAuthorized := sshKey(t, dir, "client")
	_, targetHostKey, _ := sshKey(t, dir, "target_host")
	tg := startTargetSSH(t, targetHostKey)

	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(clientAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("%s %s\n", tg.addr(),
		strings.TrimSpace(string(cssh.MarshalAuthorizedKey(targetHostKey.PublicKey()))))
	if err := os.WriteFile(known, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	// proxytest discards the logs, so this one builds the server itself with
	// the streams open on files: the claim is about what is written.
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        require_grant: true
        host_keys: [%s]
        authorized_keys: %s
        upstream_key_file: %s
        upstream_known_hosts: %s
        upstream_user: operator
logging:
  directory: %s
  access: {enabled: true}
upstreams:
  - name: hosts
    endpoints: [{address: %s}]
access:
  ledger: %s
`, hostKeyPath, authorized, upKeyPath, known, logs, tg.addr(), filepath.Join(dir, "access.log"))))
	if err != nil {
		t.Fatal(err)
	}
	streams, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatal(err)
	}
	s, err := proxy.New(cfg, streams)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		streams.Close()
	})

	g := ask(t, s, "alice", "hosts", time.Hour)
	c := dialBastion(t, s.Addrs()["bastion"], clientSigner)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("with a grant: %v", err)
	}
	if _, err := sess.Output("uptime"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	// The line is written when the *connection* ends, which is the moment
	// the gateway knows what the session did.
	_ = c.Close()

	// Waited for rather than assumed: the write happens on another
	// goroutine.
	deadline := time.Now().Add(10 * time.Second)
	for {
		found := false
		if entries, err := os.ReadDir(logs); err == nil {
			for _, e := range entries {
				raw, err := os.ReadFile(filepath.Join(logs, e.Name()))
				if err == nil && strings.Contains(string(raw), g.ID) {
					found = true
				}
			}
		}
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no access log line names the grant %s", g.ID)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
