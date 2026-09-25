package ssh_test

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// certOpts is what a test wants the certificate authority to have said.
type certOpts struct {
	principals []string
	critical   map[string]string
	extensions map[string]string
	// validFor is the window's length. Zero means an hour.
	validFor time.Duration
	// forever makes a certificate that never expires.
	forever bool
}

// certAll is what ssh-keygen puts on a certificate by default, which is
// what an ordinary one carries and what the tests vary from.
func certAll() map[string]string {
	return map[string]string{
		"permit-pty": "", "permit-port-forwarding": "", "permit-agent-forwarding": "",
		"permit-X11-forwarding": "", "permit-user-rc": "",
	}
}

// sign makes a user certificate over a key.
func sign(t *testing.T, ca cssh.Signer, key cssh.Signer, o certOpts) cssh.Signer {
	t.Helper()
	principals := o.principals
	if principals == nil {
		principals = []string{"alice"}
	}
	life := o.validFor
	if life == 0 {
		life = time.Hour
	}
	before := uint64(time.Now().Add(life).Unix()) //nolint:gosec // a future time fits
	if o.forever {
		before = cssh.CertTimeInfinity
	}
	cert := &cssh.Certificate{
		Key:             key.PublicKey(),
		Serial:          1,
		CertType:        cssh.UserCert,
		KeyId:           "alice@example",
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()), //nolint:gosec // a recent time fits
		ValidBefore:     before,
		Permissions: cssh.Permissions{
			CriticalOptions: o.critical,
			Extensions:      o.extensions,
		},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	signer, err := cssh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// certBastion is a bastion that trusts a CA. It returns the server, its
// address, a signer for a certificate the test describes, and the
// target, plus the plain client signer and the CA for the cases that
// need them.
type certHarness struct {
	s      *proxy.Server
	addr   string
	tg     *targetSSH
	ca     cssh.Signer
	client cssh.Signer
	dir    string
}

func certBastion(t *testing.T, extra string) *certHarness {
	return certBastionWith(t, func(string, cssh.Signer, cssh.Signer) string { return extra })
}

// certBastionWith builds the listener's extra lines from the keys it just
// generated, which is what the revocation cases need: the file has to
// name a key that exists before the server reads it.
func certBastionWith(t *testing.T, extra func(dir string, client, ca cssh.Signer) string) *certHarness {
	t.Helper()
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	targetHostKeyPath, targetHostSigner, _ := sshKey(t, dir, "target_host")
	_ = targetHostKeyPath
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, clientSigner, _ := sshKey(t, dir, "client")
	caPath, caSigner, caAuthorized := sshKey(t, dir, "user_ca")
	_ = caPath

	tg := startTargetSSH(t, targetHostSigner)
	caPub := filepath.Join(dir, "user_ca.pub")
	if err := os.WriteFile(caPub, []byte(caAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("%s %s", tg.addr(), strings.TrimSpace(string(cssh.MarshalAuthorizedKey(targetHostSigner.PublicKey()))))
	if err := os.WriteFile(known, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [%s]
        trusted_user_ca_keys: %s
        upstream_key_file: %s
        upstream_known_hosts: %s
        upstream_user: operator
%s
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: %s}]
`, hostKeyPath, caPub, upKeyPath, known, extra(dir, clientSigner, caSigner), tg.addr())
	s := proxytest.Start(t, yaml)
	return &certHarness{s: s, addr: s.Addrs()["bastion"], tg: tg, ca: caSigner, client: clientSigner, dir: dir}
}

// dialCert dials with a certificate signer, returning the error rather
// than failing: a refused certificate is what most of these tests are
// about.
func dialCert(addr string, signer cssh.Signer) (*cssh.Client, error) {
	return cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User:            "alice",
		Auth:            []cssh.AuthMethod{cssh.PublicKeys(signer)},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
}

// source-address is the one critical option x/crypto/ssh deliberately
// leaves to the caller, because checking it needs the client's address
// and CheckCert does not have one. A gateway that skipped it would accept
// from anywhere a certificate the CA restricted to one network, which is
// the opposite of what issuing it that way meant.
func TestACertificateRestrictedToAnotherNetworkIsRefused(t *testing.T) {
	h := certBastion(t, "")
	elsewhere := sign(t, h.ca, h.client, certOpts{
		critical:   map[string]string{"source-address": "192.0.2.0/24,198.51.100.7"},
		extensions: certAll(),
	})
	if c, err := dialCert(h.addr, elsewhere); err == nil {
		_ = c.Close()
		t.Fatal("a certificate restricted to another network was accepted")
	}
	// The same certificate naming the network this connection comes from
	// is accepted, which is the half that proves the option is read
	// rather than simply refused.
	here := sign(t, h.ca, h.client, certOpts{
		critical:   map[string]string{"source-address": "127.0.0.0/8"},
		extensions: certAll(),
	})
	c, err := dialCert(h.addr, here)
	if err != nil {
		t.Fatalf("a certificate naming this network was refused: %v", err)
	}
	_ = c.Close()
	// A list the gateway cannot read is a restriction it cannot apply,
	// and a restriction it cannot apply must not be treated as absent.
	bad := sign(t, h.ca, h.client, certOpts{
		critical:   map[string]string{"source-address": "not-a-cidr/99"},
		extensions: certAll(),
	})
	if c, err := dialCert(h.addr, bad); err == nil {
		_ = c.Close()
		t.Error("a certificate with an unreadable source-address list was accepted")
	}
}

// The extensions are permissions and their absence is a denial, which is
// how "ssh-keygen -O clear -O permit-pty" is meant to work. A gateway
// reading only its own allow_requests would hand the session everything
// the listener permits instead.
func TestACertificateGrantsOnlyWhatItCarries(t *testing.T) {
	h := certBastion(t, "        allow_channels: [session, direct-tcpip]\n        forward: [\"127.0.0.1:*\"]")
	// A certificate with nothing but a terminal.
	ptyOnly := sign(t, h.ca, h.client, certOpts{extensions: map[string]string{"permit-pty": ""}})
	c, err := dialCert(h.addr, ptyOnly)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	// A terminal is granted.
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 24, 80, cssh.TerminalModes{}); err != nil {
		t.Errorf("the certificate grants permit-pty and the terminal was refused: %v", err)
	}
	_ = sess.Close()
	// A port forward is not, although the listener allows one.
	if fc, err := c.Dial("tcp", "127.0.0.1:9"); err == nil {
		_ = fc.Close()
		t.Error("a certificate without permit-port-forwarding opened a forward")
	}
	if got := h.s.Stats().Refusals["ssh"]["cert_no_port_forwarding"]; got != 1 {
		t.Errorf("the refusal was counted %d times, want 1", got)
	}
}

// The other way round: a certificate with no permit-pty gets no
// terminal, on a listener whose own policy allows one.
func TestACertificateWithoutPermitPtyGetsNoTerminal(t *testing.T) {
	h := certBastion(t, "")
	noPTY := sign(t, h.ca, h.client, certOpts{extensions: map[string]string{"permit-port-forwarding": ""}})
	c, err := dialCert(h.addr, noPTY)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.RequestPty("xterm", 24, 80, cssh.TerminalModes{}); err == nil {
		t.Error("a certificate without permit-pty was given a terminal")
	}
	if got := h.s.Stats().Refusals["ssh"]["cert_pty_refused"]; got != 1 {
		t.Errorf("the refusal was counted %d times, want 1", got)
	}
}

// force-command fixes what the session runs, whatever the client asks
// for. OpenSSH replaces the client's command with it, and so does this:
// a certificate issued to run one thing is issued for a reason.
func TestForceCommandRunsInsteadOfWhatWasAsked(t *testing.T) {
	h := certBastion(t, "")
	forced := sign(t, h.ca, h.client, certOpts{
		critical:   map[string]string{"force-command": "/usr/bin/uptime"},
		extensions: certAll(),
	})
	c, err := dialCert(h.addr, forced)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Run("rm -rf /"); err != nil {
		t.Logf("run: %v", err) // the stand-in target's exit status is not the point
	}
	_ = sess.Close()
	var sawForced, sawAsked bool
	for _, r := range h.tg.seen() {
		if strings.Contains(r, "/usr/bin/uptime") {
			sawForced = true
		}
		if strings.Contains(r, "rm -rf /") {
			sawAsked = true
		}
	}
	if !sawForced {
		t.Errorf("the forced command did not reach the target: %v", h.tg.seen())
	}
	if sawAsked {
		t.Errorf("what the client asked for reached the target: %v", h.tg.seen())
	}
}

// A subsystem is another way to start a program on a session channel.
// It must not escape the command fixed by the certificate, even though SFTP
// is allowed by the listener's default policy.
func TestForceCommandRunsInsteadOfSubsystem(t *testing.T) {
	h := certBastion(t, "")
	forced := sign(t, h.ca, h.client, certOpts{
		critical:   map[string]string{"force-command": "/usr/bin/uptime"},
		extensions: certAll(),
	})
	c, err := dialCert(h.addr, forced)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("subsystem: %v", err)
	}
	_ = sess.Close()
	var sawForced, sawSubsystem bool
	for _, r := range h.tg.seen() {
		if strings.Contains(r, "/usr/bin/uptime") {
			sawForced = true
		}
		if r == "subsystem:sftp" {
			sawSubsystem = true
		}
	}
	if !sawForced {
		t.Errorf("the forced command did not reach the target: %v", h.tg.seen())
	}
	if sawSubsystem {
		t.Errorf("the requested subsystem reached the target: %v", h.tg.seen())
	}
}

// The point of certificates over authorized_keys is that they expire. A
// CA that issues for a year has made a credential nobody can take back
// for a year, and a bastion is entitled to say how soon.
func TestACertificateLongerThanTheListenerAcceptsIsRefused(t *testing.T) {
	h := certBastion(t, "        max_certificate_lifetime: 24h")
	for name, o := range map[string]certOpts{
		"a week":     {validFor: 7 * 24 * time.Hour, extensions: certAll()},
		"never ends": {forever: true, extensions: certAll()},
	} {
		if c, err := dialCert(h.addr, sign(t, h.ca, h.client, o)); err == nil {
			_ = c.Close()
			t.Errorf("a certificate that %s was accepted", name)
		}
	}
	// One inside the bound works.
	c, err := dialCert(h.addr, sign(t, h.ca, h.client, certOpts{validFor: time.Hour, extensions: certAll()}))
	if err != nil {
		t.Fatalf("an hour-long certificate was refused: %v", err)
	}
	_ = c.Close()
}

// A revocation is what makes a certificate revocable before it expires,
// and it has to cover the authority as well as the key: one line takes
// back a credential, or every credential an authority ever issued.
func TestRevocationOverridesTheAuthority(t *testing.T) {
	for name, pick := range map[string]func(client, ca cssh.Signer) cssh.PublicKey{
		"the certificate's own key": func(client, _ cssh.Signer) cssh.PublicKey { return client.PublicKey() },
		"the authority":             func(_, ca cssh.Signer) cssh.PublicKey { return ca.PublicKey() },
	} {
		t.Run(name, func(t *testing.T) {
			h := certBastionWith(t, func(dir string, client, ca cssh.Signer) string {
				path := filepath.Join(dir, "revoked")
				if err := os.WriteFile(path, cssh.MarshalAuthorizedKey(pick(client, ca)), 0o600); err != nil {
					t.Fatal(err)
				}
				return "        revoked_keys: " + path
			})
			good := sign(t, h.ca, h.client, certOpts{extensions: certAll()})
			if c, err := dialCert(h.addr, good); err == nil {
				_ = c.Close()
				t.Errorf("a certificate an otherwise valid CA signed was accepted although %s is revoked", name)
			}
		})
	}
	// With nothing revoked the same certificate works, which is the half
	// that proves the list is what refused it.
	h := certBastion(t, "")
	c, err := dialCert(h.addr, sign(t, h.ca, h.client, certOpts{extensions: certAll()}))
	if err != nil {
		t.Fatalf("a valid certificate was refused with no revocation list: %v", err)
	}
	_ = c.Close()
}

// A regular expression over a command line is a weak thing to hold a
// shell to: "^journalctl .*$" matches "journalctl -u x; rm -rf /" as
// happily as what it was written for. So the line is read as a shell
// would split it, and one carrying an operator is refused before any
// pattern is tried.
func TestShellOperatorsAreRefusedBeforeThePatterns(t *testing.T) {
	s, addr, signer, tg := bastion(t, "        allow_commands: [\"^journalctl .*$\", \"^uptime$\"]")
	c := dialBastion(t, addr, signer)
	for _, cmd := range []string{
		"journalctl -u x; rm -rf /",
		"journalctl -u x && rm -rf /",
		"journalctl -u x | sh",
		"journalctl -u `id`",
		"journalctl -u $(id)",
		"journalctl -u x > /etc/passwd",
		"journalctl -u x\nrm -rf /",
	} {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.Run(cmd); err == nil {
			t.Errorf("%q was allowed", cmd)
		}
		_ = sess.Close()
		for _, seen := range tg.seen() {
			if strings.Contains(seen, "rm -rf") || strings.Contains(seen, "| sh") {
				t.Fatalf("%q reached the target", seen)
			}
		}
	}
	// The command the patterns were written for still runs, which is the
	// half that proves this is not a filter on everything.
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Run("journalctl -u sshd"); err != nil {
		t.Errorf("an ordinary command was refused: %v", err)
	}
	_ = sess.Close()
	if got := s.Stats().Refusals["ssh"]["shell_syntax"]; got != 7 {
		t.Errorf("the refusals were counted %d times, want 7", got)
	}
}

// max_sessions is the listener's, which is the whole fleet's. This is the
// one per principal, so a robot looping connections cannot take the
// bastion from the people.
func TestMaxSessionsPerPrincipal(t *testing.T) {
	s, addr, signer, _ := bastion(t, "        max_sessions_per_principal: 2")
	var open []*cssh.Client
	defer func() {
		for _, c := range open {
			_ = c.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		c, err := dialCert(addr, signer)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		open = append(open, c)
	}
	// The third is refused. The refusal comes after authentication,
	// because that is when the principal is known, so the handshake
	// itself succeeds and the session does not: opening a channel on it
	// is what fails.
	third, err := dialCert(addr, signer)
	if err == nil {
		defer func() { _ = third.Close() }()
		if sess, serr := third.NewSession(); serr == nil {
			_ = sess.Close()
			t.Error("a third session opened a channel under a bound of two")
		}
	}
	waitForSSH(t, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["ssh"]["max_sessions_per_principal"] >= 1
	})
	// Closing one makes room again, so the bound is concurrency and not
	// a quota.
	_ = open[0].Close()
	open = open[1:]
	waitForSSH(t, "a slot to come free", func() bool {
		c, err := dialCert(addr, signer)
		if err != nil {
			return false
		}
		open = append(open, c)
		return true
	})
}

// A session that may forward at all can otherwise open one forward per
// descriptor the proxy has. The bound is on the forwards open at once,
// so closing one makes room.
func TestMaxForwards(t *testing.T) {
	s, addr, signer, _ := bastion(t, "        allow_channels: [session, direct-tcpip]\n        forward: [\"127.0.0.1:*\"]\n        max_forwards: 2")
	c := dialBastion(t, addr, signer)
	var open []interface{ Close() error }
	defer func() {
		for _, f := range open {
			_ = f.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		fc, err := c.Dial("tcp", "127.0.0.1:9")
		if err != nil {
			t.Fatalf("forward %d: %v", i, err)
		}
		open = append(open, fc)
	}
	if fc, err := c.Dial("tcp", "127.0.0.1:9"); err == nil {
		_ = fc.Close()
		t.Error("a third forward was opened under a bound of two")
	}
	waitForSSH(t, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["ssh"]["max_forwards"] >= 1
	})
	_ = open[0].Close()
	open = open[1:]
	waitForSSH(t, "a forward slot to come free", func() bool {
		fc, err := c.Dial("tcp", "127.0.0.1:9")
		if err != nil {
			return false
		}
		open = append(open, fc)
		return true
	})
}

// waitForSSH retries until ok holds or five seconds pass.
func waitForSSH(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ok() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %s and it did not happen", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
