package telnet_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/telnet"
	"github.com/rom/xproxy/internal/testutil"
)

// The door rather than the session: who may knock, how many may be inside at
// once, how long they may stay, and what a listener refuses to load with.
//
// On a telnet bastion these are most of the security there is. The protocol
// has no identity of its own and no confidentiality, so the client list, the
// connection bound and the session lifetime are the controls -- and each of
// them has to be in force before the equipment behind is dialled, because a
// refusal that dials first has already given somebody a session with the
// plant.

// gatewayWith is gateway() with a block of its own beside the telnet section
// and another at the top of the file: `policy:` is a listener setting and
// `bans:` is the estate's.
func gatewayWith(t *testing.T, section, listener, top string) (*proxy.Server, string, *targetTelnet) {
	t.Helper()
	tg := startTarget(t)
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
%s
      telnet:
        upstream: kit
%s
%s
logging: {access: {enabled: false}}
upstreams:
  - name: kit
    endpoints: [{address: %s}]
`, listener, section, top, tg.addr()))
	return s, s.Addrs()["legacy"], tg
}

func awaitRefused(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["telnet"][reason] > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not counted: %v", reason, s.Stats().Refusals["telnet"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A client outside the list never reaches the equipment. On this protocol the
// source address is the only thing resembling authentication there is, so the
// list is checked before the target is dialled and before anything is written
// to the client.
func TestAClientOutsideTheListIsRefusedBeforeTheKitIsDialled(t *testing.T) {
	// With a ban list configured, because the refusal reaches the ban ladder
	// before alert_on_deny can silence the record: turning the log down is
	// not a decision to stop responding.
	s, addr, tg := gatewayWith(t, "        allow_clients: [10.0.0.0/8]", "",
		"bans:\n  action: reject\n  state_file: "+
			filepath.Join(t.TempDir(), "bans.state"))
	c := dial(t, addr)
	if got := c.readUntil(""); got != "" {
		t.Errorf("a client off the list was sent %q", got)
	}
	awaitRefused(t, s, "client_refused")
	if seen := tg.seen(); len(seen) != 0 {
		t.Errorf("the equipment was dialled anyway: %q", seen)
	}
	if got := s.Stats().TelnetRejected; got == 0 {
		t.Error("the refusal was not counted as a rejection")
	}

	// And a client inside the list is served, which is the half that says the
	// list is being read rather than refusing everybody.
	s2, addr2, tg2 := gatewayWith(t, "        allow_clients: [127.0.0.0/8]", "", "")
	c2 := dial(t, addr2)
	if got := c2.readUntil("target ready"); !strings.Contains(got, "target ready") {
		t.Fatalf("a client inside the list: %q", got)
	}
	c2.write([]byte("show version\r\n"))
	if !tg2.waitSeen(t, []byte("show version")) {
		t.Errorf("the session did not reach the equipment: %q", tg2.seen())
	}
	if got := s2.Stats().Refusals["telnet"]["client_refused"]; got != 0 {
		t.Errorf("a client inside the list was refused %d times", got)
	}
}

// In shadow mode the same refusal is recorded and the session goes through,
// which is how a client list is written for an estate nobody has an inventory
// of: the report says who would have been refused, and nothing is cut off
// while it is being read.
func TestInShadowModeTheClientListRecordsAndAdmits(t *testing.T) {
	s, addr, tg := gatewayWith(t, "        allow_clients: [10.0.0.0/8]",
		"      policy: {mode: shadow}", "")
	c := dial(t, addr)
	if got := c.readUntil("target ready"); !strings.Contains(got, "target ready") {
		t.Fatalf("shadow mode refused the session: %q", got)
	}
	c.write([]byte("show version\r\n"))
	if !tg.waitSeen(t, []byte("show version")) {
		t.Errorf("the equipment did not see the session: %q", tg.seen())
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if len(s.Stats().WouldRefusals["telnet"]) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the would-be refusal was not recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rep := s.Shadow().Report()
	if len(rep) == 0 {
		t.Fatal("the shadow report is empty")
	}
	for _, e := range rep {
		if e.Kind != "telnet" || e.Listener != "legacy" || e.Reason != "client_refused" {
			t.Errorf("the shadow report: %+v", e)
		}
	}
}

// The banner, which is the one thing a bastion can say to a client before it
// has admitted it, and the session lifetime, which ends a session whatever it
// is doing. A terminal somebody walked away from is the case the lifetime
// exists for: it is not idle -- a device at the far end may be printing to it
// all day -- and nobody is at it.
func TestTheBannerIsWrittenAndTheSessionHasALifetime(t *testing.T) {
	_, addr, _ := gatewayWith(t, `        banner: "Authorised use only. Sessions are recorded."
        session_timeout: 1s`, "", "")
	c := dial(t, addr)
	if got := c.readUntil("Authorised use only"); !strings.Contains(got, "Authorised use only") {
		t.Fatalf("the banner: %q", got)
	}
	// The session ends on its own, inside the lifetime, although the target
	// is there and the client has said nothing wrong.
	_ = c.c.SetReadDeadline(time.Now().Add(15 * time.Second))
	start := time.Now()
	buf := make([]byte, 256)
	for {
		if _, err := c.c.Read(buf); err != nil {
			break
		}
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Errorf("the session was held %v, past its one-second lifetime", took)
	}
}

// The connection bound is the listener's and it refuses rather than queues: a
// bastion in front of a serial console server has a handful of real lines
// behind it, and a relay that accepted more would hold sessions that cannot
// be served while looking from outside as though they were.
func TestNoMoreSessionsThanTheBoundAllows(t *testing.T) {
	s, addr, _ := gatewayWith(t, "        max_connections: 1", "", "")
	first := dial(t, addr)
	if got := first.readUntil("target ready"); !strings.Contains(got, "target ready") {
		t.Fatalf("the first session: %q", got)
	}
	second := dial(t, addr)
	if got := second.readUntil(""); got != "" {
		t.Errorf("a session past the bound was served %q", got)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().TelnetRejected > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refused session was not counted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// What a telnet listener refuses to load with.
//
// Each of these would otherwise be a bastion running with less than the file
// asks for: a client list that failed to parse is a list that matches
// nothing, an enrolment file that is not there is a second factor nobody can
// present, and a deception section that will not compile is a decoy that
// answers as itself.
func TestWhatATelnetListenerRefusesToLoadWith(t *testing.T) {
	dir := t.TempDir()
	notAnEnrolment := filepath.Join(dir, "not-an-enrolment.json")
	if err := os.WriteFile(notAnEnrolment, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	for _, tc := range []struct{ name, section, want string }{
		{"a client list that will not parse",
			"        allow_clients: [10.0.0.1]", "allow_clients"},
		{"an enrolment file that is not one",
			"        mfa: {file: " + notAnEnrolment + "}", "mfa"},
	} {
		yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        upstream: kit
%s
logging: {access: {enabled: false}}
upstreams:
  - name: kit
    endpoints: [{address: %s}]
`, tc.section, ln.Addr().String())
		err := proxytest.StartError(t, yaml)
		if err == nil {
			t.Errorf("%s: loaded", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say which setting", tc.name, err)
		}
	}
}

// The option lists are read in order: an option named on both is denied,
// because a deny list the allow list could overrule is not a deny list. The
// options are what a telnet client uses to ask for terminal type, window size
// and -- the one that matters -- an environment the far end will trust.
func TestAnOptionOnBothListsIsDenied(t *testing.T) {
	_, addr, tg := gatewayWith(t,
		"        allow_options: [terminal-type, new-environ]\n"+
			"        deny_options: [new-environ]", "", "")
	c := dial(t, addr)
	c.readUntil("target ready")
	// WILL NEW-ENVIRON: named on both lists, so it is refused here and the
	// equipment never sees the negotiation.
	c.write([]byte{wire.IAC, wire.WILL, wire.OptNewEnviron})
	if got := c.readUntil(string([]byte{wire.IAC, wire.DONT, wire.OptNewEnviron})); !strings.Contains(got,
		string([]byte{wire.IAC, wire.DONT, wire.OptNewEnviron})) {
		t.Errorf("the answer to an option on both lists: %q", got)
	}
	// And the allowed one is carried.
	c.write([]byte{wire.IAC, wire.WILL, wire.OptTerminalType})
	if !tg.waitSeen(t, []byte{wire.IAC, wire.WILL, wire.OptTerminalType}) {
		t.Errorf("an allowed option did not reach the equipment: %q", tg.seen())
	}
}

// A listener with a certificate takes TLS from the first octet, which is the
// only way this protocol is carried over anything but a private cable: telnet
// has no upgrade and no confidentiality of its own, so the transport is
// outside it or there is none.
func TestAListenerWithACertificateTakesTLSFromTheFirstOctet(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "127.0.0.1")
	_, addr, tg := gatewayWith(t, "        allow_clients: [127.0.0.0/8]",
		fmt.Sprintf("      tls:\n        certificates: [{cert_file: %s, key_file: %s}]", cert, key), "")

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("the test CA did not read back")
	}
	tc, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("a TLS client was refused: %v", err)
	}
	defer func() { _ = tc.Close() }()
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 256)
	n, err := tc.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "target ready") {
		t.Fatalf("the greeting over TLS: %q %v", buf[:n], err)
	}
	if _, err := tc.Write([]byte("show version\r\n")); err != nil {
		t.Fatal(err)
	}
	if !tg.waitSeen(t, []byte("show version")) {
		t.Errorf("the session did not reach the equipment: %q", tg.seen())
	}

	// A client that does not speak it never reaches the equipment: the
	// handshake is the admission, so there is no plaintext session to have.
	plain := dial(t, addr)
	plain.write([]byte("show version\r\n"))
	if got := plain.readUntil("target ready"); strings.Contains(got, "target ready") {
		t.Errorf("a plaintext client was served: %q", got)
	}
}

// A shutdown closes the sessions it is holding rather than waiting for them.
//
// These sessions are interactive and open for hours, so a shutdown that waited
// would be a reload that never finished -- and the sockets have to be closed
// from the listener's own side, because what each session goroutine is waiting
// on is a read from a terminal nobody is at.
func TestAShutdownClosesTheSessionsItIsHolding(t *testing.T) {
	s, addr, _ := gatewayWith(t, "        allow_clients: [127.0.0.0/8]", "", "")
	c := dial(t, addr)
	if got := c.readUntil("target ready"); !strings.Contains(got, "target ready") {
		t.Fatalf("the session: %q", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	for {
		if _, err := c.c.Read(buf); err != nil {
			return
		}
	}
}

// A listener with no deception section reports no decoy rather than an empty
// one. The status view is what an operator reads to know which listeners are
// fabricating; a zero entry on every real listener would make it useless at
// the only moment it matters.
func TestAListenerWithNoDeceptionReportsNoDecoy(t *testing.T) {
	s, _, _ := gatewayWith(t, "        allow_clients: [127.0.0.0/8]", "", "")
	if st, ok := telnetDecoyStatus(s); ok {
		t.Errorf("a listener with no deception section reported a decoy: %+v", st)
	}
}
