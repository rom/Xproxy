package imap

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The bounds around a session rather than the policy inside it, and where a
// refusal is written down.
//
// IMAP sessions are long-lived and mostly idle: a mail client connects in the
// morning, sits in IDLE and sends a handful of commands a day. That shape is
// what makes these bounds the interesting ones -- every one of them is about a
// connection that is *not* doing anything, which is also what a session
// somebody left open behind a compromised client looks like.

// relayWith is relay() with a block of its own beside the imap section and
// another at the top of the file, for the listener-level and estate-level
// settings the imap section does not carry.
func relayWith(t *testing.T, section, listener, top, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: imap
%s
      imap:
        upstream: servers
%s
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`, listener, section, top, serverAddr))
	return s, proxytest.Addr(t, s, "mail")
}

// awaitRefusal waits for a reason to be counted, which is how a refusal that
// says nothing to the client is observed.
func awaitRefusal(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["imap"][reason] > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not counted: %v", reason, s.Stats().Refusals["imap"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A line longer than the bound ends the connection. There is nothing honest
// to do with the rest of it: the reader is at an offset inside a command it
// refused to read, so everything after it would be read as a command of its
// own -- which is the shape of a command smuggled behind a long argument.
func TestALineOverTheBoundEndsTheConnection(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS+"        max_line_bytes: 512\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob " + strings.Repeat("x", 900))
	// The BAD is untagged, because the tag was in the part that was not read.
	if l := c.line(); !strings.Contains(l, "BAD") {
		t.Errorf("the answer to a long line: %q", l)
	}
	awaitRefusal(t, s, "line_too_long")
	if _, err := c.br.ReadString('\n'); err == nil {
		t.Error("the connection was left open after a line it would not read")
	}
}

// A line that is not a command is refused with the reason, and in enforcing
// mode the connection goes on: a mail client that sent one malformed command
// is a client with a bug, not a session to end.
func TestALineThatIsNotACommandIsRefusedAndTheSessionGoesOn(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	// A tag with no command after it: there is nothing to decide about, and
	// a relay that guessed would be guessing on the client's behalf.
	c.send("a1")
	if l := c.line(); !strings.Contains(l, "BAD") {
		t.Errorf("the answer to a malformed command: %q", l)
	}
	awaitRefusal(t, s, "malformed_command")
	// And the session is still in step.
	c.send("a1 LOGIN bob secret")
	last := c.until("a1")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Errorf("the command after the malformed one: %q", answer)
	}
}

// The commands-per-session bound, which is what a session being used as a
// search engine over somebody's mail looks like from outside: the commands
// are each allowed and there are thousands of them.
func TestTheCommandsPerSessionBoundEndsTheSession(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS+"        max_commands: 2\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 SELECT INBOX")
	c.until("a2")
	c.send("a3 NOOP")
	awaitRefusal(t, s, "too_many_commands")
	if _, err := c.br.ReadString('\n'); err == nil {
		t.Error("the session went on past its command bound")
	}
}

// A session that says nothing is ended, and the end is the session's own
// lifetime where that comes first. The lifetime is the bound that matters: a
// client in IDLE says nothing on purpose, so the silence bound alone would let
// a session live for as long as somebody kept it open.
func TestASessionIsBoundedByItsSilenceAndByItsAge(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+`        idle_timeout: 30s
        session_timeout: 1s
`, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	// Nothing further. The silence bound is thirty seconds and the session's
	// lifetime is one, so what ends this is the lifetime -- which is the
	// clamp being tested: the read deadline is the earlier of the two.
	_ = c.c.SetReadDeadline(time.Now().Add(20 * time.Second))
	start := time.Now()
	if _, err := c.br.ReadString('\n'); err == nil {
		t.Error("a silent session was held open")
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("the session was held %v, past its one-second lifetime", took)
	}
}

// The connection and session bounds, which are the listener's rather than one
// client's: a relay that let them grow would answer "how many mailboxes may be
// open through here" with whoever asked for the most.
func TestTheListenerBoundsRefuseRatherThanGrow(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS+"        max_sessions: 1\n        max_sessions_per_client: 1\n", srv.addr())
	first := dial(t, addr)
	first.line()
	first.send("a1 LOGIN bob secret")
	first.until("a1")

	second := dial(t, addr)
	if _, err := second.br.ReadString('\n'); err == nil {
		t.Error("a second session past the bound got a greeting")
	}
	awaitRefusal(t, s, "too_many_sessions")
}

// The per-client connection rate, which bounds how fast one address may open
// sessions rather than how many it may hold. A credential-stuffing run against
// a mail server is a sequence of short sessions, so the bound that catches it
// is on the rate and not on the count.
func TestTheConnectionRateIsBoundedPerClient(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS+"        rate_limit: 1\n        rate_burst: 1\n", srv.addr())
	first := dial(t, addr)
	first.line()
	for i := range 4 {
		c := dial(t, addr)
		if _, err := c.br.ReadString('\n'); err != nil {
			break
		}
		if i == 3 {
			t.Error("four sessions in a row on a burst of one")
		}
	}
	awaitRefusal(t, s, "rate_limited")
}

// Where a refusal goes besides the client's answer: the ban ladder hears
// about it before alert_on_deny can silence the record, because turning the
// log down is not a decision to stop responding. A failed login is observed
// under its own reason, since a wrong password is not a policy refusal.
func TestARefusalReachesTheBanLadderWithTheAlertsOff(t *testing.T) {
	// A ban state file each: the two listeners below are two processes'
	// worth of state as far as the ban list is concerned, and it holds a
	// lock on the file it owns.
	bans := func() string {
		return "bans:\n  action: reject\n  state_file: " +
			filepath.Join(t.TempDir(), "bans.state")
	}

	// A policy refusal with the record turned down: counted, and the client
	// is still told no.
	srv := startServer(t, &fakeServer{})
	s, addr := relayWith(t, noTLS+"        alert_on_deny: false\n        read_only: true\n",
		"", bans(), srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 SELECT INBOX")
	c.until("a2")
	c.send("a3 STORE 1 +FLAGS (\\Deleted)")
	last := c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "NO") {
		t.Errorf("a write on a read-only listener: %q", answer)
	}
	awaitRefusal(t, s, "read_only")

	// And a wrong password, which is observed under a reason of its own: a
	// failed login is not a policy refusal, and a ban ladder that counted
	// them together would ban the account that mistyped alongside the one
	// being guessed at.
	refuser := startServer(t, &fakeServer{answers: map[string]string{"LOGIN": "NO"}})
	s2, addr2 := relayWith(t, noTLS+"        alert_on_deny: false\n", "", bans(), refuser.addr())
	c2 := dial(t, addr2)
	c2.line()
	c2.send("b1 LOGIN bob wrong")
	c2.until("b1")
	if got := s2.Stats().IMAPAuthFailures; got != 1 {
		t.Errorf("imap_auth_failures is %d, want 1", got)
	}
}

// Shadow mode: the refusal is recorded and the command is carried, which is
// how a mailbox or command list is tried in front of real mail before it
// starts refusing somebody's client. The hard refusals are not shadowed, and
// those have their own tests.
func TestInShadowModeTheRefusalIsRecordedAndTheCommandCarried(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relayWith(t, noTLS+"        deny_commands: [SEARCH]\n",
		"      policy: {mode: shadow}", "", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 SELECT INBOX")
	c.until("a2")
	c.send("a3 SEARCH ALL")
	last := c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("shadow mode refused the command: %q", answer)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if len(s.Stats().WouldRefusals["imap"]) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the would-be refusal was not recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rep := s.Shadow().Report()
	if len(rep) == 0 {
		t.Fatal("the shadow report is empty")
	}
	for _, e := range rep {
		if e.Kind != "imap" || e.Listener != "mail" {
			t.Errorf("the shadow report: %+v", e)
		}
	}
	// And the server saw it, which is the half the report cannot say.
	var searched bool
	for _, l := range srv.waitSaw(t, 3) {
		if strings.Contains(strings.ToUpper(l), "SEARCH") {
			searched = true
		}
	}
	if !searched {
		t.Errorf("the carried command did not reach the server: %v", srv.saw())
	}
}

// What stops the listener being built. Each is a configuration whose failure
// an operator would otherwise meet as traffic: an upgrade this relay
// terminates itself with no certificate to terminate it with, and a trust
// store for the server that is not one.
func TestASectionThatCannotBeServedIsRefusedWhenTheListenerIsBuilt(t *testing.T) {
	notACert := filepath.Join(t.TempDir(), "not-a-certificate.pem")
	if err := os.WriteFile(notACert, []byte("this is not PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		c          config.IMAPListener
	}{
		{"starttls with no certificate", "starttls needs a tls section",
			config.IMAPListener{Upstream: "u", TLSMode: "starttls"}},
		{"a trust store that is not one", "upstream_tls",
			config.IMAPListener{Upstream: "u", UpstreamTLSMode: "require",
				UpstreamTLS: &config.UpstreamTLS{CAFile: notACert}}},
		{"a policy that will not compile", "allow_clients",
			config.IMAPListener{Upstream: "u", AllowClients: []string{"not-a-network"}}},
	} {
		_, err := newServer(nil, config.Listener{Name: "mail", IMAP: &tc.c}, nil, nil)
		if err == nil {
			t.Errorf("%s: built", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say what was wrong", tc.name, err)
		}
	}
	// The transport a listener serves is the one it was told to serve, and
	// where it was told nothing it is read off the certificate.
	for _, tc := range []struct {
		mode, want string
		tlsCfg     *tls.Config
	}{
		{"implicit", "implicit", nil},
		{"none", "none", nil},
		{"", "implicit", &tls.Config{MinVersion: tls.VersionTLS12}},
		{"", "none", nil},
		{"nonsense", "implicit", &tls.Config{MinVersion: tls.VersionTLS12}},
	} {
		got := tlsModeOf(&config.IMAPListener{TLSMode: tc.mode}, tc.tlsCfg)
		if got != tc.want {
			t.Errorf("tls_mode %q with a certificate=%v read as %q, want %q",
				tc.mode, tc.tlsCfg != nil, got, tc.want)
		}
	}
}
