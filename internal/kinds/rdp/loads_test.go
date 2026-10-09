package rdp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/rdp"
)

// What this listener settles before it serves anything, and what its
// accept loop and shutdown do. None of it is reachable through a real
// socket: a listener does not fail transiently on demand, and the
// secrets below are read once at start, so a mistake in one of them has
// to be refused there or it is never refused at all.

// engine is a server to hand the kind as its host. The listeners are
// never started -- nothing here serves anything -- but the kind reads
// the process's secret resolver, access ledger and logs while it is
// being built, so it needs a real one.
func engine(t *testing.T) proxy.Host { return engineWith(t, "") }

// engineWith is engine with upstreams of its own, for the parts of a
// session that need a pool rather than a listener.
func engineWith(t *testing.T, upstreams string) proxy.Host {
	t.Helper()
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
` + upstreams))
	if err != nil {
		t.Fatal(err)
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// secret writes a password file with the mode a secret has to have.
func secret(t *testing.T, name, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheSecretsAndListsAreReadWhenTheListenerIsBuilt(t *testing.T) {
	host := engine(t)
	good := secret(t, "pw", "desktop-secret\n", 0o600)
	open := secret(t, "open", "desktop-secret\n", 0o644)
	missing := filepath.Join(t.TempDir(), "nothing")

	for _, c := range []struct {
		name string
		v    config.RDPListener
		want string
	}{
		{
			name: "an allow_clients entry that is not a prefix",
			v:    config.RDPListener{AllowClients: []string{"192.0.2.1"}},
			want: "allow_clients",
		},
		{
			name: "an upstream password file that is not there",
			v:    config.RDPListener{UpstreamPasswordFile: missing},
			want: "upstream_password_file",
		},
		{
			// The gateway's credential for every desktop behind it, in
			// a file anybody on the host can read.
			name: "an upstream password file anybody can read",
			v:    config.RDPListener{UpstreamPasswordFile: open},
			want: "readable by anyone else",
		},
		{
			name: "an upstream password file that is a directory",
			v:    config.RDPListener{UpstreamPasswordFile: t.TempDir()},
			want: "upstream_password_file",
		},
		{
			name: "an upstream CA file that is not there",
			v: config.RDPListener{
				UpstreamSecurity: "tls", UpstreamTLS: &config.UpstreamTLS{CAFile: missing},
			},
			want: "upstream_tls",
		},
		{
			name: "an MFA file that is not there",
			v:    config.RDPListener{MFA: &config.MFAPolicy{File: missing}},
			want: "mfa",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := c.v
			_, err := newServer(host, config.Listener{Name: "desks", RDP: &v}, nil, nil)
			if err == nil {
				t.Fatalf("the listener was built with %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, which does not name %q", err, c.want)
			}
		})
	}

	// And what a working listener made of its lists: the protocols it
	// will offer, the one it will use, the channels and devices it will
	// allow, and the key the legacy protocol needs. A name it does not
	// know is left out rather than taken for something else.
	t.Run("what a working listener parsed", func(t *testing.T) {
		v := config.RDPListener{
			UpstreamPasswordFile: good,
			Security:             []string{"TLS", " rdp ", "nonsense"},
			UpstreamSecurity:     "tls",
			Channels:             &config.RDPChannelPolicy{Allow: []string{"RDPDR", "cliprdr"}},
			Devices:              &config.RDPDevicePolicy{Allow: []string{"printer", "nonsense"}},
			AllowClients:         []string{"192.0.2.0/24"},
		}
		srv, err := newServer(host, config.Listener{Name: "desks", RDP: &v}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if srv.offered&protocolBit(rdp.ProtocolSSL) == 0 || !srv.offersLegacy() {
			t.Errorf("security became %#x", srv.offered)
		}
		if srv.upstreamProtocol != rdp.ProtocolSSL {
			t.Errorf("upstream_security became %#x", srv.upstreamProtocol)
		}
		if !srv.channels["rdpdr"] || !srv.channels["cliprdr"] {
			t.Errorf("the channel list became %v", srv.channels)
		}
		if len(srv.devices) != 1 {
			t.Errorf("the device list became %v; a name this gateway cannot police is not one", srv.devices)
		}
		if len(srv.allow) != 1 {
			t.Errorf("allow_clients became %v", srv.allow)
		}
		if srv.upPassword != "desktop-secret" {
			t.Errorf("the password read as %q; the newline is not part of it", srv.upPassword)
		}
		// Offering the legacy protocol means being able to complete
		// it, which needs a key of this gateway's own.
		if srv.legacyKey == nil {
			t.Error("a listener offering the legacy protocol has no key to complete it with")
		}
	})
}

// closedSocket is the error a listener gives after its socket was
// closed. The loop recognises nothing about it beyond that it is an
// error, so any will do, but the shape is the real one.
func closedSocket() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: errors.New("use of closed network connection")}
}

// scriptedAccepts answers each Accept from a script and then reports
// its socket closed, so a loop driven by it always ends.
type scriptedAccepts struct {
	mu    sync.Mutex
	next  []acceptResult
	calls int
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func (l *scriptedAccepts) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if len(l.next) == 0 {
		return nil, closedSocket()
	}
	r := l.next[0]
	l.next = l.next[1:]
	return r.conn, r.err
}

func (l *scriptedAccepts) Close() error { return nil }
func (l *scriptedAccepts) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3389}
}

func (l *scriptedAccepts) seen() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// A connection the listener cannot serve -- it is full, or it is
// shutting down -- is closed rather than left open and unattended, and
// the loop ends when the socket does.
func TestTheAcceptLoopDropsWhatItCannotServeAndEndsWithItsSocket(t *testing.T) {
	full, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	ln := &scriptedAccepts{next: []acceptResult{{conn: full}, {err: closedSocket()}}}
	srv := &server{
		engine: engine(t),
		cfg:    config.Listener{Name: "desks"},
		v:      &config.RDPListener{MaxConnections: 0},
		ln:     ln,
		cons:   map[net.Conn]struct{}{},
	}
	finished := make(chan struct{})
	go func() { srv.serve(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the accept loop did not return when its socket was closed")
	}
	if n := ln.seen(); n != 2 {
		t.Errorf("the loop called Accept %d times, want both of the script", n)
	}
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Error("a connection the listener would not serve was left open")
	}

	// A listener that is shutting down refuses the same way, for a
	// different reason: a session started now is one nothing waits for.
	srv.sessions.Close()
	if srv.admit(full) {
		t.Error("a connection was admitted by a listener that is shutting down")
	}
}

// A shutdown waits for the sessions it has, and closes the ones still
// running when the grace runs out. A shutdown that waited again would
// hang the process on one session that will not end.
func TestTheSessionsStillRunningWhenTheGraceEndsAreClosed(t *testing.T) {
	srv := &server{
		engine: engine(t),
		cfg:    config.Listener{Name: "desks"},
		v:      &config.RDPListener{MaxConnections: 10},
		cons:   map[net.Conn]struct{}{},
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	if !srv.admit(client) {
		t.Fatal("a connection was not admitted by a serving listener")
	}
	var reading sync.WaitGroup
	reading.Add(1)
	go func() {
		defer srv.sessions.Leave()
		defer srv.untrack(client)
		reading.Done()
		_, _ = client.Read(make([]byte, 1))
	}()
	reading.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { srv.shutdown(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the shutdown did not return after the grace ran out")
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("a session still running at the end of the grace was left open")
	}
}

// The door: who may open a connection at all, whether a refusal is
// recorded or enforced, and whether it is worth a security event.
func TestTheDoorAndTheLedger(t *testing.T) {
	host := engine(t)
	inside := netip.MustParseAddr("192.0.2.9")
	outside := netip.MustParseAddr("198.51.100.4")

	t.Run("an empty allow list admits everybody", func(t *testing.T) {
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.RDPListener{}}
		if !srv.clientAllowed(outside) {
			t.Error("a listener with no allow_clients refused a client")
		}
	})

	t.Run("and a list admits only what it names", func(t *testing.T) {
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.RDPListener{},
			allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
		if !srv.clientAllowed(inside) {
			t.Error("a client inside allow_clients was refused")
		}
		if srv.clientAllowed(outside) {
			t.Error("a client outside allow_clients was admitted")
		}
	})

	t.Run("enforcing, a refusal is a refusal", func(t *testing.T) {
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.RDPListener{}}
		if srv.shadowed(outside, "client_refused", "") {
			t.Error("a listener that is not shadowing recorded instead of refusing")
		}
	})

	t.Run("shadowing, it is recorded and not enforced", func(t *testing.T) {
		srv := &server{engine: host, v: &config.RDPListener{},
			cfg: config.Listener{Name: "desks", Policy: &config.ListenerPolicy{Mode: "shadow"}}}
		before := host.Counters().WouldRefusalCounts()["rdp"]["client_refused"]
		if !srv.shadowed(outside, "client_refused", "198.51.100.4") {
			t.Fatal("a shadowing listener enforced a policy refusal")
		}
		if got := host.Counters().WouldRefusalCounts()["rdp"]["client_refused"]; got != before+1 {
			t.Errorf("would_refuse counted %d, want %d", got, before+1)
		}
	})

	t.Run("alert_on_deny decides only the security event", func(t *testing.T) {
		no := false
		quiet := &server{engine: host, cfg: config.Listener{Name: "desks"},
			v: &config.RDPListener{AlertOnDeny: &no}}
		if quiet.alerts() {
			t.Error("alert_on_deny: false still alerts")
		}
		before := host.Counters().RefusalCounts()["rdp"]["client_refused"]
		quiet.deny(&session{t: quiet, ip: outside}, "client_refused", "198.51.100.4")
		if got := host.Counters().RefusalCounts()["rdp"]["client_refused"]; got != before+1 {
			t.Errorf("a refusal on a quiet listener counted %d, want %d", got, before+1)
		}
		loud := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.RDPListener{}}
		if !loud.alerts() {
			t.Error("a listener with no alert_on_deny does not alert")
		}
	})
}

// What a session says when there is nothing to dial. A pool that does
// not exist and an endpoint that refuses are different sentences to an
// operator reading the log, and neither may look like a session that
// worked.
func TestASessionWithNothingToDialSaysSo(t *testing.T) {
	t.Run("an upstream that does not exist", func(t *testing.T) {
		host := engine(t)
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"},
			v: &config.RDPListener{Upstream: "nowhere"}}
		se := &session{t: srv, ip: netip.MustParseAddr("192.0.2.9")}
		err := se.connect()
		if err == nil {
			t.Fatal("a session connected to an upstream that is not configured")
		}
		if !strings.Contains(err.Error(), "no pool") {
			t.Errorf("the error says %q", err)
		}
	})

	t.Run("an endpoint that refuses", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		gone := ln.Addr().String()
		_ = ln.Close()
		host := engineWith(t, `
upstreams:
  - name: desktops
    endpoints: [{address: `+gone+`}]
`)
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"},
			v: &config.RDPListener{Upstream: "desktops"}}
		se := &session{t: srv, ip: netip.MustParseAddr("192.0.2.9")}
		if err := se.connect(); err == nil {
			t.Fatal("a session connected to a port nothing is listening on")
		}
	})
}

// A factor can only be asked for where the credential carried a name,
// and the lockout is checked before the code is.
func TestAFactorNeedsANameAndIsLockedOutAfterItsFailures(t *testing.T) {
	host := engine(t)
	enrolled, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := mfa.Load(secret(t, "mfa", "ops:"+enrolled+"\n", 0o600))
	if err != nil {
		t.Fatal(err)
	}
	srv := &server{engine: host, cfg: config.Listener{Name: "desks"},
		v:        &config.RDPListener{MFA: &config.MFAPolicy{MaxFailures: 1}},
		mfaGuard: mfa.NewGuard(store, 0, mfa.Lockout{MaxFailures: 1, Window: time.Minute, Duration: time.Hour})}
	ip := netip.MustParseAddr("192.0.2.9")

	if reason := (&session{t: srv, ip: ip}).checkFactor(&rdp.ClientInfo{}); reason != "mfa_no_identity" {
		t.Errorf("a credential with no name ended %q, want mfa_no_identity", reason)
	}
	// RDP has nowhere to prompt, so the code arrives on the end of the
	// password: without one there is nothing to check.
	none := &session{t: srv, ip: ip, user: "ops"}
	if reason := none.checkFactor(&rdp.ClientInfo{Password: "desktop-secret"}); reason != "mfa_no_code" {
		t.Errorf("a password with no code ended %q, want mfa_no_code", reason)
	}
	wrong := &session{t: srv, ip: ip, user: "ops"}
	if reason := wrong.checkFactor(&rdp.ClientInfo{Password: "desktop-secret,000000"}); reason != "mfa_failed" {
		t.Fatalf("a wrong code ended %q, want mfa_failed", reason)
	}
	again := &session{t: srv, ip: ip, user: "ops"}
	if reason := again.checkFactor(&rdp.ClientInfo{Password: "desktop-secret,000000"}); reason != "mfa_locked" {
		t.Errorf("the second wrong code ended %q, want mfa_locked", reason)
	}
}

// Where the password ends and the code begins. A password may contain
// a comma, so what follows the last one is a code only if it looks
// like one -- and the rest of the password must reach the desktop
// unchanged, or the person is locked out of their own session by the
// gateway helping.
func TestACodeIsTakenOffThePasswordOnlyWhenItIsOne(t *testing.T) {
	for _, c := range []struct{ in, pass, code string }{
		{"desktop-secret,123456", "desktop-secret", "123456"},
		{"has,a,comma,654321", "has,a,comma", "654321"},
		// A recovery code is letters and digits with dashes.
		{"secret,ab12-cd34", "secret", "ab12-cd34"},
		// No comma at all.
		{"desktop-secret", "desktop-secret", ""},
		// Nothing behind the comma, something too long to be a code,
		// and something with a character a code cannot have: all of
		// them are passwords that happen to contain a comma.
		{"desktop-secret,", "desktop-secret,", ""},
		{"secret," + strings.Repeat("9", 64), "secret," + strings.Repeat("9", 64), ""},
		{"secret,12 34", "secret,12 34", ""},
	} {
		pass, code := splitCode(c.in)
		if pass != c.pass || code != c.code {
			t.Errorf("%q split to %q and %q, want %q and %q", c.in, pass, code, c.pass, c.code)
		}
	}
}

// The session identifier is what the recording and the capture are
// named by, and a session that was never registered has none rather
// than a made-up one.
func TestASessionThatWasNeverListedHasNoIdentifier(t *testing.T) {
	se := &session{t: &server{v: &config.RDPListener{}}}
	if id := se.sessionID(); id != "" {
		t.Errorf("an unlisted session answered %q", id)
	}
}
