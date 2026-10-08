package capture

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// files reads back what the capturer wrote, so a test asserts on the file rather
// than on a counter.
func files(t *testing.T, dir string) string {
	t.Helper()
	var all strings.Builder
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
	}
	return all.String()
}

func session(kind, listener, user, denied string) *Session {
	return &Session{
		Start:    time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
		Client:   netip.MustParseAddrPort("198.51.100.7:44321"),
		Server:   netip.MustParseAddrPort("203.0.113.9:3306"),
		Kind:     kind,
		Listener: listener,
		ID:       "sess-1",
		User:     user,
		Denied:   denied,
		ToServer: []byte("select 1"),
		ToClient: []byte("ok"),
	}
}

// A session has no host, route, method or path, so a rule selects it on the
// listener it arrived on, the protocol that listener speaks, the client, and
// whether it was refused. Those are the four things true of a session before a
// byte is read.
func TestASessionIsSelectedByListenerKindClientAndDenied(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule config.CaptureRule
		s    *Session
		want bool
	}{
		{"no rules at all takes everything", config.CaptureRule{}, session("mysql", "db", "", ""), true},
		{"by kind", config.CaptureRule{Kinds: []string{"mysql"}}, session("mysql", "db", "", ""), true},
		{"a different kind", config.CaptureRule{Kinds: []string{"postgres"}}, session("mysql", "db", "", ""), false},
		{"the kind is matched without case", config.CaptureRule{Kinds: []string{"MySQL"}}, session("mysql", "db", "", ""), true},
		{"by listener", config.CaptureRule{Listeners: []string{"db"}}, session("mysql", "db", "", ""), true},
		{"a different listener", config.CaptureRule{Listeners: []string{"plant"}}, session("mysql", "db", "", ""), false},
		{"by client network", config.CaptureRule{ClientCIDRs: []string{"198.51.100.0/24"}},
			session("mysql", "db", "", ""), true},
		{"a client outside it", config.CaptureRule{ClientCIDRs: []string{"192.0.2.0/24"}},
			session("mysql", "db", "", ""), false},
		{"denied takes a refusal", config.CaptureRule{Denied: true},
			session("mysql", "db", "", "statement_not_allowed"), true},
		{"and leaves an allowed session", config.CaptureRule{Denied: true}, session("mysql", "db", "", ""), false},
		{"a reason by name", config.CaptureRule{Reasons: []string{"statement_not_allowed"}},
			session("mysql", "db", "", "statement_not_allowed"), true},
		{"both must hold", config.CaptureRule{Kinds: []string{"mysql"}, Listeners: []string{"plant"}},
			session("mysql", "db", "", ""), false},
		// A rule written about what was asked for is a rule about HTTP. Reading
		// "no host" as "any host" would make it capture every session on the
		// estate as well as the requests somebody wrote it for.
		{"an HTTP rule does not take sessions", config.CaptureRule{Hosts: []string{"api.test"}},
			session("mysql", "db", "", ""), false},
		{"nor one about routes", config.CaptureRule{Routes: []string{"api"}}, session("mysql", "db", "", ""), false},
		{"nor one about a status", config.CaptureRule{Statuses: []int{403}}, session("mysql", "db", "", ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, tc.rule)
			cfg.Bodies = true
			cp := newTestCapturer(t, cfg)
			cp.WriteSession(tc.s)
			got := cp.Stats().Captured == 1
			if got != tc.want {
				t.Fatalf("captured = %v, want %v (stats %+v)", got, tc.want, cp.Stats())
			}
			if !tc.want {
				return
			}
			cp.Flush()
			out := files(t, cfg.Directory)
			for _, want := range []string{"select 1", "ok", "kind=mysql", "listener=db", "sess-1"} {
				if !strings.Contains(out, want) {
					t.Errorf("the capture file does not hold %q", want)
				}
			}
		})
	}
}

// The comment is what a reader has months later with no access log beside the
// file, so the protocol, the listener, the login and the refusal are all in it.
func TestTheSessionCommentNamesTheListenerAndTheLogin(t *testing.T) {
	cfg := testConfig(t)
	cfg.Bodies = true
	cp := newTestCapturer(t, cfg)
	cp.WriteSession(session("postgres", "reporting", "analyst", "read_only"))
	cp.Flush()
	out := files(t, cfg.Directory)
	for _, want := range []string{"kind=postgres", "listener=reporting", "user=analyst", "denied=read_only"} {
		if !strings.Contains(out, want) {
			t.Errorf("the comment does not hold %q:\n%s", want, printable(out))
		}
	}
}

// The tap is what a kind actually uses, and the thing it must get right is being
// usable when nothing is recording: a nil Tap does nothing rather than panicking,
// which is what lets a kind wrap its connections without a branch.
func TestANilTapIsUsable(t *testing.T) {
	var cp *Capturer
	tap := cp.Open("mysql", "db", "sess", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:1")))
	if tap != nil {
		t.Fatal("a nil capturer opened a tap")
	}
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	if got := tap.Client(client); got != client {
		t.Error("a nil tap wrapped the connection")
	}
	if got := tap.Upstream(server); got != server {
		t.Error("a nil tap wrapped the upstream")
	}
	tap.User("nobody")
	tap.Close()
}

// And when it is recording, what passed through the connection is what the file
// holds -- both directions, from the one wrapped conn.
//
// The directions are the proxy's, which is the part worth being exact about: the
// proxy *reads* the client's connection to get what the client sent, so a read is
// traffic towards the server, and it *writes* that connection to pass the server's
// answer back. Wrapping the client conn therefore records both halves, and
// wrapping the upstream one as well would double every byte.
func TestATapRecordsBothDirectionsOfTheConnection(t *testing.T) {
	cfg := testConfig(t, config.CaptureRule{Kinds: []string{"redis"}})
	cfg.Bodies = true
	cp := newTestCapturer(t, cfg)
	tap := cp.Open("redis", "cache", "sess-9", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:5555")))
	if tap == nil {
		t.Fatal("no tap for a session the rule names")
	}
	proxySide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = proxySide.Close(); _ = clientSide.Close() })
	wrapped := tap.Client(proxySide)

	// The client sends: the proxy reads it, and it is traffic to the server.
	go func() { _, _ = clientSide.Write([]byte("GET key")) }()
	buf := make([]byte, 16)
	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "GET key" {
		t.Fatalf("the proxy read %q", buf[:n])
	}
	// The server answers: the proxy writes it to the client.
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 16)
		m, _ := clientSide.Read(b)
		if string(b[:m]) != "+OK" {
			t.Errorf("the client saw %q", b[:m])
		}
	}()
	if _, err := wrapped.Write([]byte("+OK")); err != nil {
		t.Fatal(err)
	}
	<-done

	tap.User("app")
	tap.Close()
	cp.Flush()
	out := files(t, cfg.Directory)
	for _, want := range []string{"GET key", "+OK", "user=app", "listener=cache", "kind=redis"} {
		if !strings.Contains(out, want) {
			t.Errorf("the capture does not hold %q", want)
		}
	}
	// And each direction is on its own side of the conversation.
	if !strings.Contains(out, "clnt") || !strings.Contains(out, "srvr") {
		t.Error("the capture has no two-sided flow")
	}
}

// max_body bounds a session the way it bounds a body, and the file says the
// stream was cut rather than leaving a reader to think the peer stopped.
func TestASessionIsBoundedByMaxBody(t *testing.T) {
	cfg := testConfig(t)
	cfg.Bodies = true
	cfg.MaxBodyBytes = 8
	cp := newTestCapturer(t, cfg)
	tap := cp.Open("mysql", "db", "sess", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:1")))
	if tap == nil {
		t.Fatal("no tap")
	}
	proxySide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = proxySide.Close(); _ = clientSide.Close() })
	wrapped := tap.Client(proxySide)
	go func() { _, _ = clientSide.Write([]byte("0123456789abcdef")) }()
	buf := make([]byte, 16)
	for read := 0; read < 16; {
		n, err := wrapped.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		read += n
	}
	tap.Close()
	cp.Flush()
	if got := cp.Stats().Truncated; got != 1 {
		t.Errorf("truncated = %d, want 1", got)
	}
	out := files(t, cfg.Directory)
	if !strings.Contains(out, "request=truncated") {
		t.Errorf("the file does not say the stream to the server was cut:\n%s", printable(out))
	}
	if strings.Contains(out, "9abcdef") {
		t.Error("the capture kept more than max_body")
	}
}

// printable keeps a binary capture readable in a failure message.
func printable(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			r = '.'
		}
		out = append(out, r)
	}
	return string(out)
}

// A protocol that upgrades in band -- MySQL's CLIENT_SSL, STARTTLS, FTP's AUTH
// TLS -- would otherwise record its first two packets in the clear and then the
// TLS records of everything after, which is the one shape nothing can read. Pause
// covers the handshake, and the next Client picks the plaintext up again, so what
// the file holds is one continuous stream of the protocol.
func TestATapSkipsTheHandshakeOfAnInBandUpgrade(t *testing.T) {
	cfg := testConfig(t, config.CaptureRule{Kinds: []string{"mysql"}})
	cfg.Bodies = true
	cp := newTestCapturer(t, cfg)
	tap := cp.Open("mysql", "db", "", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:1")))
	if tap == nil {
		t.Fatal("no tap for a session the rule names")
	}
	proxySide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = proxySide.Close(); _ = clientSide.Close() })

	read := func(c net.Conn, send string) {
		t.Helper()
		go func() { _, _ = clientSide.Write([]byte(send)) }()
		buf := make([]byte, len(send))
		for n := 0; n < len(send); {
			m, err := c.Read(buf[n:])
			if err != nil {
				t.Error(err)
				return
			}
			n += m
		}
	}

	// Before the upgrade: the short login, in the clear.
	wrapped := tap.Client(proxySide)
	read(wrapped, "login-ssl")
	// The handshake itself still passes through the same wrapper, which is why
	// stopping it has to be a flag rather than unwrapping.
	tap.Pause()
	read(wrapped, "~ciphertext~")
	// And the upgraded connection, whose plaintext is the rest of the protocol.
	// A real kind passes the tls.Conn here; what matters is that it is a
	// different connection object layered over the one above.
	read(tap.Client(wrapped), "SELECT 1")

	tap.Close()
	cp.Flush()
	out := files(t, cfg.Directory)
	for _, want := range []string{"login-ssl", "SELECT 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("the capture does not hold %q, which was in the clear", want)
		}
	}
	if strings.Contains(out, "ciphertext") {
		t.Error("the capture holds the bytes of the TLS handshake")
	}
}

// Only the nine kinds that register with the session table have an identifier of
// their own. The other twenty-seven pass none, and a file holding several of their
// sessions has to still say which packet belongs to which, so the tap names them.
func TestATapNamesASessionTheKindCannot(t *testing.T) {
	cfg := testConfig(t, config.CaptureRule{Kinds: []string{"redis"}})
	cfg.Bodies = true
	cp := newTestCapturer(t, cfg)
	client := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:5555"))
	first, second := cp.Open("redis", "cache", "", client), cp.Open("redis", "cache", "", client)
	if first == nil || second == nil {
		t.Fatal("no tap for a session the rule names")
	}
	if first.s.ID == "" || second.s.ID == "" {
		t.Fatal("an unnamed session stayed unnamed")
	}
	if first.s.ID == second.s.ID {
		t.Errorf("two sessions share the name %q", first.s.ID)
	}
	// And a kind that does have one keeps it, because that is the identifier the
	// session table and the access log already carry.
	if got := cp.Open("redis", "cache", "abc123", client); got.s.ID != "abc123" {
		t.Errorf("the tap renamed the session %q", got.s.ID)
	}
}
