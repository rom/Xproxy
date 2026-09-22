package forward

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/masque"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// masqueProxy starts a forward listener with MASQUE on, in front of a
// UDP echo server, and returns the server and the echo port.
func masqueProxy(t *testing.T, extra string) (*proxy.Server, *forwardServer, int) {
	t.Helper()
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	port := echo.LocalAddr().(*net.UDPAddr).Port
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%d]
        allow_private: true
        masque:
          udp: true
%s
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, port, extra)
	s := proxytest.Start(t, yaml)
	return s, forwardOf(t, s), port
}

// masqueWriter is the ResponseWriter half of a MASQUE session: a
// flushable, streaming writer whose bytes a test can read as they are
// produced. net/http's own client refuses to send a `:protocol`
// pseudo-header, so the handler is driven directly — the HTTP/2
// plumbing that carries it is Go's, and what is tested here is the
// protocol this proxy implements on top of it.
type masqueWriter struct {
	hdr    http.Header
	status int
	w      *io.PipeWriter
	mu     sync.Mutex
	done   bool
}

func (m *masqueWriter) Header() http.Header { return m.hdr }

func (m *masqueWriter) WriteHeader(code int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status == 0 {
		m.status = code
	}
}

func (m *masqueWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	if m.status == 0 {
		m.status = 200
	}
	closed := m.done
	m.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	return m.w.Write(p)
}

func (m *masqueWriter) Flush() {}

func (m *masqueWriter) close() {
	m.mu.Lock()
	m.done = true
	m.mu.Unlock()
	_ = m.w.Close()
}

// connectUDP drives one CONNECT-UDP session against the listener's
// forward server and returns the writer half of the client's stream,
// the reader half of the proxy's, and the response status once the
// handler has set it.
func connectUDP(t *testing.T, f *forwardServer, host string, port int) (io.WriteCloser, *io.PipeReader, func() int) {
	t.Helper()
	return connectMasque(t, f, "connect-udp",
		fmt.Sprintf("%s%s/%d/", masque.UDPPrefix, url.PathEscape(host), port))
}

func connectMasque(t *testing.T, f *forwardServer, protocol, path string) (io.WriteCloser, *io.PipeReader, func() int) {
	t.Helper()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	w := &masqueWriter{hdr: http.Header{}, w: respW}
	req := &http.Request{
		Method:     http.MethodConnect,
		ProtoMajor: 2, ProtoMinor: 0, Proto: "HTTP/2.0",
		URL:        &url.URL{Scheme: "https", Host: "proxy.test", Path: path},
		Host:       "proxy.test",
		Body:       reqR,
		Header:     http.Header{":protocol": []string{protocol}},
		RemoteAddr: "198.51.100.7:40000",
	}
	go func() {
		f.ServeHTTP(w, req)
		w.close()
	}()
	status := func() int {
		// The handler writes the status before any capsule, so a short
		// wait is enough and a failing case does not hang the test.
		for range 200 {
			w.mu.Lock()
			code := w.status
			w.mu.Unlock()
			if code != 0 {
				return code
			}
			time.Sleep(5 * time.Millisecond)
		}
		return 0
	}
	t.Cleanup(func() { _ = reqW.Close() })
	return reqW, respR, status
}

// forwardOf builds the forward server of the running configuration's
// forward listener, against the same host the bound one has.
//
// These tests drive the handler rather than a socket: net/http's client
// refuses to send the ":protocol" pseudo-header a MASQUE session needs,
// so the HTTP/2 plumbing is Go's and what is exercised here is the
// protocol this proxy implements on top of it. A second engine over the
// same policy and the same counters is the honest way to reach it from
// outside the accept path.
func forwardOf(t *testing.T, s *proxy.Server) *forwardServer {
	t.Helper()
	for _, lc := range s.Config().Server.Listeners {
		if lc.Kind != "forward" {
			continue
		}
		f, err := newForwardServer(s, lc)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	t.Fatal("no forward listener")
	return nil
}

// TestMasqueUDP is the end to end case: datagrams through an HTTP proxy
// that until now could only carry TCP.
func TestMasqueUDP(t *testing.T) {
	_, f, port := masqueProxy(t, "")
	pw, body, status := connectUDP(t, f, "127.0.0.1", port)
	defer func() { _ = body.Close() }()
	if code := status(); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	// A datagram out, and its echo back.
	if err := masque.WriteCapsule(pw, masque.Datagram(0, []byte("hello"))); err != nil {
		t.Fatal(err)
	}
	c, err := masque.ReadCapsule(body)
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	ctx, payload, err := masque.SplitDatagram(c)
	if err != nil || ctx != 0 || string(payload) != "echo:hello" {
		t.Fatalf("answer = %d %q %v", ctx, payload, err)
	}
	// Several in a row, to prove the session is not one-shot.
	for i := range 3 {
		msg := fmt.Sprintf("n%d", i)
		if err := masque.WriteCapsule(pw, masque.Datagram(0, []byte(msg))); err != nil {
			t.Fatal(err)
		}
		c, err := masque.ReadCapsule(body)
		if err != nil {
			t.Fatal(err)
		}
		_, payload, _ := masque.SplitDatagram(c)
		if string(payload) != "echo:"+msg {
			t.Fatalf("answer %d = %q", i, payload)
		}
	}
	// A capsule type this proxy does not know is skipped rather than
	// treated as an error, which is what makes the protocol extensible.
	if err := masque.WriteCapsule(pw, masque.Capsule{Type: 0x4242, Value: []byte("ignored")}); err != nil {
		t.Fatal(err)
	}
	if err := masque.WriteCapsule(pw, masque.Datagram(0, []byte("after"))); err != nil {
		t.Fatal(err)
	}
	c, err = masque.ReadCapsule(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, payload, _ := masque.SplitDatagram(c); string(payload) != "echo:after" {
		t.Fatalf("after an unknown capsule: %q", payload)
	}
	_ = pw.Close()
}

// TestMasqueUDPPolicy: the destination policy is the forward
// listener's, so what it refuses over CONNECT it refuses here.
func TestMasqueUDPPolicy(t *testing.T) {
	_, f, port := masqueProxy(t, "        deny: [\"127.0.0.1\"]\n")
	pw, body, status := connectUDP(t, f, "127.0.0.1", port)
	_ = pw.Close()
	if code := status(); code != http.StatusForbidden {
		t.Fatalf("a denied destination gave %d", code)
	}
	_ = body.Close()
	// A port outside the list.
	pw2, body2, status2 := connectUDP(t, f, "127.0.0.1", 9)
	_ = pw2.Close()
	if code := status2(); code != http.StatusForbidden {
		t.Fatalf("an unlisted port gave %d", code)
	}
	_ = body2.Close()
}

// TestMasqueBadTarget: the path carries the destination, so it is
// attacker-controlled input parsed before anything else happens.
func TestMasqueBadTarget(t *testing.T) {
	_, f, _ := masqueProxy(t, "")
	for _, path := range []string{
		"/.well-known/masque/udp/",
		"/.well-known/masque/udp/host/",
		"/.well-known/masque/udp/host/0/",
		"/.well-known/masque/udp/host/70000/",
		"/.well-known/masque/udp/host/53/extra/",
		"/somewhere/else/",
	} {
		pw, body, status := connectMasque(t, f, "connect-udp", path)
		_ = pw.Close()
		if code := status(); code != http.StatusBadRequest {
			t.Errorf("%s gave %d, want 400", path, code)
		}
		_ = body.Close()
	}
}

// TestMasqueDisabled: without the section, or with only udp enabled, an
// unsupported protocol is refused with 501 rather than quietly turning
// into something else.
func TestMasqueDisabled(t *testing.T) {
	_, f, _ := masqueProxy(t, "")
	pw, body, status := connectMasque(t, f, "connect-ip", "/.well-known/masque/ip/127.0.0.1/17/")
	_ = pw.Close()
	if code := status(); code != http.StatusNotImplemented {
		t.Fatalf("connect-ip with ip disabled gave %d, want 501", code)
	}
	_ = body.Close()
	// An unknown :protocol is refused the same way rather than falling
	// through to an ordinary CONNECT.
	pw2, body2, status2 := connectMasque(t, f, "connect-carrier-pigeon", "/whatever/")
	_ = pw2.Close()
	if code := status2(); code != http.StatusNotImplemented {
		t.Fatalf("an unknown protocol gave %d", code)
	}
	_ = body2.Close()
}

// TestMasqueStatus reports what the listener is doing.
func TestMasqueStatus(t *testing.T) {
	s, f, port := masqueProxy(t, "")
	pw, body, status := connectUDP(t, f, "127.0.0.1", port)
	if code := status(); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if err := masque.WriteCapsule(pw, masque.Datagram(0, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if _, err := masque.ReadCapsule(body); err != nil {
		t.Fatal(err)
	}
	if sn := s.Stats(); sn.MasqueUDP != 1 || sn.MasqueOpen != 1 {
		t.Fatalf("counters: udp %d open %d", sn.MasqueUDP, sn.MasqueOpen)
	}
	// What this engine is doing, which is where the session lives.
	own := (&instance{f: f}).MasqueStatus()
	if own == nil || !own.UDP || own.IP || own.UDPTotal != 1 || own.Sessions != 1 {
		t.Fatalf("engine status = %+v", own)
	}
	// And the wiring: the bound listener reaches the same view through
	// the registry, named, with the section it was configured from.
	st := s.Masque()
	if len(st) != 1 || st[0].Listener != "fwd" || !st[0].UDP || st[0].IP || st[0].MaxSessions != own.MaxSessions {
		t.Fatalf("listener status = %+v", st)
	}
	_ = pw.Close()
	_ = body.Close()
}

// TestPacketAllowed is the anti-spoofing check of CONNECT-IP: a client
// may only use the source address it was assigned, and may only reach
// what it was told about.
func TestPacketAllowed(t *testing.T) {
	assign := []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")}
	routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	packet := func(src, dst string) []byte {
		b := make([]byte, 20)
		b[0] = 0x45
		copy(b[12:16], netip.MustParseAddr(src).AsSlice())
		copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
		return b
	}
	if !packetAllowed(packet("10.8.0.2", "192.0.2.9"), assign, routes) {
		t.Error("a packet from the assigned address to an advertised route was refused")
	}
	for _, c := range []struct{ name, src, dst string }{
		{"a forged source", "10.8.0.99", "192.0.2.9"},
		{"a destination outside the routes", "10.8.0.2", "198.51.100.1"},
		{"both wrong", "192.168.1.1", "8.8.8.8"},
	} {
		if packetAllowed(packet(c.src, c.dst), assign, routes) {
			t.Errorf("%s was allowed", c.name)
		}
	}
	// Anything that is not an IP packet.
	for _, b := range [][]byte{nil, make([]byte, 19), {0x00}, append([]byte{0x40}, make([]byte, 30)...)} {
		if packetAllowed(b, assign, routes) {
			t.Errorf("%d bytes of nonsense was allowed", len(b))
		}
	}
	// An IPv4 header claiming a header length below the fixed 20 bytes.
	bad := packet("10.8.0.2", "192.0.2.9")
	bad[0] = 0x43
	if packetAllowed(bad, assign, routes) {
		t.Error("an IPv4 header with an impossible length was allowed")
	}
	// IPv6.
	v6 := make([]byte, 40)
	v6[0] = 0x60
	copy(v6[8:24], netip.MustParseAddr("2001:db8::2").AsSlice())
	copy(v6[24:40], netip.MustParseAddr("2001:db8:1::9").AsSlice())
	if !packetAllowed(v6, []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")},
		[]netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")}) {
		t.Error("a valid IPv6 packet was refused")
	}
}
