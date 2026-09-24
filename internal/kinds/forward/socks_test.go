package forward

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// socksDial performs a SOCKS5 handshake and returns the connection,
// ready to carry the tunnelled protocol. It is written out rather than
// taken from a library so the test exercises the bytes on the wire.
func socksDial(t *testing.T, proxyAddr, host string, port int, user, pass string) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	method := byte(0x00)
	if user != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{5, 1, method}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		_ = c.Close()
		t.Fatalf("greeting reply: %v", err)
	}
	if reply[0] != 5 {
		_ = c.Close()
		t.Fatalf("greeting version %d", reply[0])
	}
	if reply[1] == 0xFF {
		_ = c.Close()
		return nil, 0xFF
	}
	if reply[1] == 0x02 {
		msg := []byte{0x01, byte(len(user))}
		msg = append(msg, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(c, ar); err != nil {
			_ = c.Close()
			t.Fatalf("auth reply: %v", err)
		}
		if ar[1] != 0 {
			_ = c.Close()
			return nil, 0xFE // authentication refused
		}
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port)) //nolint:gosec // test port
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		_ = c.Close()
		t.Fatalf("request reply: %v", err)
	}
	switch head[3] {
	case 1:
		_, _ = io.ReadFull(c, make([]byte, 4+2))
	case 4:
		_, _ = io.ReadFull(c, make([]byte, 16+2))
	case 3:
		var l [1]byte
		_, _ = io.ReadFull(c, l[:])
		_, _ = io.ReadFull(c, make([]byte, int(l[0])+2))
	}
	if head[1] != 0 {
		_ = c.Close()
		return nil, head[1]
	}
	return c, 0
}

// socksProxy starts a forward listener with SOCKS5 on and returns its
// address plus the helpers a test needs.
func socksProxy(t *testing.T, ports string, extra string) (*proxy.Server, string) {
	t.Helper()
	yaml := `
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [PORTS]
        allow_private: true
        socks5: true
        socks_udp: true
        idle_timeout: 5s
EXTRA
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`
	yaml = strings.Replace(yaml, "PORTS", ports, 1)
	yaml = strings.Replace(yaml, "EXTRA", extra, 1)
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["fwd"]
}

// TestSOCKS5TLSBoundary ensures protocol detection happens inside listener
// TLS. In particular, a client certificate requirement must cover SOCKS just
// as it covers HTTP on the shared port.
func TestSOCKS5TLSBoundary(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	serverCert, serverKey := ca.Issue(t, dir, "proxy.test")
	clientCert, clientKey := ca.Issue(t, dir, "client.test")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
        client_auth: require
        client_ca_file: %s
      forward: {socks5: true}
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, serverCert, serverKey, ca.Path)
	s := proxytest.Start(t, yaml)
	addr := s.Addrs()["fwd"]

	// A raw SOCKS greeting must encounter TLS rather than the SOCKS parser.
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = raw.Write([]byte{5, 1, 0})
	var reply [2]byte
	if _, err := io.ReadFull(raw, reply[:]); err == nil && reply == [2]byte{5, 0} {
		_ = raw.Close()
		t.Fatal("plaintext SOCKS greeting bypassed listener TLS")
	}
	_ = raw.Close()

	// An authenticated TLS client still reaches the SOCKS parser.
	pair, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	c, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{pair}, RootCAs: pool,
		ServerName: "proxy.test", MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply != [2]byte{5, 0} {
		t.Fatalf("SOCKS greeting reply = %v", reply)
	}
}

// TestSOCKS5Connect is the end to end case: a client speaks SOCKS5 to
// the same port the HTTP proxy is on, and reaches an origin.
func TestSOCKS5Connect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "socks:%s", r.URL.Path)
	}))
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	s, addr := socksProxy(t, port, "")
	_ = s
	t.Run("http through the tunnel", func(t *testing.T) {
		p, _ := strconv.Atoi(port)
		c, code := socksDial(t, addr, "localhost", p, "", "")
		if code != 0 {
			t.Fatalf("socks reply code %d", code)
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte("GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
		body, _ := io.ReadAll(c)
		if !strings.Contains(string(body), "socks:/x") {
			t.Fatalf("response = %q", body)
		}
	})
	t.Run("http on the same port still works", func(t *testing.T) {
		c := forwardClient(t, addr, nil, "", "")
		resp, err := c.Get(origin.URL + "/http")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !strings.Contains(string(body), "socks:/http") {
			t.Fatalf("the HTTP proxy broke when SOCKS was enabled: %q", body)
		}
	})
}

// TestSOCKS5Policy: the destination policy is the forward listener's,
// so everything it refuses over CONNECT it refuses here too — and says
// so with a truthful reply code.
func TestSOCKS5Policy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(origin.Close)
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	_, addr := socksProxy(t, portStr, "        deny: [localhost]\n")
	for _, c := range []struct {
		name string
		host string
		port int
		code byte
	}{
		{"an allowed destination", "127.0.0.1", port, 0},
		{"a denied name", "localhost", port, socksReplyNotAllowed},
		{"a port that is not listed", "127.0.0.1", 9999, socksReplyNotAllowed},
		{"a name that does not resolve", "nothing.invalid", port, socksReplyHostUnreachable},
	} {
		conn, code := socksDial(t, addr, c.host, c.port, "", "")
		if conn != nil {
			_ = conn.Close()
		}
		if code != c.code {
			t.Errorf("%s: reply %d, want %d", c.name, code, c.code)
		}
	}
}

// TestSOCKS5Auth: the users file is shared with the HTTP side, and a
// client offering no acceptable method is refused rather than let in.
func TestSOCKS5Auth(t *testing.T) {
	dir := t.TempDir()
	hash, err := passwd.HashWithIterations("correct horse battery", 1000)
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(dir, "proxy.htpasswd")
	if err := os.WriteFile(users, []byte("alice:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(origin.Close)
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	_, addr := socksProxy(t, portStr, "        auth: {users_file: "+users+", realm: lab}\n")

	c, code := socksDial(t, addr, "localhost", port, "alice", "correct horse battery")
	if code != 0 {
		t.Fatalf("the right password was refused: %d", code)
	}
	_ = c.Close()
	if _, code := socksDial(t, addr, "localhost", port, "alice", "wrong"); code != 0xFE {
		t.Errorf("a wrong password gave %d", code)
	}
	if _, code := socksDial(t, addr, "localhost", port, "mallory", "whatever"); code != 0xFE {
		t.Errorf("an unknown user gave %d", code)
	}
	// No method in common: the listener requires credentials and the
	// client offers only "none".
	if _, code := socksDial(t, addr, "localhost", port, "", ""); code != 0xFF {
		t.Errorf("an unauthenticated client gave %d", code)
	}
}

// TestSOCKS5Malformed: every truncation and every lie a client can tell
// in the handshake. The proxy is reachable by whoever can reach the
// port, so the parser is an attack surface.
func TestSOCKS5Malformed(t *testing.T) {
	_, addr := socksProxy(t, "80, 443", "")
	for _, c := range []struct {
		name string
		send []byte
	}{
		{"an empty greeting", []byte{5}},
		{"no methods", []byte{5, 0}},
		{"a truncated method list", []byte{5, 3, 0}},
		{"socks4", []byte{4, 1, 0, 80, 127, 0, 0, 1, 0}},
		{"a version that is not 5", []byte{9, 1, 0}},
		{"a truncated request", []byte{5, 1, 0, 5, 1, 0}},
		{"an empty domain name", []byte{5, 1, 0, 5, 1, 0, 3, 0}},
		{"a name with a NUL", append([]byte{5, 1, 0, 5, 1, 0, 3, 5}, []byte("a\x00b.c")...)},
		{"an address type nobody has", []byte{5, 1, 0, 5, 1, 0, 9, 1, 2, 3, 4, 0, 80}},
		{"bind, which is not implemented", []byte{5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80}},
	} {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(c.send)
		// Half close, so a parser waiting for the rest of a truncated
		// message sees the end rather than the handshake timeout.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		// The server must close without ever sending a success reply.
		all, _ := io.ReadAll(conn)
		if replyCode(all) == 0 && len(all) >= 3 {
			t.Errorf("%s: got a success reply: %v", c.name, all)
		}
		_ = conn.Close()
	}
}

// TestSOCKS5UDP: a datagram out and its answer back, the client
// binding, and the peer check that stops the socket being a reflector.
func TestSOCKS5UDP(t *testing.T) {
	// An echo server the association will talk to.
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
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	_, addr := socksProxy(t, strconv.Itoa(echoPort), "")

	// UDP ASSOCIATE over the control connection.
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(c, greeting); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0 {
		t.Fatalf("associate refused: %d", head[1])
	}
	if head[3] != 1 {
		t.Fatalf("bound address type %d", head[3])
	}
	rest := make([]byte, 6)
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatal(err)
	}
	relayPort := binary.BigEndian.Uint16(rest[4:])
	relay := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relayPort)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	// A datagram for the echo server, in the RFC 1928 envelope.
	msg := []byte{0, 0, 0, 1, 127, 0, 0, 1}
	msg = binary.BigEndian.AppendUint16(msg, uint16(echoPort)) //nolint:gosec // test port
	msg = append(msg, []byte("hello")...)
	if _, err := client.WriteTo(msg, net.UDPAddrFromAddrPort(relay)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, from, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no answer came back: %v", err)
	}
	if !strings.HasSuffix(from.String(), strconv.Itoa(int(relayPort))) {
		t.Errorf("answer came from %s, want the relay", from)
	}
	if n < 10 || !strings.Contains(string(buf[10:n]), "echo:hello") {
		t.Fatalf("answer = %q", buf[:n])
	}

	// A datagram from a host this client never sent to is dropped
	// rather than delivered: the relay socket must not be usable to
	// reach the client from outside.
	stranger, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stranger.Close() }()
	if _, err := stranger.WriteTo([]byte("unsolicited"), net.UDPAddrFromAddrPort(relay)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _, err := client.ReadFrom(buf); err == nil {
		t.Errorf("an unsolicited datagram was relayed to the client: %q", buf[:n])
	}
}

// TestSOCKS5UDPOffByDefault: the association is opt-in, because a UDP
// relay is a different exposure from a TCP tunnel.
func TestSOCKS5UDPOffByDefault(t *testing.T) {
	yaml := `
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward: {allow_private: true, socks5: true}
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`
	s := proxytest.Start(t, yaml)
	addr := s.Addrs()["fwd"]
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(c, greeting); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != socksReplyCmdNotSupported {
		t.Fatalf("reply %d, want command-not-supported", head[1])
	}
}

// TestSOCKSUDPHeaderParsing covers the datagram header on its own,
// including the shapes a client can lie about.
func TestSOCKSUDPHeaderParsing(t *testing.T) {
	good := []byte{0, 0, 0, 1, 10, 0, 0, 1, 0, 53, 'p', 'a', 'y'}
	host, port, payload, err := parseSOCKSUDP(good)
	if err != nil || host != "10.0.0.1" || port != 53 || string(payload) != "pay" {
		t.Fatalf("good datagram: %q %d %q %v", host, port, payload, err)
	}
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"too short", []byte{0, 0, 0, 1}},
		{"reserved bytes set", []byte{1, 0, 0, 1, 10, 0, 0, 1, 0, 53}},
		{"a fragment", []byte{0, 0, 1, 1, 10, 0, 0, 1, 0, 53}},
		{"an unknown address type", []byte{0, 0, 0, 7, 10, 0, 0, 1, 0, 53}},
		{"a truncated ipv6", append([]byte{0, 0, 0, 4}, make([]byte, 10)...)},
		{"an empty name", []byte{0, 0, 0, 3, 0, 0, 53}},
		{"a name longer than the datagram", []byte{0, 0, 0, 3, 40, 'a', 0, 53}},
		{"a name with a slash", []byte{0, 0, 0, 3, 3, 'a', '/', 'b', 0, 53}},
	} {
		if _, _, _, err := parseSOCKSUDP(c.b); err == nil {
			t.Errorf("%s was accepted", c.name)
		}
	}
	// And the answer header the relay writes back.
	h := socksUDPHeader(netip.MustParseAddrPort("192.0.2.9:53"))
	if len(h) != 10 || h[3] != socksAddrIPv4 || h[8] != 0 || h[9] != 53 {
		t.Fatalf("answer header = %v", h)
	}
	h6 := socksUDPHeader(netip.MustParseAddrPort("[2001:db8::1]:53"))
	if len(h6) != 22 || h6[3] != socksAddrIPv6 {
		t.Fatalf("ipv6 answer header = %v", h6)
	}
}

// replyCode finds the request reply in what the server sent: a
// two byte greeting reply may come first. It returns 0xFF when there
// is no request reply at all, which is the good case for a malformed
// handshake.
func replyCode(b []byte) byte {
	if len(b) >= 2 && b[0] == 5 && len(b) == 2 {
		return 0xFF // only the greeting reply: nothing was served
	}
	if len(b) > 2 && b[0] == 5 {
		rest := b[2:]
		if len(rest) >= 2 && rest[0] == 5 {
			return rest[1]
		}
	}
	return 0xFF
}

var _ = x509.NewCertPool
var _ = testutil.WriteCA
