package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 specifies SHA-1 for the accept key
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// wsEcho is an origin that speaks enough of RFC 6455 to echo: it
// completes the handshake and then reflects every data frame, unmasked,
// as a server must.
func wsEcho(t *testing.T, onFrame func(op byte, payload []byte) (byte, []byte, bool)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			http.Error(w, "no key", 400)
			return
		}
		sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // the RFC's constant
		c, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = c.Close() }()
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n"
		if sp := r.Header.Get("Sec-WebSocket-Protocol"); sp != "" {
			resp += "Sec-WebSocket-Protocol: " + strings.Split(sp, ",")[0] + "\r\n"
		}
		resp += "\r\n"
		_, _ = buf.WriteString(resp)
		_ = buf.Flush()
		for {
			op, payload, err := wsRead(buf.Reader)
			if err != nil {
				return
			}
			outOp, out, send := op, payload, true
			if outOp == wsOpContinuation {
				// The echo answers each frame on its own, so a
				// continuation goes back as a complete text message
				// rather than a continuation of nothing.
				outOp = wsOpText
			}
			if onFrame != nil {
				outOp, out, send = onFrame(op, payload)
			}
			if !send {
				continue
			}
			if _, err := c.Write(wsFrame(outOp, out, false)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wsFrame builds one frame. Client frames are masked, as RFC 6455
// requires; server frames are not.
func wsFrame(op byte, payload []byte, mask bool) []byte {
	out := []byte{0x80 | op}
	n := len(payload)
	switch {
	case n <= 125:
		out = append(out, byte(n))
	case n <= 0xffff:
		out = append(out, 126)
		out = binary.BigEndian.AppendUint16(out, uint16(n)) //nolint:gosec // bounded above
	default:
		out = append(out, 127)
		out = binary.BigEndian.AppendUint64(out, uint64(n)) //nolint:gosec // non-negative
	}
	if !mask {
		return append(out, payload...)
	}
	out[1] |= 0x80
	var key [4]byte
	_, _ = rand.Read(key[:])
	out = append(out, key[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ key[i%4]
	}
	return append(out, masked...)
}

// wsRead reads one whole frame.
func wsRead(r *bufio.Reader) (byte, []byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0, nil, err
	}
	op := h[0] & 0x0f
	masked := h[1]&0x80 != 0
	n := int64(h[1] & 0x7f)
	switch n {
	case 126:
		b := make([]byte, 2)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, nil, err
		}
		n = int64(binary.BigEndian.Uint16(b))
	case 127:
		b := make([]byte, 8)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, nil, err
		}
		n = int64(binary.BigEndian.Uint64(b)) //nolint:gosec // test input
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return op, payload, nil
}

// wsDial opens an upgraded connection through the proxy.
func wsDial(t *testing.T, addr, path, subprotocol string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var key [16]byte
	_, _ = rand.Read(key[:])
	req := "GET " + path + " HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key[:]) + "\r\n"
	if subprotocol != "" {
		req += "Sec-WebSocket-Protocol: " + subprotocol + "\r\n"
	}
	req += "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = c.Close()
		t.Fatalf("reading the upgrade response: %v", err)
	}
	return c, br, resp.StatusCode
}

// wsProxy starts a proxy with a guard in front of an echo origin.
func wsProxy(t *testing.T, origin string, guard string) *Server {
	t.Helper()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(origin, "http://"))
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: "%s:%s"}]
routes:
  - name: ws
    paths: [/]
    websocket: true
%s
    upstream: app
`, host, port, guard)
	s, _ := startServer(t, yaml)
	return s
}

// TestWebSocketGuardPasses: an ordinary conversation is untouched. A
// guard that broke normal traffic would be worse than none.
func TestWebSocketGuardPasses(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, "    websocket_guard: {max_frame_bytes: 4096, deny_patterns: [\"DROP TABLE\"]}")
	c, br, code := wsDial(t, s.Addrs()["main"], "/chat", "")
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", code)
	}
	defer func() { _ = c.Close() }()
	for _, msg := range []string{"hello", "a longer message with spaces", strings.Repeat("x", 1000)} {
		if _, err := c.Write(wsFrame(wsOpText, []byte(msg), true)); err != nil {
			t.Fatal(err)
		}
		op, payload, err := wsRead(br)
		if err != nil {
			t.Fatalf("reading the echo of %q: %v", msg, err)
		}
		if op != wsOpText || string(payload) != msg {
			t.Fatalf("echo = %d %q, want text %q", op, payload, msg)
		}
	}
	// A ping and its pong, and a fragmented message, both ordinary.
	if _, err := c.Write(wsFrame(wsOpPing, []byte("p"), true)); err != nil {
		t.Fatal(err)
	}
	if op, _, err := wsRead(br); err != nil || op != wsOpPing {
		t.Fatalf("ping echo: op %d err %v", op, err)
	}
	frag := []byte{0x01, 0x83}
	frag = append(frag, maskInto("abc")...)
	cont := []byte{0x80, 0x83}
	cont = append(cont, maskInto("def")...)
	if _, err := c.Write(append(frag, cont...)); err != nil {
		t.Fatal(err)
	}
	if op, payload, err := wsRead(br); err != nil || op != wsOpText || string(payload) != "abc" {
		t.Fatalf("fragment echo: %d %q %v", op, payload, err)
	}
	if _, payload, err := wsRead(br); err != nil || string(payload) != "def" {
		t.Fatalf("second fragment echo: %q %v", payload, err)
	}
	if st := s.WebSocketGuards(); len(st) != 1 || st[0].Violations != 0 || st[0].Messages == 0 {
		t.Fatalf("status = %+v", st)
	}
}

// maskInto builds a masked payload with a zero key, which is legal and
// keeps the test frames readable.
func maskInto(s string) []byte {
	out := []byte{0, 0, 0, 0}
	return append(out, s...)
}

// TestWebSocketGuardCloses drives every structural rule. Each case is a
// frame a normal client never sends and a hostile one does.
func TestWebSocketGuardCloses(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL,
		"    websocket_guard: {max_frame_bytes: 256, max_message_bytes: 512, deny_patterns: [\"DROP TABLE\"]}")
	addr := s.Addrs()["main"]
	for _, c := range []struct {
		name  string
		frame []byte
	}{
		{"an unmasked client frame", wsFrame(wsOpText, []byte("hi"), false)},
		{"a reserved bit", func() []byte { f := wsFrame(wsOpText, []byte("hi"), true); f[0] |= 0x40; return f }()},
		{"a reserved opcode", wsFrame(0x3, []byte("hi"), true)},
		{"a frame over max_frame_bytes", wsFrame(wsOpBinary, make([]byte, 300), true)},
		{"a fragmented control frame", func() []byte { f := wsFrame(wsOpPing, []byte("x"), true); f[0] &^= 0x80; return f }()},
		{"an oversize control frame", wsFrame(wsOpPing, make([]byte, 130), true)},
		{"a continuation with nothing to continue", func() []byte {
			f := wsFrame(wsOpContinuation, []byte("x"), true)
			return f
		}()},
		{"a close code that must not be sent", wsFrame(wsOpClose, []byte{0x03, 0xee}, true)},
		{"a one byte close payload", wsFrame(wsOpClose, []byte{0x03}, true)},
		{"a denied pattern", wsFrame(wsOpText, []byte("x; DROP TABLE users"), true)},
		{"text that is not UTF-8", wsFrame(wsOpText, []byte{0xff, 0xfe}, true)},
	} {
		conn, br, code := wsDial(t, addr, "/chat", "")
		if code != http.StatusSwitchingProtocols {
			t.Fatalf("%s: upgrade status %d", c.name, code)
		}
		if _, err := conn.Write(c.frame); err != nil {
			_ = conn.Close()
			continue
		}
		// The guard must close, and say why with a close frame rather
		// than a reset.
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		op, payload, err := wsRead(br)
		switch {
		case err == nil && op == wsOpClose:
			if len(payload) >= 2 {
				code := binary.BigEndian.Uint16(payload[:2])
				if code != wsClosePolicy && code != wsCloseProtocolError && code != wsCloseTooBig {
					t.Errorf("%s: close code %d", c.name, code)
				}
			}
		case err == nil:
			t.Errorf("%s: the frame was forwarded (op %d, %q)", c.name, op, payload)
		default:
			// A closed connection without a close frame is acceptable
			// only if the guard already wrote one that raced the reset.
		}
		_ = conn.Close()
	}
	st := s.WebSocketGuards()
	if len(st) != 1 || st[0].Violations < 10 {
		t.Fatalf("status = %+v, want a violation per case", st)
	}
}

// TestWebSocketGuardServerSide: the origin is inspected too. A
// compromised or buggy application must not be able to push frames the
// policy refuses at the client.
func TestWebSocketGuardServerSide(t *testing.T) {
	origin := wsEcho(t, func(op byte, payload []byte) (byte, []byte, bool) {
		// Answer every message with something the policy denies.
		return wsOpText, []byte("secret: DROP TABLE users"), true
	})
	s := wsProxy(t, origin.URL, "    websocket_guard: {inspect: all, deny_patterns: [\"DROP TABLE\"]}")
	c, br, code := wsDial(t, s.Addrs()["main"], "/chat", "")
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", code)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(wsFrame(wsOpText, []byte("anything"), true)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	op, payload, err := wsRead(br)
	if err == nil && op == wsOpText && strings.Contains(string(payload), "DROP TABLE") {
		t.Fatal("the origin's refused message reached the client")
	}
	if st := s.WebSocketGuards(); len(st) != 1 || st[0].Violations == 0 {
		t.Fatalf("status = %+v", st)
	}
}

// TestWebSocketGuardLogAction: with action log, nothing is cut off and
// the counters still move. This is how a policy is measured before it
// is enforced.
func TestWebSocketGuardLogAction(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, "    websocket_guard: {action: log, deny_patterns: [\"DROP TABLE\"]}")
	c, br, _ := wsDial(t, s.Addrs()["main"], "/chat", "")
	defer func() { _ = c.Close() }()
	if _, err := c.Write(wsFrame(wsOpText, []byte("x; DROP TABLE users"), true)); err != nil {
		t.Fatal(err)
	}
	op, payload, err := wsRead(br)
	if err != nil || op != wsOpText || !strings.Contains(string(payload), "DROP TABLE") {
		t.Fatalf("log mode cut the message off: %d %q %v", op, payload, err)
	}
	st := s.WebSocketGuards()
	// Two violations: the client's message and the echo of it coming
	// back, since both directions are inspected. Neither closed.
	if len(st) != 1 || st[0].Violations != 2 || st[0].Closed != 0 {
		t.Fatalf("status = %+v", st)
	}
}

// TestWebSocketSubprotocol: the origin's chosen subprotocol is checked
// before a single frame exists.
func TestWebSocketSubprotocol(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, "    websocket_guard: {allow_subprotocols: [chat.v2]}")
	addr := s.Addrs()["main"]
	if _, _, code := wsDial(t, addr, "/chat", "chat.v2"); code != http.StatusSwitchingProtocols {
		t.Fatalf("the allowed subprotocol was refused: %d", code)
	}
	if _, _, code := wsDial(t, addr, "/chat", "admin.v1"); code == http.StatusSwitchingProtocols {
		t.Fatal("an unlisted subprotocol was accepted")
	}
	if _, _, code := wsDial(t, addr, "/chat", ""); code == http.StatusSwitchingProtocols {
		t.Fatal("a connection with no subprotocol was accepted on a route that lists them")
	}
}

// TestWebSocketRate bounds how fast a client may send.
func TestWebSocketRate(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, "    websocket_guard: {messages_per_second: 5}")
	c, br, _ := wsDial(t, s.Addrs()["main"], "/chat", "")
	defer func() { _ = c.Close() }()
	closed := false
	for i := 0; i < 40 && !closed; i++ {
		if _, err := c.Write(wsFrame(wsOpText, []byte("flood"), true)); err != nil {
			closed = true
			break
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		op, _, err := wsRead(br)
		if err != nil || op == wsOpClose {
			closed = true
		}
	}
	if !closed {
		t.Fatal("a flood of messages was never refused")
	}
	if st := s.WebSocketGuards(); st[0].Violations == 0 {
		t.Fatal("the rate violation was not counted")
	}
}

// TestWebSocketNoGuardIsUntouched: without the section an upgrade is
// the opaque tunnel it always was, including frames the guard would
// refuse.
func TestWebSocketNoGuardIsUntouched(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, "")
	c, br, code := wsDial(t, s.Addrs()["main"], "/chat", "")
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", code)
	}
	defer func() { _ = c.Close() }()
	// An unmasked client frame: a protocol violation the guard would
	// close on, and which this origin happens to accept.
	if _, err := c.Write(wsFrame(wsOpText, []byte("unmasked"), false)); err != nil {
		t.Fatal(err)
	}
	if op, payload, err := wsRead(br); err != nil || op != wsOpText || string(payload) != "unmasked" {
		t.Fatalf("without a guard the frame should pass: %d %q %v", op, payload, err)
	}
	if st := s.WebSocketGuards(); len(st) != 0 {
		t.Fatalf("a route without the section reported a guard: %+v", st)
	}
}

// TestWSCloseCodes checks the close code table against RFC 6455 and the
// registry, since a wrong answer here refuses ordinary traffic.
func TestWSCloseCodes(t *testing.T) {
	for _, code := range []uint16{1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000, 4999} {
		if !wsValidCloseCode(code) {
			t.Errorf("close code %d refused", code)
		}
	}
	for _, code := range []uint16{0, 999, 1004, 1005, 1006, 1015, 1016, 2000, 2999, 5000, 65535} {
		if wsValidCloseCode(code) {
			t.Errorf("close code %d accepted", code)
		}
	}
}
