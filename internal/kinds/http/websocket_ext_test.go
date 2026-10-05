package http

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Compression on an inspected route.
//
// The guard reads frames, and a permessage-deflate frame cannot be read. The
// question is what happens to the client that offers it -- which is every
// browser, because browsers offer the extension on every WebSocket by default.
//
// The answer has to be "it works, uncompressed". Refusing the offer at the
// upgrade would break those clients for a reason they cannot see, and
// forwarding it breaks them later and more confusingly: the endpoints agree
// compression behind the proxy, the client is told it succeeded, and the first
// data frame then trips the reserved-bit check and closes the connection with
// a protocol error blaming the peer.

// wsEchoExt is an origin that reports what it was offered and can be told to
// claim an extension in its 101 whether or not one was offered.
func wsEchoExt(t *testing.T, claim bool, offered *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offered != nil {
			*offered = r.Header.Get("Sec-WebSocket-Extensions")
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // the RFC's constant
		c, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = c.Close() }()
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n"
		if claim || (offered != nil && *offered != "") {
			resp += "Sec-WebSocket-Extensions: permessage-deflate\r\n"
		}
		resp += "\r\n"
		_, _ = buf.WriteString(resp)
		_ = buf.Flush()
		for {
			op, payload, err := wsRead(buf.Reader)
			if err != nil {
				return
			}
			if op == wsOpContinuation {
				op = wsOpText
			}
			if _, err := c.Write(wsFrame(op, payload, false)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wsDialExt opens an upgrade that offers permessage-deflate, the way a browser
// does, and returns the connection and the 101's own extension header.
func wsDialExt(t *testing.T, addr string) (net.Conn, *bufio.Reader, int, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var key [16]byte
	_, _ = rand.Read(key[:])
	req := "GET / HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " +
		base64.StdEncoding.EncodeToString(key[:]) + "\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading the upgrade response: %v", err)
	}
	return c, br, resp.StatusCode, resp.Header.Get("Sec-WebSocket-Extensions")
}

// A browser's offer is taken out of the request, so the origin never accepts an
// extension, the client is never told it has one, and the conversation runs
// uncompressed -- inspected, which is the point.
func TestWebSocketCompressionOfferIsStrippedNotForwarded(t *testing.T) {
	var offered string
	origin := wsEchoExt(t, false, &offered)
	s := wsProxy(t, origin.URL,
		"    websocket_guard: {max_frame_bytes: 4096, deny_patterns: [\"DROP TABLE\"]}")

	c, br, code, gotExt := wsDialExt(t, s.Addrs()["main"])
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("a client offering permessage-deflate was refused the upgrade: %d", code)
	}
	if offered != "" {
		t.Errorf("the origin was offered %q: an inspected route negotiates no extension, "+
			"and forwarding the offer is what let the endpoints agree compression the guard cannot read", offered)
	}
	if gotExt != "" {
		t.Errorf("the client was told it had extension %q", gotExt)
	}

	// And it is a working, inspected connection: ordinary frames pass...
	if _, err := c.Write(wsFrame(wsOpText, []byte("hello"), true)); err != nil {
		t.Fatal(err)
	}
	op, payload, err := wsRead(br)
	if err != nil {
		t.Fatalf("an uncompressed message did not come back: %v", err)
	}
	if op != wsOpText || string(payload) != "hello" {
		t.Fatalf("echo: op=%#x %q", op, payload)
	}
	// ...and the guard is still reading them.
	if _, err := c.Write(wsFrame(wsOpText, []byte("x DROP TABLE y"), true)); err != nil {
		t.Fatal(err)
	}
	op, _, err = wsRead(br)
	if err == nil && op != wsOpClose {
		t.Fatalf("a denied pattern was carried on a connection that offered compression: op=%#x", op)
	}
}

// An origin that claims an extension although nothing was offered is refused at
// the 101, not at the first frame: by then the client believes it has a working
// connection, and its frames would be unreadable.
func TestWebSocketUnrequestedExtensionRefusesTheUpgrade(t *testing.T) {
	origin := wsEchoExt(t, true, nil)
	s := wsProxy(t, origin.URL, "    websocket_guard: {max_frame_bytes: 4096}")

	_, _, code, _ := wsDialExt(t, s.Addrs()["main"])
	if code == http.StatusSwitchingProtocols {
		t.Fatal("an origin claiming an unrequested extension was allowed to upgrade, " +
			"so the guard would have been reading frames it cannot read")
	}
	if code != http.StatusBadGateway {
		t.Errorf("status %d, want 502: the origin is the one misbehaving, not the client", code)
	}
	if got := s.Stats().WSViolations; got == 0 {
		t.Error("the refusal was not counted as a websocket violation")
	}
}

// Without a guard the route is a byte relay and compression is none of its
// business, so the offer goes through untouched and the endpoints may agree it.
func TestWebSocketCompressionUntouchedWithoutAGuard(t *testing.T) {
	var offered string
	origin := wsEchoExt(t, false, &offered)
	s := wsProxy(t, origin.URL, "")

	_, _, code, gotExt := wsDialExt(t, s.Addrs()["main"])
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", code)
	}
	if !strings.Contains(offered, "permessage-deflate") {
		t.Errorf("the offer was stripped on a route with no guard: %q", offered)
	}
	if gotExt == "" {
		t.Error("the origin's acceptance did not reach the client on an uninspected route")
	}
}
