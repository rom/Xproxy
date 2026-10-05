package http

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/sha1" //nolint:gosec // RFC 6455 specifies SHA-1 for the accept key
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The message policy: a route saying which messages it carries, how large and
// how often each may be, and what shape each must have.
//
// The frame guard beside it answers the protocol's question, which is the same
// on every route. This answers the application's: one max_message_bytes for a
// connection is the bound of its largest message, which is the bound that lets
// every other message be that large too.

// wsTypesGuard is a guard with a message-type policy, indented for a route.
func wsTypesGuard(schema string) string {
	return `    websocket_guard:
      max_frame_bytes: 65536
      max_message_bytes: 65536
      type_field: op
      unknown_types: deny
      types:
        - {name: ping, max_bytes: 64}
        - {name: chat, max_bytes: 512, schema_file: ` + schema + `}
        - {name: tick, direction: server}`
}

// chatSchema writes the schema a chat message has to match.
func chatSchema(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chat.json")
	doc := `{"type":"object","required":["op","text"],
	  "properties":{"op":{"type":"string"},"text":{"type":"string","maxLength":16}}}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// wsSend opens a connection, sends one frame and says what came back: the
// opcode, the payload, and the close code where the guard closed.
func wsSend(t *testing.T, addr string, frame []byte) (op byte, payload []byte, closeCode int) {
	t.Helper()
	c, br, code := wsDial(t, addr, "/chat", "")
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", code)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(frame); err != nil {
		t.Fatalf("writing the frame: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	op, payload, err := wsRead(br)
	switch {
	case err != nil:
		// A connection closed without a close frame is a refusal too.
		return 0, nil, -1
	case op == wsOpClose:
		if len(payload) >= 2 {
			return op, payload, int(binary.BigEndian.Uint16(payload[:2]))
		}
		return op, payload, -1
	}
	return op, payload, 0
}

func TestTheMessageTypesDecideWhatAConnectionCarries(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, wsTypesGuard(chatSchema(t)))
	addr := s.Addrs()["main"]

	for _, c := range []struct {
		name    string
		message string
		binary  bool
		refused bool
	}{
		{name: "a named type within its bounds", message: `{"op":"ping"}`},
		{name: "a message matching its schema", message: `{"op":"chat","text":"hello"}`},
		{name: "a message the schema refuses", message: `{"op":"chat","text":"` +
			strings.Repeat("x", 20) + `"}`, refused: true},
		{name: "a message missing what the schema requires", message: `{"op":"chat"}`, refused: true},
		{name: "a message over its type's max_bytes", message: `{"op":"chat","text":"ok","pad":"` +
			strings.Repeat("y", 600) + `"}`, refused: true},
		{name: "a small type carrying a large message", message: `{"op":"ping","pad":"` +
			strings.Repeat("y", 100) + `"}`, refused: true},
		{name: "a server type sent by the client", message: `{"op":"tick"}`, refused: true},
		{name: "a type the route does not name", message: `{"op":"transfer"}`, refused: true},
		{name: "a text message that is not JSON", message: `hello`, refused: true},
		// A binary message carries no JSON member, so the type policy is
		// not about it: inspect: text is what says so, and a route that
		// wanted binary policed would say inspect: all and get the same
		// answer about a message that is not JSON either.
		{name: "a binary message", message: `{"op":"ping"}`, binary: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			op := byte(wsOpText)
			if c.binary {
				op = wsOpBinary
			}
			gotOp, payload, closeCode := wsSend(t, addr, wsFrame(op, []byte(c.message), true))
			if c.refused {
				if closeCode == 0 {
					t.Fatalf("the message was forwarded (op %d, %q)", gotOp, payload)
				}
				return
			}
			if closeCode != 0 {
				t.Fatalf("the message was refused with close code %d", closeCode)
			}
			if string(payload) != c.message {
				t.Errorf("echo %q, want %q", payload, c.message)
			}
		})
	}

	// The report says which type a route is arguing with, which is the
	// number an operator reads before changing a bound.
	st := s.WebSocketGuards()
	if len(st) != 1 {
		t.Fatalf("status = %+v", st)
	}
	if len(st[0].Types) != 3 || st[0].UnknownTypes != "deny" {
		t.Fatalf("types = %+v (unknown_types %q)", st[0].Types, st[0].UnknownTypes)
	}
	byName := map[string]uint64{}
	for _, ty := range st[0].Types {
		byName[ty.Name] = ty.Violations
	}
	if byName["chat"] < 3 {
		t.Errorf("chat has %d violations, want the three messages it refused", byName["chat"])
	}
	if byName["ping"] < 1 {
		t.Errorf("ping has %d violations, want the oversize one", byName["ping"])
	}
	if st[0].Unknown < 2 {
		t.Errorf("%d unknown-type messages, want the unnamed type and the one that was not JSON", st[0].Unknown)
	}
}

// An unknown type under observe is recorded and forwarded, because that is how
// a type list gets written: run for a week and read the events.
func TestAnUnknownTypeIsObservedBeforeItIsRefused(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, `    websocket_guard:
      type_field: op
      unknown_types: observe
      types: [{name: ping}]`)
	op, payload, closeCode := wsSend(t, s.Addrs()["main"], wsFrame(wsOpText, []byte(`{"op":"nope"}`), true))
	if closeCode != 0 {
		t.Fatalf("an observed message was refused with close code %d", closeCode)
	}
	if op != wsOpText || string(payload) != `{"op":"nope"}` {
		t.Fatalf("echo = %d %q", op, payload)
	}
	// Twice, because the policy is about the connection and not about the
	// client: the echo comes back as the same unnamed type and is observed
	// on the way out as well.
	st := s.WebSocketGuards()
	if len(st) != 1 || st[0].Unknown != 2 {
		t.Fatalf("status = %+v", st)
	}
	if st[0].Violations != 2 {
		t.Errorf("%d violations recorded, want the observation in each direction", st[0].Violations)
	}
	if st[0].Closed != 0 {
		t.Errorf("%d connections closed, want none: observing is not enforcing", st[0].Closed)
	}
}

// require_json is the other half of the type policy: on a route whose messages
// are JSON, one that is not is not a message the policy can read at all.
func TestRequireJSONRefusesWhatTheTypePolicyCannotRead(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, `    websocket_guard: {require_json: true}`)
	addr := s.Addrs()["main"]
	if _, _, code := wsSend(t, addr, wsFrame(wsOpText, []byte("hello"), true)); code == 0 {
		t.Error("a text message that is not JSON was forwarded")
	}
	if _, payload, code := wsSend(t, addr, wsFrame(wsOpText, []byte(`{"a":1}`), true)); code != 0 {
		t.Errorf("a JSON message was refused: %d %q", code, payload)
	}
}

// A per-type rate: the type that is cheap to send many of is the one with the
// bound, and the connection's own messages_per_second says nothing about which
// messages they were.
func TestAPerTypeRateBoundsOneKindOfMessage(t *testing.T) {
	origin := wsEcho(t, nil)
	s := wsProxy(t, origin.URL, `    websocket_guard:
      type_field: op
      unknown_types: allow
      types: [{name: subscribe, messages_per_second: 2}]`)
	c, br, code := wsDial(t, s.Addrs()["main"], "/chat", "")
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", code)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	refused := false
	for i := 0; i < 6 && !refused; i++ {
		if _, err := c.Write(wsFrame(wsOpText, []byte(`{"op":"subscribe"}`), true)); err != nil {
			refused = true
			break
		}
		op, _, err := wsRead(br)
		if err != nil || op == wsOpClose {
			refused = true
		}
	}
	if !refused {
		t.Error("six subscribes in a second passed a bound of two")
	}
}

// wsDeflateOrigin is an origin that answers an upgrade with the extension
// header the caller chose and then replies "ok" to every message, so a test
// reads what the policy did rather than what an echo did with it.
func wsDeflateOrigin(t *testing.T, accept string, offered *string) *httptest.Server {
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
		if accept != "" {
			resp += "Sec-WebSocket-Extensions: " + accept + "\r\n"
		}
		resp += "\r\n"
		_, _ = buf.WriteString(resp)
		_ = buf.Flush()
		for {
			if _, _, err := wsRead(buf.Reader); err != nil {
				return
			}
			if _, err := c.Write(wsFrame(wsOpText, []byte("ok"), false)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wsDeflateFrame builds one compressed text frame. RFC 7692 sends a raw
// DEFLATE stream with the empty block at its end removed, and marks the first
// frame of the message with RSV1.
func wsDeflateFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	comp := b.Bytes()
	if n := len(comp); n >= 4 && bytes.Equal(comp[n-4:], []byte{0x00, 0x00, 0xff, 0xff}) {
		comp = comp[:n-4]
	}
	f := wsFrame(wsOpText, comp, true)
	f[0] |= 0x40
	return f
}

// wsOfferDial opens an upgrade that offers permessage-deflate.
func wsOfferDial(t *testing.T, addr string) (net.Conn, int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req := "GET /chat HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(make([]byte, 16)) +
		"\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		_ = c.Close()
		t.Fatalf("reading the upgrade response: %v", err)
	}
	return c, resp.StatusCode
}

// Compression as a policy rather than as a silent downgrade.
func TestTheCompressionPolicyIsAChoice(t *testing.T) {
	t.Run("refuse answers the client rather than changing its offer", func(t *testing.T) {
		origin := wsDeflateOrigin(t, "", nil)
		s := wsProxy(t, origin.URL, `    websocket_guard: {compression: refuse}`)
		c, code := wsOfferDial(t, s.Addrs()["main"])
		defer func() { _ = c.Close() }()
		if code != http.StatusBadRequest {
			t.Errorf("upgrade status %d, want 400", code)
		}
		// And a client that offers nothing still works.
		c2, _, code := wsDial(t, s.Addrs()["main"], "/chat", "")
		defer func() { _ = c2.Close() }()
		if code != http.StatusSwitchingProtocols {
			t.Errorf("a client with no offer got %d", code)
		}
	})

	t.Run("inspect narrows the offer and reads the messages", func(t *testing.T) {
		var offered string
		origin := wsDeflateOrigin(t, "permessage-deflate; client_no_context_takeover; server_no_context_takeover", &offered)
		s := wsProxy(t, origin.URL, `    websocket_guard:
      compression: inspect
      deny_patterns: ["DROP TABLE"]`)
		addr := s.Addrs()["main"]
		c, code := wsOfferDial(t, addr)
		defer func() { _ = c.Close() }()
		if code != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade status %d", code)
		}
		if offered != wsDeflateOffer {
			t.Errorf("the origin was offered %q, want %q", offered, wsDeflateOffer)
		}
		br := bufio.NewReader(c)
		// An ordinary compressed message travels.
		if _, err := c.Write(wsDeflateFrame(t, []byte("hello there"))); err != nil {
			t.Fatal(err)
		}
		if op, payload, err := wsRead(br); err != nil || op != wsOpText || string(payload) != "ok" {
			t.Fatalf("the origin answered %d %q (%v)", op, payload, err)
		}
		// And the pattern inside a compressed message is found, which is
		// the whole point: without inflating it this is noise.
		if _, err := c.Write(wsDeflateFrame(t, []byte("x; DROP TABLE users"))); err != nil {
			t.Fatal(err)
		}
		op, payload, err := wsRead(br)
		if err == nil && op != wsOpClose {
			t.Fatalf("a compressed message carrying a denied pattern was forwarded: %d %q", op, payload)
		}
	})

	t.Run("a bomb is refused for what it would have cost", func(t *testing.T) {
		// The message inflates to a megabyte, which is well inside
		// max_message_bytes: what refuses it is the ratio, because a
		// kilobyte on the wire becoming a megabyte in the application is
		// the shape of the attack rather than the size of it.
		origin := wsDeflateOrigin(t, "permessage-deflate; client_no_context_takeover; server_no_context_takeover", nil)
		s := wsProxy(t, origin.URL, `    websocket_guard:
      compression: inspect
      max_frame_bytes: 65536
      max_inflate_ratio: 10`)
		c, code := wsOfferDial(t, s.Addrs()["main"])
		defer func() { _ = c.Close() }()
		if code != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade status %d", code)
		}
		br := bufio.NewReader(c)
		if _, err := c.Write(wsDeflateFrame(t, make([]byte, 1<<20))); err != nil {
			t.Fatal(err)
		}
		op, payload, err := wsRead(br)
		if err == nil && op != wsOpClose {
			t.Fatalf("a megabyte of zeroes in a kilobyte was forwarded: %d %q", op, payload)
		}
		if err == nil && len(payload) >= 2 {
			if code := binary.BigEndian.Uint16(payload[:2]); code != wsCloseTooBig {
				t.Errorf("close code %d, want %d", code, wsCloseTooBig)
			}
		}
		if st := s.WebSocketGuards(); len(st) != 1 || st[0].Violations == 0 {
			t.Errorf("status = %+v", st)
		}
	})

	t.Run("an acceptance the guard cannot read is refused at the 101", func(t *testing.T) {
		// Context takeover means a message is only readable by a decoder
		// that has seen every message before it. This proxy offered not
		// to, and an origin that accepted anyway is not speaking the
		// extension that was negotiated.
		origin := wsDeflateOrigin(t, "permessage-deflate", nil)
		s := wsProxy(t, origin.URL, `    websocket_guard: {compression: inspect}`)
		c, code := wsOfferDial(t, s.Addrs()["main"])
		defer func() { _ = c.Close() }()
		if code != http.StatusBadGateway {
			t.Errorf("upgrade status %d, want 502", code)
		}
	})
}

// What counts as the offer coming back.
func TestTheCompressionAcceptanceIsRead(t *testing.T) {
	for _, c := range []struct {
		header string
		ok     bool
	}{
		{"permessage-deflate; client_no_context_takeover; server_no_context_takeover", true},
		{"permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=12", true},
		{"permessage-deflate", false},
		{"permessage-deflate; client_no_context_takeover", false},
		{"permessage-deflate; client_no_context_takeover; server_no_context_takeover; x-private", false},
		{"permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits=7", false},
		{"x-webkit-deflate-frame", false},
	} {
		if ok, _ := wsDeflateAccepted(c.header); ok != c.ok {
			t.Errorf("wsDeflateAccepted(%q) = %v, want %v", c.header, ok, c.ok)
		}
	}
}

// And what inflation does with what it is given.
func TestInflationIsBounded(t *testing.T) {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.DefaultCompression)
	_, _ = w.Write(bytes.Repeat([]byte("a"), 1<<16))
	_ = w.Flush()
	comp := bytes.TrimSuffix(b.Bytes(), []byte{0x00, 0x00, 0xff, 0xff})

	prefix, total, err := wsInflate(comp, 32, 1<<20)
	if err != nil {
		t.Fatalf("inflating: %v", err)
	}
	if total != 1<<16 {
		t.Errorf("total = %d, want %d", total, 1<<16)
	}
	if len(prefix) != 32 {
		t.Errorf("kept %d bytes, want the 32 asked for", len(prefix))
	}
	// Past the bound it stops and says how far it got, rather than
	// inflating the whole thing to find out how large it was.
	_, total, err = wsInflate(comp, 32, 1024)
	if err != nil {
		t.Fatalf("inflating past the bound: %v", err)
	}
	if total <= 1024 || total > 1024+(32<<10) {
		t.Errorf("total = %d, want just past the 1024 byte bound", total)
	}
	if _, _, err := wsInflate([]byte("not deflate at all, really not"), 16, 1<<20); err == nil {
		t.Error("bytes that are not a DEFLATE stream inflated")
	}
}
