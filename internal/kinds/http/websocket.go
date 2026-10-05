package http

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
)

// WebSocket message inspection.
//
// An upgraded connection is the one place a request-oriented proxy
// stops looking. Everything before the 101 goes through routing, the
// WAF, the filters and the logs; everything after it is an opaque byte
// stream that happens to be travelling over a connection the proxy
// opened. Applications put their real API in there — chat, trading,
// terminals, GraphQL subscriptions — and a proxy that stops at the
// handshake is protecting the doorway of a building with no walls.
//
// This is a frame-level guard: the proxy parses RFC 6455 frames in both
// directions, enforces structure (opcodes, masking, fragmentation,
// control frame rules, UTF-8), enforces bounds (frame size, reassembled
// message size, message rate), and matches text messages against a
// pattern list. It never modifies a frame: a violation closes the
// connection with a close code that says why, or is logged, depending
// on the configured action.
//
// It deliberately does not reassemble unbounded messages for
// inspection. A message larger than max_inspect_bytes is checked up to
// that bound and passed on; anything else would make the proxy's memory
// a function of what a client chooses to send.

// WebSocket opcodes (RFC 6455 section 5.2).
const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// Close codes used by the guard (RFC 6455 section 7.4.1).
const (
	wsCloseProtocolError = 1002
	wsClosePolicy        = 1008
	wsCloseTooBig        = 1009
)

// wsGuard is a compiled routes[].websocket_guard.
type wsGuard struct {
	cfg        *config.WebSocketGuard
	opcodes    map[byte]bool
	deny       []*regexp.Regexp
	subprotos  map[string]bool
	inspectAll bool
	inspectTxt bool

	// Counters, per route, for the management view.
	connections atomic.Uint64
	messages    atomic.Uint64
	violations  atomic.Uint64
	closed      atomic.Uint64
}

func newWSGuard(c *config.WebSocketGuard) (*wsGuard, error) {
	if c == nil {
		return nil, nil
	}
	g := &wsGuard{cfg: c, opcodes: map[byte]bool{}}
	for _, name := range c.AllowOpcodes {
		op, ok := wsOpcodeByName(name)
		if !ok {
			return nil, errors.New("unknown websocket opcode " + name)
		}
		g.opcodes[op] = true
	}
	if len(c.AllowOpcodes) == 0 {
		// The default set: everything a normal application uses.
		for _, op := range []byte{wsOpText, wsOpBinary, wsOpClose, wsOpPing, wsOpPong} {
			g.opcodes[op] = true
		}
	}
	// Continuation is implied by allowing a data opcode; refusing it
	// would break every fragmented message.
	g.opcodes[wsOpContinuation] = true
	for _, p := range c.DenyPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		g.deny = append(g.deny, re)
	}
	if len(c.AllowSubprotocols) > 0 {
		g.subprotos = map[string]bool{}
		for _, sp := range c.AllowSubprotocols {
			g.subprotos[strings.ToLower(sp)] = true
		}
	}
	switch c.Inspect {
	case "all":
		g.inspectAll, g.inspectTxt = true, true
	case "text", "":
		g.inspectTxt = true
	case "none":
	}
	return g, nil
}

func wsOpcodeByName(s string) (byte, bool) {
	switch strings.ToLower(s) {
	case "text":
		return wsOpText, true
	case "binary":
		return wsOpBinary, true
	case "close":
		return wsOpClose, true
	case "ping":
		return wsOpPing, true
	case "pong":
		return wsOpPong, true
	case "continuation":
		return wsOpContinuation, true
	}
	return 0, false
}

func wsOpcodeName(op byte) string {
	switch op {
	case wsOpContinuation:
		return "continuation"
	case wsOpText:
		return "text"
	case wsOpBinary:
		return "binary"
	case wsOpClose:
		return "close"
	case wsOpPing:
		return "ping"
	case wsOpPong:
		return "pong"
	}
	return "opcode-" + strconv.Itoa(int(op))
}

// subprotocolAllowed checks what the origin negotiated. An application
// that speaks several subprotocols on one route is several APIs, and
// the list is how an operator says which of them this route is for. An
// empty list allows any, including none.
func (g *wsGuard) subprotocolAllowed(sp string) (string, bool) {
	if g.subprotos == nil {
		return sp, true
	}
	sp = strings.TrimSpace(sp)
	if sp == "" {
		// The origin chose no subprotocol while the route names the
		// ones it expects: that is not one of them.
		return "(none)", false
	}
	return sp, g.subprotos[strings.ToLower(sp)]
}

// wsViolation is what the guard found.
type wsViolation struct {
	reason string
	detail string
	code   int
}

func (v *wsViolation) Error() string { return "websocket " + v.reason + ": " + v.detail }

// wsSide parses one direction of a connection. The two directions have
// different rules: client frames must be masked and server frames must
// not be (RFC 6455 sections 5.1 and 5.3), and only the client's rate is
// bounded, since the server is the estate's own application.
type wsSide struct {
	g          *wsGuard
	fromClient bool

	// Reassembly state for the message being built.
	fragOpcode byte
	fragging   bool
	fragBytes  int64
	// inspect holds the prefix of the current message kept for pattern
	// matching, bounded by max_inspect_bytes.
	inspect []byte

	// Rate accounting over a one second window.
	windowStart time.Time
	windowCount int
}

// wsConn wraps the hijacked client connection. Reads carry frames from
// the client and writes carry frames to it, so one wrapper sees both
// directions of the conversation the reverse proxy is splicing.
type wsConn struct {
	net.Conn
	g  *wsGuard
	st *reqState
	s  *engine

	mu       sync.Mutex
	fromCli  *wsSide
	fromSrv  *wsSide
	closed   bool
	closeErr error

	// readBuf and writeBuf hold bytes that arrived split across calls:
	// a frame header can straddle any boundary, so the guard buffers
	// until it can parse.
	readBuf   []byte
	readHold  []byte
	readReady []byte
	readErr   error
	writeBuf  []byte
}

// maxPendingFrame bounds the header-and-payload buffer the guard keeps
// while a frame is incomplete. It is the frame bound plus a header.
func (c *wsConn) maxPending() int64 { return c.g.cfg.MaxFrameBytes + 16 }

// maxHeld bounds the complete frame bytes retained while an enforcing guard
// waits for a fragmented message to finish. MaxMessageBytes only counts
// payload, so leave room for one maximum-sized frame of wire overhead while
// independently bounding empty fragments and interleaved control frames.
func (c *wsConn) maxHeld() int64 { return c.g.cfg.MaxMessageBytes + c.maxPending() }

func (s *engine) newWSConn(inner net.Conn, g *wsGuard, st *reqState) net.Conn {
	g.connections.Add(1)
	return &wsConn{Conn: inner, g: g, st: st, s: s,
		fromCli: &wsSide{g: g, fromClient: true},
		fromSrv: &wsSide{g: g}}
}

func (c *wsConn) Read(p []byte) (int, error) {
	if c.g.cfg.Action != "log" {
		return c.readEnforced(p)
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		if verr := c.scan(&c.readBuf, p[:n], c.fromCli); verr != nil {
			return n, c.fail(verr)
		}
	}
	return n, err
}

// readEnforced does not expose client bytes until the complete message that
// contains them has passed inspection. In particular, returning rejected
// bytes together with an error is not sufficient: io.Copy writes a positive
// byte count before it observes the error.
func (c *wsConn) readEnforced(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.readReady) > 0 {
			n := copy(p, c.readReady)
			c.readReady = c.readReady[n:]
			c.mu.Unlock()
			return n, nil
		}
		if c.closed {
			err := c.closeErr
			c.mu.Unlock()
			return 0, err
		}
		if len(c.readBuf) > 0 {
			consumed, violation := c.fromCli.parse(c.readBuf, c)
			if violation != nil {
				c.readBuf = nil
				c.readHold = nil
				c.mu.Unlock()
				return 0, c.fail(violation)
			}
			if consumed > 0 {
				if int64(len(c.readHold))+int64(consumed) > c.maxHeld() {
					c.readBuf = nil
					c.readHold = nil
					c.mu.Unlock()
					return 0, c.fail(&wsViolation{"message_size", "fragmented message wire data over max_message_bytes", wsCloseTooBig})
				}
				c.readHold = append(c.readHold, c.readBuf[:consumed]...)
				c.readBuf = c.readBuf[consumed:]
				if !c.fromCli.fragging {
					c.readReady = append(c.readReady, c.readHold...)
					c.readHold = nil
				}
				c.mu.Unlock()
				continue
			}
			if int64(len(c.readBuf)) > c.maxPending() {
				c.readBuf = nil
				c.readHold = nil
				c.mu.Unlock()
				return 0, c.fail(&wsViolation{"frame_size", "a frame header or payload larger than max_frame_bytes", wsCloseTooBig})
			}
		}
		if c.readErr != nil {
			err := c.readErr
			c.readErr = nil
			c.mu.Unlock()
			return 0, err
		}
		c.mu.Unlock()

		// It is safe to use p as scratch space: no bytes are reported to
		// the caller until they have moved through readReady.
		n, err := c.Conn.Read(p)
		c.mu.Lock()
		c.readBuf = append(c.readBuf, p[:n]...)
		if err != nil {
			c.readErr = err
		}
		c.mu.Unlock()
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	if verr := c.scan(&c.writeBuf, p, c.fromSrv); verr != nil {
		if err := c.fail(verr); err != nil {
			// The offending frame is not forwarded: the close went to
			// the client instead, so it never sees what was refused.
			return 0, err
		}
		// Log mode: recorded, and forwarded unchanged. Returning a
		// short write here would abort the copy and close the
		// connection, which is exactly what log mode promises not to do.
	}
	return c.Conn.Write(p)
}

// scan appends new bytes to a direction's buffer and parses as many
// whole frames as it can.
func (c *wsConn) scan(buf *[]byte, data []byte, side *wsSide) *wsViolation {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	*buf = append(*buf, data...)
	for {
		consumed, v := side.parse(*buf, c)
		if v != nil {
			return v
		}
		if consumed == 0 {
			break
		}
		*buf = (*buf)[consumed:]
	}
	if int64(len(*buf)) > c.maxPending() {
		return &wsViolation{"frame_size", "a frame header or payload larger than max_frame_bytes", wsCloseTooBig}
	}
	return nil
}

// parse reads one frame from the front of b. It returns how many bytes
// it consumed (0 when the frame is not complete yet).
func (s *wsSide) parse(b []byte, c *wsConn) (int, *wsViolation) {
	if len(b) < 2 {
		return 0, nil
	}
	fin := b[0]&0x80 != 0
	rsv := b[0] & 0x70
	opcode := b[0] & 0x0f
	masked := b[1]&0x80 != 0
	length := int64(b[1] & 0x7f)
	off := 2
	switch length {
	case 126:
		if len(b) < off+2 {
			return 0, nil
		}
		length = int64(binary.BigEndian.Uint16(b[off:]))
		off += 2
	case 127:
		if len(b) < off+8 {
			return 0, nil
		}
		v := binary.BigEndian.Uint64(b[off:])
		if v > 1<<62 {
			return 0, &wsViolation{"protocol", "a frame length that is not a length", wsCloseProtocolError}
		}
		length = int64(v) //nolint:gosec // bounded above
		off += 8
	}
	if masked {
		off += 4
	}
	// The structural checks happen before the payload has arrived, so a
	// client cannot make the proxy hold a refused frame's bytes.
	if v := s.checkHeader(fin, rsv, opcode, masked, length); v != nil {
		return 0, v
	}
	if int64(len(b)) < int64(off)+length {
		return 0, nil
	}
	payload := b[off : int64(off)+length]
	if masked {
		key := b[off-4 : off]
		unmasked := make([]byte, len(payload))
		for i := range payload {
			unmasked[i] = payload[i] ^ key[i%4]
		}
		payload = unmasked
	}
	if v := s.checkPayload(fin, opcode, payload, c); v != nil {
		return 0, v
	}
	return off + len(payload), nil
}

// checkHeader applies the rules that need only the header.
func (s *wsSide) checkHeader(fin bool, rsv, opcode byte, masked bool, length int64) *wsViolation {
	g := s.g
	if rsv != 0 {
		// A reserved bit means an extension was negotiated. The proxy
		// does not negotiate extensions, so a peer setting one is
		// either confused or trying to make the frames mean something
		// the guard does not read (permessage-deflate is the usual
		// one, and a compressed frame cannot be inspected).
		return &wsViolation{"protocol", "reserved bits set without a negotiated extension", wsCloseProtocolError}
	}
	if opcode >= 0x3 && opcode <= 0x7 || opcode >= 0xB {
		return &wsViolation{"protocol", "reserved opcode " + wsOpcodeName(opcode), wsCloseProtocolError}
	}
	if !g.opcodes[opcode] {
		return &wsViolation{"opcode", wsOpcodeName(opcode) + " is not allowed on this route", wsClosePolicy}
	}
	if g.cfg.Masked() {
		if s.fromClient && !masked {
			// RFC 6455 5.1: a client frame must be masked. An unmasked
			// one is how a request is smuggled past an intermediary
			// that caches on frame boundaries.
			return &wsViolation{"protocol", "an unmasked frame from the client", wsCloseProtocolError}
		}
		if !s.fromClient && masked {
			return &wsViolation{"protocol", "a masked frame from the server", wsCloseProtocolError}
		}
	}
	if length > g.cfg.MaxFrameBytes {
		return &wsViolation{"frame_size", "frame of " + strconv.FormatInt(length, 10) + " bytes", wsCloseTooBig}
	}
	isControl := opcode&0x8 != 0
	if isControl {
		if !fin {
			return &wsViolation{"protocol", "a fragmented control frame", wsCloseProtocolError}
		}
		if length > 125 {
			return &wsViolation{"protocol", "a control frame over 125 bytes", wsCloseProtocolError}
		}
		return nil
	}
	// Data frames: fragmentation must be well formed.
	if opcode == wsOpContinuation && !s.fragging {
		return &wsViolation{"protocol", "a continuation frame with nothing to continue", wsCloseProtocolError}
	}
	if opcode != wsOpContinuation && s.fragging {
		return &wsViolation{"protocol", "a new message before the previous one finished", wsCloseProtocolError}
	}
	if s.fragBytes+length > g.cfg.MaxMessageBytes {
		return &wsViolation{"message_size", "a message over max_message_bytes", wsCloseTooBig}
	}
	return nil
}

// checkPayload applies the rules that need the bytes.
func (s *wsSide) checkPayload(fin bool, opcode byte, payload []byte, c *wsConn) *wsViolation {
	g := s.g
	if opcode&0x8 != 0 {
		if opcode == wsOpClose && len(payload) > 0 {
			if len(payload) < 2 {
				return &wsViolation{"protocol", "a close frame with one byte of status", wsCloseProtocolError}
			}
			code := binary.BigEndian.Uint16(payload[:2])
			if !wsValidCloseCode(code) {
				return &wsViolation{"protocol", "close code " + strconv.Itoa(int(code)), wsCloseProtocolError}
			}
			if !utf8.Valid(payload[2:]) {
				return &wsViolation{"protocol", "a close reason that is not UTF-8", wsCloseProtocolError}
			}
		}
		return nil
	}
	// A data frame: track the message being assembled.
	if opcode != wsOpContinuation {
		s.fragOpcode = opcode
		s.inspect = s.inspect[:0]
	}
	s.fragging = !fin
	s.fragBytes += int64(len(payload))
	wantText := s.fragOpcode == wsOpText
	if (g.inspectAll || (g.inspectTxt && wantText)) && int64(len(s.inspect)) < g.cfg.MaxInspectBytes {
		room := g.cfg.MaxInspectBytes - int64(len(s.inspect))
		if int64(len(payload)) < room {
			room = int64(len(payload))
		}
		s.inspect = append(s.inspect, payload[:room]...)
	}
	if !fin {
		return nil
	}
	// The message is complete.
	defer func() {
		s.fragBytes = 0
		s.fragging = false
	}()
	g.messages.Add(1)
	c.s.stats.WSMessages.Add(1)
	if s.fromClient {
		if v := s.rate(); v != nil {
			return v
		}
	}
	if wantText && g.cfg.UTF8() && !utf8.Valid(s.inspect) && s.fragBytes <= g.cfg.MaxInspectBytes {
		// Only when the whole message was inspected: a prefix of a
		// valid UTF-8 message can end mid-rune.
		return &wsViolation{"protocol", "a text message that is not UTF-8", wsCloseProtocolError}
	}
	if len(g.deny) > 0 && (g.inspectAll || wantText) {
		for _, re := range g.deny {
			if re.Match(s.inspect) {
				return &wsViolation{"pattern", "a message matching a denied pattern", wsClosePolicy}
			}
		}
	}
	return nil
}

// rate bounds how many messages a client may send per second.
func (s *wsSide) rate() *wsViolation {
	if s.g.cfg.MessagesPerSecond <= 0 {
		return nil
	}
	now := time.Now()
	if now.Sub(s.windowStart) >= time.Second {
		s.windowStart, s.windowCount = now, 0
	}
	s.windowCount++
	if s.windowCount > s.g.cfg.MessagesPerSecond {
		return &wsViolation{"rate", "more than messages_per_second from the client", wsClosePolicy}
	}
	return nil
}

// wsValidCloseCode implements RFC 6455 section 7.4.1 and the IANA
// registry. 1004 was never defined, and 1005, 1006 and 1015 are
// produced locally by an endpoint and must never appear on the wire —
// a peer sending one is claiming a condition only the receiver can
// observe.
func wsValidCloseCode(code uint16) bool {
	switch code {
	case 1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014:
		return true
	}
	// 3000-3999 are registered by libraries, 4000-4999 are private.
	return code >= 3000 && code <= 4999
}

// fail records a violation, tries to tell the peer why, and closes.
func (c *wsConn) fail(v *wsViolation) error {
	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	c.closed = true
	c.closeErr = v
	c.mu.Unlock()

	g := c.g
	g.violations.Add(1)
	c.s.stats.WSViolations.Add(1)
	route := ""
	if c.st != nil {
		route = c.st.route
	}
	c.s.logs.SecurityEvent(nil, "websocket", "websocket", //nolint:staticcheck // no request context on a hijacked connection
		"route", route, "client_ip", netutil.PeerAddr(c.Conn.RemoteAddr()).String(),
		"reason", v.reason, "detail", v.detail, "close_code", v.code)
	if g.cfg.Action == "log" {
		// Observation only: the connection continues and the frame is
		// forwarded. The counter and the event are the product.
		c.mu.Lock()
		c.closed = false
		c.closeErr = nil
		c.mu.Unlock()
		return nil
	}
	g.closed.Add(1)
	c.s.stats.WSClosed.Add(1)
	code := v.code
	if g.cfg.CloseCode > 0 {
		code = g.cfg.CloseCode
	}
	// A close frame from the proxy is unmasked (it is the server here)
	// and carries the code, so the client logs something meaningful
	// rather than a reset.
	frame := []byte{0x88, 2, byte(code >> 8), byte(code)} //nolint:gosec // a close code is 16 bits
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	// Written through the embedded connection, not this wrapper: the
	// wrapper would scan the close frame it is itself sending.
	_, _ = c.Conn.Write(frame)
	_ = c.Close()
	return v
}

var _ io.ReadWriter = (*wsConn)(nil)

// WebSocketGuards reports the inspected routes.
func (s *engine) WebSocketGuards() []proxy.WSGuardStatus {
	rt := s.rt.Load()
	out := make([]proxy.WSGuardStatus, 0, 4)
	for _, cr := range rt.routes {
		if cr.wsGuard == nil {
			continue
		}
		g := cr.wsGuard
		out = append(out, proxy.WSGuardStatus{Route: cr.cfg.Name, Connections: g.connections.Load(),
			Messages: g.messages.Load(), Violations: g.violations.Load(),
			Closed: g.closed.Load(), Action: g.cfg.Action})
	}
	return out
}
