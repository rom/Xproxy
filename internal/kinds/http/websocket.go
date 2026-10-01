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
	// types is the message-type policy, nil where the route names none.
	types *wsTypes

	// Counters, per route, for the management view.
	connections atomic.Uint64
	messages    atomic.Uint64
	violations  atomic.Uint64
	closed      atomic.Uint64
	// unknown counts the messages whose type the route does not name,
	// whatever unknown_types then does about them: on a route that
	// allows them it is the number that says a type list is incomplete.
	unknown atomic.Uint64
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
	t, err := newWSTypes(c)
	if err != nil {
		return nil, err
	}
	g.types = t
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
	// observe marks a finding that is recorded and then forwarded
	// whatever the route's action is: unknown_types: observe is how a
	// type list gets written, and a list being written must not be a
	// list being enforced.
	observe bool
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
	// matching, bounded by max_inspect_bytes. For a compressed message
	// it holds the inflated prefix, because that is the message.
	inspect []byte
	// deflate says permessage-deflate was negotiated on terms this guard
	// can read, so RSV1 on the first frame of a message means compressed
	// rather than "an extension nobody agreed".
	deflate bool
	// rsv1 is the compression bit of the frame being parsed, and
	// compressed whether the message being assembled carries it. comp
	// holds a compressed message's bytes until it is complete, because a
	// DEFLATE stream cannot be inflated a frame at a time and stay
	// bounded.
	rsv1       bool
	compressed bool
	comp       []byte

	// Rate accounting over a one second window, for the connection and
	// then per message type.
	window     wsWindow
	typeWindow map[string]*wsWindow
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

func (s *engine) newWSConn(inner net.Conn, g *wsGuard, st *reqState) net.Conn {
	g.connections.Add(1)
	// Whether the origin accepted this proxy's compression offer, which
	// ModifyResponse decided on the 101 and checked before the client was
	// told it had a connection.
	deflate := st != nil && st.wsDeflate
	return &wsConn{Conn: inner, g: g, st: st, s: s,
		fromCli: &wsSide{g: g, fromClient: true, deflate: deflate},
		fromSrv: &wsSide{g: g, deflate: deflate}}
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
				return 0, c.fail(&wsViolation{reason: "frame_size", detail: "a frame header or payload larger than max_frame_bytes", code: wsCloseTooBig})
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
		return &wsViolation{reason: "frame_size", detail: "a frame header or payload larger than max_frame_bytes", code: wsCloseTooBig}
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
			return 0, &wsViolation{reason: "protocol", detail: "a frame length that is not a length", code: wsCloseProtocolError}
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
		if !v.observe {
			return 0, v
		}
		// Recorded where every finding is recorded, and then the message
		// travels on: this is the frame the policy is still learning
		// about rather than the one it has decided about.
		c.record(v)
	}
	return off + len(payload), nil
}

// checkHeader applies the rules that need only the header.
func (s *wsSide) checkHeader(fin bool, rsv, opcode byte, masked bool, length int64) *wsViolation {
	g := s.g
	if rsv&0x30 != 0 {
		// RSV2 and RSV3 belong to extensions nothing here negotiates, so
		// a peer setting one is either confused or trying to make the
		// frames mean something the guard does not read.
		return &wsViolation{reason: "protocol", detail: "reserved bits set without a negotiated extension", code: wsCloseProtocolError}
	}
	s.rsv1 = rsv&0x40 != 0
	if s.rsv1 {
		if !s.deflate {
			// permessage-deflate is the usual one, and a compressed
			// frame cannot be inspected -- which is why a route that
			// wants to inspect either strips the offer or negotiates
			// terms it can read. Neither of those happened here.
			return &wsViolation{reason: "protocol", detail: "reserved bits set without a negotiated extension", code: wsCloseProtocolError}
		}
		if opcode&0x8 != 0 || opcode == wsOpContinuation {
			// RFC 7692 puts the compression bit on the first frame of a
			// message and nowhere else.
			return &wsViolation{reason: "compression", detail: "RSV1 on a " + wsOpcodeName(opcode) + " frame", code: wsCloseProtocolError}
		}
	}
	if opcode >= 0x3 && opcode <= 0x7 || opcode >= 0xB {
		return &wsViolation{reason: "protocol", detail: "reserved opcode " + wsOpcodeName(opcode), code: wsCloseProtocolError}
	}
	if !g.opcodes[opcode] {
		return &wsViolation{reason: "opcode", detail: wsOpcodeName(opcode) + " is not allowed on this route", code: wsClosePolicy}
	}
	if g.cfg.Masked() {
		if s.fromClient && !masked {
			// RFC 6455 5.1: a client frame must be masked. An unmasked
			// one is how a request is smuggled past an intermediary
			// that caches on frame boundaries.
			return &wsViolation{reason: "protocol", detail: "an unmasked frame from the client", code: wsCloseProtocolError}
		}
		if !s.fromClient && masked {
			return &wsViolation{reason: "protocol", detail: "a masked frame from the server", code: wsCloseProtocolError}
		}
	}
	if length > g.cfg.MaxFrameBytes {
		return &wsViolation{reason: "frame_size", detail: "frame of " + strconv.FormatInt(length, 10) + " bytes", code: wsCloseTooBig}
	}
	isControl := opcode&0x8 != 0
	if isControl {
		if !fin {
			return &wsViolation{reason: "protocol", detail: "a fragmented control frame", code: wsCloseProtocolError}
		}
		if length > 125 {
			return &wsViolation{reason: "protocol", detail: "a control frame over 125 bytes", code: wsCloseProtocolError}
		}
		return nil
	}
	// Data frames: fragmentation must be well formed.
	if opcode == wsOpContinuation && !s.fragging {
		return &wsViolation{reason: "protocol", detail: "a continuation frame with nothing to continue", code: wsCloseProtocolError}
	}
	if opcode != wsOpContinuation && s.fragging {
		return &wsViolation{reason: "protocol", detail: "a new message before the previous one finished", code: wsCloseProtocolError}
	}
	if s.fragBytes+length > g.cfg.MaxMessageBytes {
		return &wsViolation{reason: "message_size", detail: "a message over max_message_bytes", code: wsCloseTooBig}
	}
	return nil
}

// checkPayload applies the rules that need the bytes.
func (s *wsSide) checkPayload(fin bool, opcode byte, payload []byte, c *wsConn) *wsViolation {
	g := s.g
	if opcode&0x8 != 0 {
		if opcode == wsOpClose && len(payload) > 0 {
			if len(payload) < 2 {
				return &wsViolation{reason: "protocol", detail: "a close frame with one byte of status", code: wsCloseProtocolError}
			}
			code := binary.BigEndian.Uint16(payload[:2])
			if !wsValidCloseCode(code) {
				return &wsViolation{reason: "protocol", detail: "close code " + strconv.Itoa(int(code)), code: wsCloseProtocolError}
			}
			if !utf8.Valid(payload[2:]) {
				return &wsViolation{reason: "protocol", detail: "a close reason that is not UTF-8", code: wsCloseProtocolError}
			}
		}
		return nil
	}
	// A data frame: track the message being assembled.
	if opcode != wsOpContinuation {
		s.fragOpcode = opcode
		s.inspect = s.inspect[:0]
		s.compressed = s.rsv1
		s.comp = s.comp[:0]
	}
	s.fragging = !fin
	s.fragBytes += int64(len(payload))
	wantText := s.fragOpcode == wsOpText
	keep := g.inspectAll || (g.inspectTxt && wantText)
	switch {
	case keep && s.compressed:
		s.comp = append(s.comp, payload...)
	case keep && int64(len(s.inspect)) < g.cfg.MaxInspectBytes:
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
		s.comp = s.comp[:0]
	}()
	g.messages.Add(1)
	c.s.stats.WSMessages.Add(1)
	if s.fromClient {
		if v := s.rate(); v != nil {
			return v
		}
	}
	if keep && s.compressed {
		// Everything below reads a message, so a compressed one becomes
		// a message here or the checks below are about nothing.
		if v := s.inflate(); v != nil {
			return v
		}
	}
	if wantText && g.cfg.UTF8() && !utf8.Valid(s.inspect) && s.fragBytes <= g.cfg.MaxInspectBytes {
		// Only when the whole message was inspected: a prefix of a
		// valid UTF-8 message can end mid-rune.
		return &wsViolation{reason: "protocol", detail: "a text message that is not UTF-8", code: wsCloseProtocolError}
	}
	if len(g.deny) > 0 && (g.inspectAll || wantText) {
		for _, re := range g.deny {
			if re.Match(s.inspect) {
				return &wsViolation{reason: "pattern", detail: "a message matching a denied pattern", code: wsClosePolicy}
			}
		}
	}
	return s.checkMessage(wantText)
}

// inflate turns the compressed message this side collected into the inspected
// prefix, and refuses one that expands past what the route allows.
//
// The bound is the smaller of max_message_bytes and max_inflate_ratio times
// what arrived, so a message that is small on the wire and enormous once read
// is refused for what it would have cost rather than passed for what it did.
func (s *wsSide) inflate() *wsViolation {
	g := s.g
	limit := g.cfg.MaxMessageBytes
	if ratio := int64(g.cfg.MaxInflateRatio) * int64(len(s.comp)); ratio < limit {
		limit = ratio
	}
	prefix, total, err := wsInflate(s.comp, g.cfg.MaxInspectBytes, limit)
	if err != nil {
		return &wsViolation{reason: "compression", detail: "a compressed message that does not inflate", code: wsCloseProtocolError}
	}
	if total > limit {
		return &wsViolation{reason: "compression_bomb", detail: strconv.FormatInt(int64(len(s.comp)), 10) +
			" compressed bytes inflating past " + strconv.FormatInt(limit, 10), code: wsCloseTooBig}
	}
	s.inspect = prefix
	// What the rest of the policy is about is the message the application
	// will see, not the bytes that carried it.
	s.fragBytes = total
	return nil
}

// rate bounds how many messages a client may send per second.
func (s *wsSide) rate() *wsViolation {
	if s.g.cfg.MessagesPerSecond <= 0 {
		return nil
	}
	if !s.window.allow(s.g.cfg.MessagesPerSecond) {
		return &wsViolation{reason: "rate", detail: "more than messages_per_second from the client", code: wsClosePolicy}
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

// record counts a finding and says what it was, without deciding anything.
// Every violation goes through here, including the ones nothing is done
// about, so that "the guard saw this" is one code path and one event shape.
func (c *wsConn) record(v *wsViolation) {
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
	c.record(v)
	if g.cfg.Action == "log" || v.observe {
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
		st := proxy.WSGuardStatus{Route: cr.cfg.Name, Connections: g.connections.Load(),
			Messages: g.messages.Load(), Violations: g.violations.Load(),
			Closed: g.closed.Load(), Action: g.cfg.Action,
			Compression: g.cfg.Compression, Unknown: g.unknown.Load()}
		if g.types != nil {
			st.UnknownTypes = g.types.unknown
			for _, t := range g.types.order {
				st.Types = append(st.Types, proxy.WSTypeStatus{Name: t.name,
					Messages: t.messages.Load(), Violations: t.violations.Load(),
					MaxBytes: t.maxBytes, MessagesPerSecond: t.perSecond,
					Direction: t.direction(), Schema: t.schema != nil})
			}
		}
		out = append(out, st)
	}
	return out
}
