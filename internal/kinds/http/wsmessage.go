package http

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/jsonschema"
	"github.com/rom/xproxy/internal/textsafe"
)

// The message policy of an upgraded connection: what kinds of message a route
// carries, how large and how often each of them may be, what shape each must
// have, and what happens to compression.
//
// The frame guard beside this answers "is this a well-formed WebSocket, and is
// it within these bounds". That is the protocol's own question and it is the
// same on every route. The question an application's owner actually has is a
// different one: this connection carries eight kinds of message, one of them
// places orders and one of them is a keepalive, and the bounds that are right
// for the keepalive are nowhere near the bounds that are right for the order.
// A single max_message_bytes for the connection is the bound of its largest
// message, which is the bound that lets every other message be that large too.
//
// So a route may name its message types, and say for each of them how large it
// may be, how often it may arrive, which direction it travels in and -- where
// the messages are JSON, which on a WebSocket API they almost always are -- the
// schema it must match. A message whose type the route does not name is the
// interesting one, and unknown_types says what happens to it.
//
// # What it costs, and where it decides
//
// A type is read from the message, so it is known when the message is complete
// and not before. For the client's messages that is still before anything
// reaches the origin: the frame guard already holds a client message until the
// whole of it has passed inspection, so a per-type bound refuses the message
// rather than reporting it. In the other direction the proxy forwards each
// frame as it is checked, so a bound on a fragmented message from the origin is
// found at the end of it -- the connection closes, and what had already been
// written has gone. That asymmetry is in the documentation rather than in a
// comment here, because it changes what a rule is worth.
//
// A schema needs the whole message, and the guard keeps only max_inspect_bytes
// of it. A message under a schema that is longer than that cannot be validated,
// so it is a violation rather than a pass: a check that silently stops applying
// above a size an attacker chooses is not a check. Validation says so when a
// type's max_bytes is larger than max_inspect_bytes, where that is certain
// rather than possible.

// Message-type policy for an unknown type.
const (
	wsUnknownAllow   = "allow"
	wsUnknownObserve = "observe"
	wsUnknownDeny    = "deny"
)

// What a route does about permessage-deflate. The third answer, strip, needs no
// name here: it is the default, and it is what happens to an offer neither of
// these asked about -- the offer is removed and both ends fall back to
// uncompressed frames, which is the only state in which everything is readable
// without being inflated.
const (
	// wsCompressRefuse answers the upgrade rather than quietly changing
	// what the client asked for.
	wsCompressRefuse = "refuse"
	// wsCompressInspect negotiates compression on terms this proxy can
	// read and inflates each message before inspecting it.
	wsCompressInspect = "inspect"
)

// wsDeflateOffer is the offer this proxy makes to the origin when it is going
// to read compressed messages.
//
// The no-context-takeover parameters are the whole point: with context takeover
// the DEFLATE stream carries its dictionary from one message into the next, so
// a message can only be inflated by a decoder that has seen every message
// before it -- and a proxy that holds that state per direction per connection
// has agreed to do unbounded work on behalf of whoever opened the connection.
// Without takeover each message is a self-contained DEFLATE stream, which is
// what makes inspecting one cheap and stateless.
const wsDeflateOffer = "permessage-deflate; client_no_context_takeover; server_no_context_takeover"

// wsDeflateTail is the empty stored block RFC 7692 strips from the end of a
// compressed message and that a DEFLATE reader needs to see.
var wsDeflateTail = []byte{0x00, 0x00, 0xff, 0xff}

// wsDeflateAccepted reads the origin's Sec-WebSocket-Extensions and says
// whether what it accepted is what was offered.
//
// An acceptance this proxy cannot read is refused at the 101 rather than at the
// first frame: the client has not been told it has a connection yet, and a
// stream of messages that cannot be inflated is a guard that would have to
// choose between closing every connection and inspecting nothing.
func wsDeflateAccepted(h string) (ok bool, why string) {
	parts := strings.Split(h, ";")
	if !strings.EqualFold(strings.TrimSpace(parts[0]), "permessage-deflate") {
		return false, "not permessage-deflate"
	}
	var client, server bool
	for _, p := range parts[1:] {
		name, value, _ := strings.Cut(strings.TrimSpace(p), "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "client_no_context_takeover":
			client = true
		case "server_no_context_takeover":
			server = true
		case "client_max_window_bits", "server_max_window_bits":
			// A smaller window is a smaller dictionary, which a reader
			// with the largest window reads without being told.
			if value != "" {
				if n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(value), `"`)); err != nil || n < 8 || n > 15 {
					return false, "window bits " + textsafe.Clip64(value)
				}
			}
		default:
			return false, "parameter " + textsafe.Clip64(name)
		}
	}
	if !client || !server {
		// The origin kept context takeover on one side or both, which
		// means its messages are only readable in order by a decoder
		// that keeps that state. This proxy offered not to.
		return false, "context takeover was not declined in both directions"
	}
	return true, ""
}

// errInflate is a compressed message that is not a DEFLATE stream.
var errInflate = errors.New("websocket: a compressed message that does not inflate")

// wsInflate inflates one permessage-deflate message.
//
// It returns the first keep bytes of the result for inspection and the total
// size of it, reading no more than maxOut: a bomb is a small message that
// inflates to whatever the sender chose, and a guard that inflated it to find
// out how large it was would be the thing the bomb was aimed at. Past maxOut it
// stops and says how far it got, which is all the caller needs to refuse.
func wsInflate(comp []byte, keep, maxOut int64) (prefix []byte, total int64, err error) {
	r := flate.NewReader(io.MultiReader(bytes.NewReader(comp), bytes.NewReader(wsDeflateTail)))
	defer func() { _ = r.Close() }()
	buf := make([]byte, 32<<10)
	for total <= maxOut {
		n, rerr := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if room := keep - int64(len(prefix)); room > 0 {
				if int64(n) < room {
					room = int64(n)
				}
				prefix = append(prefix, buf[:room]...)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
				// A message ends where its empty block was stripped, so
				// an unexpected EOF here is the end of the message and
				// not a truncated stream.
				return prefix, total, nil
			}
			return prefix, total, errInflate
		}
	}
	return prefix, total, nil
}

// wsTypePolicy is one entry of websocket_guard.types, compiled.
type wsTypePolicy struct {
	name      string
	maxBytes  int64
	perSecond int
	schema    *jsonschema.Validator
	root      map[string]any
	client    bool
	server    bool

	messages   atomic.Uint64
	violations atomic.Uint64
}

// wsTypes is a route's compiled message-type policy.
type wsTypes struct {
	field       string
	requireJSON bool
	unknown     string
	byName      map[string]*wsTypePolicy
	// order keeps the configured order for the status view, so a report
	// reads like the configuration rather than like a map.
	order []*wsTypePolicy
}

// newWSTypes compiles the message-type policy, nil where the route has none.
func newWSTypes(c *config.WebSocketGuard) (*wsTypes, error) {
	if c == nil || (len(c.Types) == 0 && !c.JSONRequired()) {
		return nil, nil
	}
	t := &wsTypes{field: c.TypeField, requireJSON: c.JSONRequired(),
		unknown: c.UnknownTypes, byName: map[string]*wsTypePolicy{}}
	if t.unknown == "" {
		t.unknown = wsUnknownAllow
	}
	for i := range c.Types {
		mt := &c.Types[i]
		p := &wsTypePolicy{name: mt.Name, maxBytes: mt.MaxBytes, perSecond: mt.MessagesPerSecond}
		switch mt.Direction {
		case "client":
			p.client = true
		case "server":
			p.server = true
		default:
			p.client, p.server = true, true
		}
		if mt.SchemaFile != "" {
			doc, err := jsonschema.LoadDocument(mt.SchemaFile, maxWSSchemaBytes)
			if err != nil {
				return nil, errors.New("websocket_guard types " + mt.Name + ": " + err.Error())
			}
			p.schema, p.root = jsonschema.New(doc), doc
		}
		t.byName[mt.Name] = p
		t.order = append(t.order, p)
	}
	return t, nil
}

// maxWSSchemaBytes bounds one message schema document.
const maxWSSchemaBytes = 8 << 20

// checkMessage applies the message-type policy to a complete message.
//
// It runs on the inspected prefix, which for a compressed message is the
// inflated one, and only on text messages: the type is a JSON member, and a
// binary message is a format this does not claim to read.
func (s *wsSide) checkMessage(text bool) *wsViolation {
	t := s.g.types
	if t == nil || !text {
		return nil
	}
	whole := s.fragBytes <= s.g.cfg.MaxInspectBytes
	value, err := jsonschema.Decode(s.inspect)
	if err != nil || !whole {
		// Not JSON, or not all of it. Both are "this message is not one
		// the policy can read", and require_json is whether that is a
		// violation or a message the types simply do not cover.
		if t.requireJSON {
			detail := "a text message that is not JSON"
			if err == nil {
				detail = "a message larger than max_inspect_bytes, which cannot be read as JSON"
			}
			return &wsViolation{reason: "json", detail: detail, code: wsClosePolicy}
		}
		return s.unknownType("(not JSON)")
	}
	obj, ok := value.(map[string]any)
	if !ok {
		if t.requireJSON {
			return &wsViolation{reason: "json", detail: "a JSON message that is not an object", code: wsClosePolicy}
		}
		return s.unknownType("(not an object)")
	}
	name, _ := obj[t.field].(string)
	if name == "" {
		return s.unknownType("(no " + t.field + ")")
	}
	p := t.byName[name]
	if p == nil {
		return s.unknownType(name)
	}
	p.messages.Add(1)
	if (s.fromClient && !p.client) || (!s.fromClient && !p.server) {
		return p.deny(&wsViolation{reason: "message_type", detail: name + " is not a message this route carries in that direction", code: wsClosePolicy})
	}
	if p.maxBytes > 0 && s.fragBytes > p.maxBytes {
		return p.deny(&wsViolation{reason: "type_size", detail: name + " of " + strconv.FormatInt(s.fragBytes, 10) + " bytes, over its max_bytes", code: wsCloseTooBig})
	}
	if p.perSecond > 0 {
		if s.typeWindow == nil {
			s.typeWindow = map[string]*wsWindow{}
		}
		w := s.typeWindow[name]
		if w == nil {
			w = &wsWindow{}
			s.typeWindow[name] = w
		}
		if !w.allow(p.perSecond) {
			return p.deny(&wsViolation{reason: "type_rate", detail: "more " + name + " messages than its messages_per_second", code: wsClosePolicy})
		}
	}
	if p.schema != nil {
		rep := &jsonschema.Report{}
		if !p.schema.Validate(p.root, value, name, rep, 0) {
			first := rep.Issues[0]
			return p.deny(&wsViolation{reason: "schema", detail: textsafe.Clip256(first.Path + " " + first.Msg), code: wsClosePolicy})
		}
	}
	return nil
}

// direction is which way this type travels, as the status view names it.
func (p *wsTypePolicy) direction() string {
	switch {
	case p.client && p.server:
		return "both"
	case p.client:
		return "client"
	default:
		return "server"
	}
}

// deny counts a violation against the type that produced it, so the report
// says which message type a route is arguing with.
func (p *wsTypePolicy) deny(v *wsViolation) *wsViolation {
	p.violations.Add(1)
	return v
}

// unknownType is what happens to a message whose type the route does not name.
//
// allow passes it, which is what a route that is only bounding the types it
// knows about wants. observe records it and passes it, which is how a list is
// written: run for a week and read the events. deny refuses it, which is the
// positive security model -- the route carries these messages and nothing else
// -- and is the default once a route names its types, because a list of what is
// allowed that also allows everything else is not a list.
func (s *wsSide) unknownType(name string) *wsViolation {
	t := s.g.types
	// Counted whatever happens next, because a route that allows unknown
	// types still wants the number: it is the one that says a type list is
	// incomplete.
	s.g.unknown.Add(1)
	switch t.unknown {
	case wsUnknownDeny:
		return &wsViolation{reason: "message_type", detail: "a message of type " + textsafe.Clip64(name) +
			", which this route does not carry", code: wsClosePolicy}
	case wsUnknownObserve:
		return &wsViolation{reason: "message_type", detail: "a message of type " + textsafe.Clip64(name) +
			", which this route does not carry", code: wsClosePolicy, observe: true}
	}
	return nil
}

// wsWindow is a one-second message counter.
type wsWindow struct {
	start time.Time
	count int
}

// allow reports whether one more message fits in the current second.
func (w *wsWindow) allow(limit int) bool {
	now := time.Now()
	if now.Sub(w.start) >= time.Second {
		w.start, w.count = now, 0
	}
	w.count++
	return w.count <= limit
}
