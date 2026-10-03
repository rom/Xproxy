package http

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/jsonschema"
	"github.com/rom/xproxy/internal/sse"
	"github.com/rom/xproxy/internal/textsafe"
)

// The event policy of a `text/event-stream` response.
//
// The WebSocket guard beside this one answers "is this a well-formed WebSocket
// and is it within these bounds", in both directions, for a connection the
// client opened deliberately. This answers a narrower and stranger question.
//
// An event stream is a response. The client sent a GET, the status line has
// already gone, and from then on only the application speaks. Three things
// follow and they shape everything here:
//
// **A single event cannot be refused.** By the time an event is read the
// response is committed: there is no status code left to send and no way to
// say "not that one" inside a stream a client is reading as a sequence. So
// `action` has two values rather than three -- the stream ends, or the event is
// carried and reported -- and a per-event refusal is a decision to end the
// stream at that event.
//
// **The direction is outward, so the policy is about answers.** Every byte is
// the estate's own application talking. That puts this guard in the same
// position as the dhcp kind, whose whole policy is about replies, and it is
// also why `deny_patterns` here reads what is *leaving*: an event stream is a
// well-shaped exfiltration channel -- arbitrary text, chunked, flushed per
// event, open for hours, on a port that is already open, under a Content-Type
// a dashboard uses -- and nothing about the traffic is malformed.
//
// **The only client input is a cursor.** `Last-Event-ID` on a reconnection is
// the one thing a client contributes, and an application that replays from it
// is being told where to start. An identifier a client was never issued is a
// request for history it was not shown, so the header has a bound, a pattern
// and an off switch.
//
// What makes all of that decidable is that the proxy reads the stream and
// writes it out again rather than splicing it. The octets the client sees are
// this guard's, so the framing ambiguity SSE has -- three line terminators, a
// blank line as the only separator, a field with no colon -- is resolved once
// here instead of twice at the two ends.

// What a route does about an event whose name no list covers.
const (
	sseUnknownAllow   = "allow"
	sseUnknownObserve = "observe"
	sseUnknownDeny    = "deny"
)

// What a route does about compression on an event stream.
const (
	// sseCompressStrip removes the client's Accept-Encoding so the
	// application sends the stream in the clear. The default, and nearly
	// free: an event stream is small messages flushed one at a time, so a
	// sender has already given up cross-message compression to keep latency.
	sseCompressStrip = "strip"
	// sseCompressRefuse answers the request rather than quietly changing what
	// the client asked for.
	sseCompressRefuse = "refuse"
	// sseCompressInspect inflates each event before the policy sees it.
	sseCompressInspect = "inspect"
)

// maxSSESchemaBytes bounds one event schema document.
const maxSSESchemaBytes = 8 << 20

// sseEventPolicy is the policy for one event name.
type sseEventPolicy struct {
	name      string
	maxBytes  int64
	perSecond int
	schema    *jsonschema.Validator
	root      map[string]any
}

// sseGuard is a route's compiled event policy. It holds no per-stream state:
// every stream gets its own sseStream below, because the totals and the rates
// are the stream's.
type sseGuard struct {
	cfg *config.SSEGuard

	allow   map[string]bool
	deny    map[string]bool
	unknown string

	byName map[string]*sseEventPolicy

	patterns []*regexp.Regexp
	idShape  *regexp.Regexp

	inspect     string
	inspectMax  int64
	requireJSON bool
	comments    bool
	lastEventID bool
	maxID       int
	minRetry    time.Duration
	compression string
	ratio       int
	action      string
	logEvents   bool
	monitorOnly bool

	// The bounds, resolved once so the hot path reads no config.
	maxEvent  int64
	maxLine   int
	maxFields int
	perSecond int
	maxEvents int64
	maxBytes  int64
	maxDur    time.Duration
	idle      time.Duration
}

// newSSEGuard compiles a route's sse_guard.
func newSSEGuard(c *config.SSEGuard) (*sseGuard, error) {
	if c == nil {
		return nil, nil
	}
	g := &sseGuard{
		cfg: c, allow: sseSet(c.AllowEvents), deny: sseSet(c.DenyEvents),
		unknown: c.UnknownEvents, byName: map[string]*sseEventPolicy{},
		inspect: c.Inspect, inspectMax: sseOr64(c.MaxInspectBytes, 64<<10),
		requireJSON: c.JSONRequired(), comments: c.Comments(),
		lastEventID: c.LastEventID(), maxID: sseOrInt(c.MaxIDBytes, 256),
		minRetry: c.MinRetry.D(), compression: c.Compression,
		ratio: sseOrInt(c.MaxInflateRatio, 100), action: c.Action,
		logEvents: c.LogEvents, monitorOnly: c.MonitorOnly,
		maxEvent: sseOr64(c.MaxEventBytes, 1<<20), maxLine: sseOrInt(int(c.MaxLineBytes), 64<<10),
		maxFields: sseOrInt(c.MaxFields, 256), perSecond: c.EventsPerSecond,
		maxEvents: c.MaxEvents, maxBytes: c.MaxStreamBytes,
		maxDur: c.MaxDuration.D(), idle: c.IdleTimeout.D(),
	}
	if g.unknown == "" {
		// A list that also carries everything else is not a list, so naming
		// any event name makes the rest deny by default.
		if len(g.allow) > 0 {
			g.unknown = sseUnknownDeny
		} else {
			g.unknown = sseUnknownAllow
		}
	}
	if g.inspect == "" {
		g.inspect = "data"
	}
	if g.compression == "" {
		g.compression = sseCompressStrip
	}
	if g.action == "" {
		g.action = "close"
	}
	for _, p := range c.DenyPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, errors.New("sse_guard deny_patterns " + p + ": " + err.Error())
		}
		g.patterns = append(g.patterns, re)
	}
	if p := c.LastEventIDPattern; p != "" {
		re, err := regexp.Compile(anchored(p))
		if err != nil {
			return nil, errors.New("sse_guard last_event_id_pattern: " + err.Error())
		}
		g.idShape = re
	}
	for i := range c.Events {
		et := &c.Events[i]
		p := &sseEventPolicy{name: et.Name, maxBytes: et.MaxBytes, perSecond: et.EventsPerSecond}
		if et.SchemaFile != "" {
			doc, err := jsonschema.LoadDocument(et.SchemaFile, maxSSESchemaBytes)
			if err != nil {
				return nil, errors.New("sse_guard events " + et.Name + ": " + err.Error())
			}
			p.schema, p.root = jsonschema.New(doc), doc
		}
		g.byName[et.Name] = p
	}
	return g, nil
}

// anchored wraps a pattern so it has to match the whole value. A cursor
// pattern that matched a substring would admit every identifier with a legal
// one somewhere inside it, which is the opposite of what its author wrote.
func anchored(p string) string {
	if !strings.HasPrefix(p, "^") {
		p = "^" + p
	}
	if !strings.HasSuffix(p, "$") {
		p += "$"
	}
	return p
}

func sseSet(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[s] = true
	}
	return m
}

func sseOr64(v, def int64) int64 {
	if v <= 0 {
		return def
	}
	return v
}

func sseOrInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// sseViolation is a refusal: a reason an operator can act on, the detail that
// says which event it was about, and whether it is hard.
type sseViolation struct {
	reason string
	detail string
	// hard marks a violation that stands in monitor_only as well. There is
	// exactly one: a stream whose framing this proxy could not read cannot be
	// forwarded, because forwarding it would mean forwarding octets nobody
	// decided about, which is what monitor_only is not for.
	hard bool
}

// decide applies the policy to one complete event.
//
// The order is the cheapest and least revocable first, as the sibling kinds
// do: the bounds, then the lists, then the shape, then the patterns. The one
// before all of them -- whether the framing read at all -- happened in the
// reader and arrives here as a hard violation.
func (s *sseStream) decide(e sse.Event) *sseViolation {
	g := s.g
	name := e.Named()

	// The totals first. They are the settings that make a stream finite, so a
	// stream past one of them is ended whatever the event was.
	s.events++
	s.bytes += int64(e.Bytes)
	if g.maxEvents > 0 && s.events > g.maxEvents {
		return &sseViolation{reason: "too_many_events",
			detail: strconv.FormatInt(s.events, 10) + " events on one stream"}
	}
	if g.maxBytes > 0 && s.bytes > g.maxBytes {
		return &sseViolation{reason: "stream_too_large",
			detail: strconv.FormatInt(s.bytes, 10) + " bytes on one stream"}
	}
	if int64(e.Bytes) > g.maxEvent {
		return &sseViolation{reason: "event_too_large",
			detail: strconv.FormatInt(int64(e.Bytes), 10) + " bytes in one event"}
	}
	if e.Fields > g.maxFields {
		return &sseViolation{reason: "too_many_fields",
			detail: strconv.FormatInt(int64(e.Fields), 10) + " fields in one event"}
	}

	// The rate, which on this protocol is the server's. An application that
	// has started emitting a thousand events a second is either broken or
	// being read, and both are worth stopping.
	if g.perSecond > 0 && !s.rate.allow(g.perSecond) {
		return &sseViolation{reason: "event_rate", detail: name}
	}

	// The lists. deny is checked first and no entry in allow overrides it,
	// which is how an exception inside an admitted set is written.
	if g.deny[name] {
		return &sseViolation{reason: "event_denied", detail: name}
	}
	ep := g.byName[name]
	known := g.allow[name] || ep != nil
	if !known && len(g.allow) > 0 {
		switch g.unknown {
		case sseUnknownDeny:
			return &sseViolation{reason: "event_not_allowed", detail: name}
		case sseUnknownObserve:
			s.observed(name)
		}
	} else if !known && g.unknown == sseUnknownDeny {
		return &sseViolation{reason: "event_not_allowed", detail: name}
	}

	// The per-name policy: its own size bound, its own rate, its own schema.
	// One max_event_bytes for the stream is the bound of its largest event,
	// which is the bound that lets every other event be that large too.
	if ep != nil {
		if ep.maxBytes > 0 && int64(e.Bytes) > ep.maxBytes {
			return &sseViolation{reason: "event_too_large",
				detail: name + ": " + strconv.FormatInt(int64(e.Bytes), 10) + " bytes"}
		}
		if ep.perSecond > 0 {
			r := s.named[name]
			if r == nil {
				r = &wsWindow{}
				s.named[name] = r
			}
			if !r.allow(ep.perSecond) {
				return &sseViolation{reason: "event_rate", detail: name}
			}
		}
	}

	// The identifier the server sent, which is what the client will send back.
	if e.HasID && len(e.ID) > g.maxID {
		return &sseViolation{reason: "id_too_long",
			detail: strconv.FormatInt(int64(len(e.ID)), 10) + " bytes"}
	}

	// The shape, where a name has a schema or the route requires JSON at all.
	if v := s.checkShape(e, ep); v != nil {
		return v
	}

	// And the patterns, over what the route said to inspect. This is the check
	// that reads what is leaving.
	if len(g.patterns) > 0 {
		subject := e.Data
		if g.inspect == "all" {
			subject = name + "\n" + e.ID + "\n" + e.Data
		}
		if int64(len(subject)) > g.inspectMax {
			subject = subject[:g.inspectMax]
		}
		for _, re := range g.patterns {
			if re.MatchString(subject) {
				return &sseViolation{reason: "pattern",
					detail: name + ": " + textsafe.Clip64(re.String())}
			}
		}
	}
	return nil
}

// checkShape validates an event's data against the schema for its name, and
// applies require_json.
//
// An event larger than max_inspect_bytes was not kept whole, so it cannot be
// validated. That is a refusal rather than a pass: a check that silently stops
// applying above a size the sender chooses is not a check, and the sender here
// is the thing being checked.
func (s *sseStream) checkShape(e sse.Event, ep *sseEventPolicy) *sseViolation {
	g := s.g
	needs := g.requireJSON || (ep != nil && ep.schema != nil)
	if !needs {
		return nil
	}
	if int64(len(e.Data)) > g.inspectMax {
		return &sseViolation{reason: "not_inspectable",
			detail: "an event larger than max_inspect_bytes cannot be validated"}
	}
	value, err := jsonschema.Decode([]byte(e.Data))
	if err != nil {
		if g.requireJSON {
			return &sseViolation{reason: "json", detail: e.Named() + ": data is not JSON"}
		}
		return nil
	}
	if ep == nil || ep.schema == nil {
		return nil
	}
	rep := &jsonschema.Report{}
	if !ep.schema.Validate(ep.root, value, e.Named(), rep, 0) {
		first := rep.Issues[0]
		return &sseViolation{reason: "schema",
			detail: e.Named() + ": " + textsafe.Clip64(first.Path+" "+first.Msg)}
	}
	return nil
}
