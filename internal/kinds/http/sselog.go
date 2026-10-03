package http

import (
	"io"
	"net/http"
	"strings"

	"github.com/rom/xproxy/internal/textsafe"
)

// What an event stream leaves behind.
//
// The record a stream deserves is not the record a request deserves, and the
// difference is the point of this file. A request is one line: it arrived, it
// was decided about, it finished. A stream is one line *and then thousands of
// events over three hours*, and an operator reading a log wants the shape of
// that rather than the events.
//
// So the default is a summary: how many events crossed, how many bytes, how
// long it was open, and what ended it. `log_events` turns on a line per event,
// for a route somebody is investigating -- and the prose on that setting says
// so, because leaving it on across an estate is how a log pipeline falls over.
//
// A refusal is a security event whatever the logging setting, because the
// refusal is the thing that happened.

// sseRecord is the recorder the stream reports through. It holds the engine and
// the request's state, which is everything the logs and counters need.
type sseRecord struct {
	s   *engine
	st  *reqState
	req *http.Request
}

// sseRecorder makes a recorder for one stream.
func (s *engine) sseRecorder(st *reqState, r *http.Request) *sseRecord {
	return &sseRecord{s: s, st: st, req: r}
}

func (c *sseRecord) event(name string, bytes int) {
	c.st.sseEvents++
	c.s.stats.SSEEvents.Add(1)
	// The guard bounds an event's size before it gets here, so this is a
	// length and cannot be negative; the test keeps the conversion honest
	// rather than assuming it.
	if bytes > 0 {
		c.st.sseBytes += int64(bytes)
		c.s.stats.SSEEventBytes.Add(uint64(bytes))
	}
	if c.st.sseGuard != nil && c.st.sseGuard.logEvents {
		c.s.logs.Error.Debug("sse event", "route", c.st.route,
			"client_ip", c.st.clientIP.String(), "event", textsafe.Clip64(name),
			"bytes", bytes)
	}
}

func (c *sseRecord) comment() {
	c.st.sseComments++
	c.s.stats.SSEComments.Add(1)
}

// refused reports the violation that ended a stream. It is a security event,
// it is counted under its own reason so a ban trigger can act on it, and it
// carries the stream's totals -- because "the stream was refused" is a
// different thing after four events and after four hundred thousand.
func (c *sseRecord) refused(v *sseViolation) {
	c.st.sseRefused = v.reason
	c.s.stats.SSEViolations.Add(1)
	c.s.stats.Refuse("sse", v.reason)
	attrs := []any{"route", c.st.route, "client_ip", c.st.clientIP.String(),
		"reason", v.reason, "events", c.st.sseEvents, "bytes", c.st.sseBytes}
	if v.detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(v.detail))
	}
	if v.hard {
		attrs = append(attrs, "hard", true)
	}
	c.s.logs.SecurityEvent(c.req.Context(), "sse", "sse_"+v.reason, attrs...)
}

// would reports what enforcement would have refused. Shadow mode's report is
// as detailed as the refusal, because an operator comparing the two is the
// person the mode exists for.
func (c *sseRecord) would(v *sseViolation) {
	c.s.stats.WouldRefuse("sse", v.reason)
	c.s.host.Shadow().Record("sse", c.st.route, v.reason, "event", v.detail)
}

func (c *sseRecord) observed(name string) {
	c.s.stats.SSEUnknownEvents.Add(1)
	c.s.logs.Error.Debug("sse event no list covers", "route", c.st.route,
		"client_ip", c.st.clientIP.String(), "event", textsafe.Clip64(name))
}

// stripped reports a client's Last-Event-ID that did not cross. It is not a
// refusal -- the request goes on and the client gets the stream from the
// beginning, which is what a client with no cursor gets -- so it is counted
// and reported rather than denied.
func (c *sseRecord) stripped(reason, detail string) {
	c.s.stats.SSECursorsStripped.Add(1)
	attrs := []any{"route", c.st.route, "client_ip", c.st.clientIP.String(), "reason", reason}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(detail))
	}
	c.s.logs.SecurityEvent(c.req.Context(), "sse", "sse_"+reason, attrs...)
}

// acceptsEventStream reports whether a request is asking for an event stream.
//
// The request side of the policy applies to a request that asked for one,
// rather than to every request on the route: a route that serves a page and a
// stream under one path is ordinary, and stripping Accept-Encoding from the
// page would make this proxy the reason the page is uncompressed.
func acceptsEventStream(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept") {
		for _, part := range strings.Split(v, ",") {
			if t := part; t != "" {
				if i := strings.IndexByte(t, ';'); i >= 0 {
					t = t[:i]
				}
				if strings.EqualFold(strings.TrimSpace(t), "text/event-stream") {
					return true
				}
			}
		}
	}
	return false
}

// readCloser joins a reader to somebody else's Closer, for the inflating path
// where what is read and what has to be closed are two different objects.
type readCloser struct {
	io.Reader
	io.Closer
}
