// Package sse reads the Server-Sent Events stream format: the wire side of
// `text/event-stream`, as the HTML standard defines it, for a proxy that has
// to decide about a response it is forwarding one event at a time.
//
// SSE is the other long-lived HTTP response an estate runs, and it is the
// opposite of the WebSocket beside it in two ways that both matter here.
//
// It is one-directional and the direction is outward. A client sends an
// ordinary GET and then says nothing; everything after that is the server
// talking. So unlike a WebSocket, where the interesting message is usually the
// client's, every byte of an event stream is the *application's* own output
// leaving the estate — which makes the policy a policy about answers, the way
// the dhcp kind's is, and makes the stream a well-shaped place to put data that
// is not meant to leave. An event stream is arbitrary text, chunked, flushed
// per event, held open for hours, and indistinguishable from a dashboard feed.
//
// And its framing is deceptively small. Four field names, a colon, a blank
// line to end an event, a leading colon for a comment. The traps are in what
// that leaves unsaid:
//
//   - **A blank line is the only terminator**, so a reader that buffers
//     greedily merges two events and a reader that splits on the wrong
//     newline splits one. The standard's line terminators are CRLF, LF *and
//     a bare CR*, all three, which is unlike every other line protocol in
//     this project and is the single most likely thing to get wrong.
//   - **A field with no colon is a field with an empty value**, not a
//     malformed line: `data` alone is a `data:` with nothing after it. A
//     reader that refuses it diverges from every browser.
//   - **One space after the colon is stripped, and only one.** `data:  x`
//     carries ` x`. A proxy that trimmed the whole run would change the
//     payload.
//   - **`data` accumulates across lines** with a newline between them, so an
//     event's payload is the join of its data fields and its size is not any
//     one line's length.
//   - **A leading BOM is stripped once**, at the start of the stream only.
//   - **`id` may not contain NUL**, and that is the one field value the
//     standard says to ignore rather than carry.
//
// What this package does not do is decide anything. It reads events and their
// fields and bounds what it reads; the policy lives in the listener kind, and
// what the client is told about a refusal is the kind's business too.
package sse

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The bounds. Every one of them is a bound on what this reader will hold in
// memory for one event, because an event stream is unbounded by construction
// and the sender is the one choosing the sizes.
const (
	// MaxLine is the longest single field line. Generous: a `data:` line
	// carrying a JSON object is the ordinary case and those are not small.
	MaxLine = 1 << 20
	// MaxEventBytes is the largest reassembled event: the joined data, plus
	// the event name and the identifier. An event larger than this is refused
	// rather than truncated, because half an event delivered as whole is
	// worse than none.
	MaxEventBytes = 8 << 20
	// MaxFields is the number of field lines one event may carry. A stream
	// that sends ten thousand `data:` lines before its blank line is not
	// sending an event.
	MaxFields = 4096
	// MaxName is the longest event name. An event name is an API's own
	// vocabulary, and nothing in that vocabulary is a kilobyte.
	MaxName = 256
	// MaxID is the longest last-event identifier, in either direction: the
	// server's `id:` field and the client's Last-Event-ID request header are
	// the same value making a round trip.
	MaxID = 1024
)

// The errors a reader reports. They are distinguished because the kind turns
// each into its own refusal reason, and "the stream was malformed" is not a
// reason anybody can act on.
var (
	ErrLineTooLong  = errors.New("sse: field line too long")
	ErrEventTooLong = errors.New("sse: event too large")
	ErrTooManyField = errors.New("sse: too many fields in one event")
	ErrNameTooLong  = errors.New("sse: event name too long")
	ErrIDTooLong    = errors.New("sse: event id too long")
	ErrControl      = errors.New("sse: control character in a field value")
	ErrNotUTF8      = errors.New("sse: stream is not valid UTF-8")
)

// Event is one event, reassembled.
//
// It is deliberately not a parsed payload: Data is the joined text and
// nothing here looks inside it. An SSE payload is whatever the application
// chose — JSON, a number, a fragment of HTML, a line of log — and a reader
// that assumed one of those would be wrong about the others.
type Event struct {
	// Name is the `event:` field, or "" where the stream sent none. An event
	// with no name is the default `message` event to a client; it is left
	// empty here so a policy can tell "the stream said message" from "the
	// stream said nothing", which are the same to a browser and not the same
	// to somebody reading a rule.
	Name string
	// Data is the joined `data:` fields, one newline between each. A final
	// newline is not added: the standard strips it.
	Data string
	// ID is the `id:` field. It is what the client will send back as
	// Last-Event-ID after a reconnection, which is what makes it worth
	// bounding in both directions.
	ID string
	// HasID says whether the event carried an `id:` field at all, because an
	// `id:` with an empty value is meaningful — it clears the client's
	// stored identifier — and is not the same as no field.
	HasID bool
	// Retry is the `retry:` field in milliseconds and RetrySet whether it was
	// present. It is the server telling the client how long to wait before
	// reconnecting, so a small value is a server asking to be hammered and a
	// policy that bounds it is bounding its own load.
	Retry    int64
	RetrySet bool
	// Comments are the `:`-prefixed lines, which carry no data and exist to
	// keep a connection alive through an intermediary that would time it
	// out. They are kept because a stream whose every event is a comment is
	// a stream doing nothing, and that is worth being able to see.
	Comments int
	// Fields is how many field lines this event was built from, and Bytes the
	// size of the reassembled event. Both are what a bound is applied to.
	Fields int
	Bytes  int
	// Unknown is how many field lines named something other than the four the
	// standard defines. The standard says to ignore them; this records that
	// they were there, because a stream using an undefined field name is
	// either a newer standard or somebody's channel.
	Unknown int
}

// Named reports the event's name as a client would see it: the default
// `message` where the stream sent none.
func (e Event) Named() string {
	if e.Name == "" {
		return "message"
	}
	return e.Name
}

// Reader reads events from an event stream.
//
// It is a bufio.Reader with a line splitter that honours all three of the
// standard's terminators and a reassembler that applies the bounds above. The
// ceiling is stored so SetMax cannot raise a bound above the buffer that has
// to hold the line -- a bound that silently did not apply would be worse than
// no bound.
type Reader struct {
	br      *bufio.Reader
	max     int
	ceiling int
	// bom says whether the leading byte-order mark has been dealt with. It is
	// stripped once, at the start of the stream, and a BOM in the middle of a
	// stream is data.
	bom bool
	// pending holds the data fields of the event being read, so the join
	// happens once at the end rather than on every line.
	pending []string
}

// NewReader wraps r. The buffer is MaxLine, so a line at the bound is read
// whole and one past it is refused rather than split.
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, MaxLine), max: MaxLine, ceiling: MaxLine}
}

// SetMax lowers the line bound, clamped to the buffer the reader was built
// with. Raising it past the ceiling is silently clamped rather than honoured,
// because the buffer cannot hold more and a bound that does not apply is a
// bound somebody is relying on.
func (r *Reader) SetMax(n int) {
	switch {
	case n <= 0:
		r.max = r.ceiling
	case n > r.ceiling:
		r.max = r.ceiling
	default:
		r.max = n
	}
}

// Buffered reports how many bytes are held but not yet read, which is what
// says whether a sender wrote ahead of being answered.
func (r *Reader) Buffered() int { return r.br.Buffered() }

// line reads one line, ending at CRLF, LF or a bare CR, and returns it
// without the terminator.
//
// The bare CR is why this is not bufio.Reader.ReadString('\n'). A sender that
// ends its lines with CR alone is within the standard, and a reader that
// waited for an LF would hold a whole event in its buffer and deliver
// nothing -- which on this protocol looks exactly like a server that has
// stopped sending.
func (r *Reader) line() ([]byte, error) {
	var out []byte
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			if len(out) > 0 && errors.Is(err, io.EOF) {
				// A final line with no terminator. The standard discards an
				// incomplete event at end of stream, and the caller does
				// that; here it is a line, so that the caller can see it.
				return out, io.EOF
			}
			return out, err
		}
		switch b {
		case '\n':
			return out, nil
		case '\r':
			// CRLF or a bare CR: peek one byte and put it back unless it is
			// the LF that belongs to this terminator.
			if nb, err := r.br.ReadByte(); err == nil {
				if nb != '\n' {
					_ = r.br.UnreadByte()
				}
			}
			return out, nil
		}
		if len(out) >= r.max {
			return out, ErrLineTooLong
		}
		out = append(out, b)
	}
}

// field splits a line into a name and a value, the way the standard says.
//
// No colon at all is a field name with an empty value. A leading colon is a
// comment, which the caller recognises by an empty name. Exactly one space
// after the colon is stripped.
func field(line []byte) (name, value []byte, comment bool) {
	i := bytes.IndexByte(line, ':')
	switch {
	case i == 0:
		return nil, line[1:], true
	case i < 0:
		return line, nil, false
	}
	value = line[i+1:]
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return line[:i], value, false
}

// ReadEvent reads field lines until the blank line that ends an event, and
// returns the event it built.
//
// An event with no data and no name -- a run of comments and nothing else --
// is returned as it is rather than skipped, because a keepalive is a thing a
// policy may want to count and a reader that swallowed it would make a silent
// stream indistinguishable from a busy one.
//
// At end of stream an incomplete event is discarded, as the standard requires,
// and io.EOF is returned.
func (r *Reader) ReadEvent() (Event, error) {
	var e Event
	r.pending = r.pending[:0]
	for {
		line, err := r.line()
		if err != nil && !errors.Is(err, io.EOF) {
			return e, err
		}
		eof := errors.Is(err, io.EOF)
		if !r.bom {
			r.bom = true
			line = bytes.TrimPrefix(line, []byte{0xEF, 0xBB, 0xBF})
		}
		if len(line) == 0 {
			if eof {
				// The blank line never came: whatever was accumulated is an
				// incomplete event and the standard drops it.
				return Event{}, io.EOF
			}
			// The terminator. An event is dispatched even when it carried
			// only comments.
			e.Data = joinData(r.pending)
			e.Bytes = len(e.Data) + len(e.Name) + len(e.ID)
			if e.Bytes > MaxEventBytes {
				return e, ErrEventTooLong
			}
			return e, nil
		}
		if !utf8.Valid(line) {
			return e, ErrNotUTF8
		}
		name, value, comment := field(line)
		e.Fields++
		if e.Fields > MaxFields {
			return e, ErrTooManyField
		}
		if comment {
			e.Comments++
			if eof {
				return Event{}, io.EOF
			}
			continue
		}
		switch string(name) {
		case "event":
			if len(value) > MaxName {
				return e, ErrNameTooLong
			}
			if hasControl(value) {
				return e, ErrControl
			}
			e.Name = string(value)
		case "data":
			r.pending = append(r.pending, string(value))
			if n := sizeOf(r.pending); n > MaxEventBytes {
				e.Bytes = n
				return e, ErrEventTooLong
			}
		case "id":
			// The one value the standard says to ignore rather than carry: an
			// identifier with a NUL in it is dropped, field and all.
			if bytes.IndexByte(value, 0) >= 0 {
				break
			}
			if len(value) > MaxID {
				return e, ErrIDTooLong
			}
			e.ID, e.HasID = string(value), true
		case "retry":
			// Digits only, and anything else is ignored rather than refused:
			// the standard says so, and a stream whose retry field is
			// nonsense is a stream whose reconnection delay is the client's
			// default.
			if n, err := strconv.ParseInt(string(value), 10, 64); err == nil && allDigits(value) {
				e.Retry, e.RetrySet = n, true
			}
		default:
			e.Unknown++
		}
		if eof {
			return Event{}, io.EOF
		}
	}
}

// joinData joins an event's data fields with one newline between them. The
// standard appends a newline per field and then strips the last one, which is
// the same thing and one allocation fewer.
func joinData(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	var b []byte
	for i, p := range parts {
		if i > 0 {
			b = append(b, '\n')
		}
		b = append(b, p...)
	}
	return string(b)
}

func sizeOf(parts []string) int {
	n := 0
	for _, p := range parts {
		n += len(p) + 1
	}
	return n
}

// hasControl reports whether a value carries a C0 control character other
// than tab. An event name is a token in an API's vocabulary; a control
// character in one is either a mistake or an attempt to confuse something
// downstream that logs it.
func hasControl(v []byte) bool {
	for _, b := range v {
		if b < 0x20 && b != '\t' {
			return true
		}
	}
	return false
}

func allDigits(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	for _, b := range v {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// Stream reports whether a Content-Type names an event stream.
//
// The comparison is on the media type alone, with parameters and case
// ignored, because `text/event-stream; charset=utf-8` is the same stream and
// a check on the whole header would miss it.
func Stream(contentType string) bool {
	ct := contentType
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return equalFold(trimSpace(ct), "text/event-stream")
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Write renders an event back onto the wire.
//
// A proxy that decides about events has to write them out again, and writing
// them out again is what makes the framing decision happen once rather than
// twice: the octets the client reads are this function's, so a sender's bare
// CR, its missing final newline and its ambiguous blank line are all resolved
// here and cannot be resolved differently downstream.
func (e Event) Write(w io.Writer) error {
	var b []byte
	if e.Name != "" {
		b = append(append(append(b, "event: "...), e.Name...), '\n')
	}
	if e.HasID {
		b = append(append(append(b, "id: "...), e.ID...), '\n')
	}
	if e.RetrySet {
		b = append(append(append(b, "retry: "...), strconv.FormatInt(e.Retry, 10)...), '\n')
	}
	// Data is written one line per newline it contains, because a newline
	// inside a data field is what separates two data fields and writing it
	// raw would end the event.
	if e.Data != "" || (e.Name == "" && !e.HasID && !e.RetrySet) {
		for _, part := range splitLines(e.Data) {
			b = append(append(append(b, "data: "...), part...), '\n')
		}
	}
	b = append(b, '\n')
	_, err := w.Write(b)
	return err
}

func splitLines(s string) []string {
	if s == "" {
		return []string{""}
	}
	var out []string
	for {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			return append(out, s)
		}
		out = append(out, s[:i])
		s = s[i+1:]
	}
}
