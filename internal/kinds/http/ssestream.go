package http

import (
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/sse"
	"github.com/rom/xproxy/internal/textsafe"
)

// sseStream is one event stream being read, decided about and written out
// again. It replaces the response body, so the octets the client reads are
// this type's rather than the application's.
//
// Re-emitting rather than splicing is the whole of why the policy is
// trustworthy. SSE has three line terminators, a blank line as its only
// separator and a field with no colon that means an empty value; a spliced
// stream leaves those to be resolved twice, once by this proxy's reader and
// once by the client's, and the two can disagree about where an event ends.
// Writing each event out means the client sees exactly what was decided about.
//
// It is a reader, so it runs on the data plane's own goroutine for this
// response and needs no locking: Read is called from one place at a time, and
// every field here belongs to that call.
type sseStream struct {
	g    *sseGuard
	src  io.ReadCloser
	r    *sse.Reader
	rec  sseRecorder
	zrc  io.ReadCloser
	stop func()

	// out holds the octets of events already decided about, waiting to be
	// read by the data plane. An event is written whole or not at all.
	out []byte
	// ended says the stream is finished: either the application closed it or
	// the policy ended it. Nothing more is read from the application after
	// that, which is what makes "the stream ends" mean something.
	ended bool
	err   error

	started time.Time
	last    time.Time
	events  int64
	bytes   int64
	rate    wsWindow
	named   map[string]*wsWindow
}

// sseRecorder is what the stream reports through. It is an interface so the
// guard can be tested without an engine behind it, and so this file holds no
// opinion about counters or logs.
type sseRecorder interface {
	// event is one event carried.
	event(name string, bytes int)
	// comment is one keepalive carried.
	comment()
	// refused reports a violation that ended the stream.
	refused(v *sseViolation)
	// would reports a violation shadow mode carried anyway.
	would(v *sseViolation)
	// observed is an event name no list covers, under unknown_events: observe.
	observed(name string)
	// stripped reports that a client's Last-Event-ID did not cross.
	stripped(reason, detail string)
}

// newSSEStream wraps a response body. The caller has already decided this is
// an event stream and that the route has a guard.
func newSSEStream(g *sseGuard, body io.ReadCloser, rec sseRecorder, stop func()) *sseStream {
	now := time.Now()
	s := &sseStream{g: g, src: body, rec: rec, stop: stop,
		started: now, last: now, named: map[string]*wsWindow{}}
	s.r = sse.NewReader(body)
	s.r.SetMax(g.maxLine)
	return s
}

// inflate puts a decompressor in front of the reader, for a route that
// inspects a compressed stream. The ratio bound is applied by the reader
// below rather than here: a decompressor asked how large its output will be
// has to produce it first, which is the thing the bound exists to prevent.
func (s *sseStream) inflate(encoding string) error {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(s.src)
		if err != nil {
			return err
		}
		s.zrc = zr
	case "deflate":
		s.zrc = flate.NewReader(s.src)
	default:
		return errors.New("sse: cannot inspect Content-Encoding " + encoding)
	}
	// The ratio bound: at most max_inflate_ratio bytes out per byte in, so a
	// few hundred bytes of zeroes cannot become whatever the sender chose.
	s.r = sse.NewReader(&ratioReader{r: s.zrc, src: s.src, ratio: int64(s.g.ratio)})
	s.r.SetMax(s.g.maxLine)
	return nil
}

// Read gives the data plane the octets of events that have passed the policy.
//
// It fills from the reader one event at a time, because an event is the unit a
// decision is about: half an event written and then refused would hand a client
// a fragment as a whole message, which is the failure this design exists to
// avoid.
func (s *sseStream) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.ended {
			if s.err != nil {
				return 0, s.err
			}
			return 0, io.EOF
		}
		s.fill()
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

// Close ends the stream and the body under it.
func (s *sseStream) Close() error { return s.src.Close() }

// fill reads one event and decides about it, appending its octets to out when
// it may cross.
func (s *sseStream) fill() {
	// The stream's own clock bounds, checked before a read rather than after:
	// a stream past max_duration should end whether or not the application
	// ever sends again, and a stream that has gone quiet is exactly the one a
	// check after the read would never reach.
	if d := s.g.maxDur; d > 0 && time.Since(s.started) > d {
		s.end(&sseViolation{reason: "stream_too_long",
			detail: time.Since(s.started).Truncate(time.Second).String()})
		return
	}
	if d := s.g.idle; d > 0 && time.Since(s.last) > d {
		s.end(&sseViolation{reason: "stream_idle",
			detail: time.Since(s.last).Truncate(time.Second).String()})
		return
	}
	e, err := s.r.ReadEvent()
	if err != nil {
		if errors.Is(err, io.EOF) {
			// The application finished. Whatever it had accumulated without a
			// blank line is an incomplete event and the reader has already
			// discarded it, which is what the standard requires.
			s.ended = true
			return
		}
		// The framing did not read. This is the one violation that stands in
		// monitor_only too: a stream whose events cannot be found cannot be
		// forwarded event by event, and forwarding it raw would mean
		// forwarding octets nobody decided about.
		s.end(&sseViolation{reason: sseFramingReason(err),
			detail: textsafe.Clip64(err.Error()), hard: true})
		return
	}
	s.last = time.Now()

	// A comment carries no event. It is traffic -- that is what a keepalive is
	// for -- so it refreshes the idle clock above, and it crosses unless the
	// route turned comments off.
	if e.Comments > 0 && e.Data == "" && e.Name == "" && !e.HasID {
		s.rec.comment()
		if s.g.comments {
			s.out = append(s.out, ':', '\n', '\n')
		}
		return
	}

	if v := s.decide(e); v != nil {
		if s.g.monitorOnly && !v.hard {
			// Shadow mode: say what would have happened and carry the event.
			// This is how an estate finds out what its own streams send
			// before a bound is set, and the reason the reporting is as
			// detailed as the refusal.
			s.rec.would(v)
			s.write(e)
			return
		}
		if s.g.action == "log" && !v.hard {
			s.rec.would(v)
			s.write(e)
			return
		}
		s.end(v)
		return
	}
	s.write(e)
}

// write renders an event onto the output, applying the two rewrites the policy
// makes rather than refuses.
func (s *sseStream) write(e sse.Event) {
	// A retry floor rewrites rather than refuses: `retry: 0` from a
	// misconfigured application is a fleet of browsers reconnecting as fast as
	// they can, and the stream itself is fine.
	if s.g.minRetry > 0 && e.RetrySet {
		if min := s.g.minRetry.Milliseconds(); e.Retry < min {
			e.Retry = min
		}
	}
	var b strings.Builder
	if err := e.Write(&b); err != nil {
		s.ended, s.err = true, err
		return
	}
	s.out = append(s.out, b.String()...)
	s.rec.event(e.Named(), e.Bytes)
}

// end stops the stream at this event and records why.
//
// There is no status code left to send and no way to say "not that one" inside
// a sequence a client is reading, so a refusal here is the end of the stream.
// The client sees a closed body, which is what it sees when an application
// finishes, and reconnects -- which is the right outcome for a dashboard and a
// dead end for a channel.
func (s *sseStream) end(v *sseViolation) {
	s.rec.refused(v)
	s.ended = true
	if s.stop != nil {
		s.stop()
	}
}

// observed passes an unknown event name through to the recorder.
func (s *sseStream) observed(name string) { s.rec.observed(name) }

// sseFramingReason names a reader error, so each becomes its own refusal
// reason rather than all of them becoming "malformed".
func sseFramingReason(err error) string {
	switch {
	case errors.Is(err, sse.ErrLineTooLong):
		return "line_too_long"
	case errors.Is(err, sse.ErrEventTooLong):
		return "event_too_large"
	case errors.Is(err, sse.ErrTooManyField):
		return "too_many_fields"
	case errors.Is(err, sse.ErrNameTooLong):
		return "name_too_long"
	case errors.Is(err, sse.ErrIDTooLong):
		return "id_too_long"
	case errors.Is(err, sse.ErrControl):
		return "control_character"
	case errors.Is(err, sse.ErrNotUTF8):
		return "not_utf8"
	}
	return "malformed_stream"
}

// ratioReader bounds how far a compressed stream may expand. It counts the
// compressed bytes consumed and the inflated bytes produced, and refuses once
// the second is more than ratio times the first -- which is the check that
// cannot be made by asking the decompressor how large its output is, because
// answering that means producing it.
type ratioReader struct {
	r     io.Reader
	src   io.Reader
	ratio int64
	out   int64
}

func (r *ratioReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.out += int64(n)
	// The floor of 32 KiB is there so a small stream with a large ratio is not
	// refused before it has sent anything worth measuring: a 200-byte gzip
	// header inflating to 4 KiB is an ordinary first event.
	if in := r.consumed(); r.ratio > 0 && r.out > 32<<10 && in > 0 && r.out/in > r.ratio {
		return n, errors.New("sse: compressed stream expanded past max_inflate_ratio")
	}
	return n, err
}

// consumed reports the compressed bytes read so far. It is the denominator of
// the ratio, and it is only available where the source is counted -- which is
// why inflate below wraps it in one.
func (r *ratioReader) consumed() int64 {
	if c, ok := r.src.(*countingReader); ok {
		return c.n
	}
	return 0
}

// countingReader counts what it passes through, so the ratio above has a
// denominator.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// sseCursor applies the part of the policy that is about the client: its
// cursor, which is the only input a client contributes to this protocol.
//
// It runs before the request is forwarded, which is the only place it can be
// decided -- Last-Event-ID has to be removed before the application reads it
// -- and it runs for every request on a route that has a guard rather than
// only for one whose Accept header asked for a stream. That is deliberate and
// it is the whole of the check's reach: what decides whether a stream is served
// is the *response's* Content-Type, so an application that answers a path with
// `text/event-stream` answers it that way for a client that sent no Accept
// header at all. Gating this on Accept would have meant the cursor policy was
// skipped by leaving a header out, which is not a bound. A Last-Event-ID on a
// request that turns out not to be a stream means nothing to anybody, so
// deciding about it there costs nothing.
func (g *sseGuard) sseCursor(r *http.Request, rec sseRecorder) {
	ids := r.Header.Values("Last-Event-ID")
	if len(ids) == 0 {
		return
	}
	if len(ids) > 1 {
		// Two cursors are a differential rather than a cursor. Reading the
		// first is one library's answer, the last is another's and the pair
		// joined by a comma is a third, so a policy that checked one of them
		// has checked a value the application may not be the one to use.
		// There is no reading of two Last-Event-ID headers that is a client
		// resuming a stream, so the header goes whatever the values are.
		r.Header.Del("Last-Event-ID")
		rec.stripped("last_event_id_repeated", strconv.Itoa(len(ids)))
		return
	}
	id := ids[0]
	if id == "" {
		return
	}
	switch {
	case !g.lastEventID:
		r.Header.Del("Last-Event-ID")
		rec.stripped("last_event_id_not_allowed", "")
	case len(id) > g.maxID:
		r.Header.Del("Last-Event-ID")
		rec.stripped("id_too_long", strconv.Itoa(len(id)))
	case g.idShape != nil && !g.idShape.MatchString(id):
		// A cursor of a shape the estate does not issue is not one the
		// application should resume from: it is a request for history the
		// client was never shown. Removing it rather than refusing the
		// request means the client gets the stream from the beginning,
		// which is what a client with no cursor gets.
		r.Header.Del("Last-Event-ID")
		rec.stripped("last_event_id_shape", textsafe.Clip64(id))
	}
}

// sseEncoding applies the part of the policy that is about what the client
// offered to accept, which has to be settled before the application compresses.
//
// Unlike the cursor above, this one is for a request that asked for a stream:
// a route that serves a page and a stream under one path is ordinary, and
// stripping Accept-Encoding from the page would make this proxy the reason the
// page is uncompressed.
func (g *sseGuard) sseEncoding(r *http.Request) {
	switch g.compression {
	case sseCompressInspect:
		// The route inflates, so the offer stands.
	default:
		// strip, and refuse too: refuse answers the request elsewhere, and if
		// it got here the offer must not reach the application.
		r.Header.Del("Accept-Encoding")
	}
}
