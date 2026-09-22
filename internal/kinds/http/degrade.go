package http

import (
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
)

// Graduated degradation.
//
// The proxy's answers are binary: a client is served or it is refused.
// For a client that has done something wrong but not enough to ban —
// touched a decoy, scored badly, come from a range with a history —
// both answers are wrong. Serving it in full funds the next request;
// refusing it outright tells it exactly which request to change, and
// hands a scanner a clean signal to tune against.
//
// Degrading is the middle: the client is served, correctly, slowly.
// The page arrives, so there is nothing to tune against and nothing to
// report as broken. It arrives at eight kilobytes a second on a
// connection that will not be reused, so a crawl that cost the scanner
// nothing now costs it the one thing it has least of — time.

// degradeLevel is one compiled rule: who, and how much.
type degradeLevel struct {
	cfg      *config.DegradeLevel
	clients  []netip.Prefix
	routes   map[string]bool
	methods  map[string]bool
	applied  atomic.Uint64
	rate     int64
	delay    time.Duration
	closeIt  bool
	scoreAt  float64
	onScore  bool
	onMarked bool
}

// degradation is the compiled section.
type degradation struct {
	levels []*degradeLevel
}

func newDegradation(c *config.Degradation) *degradation {
	if c == nil || len(c.Levels) == 0 {
		return nil
	}
	d := &degradation{}
	for i := range c.Levels {
		l := &c.Levels[i]
		lv := &degradeLevel{
			cfg: l, rate: l.BytesPerSecond, delay: l.Delay.D(), closeIt: l.Close,
			onMarked: l.Marked, onScore: l.BotScoreAt > 0, scoreAt: float64(l.BotScoreAt),
		}
		lv.clients = netutil.ParsePrefixes(l.ClientCIDRs)
		if len(l.Routes) > 0 {
			lv.routes = map[string]bool{}
			for _, r := range l.Routes {
				lv.routes[r] = true
			}
		}
		if len(l.Methods) > 0 {
			lv.methods = map[string]bool{}
			for _, m := range l.Methods {
				lv.methods[strings.ToUpper(m)] = true
			}
		}
		d.levels = append(d.levels, lv)
	}
	return d
}

// pick returns the first level that admits this request, or nil. The
// first match wins, so the narrowest level goes first — the same order
// every other list in the configuration uses.
func (d *degradation) pick(st *reqState, r *http.Request) *degradeLevel {
	if d == nil {
		return nil
	}
	for _, l := range d.levels {
		if l.admits(st, r) {
			return l
		}
	}
	return nil
}

func (l *degradeLevel) admits(st *reqState, r *http.Request) bool {
	if l.routes != nil && !l.routes[st.route] {
		return false
	}
	if l.methods != nil && !l.methods[strings.ToUpper(r.Method)] {
		return false
	}
	if len(l.clients) > 0 && !netutil.Contains(l.clients, st.clientIP) {
		return false
	}
	// The conditions proper. A level that names none applies to every
	// request the selectors above let through, which is how a route is
	// put on a slow lane wholesale.
	if !l.onMarked && !l.onScore {
		return true
	}
	if l.onMarked && st.marked {
		return true
	}
	if l.onScore {
		if score, ok := botScoreOf(st); ok && score >= l.scoreAt {
			return true
		}
	}
	return false
}

// botScoreOf reads the score a bot_score filter recorded for the access
// log. It is a small linear scan over attributes the filters added,
// done only for a level that asks for it.
func botScoreOf(st *reqState) (float64, bool) {
	for i := 0; i+1 < len(st.extra); i += 2 {
		if name, ok := st.extra[i].(string); !ok || name != "bot_score" {
			continue
		}
		switch v := st.extra[i+1].(type) {
		case int:
			return float64(v), true
		case int64:
			return float64(v), true
		case float64:
			return v, true
		}
	}
	return 0, false
}

// apply installs the level on the response. It returns the delay to
// hold the response for, which the caller spends in a tarpit slot
// rather than a request slot.
func (s *engine) applyDegradation(rw *responseWriter, r *http.Request, st *reqState) time.Duration {
	d := s.degradation.Load()
	if d == nil {
		return 0
	}
	l := d.pick(st, r)
	if l == nil {
		return 0
	}
	l.applied.Add(1)
	s.stats.Degraded.Add(1)
	st.degraded = l.cfg.Name
	st.extra = append(st.extra, "degraded", l.cfg.Name)
	if l.closeIt {
		// A connection the client cannot reuse costs it a handshake per
		// request, and costs us one accept we were going to pay anyway.
		rw.Header().Set("Connection", "close")
		r.Close = true
	}
	if l.rate > 0 {
		rw.ResponseWriter = &shapedWriter{ResponseWriter: rw.ResponseWriter, rate: l.rate, ctx: r.Context()}
	}
	return l.delay
}

// shapedWriter writes at a bounded rate. It is a token bucket without a
// goroutine or a timer: each write takes what it needs and sleeps for
// what it took, which is exactly the shape of a slow link.
type shapedWriter struct {
	http.ResponseWriter
	rate    int64 // bytes per second
	allowed float64
	last    time.Time
	ctx     interface{ Done() <-chan struct{} }
}

func (w *shapedWriter) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		n := w.take(len(p) - written)
		m, err := w.ResponseWriter.Write(p[written : written+n])
		written += m
		if err != nil {
			return written, err
		}
		if f, ok := w.ResponseWriter.(http.Flusher); ok && written < len(p) {
			// Without a flush the shaping would only delay a buffer
			// boundary rather than the bytes the client sees.
			f.Flush()
		}
	}
	return written, nil
}

// take waits until the bucket holds at least one byte and returns how
// many of the n wanted it can spend now, at most a second's worth so a
// large body is written in pieces rather than after one long sleep.
func (w *shapedWriter) take(n int) int {
	now := time.Now()
	if w.last.IsZero() {
		// The first write starts with a second's allowance, so a small
		// response is not delayed before it has spent anything.
		w.last, w.allowed = now, float64(w.rate)
	} else {
		w.allowed += now.Sub(w.last).Seconds() * float64(w.rate)
		w.last = now
		if w.allowed > float64(w.rate) {
			w.allowed = float64(w.rate)
		}
	}
	for w.allowed < 1 {
		wait := time.Duration(float64(time.Second) * (1 - w.allowed) / float64(w.rate))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		if wait > time.Second {
			wait = time.Second
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-w.ctx.Done():
			// The client gave up. Stop sleeping and let the write fail
			// the way it would have anyway.
			t.Stop()
			return min(n, 1)
		}
		now = time.Now()
		w.allowed += now.Sub(w.last).Seconds() * float64(w.rate)
		w.last = now
	}
	take := min(n, int(w.allowed))
	if take < 1 {
		take = 1
	}
	w.allowed -= float64(take)
	return take
}

func (w *shapedWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *shapedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Degradation reports the configured levels and how often each applied.
func (s *engine) Degradation() []proxy.DegradeStatus {
	d := s.degradation.Load()
	if d == nil {
		return nil
	}
	out := make([]proxy.DegradeStatus, 0, len(d.levels))
	for _, l := range d.levels {
		st := proxy.DegradeStatus{Name: l.cfg.Name, Applied: l.applied.Load(),
			BytesPerSecond: l.rate, Close: l.closeIt}
		if l.delay > 0 {
			st.Delay = l.delay.String()
		}
		out = append(out, st)
	}
	return out
}

// holdDegraded spends a degradation delay in a tarpit slot rather than
// a request slot, the way a honeypot delay does: a held response must
// not occupy the concurrency the proxy sells to everyone else. It
// reports false when the client gave up first.
func (s *engine) holdDegraded(r *http.Request, d time.Duration) bool {
	release, ok := s.tarpits.Acquire()
	if !ok {
		// No slot: serve without the delay rather than queue. The
		// shaping and the connection close still apply.
		s.stats.TarpitOverflow.Add(1)
		return true
	}
	defer release()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-r.Context().Done():
		return false
	}
}
