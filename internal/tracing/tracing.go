// Package tracing gives every request a W3C trace context (traceparent,
// RFC-less but universal), propagates it to the upstream and exports one
// server span per request, and one client span per upstream exchange, as
// OTLP/HTTP JSON. No SDK: the span is a small struct, the exporter a
// bounded queue and a batching goroutine.
package tracing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/rom/xproxy/internal/bound"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/otlp"
)

// Config is the tracer's configuration.
type Config struct {
	SamplePercent float64
	Propagate     bool
	// TrustIncoming honours the sampled flag of an incoming traceparent;
	// otherwise the local sampling share decides.
	TrustIncoming bool
	// Export is nil when spans are only propagated, not exported.
	Export   *otlp.Config
	Batch    int
	Interval time.Duration
	Queue    int
}

// Status is the management view.
type Status struct {
	Enabled       bool      `json:"enabled"`
	SamplePercent float64   `json:"sample_percent"`
	Propagate     bool      `json:"propagate"`
	Endpoint      string    `json:"endpoint,omitempty"`
	Started       uint64    `json:"spans_started"`
	Sampled       uint64    `json:"spans_sampled"`
	Sent          uint64    `json:"spans_sent"`
	Dropped       uint64    `json:"spans_dropped"`
	Pushes        uint64    `json:"pushes"`
	Failed        uint64    `json:"pushes_failed"`
	Queued        int       `json:"queued"`
	LastSent      time.Time `json:"last_sent,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
}

// Tracer creates spans and exports them.
type Tracer struct {
	cfg    Config
	client *otlp.Client
	log    *slog.Logger

	queue     chan *Span
	stop      chan struct{}
	queueFull bound.Notice
	wg        sync.WaitGroup
	once      sync.Once

	started, sampled, sent, dropped, pushes, failed atomic.Uint64
	mu                                              sync.Mutex
	lastSent                                        time.Time
	lastErr                                         string
}

// Span is one unit of work.
type Span struct {
	TraceID  [16]byte
	SpanID   [8]byte
	ParentID [8]byte
	Sampled  bool
	Name     string
	Kind     int // 2 server, 3 client
	Start    time.Time
	End      time.Time
	Attrs    []otlp.KV
	Error    bool
	// TraceState is passed through untouched.
	TraceState string
	tracer     *Tracer
	ended      atomic.Bool
}

// New builds a tracer; with an export configuration the batching
// goroutine starts at once.
func New(cfg Config, log *slog.Logger) (*Tracer, error) {
	t := &Tracer{cfg: cfg, log: log, stop: make(chan struct{})}
	if cfg.Export != nil {
		c, err := otlp.New(*cfg.Export)
		if err != nil {
			return nil, err
		}
		t.client = c
		if cfg.Batch <= 0 {
			cfg.Batch = 512
		}
		if cfg.Interval <= 0 {
			cfg.Interval = 5 * time.Second
		}
		if cfg.Queue <= 0 {
			cfg.Queue = 8192
		}
		t.cfg = cfg
		t.queue = make(chan *Span, cfg.Queue)
		t.wg.Add(1)
		go t.loop()
	}
	return t, nil
}

// Stop flushes and ends the exporter.
func (t *Tracer) Stop() {
	if t == nil || t.client == nil {
		return
	}
	t.once.Do(func() { close(t.stop) })
	t.wg.Wait()
}

// Status returns counters.
func (t *Tracer) Status() Status {
	if t == nil {
		return Status{}
	}
	st := Status{Enabled: true, SamplePercent: t.cfg.SamplePercent, Propagate: t.cfg.Propagate,
		Started: t.started.Load(), Sampled: t.sampled.Load(), Sent: t.sent.Load(), Dropped: t.dropped.Load(),
		Pushes: t.pushes.Load(), Failed: t.failed.Load()}
	if t.client != nil {
		st.Endpoint = t.client.Config().Endpoint
		st.Queued = len(t.queue)
	}
	t.mu.Lock()
	st.LastSent, st.LastError = t.lastSent, t.lastErr
	t.mu.Unlock()
	return st
}

// StartServer begins the server span of a request: the incoming
// traceparent is continued (its sampled flag honoured) or a new trace
// started, sampled by percent.
func (t *Tracer) StartServer(r *http.Request, name string) *Span {
	// A nil tracer is how this package spells "tracing is off", and
	// every other method already takes one; a nil span is inert in the
	// same way, so a caller that skipped the check still works.
	if t == nil {
		return nil
	}
	s := &Span{Name: name, Kind: 2, Start: time.Now(), tracer: t}
	t.started.Add(1)
	if tp := r.Header.Get("Traceparent"); tp != "" {
		if tid, pid, flags, ok := parseTraceparent(tp); ok {
			s.TraceID, s.ParentID = tid, pid
			s.TraceState = boundedTraceState(r.Header.Get("Tracestate"))
			_, _ = rand.Read(s.SpanID[:])
			if t.cfg.TrustIncoming {
				s.Sampled = flags&1 == 1
			} else {
				s.Sampled = t.decide()
			}
			if s.Sampled {
				t.sampled.Add(1)
			}
			return s
		}
	}
	_, _ = rand.Read(s.TraceID[:])
	_, _ = rand.Read(s.SpanID[:])
	s.Sampled = t.decide()
	if s.Sampled {
		t.sampled.Add(1)
	}
	return s
}

// decide applies the sampling share.
func (t *Tracer) decide() bool {
	return t.cfg.SamplePercent >= 100 || (t.cfg.SamplePercent > 0 && mrand.Float64()*100 < t.cfg.SamplePercent)
}

// Child starts a client span under parent.
func (parent *Span) Child(name string) *Span {
	if parent == nil {
		return nil
	}
	c := &Span{TraceID: parent.TraceID, ParentID: parent.SpanID, Sampled: parent.Sampled, Name: name, Kind: 3,
		Start: time.Now(), TraceState: parent.TraceState, tracer: parent.tracer}
	_, _ = rand.Read(c.SpanID[:])
	return c
}

// Traceparent renders the header value that names this span as parent.
// A nil span has no trace to name, so it renders as nothing and the
// header is simply not sent.
func (s *Span) Traceparent() string {
	if s == nil {
		return ""
	}
	flags := "00"
	if s.Sampled {
		flags = "01"
	}
	return "00-" + hex.EncodeToString(s.TraceID[:]) + "-" + hex.EncodeToString(s.SpanID[:]) + "-" + flags
}

// TraceIDString and SpanIDString return the hex identifiers for logs,
// or "" for a nil span, so a log line built without tracing carries an
// empty field rather than crashing the request.
func (s *Span) TraceIDString() string {
	if s == nil {
		return ""
	}
	return hex.EncodeToString(s.TraceID[:])
}

func (s *Span) SpanIDString() string {
	if s == nil {
		return ""
	}
	return hex.EncodeToString(s.SpanID[:])
}

// Set adds attributes.
func (s *Span) Set(kv ...otlp.KV) {
	if s == nil {
		return
	}
	s.Attrs = append(s.Attrs, kv...)
}

// Finish ends the span and queues it when sampled and exported. It is
// idempotent.
func (s *Span) Finish(err bool) {
	if s == nil || !s.ended.CompareAndSwap(false, true) {
		return
	}
	s.End = time.Now()
	s.Error = err
	t := s.tracer
	if t == nil || t.client == nil || !s.Sampled {
		return
	}
	select {
	case t.queue <- s:
	default:
		t.dropped.Add(1)
		t.queueFull.Hit(t.log, "trace queue full; spans are dropped", "table", "trace_queue")
	}
}

// Propagate reports whether outgoing requests get a traceparent.
func (t *Tracer) Propagate() bool { return t != nil && t.cfg.Propagate }

// boundedTraceState keeps an incoming tracestate only within the bounds
// the W3C recommendation sets: at most 512 bytes and 32 list members,
// with anything longer discarded rather than truncated. The header is
// client-supplied and is retained on the server span and on the
// upstream span until the exporter flushes, so without a bound a client
// decides how many bytes each sampled request holds in the queue.
func boundedTraceState(v string) string {
	if v == "" {
		return ""
	}
	if len(v) > 512 || strings.Count(v, ",") >= 32 {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return v
}

func parseTraceparent(v string) (tid [16]byte, pid [8]byte, flags byte, ok bool) {
	parts := strings.Split(strings.TrimSpace(v), "-")
	if len(parts) < 4 || len(parts[0]) != 2 || parts[0] == "ff" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return
	}
	t, err := hex.DecodeString(parts[1])
	if err != nil {
		return
	}
	p, err := hex.DecodeString(parts[2])
	if err != nil {
		return
	}
	f, err := hex.DecodeString(parts[3])
	if err != nil {
		return
	}
	copy(tid[:], t)
	copy(pid[:], p)
	if tid == [16]byte{} || pid == [8]byte{} {
		return
	}
	return tid, pid, f[0], true
}

func (t *Tracer) loop() {
	defer t.wg.Done()
	ticker := time.NewTicker(t.cfg.Interval)
	defer ticker.Stop()
	batch := make([]*Span, 0, t.cfg.Batch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), t.client.Config().Timeout)
		err := t.client.Post(ctx, t.encode(batch))
		cancel()
		t.pushes.Add(1)
		t.mu.Lock()
		if err != nil {
			t.failed.Add(1)
			t.dropped.Add(uint64(len(batch))) //nolint:gosec // bounded by Batch
			t.lastErr = err.Error()
			t.log.Warn("trace export failed", "endpoint", t.client.Config().Endpoint, "err", err.Error())
		} else {
			t.sent.Add(uint64(len(batch))) //nolint:gosec // bounded by Batch
			t.lastSent = time.Now()
			t.lastErr = ""
		}
		t.mu.Unlock()
		batch = batch[:0]
	}
	for {
		select {
		case <-t.stop:
			for {
				select {
				case s := <-t.queue:
					batch = append(batch, s)
					if len(batch) >= t.cfg.Batch {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		case s := <-t.queue:
			batch = append(batch, s)
			if len(batch) >= t.cfg.Batch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// encode renders a batch as an OTLP/JSON ExportTraceServiceRequest.
func (t *Tracer) encode(batch []*Span) []byte {
	type status struct {
		Code int `json:"code"`
	}
	type span struct {
		TraceID    string    `json:"traceId"`
		SpanID     string    `json:"spanId"`
		ParentID   string    `json:"parentSpanId,omitempty"`
		TraceState string    `json:"traceState,omitempty"`
		Name       string    `json:"name"`
		Kind       int       `json:"kind"`
		Start      string    `json:"startTimeUnixNano"`
		End        string    `json:"endTimeUnixNano"`
		Attributes []otlp.KV `json:"attributes,omitempty"`
		Status     status    `json:"status"`
	}
	spans := make([]span, 0, len(batch))
	for _, s := range batch {
		sp := span{TraceID: hex.EncodeToString(s.TraceID[:]), SpanID: hex.EncodeToString(s.SpanID[:]), TraceState: s.TraceState,
			Name: s.Name, Kind: s.Kind, Start: otlp.Nanos(s.Start), End: otlp.Nanos(s.End), Attributes: s.Attrs}
		if s.ParentID != [8]byte{} {
			sp.ParentID = hex.EncodeToString(s.ParentID[:])
		}
		if s.Error {
			sp.Status = status{Code: 2}
		} else {
			sp.Status = status{Code: 1}
		}
		spans = append(spans, sp)
	}
	body, _ := json.Marshal(map[string]any{
		"resourceSpans": []any{map[string]any{
			"resource": map[string]any{"attributes": t.client.Resource()},
			"scopeSpans": []any{map[string]any{
				"scope": map[string]any{"name": "xproxy", "version": t.client.Config().Version},
				"spans": spans,
			}},
		}},
	})
	return body
}

// Encode is exposed for tests. A tracer that only propagates has no
// exporter and therefore no resource to describe, so it encodes to
// nothing rather than dereferencing a client it never built.
func (t *Tracer) Encode(batch []*Span) []byte {
	if t == nil || t.client == nil {
		return nil
	}
	return t.encode(batch)
}

var mrand = rand2{}

// rand2 wraps math/rand/v2 so the sampling source is explicit.
type rand2 struct{}

func (rand2) Float64() float64 { return mathrand.Float64() } //nolint:gosec // sampling, not security
