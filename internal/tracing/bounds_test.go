package tracing

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/otlp"
)

// A trace context arrives on a header a client writes. Everything the
// tracer keeps from it is held for the life of the span and again in
// the export queue, so what the client may put there decides how much
// memory one request costs.

// TestTraceStateIsBounded covers the vendor state, which is copied onto
// the server span and every child and kept until the exporter flushes.
func TestTraceStateIsBounded(t *testing.T) {
	tr, err := New(Config{SamplePercent: 100, Propagate: true}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		in   string
		kept bool
	}{
		{"empty", "", false},
		{"one vendor", "vendor=x", true},
		{"several vendors", "a=1,b=2,c=3", true},
		{"at the length limit", "v=" + strings.Repeat("x", 510), true},
		{"past the length limit", "v=" + strings.Repeat("x", 511), false},
		{"many entries", strings.Repeat("a=1,", 31) + "b=2", true},
		{"too many entries", strings.Repeat("a=1,", 40) + "b=2", false},
		{"newline", "a=1\nb=2", false},
		{"carriage return", "a=1\rb=2", false},
		{"nul", "a=\x00", false},
		{"del", "a=\x7f", false},
		{"non-ascii", "a=ö", false},
		{"tab", "a=\t1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
			r.Header.Set("Tracestate", tc.in)
			s := tr.StartServer(r, "GET")
			if tc.kept && s.TraceState != tc.in {
				t.Fatalf("kept %q, want %q", s.TraceState, tc.in)
			}
			if !tc.kept && s.TraceState != "" {
				t.Fatalf("kept %q, which must have been dropped", s.TraceState)
			}
			// Whatever the state, the child carries the same one.
			if c := s.Child("upstream"); c.TraceState != s.TraceState {
				t.Fatalf("the child carries %q, the parent %q", c.TraceState, s.TraceState)
			}
		})
	}
}

// TestSpanIdentifiers covers the hex renderings the access log and the
// error log carry, which is how a log line is tied to a trace.
func TestSpanIdentifiers(t *testing.T) {
	tr, err := New(Config{SamplePercent: 100}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	s := tr.StartServer(r, "GET")
	if len(s.TraceIDString()) != 32 {
		t.Fatalf("trace id %q", s.TraceIDString())
	}
	if len(s.SpanIDString()) != 16 {
		t.Fatalf("span id %q", s.SpanIDString())
	}
	if s.SpanIDString() == "0000000000000000" {
		t.Fatal("the span id is all zeroes")
	}
	// Two spans of one trace differ, or the identifiers name nothing.
	c := s.Child("upstream")
	if c.SpanIDString() == s.SpanIDString() {
		t.Fatal("a child shares its parent's span id")
	}
	if c.TraceIDString() != s.TraceIDString() {
		t.Fatal("a child started another trace")
	}
}

// TestFinishIsIdempotent covers a span ended twice, which is what a
// handler that returns early and a deferred Finish do together. The
// second call must not queue the span again: an exporter that saw the
// same span twice would double every count drawn from it.
func TestFinishIsIdempotent(t *testing.T) {
	tr, err := New(Config{
		SamplePercent: 100,
		Export:        &otlp.Config{Endpoint: "http://127.0.0.1:1/v1/traces", Timeout: time.Second},
		Queue:         16, Batch: 1000, Interval: time.Hour,
	}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	s := tr.StartServer(r, "GET")
	s.Set(otlp.String("http.method", "GET"))
	s.Finish(false)
	first := tr.Status().Queued
	s.Finish(false)
	s.Finish(true)
	if got := tr.Status().Queued; got != first {
		t.Fatalf("finishing twice queued the span again: %d then %d", first, got)
	}
}

// TestUnsampledSpansCostNothing requires an unsampled span not to reach
// the queue. At a 1% sample rate the other 99% must not be work.
func TestUnsampledSpansCostNothing(t *testing.T) {
	tr, err := New(Config{
		SamplePercent: 0,
		Export:        &otlp.Config{Endpoint: "http://127.0.0.1:1/v1/traces", Timeout: time.Second},
		Queue:         8, Batch: 1000, Interval: time.Hour,
	}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	for i := 0; i < 100; i++ {
		s := tr.StartServer(r, "GET")
		if s.Sampled {
			t.Fatal("a span was sampled at 0%")
		}
		s.Set(otlp.String("k", "v"))
		s.Finish(false)
	}
	if q := tr.Status().Queued; q != 0 {
		t.Fatalf("%d unsampled spans reached the queue", q)
	}
}

// TestQueueIsBounded requires the export queue to drop rather than
// block. The alternative is a slow collector holding the request path.
func TestQueueIsBounded(t *testing.T) {
	tr, err := New(Config{
		SamplePercent: 100,
		Export:        &otlp.Config{Endpoint: "http://127.0.0.1:1/v1/traces", Timeout: time.Second},
		Queue:         4, Batch: 1000, Interval: time.Hour,
	}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			tr.StartServer(r, "GET").Finish(false)
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("finishing spans blocked on a full queue")
	}
	st := tr.Status()
	if st.Dropped == 0 {
		t.Fatalf("1000 spans into a queue of 4 dropped none: %+v", st)
	}
}

// TestEncodeShape covers the exported document, which is what a
// collector parses. A span with no attributes and one with many must
// both produce a document rather than a panic.
func TestEncodeShape(t *testing.T) {
	tr, err := New(Config{
		SamplePercent: 100,
		Export:        &otlp.Config{Endpoint: "http://127.0.0.1:1/v1/traces", Timeout: time.Second, ServiceName: "xproxy"},
		Queue:         16, Batch: 1000, Interval: time.Hour,
	}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	bare := tr.StartServer(r, "GET")
	rich := tr.StartServer(r, "GET")
	for i := 0; i < 100; i++ {
		rich.Set(otlp.String("k", strings.Repeat("v", 100)))
	}
	rich.Error = true
	body := tr.Encode([]*Span{bare, rich})
	if len(body) == 0 {
		t.Fatal("the encoder produced nothing")
	}
	if !strings.Contains(string(body), "resourceSpans") {
		t.Fatalf("the document is not OTLP:\n%.200s", body)
	}
	// An empty batch is a document too, not a nil dereference.
	if len(tr.Encode(nil)) == 0 {
		t.Fatal("an empty batch produced nothing")
	}
	// A tracer that only propagates has no exporter and no resource to
	// describe: it encodes to nothing rather than reaching for a client
	// it never built.
	only, err := New(Config{SamplePercent: 100, Propagate: true}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if got := only.Encode([]*Span{bare}); got != nil {
		t.Fatalf("a propagate-only tracer encoded %d bytes", len(got))
	}
}

// TestNilTracerIsInert covers a proxy with no tracing configured, where
// every call site still runs.
func TestNilTracerIsInert(t *testing.T) {
	var tr *Tracer
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	s := tr.StartServer(r, "GET")
	s.Set(otlp.String("k", "v"))
	if s.Child("x") != nil {
		t.Fatal("a nil tracer made a child span")
	}
	s.Finish(true)
	if s.Traceparent() != "" {
		t.Fatalf("a nil tracer produced the traceparent %q", s.Traceparent())
	}
	tr.Stop()
	if st := tr.Status(); st.Enabled {
		t.Fatalf("a nil tracer reports %+v", st)
	}
}
