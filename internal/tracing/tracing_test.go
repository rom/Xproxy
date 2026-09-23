package tracing

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/otlp"
)

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestTraceparent(t *testing.T) {
	tr, _ := New(Config{SamplePercent: 100, Propagate: true}, nolog)
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	r.Header.Set("Tracestate", "vendor=x")
	s := tr.StartServer(r, "GET")
	if s.TraceIDString() != "4bf92f3577b34da6a3ce929d0e0e4736" || s.ParentID != [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7} || s.TraceState != "vendor=x" || !s.Sampled {
		t.Fatalf("continued span %+v", s)
	}
	tp := s.Traceparent()
	if !strings.HasPrefix(tp, "00-4bf92f3577b34da6a3ce929d0e0e4736-") || !strings.HasSuffix(tp, "-01") || strings.Contains(tp, "00f067aa0ba902b7") {
		t.Fatalf("outgoing traceparent %q", tp)
	}
	c := s.Child("upstream a")
	if c.TraceID != s.TraceID || c.ParentID != s.SpanID || c.Kind != 3 || !c.Sampled || c.TraceState != "vendor=x" {
		t.Fatalf("child %+v", c)
	}
	// Malformed and all-zero contexts start a new trace.
	for _, bad := range []string{"", "xx", "00-0000000000000000000000000000000-0000000000000000-01", "00-00000000000000000000000000000000-00f067aa0ba902b7-01", "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-zz-01"} {
		r.Header.Set("Traceparent", bad)
		n := tr.StartServer(r, "GET")
		if n.TraceIDString() == "4bf92f3577b34da6a3ce929d0e0e4736" || n.ParentID != [8]byte{} {
			t.Fatalf("%q continued: %+v", bad, n)
		}
	}
	// Sampling: 0 never, an incoming sampled flag is not trusted by default.
	off, _ := New(Config{SamplePercent: 0}, nolog)
	r.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if off.StartServer(r, "GET").Sampled {
		t.Fatal("client forced sampling")
	}
	trust, _ := New(Config{SamplePercent: 0, TrustIncoming: true}, nolog)
	if !trust.StartServer(r, "GET").Sampled {
		t.Fatal("trusted flag ignored")
	}
	r.Header.Del("Traceparent")
	half, _ := New(Config{SamplePercent: 50}, nolog)
	n := 0
	for i := 0; i < 2000; i++ {
		if half.StartServer(r, "GET").Sampled {
			n++
		}
	}
	if n < 800 || n > 1200 {
		t.Fatalf("50%% sampled %d of 2000", n)
	}
	if st := half.Status(); st.Started != 2000 || st.Sampled != uint64(n) || st.Endpoint != "" { //nolint:gosec // positive
		t.Fatalf("status %+v", st)
	}
	var none *Tracer
	if none.Propagate() || none.Status().Enabled {
		t.Fatal("nil tracer")
	}
	var nilSpan *Span
	nilSpan.Set(otlp.String("a", "b"))
	nilSpan.Finish(false)
	if nilSpan.Child("x") != nil {
		t.Fatal("child of nil")
	}
}

func TestExport(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer t" || r.Header.Get("Content-Encoding") != "" {
			w.WriteHeader(400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		got = append(got, doc)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	t.Cleanup(collector.Close)
	tr, err := New(Config{SamplePercent: 100, Propagate: true,
		Export: &otlp.Config{Endpoint: collector.URL, Timeout: 2 * time.Second, Headers: map[string]string{"Authorization": "Bearer t"}, ServiceName: "edge", Attributes: map[string]string{"env": "test"}, Version: "9"},
		// The batch size is what flushes here, not the interval: with
		// a short interval the ticker can fire between the two spans
		// and push the first on its own, which is a second push this
		// test then asserts did not happen.
		Batch: 2, Interval: time.Hour, Queue: 10}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	s := tr.StartServer(r, "GET")
	s.Set(otlp.String("http.request.method", "GET"), otlp.Int("http.response.status_code", 200), otlp.Bool("b", true), otlp.Float("f", 1.5))
	c := s.Child("upstream app")
	c.Finish(false)
	s.Name = "GET web"
	s.Finish(true)
	s.Finish(false) // idempotent
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("pushes %d", len(got))
	}
	rs := got[0]["resourceSpans"].([]any)[0].(map[string]any)
	res := rs["resource"].(map[string]any)["attributes"].([]any)
	if a := res[0].(map[string]any); a["key"] != "service.name" || a["value"].(map[string]any)["stringValue"] != "edge" {
		t.Fatalf("resource %v", res)
	}
	spans := rs["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)
	if len(spans) != 2 {
		t.Fatalf("spans %v", spans)
	}
	child, server := spans[0].(map[string]any), spans[1].(map[string]any)
	if child["parentSpanId"] != server["spanId"] || child["traceId"] != server["traceId"] || child["kind"].(float64) != 3 || server["kind"].(float64) != 2 {
		t.Fatalf("span relation: %v / %v", child, server)
	}
	if server["name"] != "GET web" || server["status"].(map[string]any)["code"].(float64) != 2 || child["status"].(map[string]any)["code"].(float64) != 1 || server["parentSpanId"] != nil {
		t.Fatalf("server span %v", server)
	}
	attrs := server["attributes"].([]any)
	if len(attrs) != 4 || attrs[1].(map[string]any)["value"].(map[string]any)["intValue"] != "200" || attrs[2].(map[string]any)["value"].(map[string]any)["boolValue"] != true {
		t.Fatalf("attributes %v", attrs)
	}
	st := tr.Status()
	if st.Sent != 2 || st.Pushes != 1 || st.Failed != 0 || st.Endpoint != collector.URL {
		t.Fatalf("status %+v", st)
	}
	// A dead collector counts failures and drops; Stop flushes.
	collector.Close()
	x := tr.StartServer(r, "GET")
	x.Finish(false)
	tr.Stop()
	if st := tr.Status(); st.Failed == 0 || st.Dropped == 0 || st.LastError == "" {
		t.Fatalf("after failure %+v", st)
	}
}
