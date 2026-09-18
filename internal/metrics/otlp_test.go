package metrics

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestOTLPExporter(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	var headers []http.Header
	fail := false
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		var rd io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			rd = gz
		}
		b, _ := io.ReadAll(rd)
		bodies = append(bodies, b)
		headers = append(headers, r.Header.Clone())
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(col.Close)
	h := NewHistogram([]float64{0.1, 1})
	h.Observe(0.05)
	h.Observe(5)
	source := func(c Collector) {
		c.Counter("xproxy_requests_total", "Requests.", nil, 42)
		c.Counter("xproxy_responses_total", "By class.", Labels{"class": "2xx"}, 40)
		c.Counter("xproxy_responses_total", "By class.", Labels{"class": "5xx"}, 2)
		c.Gauge("xproxy_connections_open", "Open.", nil, 3)
		c.Histogram("xproxy_request_duration_seconds", "Latency.", nil, h.Snapshot())
	}
	ex, err := NewOTLPExporter(OTLPConfig{Endpoint: col.URL + "/v1/metrics", Interval: 50 * time.Millisecond, Timeout: 2 * time.Second,
		Headers: map[string]string{"Authorization": "Bearer t0k"}, ServiceName: "edge", Attributes: map[string]string{"deployment.environment": "test"}, Compress: true, Version: "1.3"}, source, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(bodies) != 1 || headers[0].Get("Authorization") != "Bearer t0k" || headers[0].Get("Content-Type") != "application/json" {
		mu.Unlock()
		t.Fatalf("push: %d bodies, headers %v", len(bodies), headers)
	}
	var doc struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []otlpKV `json:"attributes"`
			} `json:"resource"`
			ScopeMetrics []struct {
				Metrics []otlpMetric `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(bodies[0], &doc); err != nil {
		mu.Unlock()
		t.Fatal(err)
	}
	mu.Unlock()
	rm := doc.ResourceMetrics[0]
	attrs := map[string]string{}
	for _, kv := range rm.Resource.Attributes {
		attrs[kv.Key] = kv.Value.StringValue
	}
	if attrs["service.name"] != "edge" || attrs["service.version"] != "1.3" || attrs["deployment.environment"] != "test" || attrs["host.name"] == "" {
		t.Fatalf("resource: %v", attrs)
	}
	ms := map[string]otlpMetric{}
	for _, m := range rm.ScopeMetrics[0].Metrics {
		ms[m.Name] = m
	}
	if s := ms["xproxy_responses_total"].Sum; s == nil || !s.Monotonic || s.Temporality != cumulative || len(s.Points) != 2 || s.Points[0].Attributes[0].Value.StringValue != "2xx" || *s.Points[1].AsDouble != 2 || s.Points[0].StartTime == "" {
		t.Fatalf("sum: %+v", ms["xproxy_responses_total"])
	}
	if g := ms["xproxy_connections_open"].Gauge; g == nil || *g.Points[0].AsDouble != 3 || g.Points[0].StartTime != "" {
		t.Fatalf("gauge: %+v", ms["xproxy_connections_open"])
	}
	hist := ms["xproxy_request_duration_seconds"].Histogram
	if hist == nil || hist.Temporality != cumulative || hist.Points[0].Count != "2" || len(hist.Points[0].BucketCounts) != 3 || hist.Points[0].BucketCounts[0] != "1" || hist.Points[0].BucketCounts[2] != "1" || len(hist.Points[0].ExplicitBound) != 2 {
		t.Fatalf("histogram: %+v", hist)
	}
	if st := ex.Status(); st.Sent != 1 || st.Failed != 0 || st.Metrics != 4 || st.LastBytes == 0 || st.LastSent.IsZero() {
		t.Fatalf("status: %+v", st)
	}
	// The loop pushes on the interval; a failing collector is counted.
	ex.Start()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && ex.Status().Sent < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && ex.Status().Failed == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	ex.Stop() // one final push
	st := ex.Status()
	if st.Sent < 4 || st.Failed == 0 || st.LastError != "" {
		t.Fatalf("after loop: %+v", st)
	}
	if _, err := NewOTLPExporter(OTLPConfig{Endpoint: col.URL, CAFile: "/nonexistent.pem", Interval: time.Second, Timeout: time.Second}, source, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("missing ca accepted")
	}
}
