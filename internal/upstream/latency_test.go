package upstream

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func TestLatencyEjection(t *testing.T) {
	c := testCfg("round_robin", "a:1", "b:1")
	c.OutlierEjection = &config.OutlierEjection{ConsecutiveFailures: 5, BaseEjectionTime: config.Duration(time.Minute), MaxEjectionPercent: 50,
		LatencyThreshold: config.Duration(200 * time.Millisecond), LatencyMinSamples: 5}
	p, _ := NewPool(c, nolog)
	a, b := p.endpoints()[0], p.endpoints()[1]
	// Fast responses never eject.
	for i := 0; i < 20; i++ {
		p.Begin(a)
		p.End(a, false, 10*time.Millisecond)
	}
	if !a.Available(time.Now()) || a.stats(time.Now()).LatencyMS > 11 {
		t.Fatalf("fast endpoint: %+v", a.stats(time.Now()))
	}
	// Slow responses eject after min_samples, and the average is reset.
	for i := 0; i < 4; i++ {
		p.Begin(b)
		p.End(b, false, time.Second)
	}
	if !b.Available(time.Now()) {
		t.Fatal("ejected before latency_min_samples")
	}
	p.Begin(b)
	p.End(b, false, time.Second)
	if b.Available(time.Now()) {
		t.Fatal("slow endpoint not ejected")
	}
	if st := b.stats(time.Now()); st.LatencyEjections != 1 || st.Ejections != 1 || st.LatencyMS != 0 {
		t.Fatalf("stats after ejection: %+v", st)
	}
	// While ejected, samples do not eject again; max_ejection_percent
	// protects the other endpoint.
	for i := 0; i < 10; i++ {
		p.Begin(a)
		p.End(a, false, 2*time.Second)
	}
	if !a.Available(time.Now()) {
		t.Fatal("max_ejection_percent violated by a latency ejection")
	}

	// Relative rule: three endpoints, one three times slower than the pool.
	c = testCfg("round_robin", "a:1", "b:1", "c:1")
	c.OutlierEjection = &config.OutlierEjection{ConsecutiveFailures: 5, BaseEjectionTime: config.Duration(time.Minute), MaxEjectionPercent: 50,
		LatencyFactor: 3, LatencyMinSamples: 5}
	p, _ = NewPool(c, nolog)
	eps := p.endpoints()
	for i := 0; i < 30; i++ {
		for _, e := range eps[:2] {
			p.Begin(e)
			p.End(e, false, 20*time.Millisecond)
		}
	}
	for i := 0; i < 5; i++ {
		p.Begin(eps[2])
		p.End(eps[2], false, 20*time.Millisecond)
	}
	if !eps[2].Available(time.Now()) {
		t.Fatal("endpoint at the pool average ejected")
	}
	for i := 0; i < 40 && eps[2].Available(time.Now()); i++ {
		p.Begin(eps[2])
		p.End(eps[2], false, 400*time.Millisecond)
	}
	if eps[2].Available(time.Now()) {
		t.Fatal("endpoint three times slower than the pool not ejected")
	}
	// Failures and zero latency record no sample.
	if eps[0].latencySamples.Load() != 30 {
		t.Fatalf("samples: %d", eps[0].latencySamples.Load())
	}
	p.Begin(eps[0])
	p.End(eps[0], true, 0)
	if eps[0].latencySamples.Load() != 30 {
		t.Fatal("a zero latency counted as a sample")
	}
}

func TestHealthCheckBody(t *testing.T) {
	var body atomic.Pointer[string]
	set := func(s string) { body.Store(&s) }
	set(`{"status":"ok","db":"up"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(*body.Load()))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	c := testCfg("round_robin", addr)
	c.HealthCheck = &config.HealthCheck{Type: "http", Path: "/health", Interval: config.Duration(50 * time.Millisecond), Timeout: config.Duration(20 * time.Millisecond),
		HealthyThreshold: 1, UnhealthyThreshold: 1, ExpectedStatus: []int{200}, MaxConcurrent: 4,
		BodyContains: `"status":"ok"`, BodyRegex: `"db":"(up|degraded)"`}
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	p.Start()
	defer p.Stop()
	e := p.endpoints()[0]
	wait := func(want bool, what string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for e.Healthy() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: healthy=%v", what, e.Healthy())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait(true, "matching body")
	set(`{"status":"ok","db":"down"}`)
	wait(false, "regex mismatch")
	set(`{"status":"ok","db":"degraded"}`)
	wait(true, "regex alternative")
	set(`{"status":"starting","db":"up"}`)
	wait(false, "body_contains mismatch")
}
