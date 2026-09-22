package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreaker(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(origin.Close)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: o
    retries: 0
    circuit_breaker: {consecutive_failures: 2, open_for: 400ms, half_open_requests: 1}
    endpoints: [{address: %q}]
routes:
  - name: r
    upstream: o
`, strings.TrimPrefix(origin.URL, "http://"))
	s, url := startServer(t, yaml)
	for i := 0; i < 2; i++ {
		if resp, _ := get(t, url+"/"); resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "" {
			t.Fatalf("upstream 503 %d: %d %v", i, resp.StatusCode, resp.Header)
		}
	}
	// The circuit is open: refused locally with Retry-After, the upstream
	// not contacted.
	resp, _ := get(t, url+"/")
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("open circuit: %d %v", resp.StatusCode, resp.Header)
	}
	pools := s.Pools()
	if c := pools["o"].Circuit; c == nil || c.State != "open" || c.Opens != 1 || c.Rejected != 1 {
		t.Fatalf("pool status %+v", pools["o"])
	}
	if st := s.Stats(); st.UpstreamCircuitOpen != 1 {
		t.Fatalf("counter %+v", st)
	}
	// After open_for one trial goes through; the upstream is healthy again,
	// so the circuit closes and traffic flows.
	failing.Store(false)
	time.Sleep(500 * time.Millisecond)
	if resp, body := get(t, url+"/"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("trial: %d %q", resp.StatusCode, body)
	}
	if c := s.Pools()["o"].Circuit; c.State != "closed" {
		t.Fatalf("after trial %+v", c)
	}
	for i := 0; i < 3; i++ {
		if resp, _ := get(t, url+"/"); resp.StatusCode != 200 {
			t.Fatalf("closed %d: %d", i, resp.StatusCode)
		}
	}
}

func TestUpstreamQueue(t *testing.T) {
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started.Done()
		<-release
		_, _ = w.Write([]byte("slow"))
	}))
	t.Cleanup(origin.Close)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: o
    max_concurrent: 1
    queue: {size: 1, timeout: 200ms}
    endpoints: [{address: %q}]
routes:
  - name: r
    upstream: o
`, strings.TrimPrefix(origin.URL, "http://"))
	s, url := startServer(t, yaml)

	first := make(chan int)
	go func() { resp, _ := get(t, url+"/a"); first <- resp.StatusCode }()
	started.Wait() // the first request holds the only slot
	if q := s.Pools()["o"].Queue; q == nil || q.InFlight != 1 || q.MaxConcurrent != 1 {
		t.Fatalf("queue status %+v", s.Pools()["o"])
	}
	second := make(chan int)
	go func() { resp, _ := get(t, url+"/b"); second <- resp.StatusCode }()
	time.Sleep(50 * time.Millisecond) // the second request is waiting
	if q := s.Pools()["o"].Queue; q.Waiting != 1 {
		t.Fatalf("waiting %+v", q)
	}
	// The third finds the queue full and is refused at once.
	if resp, _ := get(t, url+"/c"); resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("queue full: %d %v", resp.StatusCode, resp.Header)
	}
	// The second times out in the queue.
	if code := <-second; code != 503 {
		t.Fatalf("queued request: %d", code)
	}
	close(release)
	if code := <-first; code != 200 {
		t.Fatalf("first request: %d", code)
	}
	st := s.Stats()
	if st.UpstreamQueueFull != 1 || st.UpstreamQueueTimeouts != 1 {
		t.Fatalf("counters %+v", st)
	}
	if q := s.Pools()["o"].Queue; q.InFlight != 0 || q.Waiting != 0 || q.Queued != 1 || q.Timeouts != 1 || q.Full != 1 {
		t.Fatalf("final queue %+v", q)
	}
}
