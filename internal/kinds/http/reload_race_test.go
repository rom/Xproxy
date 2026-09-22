package http

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Several scalars were read on the request path and written by a
// reload: the cache's bounds, the shedder's bucket span and concurrency
// ceiling, the inventory's start time and logger, a QUIC flow's peeked
// server name. Each is word-sized, so nothing was observed to go wrong
// — and nothing would have been, because no test reloaded while
// requests were in flight. This one does, under -race.
func TestReloadUnderLoad(t *testing.T) {
	backend := newBackend(t, "a")
	yaml := func(maxObject string, window string) string {
		return fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
cache: {max_bytes: 1048576, max_object_bytes: %s}
shedding: {target_latency: 100ms, window: %s}
api_inventory: {enabled: true}
upstreams:
  - name: u
    endpoints: [{address: %q}]
routes:
  - name: r
    paths: [/]
    cache: {ttl: 1s}
    upstream: u
`, maxObject, window, backend.addr())
	}
	s, url := startServer(t, yaml("65536", "10s"))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c := &http.Client{Timeout: 5 * time.Second}
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := c.Get(fmt.Sprintf("%s/x?w=%d-%d", url, n, j%16))
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				// Read the views a management client would.
				_ = s.Stats()
				_ = s.APIInventory("all", 5)
			}
		}(i)
	}
	for i := 0; i < 12; i++ {
		maxObject, window := "65536", "10s"
		if i%2 == 1 {
			maxObject, window = "32768", "5s"
		}
		if err := s.Reload(mustParse(t, yaml(maxObject, window))); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("reload %d: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

// Every feature that materialises a request body was bounded per
// request, and the product was the real ceiling:
// max_connections_per_ip times max_body_bytes is gigabytes of heap
// from one address, sent slowly enough to stay inside read_timeout.
// The process-wide budget turns that product into one number.
func TestBufferedBodyBudget(t *testing.T) {
	backend := newBackend(t, "a")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  limits: {max_body_bytes: 1048576, max_buffered_body_bytes: 2097152}
logging: {access: {enabled: false}}
filters:
  - name: guard
    kind: upload_guard
    options: {max_files: 4}
upstreams:
  - name: u
    endpoints: [{address: %q}]
routes:
  - name: buffered
    paths: [/buffered]
    filters: [guard]
    upstream: u
  - name: plain
    paths: [/]
    upstream: u
`, backend.addr())
	s, url := startServer(t, yaml)

	// Hold the whole budget with two requests that never finish sending.
	held := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		pr, pw := io.Pipe()
		req, _ := http.NewRequest("POST", url+"/buffered", pr)
		req.ContentLength = 1 << 20
		req.Header.Set("Content-Type", "application/octet-stream")
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
		go func() {
			<-held
			_ = pw.Close()
		}()
	}
	// Wait until both reservations are held.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && s.Stats().BufferedBody.Used < 2<<20 {
		time.Sleep(10 * time.Millisecond)
	}
	if used := s.Stats().BufferedBody.Used; used < 2<<20 {
		close(held)
		wg.Wait()
		t.Fatalf("the budget was not charged: %d bytes held", used)
	}
	// A third buffered request does not fit and is refused, rather than
	// adding another megabyte of heap.
	resp, err := http.Post(url+"/buffered", "application/octet-stream", strings.NewReader(strings.Repeat("x", 1024)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a request past the budget: %d", resp.StatusCode)
	}
	// A route that buffers nothing is unaffected.
	if r2, err := http.Get(url + "/x"); err != nil || r2.StatusCode != 200 {
		t.Fatalf("a route without a buffering filter was refused: %v", err)
	} else {
		_, _ = io.Copy(io.Discard, r2.Body)
		_ = r2.Body.Close()
	}
	close(held)
	wg.Wait()
	// The budget is released when the requests end.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && s.Stats().BufferedBody.Used != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if used := s.Stats().BufferedBody.Used; used != 0 {
		t.Fatalf("%d bytes still reserved after the requests ended", used)
	}
}

// The old generation used to be torn down after a fixed
// shutdown_timeout, so an exchange older than that — a long upload, a
// gRPC or SSE stream — was cut or answered 500 although it was still
// making progress. It is torn down when its last request ends now,
// with a hard cap for one that never does. The concurrency and tarpit
// gates were also sized once at start, so a reload that changed either
// was ignored.
func TestReloadWaitsForInFlightRequestsAndResizesGates(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "done")
	}))
	defer slow.Close()
	yaml := func(concurrent int) string {
		return fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  shutdown_timeout: 100ms
  limits: {max_concurrent_requests: %d, max_tarpits: %d}
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: %q}]
routes:
  - name: r
    paths: [/]
    timeouts: {total: 60s}
    upstream: u
`, concurrent, concurrent, strings.TrimPrefix(slow.URL, "http://"))
	}
	s, url := startServer(t, yaml(100))
	if got := eng(s).concurrency.Max(); got != 100 {
		t.Fatalf("concurrency ceiling %d", got)
	}
	body := make(chan string, 1)
	go func() {
		resp, err := http.Get(url + "/slow")
		if err != nil {
			body <- "error: " + err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		body <- string(b)
	}()
	<-started
	if err := s.Reload(mustParse(t, yaml(7))); err != nil {
		t.Fatal(err)
	}
	// A reload now changes both gates.
	if got := eng(s).concurrency.Max(); got != 7 {
		t.Fatalf("the concurrency ceiling was not resized: %d", got)
	}
	if got := eng(s).tarpits.Max(); got != 7 {
		t.Fatalf("the tarpit ceiling was not resized: %d", got)
	}
	// The in-flight request outlives shutdown_timeout and still finishes.
	time.Sleep(400 * time.Millisecond)
	close(release)
	select {
	case got := <-body:
		if got != "done" {
			t.Fatalf("the request in flight across the reload got %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the request never came back")
	}
}
