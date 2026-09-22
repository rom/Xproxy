package http

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestTarpitDoesNotHoldConcurrency: tarpitted requests release their
// concurrency slot and are bounded by max_tarpits; above the bound they
// are rejected at once rather than held, so a flood of tarpits cannot
// starve legitimate requests (security review finding SR-1).
func TestTarpitDoesNotHoldConcurrency(t *testing.T) {
	backend := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
  limits:
    max_concurrent_requests: 4
    max_tarpits: 2
logging:
  access: {enabled: false}
rate_limits:
  - {name: slow, key: client_ip, rate: 0.001, burst: 1, action: tarpit, tarpit_delay: 2s}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
routes:
  - name: limited
    paths: [/limited]
    rate_limits: [slow]
    upstream: app
  - name: open
    paths: ["/"]
    upstream: app
`
	s, url := startServer(t, fmt.Sprintf(yaml, backend.addr()))
	// First request consumes the single token; the next ones are tarpitted.
	resp, _ := get(t, url+"/limited")
	if resp.StatusCode != 200 {
		t.Fatalf("first: %d", resp.StatusCode)
	}
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	start := time.Now()
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Timeout: 10 * time.Second}
			r, err := c.Get(url + "/limited")
			if err != nil {
				codes <- -1
				return
			}
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			codes <- r.StatusCode
		}()
	}
	time.Sleep(300 * time.Millisecond)
	// While two requests sit in the tarpit (and the other four were
	// rejected immediately), the open route must still be served: no
	// concurrency slot is held by a tarpit.
	for i := 0; i < 4; i++ {
		r, body := get(t, url+"/x")
		if r.StatusCode != 200 || body != "a:/x" {
			t.Fatalf("open route during tarpits: %d %q", r.StatusCode, body)
		}
	}
	if st := s.Stats(); st.TarpitActive != 2 || st.TarpitOverflow != 4 {
		t.Fatalf("tarpit_active %d overflow %d", st.TarpitActive, st.TarpitOverflow)
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 429 {
			t.Fatalf("tarpitted or overflowed request answered %d", c)
		}
	}
	if el := time.Since(start); el < 2*time.Second || el > 6*time.Second {
		t.Fatalf("held for %v", el)
	}
	if st := s.Stats(); st.Tarpitted != 2 || st.TarpitActive != 0 {
		t.Fatalf("tarpitted %d active %d", st.Tarpitted, st.TarpitActive)
	}
}

// TestHeaderRateLimitRotation: rotating the value of a header keyed limit
// does not yield a fresh burst per value once the key table is full; the
// client address bounds the client (security review finding SR-2).
func TestHeaderRateLimitRotation(t *testing.T) {
	backend := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
logging:
  access: {enabled: false}
rate_limits:
  - {name: key, key: "header:X-Key", rate: 0.001, burst: 3}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
routes:
  - name: all
    paths: ["/"]
    rate_limits: [key]
    upstream: app
`
	s, url := startServer(t, fmt.Sprintf(yaml, backend.addr()))
	// Shrink the table so the test fills it: one key per shard.
	for _, rl := range eng(s).rt.Load().rateLimits {
		rl.lim.SetMaxKeysForTest(1)
	}
	allowed := 0
	for i := 0; i < 400; i++ {
		resp, _ := get(t, url+"/", "X-Key", fmt.Sprintf("k%d", i))
		if resp.StatusCode == 200 {
			allowed++
		}
	}
	// 64 shards fill with one key each (each with its burst of 3 spent
	// over subsequent same-key requests is irrelevant here: every key is
	// new). Once a shard is full, the client address bucket (burst 3)
	// decides, so the total stays far below 400.
	if allowed > 64*3+3 {
		t.Fatalf("%d of 400 rotating keys allowed", allowed)
	}
	if st := s.Stats(); st.DeniedRateLimit == 0 {
		t.Fatal("no rate limit denials")
	}
}
