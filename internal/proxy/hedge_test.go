package proxy

import (
	"fmt"
	"testing"
	"time"
)

const hedgeYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: pool
    balancer: round_robin
    retries: 0
    retry_budget: {percent: 100, min_concurrency: 4}
    hedge: {delay: 40ms, max: 1}
    endpoints: [{address: "%s"}, {address: "%s"}]
routes:
  - name: r
    upstream: pool
`

// TestHedge sends a slow and a fast endpoint into a hedged pool: whichever
// endpoint is picked first, the fast one answers within the hedge delay, so
// every response is fast and the slow endpoint's copies are cancelled.
func TestHedge(t *testing.T) {
	slow := newBackend(t, "slow")
	slow.delay = 400 * time.Millisecond
	fast := newBackend(t, "fast")

	s, url := startServer(t, fmt.Sprintf(hedgeYAML, slow.addr(), fast.addr()))

	for i := 0; i < 8; i++ {
		start := time.Now()
		resp, body := get(t, url+"/x")
		took := time.Since(start)
		if resp.StatusCode != 200 || body != "fast:/x" {
			t.Fatalf("request %d: %d %q", i, resp.StatusCode, body)
		}
		if took > 300*time.Millisecond {
			t.Fatalf("request %d took %v, hedge did not fire", i, took)
		}
	}
	// The slow endpoint was picked first on roughly half the requests and
	// hedged past, so it saw traffic; the hedged copies count as retries.
	if slow.hits.Load() == 0 {
		t.Fatal("slow endpoint never tried; round robin or hedge broken")
	}
	st := s.Stats()
	if st.UpstreamRetries == 0 {
		t.Fatalf("no hedged copies counted: %+v", st)
	}
}

// TestHedgeNonReplayable keeps a POST on a single endpoint: a body that
// cannot be replayed is never hedged.
func TestHedgeNonReplayable(t *testing.T) {
	slow := newBackend(t, "slow")
	slow.delay = 120 * time.Millisecond
	fast := newBackend(t, "fast")
	_, url := startServer(t, fmt.Sprintf(hedgeYAML, slow.addr(), fast.addr()))

	// Drive several POSTs; each stays on its one picked endpoint. The test
	// asserts correctness (a single upstream hit per request), not timing.
	before := slow.hits.Load() + fast.hits.Load()
	for i := 0; i < 6; i++ {
		resp, _ := post(t, url+"/x", "", "203.0.113.9", "a=b")
		if resp.StatusCode != 200 {
			t.Fatalf("post %d: %d", i, resp.StatusCode)
		}
	}
	if got := slow.hits.Load() + fast.hits.Load() - before; got != 6 {
		t.Fatalf("POST fanned out: %d upstream hits for 6 requests", got)
	}
}
