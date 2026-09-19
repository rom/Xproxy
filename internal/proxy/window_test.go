package proxy

import (
	"fmt"
	"testing"
)

func TestSlidingWindowRoute(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
rate_limits:
  - {name: win, algorithm: sliding_window, limit: 3, window: 1m}
upstreams:
  - {name: a, endpoints: [{address: "%s"}]}
routes:
  - {name: r, paths: ["/"], upstream: a, rate_limits: [win]}
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	for i := 0; i < 3; i++ {
		if resp, _ := get(t, url+"/"); resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
	if resp, _ := get(t, url+"/"); resp.StatusCode != 429 {
		t.Fatalf("4th request in the window: %d", resp.StatusCode)
	}
	q := s.Quotas(3)
	if len(q.RateLimits) != 1 || q.RateLimits[0].Algorithm != "sliding_window" || q.RateLimits[0].Limit != 3 || q.RateLimits[0].Window != "1m0s" || q.RateLimits[0].Denied != 1 {
		t.Fatalf("policy quota: %+v", q.RateLimits)
	}
	if top := q.RateLimits[0].Top; len(top) != 1 || top[0].Total != 3 || top[0].Tokens != 0 {
		t.Fatalf("top: %+v", top)
	}
}
