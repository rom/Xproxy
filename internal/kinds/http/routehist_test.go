package http

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRouteLatencyHistogram(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - {name: a, endpoints: [{address: "%s"}]}
routes:
  - {name: api, paths: ["/api"], tenant: acme, upstream: a}
  - {name: rest, paths: ["/"], upstream: a}
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	for i := 0; i < 5; i++ {
		get(t, url+"/api/x")
	}
	get(t, url+"/other")
	// The histogram is recorded where the access log is written, in a
	// deferred call that runs after the response has gone to the
	// client — so a request can be complete from the client's side
	// while its observation is still a moment away. Wait for the
	// counts rather than racing them.
	want := []string{
		`xproxy_route_request_duration_seconds_bucket{le="+Inf",route="api",tenant="acme"} 5`,
		`xproxy_route_request_duration_seconds_count{route="api",tenant="acme"} 5`,
		`xproxy_route_request_duration_seconds_count{route="rest"} 1`,
	}
	var text string
	deadline := time.Now().Add(10 * time.Second)
	for {
		var sb strings.Builder
		if err := s.WriteMetrics(&sb); err != nil {
			t.Fatal(err)
		}
		text = sb.String()
		missing := ""
		for _, w := range want {
			if !strings.Contains(text, w) {
				missing = w
				break
			}
		}
		if missing == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics missing %q", missing)
		}
		time.Sleep(10 * time.Millisecond)
	}
	q := s.Quotas(5)
	for _, r := range q.Routes {
		if r.Route == "api" && (r.LatencyP50MS <= 0 || r.LatencyP99MS < r.LatencyP50MS || r.LatencyP99MS > 1000) {
			t.Fatalf("api latency quantiles: %+v", r)
		}
	}
}
