package proxy

import (
	"fmt"
	"strings"
	"testing"
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
	var sb strings.Builder
	if err := s.WriteMetrics(&sb); err != nil {
		t.Fatal(err)
	}
	text := sb.String()
	for _, want := range []string{
		`xproxy_route_request_duration_seconds_bucket{le="+Inf",route="api",tenant="acme"} 5`,
		`xproxy_route_request_duration_seconds_count{route="api",tenant="acme"} 5`,
		`xproxy_route_request_duration_seconds_count{route="rest"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	q := s.Quotas(5)
	for _, r := range q.Routes {
		if r.Route == "api" && (r.LatencyP50MS <= 0 || r.LatencyP99MS < r.LatencyP50MS || r.LatencyP99MS > 1000) {
			t.Fatalf("api latency quantiles: %+v", r)
		}
	}
}
