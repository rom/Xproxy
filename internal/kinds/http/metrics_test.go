package http

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWriteMetrics(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
shedding: {target_latency: 100ms}
bans: {action: reject}
metrics: {sample_interval: 1s, retention: 1m}
upstreams:
  - name: up
    endpoints: [{address: "%s"}]
routes:
  - {name: web, upstream: up}
  - {name: nf,  hosts: [nf.test], respond: {status: 404, body: no}}
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	for i := 0; i < 3; i++ {
		get(t, url+"/x")
	}
	get(t, url+"/", "Host", "nf.test")
	get(t, url+"/", "Host", "nowhere.test") // routes to web (catch-all) -> 200

	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# TYPE xproxy_requests_total counter\nxproxy_requests_total 5\n",
		`xproxy_responses_total{class="2xx"} 4`,
		`xproxy_responses_total{class="4xx"} 1`,
		`xproxy_denied_total{reason="waf"} 0`,
		`xproxy_upstream_endpoint_healthy{endpoint="` + a.addr() + `",upstream="up"} 1`,
		`xproxy_upstream_endpoint_requests_total{endpoint="` + a.addr() + `",upstream="up"} 4`,
		`xproxy_route_requests_total{outcome="2xx",route="web"} 4`,
		`xproxy_route_requests_total{outcome="4xx",route="nf"} 1`,
		"# TYPE xproxy_request_duration_seconds histogram",
		`xproxy_request_duration_seconds_count 5`,
		`xproxy_upstream_ttfb_seconds_count 4`,
		`xproxy_load_level 0`,
		`xproxy_shedding{class="low"} 0`,
		`xproxy_bans_active 0`,
		`xproxy_build_info{commit=`,
		`xproxy_config_generation 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in exposition:\n%s", want, out)
		}
	}
	// Every family declared once; no duplicate TYPE lines.
	seen := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "# TYPE ") {
			seen[line]++
		}
	}
	for l, n := range seen {
		if n != 1 {
			t.Fatalf("family declared %d times: %s", n, l)
		}
	}

	// Sampler produces points at the configured interval.
	time.Sleep(2500 * time.Millisecond)
	pts := s.Series().Since(time.Time{}, 0)
	if len(pts) < 2 || len(pts[0].Values) != len(s.Series().Names()) {
		t.Fatalf("series: %d points", len(pts))
	}
	if s.Series().Names()[0] != "requests" {
		t.Fatal("names")
	}
}
