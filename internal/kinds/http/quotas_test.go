package http

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
)

func TestQuotas(t *testing.T) {
	a := newBackend(t, "a")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
logging: {access: {enabled: false}}
rate_limits:
  - {name: small, rate: 1, burst: 2}
upstreams:
  - name: app
    endpoints: [{address: %q}]
routes:
  - name: shop-web
    hosts: [shop.test]
    tenant: shop
    upstream: app
  - name: shop-api
    hosts: [api.shop.test]
    tenant: shop
    rate_limits: [small]
    upstream: app
  - name: other
    hosts: [other.test]
    respond: {status: 204}
`, a.addr())
	s, url := startServer(t, yaml)
	for i := 0; i < 3; i++ {
		get(t, url+"/page", "Host", "shop.test")
	}
	codes := []int{}
	for i := 0; i < 4; i++ {
		resp, _ := getAs(t, url+"/v1", "api.shop.test", "203.0.113.7")
		codes = append(codes, resp.StatusCode)
	}
	get(t, url+"/", "Host", "other.test")

	// The per-route counters are written by a deferred call inside the handler, so
	// they can still be in flight when the client's own get has returned. Waiting
	// for the counts rather than reading them the instant the last request came
	// back is what stops this being a test that passes on an idle machine.
	var q proxy.QuotaReport
	byRoute := map[string]proxy.RouteQuota{}
	eventually(t, 10*time.Second, "the route counters to catch up with the eight requests", func() bool {
		q = s.Quotas(5)
		byRoute = map[string]proxy.RouteQuota{}
		for _, r := range q.Routes {
			byRoute[r.Route] = r
		}
		return byRoute["shop-web"].Requests == 3 && byRoute["shop-api"].Requests == 4 &&
			byRoute["other"].Requests == 1
	})
	web := byRoute["shop-web"]
	if web.Requests != 3 || web.Status2xx != 3 || web.Tenant != "shop" || web.Upstream != "app" || web.BytesOut < uint64(3*len("a:/page")) {
		t.Fatalf("web %+v", web)
	}
	api := byRoute["shop-api"]
	if api.Requests != 4 || api.Status2xx != 2 || api.Denied != 2 || api.RateLimited != 2 {
		t.Fatalf("api %+v (codes %v)", api, codes)
	}
	if o := byRoute["other"]; o.Requests != 1 || o.Status2xx != 1 || o.Tenant != "" {
		t.Fatalf("other %+v", o)
	}
	if len(q.Tenants) != 1 || q.Tenants[0].Tenant != "shop" || q.Tenants[0].Routes != 2 || q.Tenants[0].Requests != 7 || q.Tenants[0].RateLimited != 2 {
		t.Fatalf("tenants %+v", q.Tenants)
	}
	if len(q.RateLimits) != 1 {
		t.Fatalf("policies %+v", q.RateLimits)
	}
	p := q.RateLimits[0]
	if p.Policy != "small" || p.Allowed != 2 || p.Denied != 2 || p.Keys != 1 || len(p.Top) != 1 || !strings.Contains(p.Top[0].Key, "203.0.113.7") || p.Top[0].Total != 2 {
		t.Fatalf("policy %+v", p)
	}
	if len(q.Upstreams) != 1 || q.Upstreams[0].Requests != 5 {
		t.Fatalf("upstreams %+v", q.Upstreams)
	}
	if q.Generation == 0 || q.Generated.IsZero() {
		t.Fatalf("header %+v", q)
	}
	// The metrics carry the tenant label and the byte counters.
	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	m := buf.String()
	for _, want := range []string{`xproxy_route_requests_total{outcome="2xx",route="shop-web",tenant="shop"} 3`, `xproxy_route_bytes_total{direction="out",route="shop-web",tenant="shop"}`, `xproxy_rate_limit_decisions_total{outcome="denied",policy="small"} 2`, `xproxy_route_rate_limited_total{route="shop-api",tenant="shop"} 2`} {
		if !strings.Contains(m, want) {
			t.Fatalf("metric %q missing in:\n%s", want, m)
		}
	}
}
