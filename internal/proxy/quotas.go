package proxy

import (
	"math"
	"sort"
	"time"

	"github.com/rom/xproxy/internal/limits"
)

// QuotaReport is the usage view per tenant, route and rate limit policy
// (GET /v1/quotas). Counters are per configuration generation: a reload
// starts them over, as the per route metrics do.
type QuotaReport struct {
	Generated  time.Time      `json:"generated"`
	Generation uint64         `json:"generation"`
	Tenants    []TenantQuota  `json:"tenants"`
	Routes     []RouteQuota   `json:"routes"`
	RateLimits []PolicyQuota  `json:"rate_limits"`
	Upstreams  []UpstreamLoad `json:"upstreams"`
}

// RouteQuota is one route's usage.
type RouteQuota struct {
	Route       string `json:"route"`
	Tenant      string `json:"tenant,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
	Requests    uint64 `json:"requests"`
	Status2xx   uint64 `json:"status_2xx"`
	Status3xx   uint64 `json:"status_3xx"`
	Status4xx   uint64 `json:"status_4xx"`
	Status5xx   uint64 `json:"status_5xx"`
	Denied      uint64 `json:"denied"`
	RateLimited uint64 `json:"rate_limited"`
	BytesIn     uint64 `json:"bytes_in"`
	BytesOut    uint64 `json:"bytes_out"`
	// Latency quantiles in milliseconds, estimated from the route's
	// duration histogram (0 without requests).
	LatencyP50MS float64 `json:"latency_p50_ms"`
	LatencyP95MS float64 `json:"latency_p95_ms"`
	LatencyP99MS float64 `json:"latency_p99_ms"`
}

// TenantQuota aggregates the routes sharing a tenant label.
type TenantQuota struct {
	Tenant      string `json:"tenant"`
	Routes      int    `json:"routes"`
	Requests    uint64 `json:"requests"`
	Denied      uint64 `json:"denied"`
	RateLimited uint64 `json:"rate_limited"`
	BytesIn     uint64 `json:"bytes_in"`
	BytesOut    uint64 `json:"bytes_out"`
}

// PolicyQuota is one rate limit policy's decisions and top consumers.
type PolicyQuota struct {
	Policy  string  `json:"policy"`
	Key     string  `json:"key"`
	Rate    float64 `json:"rate"`
	Burst   int     `json:"burst"`
	Keys    int     `json:"keys"`
	Allowed uint64  `json:"allowed"`
	Denied  uint64  `json:"denied"`
	// Overflow counts decisions taken without a bucket because the key
	// table was full of active keys (a warning is logged as well).
	Overflow uint64            `json:"overflow,omitempty"`
	Top      []limits.KeyUsage `json:"top"`
}

// UpstreamLoad is one pool's request share.
type UpstreamLoad struct {
	Upstream string `json:"upstream"`
	Requests uint64 `json:"requests"`
	Errors   uint64 `json:"errors"`
	Active   int64  `json:"active"`
}

// Quotas builds the usage report with at most top consumers per policy.
func (s *Server) Quotas(top int) QuotaReport {
	rt := s.rt.Load()
	rep := QuotaReport{Generated: time.Now(), Generation: rt.generation,
		Tenants: []TenantQuota{}, Routes: []RouteQuota{}, RateLimits: []PolicyQuota{}, Upstreams: []UpstreamLoad{}}
	tenants := map[string]*TenantQuota{}
	for _, cr := range rt.routes {
		q := RouteQuota{Route: cr.cfg.Name, Tenant: cr.cfg.Tenant, Upstream: cr.cfg.Upstream,
			Status2xx: cr.counts[0].Load(), Status3xx: cr.counts[1].Load(), Status4xx: cr.counts[2].Load(),
			Status5xx: cr.counts[3].Load(), Denied: cr.counts[4].Load(), RateLimited: cr.rateLimited.Load(),
			BytesIn: cr.bytesIn.Load(), BytesOut: cr.bytesOut.Load()}
		q.Requests = q.Status2xx + q.Status3xx + q.Status4xx + q.Status5xx + q.Denied
		if snap := cr.hist.Snapshot(); snap.Count > 0 {
			q.LatencyP50MS = ms(snap.Quantile(0.5))
			q.LatencyP95MS = ms(snap.Quantile(0.95))
			q.LatencyP99MS = ms(snap.Quantile(0.99))
		}
		rep.Routes = append(rep.Routes, q)
		if q.Tenant == "" {
			continue
		}
		t, ok := tenants[q.Tenant]
		if !ok {
			t = &TenantQuota{Tenant: q.Tenant}
			tenants[q.Tenant] = t
		}
		t.Routes++
		t.Requests += q.Requests
		t.Denied += q.Denied
		t.RateLimited += q.RateLimited
		t.BytesIn += q.BytesIn
		t.BytesOut += q.BytesOut
	}
	for _, t := range tenants {
		rep.Tenants = append(rep.Tenants, *t)
	}
	sort.Slice(rep.Tenants, func(i, j int) bool { return rep.Tenants[i].Tenant < rep.Tenants[j].Tenant })
	for name, rl := range rt.rateLimits {
		rep.RateLimits = append(rep.RateLimits, PolicyQuota{Policy: name, Key: rl.cfg.Key, Rate: rl.cfg.Rate, Burst: rl.cfg.Burst, Overflow: rl.lim.Overflow(),
			Keys: rl.lim.Len(), Allowed: rl.allowed.Load(), Denied: rl.denied.Load(), Top: rl.lim.Top(top)})
	}
	sort.Slice(rep.RateLimits, func(i, j int) bool { return rep.RateLimits[i].Policy < rep.RateLimits[j].Policy })
	for name, p := range rt.pools {
		ul := UpstreamLoad{Upstream: name}
		for _, e := range p.Stats() {
			ul.Requests += e.Requests
			ul.Errors += e.Errors
			ul.Active += e.Active
		}
		rep.Upstreams = append(rep.Upstreams, ul)
	}
	sort.Slice(rep.Upstreams, func(i, j int) bool { return rep.Upstreams[i].Upstream < rep.Upstreams[j].Upstream })
	return rep
}

// ms converts seconds to milliseconds with one decimal.
func ms(seconds float64) float64 { return math.Round(seconds*10000) / 10 }
