package http

import (
	"math"
	"sort"
	"time"

	"github.com/rom/xproxy/internal/proxy"
)

// Quotas builds the usage report with at most top consumers per policy.
func (s *engine) Quotas(top int) proxy.QuotaReport {
	rt := s.rt.Load()
	rep := proxy.QuotaReport{Generated: time.Now(), Generation: rt.generation,
		Tenants: []proxy.TenantQuota{}, Routes: []proxy.RouteQuota{}, RateLimits: []proxy.PolicyQuota{}, Upstreams: []proxy.UpstreamLoad{}}
	tenants := map[string]*proxy.TenantQuota{}
	for _, cr := range rt.routes {
		q := proxy.RouteQuota{Route: cr.cfg.Name, Tenant: cr.cfg.Tenant, Upstream: cr.cfg.Upstream,
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
			t = &proxy.TenantQuota{Tenant: q.Tenant}
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
		pq := proxy.PolicyQuota{Policy: name, Key: rl.cfg.Key, Algorithm: rl.cfg.Algorithm, Distributed: rl.cfg.Distributed, Rate: rl.cfg.Rate, Burst: rl.cfg.Burst, Overflow: rl.lim.Overflow(),
			Keys: rl.lim.Len(), Allowed: rl.allowed.Load(), Denied: rl.denied.Load(), Top: rl.lim.Top(top)}
		if rl.cfg.Algorithm == "sliding_window" {
			pq.Limit, pq.Window = rl.cfg.Limit, rl.cfg.Window.D().String()
		}
		rep.RateLimits = append(rep.RateLimits, pq)
	}
	sort.Slice(rep.RateLimits, func(i, j int) bool { return rep.RateLimits[i].Policy < rep.RateLimits[j].Policy })
	for name, p := range rt.pools {
		ul := proxy.UpstreamLoad{Upstream: name}
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
