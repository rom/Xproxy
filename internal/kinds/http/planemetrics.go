package http

import (
	"sort"

	"github.com/rom/xproxy/internal/filters/accountguard"
	"github.com/rom/xproxy/internal/filters/apiabuse"
	"github.com/rom/xproxy/internal/filters/flow"
	"github.com/rom/xproxy/internal/filters/sensitive"
	"github.com/rom/xproxy/internal/metrics"
)

// Collect emits the metric families of the HTTP data plane. The engine
// emits everything that comes from the shared counter snapshot; what is
// here is what only this plane can answer — its compiled generation,
// its filters, its cache and the packages it alone links.
func (s *engine) Collect(e metrics.Collector) {
	rt := s.rt.Load()
	if rt == nil {
		return
	}
	type L = metrics.Labels

	sens := sensitive.Snapshot()
	for _, f := range sens.Findings {
		e.Counter("xproxy_sensitive_findings_total", "Sensitive data findings by detector kind, both directions.", L{"kind": f.Kind}, float64(f.Count))
	}
	for _, a := range sens.Actions {
		e.Counter("xproxy_sensitive_messages_total", "Messages with sensitive data by direction and outcome.", L{"direction": a.Direction, "outcome": a.Outcome}, float64(a.Count))
	}
	acc := accountguard.Snapshot()
	for _, a := range acc.Actions {
		e.Counter("xproxy_account_actions_total", "Account guard actions by endpoint class.", L{"class": a.Class, "action": a.Action}, float64(a.Count))
	}
	e.Counter("xproxy_account_events_total", "Failed attempts or requests the account guard counted.", nil, float64(acc.Events))
	e.Counter("xproxy_account_blocks_total", "Blocks the account guard placed.", nil, float64(acc.Blocks))
	e.Counter("xproxy_account_campaigns_total", "Distributed campaigns the account guard declared.", nil, float64(acc.Campaigns))
	e.Counter("xproxy_account_disposable_total", "Registrations with a disposable e-mail domain.", nil, float64(acc.Disposable))
	e.Counter("xproxy_account_automation_total", "Requests whose challenge cookie carried automation markers on an endpoint acting on them.", nil, float64(acc.Automation))
	e.Gauge("xproxy_account_blocks_active", "Account guard blocks in force.", nil, float64(accountBlocksActive()))
	for _, ab := range apiabuse.Statuses() {
		l := L{"filter": ab.Name}
		e.Counter("xproxy_api_abuse_requests_total", "Requests an api_abuse filter counted against a caller and endpoint.", l, float64(ab.Requests))
		e.Counter("xproxy_api_abuse_flagged_total", "Requests from a caller an api_abuse filter had flagged.", l, float64(ab.Flagged))
		e.Counter("xproxy_api_abuse_blocked_total", "Requests an api_abuse filter refused.", l, float64(ab.Blocked))
		e.Counter("xproxy_api_abuse_challenged_total", "Requests an api_abuse filter sent to the challenge.", l, float64(ab.Challenged))
		e.Counter("xproxy_api_abuse_dropped_total", "Callers dropped from an api_abuse filter's table for space.", l, float64(ab.Dropped))
		e.Gauge("xproxy_api_abuse_subjects", "Caller and endpoint pairs an api_abuse filter holds.", l, float64(ab.Subjects))
		e.Gauge("xproxy_api_abuse_objects", "Identifiers an api_abuse filter holds across its callers.", l, float64(ab.Objects))
		e.Gauge("xproxy_api_abuse_overflowed", "Identifiers past what one caller holds, counted but not kept.", l, float64(ab.Overflowed))
	}
	for _, fs := range flow.Statuses() {
		l := L{"filter": fs.Name}
		e.Counter("xproxy_flow_requests_total", "Requests that matched a step of a business flow.", l, float64(fs.Requests))
		e.Counter("xproxy_flow_steps_total", "Steps a flow filter let a caller take.", l, float64(fs.Steps))
		e.Counter("xproxy_flow_flagged_total", "Steps reached out of order or repeated.", l, float64(fs.Flagged))
		e.Counter("xproxy_flow_blocked_total", "Steps a flow filter refused.", l, float64(fs.Blocked))
		e.Counter("xproxy_flow_challenged_total", "Steps a flow filter sent to the challenge.", l, float64(fs.Challenged))
		e.Counter("xproxy_flow_dropped_total", "Callers dropped from a flow filter's table for space; one dropped mid-flow arrives at its next step looking like one that skipped a step.", l, float64(fs.Dropped))
		e.Gauge("xproxy_flow_callers", "Callers a flow filter holds progress for.", l, float64(fs.Callers))
		e.Gauge("xproxy_flow_flows", "Flows a filter enforces.", l, float64(fs.Flows))
	}
	for _, vp := range rt.patches {
		e.Counter("xproxy_virtual_patch_hits_total", "Requests matched by a virtual patch.", L{"patch": vp.cfg.ID}, float64(vp.hits.Load()))
	}
	for _, g := range s.WebSocketGuards() {
		e.Counter("xproxy_websocket_connections_total", "Upgraded connections inspected by a websocket guard.", L{"route": g.Route}, float64(g.Connections))
		e.Counter("xproxy_websocket_messages_total", "WebSocket messages seen by a guard.", L{"route": g.Route}, float64(g.Messages))
		e.Counter("xproxy_websocket_violations_total", "WebSocket frames or messages that broke the route's policy.", L{"route": g.Route}, float64(g.Violations))
		e.Counter("xproxy_websocket_closed_total", "Connections closed by a websocket guard.", L{"route": g.Route}, float64(g.Closed))
	}
	if c := s.cache.Load(); c != nil {
		cs := c.Stats()
		e.Counter("xproxy_cache_hits_total", "Responses served from the cache.", nil, float64(cs.Hits))
		e.Counter("xproxy_cache_misses_total", "Cacheable requests not found in the cache.", nil, float64(cs.Misses))
		e.Counter("xproxy_cache_stores_total", "Responses stored.", nil, float64(cs.Stores))
		e.Counter("xproxy_cache_evictions_total", "Entries evicted for space.", nil, float64(cs.Evictions))
		e.Gauge("xproxy_cache_entries", "Entries in the cache.", nil, float64(cs.Entries))
		e.Gauge("xproxy_cache_bytes", "Bytes held by the cache.", nil, float64(cs.Bytes))
	}
	if rt.geo != nil {
		gs := rt.geo.Status()
		e.Counter("xproxy_geoip_lookups_total", "Country lookups.", nil, float64(gs.Lookups))
		e.Counter("xproxy_geoip_unknown_total", "Country lookups without a result.", nil, float64(gs.Unknown))
	}
	for _, fs := range rt.filterStatus() {
		e.Counter("xproxy_filter_denied_total", "Requests denied by a configured filter.", L{"filter": fs.Name, "kind": fs.Kind}, float64(fs.Denied))
	}
	// Per route counters (bounded by the number of routes).
	// Each family is emitted contiguously (the exposition declares a
	// family once), so the routes are walked once per family.
	if rt.cfg.Metrics.PerRouteEnabled() {
		labels := func(cr *compiledRoute, extra ...string) L {
			l := L{"route": cr.cfg.Name}
			if cr.cfg.Tenant != "" {
				l["tenant"] = cr.cfg.Tenant
			}
			for i := 0; i+1 < len(extra); i += 2 {
				l[extra[i]] = extra[i+1]
			}
			return l
		}
		for _, cr := range rt.routes {
			for i, class := range routeClasses {
				if v := cr.counts[i].Load(); v > 0 || i == 0 {
					e.Counter("xproxy_route_requests_total", "Requests per route and outcome.", labels(cr, "outcome", class), float64(v))
				}
			}
		}
		for _, cr := range rt.routes {
			e.Counter("xproxy_route_bytes_total", "Bytes per route and direction.", labels(cr, "direction", "in"), float64(cr.bytesIn.Load()))
			e.Counter("xproxy_route_bytes_total", "Bytes per route and direction.", labels(cr, "direction", "out"), float64(cr.bytesOut.Load()))
		}
		for _, cr := range rt.routes {
			if v := cr.rateLimited.Load(); v > 0 {
				e.Counter("xproxy_route_rate_limited_total", "Requests refused by a rate limit per route.", labels(cr), float64(v))
			}
		}
		for _, cr := range rt.routes {
			if snap := cr.hist.Snapshot(); snap.Count > 0 {
				e.Histogram("xproxy_route_request_duration_seconds", "Time from request start to response end per route.", labels(cr), snap)
			}
		}
		names := make([]string, 0, len(rt.rateLimits))
		for name := range rt.rateLimits {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			rl := rt.rateLimits[name]
			e.Counter("xproxy_rate_limit_decisions_total", "Rate limit decisions per policy.", L{"policy": name, "outcome": "allowed"}, float64(rl.allowed.Load()))
			e.Counter("xproxy_rate_limit_decisions_total", "Rate limit decisions per policy.", L{"policy": name, "outcome": "denied"}, float64(rl.denied.Load()))
		}
		for _, name := range names {
			e.Gauge("xproxy_rate_limit_keys", "Keys tracked per policy.", L{"policy": name}, float64(rt.rateLimits[name].lim.Len()))
		}
	}
}

// accountBlocksActive totals the blocks in force across every guard.
func accountBlocksActive() int {
	n := 0
	for _, g := range accountguard.Status(0).Guards {
		for _, ep := range g.Endpoints {
			n += ep.ActiveBlocks
		}
	}
	return n
}
