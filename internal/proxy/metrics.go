package proxy

import (
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/rom/xproxy/internal/metrics"
	"github.com/rom/xproxy/internal/upstream"
	"github.com/rom/xproxy/internal/version"
)

// Names of the sampled series, counters first (per-second rates) then
// gauges. The order is the wire order of Point.Values.
var (
	seriesCounters = []string{"requests", "responses_2xx", "responses_4xx", "responses_5xx", "denied", "shed", "bytes_in", "bytes_out", "upstream_errors"}
	seriesGauges   = []string{"open_connections", "in_flight", "load_level", "upstream_latency_ms", "bans_active", "cluster_connected"}
)

// sample feeds the time series sampler.
func (s *Server) sample() metrics.Sample {
	sn := s.Stats()
	denied := sn.DeniedACL + sn.DeniedRateLimit + sn.Tarpitted + sn.DeniedConcurrency + sn.DeniedBodySize + sn.DeniedURILength +
		sn.DeniedNoRoute + sn.DeniedWebSocket + sn.DeniedBadHost + sn.DeniedBan + sn.DeniedWAF + sn.DeniedJWT + sn.DeniedICAP + sn.DeniedFilter + sn.DeniedGeo
	return metrics.Sample{
		Counters: []float64{float64(sn.Requests), float64(sn.Responses2xx), float64(sn.Responses4xx), float64(sn.Responses5xx),
			float64(denied), float64(sn.Shed), float64(sn.BytesIn), float64(sn.BytesOut), float64(sn.UpstreamErrors)},
		Gauges: []float64{float64(sn.OpenConnections), float64(sn.InFlight), sn.LoadLevel, sn.UpstreamLatencyMS,
			float64(sn.BansActive), float64(sn.ClusterConnected)},
	}
}

// Series returns the sampled time series buffer.
func (s *Server) Series() *metrics.Series { return s.sampler.Series() }

// WriteMetrics writes the Prometheus exposition of the whole process.
func (s *Server) WriteMetrics(w io.Writer) error {
	e := metrics.NewEncoder(w)
	s.Collect(e)
	return e.Flush()
}

// Collect runs one collection of every metric family into c (the
// Prometheus encoder or the OTLP exporter).
func (s *Server) Collect(e metrics.Collector) {
	sn := s.Stats()
	rt := s.rt.Load()
	type L = metrics.Labels

	e.Gauge("xproxy_build_info", "Build information; always 1.", L{"version": version.Version, "commit": version.Commit}, 1)
	e.Gauge("xproxy_uptime_seconds", "Seconds since the process started.", nil, sn.UptimeSeconds)
	e.Gauge("xproxy_config_generation", "Configuration generation counter.", nil, float64(rt.generation))

	e.Counter("xproxy_requests_total", "Requests received.", nil, float64(sn.Requests))
	for class, v := range map[string]uint64{"2xx": sn.Responses2xx, "3xx": sn.Responses3xx, "4xx": sn.Responses4xx, "5xx": sn.Responses5xx} {
		e.Counter("xproxy_responses_total", "Responses by status class.", L{"class": class}, float64(v))
	}
	e.Counter("xproxy_bytes_in_total", "Request body bytes received (declared).", nil, float64(sn.BytesIn))
	e.Counter("xproxy_bytes_out_total", "Response bytes written.", nil, float64(sn.BytesOut))
	denied := []struct {
		reason string
		v      uint64
	}{
		{"acl", sn.DeniedACL}, {"rate_limit", sn.DeniedRateLimit}, {"tarpit", sn.Tarpitted}, {"concurrency", sn.DeniedConcurrency},
		{"body_size", sn.DeniedBodySize}, {"uri_length", sn.DeniedURILength}, {"no_route", sn.DeniedNoRoute}, {"websocket", sn.DeniedWebSocket},
		{"bad_host", sn.DeniedBadHost}, {"ban", sn.DeniedBan}, {"waf", sn.DeniedWAF}, {"jwt", sn.DeniedJWT}, {"icap", sn.DeniedICAP}, {"filter", sn.DeniedFilter}, {"geo", sn.DeniedGeo}, {"shed", sn.Shed},
	}
	for _, d := range denied {
		e.Counter("xproxy_denied_total", "Requests refused by the proxy, by reason.", L{"reason": d.reason}, float64(d.v))
	}
	e.Counter("xproxy_waf_detected_total", "Requests the WAF flagged in detect mode.", nil, float64(sn.WAFDetected))
	e.Counter("xproxy_upstream_errors_total", "Upstream connection failures.", nil, float64(sn.UpstreamErrors))
	e.Counter("xproxy_upstream_retries_total", "Attempts repeated on another endpoint.", L{"reason": "connect"}, float64(sn.UpstreamRetries-sn.UpstreamStatusRetries))
	e.Counter("xproxy_upstream_retries_total", "Attempts repeated on another endpoint.", L{"reason": "status"}, float64(sn.UpstreamStatusRetries))
	e.Counter("xproxy_upstream_timeouts_total", "Upstream timeouts.", nil, float64(sn.UpstreamTimeouts))
	e.Counter("xproxy_upstream_no_healthy_total", "Requests with no healthy endpoint.", nil, float64(sn.UpstreamNoHealthy))
	e.Counter("xproxy_upstream_circuit_open_total", "Requests refused by an open circuit breaker.", nil, float64(sn.UpstreamCircuitOpen))
	e.Counter("xproxy_upstream_queue_refused_total", "Requests refused by a pool's queue.", L{"reason": "full"}, float64(sn.UpstreamQueueFull))
	e.Counter("xproxy_upstream_queue_refused_total", "Requests refused by a pool's queue.", L{"reason": "timeout"}, float64(sn.UpstreamQueueTimeouts))
	e.Counter("xproxy_client_aborts_total", "Requests abandoned by the client.", nil, float64(sn.ClientAborts))
	e.Counter("xproxy_connections_rejected_total", "Connections closed at accept by limits or bans.", nil, float64(sn.RejectedConns))
	e.Counter("xproxy_reloads_total", "Configuration reloads.", L{"result": "ok"}, float64(sn.Reloads))
	e.Counter("xproxy_reloads_total", "Configuration reloads.", L{"result": "failed"}, float64(sn.ReloadFailures))
	e.Counter("xproxy_bans_total", "Bans applied.", nil, float64(sn.BansTotal))
	for result, v := range map[string]uint64{"issued": sn.ChallengesIssued, "passed": sn.ChallengesPassed, "failed": sn.ChallengesFailed} {
		e.Counter("xproxy_challenges_total", "Browser challenges by result.", L{"result": result}, float64(v))
	}
	e.Counter("xproxy_log_sent_total", "Log records delivered to network sinks.", L{"sink": "syslog"}, float64(sn.LogSyslogSent))
	e.Counter("xproxy_log_dropped_total", "Log records dropped by a sink.", L{"sink": "syslog"}, float64(sn.LogSyslogDropped))
	e.Counter("xproxy_log_dropped_total", "Log records dropped by a sink.", L{"sink": "journald"}, float64(sn.LogJournalDropped))

	e.Gauge("xproxy_connections_open", "Open client connections (TCP and QUIC).", nil, float64(sn.OpenConnections))
	e.Gauge("xproxy_requests_in_flight", "Requests currently admitted.", nil, float64(sn.InFlight))
	e.Gauge("xproxy_bans_active", "Active bans.", nil, float64(sn.BansActive))
	if s.shedder.Load() != nil {
		e.Gauge("xproxy_load_level", "Load level used for shedding (0 to 1).", nil, sn.LoadLevel)
		e.Gauge("xproxy_upstream_latency_seconds", "Average upstream time to first byte over the shedding window.", nil, sn.UpstreamLatencyMS/1000)
		for _, class := range []string{"low", "normal", "high"} {
			v := 0.0
			for _, c := range sn.SheddingClasses {
				if c == class {
					v = 1
				}
			}
			e.Gauge("xproxy_shedding", "1 while the priority class is being shed.", L{"class": class}, v)
		}
	}
	if node := s.cluster.Load(); node != nil {
		st := node.Status()
		e.Gauge("xproxy_cluster_peers", "Configured cluster peers.", nil, float64(len(st.Peers)))
		e.Gauge("xproxy_cluster_peers_connected", "Cluster peers with an open outbound connection.", nil, float64(sn.ClusterConnected))
		e.Counter("xproxy_cluster_messages_total", "Cluster messages by direction and type.", L{"direction": "out", "type": "rates"}, float64(st.RatesSent))
		e.Counter("xproxy_cluster_messages_total", "Cluster messages by direction and type.", L{"direction": "in", "type": "rates"}, float64(st.RatesReceived))
		e.Counter("xproxy_cluster_messages_total", "Cluster messages by direction and type.", L{"direction": "out", "type": "bans"}, float64(st.BansSent))
		e.Counter("xproxy_cluster_messages_total", "Cluster messages by direction and type.", L{"direction": "in", "type": "bans"}, float64(st.BansReceived))
		e.Counter("xproxy_cluster_rejected_total", "Cluster connections rejected.", nil, float64(st.Rejected))
	}

	for _, st := range s.ICAP() {
		l := L{"service": st.Name}
		e.Gauge("xproxy_icap_reachable", "1 when the ICAP service answered its last exchange.", l, b2f(st.Reachable))
		for result, v := range map[string]uint64{"unmodified": st.Unmodified, "modified": st.Modified, "replaced": st.Replacements, "error": st.Errors, "bypassed": st.Bypassed} {
			e.Counter("xproxy_icap_results_total", "ICAP exchanges by result.", L{"service": st.Name, "result": result}, float64(v))
		}
	}

	e.Counter("xproxy_log_write_errors_total", "Failed log file writes (disk full); events were dropped.", nil, float64(sn.LogWriteErrors))
	{
		exp := s.CertificateExpiry()
		names := make([]string, 0, len(exp))
		for n := range exp {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			e.Gauge("xproxy_certificate_expiry_seconds", "Seconds until the earliest file certificate of the listener expires.", L{"listener": n}, time.Until(exp[n]).Seconds())
		}
	}
	e.Counter("xproxy_tcp_connections_total", "Connections accepted on tcp listeners.", nil, float64(sn.TCPConnections))
	e.Counter("xproxy_tcp_rejected_total", "Connections on tcp listeners closed without a route or over the listener bound.", nil, float64(sn.TCPRejected))
	e.Counter("xproxy_tcp_errors_total", "tcp listener connections that found no reachable endpoint.", nil, float64(sn.TCPErrors))
	e.Counter("xproxy_tcp_bytes_total", "Bytes relayed by tcp listeners.", L{"direction": "in"}, float64(sn.TCPBytesIn))
	e.Counter("xproxy_tcp_bytes_total", "Bytes relayed by tcp listeners.", L{"direction": "out"}, float64(sn.TCPBytesOut))
	e.Counter("xproxy_quic_flows_total", "QUIC flows relayed by tcp listeners.", nil, float64(sn.QUICFlows))
	e.Counter("xproxy_quic_rejected_total", "QUIC flows without a route or over the listener bound.", nil, float64(sn.QUICRejected))
	e.Gauge("xproxy_quic_flows_open", "Open QUIC flows.", nil, float64(sn.QUICFlowsOpen))
	e.Counter("xproxy_honeypot_hits_total", "Requests answered by a honeypot route.", nil, float64(sn.HoneypotHits))
	e.Gauge("xproxy_honeypot_marked", "Clients currently marked by a honeypot.", nil, float64(sn.HoneypotMarked))
	e.Counter("xproxy_static_responses_total", "Requests answered by static routes.", L{"result": "served"}, float64(sn.StaticServed))
	e.Counter("xproxy_static_responses_total", "Requests answered by static routes.", L{"result": "not_found"}, float64(sn.StaticNotFound))
	e.Counter("xproxy_compressed_responses_total", "Responses the proxy compressed with gzip.", nil, float64(sn.Compressed))
	e.Counter("xproxy_compressed_raw_bytes_total", "Uncompressed size of the responses the proxy compressed.", nil, float64(sn.CompressedRawBytes))
	for code, n := range sn.GRPCStatus {
		if n > 0 {
			e.Counter("xproxy_grpc_responses_total", "gRPC responses relayed by grpc-status code.", L{"code": strconv.Itoa(code)}, float64(n))
		}
	}
	for _, d := range s.DNS() {
		l := L{"listener": d.Listener}
		e.Counter("xproxy_dns_queries_total", "DNS queries received.", l, float64(d.Queries))
		e.Counter("xproxy_dns_cache_hits_total", "DNS queries answered from the cache.", l, float64(d.CacheHits))
		e.Gauge("xproxy_dns_cache_entries", "DNS cache entries.", l, float64(d.CacheEntries))
		e.Counter("xproxy_dns_blocked_total", "DNS queries for blocked names.", l, float64(d.Blocked))
		e.Counter("xproxy_dns_refused_total", "DNS queries refused by the client policy.", l, float64(d.Refused))
		e.Counter("xproxy_dns_dropped_total", "DNS queries dropped (banned, rate limited, malformed, over the in-flight bound).", l, float64(d.Dropped))
		e.Counter("xproxy_dns_servfail_total", "DNS queries answered SERVFAIL (no upstream answer).", l, float64(d.ServFail))
		e.Counter("xproxy_dns_truncated_total", "DNS answers truncated for UDP clients.", l, float64(d.Truncated))
		e.Counter("xproxy_dns_upstream_failures_total", "DNS upstream attempts without an answer.", l, float64(d.UpstreamFail))
	}
	e.Counter("xproxy_mirror_total", "Mirror copies by outcome.", L{"outcome": "sent"}, float64(sn.MirrorSent))
	e.Counter("xproxy_mirror_total", "Mirror copies by outcome.", L{"outcome": "dropped"}, float64(sn.MirrorDropped))
	e.Counter("xproxy_mirror_total", "Mirror copies by outcome.", L{"outcome": "skipped"}, float64(sn.MirrorSkipped))
	e.Counter("xproxy_mirror_total", "Mirror copies by outcome.", L{"outcome": "failed"}, float64(sn.MirrorFailed))
	e.Counter("xproxy_forward_requests_total", "Requests received on forward listeners (CONNECT and plain).", nil, float64(sn.ForwardRequests))
	e.Counter("xproxy_forward_tunnels_total", "CONNECT tunnels opened by forward listeners.", nil, float64(sn.ForwardTunnels))
	e.Gauge("xproxy_forward_tunnels_open", "Open CONNECT tunnels.", nil, float64(sn.ForwardTunnelsOpen))
	e.Counter("xproxy_forward_denied_total", "Forward requests refused by the destination policy.", nil, float64(sn.ForwardDenied))
	e.Counter("xproxy_forward_auth_failures_total", "Forward requests without valid proxy credentials.", nil, float64(sn.ForwardAuthFailed))
	e.Counter("xproxy_forward_rejected_total", "CONNECT requests refused by the tunnel bound.", nil, float64(sn.ForwardRejected))
	e.Counter("xproxy_forward_errors_total", "Forward requests whose destination failed (dial, response, size).", nil, float64(sn.ForwardErrors))
	e.Counter("xproxy_forward_bytes_total", "Bytes relayed by forward listeners.", L{"direction": "in"}, float64(sn.ForwardBytesIn))
	e.Counter("xproxy_forward_bytes_total", "Bytes relayed by forward listeners.", L{"direction": "out"}, float64(sn.ForwardBytesOut))
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

	// Process and Go runtime, for capacity planning and soak tests.
	rm := runtimeSample()
	e.Gauge("go_goroutines", "Goroutines.", nil, rm.goroutines)
	e.Gauge("go_memstats_heap_alloc_bytes", "Heap bytes in use.", nil, rm.heapAlloc)
	e.Gauge("go_memstats_sys_bytes", "Bytes obtained from the OS.", nil, rm.sys)
	e.Counter("go_gc_cycles_total", "Completed garbage collection cycles.", nil, rm.gcCycles)
	e.Gauge("process_open_fds", "Open file descriptors, or -1 when unknown.", nil, float64(openFDs()))

	e.Histogram("xproxy_request_duration_seconds", "Time from request start to response end.", nil, s.stats.RequestDuration.Snapshot())
	e.Histogram("xproxy_upstream_ttfb_seconds", "Upstream time to first byte.", nil, s.stats.UpstreamTTFB.Snapshot())

	// Upstream pools and endpoints.
	names := make([]string, 0, len(rt.pools))
	for name := range rt.pools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		eps := rt.pools[name].Stats()
		healthy := 0
		for _, ep := range eps {
			if ep.Healthy && !ep.Ejected {
				healthy++
			}
		}
		e.Gauge("xproxy_upstream_endpoints", "Configured endpoints in the pool.", L{"upstream": name}, float64(len(eps)))
		ps := rt.pools[name].Status()
		if ps.Circuit != nil {
			state := 0.0
			switch ps.Circuit.State {
			case upstream.CircuitHalfOpen:
				state = 1
			case upstream.CircuitOpen:
				state = 2
			}
			e.Gauge("xproxy_upstream_circuit_state", "Circuit breaker state: 0 closed, 1 half open, 2 open.", L{"upstream": name}, state)
			e.Counter("xproxy_upstream_circuit_opens_total", "Times the circuit opened.", L{"upstream": name}, float64(ps.Circuit.Opens))
		}
		if ps.Queue != nil {
			e.Gauge("xproxy_upstream_queue_waiting", "Requests waiting for a pool slot.", L{"upstream": name}, float64(ps.Queue.Waiting))
			e.Gauge("xproxy_upstream_in_flight", "Requests holding a pool slot.", L{"upstream": name}, float64(ps.Queue.InFlight))
		}
		e.Gauge("xproxy_upstream_endpoints_healthy", "Endpoints passing health checks and not ejected.", L{"upstream": name}, float64(healthy))
		if !rt.cfg.Metrics.EndpointSeriesEnabled() {
			continue
		}
		for _, ep := range eps {
			l := L{"upstream": name, "endpoint": ep.Address}
			e.Gauge("xproxy_upstream_endpoint_healthy", "1 when the endpoint passes health checks.", l, b2f(ep.Healthy))
			e.Gauge("xproxy_upstream_endpoint_ejected", "1 while the endpoint is ejected as an outlier.", l, b2f(ep.Ejected))
			e.Gauge("xproxy_upstream_endpoint_active", "In-flight requests on the endpoint.", l, float64(ep.Active))
			e.Counter("xproxy_upstream_endpoint_requests_total", "Requests sent to the endpoint.", l, float64(ep.Requests))
			e.Counter("xproxy_upstream_endpoint_errors_total", "Failed requests on the endpoint.", l, float64(ep.Errors))
		}
	}

	// Per route counters (bounded by the number of routes).
	if rt.cfg.Metrics.PerRouteEnabled() {
		for _, cr := range rt.routes {
			labels := func(extra ...string) L {
				l := L{"route": cr.cfg.Name}
				if cr.cfg.Tenant != "" {
					l["tenant"] = cr.cfg.Tenant
				}
				for i := 0; i+1 < len(extra); i += 2 {
					l[extra[i]] = extra[i+1]
				}
				return l
			}
			for i, class := range routeClasses {
				if v := cr.counts[i].Load(); v > 0 || i == 0 {
					e.Counter("xproxy_route_requests_total", "Requests per route and outcome.", labels("outcome", class), float64(v))
				}
			}
			e.Counter("xproxy_route_bytes_total", "Bytes per route and direction.", labels("direction", "in"), float64(cr.bytesIn.Load()))
			e.Counter("xproxy_route_bytes_total", "Bytes per route and direction.", labels("direction", "out"), float64(cr.bytesOut.Load()))
			if v := cr.rateLimited.Load(); v > 0 {
				e.Counter("xproxy_route_rate_limited_total", "Requests refused by a rate limit per route.", labels(), float64(v))
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
			e.Gauge("xproxy_rate_limit_keys", "Keys tracked per policy.", L{"policy": name}, float64(rl.lim.Len()))
		}
	}
}

var routeClasses = [...]string{"2xx", "3xx", "4xx", "5xx", "denied"}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// observeRoute records the outcome and the bytes of a request on its route.
func (cr *compiledRoute) observe(status int, denied bool, bytesIn, bytesOut int64) {
	if bytesIn > 0 {
		cr.bytesIn.Add(uint64(bytesIn)) //nolint:gosec // positive
	}
	if bytesOut > 0 {
		cr.bytesOut.Add(uint64(bytesOut)) //nolint:gosec // positive
	}
	switch {
	case denied:
		cr.counts[4].Add(1)
	case status >= 500:
		cr.counts[3].Add(1)
	case status >= 400:
		cr.counts[2].Add(1)
	case status >= 300:
		cr.counts[1].Add(1)
	default:
		cr.counts[0].Add(1)
	}
}
