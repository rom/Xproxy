package proxy

import (
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/attack"
	"github.com/rom/xproxy/internal/metrics"
	"github.com/rom/xproxy/internal/safe"
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
		sn.DeniedNoRoute + sn.DeniedWebSocket + sn.DeniedBadHost + sn.DeniedBan + sn.DeniedWAF + sn.DeniedJWT + sn.DeniedICAP + sn.DeniedFilter + sn.DeniedGeo +
		sn.DeniedPolicy + sn.DeniedVirtualPatch + sn.DeniedNormalization + sn.DeniedSensitive + sn.DeniedAccount + sn.DeniedMaintenance
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
	// Any non-zero value here is a bug that a client's bytes reached: the
	// flow was dropped rather than the process, but it must be fixed.
	e.Counter("xproxy_panics_total", "Panics contained on a connection or datagram goroutine. Always zero in a healthy process.", nil, float64(safe.Panics()))

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
		{"policy", sn.DeniedPolicy}, {"virtual_patch", sn.DeniedVirtualPatch}, {"normalization", sn.DeniedNormalization},
		{"sensitive_data", sn.DeniedSensitive}, {"account_abuse", sn.DeniedAccount}, {"maintenance", sn.DeniedMaintenance},
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
	e.Counter("xproxy_connections_rate_refused_total", "Connections closed at accept for arriving faster than the configured rate.", nil, float64(sn.RateRefusedConns))
	e.Counter("xproxy_reloads_total", "Configuration reloads.", L{"result": "ok"}, float64(sn.Reloads))
	e.Counter("xproxy_reloads_total", "Configuration reloads.", L{"result": "failed"}, float64(sn.ReloadFailures))
	e.Counter("xproxy_bans_total", "Bans applied.", nil, float64(sn.BansTotal))
	for result, v := range map[string]uint64{"issued": sn.ChallengesIssued, "passed": sn.ChallengesPassed, "failed": sn.ChallengesFailed, "captcha_passed": sn.CaptchasPassed} {
		e.Counter("xproxy_challenges_total", "Browser challenges by result.", L{"result": result}, float64(v))
	}
	e.Counter("xproxy_log_sent_total", "Log records delivered to network sinks.", L{"sink": "syslog"}, float64(sn.LogSyslogSent))
	e.Counter("xproxy_log_sent_total", "Log records delivered to network sinks.", L{"sink": "siem"}, float64(sn.LogSIEMSent))
	e.Counter("xproxy_log_dropped_total", "Log records dropped by a sink.", L{"sink": "syslog"}, float64(sn.LogSyslogDropped))
	e.Counter("xproxy_log_dropped_total", "Log records dropped by a sink.", L{"sink": "journald"}, float64(sn.LogJournalDropped))
	e.Counter("xproxy_log_dropped_total", "Log records dropped by a sink.", L{"sink": "siem"}, float64(sn.LogSIEMDropped))

	e.Gauge("xproxy_connections_open", "Open client connections (TCP and QUIC).", nil, float64(sn.OpenConnections))
	e.Gauge("xproxy_requests_in_flight", "Requests currently admitted.", nil, float64(sn.InFlight))
	e.Gauge("xproxy_bans_active", "Active bans.", nil, float64(sn.BansActive))
	e.Gauge("xproxy_sessions_live", "Sessions being served now (ssh, sftp, telnet, vnc, rdp, ftp, modbus).", nil, float64(sn.SessionsLive))
	e.Counter("xproxy_sessions_total", "Sessions served.", nil, float64(sn.SessionsOpened))
	e.Counter("xproxy_sessions_closed_total", "Sessions closed by an operator.", L{"by": "operator"}, float64(sn.SessionsKilled))
	if sn.SheddingClasses != nil {
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
	// Just-in-time access. The three worth alerting on are a pending queue
	// that is not being answered, sessions refused for want of a grant, and
	// -- in the other direction -- a listener that requires grants and has
	// none in force at all, which looks the same from outside as a listener
	// that is down.
	if a := sn.Access; a != nil {
		for state, n := range a.ByState {
			e.Gauge("xproxy_access_grants", "Access grants by state.", L{"state": state}, float64(n))
		}
		e.Counter("xproxy_access_requests_total", "Access grants asked for.", nil, float64(a.Requests))
		e.Counter("xproxy_access_approvals_total", "Approvals recorded.", nil, float64(a.Approvals))
		e.Counter("xproxy_access_denials_total", "Requests refused by an approver.", nil, float64(a.Denials))
		e.Counter("xproxy_access_revocations_total", "Grants withdrawn.", nil, float64(a.Revocations))
		e.Counter("xproxy_access_uses_total", "Sessions opened against a grant.", nil, float64(a.Uses))
		for reason, n := range a.Refusals {
			e.Counter("xproxy_access_refusals_total", "Sessions turned away, by reason.",
				L{"reason": reason}, float64(n))
		}
	}
	// The authorisation policy. The number worth alerting on is no_rule: a
	// rising count of decisions the default made is a policy whose rules cover
	// less of the estate than whoever wrote them believes -- and with a deny
	// default, an estate about to find that out one refusal at a time. The
	// per-rule counter is what says which rules are doing the work, and which
	// have never fired because a rule above them matched first.
	if a := sn.Authz; a != nil {
		e.Counter("xproxy_authz_decisions_total", "Authorisation decisions, by outcome.",
			L{"outcome": "allow"}, float64(a.Allowed))
		e.Counter("xproxy_authz_decisions_total", "Authorisation decisions, by outcome.",
			L{"outcome": "deny"}, float64(a.Denied))
		e.Counter("xproxy_authz_default_total", "Authorisation decisions no rule matched, so the section default decided.", nil, float64(a.NoRule))
		e.Gauge("xproxy_authz_shadow", "1 while the authorisation policy evaluates without enforcing.", nil, b2f(a.Shadow))
		e.Gauge("xproxy_authz_default_allows", "1 when an unmatched subject is allowed.", nil, b2f(a.DefaultAllows))
		for _, r := range a.Rules {
			action := "deny"
			if r.Allow {
				action = "allow"
			}
			e.Counter("xproxy_authz_rule_hits_total", "Decisions each authorisation rule made.",
				L{"rule": r.Name, "action": action}, float64(r.Hits))
		}
	}
	// Key custody. The two worth alerting on are a stale secret -- a
	// reference whose refresh keeps failing, so rotation has stopped without
	// the proxy stopping -- and an algorithm the active FIPS module refuses,
	// which is a listener that cannot handshake with the clients asking for
	// it. keys_on_disk is not an alert but a number an estate should be able
	// to watch going down.
	{
		cu := sn.Custody
		e.Gauge("xproxy_private_keys", "Configured private keys by where they are held.",
			L{"custody": "file"}, float64(cu.KeysOnDisk))
		e.Gauge("xproxy_private_keys", "Configured private keys by where they are held.",
			L{"custody": "reference"}, float64(cu.KeysReferenced))
		e.Gauge("xproxy_private_keys", "Configured private keys by where they are held.",
			L{"custody": "signer"}, float64(cu.KeysExternal))
		e.Gauge("xproxy_secrets_vault", "1 when a vault is configured.", nil, b2f(cu.Vault))
		e.Gauge("xproxy_secrets_stale", "References whose last refresh failed and which serve a previous value.",
			nil, float64(len(cu.Stale)))
		e.Counter("xproxy_secret_rotations_total", "Certificate keys replaced from their reference without a reload.",
			nil, float64(cu.Rotations))
		e.Counter("xproxy_secret_refresh_failures_total", "Refreshes of a referenced key that could not resolve.",
			nil, float64(cu.RefreshFailures))
		e.Gauge("xproxy_fips_enabled", "1 when the FIPS 140-3 module is active in this process.", nil, b2f(cu.FIPSEnabled))
		e.Gauge("xproxy_fips_required", "1 when the configuration requires FIPS.", nil, b2f(cu.FIPSRequired))
		e.Gauge("xproxy_fips_refused_algorithms", "Configured algorithms the active module will not do.",
			nil, float64(len(cu.FIPSRefused)))
	}
	// The device inventory. The numbers worth alerting on are the last two:
	// a device nobody accounted for, and a device behaving like something
	// this estate said it does not have.
	if a := sn.Assets; a != nil {
		e.Gauge("xproxy_assets", "Devices in the inventory.", nil, float64(a.Assets))
		e.Gauge("xproxy_assets_unclassified", "Devices the evidence does not identify.", nil, float64(a.Unknown))
		e.Gauge("xproxy_assets_baseline_frozen", "1 while a baseline has been taken.", nil, b2f(a.Frozen))
		e.Gauge("xproxy_assets_new", "Devices seen since the baseline was frozen.", nil, float64(a.New))
		for role, n := range a.ByRole {
			e.Gauge("xproxy_assets_by_role", "Devices per classified role.", L{"role": role}, float64(n))
		}
		e.Counter("xproxy_asset_observations_total", "Observations folded into the inventory.", nil, float64(sn.AssetObservations))
		e.Counter("xproxy_asset_findings_total", "Identity changes the inventory noticed.", nil, float64(a.Findings))
		e.Counter("xproxy_asset_unexpected_role_total", "Observations of a device whose role the estate did not list.", nil, float64(sn.AssetUnexpected))
		e.Counter("xproxy_assets_dropped_total", "Devices the bound evicted, least recently seen first.", nil, float64(a.Dropped))
		e.Counter("xproxy_assets_expired_total", "Devices forgotten after ttl.", nil, float64(a.Expired))
		e.Counter("xproxy_asset_save_failures_total", "Times the inventory could not be written to its state file.", nil, float64(sn.AssetSaveFailures))
		// The advisory matching. The two gauges say different things and both
		// are worth a panel: the first goes down as an estate is patched, and
		// the second says how much of the estate the matching cannot answer
		// for, which is a fact about the equipment rather than a fault in the
		// matching.
		if adv := s.Advisories(); adv != nil {
			c := adv.Counts()
			e.Gauge("xproxy_advisory_documents", "Security advisories loaded.", nil, float64(c.Documents))
			e.Gauge("xproxy_advisory_affected", "Devices an advisory names at the version they report.", nil, float64(sn.AdvisoryAffected))
			e.Gauge("xproxy_advisory_not_assessed", "Devices whose exposure could not be established.", nil, float64(sn.AdvisoryNotAssessed))
			e.Counter("xproxy_advisory_findings_total", "Devices found affected, counted as they were found.", nil, float64(sn.AdvisoryFindings))
			e.Counter("xproxy_advisory_failures_total", "Times an advisory source could not be re-read.", nil, float64(sn.AdvisoryFailures))
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
	// The non-HTTP protocols' equivalent of xproxy_denied_total: each
	// kind has an aggregate counter below ("SSH channels and requests
	// refused"), and this is the breakdown that says which policy did
	// it. The reasons are the same strings the security log carries, so
	// a spike here names the log line to go and read.
	refusals := sn.Refusals
	kinds := make([]string, 0, len(refusals))
	for k := range refusals {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		reasons := make([]string, 0, len(refusals[k]))
		for r := range refusals[k] {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			e.Counter("xproxy_refusals_total", "Connections, sessions, datagrams, commands and channels refused by a protocol listener, by kind and reason.", L{"kind": k, "reason": r}, float64(refusals[k][r]))
		}
	}
	if c := sn.Correlation; c != nil {
		// The cross-listener window. The drops and the evictions are the
		// pair worth an alert: a window being pushed out is one whose
		// answers are becoming "no" for the wrong reason.
		e.Gauge("xproxy_correlation_actors", "Addresses in the cross-listener correlation window.", nil, float64(c.Actors))
		e.Gauge("xproxy_correlation_facts", "Facts in the cross-listener correlation window.", nil, float64(c.Facts))
		e.Counter("xproxy_correlation_observed_total", "Facts written to the cross-listener correlation window.", nil, float64(c.Observed))
		e.Counter("xproxy_correlation_collapsed_total", "Facts that bumped an identical fact's count rather than being appended.", nil, float64(c.Collapsed))
		e.Counter("xproxy_correlation_dropped_total", "Facts the per-address bound pushed out of the window, so a detection reading it has less than the window to work with.", nil, float64(c.Dropped))
		e.Counter("xproxy_correlation_evicted_total", "Addresses the actor bound evicted from the window.", nil, float64(c.Evicted))
	}
	e.Counter("xproxy_correlation_merged_total", "Correlation facts a cluster peer reported, which is how a pivot across two daemons is visible at all.", nil, float64(sn.CorrelationMerged))
	e.Counter("xproxy_correlation_refused_total", "Correlation facts from a peer whose key did not decode -- a sibling of another version, or a message that is not one. Always zero in a healthy cluster.", nil, float64(sn.CorrelationRefused))
	e.Counter("xproxy_refusals_untracked_total", "Refusals a listener kind named under an unknown kind or beyond its reason bound, so they carry no reason label. Always zero in a healthy process.", nil, float64(sn.RefusalsUntracked))
	// The same refusals in the vocabularies an operations centre
	// catalogues detections in -- ATT&CK for ICS for the plant, Enterprise
	// ATT&CK for the rest of the estate, and both where a refusal means
	// something in each. A reason carrying two techniques counts
	// under both, so these do not sum to the refusal total and are not
	// meant to: the question they answer is "how much of this technique
	// did we see", not "how many refusals were there".
	techniques := make([]string, 0, len(sn.Techniques))
	for id := range sn.Techniques {
		techniques = append(techniques, id)
	}
	sort.Strings(techniques)
	for _, id := range techniques {
		t, ok := attack.Get(id)
		if !ok {
			continue
		}
		e.Counter("xproxy_attack_technique_total",
			"Refusals and detections by MITRE ATT&CK technique, for the subset of techniques this proxy can observe. The matrix label is ics for ATT&CK for ICS and enterprise for Enterprise ATT&CK, whose identifier spaces and tactic vocabularies are separate.",
			L{"technique": t.ID, "name": t.Name, "tactic": string(t.Tactic()), "matrix": string(t.Matrix)},
			float64(sn.Techniques[id]))
	}
	// The plant's own tooling, which is not a refusal and is counted apart
	// from them: a program download is a plant being engineered, and the
	// question here is "how much engineering happened, of what kind, where".
	ops := make([]string, 0, len(sn.EngineeringOps))
	for k := range sn.EngineeringOps {
		ops = append(ops, k)
	}
	sort.Strings(ops)
	for _, k := range ops {
		kind, class, ok := strings.Cut(k, "/")
		if !ok {
			continue
		}
		e.Counter("xproxy_engineering_total",
			"Engineering operations recognised: program downloads and uploads, mode changes, restarts, configuration writes, firmware pushes, method calls and file transfers. Not refusals -- what was refused is in xproxy_refusals_total.",
			L{"kind": kind, "operation": class}, float64(sn.EngineeringOps[k]))
	}
	e.Counter("xproxy_tcp_connections_total", "Connections accepted on tcp listeners.", nil, float64(sn.TCPConnections))
	e.Counter("xproxy_tcp_rejected_total", "Connections on tcp listeners closed without a route or over the listener bound.", nil, float64(sn.TCPRejected))
	e.Counter("xproxy_tcp_errors_total", "tcp listener connections that found no reachable endpoint.", nil, float64(sn.TCPErrors))
	e.Counter("xproxy_tcp_bounded_total", "tcp listener connections ended by the session lifetime or a byte bound rather than by a peer.", nil, float64(sn.TCPBounded))
	e.Counter("xproxy_tcp_bytes_total", "Bytes relayed by tcp listeners.", L{"direction": "in"}, float64(sn.TCPBytesIn))
	e.Counter("xproxy_tcp_bytes_total", "Bytes relayed by tcp listeners.", L{"direction": "out"}, float64(sn.TCPBytesOut))
	e.Counter("xproxy_quic_flows_total", "QUIC flows relayed by tcp listeners.", nil, float64(sn.QUICFlows))
	e.Counter("xproxy_quic_rejected_total", "QUIC flows without a route or over the listener bound.", nil, float64(sn.QUICRejected))
	e.Gauge("xproxy_quic_flows_open", "Open QUIC flows.", nil, float64(sn.QUICFlowsOpen))
	e.Counter("xproxy_udp_sessions_total", "Sessions opened on udp listeners.", nil, float64(sn.UDPSessions))
	e.Gauge("xproxy_udp_sessions_open", "Open udp listener sessions.", nil, float64(sn.UDPSessionsOpen))
	e.Counter("xproxy_udp_datagrams_total", "Datagrams relayed by udp listeners.", L{"direction": "in"}, float64(sn.UDPDatagramsIn))
	e.Counter("xproxy_udp_datagrams_total", "Datagrams relayed by udp listeners.", L{"direction": "out"}, float64(sn.UDPDatagramsOut))
	e.Counter("xproxy_udp_bytes_total", "Bytes relayed by udp listeners.", L{"direction": "in"}, float64(sn.UDPBytesIn))
	e.Counter("xproxy_udp_bytes_total", "Bytes relayed by udp listeners.", L{"direction": "out"}, float64(sn.UDPBytesOut))
	e.Counter("xproxy_udp_dropped_total", "Datagrams a udp listener would not relay (a refused client, the rate limit, an oversize datagram).", nil, float64(sn.UDPDropped))
	e.Counter("xproxy_udp_rejected_total", "Datagrams from a new client refused by the session table bounds.", nil, float64(sn.UDPRejected))
	e.Counter("xproxy_udp_errors_total", "udp listener sessions that found no reachable endpoint.", nil, float64(sn.UDPErrors))
	e.Counter("xproxy_honeypot_hits_total", "Requests answered by a honeypot route.", nil, float64(sn.HoneypotHits))
	e.Gauge("xproxy_honeypot_marked", "Clients currently marked by a honeypot.", nil, float64(sn.HoneypotMarked))
	e.Counter("xproxy_tls_handshakes_refused_total", "TLS handshakes refused in the ClientHello.", nil, float64(sn.HandshakesRefused))
	// Per group, so a post-quantum rollout is measured on real traffic:
	// the share of handshakes that agreed a hybrid key is the number,
	// and it moves as client fleets upgrade, not as the configuration
	// changes.
	for g, n := range sn.KeyExchange {
		e.Counter("xproxy_tls_key_exchange_total", "Completed handshakes by key agreement group.", L{"group": g}, float64(n))
	}
	e.Counter("xproxy_masque_sessions_total", "MASQUE sessions accepted, by protocol.", L{"protocol": "connect-udp"}, float64(sn.MasqueUDP))
	e.Counter("xproxy_masque_sessions_total", "MASQUE sessions accepted, by protocol.", L{"protocol": "connect-ip"}, float64(sn.MasqueIP))
	e.Gauge("xproxy_masque_sessions_open", "Open MASQUE sessions.", nil, float64(sn.MasqueOpen))
	e.Counter("xproxy_masque_dropped_total", "Datagrams or packets dropped by a MASQUE session: an unknown context, a bad header, a source or destination the policy refuses.", nil, float64(sn.MasqueDropped))
	e.Counter("xproxy_smtp_sessions_total", "SMTP sessions accepted.", nil, float64(sn.SMTPSessions))
	e.Gauge("xproxy_smtp_sessions_open", "Open SMTP sessions.", nil, float64(sn.SMTPSessionsOpen))
	e.Counter("xproxy_smtp_messages_total", "Messages relayed by smtp listeners.", nil, float64(sn.SMTPMessages))
	e.Counter("xproxy_smtp_refused_total", "SMTP commands refused by the proxy's own policy.", nil, float64(sn.SMTPRefused))
	e.Counter("xproxy_smtp_rejected_total", "SMTP connections closed at accept: over the listener bound, or from a client the policy does not allow.", nil, float64(sn.SMTPRejected))
	e.Counter("xproxy_smtp_tls_upgrades_total", "SMTP sessions that completed STARTTLS.", nil, float64(sn.SMTPTLSUpgrades))
	e.Counter("xproxy_smtp_protocol_errors_total", "SMTP sessions ended on a protocol violation: an overlong line, a bare newline, a reply that did not parse, or data pipelined across STARTTLS.", nil, float64(sn.SMTPProtocolErrors))
	e.Counter("xproxy_smtp_bytes_total", "Message octets relayed by smtp listeners.", L{"direction": "in"}, float64(sn.SMTPBytesIn))
	e.Counter("xproxy_mqtt_sessions_total", "MQTT sessions accepted.", nil, float64(sn.MQTTSessions))
	e.Gauge("xproxy_mqtt_sessions_open", "Open MQTT sessions.", nil, float64(sn.MQTTSessionsOpen))
	e.Counter("xproxy_mqtt_published_total", "PUBLISH packets relayed to the broker.", nil, float64(sn.MQTTPublished))
	e.Counter("xproxy_mqtt_subscribed_total", "SUBSCRIBE packets relayed to the broker.", nil, float64(sn.MQTTSubscribed))
	e.Counter("xproxy_mqtt_refused_total", "MQTT packets refused by the topic policy or a bound.", nil, float64(sn.MQTTRefused))
	e.Counter("xproxy_mqtt_rejected_total", "MQTT connections closed at accept: over the listener bound, or from a client the policy does not allow.", nil, float64(sn.MQTTRejected))
	e.Counter("xproxy_mqtt_protocol_errors_total", "MQTT sessions ended on a malformed packet, from either side.", nil, float64(sn.MQTTProtocolErrors))
	e.Counter("xproxy_ssh_sessions_total", "SSH bastion sessions accepted.", nil, float64(sn.SSHSessions))
	e.Gauge("xproxy_ssh_sessions_open", "Open SSH bastion sessions.", nil, float64(sn.SSHSessionsOpen))
	e.Counter("xproxy_ssh_channels_total", "SSH channels opened through the bastion.", nil, float64(sn.SSHChannels))
	e.Counter("xproxy_ssh_refused_total", "SSH channels and requests refused by the bastion's policy.", nil, float64(sn.SSHRefused))
	e.Counter("xproxy_ssh_rejected_total", "SSH connections closed at accept: over the listener bound, or from a client the policy does not allow.", nil, float64(sn.SSHRejected))
	e.Counter("xproxy_ssh_auth_failed_total", "Failed SSH authentication attempts.", nil, float64(sn.SSHAuthFailed))
	// The pair that says whether a move to security tokens is finished:
	// accepted carrying the traffic while refused falls to nothing.
	e.Counter("xproxy_ssh_hardware_key_total", "SSH authentications by a key held in a security token, and the ones refused for not being one.", L{"result": "accepted"}, float64(sn.SSHHardwareAuths))
	e.Counter("xproxy_ssh_hardware_key_total", "SSH authentications by a key held in a security token, and the ones refused for not being one.", L{"result": "refused"}, float64(sn.SSHHardwareRefused))
	e.Counter("xproxy_ssh_bytes_total", "Bytes relayed through SSH channels.", L{"direction": "in"}, float64(sn.SSHBytesIn))
	e.Counter("xproxy_ssh_bytes_total", "Bytes relayed through SSH channels.", L{"direction": "out"}, float64(sn.SSHBytesOut))
	e.Counter("xproxy_sftp_requests_total", "SFTP requests relayed to the target.", nil, float64(sn.SFTPRequests))
	e.Counter("xproxy_sftp_refused_total", "SFTP requests refused by the policy.", nil, float64(sn.SFTPRefused))
	e.Counter("xproxy_mfa_total", "Second factor checks, by outcome.", L{"outcome": "verified"}, float64(sn.MFAVerified))
	e.Counter("xproxy_mfa_total", "Second factor checks, by outcome.", L{"outcome": "failed"}, float64(sn.MFAFailed))
	// The push factor's own outcomes. throttled is the fatigue bounds refusing
	// an attempt, and it climbing is somebody trying the attack rather than a
	// service having a bad day.
	for result, n := range map[string]uint64{
		"sent": sn.MFAPushSent, "approved": sn.MFAPushApproved, "denied": sn.MFAPushDenied,
		"failed": sn.MFAPushFailed, "throttled": sn.MFAPushThrottled,
	} {
		e.Counter("xproxy_mfa_push_total", "Approval requests for the push second factor, by outcome.", L{"result": result}, float64(n))
	}
	e.Counter("xproxy_yara_matches_total", "Streams and bodies where a YARA rule fired.", nil, float64(sn.YARAMatches))
	e.Counter("xproxy_yara_bytes_total", "Bytes given to the YARA scanner.", nil, float64(sn.YARAScanned))
	e.Counter("xproxy_forward_socks_total", "SOCKS5 connections accepted on forward listeners.", nil, float64(sn.ForwardSOCKS))
	e.Counter("xproxy_forward_udp_associations_total", "SOCKS5 UDP associations opened.", nil, float64(sn.ForwardUDPAssociations))
	e.Gauge("xproxy_forward_udp_open", "Open SOCKS5 UDP associations.", nil, float64(sn.ForwardUDPOpen))
	e.Counter("xproxy_forward_udp_dropped_total", "Datagrams dropped by an association: a bad header, a refused destination, an unsolicited sender or a full peer table.", nil, float64(sn.ForwardUDPDropped))
	e.Counter("xproxy_dns_tunnels_total", "Clients detected exfiltrating through DNS query names.", nil, float64(sn.DNSTunnels))
	e.Counter("xproxy_dns_tunnel_blocked_total", "Queries refused because the client was detected tunnelling under that domain.", nil, float64(sn.DNSTunnelBlocked))
	e.Gauge("xproxy_dns_tunnel_tracked", "Client and domain windows the tunnelling detector holds.", nil, float64(sn.DNSTunnelTracked))
	e.Counter("xproxy_forward_intercepted_total", "CONNECT tunnels whose TLS was terminated and read.", nil, float64(sn.Intercepted))
	e.Counter("xproxy_forward_intercept_refused_total", "Tunnels refused rather than intercepted: the destination did not verify, the handshake named another host, or the client did not trust the CA.", nil, float64(sn.InterceptRefused))
	e.Counter("xproxy_forward_intercept_passed_total", "Tunnels passed through untouched because they were not carrying TLS.", nil, float64(sn.InterceptPassed))
	e.Counter("xproxy_forward_intercept_bytes_total", "Plaintext bytes relayed through an intercepted tunnel.", nil, float64(sn.InterceptBytes))
	for name, st := range s.ECH() {
		e.Counter("xproxy_tls_ech_total", "TLS handshakes by Encrypted Client Hello outcome.", L{"listener": name, "outcome": "accepted"}, float64(st.Accepted))
		e.Counter("xproxy_tls_ech_total", "TLS handshakes by Encrypted Client Hello outcome.", L{"listener": name, "outcome": "not_used"}, float64(st.Rejected))
		e.Counter("xproxy_tls_ech_total", "TLS handshakes by Encrypted Client Hello outcome.", L{"listener": name, "outcome": "refused"}, float64(st.Refused))
	}
	for _, d := range s.Deceptions() {
		e.Counter("xproxy_deceived_total", "Requests answered with a deceptive response instead of the origin's.", L{"route": d.Route}, float64(d.Served))
	}
	for _, d := range s.DeviceDecoys() {
		e.Counter("xproxy_decoy_frames_total", "Frames answered by a fabricated device instead of a real one.",
			L{"listener": d.Listener, "kind": d.Kind, "mode": d.Mode}, float64(d.Served))
		// Worth its own series rather than a label on the one above: a
		// tripwire is the number to alert on, because nothing legitimate
		// reads those addresses.
		e.Counter("xproxy_decoy_tripwire_total", "Frames that touched an address no legitimate client reads.",
			L{"listener": d.Listener, "kind": d.Kind}, float64(d.Tripped))
	}
	for _, d := range s.Degradation() {
		e.Counter("xproxy_degraded_total", "Responses served on a degradation level.", L{"level": d.Name}, float64(d.Applied))
	}
	// Per token only: one series with a token label and one without
	// would not sum, and the name of the plant that was found is the
	// whole point of the counter.
	for _, ht := range s.Honeytokens() {
		e.Counter("xproxy_honeytoken_hits_total", "Requests presenting a planted credential.", L{"token": ht.Name}, float64(ht.Hits))
	}
	if cp := s.capture.Load(); cp != nil {
		cs := cp.Stats()
		e.Gauge("xproxy_capture_active", "1 while the proxy is recording exchanges to a pcapng file.", nil, b2f(cs.Active))
		e.Counter("xproxy_capture_flows_total", "Exchanges seen while recording, by what became of them.", L{"result": "captured"}, float64(cs.Captured))
		e.Counter("xproxy_capture_flows_total", "Exchanges seen while recording, by what became of them.", L{"result": "skipped"}, float64(cs.Skipped))
		e.Counter("xproxy_capture_flows_total", "Exchanges seen while recording, by what became of them.", L{"result": "dropped"}, float64(cs.DroppedFull))
		e.Counter("xproxy_capture_flows_total", "Exchanges seen while recording, by what became of them.", L{"result": "failed"}, float64(cs.WriteFailures))
		e.Counter("xproxy_capture_truncated_total", "Captured bodies cut short at max_body_bytes.", nil, float64(cs.Truncated))
		e.Counter("xproxy_capture_bytes_total", "Bytes written to capture files.", nil, float64(cs.Bytes))
	}
	e.Counter("xproxy_threat_intel_total", "Requests an imported threat intelligence list matched, by what was done.", L{"result": "logged"}, float64(sn.ThreatIntelMatched-sn.ThreatIntelBlocked-sn.ThreatIntelChallenged))
	e.Counter("xproxy_threat_intel_total", "Requests an imported threat intelligence list matched, by what was done.", L{"result": "blocked"}, float64(sn.ThreatIntelBlocked))
	e.Counter("xproxy_threat_intel_total", "Requests an imported threat intelligence list matched, by what was done.", L{"result": "challenged"}, float64(sn.ThreatIntelChallenged))
	// Per list, because an imported list is only as good as its last read:
	// a feed whose fetches have stopped while its failures climb still
	// matches, on entries nobody has refreshed.
	for _, tl := range sn.ThreatLists {
		e.Gauge("xproxy_threat_list_entries", "Entries an imported threat list holds.", L{"list": tl.Name, "kind": listKind(tl.Kind)}, float64(tl.Entries))
		e.Counter("xproxy_threat_list_hits_total", "Matches by the list that made them.", L{"list": tl.Name}, float64(tl.Hits))
		e.Gauge("xproxy_threat_list_age_seconds", "Seconds since an imported threat list was last read.", L{"list": tl.Name}, sinceSeconds(tl.Read))
		e.Gauge("xproxy_threat_list_skipped", "Objects a structured feed held that this list did not take: indicators of other kinds, and objects that are not indicators.", L{"list": tl.Name}, float64(tl.Skipped))
		if tl.Fetches+tl.Failures+tl.NotModified == 0 {
			continue // a file source: nothing is fetched
		}
		e.Counter("xproxy_threat_feed_fetches_total", "Fetches of a network threat feed, by outcome.", L{"list": tl.Name, "result": "fetched"}, float64(tl.Fetches))
		e.Counter("xproxy_threat_feed_fetches_total", "Fetches of a network threat feed, by outcome.", L{"list": tl.Name, "result": "not_modified"}, float64(tl.NotModified))
		e.Counter("xproxy_threat_feed_fetches_total", "Fetches of a network threat feed, by outcome.", L{"list": tl.Name, "result": "failed"}, float64(tl.Failures))
	}
	e.Counter("xproxy_scim_requests_total", "Requests the SCIM provisioning endpoint acted on, by outcome.", L{"result": "answered"}, float64(sn.SCIMRequests-sn.SCIMDenied))
	e.Counter("xproxy_scim_requests_total", "Requests the SCIM provisioning endpoint acted on, by outcome.", L{"result": "refused"}, float64(sn.SCIMDenied))
	e.Counter("xproxy_ranges_total", "Byte range requests the range policy acted on.", L{"result": "dropped"}, float64(sn.RangesDropped))
	e.Counter("xproxy_ranges_total", "Byte range requests the range policy acted on.", L{"result": "refused"}, float64(sn.RangesRefused))
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
		e.Counter("xproxy_dns_upstream_resumed_total", "Encrypted DNS upstream connections that resumed a TLS session instead of a full handshake.", l, float64(d.UpstreamResumed))
		// Per transport, which is how an operator sees an encrypted
		// rollout happening: the plaintext share is the number that has
		// to fall.
		for proto, n := range map[string]uint64{"udp": d.QueriesUDP, "tcp": d.QueriesTCP,
			"dot": d.QueriesDoT, "doh": d.QueriesDoH, "doq": d.QueriesDoQ} {
			e.Counter("xproxy_dns_queries_by_transport_total", "DNS queries by transport.",
				L{"listener": d.Listener, "transport": proto}, float64(n))
		}
		e.Counter("xproxy_dns_local_total", "DNS queries answered from the local record set (discovery and published SVCB or HTTPS records).", l, float64(d.QueriesLocal))
		e.Counter("xproxy_dns_answer_denied_total", "DNS answers refused because they pointed into a denied range (rebinding, metadata endpoints).", l, float64(d.AnswerDenied))
		e.Counter("xproxy_dns_answer_stripped_total", "DNS answers that had denied records removed.", l, float64(d.AnswerStripped))
		e.Counter("xproxy_dns_ecs_stripped_total", "DNS queries whose client subnet option was not forwarded upstream.", l, float64(d.ECSStripped))
		e.Counter("xproxy_dns_stale_total", "DNS answers served after their TTL expired because the upstream had nothing (RFC 8767).", l, float64(d.Stale))
		e.Counter("xproxy_dns_prefetch_total", "DNS cache entries refreshed before they expired.", l, float64(d.Prefetched))
		e.Counter("xproxy_dns_cookies_total", "DNS cookies issued to clients.", L{"listener": d.Listener, "result": "issued"}, float64(d.CookiesIssued))
		e.Counter("xproxy_dns_cookies_total", "DNS cookies issued to clients.", L{"listener": d.Listener, "result": "verified"}, float64(d.CookiesVerified))
		e.Counter("xproxy_dns_cookies_total", "DNS cookies issued to clients.", L{"listener": d.Listener, "result": "refused"}, float64(d.CookiesRefused))
		e.Counter("xproxy_dns_viewed_total", "DNS queries answered by a split-horizon view.", l, float64(d.QueriesViewed))
		e.Counter("xproxy_dns_synthesised_total", "AAAA answers synthesised from an A record for a DNS64 client (RFC 6147).", l, float64(d.QueriesSynthesised))
		e.Counter("xproxy_dns_nsec_denied_total", "NXDOMAIN answers taken from a validated NSEC gap instead of the upstream (RFC 8198).", l, float64(d.QueriesNSEC))
		e.Gauge("xproxy_dns_denials_held", "Parent names whose validated NSEC gaps are held.", l, float64(d.DenialsHeld))
		e.Counter("xproxy_dns_rpz_total", "DNS queries a response policy zone decided.", L{"listener": d.Listener, "result": "acted"}, float64(d.RPZMatched-d.RPZPassthru))
		e.Counter("xproxy_dns_rpz_total", "DNS queries a response policy zone decided.", L{"listener": d.Listener, "result": "passthru"}, float64(d.RPZPassthru))
		for _, z := range d.RPZZones {
			e.Gauge("xproxy_dns_rpz_rules", "Rules held by a response policy zone.", L{"listener": d.Listener, "zone": z.Name}, float64(z.Rules))
			e.Counter("xproxy_dns_rpz_zone_matches_total", "Queries one response policy zone decided.", L{"listener": d.Listener, "zone": z.Name}, float64(z.Matches))
		}
	}
	e.Counter("xproxy_mirror_total", "Mirror copies by outcome.", L{"outcome": "sent"}, float64(sn.MirrorSent))
	e.Counter("xproxy_mirror_total", "Mirror copies by outcome.", L{"outcome": "dropped"}, float64(sn.MirrorDropped))
	e.Counter("xproxy_mirror_total", "Mirror copies by outcome.", L{"outcome": "skipped"}, float64(sn.MirrorSkipped))
	e.Counter("xproxy_mirror_total", "Mirror copies by outcome.", L{"outcome": "failed"}, float64(sn.MirrorFailed))
	e.Counter("xproxy_mirror_diff_total", "Shadow response comparisons by result.", L{"result": "match"}, float64(sn.MirrorDiffMatch))
	e.Counter("xproxy_mirror_diff_total", "Shadow response comparisons by result.", L{"result": "status"}, float64(sn.MirrorDiffStatus))
	e.Counter("xproxy_mirror_diff_total", "Shadow response comparisons by result.", L{"result": "header"}, float64(sn.MirrorDiffHeader))
	e.Counter("xproxy_mirror_diff_total", "Shadow response comparisons by result.", L{"result": "body"}, float64(sn.MirrorDiffBody))
	e.Counter("xproxy_forward_requests_total", "Requests received on forward listeners (CONNECT and plain).", nil, float64(sn.ForwardRequests))
	e.Counter("xproxy_forward_tunnels_total", "CONNECT tunnels opened by forward listeners.", nil, float64(sn.ForwardTunnels))
	e.Gauge("xproxy_forward_tunnels_open", "Open CONNECT tunnels.", nil, float64(sn.ForwardTunnelsOpen))
	e.Counter("xproxy_forward_denied_total", "Forward requests refused by the destination policy.", nil, float64(sn.ForwardDenied))
	e.Counter("xproxy_forward_auth_failures_total", "Forward requests without valid proxy credentials.", nil, float64(sn.ForwardAuthFailed))
	e.Counter("xproxy_forward_rejected_total", "CONNECT requests refused by the tunnel bound.", nil, float64(sn.ForwardRejected))
	e.Counter("xproxy_forward_errors_total", "Forward requests whose destination failed (dial, response, size).", nil, float64(sn.ForwardErrors))
	e.Counter("xproxy_forward_bytes_total", "Bytes relayed by forward listeners.", L{"direction": "in"}, float64(sn.ForwardBytesIn))
	e.Counter("xproxy_forward_bytes_total", "Bytes relayed by forward listeners.", L{"direction": "out"}, float64(sn.ForwardBytesOut))
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

	// The families of whatever data plane this binary linked: per route
	// counters, the WAF, the filters, the cache. A daemon that serves no
	// http listener simply does not emit them, which is the honest
	// exposition for a process that has none.
	if pl := s.plane.Load(); pl != nil {
		(*pl).Collect(e)
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// listKind is a threat list's kind for a label, with the default spelled
// out: an empty label reads as a broken exporter, and "cidr" is what the
// configuration means by leaving it out.
func listKind(kind string) string {
	if kind == "" {
		return "cidr"
	}
	return kind
}

// sinceSeconds is how long ago something happened, for a staleness gauge. A
// zero time means it has not happened at all, which is reported as 0 rather
// than as the seconds since the epoch: a gauge of 1.7e9 on a list that was
// never read would fire every threshold there is and say nothing.
func sinceSeconds(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return time.Since(t).Seconds()
}
