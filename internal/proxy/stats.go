package proxy

import (
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/metrics"
)

// Stats are process-wide counters exposed by the management API. They are
// monotonically increasing except for the gauges.
type Stats struct {
	StartedAt time.Time

	RequestDuration *metrics.Histogram
	UpstreamTTFB    *metrics.Histogram

	Requests     atomic.Uint64
	Responses2xx atomic.Uint64
	Responses3xx atomic.Uint64
	Responses4xx atomic.Uint64
	Responses5xx atomic.Uint64
	BytesIn      atomic.Uint64
	BytesOut     atomic.Uint64

	DeniedACL             atomic.Uint64
	DeniedRateLimit       atomic.Uint64
	Tarpitted             atomic.Uint64
	TarpitOverflow        atomic.Uint64
	DeniedConcurrency     atomic.Uint64
	DeniedBodySize        atomic.Uint64
	DeniedURILength       atomic.Uint64
	DeniedNoRoute         atomic.Uint64
	DeniedWebSocket       atomic.Uint64
	DeniedBadHost         atomic.Uint64
	DeniedBan             atomic.Uint64
	Shed                  atomic.Uint64
	Challenged            atomic.Uint64
	DeniedWAF             atomic.Uint64
	DeniedJWT             atomic.Uint64
	DeniedICAP            atomic.Uint64
	DeniedFilter          atomic.Uint64
	DeniedGeo             atomic.Uint64
	DeniedPolicy          atomic.Uint64
	DeniedVirtualPatch    atomic.Uint64
	HoneypotHits          atomic.Uint64
	StaticServed          atomic.Uint64
	StaticNotFound        atomic.Uint64
	Compressed            atomic.Uint64
	CompressedRawBytes    atomic.Uint64
	MirrorSent            atomic.Uint64
	GRPCStatus            [17]atomic.Uint64 // responses by grpc-status code
	MirrorDropped         atomic.Uint64
	MirrorSkipped         atomic.Uint64
	MirrorFailed          atomic.Uint64
	TCPConnections        atomic.Uint64
	TCPRejected           atomic.Uint64
	TCPErrors             atomic.Uint64
	TCPBytesIn            atomic.Uint64
	TCPBytesOut           atomic.Uint64
	QUICFlows             atomic.Uint64
	QUICRejected          atomic.Uint64
	ForwardRequests       atomic.Uint64
	ForwardTunnels        atomic.Uint64
	ForwardTunnelsOpen    atomic.Int64
	ForwardDenied         atomic.Uint64
	ForwardAuthFailed     atomic.Uint64
	ForwardRejected       atomic.Uint64
	ForwardErrors         atomic.Uint64
	ForwardBytesIn        atomic.Uint64
	ForwardBytesOut       atomic.Uint64
	WAFDetected           atomic.Uint64
	UpstreamErrors        atomic.Uint64
	WebTransportSessions  atomic.Uint64
	UpstreamRetries       atomic.Uint64
	UpstreamStatusRetries atomic.Uint64
	UpstreamCircuitOpen   atomic.Uint64
	UpstreamQueueFull     atomic.Uint64
	UpstreamQueueTimeouts atomic.Uint64
	UpstreamTimeouts      atomic.Uint64
	UpstreamNoHealthy     atomic.Uint64
	ClientAborts          atomic.Uint64

	Reloads        atomic.Uint64
	ReloadFailures atomic.Uint64
}

// Snapshot is the JSON form of Stats.
type Snapshot struct {
	StartedAt             time.Time  `json:"started_at"`
	UptimeSeconds         float64    `json:"uptime_seconds"`
	Requests              uint64     `json:"requests"`
	Responses2xx          uint64     `json:"responses_2xx"`
	Responses3xx          uint64     `json:"responses_3xx"`
	Responses4xx          uint64     `json:"responses_4xx"`
	Responses5xx          uint64     `json:"responses_5xx"`
	BytesIn               uint64     `json:"bytes_in"`
	BytesOut              uint64     `json:"bytes_out"`
	DeniedACL             uint64     `json:"denied_acl"`
	DeniedRateLimit       uint64     `json:"denied_rate_limit"`
	Tarpitted             uint64     `json:"tarpitted"`
	TarpitOverflow        uint64     `json:"tarpit_overflow"`
	TarpitActive          int64      `json:"tarpit_active"`
	DeniedConcurrency     uint64     `json:"denied_concurrency"`
	DeniedBodySize        uint64     `json:"denied_body_size"`
	DeniedURILength       uint64     `json:"denied_uri_length"`
	DeniedNoRoute         uint64     `json:"denied_no_route"`
	DeniedWebSocket       uint64     `json:"denied_websocket"`
	DeniedBadHost         uint64     `json:"denied_bad_host"`
	DeniedBan             uint64     `json:"denied_ban"`
	DeniedWAF             uint64     `json:"denied_waf"`
	DeniedJWT             uint64     `json:"denied_jwt"`
	DeniedICAP            uint64     `json:"denied_icap"`
	DeniedFilter          uint64     `json:"denied_filter"`
	DeniedGeo             uint64     `json:"denied_geo"`
	DeniedPolicy          uint64     `json:"denied_policy"`
	DeniedVirtualPatch    uint64     `json:"denied_virtual_patch"`
	HoneypotHits          uint64     `json:"honeypot_hits"`
	StaticServed          uint64     `json:"static_served"`
	StaticNotFound        uint64     `json:"static_not_found"`
	Compressed            uint64     `json:"compressed"`
	CompressedRawBytes    uint64     `json:"compressed_raw_bytes"`
	MirrorSent            uint64     `json:"mirror_sent"`
	GRPCStatus            [17]uint64 `json:"grpc_status"`
	DNSQueries            uint64     `json:"dns_queries"`
	DNSCacheHits          uint64     `json:"dns_cache_hits"`
	DNSCacheEntries       int        `json:"dns_cache_entries"`
	DNSBlocked            uint64     `json:"dns_blocked"`
	DNSRefused            uint64     `json:"dns_refused"`
	DNSDropped            uint64     `json:"dns_dropped"`
	DNSServFail           uint64     `json:"dns_servfail"`
	MirrorDropped         uint64     `json:"mirror_dropped"`
	MirrorSkipped         uint64     `json:"mirror_skipped"`
	MirrorFailed          uint64     `json:"mirror_failed"`
	HoneypotMarked        int        `json:"honeypot_marked"`
	TCPConnections        uint64     `json:"tcp_connections"`
	TCPRejected           uint64     `json:"tcp_rejected"`
	TCPErrors             uint64     `json:"tcp_errors"`
	TCPBytesIn            uint64     `json:"tcp_bytes_in"`
	TCPBytesOut           uint64     `json:"tcp_bytes_out"`
	QUICFlows             uint64     `json:"quic_flows"`
	QUICRejected          uint64     `json:"quic_rejected"`
	QUICFlowsOpen         int        `json:"quic_flows_open"`
	ForwardRequests       uint64     `json:"forward_requests"`
	ForwardTunnels        uint64     `json:"forward_tunnels"`
	ForwardTunnelsOpen    int64      `json:"forward_tunnels_open"`
	ForwardDenied         uint64     `json:"forward_denied"`
	ForwardAuthFailed     uint64     `json:"forward_auth_failed"`
	ForwardRejected       uint64     `json:"forward_rejected"`
	ForwardErrors         uint64     `json:"forward_errors"`
	ForwardBytesIn        uint64     `json:"forward_bytes_in"`
	ForwardBytesOut       uint64     `json:"forward_bytes_out"`
	WAFDetected           uint64     `json:"waf_detected"`
	BansActive            int        `json:"bans_active"`
	BansTotal             uint64     `json:"bans_total"`
	ClusterPeers          int        `json:"cluster_peers"`
	ClusterConnected      int        `json:"cluster_connected"`
	Shed                  uint64     `json:"shed"`
	LoadLevel             float64    `json:"load_level"`
	UpstreamLatencyMS     float64    `json:"upstream_latency_ms"`
	SheddingClasses       []string   `json:"shedding_classes"`
	ChallengesIssued      uint64     `json:"challenges_issued"`
	ChallengesPassed      uint64     `json:"challenges_passed"`
	ChallengesFailed      uint64     `json:"challenges_failed"`
	LogSyslogSent         uint64     `json:"log_syslog_sent"`
	LogSyslogDropped      uint64     `json:"log_syslog_dropped"`
	LogJournalDropped     uint64     `json:"log_journald_dropped"`
	LogSIEMSent           uint64     `json:"log_siem_sent"`
	LogSIEMDropped        uint64     `json:"log_siem_dropped"`
	LogRedaction          bool       `json:"log_redaction"`
	LogWriteErrors        uint64     `json:"log_write_errors"`
	UpstreamErrors        uint64     `json:"upstream_errors"`
	WebTransportSessions  uint64     `json:"webtransport_sessions"`
	UpstreamRetries       uint64     `json:"upstream_retries"`
	UpstreamStatusRetries uint64     `json:"upstream_status_retries"`
	UpstreamCircuitOpen   uint64     `json:"upstream_circuit_open"`
	UpstreamQueueFull     uint64     `json:"upstream_queue_full"`
	UpstreamQueueTimeouts uint64     `json:"upstream_queue_timeouts"`
	UpstreamTimeouts      uint64     `json:"upstream_timeouts"`
	UpstreamNoHealthy     uint64     `json:"upstream_no_healthy"`
	ClientAborts          uint64     `json:"client_aborts"`
	Reloads               uint64     `json:"reloads"`
	ReloadFailures        uint64     `json:"reload_failures"`
	OpenConnections       int64      `json:"open_connections"`
	RejectedConns         uint64     `json:"rejected_connections"`
	InFlight              int64      `json:"in_flight"`
}

func (s *Stats) snapshot() Snapshot {
	return Snapshot{
		StartedAt:             s.StartedAt,
		UptimeSeconds:         time.Since(s.StartedAt).Seconds(),
		Requests:              s.Requests.Load(),
		Responses2xx:          s.Responses2xx.Load(),
		Responses3xx:          s.Responses3xx.Load(),
		Responses4xx:          s.Responses4xx.Load(),
		Responses5xx:          s.Responses5xx.Load(),
		BytesIn:               s.BytesIn.Load(),
		BytesOut:              s.BytesOut.Load(),
		DeniedACL:             s.DeniedACL.Load(),
		DeniedRateLimit:       s.DeniedRateLimit.Load(),
		Tarpitted:             s.Tarpitted.Load(),
		TarpitOverflow:        s.TarpitOverflow.Load(),
		DeniedConcurrency:     s.DeniedConcurrency.Load(),
		DeniedBodySize:        s.DeniedBodySize.Load(),
		DeniedURILength:       s.DeniedURILength.Load(),
		DeniedNoRoute:         s.DeniedNoRoute.Load(),
		DeniedWebSocket:       s.DeniedWebSocket.Load(),
		DeniedBadHost:         s.DeniedBadHost.Load(),
		DeniedBan:             s.DeniedBan.Load(),
		Shed:                  s.Shed.Load(),
		DeniedWAF:             s.DeniedWAF.Load(),
		DeniedJWT:             s.DeniedJWT.Load(),
		DeniedICAP:            s.DeniedICAP.Load(),
		DeniedFilter:          s.DeniedFilter.Load(),
		DeniedGeo:             s.DeniedGeo.Load(),
		DeniedPolicy:          s.DeniedPolicy.Load(),
		DeniedVirtualPatch:    s.DeniedVirtualPatch.Load(),
		HoneypotHits:          s.HoneypotHits.Load(),
		StaticServed:          s.StaticServed.Load(),
		StaticNotFound:        s.StaticNotFound.Load(),
		Compressed:            s.Compressed.Load(),
		CompressedRawBytes:    s.CompressedRawBytes.Load(),
		MirrorSent:            s.MirrorSent.Load(),
		GRPCStatus:            grpcSnapshot(&s.GRPCStatus),
		MirrorDropped:         s.MirrorDropped.Load(),
		MirrorSkipped:         s.MirrorSkipped.Load(),
		MirrorFailed:          s.MirrorFailed.Load(),
		TCPConnections:        s.TCPConnections.Load(),
		TCPRejected:           s.TCPRejected.Load(),
		TCPErrors:             s.TCPErrors.Load(),
		TCPBytesIn:            s.TCPBytesIn.Load(),
		TCPBytesOut:           s.TCPBytesOut.Load(),
		QUICFlows:             s.QUICFlows.Load(),
		QUICRejected:          s.QUICRejected.Load(),
		ForwardRequests:       s.ForwardRequests.Load(),
		ForwardTunnels:        s.ForwardTunnels.Load(),
		ForwardTunnelsOpen:    s.ForwardTunnelsOpen.Load(),
		ForwardDenied:         s.ForwardDenied.Load(),
		ForwardAuthFailed:     s.ForwardAuthFailed.Load(),
		ForwardRejected:       s.ForwardRejected.Load(),
		ForwardErrors:         s.ForwardErrors.Load(),
		ForwardBytesIn:        s.ForwardBytesIn.Load(),
		ForwardBytesOut:       s.ForwardBytesOut.Load(),
		WAFDetected:           s.WAFDetected.Load(),
		UpstreamErrors:        s.UpstreamErrors.Load(),
		WebTransportSessions:  s.WebTransportSessions.Load(),
		UpstreamRetries:       s.UpstreamRetries.Load(),
		UpstreamStatusRetries: s.UpstreamStatusRetries.Load(),
		UpstreamCircuitOpen:   s.UpstreamCircuitOpen.Load(),
		UpstreamQueueFull:     s.UpstreamQueueFull.Load(),
		UpstreamQueueTimeouts: s.UpstreamQueueTimeouts.Load(),
		UpstreamTimeouts:      s.UpstreamTimeouts.Load(),
		UpstreamNoHealthy:     s.UpstreamNoHealthy.Load(),
		ClientAborts:          s.ClientAborts.Load(),
		Reloads:               s.Reloads.Load(),
		ReloadFailures:        s.ReloadFailures.Load(),
	}
}

func (s *Stats) countStatus(code int) {
	switch {
	case code >= 500:
		s.Responses5xx.Add(1)
	case code >= 400:
		s.Responses4xx.Add(1)
	case code >= 300:
		s.Responses3xx.Add(1)
	default:
		s.Responses2xx.Add(1)
	}
}

func grpcSnapshot(a *[17]atomic.Uint64) [17]uint64 {
	var out [17]uint64
	for i := range a {
		out[i] = a[i].Load()
	}
	return out
}
