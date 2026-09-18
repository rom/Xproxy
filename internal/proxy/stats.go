package proxy

import (
	"sync/atomic"
	"time"
)

// Stats are process-wide counters exposed by the management API. They are
// monotonically increasing except for the gauges.
type Stats struct {
	StartedAt time.Time

	Requests     atomic.Uint64
	Responses2xx atomic.Uint64
	Responses3xx atomic.Uint64
	Responses4xx atomic.Uint64
	Responses5xx atomic.Uint64
	BytesIn      atomic.Uint64
	BytesOut     atomic.Uint64

	DeniedACL         atomic.Uint64
	DeniedRateLimit   atomic.Uint64
	Tarpitted         atomic.Uint64
	DeniedConcurrency atomic.Uint64
	DeniedBodySize    atomic.Uint64
	DeniedURILength   atomic.Uint64
	DeniedNoRoute     atomic.Uint64
	DeniedWebSocket   atomic.Uint64
	DeniedBadHost     atomic.Uint64
	DeniedBan         atomic.Uint64
	Shed              atomic.Uint64
	Challenged        atomic.Uint64
	DeniedWAF         atomic.Uint64
	DeniedJWT         atomic.Uint64
	WAFDetected       atomic.Uint64
	UpstreamErrors    atomic.Uint64
	UpstreamTimeouts  atomic.Uint64
	UpstreamNoHealthy atomic.Uint64
	ClientAborts      atomic.Uint64

	Reloads        atomic.Uint64
	ReloadFailures atomic.Uint64
}

// Snapshot is the JSON form of Stats.
type Snapshot struct {
	StartedAt         time.Time `json:"started_at"`
	UptimeSeconds     float64   `json:"uptime_seconds"`
	Requests          uint64    `json:"requests"`
	Responses2xx      uint64    `json:"responses_2xx"`
	Responses3xx      uint64    `json:"responses_3xx"`
	Responses4xx      uint64    `json:"responses_4xx"`
	Responses5xx      uint64    `json:"responses_5xx"`
	BytesIn           uint64    `json:"bytes_in"`
	BytesOut          uint64    `json:"bytes_out"`
	DeniedACL         uint64    `json:"denied_acl"`
	DeniedRateLimit   uint64    `json:"denied_rate_limit"`
	Tarpitted         uint64    `json:"tarpitted"`
	DeniedConcurrency uint64    `json:"denied_concurrency"`
	DeniedBodySize    uint64    `json:"denied_body_size"`
	DeniedURILength   uint64    `json:"denied_uri_length"`
	DeniedNoRoute     uint64    `json:"denied_no_route"`
	DeniedWebSocket   uint64    `json:"denied_websocket"`
	DeniedBadHost     uint64    `json:"denied_bad_host"`
	DeniedBan         uint64    `json:"denied_ban"`
	DeniedWAF         uint64    `json:"denied_waf"`
	DeniedJWT         uint64    `json:"denied_jwt"`
	WAFDetected       uint64    `json:"waf_detected"`
	BansActive        int       `json:"bans_active"`
	BansTotal         uint64    `json:"bans_total"`
	ClusterPeers      int       `json:"cluster_peers"`
	ClusterConnected  int       `json:"cluster_connected"`
	Shed              uint64    `json:"shed"`
	LoadLevel         float64   `json:"load_level"`
	UpstreamLatencyMS float64   `json:"upstream_latency_ms"`
	SheddingClasses   []string  `json:"shedding_classes"`
	ChallengesIssued  uint64    `json:"challenges_issued"`
	ChallengesPassed  uint64    `json:"challenges_passed"`
	ChallengesFailed  uint64    `json:"challenges_failed"`
	LogSyslogSent     uint64    `json:"log_syslog_sent"`
	LogSyslogDropped  uint64    `json:"log_syslog_dropped"`
	LogJournalDropped uint64    `json:"log_journald_dropped"`
	LogRedaction      bool      `json:"log_redaction"`
	UpstreamErrors    uint64    `json:"upstream_errors"`
	UpstreamTimeouts  uint64    `json:"upstream_timeouts"`
	UpstreamNoHealthy uint64    `json:"upstream_no_healthy"`
	ClientAborts      uint64    `json:"client_aborts"`
	Reloads           uint64    `json:"reloads"`
	ReloadFailures    uint64    `json:"reload_failures"`
	OpenConnections   int64     `json:"open_connections"`
	RejectedConns     uint64    `json:"rejected_connections"`
	InFlight          int64     `json:"in_flight"`
}

func (s *Stats) snapshot() Snapshot {
	return Snapshot{
		StartedAt:         s.StartedAt,
		UptimeSeconds:     time.Since(s.StartedAt).Seconds(),
		Requests:          s.Requests.Load(),
		Responses2xx:      s.Responses2xx.Load(),
		Responses3xx:      s.Responses3xx.Load(),
		Responses4xx:      s.Responses4xx.Load(),
		Responses5xx:      s.Responses5xx.Load(),
		BytesIn:           s.BytesIn.Load(),
		BytesOut:          s.BytesOut.Load(),
		DeniedACL:         s.DeniedACL.Load(),
		DeniedRateLimit:   s.DeniedRateLimit.Load(),
		Tarpitted:         s.Tarpitted.Load(),
		DeniedConcurrency: s.DeniedConcurrency.Load(),
		DeniedBodySize:    s.DeniedBodySize.Load(),
		DeniedURILength:   s.DeniedURILength.Load(),
		DeniedNoRoute:     s.DeniedNoRoute.Load(),
		DeniedWebSocket:   s.DeniedWebSocket.Load(),
		DeniedBadHost:     s.DeniedBadHost.Load(),
		DeniedBan:         s.DeniedBan.Load(),
		Shed:              s.Shed.Load(),
		DeniedWAF:         s.DeniedWAF.Load(),
		DeniedJWT:         s.DeniedJWT.Load(),
		WAFDetected:       s.WAFDetected.Load(),
		UpstreamErrors:    s.UpstreamErrors.Load(),
		UpstreamTimeouts:  s.UpstreamTimeouts.Load(),
		UpstreamNoHealthy: s.UpstreamNoHealthy.Load(),
		ClientAborts:      s.ClientAborts.Load(),
		Reloads:           s.Reloads.Load(),
		ReloadFailures:    s.ReloadFailures.Load(),
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
