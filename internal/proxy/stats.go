package proxy

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/bodybudget"
	"github.com/rom/xproxy/internal/intel"
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

	DeniedACL         atomic.Uint64
	DeniedRateLimit   atomic.Uint64
	Tarpitted         atomic.Uint64
	TarpitOverflow    atomic.Uint64
	DeniedConcurrency atomic.Uint64
	DeniedBodySize    atomic.Uint64
	DeniedBodyBudget  atomic.Uint64
	SecurityTxt       atomic.Uint64
	// SCIMRequests counts requests the provisioning endpoint answered,
	// SCIMDenied the ones it refused.
	SCIMRequests    atomic.Uint64
	SCIMDenied      atomic.Uint64
	DeniedURILength atomic.Uint64
	DeniedNoRoute   atomic.Uint64
	DeniedWebSocket atomic.Uint64
	DeniedBadHost   atomic.Uint64
	DeniedBan       atomic.Uint64
	Shed            atomic.Uint64
	// RangesDropped counts requests whose Range header the range policy
	// removed, RangesRefused the ones it answered 416.
	RangesDropped atomic.Uint64
	RangesRefused atomic.Uint64
	// ThreatIntelMatched counts requests an imported list matched, and
	// the two after it what was done about them; a match whose list only
	// logs is counted by the first alone.
	ThreatIntelMatched    atomic.Uint64
	ThreatIntelBlocked    atomic.Uint64
	ThreatIntelChallenged atomic.Uint64
	Challenged            atomic.Uint64
	DeniedWAF             atomic.Uint64
	DeniedJWT             atomic.Uint64
	DeniedICAP            atomic.Uint64
	DeniedFilter          atomic.Uint64
	DeniedGeo             atomic.Uint64
	DeniedPolicy          atomic.Uint64
	DeniedVirtualPatch    atomic.Uint64
	DeniedNormalization   atomic.Uint64
	DeniedMaintenance     atomic.Uint64
	DeniedSensitive       atomic.Uint64
	DeniedAccount         atomic.Uint64
	HoneypotHits          atomic.Uint64
	HoneytokenHits        atomic.Uint64
	HandshakesRefused     atomic.Uint64
	Degraded              atomic.Uint64
	Deceived              atomic.Uint64
	StaticServed          atomic.Uint64
	StaticNotFound        atomic.Uint64
	Compressed            atomic.Uint64
	CompressedRawBytes    atomic.Uint64
	MirrorSent            atomic.Uint64
	GRPCStatus            [17]atomic.Uint64 // responses by grpc-status code
	MirrorDropped         atomic.Uint64
	MirrorSkipped         atomic.Uint64
	MirrorFailed          atomic.Uint64
	// Mirror shadow diff outcomes.
	MirrorDiffMatch  atomic.Uint64
	MirrorDiffStatus atomic.Uint64
	MirrorDiffHeader atomic.Uint64
	MirrorDiffBody   atomic.Uint64
	TCPConnections   atomic.Uint64
	TCPRejected      atomic.Uint64
	TCPErrors        atomic.Uint64
	// TCPBounded counts connections a listener bound ended rather than
	// a peer: the session lifetime or a byte bound. The access log's
	// closed field says which.
	TCPBounded   atomic.Uint64
	TCPBytesIn   atomic.Uint64
	TCPBytesOut  atomic.Uint64
	QUICFlows    atomic.Uint64
	QUICRejected atomic.Uint64
	// The generic datagram relay. Dropped counts datagrams the relay
	// would not forward and could not refuse -- there is nothing to
	// refuse a datagram with -- with the reason in the security log.
	UDPSessions          atomic.Uint64
	UDPSessionsOpen      atomic.Int64
	UDPDatagramsIn       atomic.Uint64
	UDPDatagramsOut      atomic.Uint64
	UDPBytesIn           atomic.Uint64
	UDPBytesOut          atomic.Uint64
	UDPDropped           atomic.Uint64
	UDPRejected          atomic.Uint64
	UDPErrors            atomic.Uint64
	ForwardRequests      atomic.Uint64
	ForwardTunnels       atomic.Uint64
	ForwardTunnelsOpen   atomic.Int64
	ForwardDenied        atomic.Uint64
	ForwardAuthFailed    atomic.Uint64
	ForwardRejected      atomic.Uint64
	ForwardErrors        atomic.Uint64
	ForwardBytesIn       atomic.Uint64
	ForwardBytesOut      atomic.Uint64
	ForwardSOCKS         atomic.Uint64
	MasqueUDP            atomic.Uint64
	MasqueIP             atomic.Uint64
	MasqueOpen           atomic.Int64
	MasqueDropped        atomic.Uint64
	SMTPSessions         atomic.Uint64
	SMTPSessionsOpen     atomic.Int64
	SMTPMessages         atomic.Uint64
	SMTPRefused          atomic.Uint64
	SMTPRejected         atomic.Uint64
	SMTPTLSUpgrades      atomic.Uint64
	SMTPProtocolErrors   atomic.Uint64
	SMTPBytesIn          atomic.Uint64
	MQTTSessions         atomic.Uint64
	MQTTSessionsOpen     atomic.Int64
	MQTTPublished        atomic.Uint64
	MQTTSubscribed       atomic.Uint64
	MQTTRefused          atomic.Uint64
	MQTTRejected         atomic.Uint64
	MQTTProtocolErrors   atomic.Uint64
	SSHSessions          atomic.Uint64
	SSHSessionsOpen      atomic.Int64
	SSHChannels          atomic.Uint64
	SSHRefused           atomic.Uint64
	FTPSessions          atomic.Uint64
	FTPSessionsOpen      atomic.Int64
	FTPRefused           atomic.Uint64
	FTPRejected          atomic.Uint64
	FTPAuthFailed        atomic.Uint64
	FTPTransfers         atomic.Uint64
	FTPScanned           atomic.Uint64
	FTPScanBlocked       atomic.Uint64
	FTPRecorded          atomic.Uint64
	FTPMFAOK             atomic.Uint64
	FTPMFAFailed         atomic.Uint64
	ModbusSessions       atomic.Uint64
	ModbusSessionsOpen   atomic.Int64
	ModbusRequests       atomic.Uint64
	ModbusResponses      atomic.Uint64
	ModbusDenied         atomic.Uint64
	ModbusWouldDeny      atomic.Uint64
	ModbusExceptions     atomic.Uint64
	ModbusMalformed      atomic.Uint64
	ModbusRefused        atomic.Uint64
	ModbusRejected       atomic.Uint64
	ModbusRateLimited    atomic.Uint64
	ModbusQueueFull      atomic.Uint64
	ModbusUpstreamFailed atomic.Uint64
	ModbusTraced         atomic.Uint64
	ModbusLearned        atomic.Uint64

	// The NTP and NTS gateway.
	//
	// The counters are split by what an operator does next. Requests and
	// Forwarded are the traffic; Denied and WouldDeny are the policy;
	// Malformed, Unsolicited and TimedOut are the packets that were not
	// an exchange; Probes, Disagreements and the Source counters are the
	// monitor, which is the half of this listener that answers "is the
	// time any good".
	NTPRequests            atomic.Uint64
	NTPForwarded           atomic.Uint64
	NTPResponses           atomic.Uint64
	NTPAnswered            atomic.Uint64
	NTPDenied              atomic.Uint64
	NTPWouldDeny           atomic.Uint64
	NTPDropped             atomic.Uint64
	NTPMalformed           atomic.Uint64
	NTPUnsolicited         atomic.Uint64
	NTPRateLimited         atomic.Uint64
	NTPKissSent            atomic.Uint64
	NTPTimedOut            atomic.Uint64
	NTPAssociations        atomic.Uint64
	NTPAssociationsOpen    atomic.Int64
	NTPUpstreamFailed      atomic.Uint64
	NTPUpstreamUnavailable atomic.Uint64
	NTPSendFailed          atomic.Uint64
	NTPInterleaved         atomic.Uint64
	NTPNTSForwarded        atomic.Uint64
	NTPVersion5            atomic.Uint64
	NTPProbes              atomic.Uint64
	NTPProbeFailed         atomic.Uint64
	NTPDisagreements       atomic.Uint64
	NTPSourceHealthy       atomic.Uint64
	NTPSourceUnhealthy     atomic.Uint64
	NTPHoldoverExpired     atomic.Uint64
	NTPSourceChanged       atomic.Uint64
	NTPStratumJumped       atomic.Uint64
	NTPOffsetStepped       atomic.Uint64
	NTPDispersionGrew      atomic.Uint64
	NTPNTSLost             atomic.Uint64
	NTPLeapAnnounced       atomic.Uint64
	NTPLeapUnexpected      atomic.Uint64

	// NTS key establishment, which is its own listener on its own port.
	NTSKESessions          atomic.Uint64
	NTSKERelayed           atomic.Uint64
	NTSKERefused           atomic.Uint64
	NTSKERejected          atomic.Uint64
	NTSKENotNTS            atomic.Uint64
	NTSKEHandshakeLimited  atomic.Uint64
	NTSKEUpstreamFailed    atomic.Uint64
	SyslogReceived         atomic.Uint64
	SyslogForwarded        atomic.Uint64
	SyslogDropped          atomic.Uint64
	SyslogQueueDropped     atomic.Uint64
	SyslogRefused          atomic.Uint64
	SyslogRejected         atomic.Uint64
	SyslogRateLimited      atomic.Uint64
	SyslogRedacted         atomic.Uint64
	SyslogSendFailed       atomic.Uint64
	SyslogConnections      atomic.Uint64
	Intercepted            atomic.Uint64
	InterceptRefused       atomic.Uint64
	InterceptPassed        atomic.Uint64
	InterceptBytes         atomic.Uint64
	SSHRecorded            atomic.Uint64
	SSHRejected            atomic.Uint64
	SSHAuthFailed          atomic.Uint64
	SSHBytesIn             atomic.Uint64
	SSHBytesOut            atomic.Uint64
	SFTPRequests           atomic.Uint64
	VNCSessions            atomic.Uint64
	VNCSessionsOpen        atomic.Int64
	VNCRejected            atomic.Uint64
	VNCRefused             atomic.Uint64
	VNCRecorded            atomic.Uint64
	VNCMFAOK               atomic.Uint64
	VNCMFAFailed           atomic.Uint64
	RDPSessions            atomic.Uint64
	RDPSessionsOpen        atomic.Int64
	RDPRejected            atomic.Uint64
	RDPRefused             atomic.Uint64
	RDPRecorded            atomic.Uint64
	RDPMFAOK               atomic.Uint64
	RDPMFAFailed           atomic.Uint64
	RDPChannelsRefused     atomic.Uint64
	RDPDevicesRefused      atomic.Uint64
	RDPLegacySessions      atomic.Uint64
	RDPLegacyClients       atomic.Uint64
	TelnetSessions         atomic.Uint64
	TelnetSessionsOpen     atomic.Int64
	TelnetRejected         atomic.Uint64
	TelnetRefused          atomic.Uint64
	TelnetOptionsRefused   atomic.Uint64
	TelnetRecorded         atomic.Uint64
	TelnetMFAOK            atomic.Uint64
	TelnetMFAFailed        atomic.Uint64
	SFTPRefused            atomic.Uint64
	SFTPScanned            atomic.Uint64
	SFTPScanBlocked        atomic.Uint64
	MFAVerified            atomic.Uint64
	MFAFailed              atomic.Uint64
	YARAMatches            atomic.Uint64
	YARAScanned            atomic.Uint64
	WSConnections          atomic.Uint64
	WSMessages             atomic.Uint64
	WSViolations           atomic.Uint64
	WSClosed               atomic.Uint64
	ForwardUDPAssociations atomic.Uint64
	ForwardUDPOpen         atomic.Int64
	ForwardUDPDropped      atomic.Uint64
	WAFDetected            atomic.Uint64
	UpstreamErrors         atomic.Uint64
	WebTransportSessions   atomic.Uint64
	UpstreamRetries        atomic.Uint64
	UpstreamStatusRetries  atomic.Uint64
	UpstreamCircuitOpen    atomic.Uint64
	UpstreamQueueFull      atomic.Uint64
	UpstreamQueueTimeouts  atomic.Uint64
	UpstreamTimeouts       atomic.Uint64
	UpstreamNoHealthy      atomic.Uint64
	ClientAborts           atomic.Uint64

	Reloads        atomic.Uint64
	ReloadFailures atomic.Uint64

	// kx counts handshakes by negotiated key agreement group. A map
	// under a mutex rather than an atomic per group: the set is small
	// and fixed by the configuration, and a handshake is already the
	// expensive part of the request.
	kxMu sync.Mutex
	kx   map[string]uint64
	// KeyExchangePQ counts the share that used a post-quantum group,
	// which is the number a rollout is actually measured by.
	KeyExchangePQ atomic.Uint64

	// refusals counts what each listener kind refused and why. HTTP
	// has a counter per reason on this struct; the other protocols
	// have one aggregate each ("SSH channels and requests refused by
	// the bastion's policy"), which says that something was refused
	// but not what an operator has to change. This holds the same
	// breakdown for them, keyed by the kind and the reason the kind
	// already logs.
	refusals refusals
	// RefusalsUntracked counts refusals named under a kind the roster
	// does not have or beyond a kind's reason bound. Zero in a healthy
	// process; anything else is a bug in a listener kind.
	RefusalsUntracked atomic.Uint64
}

// KeyExchange records one completed handshake's group.
func (s *Stats) KeyExchange(group string, pq bool) {
	if group == "" {
		return
	}
	if pq {
		s.KeyExchangePQ.Add(1)
	}
	s.kxMu.Lock()
	defer s.kxMu.Unlock()
	if s.kx == nil {
		s.kx = make(map[string]uint64, 8)
	}
	// The name comes from a closed set plus "group-N" for a group a
	// future Go negotiates, so the map cannot be grown by a client.
	s.kx[group]++
}

// KeyExchangeCounts copies the per group counters.
func (s *Stats) KeyExchangeCounts() map[string]uint64 {
	s.kxMu.Lock()
	defer s.kxMu.Unlock()
	out := make(map[string]uint64, len(s.kx))
	for k, v := range s.kx {
		out[k] = v
	}
	return out
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
	TarpitOverflow    uint64    `json:"tarpit_overflow"`
	TarpitActive      int64     `json:"tarpit_active"`
	DeniedConcurrency uint64    `json:"denied_concurrency"`
	DeniedBodySize    uint64    `json:"denied_body_size"`
	DeniedBodyBudget  uint64    `json:"denied_body_budget"`
	// SecurityTxt counts requests answered with a virtual security.txt.
	SecurityTxt uint64 `json:"security_txt"`
	// SCIMRequests counts requests the SCIM provisioning endpoint
	// answered and SCIMDenied the ones it refused.
	SCIMRequests uint64 `json:"scim_requests"`
	SCIMDenied   uint64 `json:"scim_denied"`
	// BufferedBody is the process-wide buffered-body budget.
	BufferedBody        bodybudget.Stats  `json:"buffered_body"`
	DeniedURILength     uint64            `json:"denied_uri_length"`
	DeniedNoRoute       uint64            `json:"denied_no_route"`
	DeniedWebSocket     uint64            `json:"denied_websocket"`
	DeniedBadHost       uint64            `json:"denied_bad_host"`
	DeniedBan           uint64            `json:"denied_ban"`
	DeniedWAF           uint64            `json:"denied_waf"`
	DeniedJWT           uint64            `json:"denied_jwt"`
	DeniedICAP          uint64            `json:"denied_icap"`
	DeniedFilter        uint64            `json:"denied_filter"`
	DeniedGeo           uint64            `json:"denied_geo"`
	DeniedPolicy        uint64            `json:"denied_policy"`
	DeniedVirtualPatch  uint64            `json:"denied_virtual_patch"`
	DeniedNormalization uint64            `json:"denied_normalization"`
	DeniedMaintenance   uint64            `json:"denied_maintenance"`
	DeniedSensitive     uint64            `json:"denied_sensitive_data"`
	DeniedAccount       uint64            `json:"denied_account_abuse"`
	SensitiveFindings   uint64            `json:"sensitive_findings"`
	AccountBlocks       uint64            `json:"account_blocks"`
	AccountCampaigns    uint64            `json:"account_campaigns"`
	AccountBlocksActive int               `json:"account_blocks_active"`
	HoneypotHits        uint64            `json:"honeypot_hits"`
	HoneytokenHits      uint64            `json:"honeytoken_hits"`
	HandshakesRefused   uint64            `json:"handshakes_refused"`
	KeyExchange         map[string]uint64 `json:"key_exchange"`
	KeyExchangePQ       uint64            `json:"key_exchange_post_quantum"`
	Degraded            uint64            `json:"degraded"`
	Deceived            uint64            `json:"deceived"`
	StaticServed        uint64            `json:"static_served"`
	StaticNotFound      uint64            `json:"static_not_found"`
	Compressed          uint64            `json:"compressed"`
	CompressedRawBytes  uint64            `json:"compressed_raw_bytes"`
	MirrorSent          uint64            `json:"mirror_sent"`
	GRPCStatus          [17]uint64        `json:"grpc_status"`
	DNSQueries          uint64            `json:"dns_queries"`
	DNSCacheHits        uint64            `json:"dns_cache_hits"`
	DNSCacheEntries     int               `json:"dns_cache_entries"`
	DNSBlocked          uint64            `json:"dns_blocked"`
	DNSRefused          uint64            `json:"dns_refused"`
	DNSDropped          uint64            `json:"dns_dropped"`
	DNSServFail         uint64            `json:"dns_servfail"`
	DNSTunnels          uint64            `json:"dns_tunnels"`
	DNSTunnelBlocked    uint64            `json:"dns_tunnel_blocked"`
	DNSTunnelTracked    int               `json:"dns_tunnel_tracked"`
	MirrorDropped       uint64            `json:"mirror_dropped"`
	MirrorSkipped       uint64            `json:"mirror_skipped"`
	MirrorFailed        uint64            `json:"mirror_failed"`
	MirrorDiffMatch     uint64            `json:"mirror_diff_match"`
	MirrorDiffStatus    uint64            `json:"mirror_diff_status"`
	MirrorDiffHeader    uint64            `json:"mirror_diff_header"`
	MirrorDiffBody      uint64            `json:"mirror_diff_body"`
	HoneypotMarked      int               `json:"honeypot_marked"`
	TCPConnections      uint64            `json:"tcp_connections"`
	TCPRejected         uint64            `json:"tcp_rejected"`
	TCPErrors           uint64            `json:"tcp_errors"`
	TCPBounded          uint64            `json:"tcp_bounded"`
	TCPBytesIn          uint64            `json:"tcp_bytes_in"`
	TCPBytesOut         uint64            `json:"tcp_bytes_out"`
	QUICFlows           uint64            `json:"quic_flows"`
	QUICRejected        uint64            `json:"quic_rejected"`
	QUICFlowsOpen       int               `json:"quic_flows_open"`
	UDPSessions         uint64            `json:"udp_sessions"`
	UDPSessionsOpen     int64             `json:"udp_sessions_open"`
	UDPDatagramsIn      uint64            `json:"udp_datagrams_in"`
	UDPDatagramsOut     uint64            `json:"udp_datagrams_out"`
	UDPBytesIn          uint64            `json:"udp_bytes_in"`
	UDPBytesOut         uint64            `json:"udp_bytes_out"`
	UDPDropped          uint64            `json:"udp_dropped"`
	UDPRejected         uint64            `json:"udp_rejected"`
	UDPErrors           uint64            `json:"udp_errors"`
	ForwardRequests     uint64            `json:"forward_requests"`
	ForwardTunnels      uint64            `json:"forward_tunnels"`
	ForwardTunnelsOpen  int64             `json:"forward_tunnels_open"`
	ForwardDenied       uint64            `json:"forward_denied"`
	ForwardAuthFailed   uint64            `json:"forward_auth_failed"`
	ForwardRejected     uint64            `json:"forward_rejected"`
	ForwardErrors       uint64            `json:"forward_errors"`
	ForwardSOCKS        uint64            `json:"forward_socks"`
	MasqueUDP           uint64            `json:"masque_udp"`
	MasqueIP            uint64            `json:"masque_ip"`
	MasqueOpen          int64             `json:"masque_open"`
	MasqueDropped       uint64            `json:"masque_dropped"`
	SMTPSessions        uint64            `json:"smtp_sessions"`
	SMTPSessionsOpen    int64             `json:"smtp_sessions_open"`
	SMTPMessages        uint64            `json:"smtp_messages"`
	SMTPRefused         uint64            `json:"smtp_refused"`
	SMTPRejected        uint64            `json:"smtp_rejected"`
	SMTPTLSUpgrades     uint64            `json:"smtp_tls_upgrades"`
	SMTPProtocolErrors  uint64            `json:"smtp_protocol_errors"`
	SMTPBytesIn         uint64            `json:"smtp_bytes_in"`
	MQTTSessions        uint64            `json:"mqtt_sessions"`
	MQTTSessionsOpen    int64             `json:"mqtt_sessions_open"`
	MQTTPublished       uint64            `json:"mqtt_published"`
	MQTTSubscribed      uint64            `json:"mqtt_subscribed"`
	MQTTRefused         uint64            `json:"mqtt_refused"`
	MQTTRejected        uint64            `json:"mqtt_rejected"`
	MQTTProtocolErrors  uint64            `json:"mqtt_protocol_errors"`
	SSHSessions         uint64            `json:"ssh_sessions"`
	SSHSessionsOpen     int64             `json:"ssh_sessions_open"`
	SSHChannels         uint64            `json:"ssh_channels"`
	SSHRefused          uint64            `json:"ssh_refused"`
	FTPSessions         uint64            `json:"ftp_sessions"`
	FTPSessionsOpen     int64             `json:"ftp_sessions_open"`
	FTPRefused          uint64            `json:"ftp_refused"`
	FTPRejected         uint64            `json:"ftp_rejected"`
	FTPAuthFailed       uint64            `json:"ftp_auth_failed"`
	FTPTransfers        uint64            `json:"ftp_transfers"`
	FTPScanned          uint64            `json:"ftp_scanned"`
	FTPScanBlocked      uint64            `json:"ftp_scan_blocked"`
	FTPRecorded         uint64            `json:"ftp_recorded"`
	FTPMFAOK            uint64            `json:"ftp_mfa_ok"`
	FTPMFAFailed        uint64            `json:"ftp_mfa_failed"`
	// The Modbus relay: sessions, the frames it decided about, and what
	// it decided. ModbusWouldDeny counts the frames a policy would have
	// refused while learning mode was observing rather than enforcing,
	// which is the number that says whether a policy is ready.
	ModbusSessions         uint64             `json:"modbus_sessions"`
	ModbusSessionsOpen     int64              `json:"modbus_sessions_open"`
	ModbusRequests         uint64             `json:"modbus_requests"`
	ModbusResponses        uint64             `json:"modbus_responses"`
	ModbusDenied           uint64             `json:"modbus_denied"`
	ModbusWouldDeny        uint64             `json:"modbus_would_deny"`
	ModbusExceptions       uint64             `json:"modbus_exceptions"`
	ModbusMalformed        uint64             `json:"modbus_malformed"`
	ModbusRefused          uint64             `json:"modbus_refused"`
	ModbusRejected         uint64             `json:"modbus_rejected"`
	ModbusRateLimited      uint64             `json:"modbus_rate_limited"`
	ModbusQueueFull        uint64             `json:"modbus_queue_full"`
	ModbusUpstreamFailed   uint64             `json:"modbus_upstream_failed"`
	ModbusTraced           uint64             `json:"modbus_traced"`
	ModbusLearned          uint64             `json:"modbus_learned"`
	NTPRequests            uint64             `json:"ntp_requests"`
	NTPForwarded           uint64             `json:"ntp_forwarded"`
	NTPResponses           uint64             `json:"ntp_responses"`
	NTPAnswered            uint64             `json:"ntp_answered"`
	NTPDenied              uint64             `json:"ntp_denied"`
	NTPWouldDeny           uint64             `json:"ntp_would_deny"`
	NTPDropped             uint64             `json:"ntp_dropped"`
	NTPMalformed           uint64             `json:"ntp_malformed"`
	NTPUnsolicited         uint64             `json:"ntp_unsolicited"`
	NTPRateLimited         uint64             `json:"ntp_rate_limited"`
	NTPKissSent            uint64             `json:"ntp_kiss_sent"`
	NTPTimedOut            uint64             `json:"ntp_timed_out"`
	NTPAssociations        uint64             `json:"ntp_associations"`
	NTPAssociationsOpen    int64              `json:"ntp_associations_open"`
	NTPUpstreamFailed      uint64             `json:"ntp_upstream_failed"`
	NTPUpstreamUnavailable uint64             `json:"ntp_upstream_unavailable"`
	NTPSendFailed          uint64             `json:"ntp_send_failed"`
	NTPInterleaved         uint64             `json:"ntp_interleaved"`
	NTPNTSForwarded        uint64             `json:"ntp_nts_forwarded"`
	NTPVersion5            uint64             `json:"ntp_version5"`
	NTPProbes              uint64             `json:"ntp_probes"`
	NTPProbeFailed         uint64             `json:"ntp_probe_failed"`
	NTPDisagreements       uint64             `json:"ntp_disagreements"`
	NTPSourceHealthy       uint64             `json:"ntp_source_healthy"`
	NTPSourceUnhealthy     uint64             `json:"ntp_source_unhealthy"`
	NTPHoldoverExpired     uint64             `json:"ntp_holdover_expired"`
	NTPSourceChanged       uint64             `json:"ntp_source_changed"`
	NTPStratumJumped       uint64             `json:"ntp_stratum_jumped"`
	NTPOffsetStepped       uint64             `json:"ntp_offset_stepped"`
	NTPDispersionGrew      uint64             `json:"ntp_dispersion_grew"`
	NTPNTSLost             uint64             `json:"ntp_nts_lost"`
	NTPLeapAnnounced       uint64             `json:"ntp_leap_announced"`
	NTPLeapUnexpected      uint64             `json:"ntp_leap_unexpected"`
	NTSKESessions          uint64             `json:"ntske_sessions"`
	NTSKERelayed           uint64             `json:"ntske_relayed"`
	NTSKERefused           uint64             `json:"ntske_refused"`
	NTSKERejected          uint64             `json:"ntske_rejected"`
	NTSKENotNTS            uint64             `json:"ntske_not_nts"`
	NTSKEHandshakeLimited  uint64             `json:"ntske_handshake_limited"`
	NTSKEUpstreamFailed    uint64             `json:"ntske_upstream_failed"`
	SyslogReceived         uint64             `json:"syslog_received"`
	SyslogForwarded        uint64             `json:"syslog_forwarded"`
	SyslogDropped          uint64             `json:"syslog_dropped"`
	SyslogQueueDropped     uint64             `json:"syslog_queue_dropped"`
	SyslogRefused          uint64             `json:"syslog_refused"`
	SyslogRejected         uint64             `json:"syslog_rejected"`
	SyslogRateLimited      uint64             `json:"syslog_rate_limited"`
	SyslogRedacted         uint64             `json:"syslog_redacted"`
	SyslogSendFailed       uint64             `json:"syslog_send_failed"`
	SyslogConnections      uint64             `json:"syslog_connections"`
	Intercepted            uint64             `json:"forward_intercepted"`
	InterceptRefused       uint64             `json:"forward_intercept_refused"`
	InterceptPassed        uint64             `json:"forward_intercept_passed"`
	InterceptBytes         uint64             `json:"forward_intercept_bytes"`
	SSHRecorded            uint64             `json:"ssh_recorded"`
	SSHRejected            uint64             `json:"ssh_rejected"`
	SSHAuthFailed          uint64             `json:"ssh_auth_failed"`
	SSHBytesIn             uint64             `json:"ssh_bytes_in"`
	SSHBytesOut            uint64             `json:"ssh_bytes_out"`
	SFTPRequests           uint64             `json:"sftp_requests"`
	VNCSessions            uint64             `json:"vnc_sessions"`
	VNCSessionsOpen        int64              `json:"vnc_sessions_open"`
	VNCRejected            uint64             `json:"vnc_rejected"`
	VNCRefused             uint64             `json:"vnc_refused"`
	VNCRecorded            uint64             `json:"vnc_recorded"`
	VNCMFAOK               uint64             `json:"vnc_mfa_ok"`
	VNCMFAFailed           uint64             `json:"vnc_mfa_failed"`
	RDPSessions            uint64             `json:"rdp_sessions"`
	RDPSessionsOpen        int64              `json:"rdp_sessions_open"`
	RDPRejected            uint64             `json:"rdp_rejected"`
	RDPRefused             uint64             `json:"rdp_refused"`
	RDPRecorded            uint64             `json:"rdp_recorded"`
	RDPMFAOK               uint64             `json:"rdp_mfa_ok"`
	RDPMFAFailed           uint64             `json:"rdp_mfa_failed"`
	RDPChannelsRefused     uint64             `json:"rdp_channels_refused"`
	RDPDevicesRefused      uint64             `json:"rdp_devices_refused"`
	RDPLegacySessions      uint64             `json:"rdp_legacy_sessions"`
	RDPLegacyClients       uint64             `json:"rdp_legacy_clients"`
	TelnetSessions         uint64             `json:"telnet_sessions"`
	TelnetSessionsOpen     int64              `json:"telnet_sessions_open"`
	TelnetRejected         uint64             `json:"telnet_rejected"`
	TelnetRefused          uint64             `json:"telnet_refused"`
	TelnetOptionsRefused   uint64             `json:"telnet_options_refused"`
	TelnetRecorded         uint64             `json:"telnet_recorded"`
	TelnetMFAOK            uint64             `json:"telnet_mfa_ok"`
	TelnetMFAFailed        uint64             `json:"telnet_mfa_failed"`
	SFTPRefused            uint64             `json:"sftp_refused"`
	SFTPScanned            uint64             `json:"sftp_scanned"`
	SFTPScanBlocked        uint64             `json:"sftp_scan_blocked"`
	MFAVerified            uint64             `json:"mfa_verified"`
	MFAFailed              uint64             `json:"mfa_failed"`
	YARAMatches            uint64             `json:"yara_matches"`
	YARAScanned            uint64             `json:"yara_scanned"`
	WSConnections          uint64             `json:"websocket_connections"`
	WSMessages             uint64             `json:"websocket_messages"`
	WSViolations           uint64             `json:"websocket_violations"`
	WSClosed               uint64             `json:"websocket_closed"`
	ForwardUDPAssociations uint64             `json:"forward_udp_associations"`
	ForwardUDPOpen         int64              `json:"forward_udp_open"`
	ForwardUDPDropped      uint64             `json:"forward_udp_dropped"`
	ForwardBytesIn         uint64             `json:"forward_bytes_in"`
	ForwardBytesOut        uint64             `json:"forward_bytes_out"`
	WAFDetected            uint64             `json:"waf_detected"`
	SessionsLive           int                `json:"sessions_live"`
	SessionsOpened         uint64             `json:"sessions_opened"`
	SessionsClosed         uint64             `json:"sessions_closed"`
	SessionsKilled         uint64             `json:"sessions_killed"`
	SessionsRefused        uint64             `json:"sessions_refused"`
	BansActive             int                `json:"bans_active"`
	BansTotal              uint64             `json:"bans_total"`
	ClusterPeers           int                `json:"cluster_peers"`
	ClusterConnected       int                `json:"cluster_connected"`
	Shed                   uint64             `json:"shed"`
	RangesDropped          uint64             `json:"ranges_dropped"`
	ThreatIntelMatched     uint64             `json:"threat_intel_matched"`
	ThreatIntelBlocked     uint64             `json:"threat_intel_blocked"`
	ThreatIntelChallenged  uint64             `json:"threat_intel_challenged"`
	ThreatIntelReloads     uint64             `json:"threat_intel_reloads"`
	ThreatIntelWatching    bool               `json:"threat_intel_watching"`
	ThreatLists            []intel.ListStatus `json:"threat_lists,omitempty"`
	RangesRefused          uint64             `json:"ranges_refused"`
	LoadLevel              float64            `json:"load_level"`
	UpstreamLatencyMS      float64            `json:"upstream_latency_ms"`
	SheddingClasses        []string           `json:"shedding_classes"`
	ChallengesIssued       uint64             `json:"challenges_issued"`
	ChallengesPassed       uint64             `json:"challenges_passed"`
	ChallengesFailed       uint64             `json:"challenges_failed"`
	CaptchasPassed         uint64             `json:"captchas_passed"`
	LogSyslogSent          uint64             `json:"log_syslog_sent"`
	LogSyslogDropped       uint64             `json:"log_syslog_dropped"`
	LogJournalDropped      uint64             `json:"log_journald_dropped"`
	LogSIEMSent            uint64             `json:"log_siem_sent"`
	LogSIEMDropped         uint64             `json:"log_siem_dropped"`
	LogRedaction           bool               `json:"log_redaction"`
	LogWriteErrors         uint64             `json:"log_write_errors"`
	UpstreamErrors         uint64             `json:"upstream_errors"`
	WebTransportSessions   uint64             `json:"webtransport_sessions"`
	UpstreamRetries        uint64             `json:"upstream_retries"`
	UpstreamStatusRetries  uint64             `json:"upstream_status_retries"`
	UpstreamCircuitOpen    uint64             `json:"upstream_circuit_open"`
	UpstreamQueueFull      uint64             `json:"upstream_queue_full"`
	UpstreamQueueTimeouts  uint64             `json:"upstream_queue_timeouts"`
	UpstreamTimeouts       uint64             `json:"upstream_timeouts"`
	UpstreamNoHealthy      uint64             `json:"upstream_no_healthy"`
	ClientAborts           uint64             `json:"client_aborts"`
	Reloads                uint64             `json:"reloads"`
	ReloadFailures         uint64             `json:"reload_failures"`
	OpenConnections        int64              `json:"open_connections"`
	RejectedConns          uint64             `json:"rejected_connections"`
	RateRefusedConns       uint64             `json:"rate_refused_connections"`
	InFlight               int64              `json:"in_flight"`
	// Refusals is what each listener kind refused, kind to reason to
	// count. Omitted when nothing has been refused, so a quiet
	// process's snapshot does not carry an empty object per kind.
	Refusals          map[string]map[string]uint64 `json:"refusals,omitempty"`
	RefusalsUntracked uint64                       `json:"refusals_untracked"`
}

func (s *Stats) snapshot() Snapshot {
	return Snapshot{
		StartedAt:              s.StartedAt,
		UptimeSeconds:          time.Since(s.StartedAt).Seconds(),
		Requests:               s.Requests.Load(),
		Responses2xx:           s.Responses2xx.Load(),
		Responses3xx:           s.Responses3xx.Load(),
		Responses4xx:           s.Responses4xx.Load(),
		Responses5xx:           s.Responses5xx.Load(),
		BytesIn:                s.BytesIn.Load(),
		BytesOut:               s.BytesOut.Load(),
		DeniedACL:              s.DeniedACL.Load(),
		DeniedRateLimit:        s.DeniedRateLimit.Load(),
		Tarpitted:              s.Tarpitted.Load(),
		TarpitOverflow:         s.TarpitOverflow.Load(),
		DeniedConcurrency:      s.DeniedConcurrency.Load(),
		DeniedBodySize:         s.DeniedBodySize.Load(),
		DeniedBodyBudget:       s.DeniedBodyBudget.Load(),
		SecurityTxt:            s.SecurityTxt.Load(),
		SCIMRequests:           s.SCIMRequests.Load(),
		SCIMDenied:             s.SCIMDenied.Load(),
		DeniedURILength:        s.DeniedURILength.Load(),
		DeniedNoRoute:          s.DeniedNoRoute.Load(),
		DeniedWebSocket:        s.DeniedWebSocket.Load(),
		DeniedBadHost:          s.DeniedBadHost.Load(),
		DeniedBan:              s.DeniedBan.Load(),
		Shed:                   s.Shed.Load(),
		RangesDropped:          s.RangesDropped.Load(),
		ThreatIntelMatched:     s.ThreatIntelMatched.Load(),
		ThreatIntelBlocked:     s.ThreatIntelBlocked.Load(),
		ThreatIntelChallenged:  s.ThreatIntelChallenged.Load(),
		RangesRefused:          s.RangesRefused.Load(),
		DeniedWAF:              s.DeniedWAF.Load(),
		DeniedJWT:              s.DeniedJWT.Load(),
		DeniedICAP:             s.DeniedICAP.Load(),
		DeniedFilter:           s.DeniedFilter.Load(),
		DeniedGeo:              s.DeniedGeo.Load(),
		DeniedPolicy:           s.DeniedPolicy.Load(),
		DeniedVirtualPatch:     s.DeniedVirtualPatch.Load(),
		DeniedNormalization:    s.DeniedNormalization.Load(),
		DeniedMaintenance:      s.DeniedMaintenance.Load(),
		DeniedSensitive:        s.DeniedSensitive.Load(),
		DeniedAccount:          s.DeniedAccount.Load(),
		HoneypotHits:           s.HoneypotHits.Load(),
		HoneytokenHits:         s.HoneytokenHits.Load(),
		HandshakesRefused:      s.HandshakesRefused.Load(),
		KeyExchange:            s.KeyExchangeCounts(),
		Refusals:               s.RefusalCounts(),
		RefusalsUntracked:      s.RefusalsUntracked.Load(),
		KeyExchangePQ:          s.KeyExchangePQ.Load(),
		Degraded:               s.Degraded.Load(),
		Deceived:               s.Deceived.Load(),
		StaticServed:           s.StaticServed.Load(),
		StaticNotFound:         s.StaticNotFound.Load(),
		Compressed:             s.Compressed.Load(),
		CompressedRawBytes:     s.CompressedRawBytes.Load(),
		MirrorSent:             s.MirrorSent.Load(),
		GRPCStatus:             grpcSnapshot(&s.GRPCStatus),
		MirrorDropped:          s.MirrorDropped.Load(),
		MirrorSkipped:          s.MirrorSkipped.Load(),
		MirrorFailed:           s.MirrorFailed.Load(),
		MirrorDiffMatch:        s.MirrorDiffMatch.Load(),
		MirrorDiffStatus:       s.MirrorDiffStatus.Load(),
		MirrorDiffHeader:       s.MirrorDiffHeader.Load(),
		MirrorDiffBody:         s.MirrorDiffBody.Load(),
		TCPConnections:         s.TCPConnections.Load(),
		TCPRejected:            s.TCPRejected.Load(),
		TCPErrors:              s.TCPErrors.Load(),
		TCPBounded:             s.TCPBounded.Load(),
		TCPBytesIn:             s.TCPBytesIn.Load(),
		TCPBytesOut:            s.TCPBytesOut.Load(),
		QUICFlows:              s.QUICFlows.Load(),
		UDPSessions:            s.UDPSessions.Load(),
		UDPSessionsOpen:        s.UDPSessionsOpen.Load(),
		UDPDatagramsIn:         s.UDPDatagramsIn.Load(),
		UDPDatagramsOut:        s.UDPDatagramsOut.Load(),
		UDPBytesIn:             s.UDPBytesIn.Load(),
		UDPBytesOut:            s.UDPBytesOut.Load(),
		UDPDropped:             s.UDPDropped.Load(),
		UDPRejected:            s.UDPRejected.Load(),
		UDPErrors:              s.UDPErrors.Load(),
		QUICRejected:           s.QUICRejected.Load(),
		ForwardRequests:        s.ForwardRequests.Load(),
		ForwardTunnels:         s.ForwardTunnels.Load(),
		ForwardTunnelsOpen:     s.ForwardTunnelsOpen.Load(),
		ForwardDenied:          s.ForwardDenied.Load(),
		ForwardAuthFailed:      s.ForwardAuthFailed.Load(),
		ForwardRejected:        s.ForwardRejected.Load(),
		ForwardErrors:          s.ForwardErrors.Load(),
		ForwardSOCKS:           s.ForwardSOCKS.Load(),
		MasqueUDP:              s.MasqueUDP.Load(),
		MasqueIP:               s.MasqueIP.Load(),
		MasqueOpen:             s.MasqueOpen.Load(),
		MasqueDropped:          s.MasqueDropped.Load(),
		SMTPSessions:           s.SMTPSessions.Load(),
		SMTPSessionsOpen:       s.SMTPSessionsOpen.Load(),
		SMTPMessages:           s.SMTPMessages.Load(),
		SMTPRefused:            s.SMTPRefused.Load(),
		SMTPRejected:           s.SMTPRejected.Load(),
		SMTPTLSUpgrades:        s.SMTPTLSUpgrades.Load(),
		SMTPProtocolErrors:     s.SMTPProtocolErrors.Load(),
		SMTPBytesIn:            s.SMTPBytesIn.Load(),
		MQTTSessions:           s.MQTTSessions.Load(),
		MQTTSessionsOpen:       s.MQTTSessionsOpen.Load(),
		MQTTPublished:          s.MQTTPublished.Load(),
		MQTTSubscribed:         s.MQTTSubscribed.Load(),
		MQTTRefused:            s.MQTTRefused.Load(),
		MQTTRejected:           s.MQTTRejected.Load(),
		MQTTProtocolErrors:     s.MQTTProtocolErrors.Load(),
		SSHSessions:            s.SSHSessions.Load(),
		SSHSessionsOpen:        s.SSHSessionsOpen.Load(),
		SSHChannels:            s.SSHChannels.Load(),
		SSHRefused:             s.SSHRefused.Load(),
		FTPSessions:            s.FTPSessions.Load(),
		FTPSessionsOpen:        s.FTPSessionsOpen.Load(),
		FTPRefused:             s.FTPRefused.Load(),
		FTPRejected:            s.FTPRejected.Load(),
		FTPAuthFailed:          s.FTPAuthFailed.Load(),
		FTPTransfers:           s.FTPTransfers.Load(),
		FTPScanned:             s.FTPScanned.Load(),
		FTPScanBlocked:         s.FTPScanBlocked.Load(),
		FTPRecorded:            s.FTPRecorded.Load(),
		FTPMFAOK:               s.FTPMFAOK.Load(),
		FTPMFAFailed:           s.FTPMFAFailed.Load(),
		ModbusSessions:         s.ModbusSessions.Load(),
		ModbusSessionsOpen:     s.ModbusSessionsOpen.Load(),
		ModbusRequests:         s.ModbusRequests.Load(),
		ModbusResponses:        s.ModbusResponses.Load(),
		ModbusDenied:           s.ModbusDenied.Load(),
		ModbusWouldDeny:        s.ModbusWouldDeny.Load(),
		ModbusExceptions:       s.ModbusExceptions.Load(),
		ModbusMalformed:        s.ModbusMalformed.Load(),
		ModbusRefused:          s.ModbusRefused.Load(),
		ModbusRejected:         s.ModbusRejected.Load(),
		ModbusRateLimited:      s.ModbusRateLimited.Load(),
		ModbusQueueFull:        s.ModbusQueueFull.Load(),
		ModbusUpstreamFailed:   s.ModbusUpstreamFailed.Load(),
		ModbusTraced:           s.ModbusTraced.Load(),
		ModbusLearned:          s.ModbusLearned.Load(),
		NTPRequests:            s.NTPRequests.Load(),
		NTPForwarded:           s.NTPForwarded.Load(),
		NTPResponses:           s.NTPResponses.Load(),
		NTPAnswered:            s.NTPAnswered.Load(),
		NTPDenied:              s.NTPDenied.Load(),
		NTPWouldDeny:           s.NTPWouldDeny.Load(),
		NTPDropped:             s.NTPDropped.Load(),
		NTPMalformed:           s.NTPMalformed.Load(),
		NTPUnsolicited:         s.NTPUnsolicited.Load(),
		NTPRateLimited:         s.NTPRateLimited.Load(),
		NTPKissSent:            s.NTPKissSent.Load(),
		NTPTimedOut:            s.NTPTimedOut.Load(),
		NTPAssociations:        s.NTPAssociations.Load(),
		NTPAssociationsOpen:    s.NTPAssociationsOpen.Load(),
		NTPUpstreamFailed:      s.NTPUpstreamFailed.Load(),
		NTPUpstreamUnavailable: s.NTPUpstreamUnavailable.Load(),
		NTPSendFailed:          s.NTPSendFailed.Load(),
		NTPInterleaved:         s.NTPInterleaved.Load(),
		NTPNTSForwarded:        s.NTPNTSForwarded.Load(),
		NTPVersion5:            s.NTPVersion5.Load(),
		NTPProbes:              s.NTPProbes.Load(),
		NTPProbeFailed:         s.NTPProbeFailed.Load(),
		NTPDisagreements:       s.NTPDisagreements.Load(),
		NTPSourceHealthy:       s.NTPSourceHealthy.Load(),
		NTPSourceUnhealthy:     s.NTPSourceUnhealthy.Load(),
		NTPHoldoverExpired:     s.NTPHoldoverExpired.Load(),
		NTPSourceChanged:       s.NTPSourceChanged.Load(),
		NTPStratumJumped:       s.NTPStratumJumped.Load(),
		NTPOffsetStepped:       s.NTPOffsetStepped.Load(),
		NTPDispersionGrew:      s.NTPDispersionGrew.Load(),
		NTPNTSLost:             s.NTPNTSLost.Load(),
		NTPLeapAnnounced:       s.NTPLeapAnnounced.Load(),
		NTPLeapUnexpected:      s.NTPLeapUnexpected.Load(),
		NTSKESessions:          s.NTSKESessions.Load(),
		NTSKERelayed:           s.NTSKERelayed.Load(),
		NTSKERefused:           s.NTSKERefused.Load(),
		NTSKERejected:          s.NTSKERejected.Load(),
		NTSKENotNTS:            s.NTSKENotNTS.Load(),
		NTSKEHandshakeLimited:  s.NTSKEHandshakeLimited.Load(),
		NTSKEUpstreamFailed:    s.NTSKEUpstreamFailed.Load(),
		SyslogReceived:         s.SyslogReceived.Load(),
		SyslogForwarded:        s.SyslogForwarded.Load(),
		SyslogDropped:          s.SyslogDropped.Load(),
		SyslogQueueDropped:     s.SyslogQueueDropped.Load(),
		SyslogRefused:          s.SyslogRefused.Load(),
		SyslogRejected:         s.SyslogRejected.Load(),
		SyslogRateLimited:      s.SyslogRateLimited.Load(),
		SyslogRedacted:         s.SyslogRedacted.Load(),
		SyslogSendFailed:       s.SyslogSendFailed.Load(),
		SyslogConnections:      s.SyslogConnections.Load(),
		Intercepted:            s.Intercepted.Load(),
		InterceptRefused:       s.InterceptRefused.Load(),
		InterceptPassed:        s.InterceptPassed.Load(),
		InterceptBytes:         s.InterceptBytes.Load(),
		SSHRecorded:            s.SSHRecorded.Load(),
		SSHRejected:            s.SSHRejected.Load(),
		SSHAuthFailed:          s.SSHAuthFailed.Load(),
		SSHBytesIn:             s.SSHBytesIn.Load(),
		SSHBytesOut:            s.SSHBytesOut.Load(),
		SFTPRequests:           s.SFTPRequests.Load(),
		VNCSessions:            s.VNCSessions.Load(),
		VNCSessionsOpen:        s.VNCSessionsOpen.Load(),
		VNCRejected:            s.VNCRejected.Load(),
		VNCRefused:             s.VNCRefused.Load(),
		VNCRecorded:            s.VNCRecorded.Load(),
		VNCMFAOK:               s.VNCMFAOK.Load(),
		VNCMFAFailed:           s.VNCMFAFailed.Load(),
		RDPSessions:            s.RDPSessions.Load(),
		RDPSessionsOpen:        s.RDPSessionsOpen.Load(),
		RDPRejected:            s.RDPRejected.Load(),
		RDPRefused:             s.RDPRefused.Load(),
		RDPRecorded:            s.RDPRecorded.Load(),
		RDPMFAOK:               s.RDPMFAOK.Load(),
		RDPMFAFailed:           s.RDPMFAFailed.Load(),
		RDPChannelsRefused:     s.RDPChannelsRefused.Load(),
		RDPDevicesRefused:      s.RDPDevicesRefused.Load(),
		RDPLegacySessions:      s.RDPLegacySessions.Load(),
		RDPLegacyClients:       s.RDPLegacyClients.Load(),
		TelnetSessions:         s.TelnetSessions.Load(),
		TelnetSessionsOpen:     s.TelnetSessionsOpen.Load(),
		TelnetRejected:         s.TelnetRejected.Load(),
		TelnetRefused:          s.TelnetRefused.Load(),
		TelnetOptionsRefused:   s.TelnetOptionsRefused.Load(),
		TelnetRecorded:         s.TelnetRecorded.Load(),
		TelnetMFAOK:            s.TelnetMFAOK.Load(),
		TelnetMFAFailed:        s.TelnetMFAFailed.Load(),
		SFTPRefused:            s.SFTPRefused.Load(),
		SFTPScanned:            s.SFTPScanned.Load(),
		SFTPScanBlocked:        s.SFTPScanBlocked.Load(),
		MFAVerified:            s.MFAVerified.Load(),
		MFAFailed:              s.MFAFailed.Load(),
		YARAMatches:            s.YARAMatches.Load(),
		YARAScanned:            s.YARAScanned.Load(),
		WSConnections:          s.WSConnections.Load(),
		WSMessages:             s.WSMessages.Load(),
		WSViolations:           s.WSViolations.Load(),
		WSClosed:               s.WSClosed.Load(),
		ForwardUDPAssociations: s.ForwardUDPAssociations.Load(),
		ForwardUDPOpen:         s.ForwardUDPOpen.Load(),
		ForwardUDPDropped:      s.ForwardUDPDropped.Load(),
		ForwardBytesIn:         s.ForwardBytesIn.Load(),
		ForwardBytesOut:        s.ForwardBytesOut.Load(),
		WAFDetected:            s.WAFDetected.Load(),
		UpstreamErrors:         s.UpstreamErrors.Load(),
		WebTransportSessions:   s.WebTransportSessions.Load(),
		UpstreamRetries:        s.UpstreamRetries.Load(),
		UpstreamStatusRetries:  s.UpstreamStatusRetries.Load(),
		UpstreamCircuitOpen:    s.UpstreamCircuitOpen.Load(),
		UpstreamQueueFull:      s.UpstreamQueueFull.Load(),
		UpstreamQueueTimeouts:  s.UpstreamQueueTimeouts.Load(),
		UpstreamTimeouts:       s.UpstreamTimeouts.Load(),
		UpstreamNoHealthy:      s.UpstreamNoHealthy.Load(),
		ClientAborts:           s.ClientAborts.Load(),
		Reloads:                s.Reloads.Load(),
		ReloadFailures:         s.ReloadFailures.Load(),
	}
}

// CountStatus records a response's status class, for the exposition's
// xproxy_responses_total. The data plane calls it for every response it
// writes.
func (s *Stats) CountStatus(code int) {
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
