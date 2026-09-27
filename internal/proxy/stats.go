package proxy

import (
	"github.com/rom/xproxy/internal/shadow"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/authorization"
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
	UDPSessions        atomic.Uint64
	UDPSessionsOpen    atomic.Int64
	UDPDatagramsIn     atomic.Uint64
	UDPDatagramsOut    atomic.Uint64
	UDPBytesIn         atomic.Uint64
	UDPBytesOut        atomic.Uint64
	UDPDropped         atomic.Uint64
	UDPRejected        atomic.Uint64
	UDPErrors          atomic.Uint64
	ForwardRequests    atomic.Uint64
	ForwardTunnels     atomic.Uint64
	ForwardTunnelsOpen atomic.Int64
	ForwardDenied      atomic.Uint64
	ForwardAuthFailed  atomic.Uint64
	ForwardRejected    atomic.Uint64
	ForwardErrors      atomic.Uint64
	ForwardBytesIn     atomic.Uint64
	ForwardBytesOut    atomic.Uint64
	ForwardSOCKS       atomic.Uint64
	MasqueUDP          atomic.Uint64
	MasqueIP           atomic.Uint64
	MasqueOpen         atomic.Int64
	MasqueDropped      atomic.Uint64
	SMTPSessions       atomic.Uint64
	SMTPSessionsOpen   atomic.Int64
	SMTPMessages       atomic.Uint64
	SMTPRefused        atomic.Uint64
	SMTPRejected       atomic.Uint64
	SMTPTLSUpgrades    atomic.Uint64
	SMTPProtocolErrors atomic.Uint64
	SMTPBytesIn        atomic.Uint64
	MQTTSessions       atomic.Uint64
	MQTTSessionsOpen   atomic.Int64
	MQTTPublished      atomic.Uint64
	MQTTSubscribed     atomic.Uint64
	MQTTRefused        atomic.Uint64
	MQTTRejected       atomic.Uint64
	MQTTProtocolErrors atomic.Uint64
	SSHSessions        atomic.Uint64
	SSHSessionsOpen    atomic.Int64
	SSHChannels        atomic.Uint64
	SSHRefused         atomic.Uint64
	FTPSessions        atomic.Uint64
	FTPSessionsOpen    atomic.Int64
	FTPRefused         atomic.Uint64
	FTPRejected        atomic.Uint64
	FTPAuthFailed      atomic.Uint64
	FTPTransfers       atomic.Uint64
	FTPScanned         atomic.Uint64
	FTPScanBlocked     atomic.Uint64
	FTPRecorded        atomic.Uint64
	FTPMFAOK           atomic.Uint64
	FTPMFAFailed       atomic.Uint64
	ModbusSessions     atomic.Uint64
	ModbusSessionsOpen atomic.Int64
	ModbusRequests     atomic.Uint64
	ModbusResponses    atomic.Uint64
	ModbusDenied       atomic.Uint64
	ModbusWouldDeny    atomic.Uint64
	ModbusExceptions   atomic.Uint64
	ModbusMalformed    atomic.Uint64
	ModbusRefused      atomic.Uint64
	// ModbusValueUnknown counts the value checks that needed an address's
	// current value and had none: a policy running on less than it asks
	// for should be visible rather than silently permissive.
	ModbusValueUnknown   atomic.Uint64
	ModbusValuePoints    atomic.Int64
	ModbusRejected       atomic.Uint64
	ModbusRateLimited    atomic.Uint64
	ModbusQueueFull      atomic.Uint64
	ModbusUpstreamFailed atomic.Uint64
	ModbusTraced         atomic.Uint64
	ModbusLearned        atomic.Uint64
	// ModbusDeceived counts the frames answered by a device that is not
	// there, and ModbusTripwire the ones that touched an address no
	// legitimate master has a reason to touch.
	ModbusDeceived atomic.Uint64
	ModbusTripwire atomic.Uint64

	// The IEC 60870-5-104 relay.
	//
	// The counters are split by what the protocol distinguishes, because
	// that is what an operator asks about: the frames, then the commands
	// separately from the telemetry (a control room's question is never
	// "how many measurements", it is "what was commanded"), then the
	// select-before-operate state, and then the numbering checks that
	// find a lost, duplicated or replayed frame.
	IEC104Sessions     atomic.Uint64
	IEC104SessionsOpen atomic.Int64
	IEC104Frames       atomic.Uint64
	// IEC104Deceived counts the frames answered by a station that is not
	// there, and IEC104Tripwire the ones naming an information object
	// address no legitimate control centre reads.
	IEC104Deceived atomic.Uint64
	IEC104Tripwire atomic.Uint64

	// S7Deceived counts the requests answered by a controller that is not
	// there, and S7Tripwire the ones naming a data block no legitimate
	// client reads.
	S7Deceived atomic.Uint64
	S7Tripwire atomic.Uint64
	// SNMPDeceived counts the requests answered by an agent that is not
	// there, and SNMPTripwire the ones naming an object no legitimate
	// manager reads.
	SNMPDeceived      atomic.Uint64
	SNMPTripwire      atomic.Uint64
	IEC104Commands    atomic.Uint64
	IEC104SystemCmds  atomic.Uint64
	IEC104Denied      atomic.Uint64
	IEC104WouldDeny   atomic.Uint64
	IEC104Malformed   atomic.Uint64
	IEC104Rejected    atomic.Uint64
	IEC104RateLimited atomic.Uint64
	// IEC104Selects and IEC104Executes count the two halves of a
	// two-step command; IEC104Unselected counts the executes refused for
	// arriving without one, which is the number that says whether
	// require_select is doing anything.
	IEC104Selects     atomic.Uint64
	IEC104Executes    atomic.Uint64
	IEC104Unselected  atomic.Uint64
	IEC104SelectsHeld atomic.Int64
	// The setpoint value bounds. IEC104Setpoints counts the setpoint
	// commands seen at all; IEC104SetpointPoints is how many points the
	// relay currently remembers a value for, and IEC104SetpointUnknown how
	// many delta checks ran without one -- which is the number that says
	// whether a delta bound is deciding anything.
	IEC104Setpoints       atomic.Uint64
	IEC104SetpointPoints  atomic.Int64
	IEC104SetpointUnknown atomic.Int64
	IEC104SeqGaps         atomic.Uint64
	IEC104WindowFull      atomic.Uint64
	IEC104UpstreamFail    atomic.Uint64

	// The SNMP relay.
	//
	// The counters are split by what the protocol distinguishes and an
	// operator asks about: the messages, then the *writes* separately from
	// the polling (a poller asks the same questions every thirty seconds;
	// what was changed is the record an estate is asked for), then the
	// amplification bounds, which are the ones that say whether this relay
	// is being used as a reflector.
	SNMPMessages     atomic.Uint64
	SNMPSessions     atomic.Uint64
	SNMPSessionsOpen atomic.Int64
	SNMPReads        atomic.Uint64
	SNMPWrites       atomic.Uint64
	SNMPTraps        atomic.Uint64
	SNMPDenied       atomic.Uint64
	SNMPWouldDeny    atomic.Uint64
	SNMPMalformed    atomic.Uint64
	SNMPRejected     atomic.Uint64
	SNMPRateLimited  atomic.Uint64
	// SNMPAmplified counts the responses refused for being disproportionate
	// to the request that asked for them, and SNMPTruncated the GETBULKs
	// whose repetition count this relay lowered. The second is the quieter
	// number and the more useful one: it says the bound is working rather
	// than that an attack arrived.
	SNMPAmplified    atomic.Uint64
	SNMPTruncated    atomic.Uint64
	SNMPUpgraded     atomic.Uint64
	SNMPTimedOut     atomic.Uint64
	SNMPUpstreamFail atomic.Uint64
	SNMPUnsolicited  atomic.Uint64
	// The LDAP relay.
	//
	// Binds are counted apart from requests and failures apart from binds,
	// because those are the three numbers that say whether somebody is
	// trying passwords against a directory. LDAPStripped counts the
	// attributes removed from answers the directory sent anyway, which is
	// the number that says the attribute policy is doing something a
	// request-side check could not.
	LDAPSessions     atomic.Uint64
	LDAPSessionsOpen atomic.Int64
	LDAPRequests     atomic.Uint64
	LDAPBinds        atomic.Uint64
	LDAPBindFailures atomic.Uint64
	LDAPSearches     atomic.Uint64
	LDAPWrites       atomic.Uint64
	LDAPEntries      atomic.Uint64
	LDAPStripped     atomic.Uint64
	LDAPTruncated    atomic.Uint64
	LDAPStartTLS     atomic.Uint64
	LDAPDenied       atomic.Uint64
	LDAPWouldDeny    atomic.Uint64
	LDAPMalformed    atomic.Uint64
	LDAPRejected     atomic.Uint64
	LDAPRateLimited  atomic.Uint64
	LDAPUpstreamFail atomic.Uint64
	LDAPOutstanding  atomic.Int64
	// The TFTP relay.
	//
	// Transfers are counted rather than datagrams, because a transfer is
	// what a policy decided about and what an operator asks after: which
	// device got which firmware. TFTPLowered counts the requests whose
	// block size or window this relay rewrote to its bound, which is the
	// number that says the amplification bound is working without anything
	// being refused; TFTPPathRefused counts the filenames refused for their
	// shape, which is the other half of the same story.
	TFTPRequests      atomic.Uint64
	TFTPTransfers     atomic.Uint64
	TFTPTransfersOpen atomic.Int64
	TFTPReads         atomic.Uint64
	TFTPWrites        atomic.Uint64
	TFTPBytesIn       atomic.Uint64
	TFTPBytesOut      atomic.Uint64
	TFTPDenied        atomic.Uint64
	TFTPWouldDeny     atomic.Uint64
	TFTPPathRefused   atomic.Uint64
	TFTPLowered       atomic.Uint64
	TFTPOversize      atomic.Uint64
	TFTPMalformed     atomic.Uint64
	TFTPRejected      atomic.Uint64
	TFTPRateLimited   atomic.Uint64
	TFTPTimedOut      atomic.Uint64
	TFTPUpstreamFail  atomic.Uint64
	TFTPUnsolicited   atomic.Uint64
	// The DHCP relay.
	//
	// DHCPRogue is the counter that matters most and the one an operator
	// should alert on: a reply from an address the listener does not admit as
	// a server is somebody answering on the segment, which is the whole of
	// this protocol's attack. DHCPStripped counts the options removed from
	// replies -- a route, a proxy, a boot file -- which is the number that
	// says the answer policy is doing something a request-side check could
	// not.
	DHCPMessages     atomic.Uint64
	DHCPDiscovers    atomic.Uint64
	DHCPRequests     atomic.Uint64
	DHCPReplies      atomic.Uint64
	DHCPLeases       atomic.Uint64
	DHCPReleases     atomic.Uint64
	DHCPDenied       atomic.Uint64
	DHCPWouldDeny    atomic.Uint64
	DHCPRogue        atomic.Uint64
	DHCPStripped     atomic.Uint64
	DHCPMalformed    atomic.Uint64
	DHCPRejected     atomic.Uint64
	DHCPRateLimited  atomic.Uint64
	DHCPTimedOut     atomic.Uint64
	DHCPUpstreamFail atomic.Uint64
	DHCPUnsolicited  atomic.Uint64
	DHCPPending      atomic.Int64
	DHCPClients      atomic.Int64
	// The device inventory.
	//
	// AssetFindings is the one to alert on: an identity change, or a device
	// that was not in the frozen baseline. AssetUnexpected counts the
	// observations of a device whose role is not one the estate said it has,
	// which is how "there are no engineering workstations on the process
	// network" becomes a number.
	AssetObservations atomic.Uint64
	AssetFindings     atomic.Uint64
	AssetUnexpected   atomic.Uint64
	AssetSaveFailures atomic.Uint64

	// SNMPPending is how many requests are outstanding towards agents right
	// now. It is a gauge rather than a total because the number an operator
	// wants is "is the table filling up", and the bound refusing is counted
	// under the too_many_pending refusal.
	SNMPPending atomic.Int64

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
	NTSKESessions         atomic.Uint64
	NTSKERelayed          atomic.Uint64
	NTSKERefused          atomic.Uint64
	NTSKERejected         atomic.Uint64
	NTSKENotNTS           atomic.Uint64
	NTSKEHandshakeLimited atomic.Uint64
	NTSKEUpstreamFailed   atomic.Uint64
	// NTSKEHandshakes is a gauge: the handshakes holding a slot right
	// now. max_concurrent_handshakes is a bound with nothing else to
	// read it by -- the limited counter only moves once clients are
	// being turned away, which is after the answer an operator wanted.
	NTSKEHandshakes    atomic.Int64
	SyslogReceived     atomic.Uint64
	SyslogForwarded    atomic.Uint64
	SyslogDropped      atomic.Uint64
	SyslogQueueDropped atomic.Uint64
	SyslogRefused      atomic.Uint64
	SyslogRejected     atomic.Uint64
	SyslogRateLimited  atomic.Uint64
	SyslogRedacted     atomic.Uint64
	SyslogSendFailed   atomic.Uint64
	SyslogConnections  atomic.Uint64
	Intercepted        atomic.Uint64
	InterceptRefused   atomic.Uint64
	InterceptPassed    atomic.Uint64
	InterceptBytes     atomic.Uint64
	SSHRecorded        atomic.Uint64
	SSHRejected        atomic.Uint64
	SSHAuthFailed      atomic.Uint64
	// SSHHardwareAuths counts authentications by a key held in a security
	// token, and SSHHardwareRefused the ones refused for not being one (or
	// for a certificate that asked for the touch to be waived). The pair is
	// what says whether an estate's move to tokens is finished: refusals
	// falling to nothing while hardware authentications carry the traffic.
	SSHHardwareAuths   atomic.Uint64
	SSHHardwareRefused atomic.Uint64
	SSHBytesIn         atomic.Uint64
	SSHBytesOut        atomic.Uint64
	SFTPRequests       atomic.Uint64
	VNCSessions        atomic.Uint64
	VNCSessionsOpen    atomic.Int64
	VNCRejected        atomic.Uint64
	VNCRefused         atomic.Uint64
	VNCRecorded        atomic.Uint64
	VNCMFAOK           atomic.Uint64
	VNCMFAFailed       atomic.Uint64
	RDPSessions        atomic.Uint64
	RDPSessionsOpen    atomic.Int64
	RDPRejected        atomic.Uint64
	RDPRefused         atomic.Uint64
	RDPRecorded        atomic.Uint64
	RDPMFAOK           atomic.Uint64
	RDPMFAFailed       atomic.Uint64
	RDPChannelsRefused atomic.Uint64
	RDPDevicesRefused  atomic.Uint64
	// RDPDynamicChannelsSeen counts the channels opened inside drdynvc that
	// were carried. On a listener with no dynamic policy written it is the
	// number that says how much of a session is going past undecided.
	RDPDynamicChannelsSeen atomic.Uint64
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
	// The push factor, counted apart from the typed one because its failures
	// mean different things: denied is a person saying no, failed is the
	// approval service not answering usefully, and throttled is the fatigue
	// bounds refusing an attempt without sending anything.
	MFAPushSent            atomic.Uint64
	MFAPushApproved        atomic.Uint64
	MFAPushDenied          atomic.Uint64
	MFAPushFailed          atomic.Uint64
	MFAPushThrottled       atomic.Uint64
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
	// wouldRefusals is the same table for the listeners in shadow mode.
	wouldRefusals refusals
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
	ModbusSessions        uint64 `json:"modbus_sessions"`
	ModbusSessionsOpen    int64  `json:"modbus_sessions_open"`
	ModbusRequests        uint64 `json:"modbus_requests"`
	ModbusResponses       uint64 `json:"modbus_responses"`
	ModbusDenied          uint64 `json:"modbus_denied"`
	ModbusWouldDeny       uint64 `json:"modbus_would_deny"`
	ModbusExceptions      uint64 `json:"modbus_exceptions"`
	ModbusMalformed       uint64 `json:"modbus_malformed"`
	ModbusRefused         uint64 `json:"modbus_refused"`
	ModbusValueUnknown    uint64 `json:"modbus_value_unknown"`
	ModbusValuePoints     int64  `json:"modbus_value_points"`
	ModbusRejected        uint64 `json:"modbus_rejected"`
	ModbusRateLimited     uint64 `json:"modbus_rate_limited"`
	ModbusQueueFull       uint64 `json:"modbus_queue_full"`
	ModbusUpstreamFailed  uint64 `json:"modbus_upstream_failed"`
	ModbusTraced          uint64 `json:"modbus_traced"`
	ModbusLearned         uint64 `json:"modbus_learned"`
	ModbusDeceived        uint64 `json:"modbus_deceived"`
	ModbusTripwire        uint64 `json:"modbus_tripwire"`
	IEC104Sessions        uint64 `json:"iec104_sessions"`
	IEC104SessionsOpen    int64  `json:"iec104_sessions_open"`
	IEC104Frames          uint64 `json:"iec104_frames"`
	IEC104Deceived        uint64 `json:"iec104_deceived"`
	IEC104Tripwire        uint64 `json:"iec104_tripwire"`
	S7Deceived            uint64 `json:"s7_deceived"`
	S7Tripwire            uint64 `json:"s7_tripwire"`
	SNMPDeceived          uint64 `json:"snmp_deceived"`
	SNMPTripwire          uint64 `json:"snmp_tripwire"`
	IEC104Commands        uint64 `json:"iec104_commands"`
	IEC104SystemCmds      uint64 `json:"iec104_system_commands"`
	IEC104Denied          uint64 `json:"iec104_denied"`
	IEC104WouldDeny       uint64 `json:"iec104_would_deny"`
	IEC104Malformed       uint64 `json:"iec104_malformed"`
	IEC104Rejected        uint64 `json:"iec104_rejected"`
	IEC104RateLimited     uint64 `json:"iec104_rate_limited"`
	IEC104Selects         uint64 `json:"iec104_selects"`
	IEC104Executes        uint64 `json:"iec104_executes"`
	IEC104Unselected      uint64 `json:"iec104_unselected"`
	IEC104SelectsHeld     int64  `json:"iec104_selects_held"`
	IEC104Setpoints       uint64 `json:"iec104_setpoints"`
	IEC104SetpointPoints  int64  `json:"iec104_setpoint_points"`
	IEC104SetpointUnknown int64  `json:"iec104_setpoint_unknown"`
	IEC104SeqGaps         uint64 `json:"iec104_sequence_gaps"`
	IEC104WindowFull      uint64 `json:"iec104_window_full"`
	IEC104UpstreamFail    uint64 `json:"iec104_upstream_failed"`
	SNMPMessages          uint64 `json:"snmp_messages"`
	SNMPSessions          uint64 `json:"snmp_sessions"`
	SNMPSessionsOpen      int64  `json:"snmp_sessions_open"`
	SNMPReads             uint64 `json:"snmp_reads"`
	SNMPWrites            uint64 `json:"snmp_writes"`
	SNMPTraps             uint64 `json:"snmp_traps"`
	SNMPDenied            uint64 `json:"snmp_denied"`
	SNMPWouldDeny         uint64 `json:"snmp_would_deny"`
	SNMPMalformed         uint64 `json:"snmp_malformed"`
	SNMPRejected          uint64 `json:"snmp_rejected"`
	SNMPRateLimited       uint64 `json:"snmp_rate_limited"`
	SNMPAmplified         uint64 `json:"snmp_amplified"`
	SNMPTruncated         uint64 `json:"snmp_truncated"`
	SNMPUpgraded          uint64 `json:"snmp_upgraded"`
	SNMPTimedOut          uint64 `json:"snmp_timed_out"`
	SNMPUpstreamFail      uint64 `json:"snmp_upstream_failed"`
	SNMPUnsolicited       uint64 `json:"snmp_unsolicited"`
	SNMPPending           int64  `json:"snmp_pending"`
	LDAPSessions          uint64 `json:"ldap_sessions"`
	LDAPSessionsOpen      int64  `json:"ldap_sessions_open"`
	LDAPRequests          uint64 `json:"ldap_requests"`
	LDAPBinds             uint64 `json:"ldap_binds"`
	LDAPBindFailures      uint64 `json:"ldap_bind_failures"`
	LDAPSearches          uint64 `json:"ldap_searches"`
	LDAPWrites            uint64 `json:"ldap_writes"`
	LDAPEntries           uint64 `json:"ldap_entries"`
	LDAPStripped          uint64 `json:"ldap_stripped"`
	LDAPTruncated         uint64 `json:"ldap_truncated"`
	LDAPStartTLS          uint64 `json:"ldap_starttls"`
	LDAPDenied            uint64 `json:"ldap_denied"`
	LDAPWouldDeny         uint64 `json:"ldap_would_deny"`
	LDAPMalformed         uint64 `json:"ldap_malformed"`
	LDAPRejected          uint64 `json:"ldap_rejected"`
	LDAPRateLimited       uint64 `json:"ldap_rate_limited"`
	LDAPUpstreamFail      uint64 `json:"ldap_upstream_failed"`
	LDAPOutstanding       int64  `json:"ldap_outstanding"`
	TFTPRequests          uint64 `json:"tftp_requests"`
	TFTPTransfers         uint64 `json:"tftp_transfers"`
	TFTPTransfersOpen     int64  `json:"tftp_transfers_open"`
	TFTPReads             uint64 `json:"tftp_reads"`
	TFTPWrites            uint64 `json:"tftp_writes"`
	TFTPBytesIn           uint64 `json:"tftp_bytes_in"`
	TFTPBytesOut          uint64 `json:"tftp_bytes_out"`
	TFTPDenied            uint64 `json:"tftp_denied"`
	TFTPWouldDeny         uint64 `json:"tftp_would_deny"`
	TFTPPathRefused       uint64 `json:"tftp_path_refused"`
	TFTPLowered           uint64 `json:"tftp_lowered"`
	TFTPOversize          uint64 `json:"tftp_oversize"`
	TFTPMalformed         uint64 `json:"tftp_malformed"`
	TFTPRejected          uint64 `json:"tftp_rejected"`
	TFTPRateLimited       uint64 `json:"tftp_rate_limited"`
	TFTPTimedOut          uint64 `json:"tftp_timed_out"`
	TFTPUpstreamFail      uint64 `json:"tftp_upstream_failed"`
	TFTPUnsolicited       uint64 `json:"tftp_unsolicited"`
	DHCPMessages          uint64 `json:"dhcp_messages"`
	DHCPDiscovers         uint64 `json:"dhcp_discovers"`
	DHCPRequests          uint64 `json:"dhcp_requests"`
	DHCPReplies           uint64 `json:"dhcp_replies"`
	DHCPLeases            uint64 `json:"dhcp_leases"`
	DHCPReleases          uint64 `json:"dhcp_releases"`
	DHCPDenied            uint64 `json:"dhcp_denied"`
	DHCPWouldDeny         uint64 `json:"dhcp_would_deny"`
	DHCPRogue             uint64 `json:"dhcp_rogue"`
	DHCPStripped          uint64 `json:"dhcp_stripped"`
	DHCPMalformed         uint64 `json:"dhcp_malformed"`
	DHCPRejected          uint64 `json:"dhcp_rejected"`
	DHCPRateLimited       uint64 `json:"dhcp_rate_limited"`
	DHCPTimedOut          uint64 `json:"dhcp_timed_out"`
	DHCPUpstreamFail      uint64 `json:"dhcp_upstream_failed"`
	DHCPUnsolicited       uint64 `json:"dhcp_unsolicited"`
	DHCPPending           int64  `json:"dhcp_pending"`
	DHCPClients           int64  `json:"dhcp_clients"`
	AssetObservations     uint64 `json:"asset_observations"`
	AssetFindings         uint64 `json:"asset_findings"`
	AssetUnexpected       uint64 `json:"asset_unexpected_role"`
	AssetSaveFailures     uint64 `json:"asset_save_failures"`
	// Access is the just-in-time access ledger's summary, absent when the
	// configuration has no access section. It is here rather than only on
	// the management view because a grant queue nobody drains and sessions
	// refused for want of one are both things to alert on.
	Access *AccessSummary `json:"access,omitempty"`
	// Authz is the estate's authorisation policy, absent when there is no
	// authorization section. The number to watch is NoRule: decisions the
	// default made because nothing matched, which is what says whether the
	// rules describe the estate or only the part somebody remembered.
	Authz *AuthzSummary `json:"authorization,omitempty"`
	// Custody says where this daemon's private keys live and whether the
	// FIPS module is active. It is always present, because "no vault, keys
	// on disk, no FIPS" is an answer somebody auditing an estate needs to
	// be able to read off a status page rather than infer from silence.
	Custody CustodySummary `json:"custody"`
	// Assets is the inventory's own summary, absent when no inventory is
	// configured.
	Assets                 *AssetSummary      `json:"assets,omitempty"`
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
	NTSKEHandshakes        int64              `json:"ntske_handshakes"`
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
	SSHHardwareAuths       uint64             `json:"ssh_hardware_auths"`
	SSHHardwareRefused     uint64             `json:"ssh_hardware_refused"`
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
	RDPDynamicChannelsSeen uint64             `json:"rdp_dynamic_channels_seen"`
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
	MFAPushSent            uint64             `json:"mfa_push_sent"`
	MFAPushApproved        uint64             `json:"mfa_push_approved"`
	MFAPushDenied          uint64             `json:"mfa_push_denied"`
	MFAPushFailed          uint64             `json:"mfa_push_failed"`
	MFAPushThrottled       uint64             `json:"mfa_push_throttled"`
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
	Refusals map[string]map[string]uint64 `json:"refusals,omitempty"`
	// WouldRefusals is the same breakdown for the listeners in shadow
	// mode: what they would have refused and did not. The detail is in
	// the shadow ledger (xproxyctl policy report).
	WouldRefusals map[string]map[string]uint64 `json:"would_refusals,omitempty"`
	// Shadow is the ledger's own totals.
	Shadow            shadow.Status `json:"shadow"`
	RefusalsUntracked uint64        `json:"refusals_untracked"`
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
		WouldRefusals:          s.WouldRefusalCounts(),
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
		ModbusValueUnknown:     s.ModbusValueUnknown.Load(),
		ModbusValuePoints:      s.ModbusValuePoints.Load(),
		ModbusRejected:         s.ModbusRejected.Load(),
		ModbusRateLimited:      s.ModbusRateLimited.Load(),
		ModbusQueueFull:        s.ModbusQueueFull.Load(),
		ModbusUpstreamFailed:   s.ModbusUpstreamFailed.Load(),
		ModbusTraced:           s.ModbusTraced.Load(),
		ModbusLearned:          s.ModbusLearned.Load(),
		ModbusDeceived:         s.ModbusDeceived.Load(),
		ModbusTripwire:         s.ModbusTripwire.Load(),
		IEC104Sessions:         s.IEC104Sessions.Load(),
		IEC104SessionsOpen:     s.IEC104SessionsOpen.Load(),
		IEC104Frames:           s.IEC104Frames.Load(),
		IEC104Deceived:         s.IEC104Deceived.Load(),
		IEC104Tripwire:         s.IEC104Tripwire.Load(),
		S7Deceived:             s.S7Deceived.Load(),
		S7Tripwire:             s.S7Tripwire.Load(),
		SNMPDeceived:           s.SNMPDeceived.Load(),
		SNMPTripwire:           s.SNMPTripwire.Load(),
		IEC104Commands:         s.IEC104Commands.Load(),
		IEC104SystemCmds:       s.IEC104SystemCmds.Load(),
		IEC104Denied:           s.IEC104Denied.Load(),
		IEC104WouldDeny:        s.IEC104WouldDeny.Load(),
		IEC104Malformed:        s.IEC104Malformed.Load(),
		IEC104Rejected:         s.IEC104Rejected.Load(),
		IEC104RateLimited:      s.IEC104RateLimited.Load(),
		IEC104Selects:          s.IEC104Selects.Load(),
		IEC104Executes:         s.IEC104Executes.Load(),
		IEC104Unselected:       s.IEC104Unselected.Load(),
		IEC104SelectsHeld:      s.IEC104SelectsHeld.Load(),
		IEC104Setpoints:        s.IEC104Setpoints.Load(),
		IEC104SetpointPoints:   s.IEC104SetpointPoints.Load(),
		IEC104SetpointUnknown:  s.IEC104SetpointUnknown.Load(),
		IEC104SeqGaps:          s.IEC104SeqGaps.Load(),
		IEC104WindowFull:       s.IEC104WindowFull.Load(),
		IEC104UpstreamFail:     s.IEC104UpstreamFail.Load(),
		SNMPMessages:           s.SNMPMessages.Load(),
		SNMPSessions:           s.SNMPSessions.Load(),
		SNMPSessionsOpen:       s.SNMPSessionsOpen.Load(),
		SNMPReads:              s.SNMPReads.Load(),
		SNMPWrites:             s.SNMPWrites.Load(),
		SNMPTraps:              s.SNMPTraps.Load(),
		SNMPDenied:             s.SNMPDenied.Load(),
		SNMPWouldDeny:          s.SNMPWouldDeny.Load(),
		SNMPMalformed:          s.SNMPMalformed.Load(),
		SNMPRejected:           s.SNMPRejected.Load(),
		SNMPRateLimited:        s.SNMPRateLimited.Load(),
		SNMPAmplified:          s.SNMPAmplified.Load(),
		SNMPTruncated:          s.SNMPTruncated.Load(),
		SNMPUpgraded:           s.SNMPUpgraded.Load(),
		SNMPTimedOut:           s.SNMPTimedOut.Load(),
		SNMPUpstreamFail:       s.SNMPUpstreamFail.Load(),
		SNMPUnsolicited:        s.SNMPUnsolicited.Load(),
		SNMPPending:            s.SNMPPending.Load(),
		LDAPSessions:           s.LDAPSessions.Load(),
		LDAPSessionsOpen:       s.LDAPSessionsOpen.Load(),
		LDAPRequests:           s.LDAPRequests.Load(),
		LDAPBinds:              s.LDAPBinds.Load(),
		LDAPBindFailures:       s.LDAPBindFailures.Load(),
		LDAPSearches:           s.LDAPSearches.Load(),
		LDAPWrites:             s.LDAPWrites.Load(),
		LDAPEntries:            s.LDAPEntries.Load(),
		LDAPStripped:           s.LDAPStripped.Load(),
		LDAPTruncated:          s.LDAPTruncated.Load(),
		LDAPStartTLS:           s.LDAPStartTLS.Load(),
		LDAPDenied:             s.LDAPDenied.Load(),
		LDAPWouldDeny:          s.LDAPWouldDeny.Load(),
		LDAPMalformed:          s.LDAPMalformed.Load(),
		LDAPRejected:           s.LDAPRejected.Load(),
		LDAPRateLimited:        s.LDAPRateLimited.Load(),
		LDAPUpstreamFail:       s.LDAPUpstreamFail.Load(),
		LDAPOutstanding:        s.LDAPOutstanding.Load(),
		TFTPRequests:           s.TFTPRequests.Load(),
		TFTPTransfers:          s.TFTPTransfers.Load(),
		TFTPTransfersOpen:      s.TFTPTransfersOpen.Load(),
		TFTPReads:              s.TFTPReads.Load(),
		TFTPWrites:             s.TFTPWrites.Load(),
		TFTPBytesIn:            s.TFTPBytesIn.Load(),
		TFTPBytesOut:           s.TFTPBytesOut.Load(),
		TFTPDenied:             s.TFTPDenied.Load(),
		TFTPWouldDeny:          s.TFTPWouldDeny.Load(),
		TFTPPathRefused:        s.TFTPPathRefused.Load(),
		TFTPLowered:            s.TFTPLowered.Load(),
		TFTPOversize:           s.TFTPOversize.Load(),
		TFTPMalformed:          s.TFTPMalformed.Load(),
		TFTPRejected:           s.TFTPRejected.Load(),
		TFTPRateLimited:        s.TFTPRateLimited.Load(),
		TFTPTimedOut:           s.TFTPTimedOut.Load(),
		TFTPUpstreamFail:       s.TFTPUpstreamFail.Load(),
		TFTPUnsolicited:        s.TFTPUnsolicited.Load(),
		DHCPMessages:           s.DHCPMessages.Load(),
		DHCPDiscovers:          s.DHCPDiscovers.Load(),
		DHCPRequests:           s.DHCPRequests.Load(),
		DHCPReplies:            s.DHCPReplies.Load(),
		DHCPLeases:             s.DHCPLeases.Load(),
		DHCPReleases:           s.DHCPReleases.Load(),
		DHCPDenied:             s.DHCPDenied.Load(),
		DHCPWouldDeny:          s.DHCPWouldDeny.Load(),
		DHCPRogue:              s.DHCPRogue.Load(),
		DHCPStripped:           s.DHCPStripped.Load(),
		DHCPMalformed:          s.DHCPMalformed.Load(),
		DHCPRejected:           s.DHCPRejected.Load(),
		DHCPRateLimited:        s.DHCPRateLimited.Load(),
		DHCPTimedOut:           s.DHCPTimedOut.Load(),
		DHCPUpstreamFail:       s.DHCPUpstreamFail.Load(),
		DHCPUnsolicited:        s.DHCPUnsolicited.Load(),
		DHCPPending:            s.DHCPPending.Load(),
		DHCPClients:            s.DHCPClients.Load(),
		AssetObservations:      s.AssetObservations.Load(),
		AssetFindings:          s.AssetFindings.Load(),
		AssetUnexpected:        s.AssetUnexpected.Load(),
		AssetSaveFailures:      s.AssetSaveFailures.Load(),
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
		NTSKEHandshakes:        s.NTSKEHandshakes.Load(),
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
		SSHHardwareAuths:       s.SSHHardwareAuths.Load(),
		SSHHardwareRefused:     s.SSHHardwareRefused.Load(),
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
		RDPDynamicChannelsSeen: s.RDPDynamicChannelsSeen.Load(),
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
		MFAPushSent:            s.MFAPushSent.Load(),
		MFAPushApproved:        s.MFAPushApproved.Load(),
		MFAPushDenied:          s.MFAPushDenied.Load(),
		MFAPushFailed:          s.MFAPushFailed.Load(),
		MFAPushThrottled:       s.MFAPushThrottled.Load(),
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

// AssetSummary is the device inventory in a status view: how many devices, how
// many the estate has not accounted for, and the count per role.
// AccessSummary is what the exposition and the status view say about
// just-in-time access: how many grants are in each state, and the acts and
// refusals counted since start.
type AccessSummary struct {
	// ByState counts the grants in each state (pending, active, expired and
	// the rest). Pending is the one to watch: a request nobody answers is an
	// operator who cannot work, and an approval system that is quietly
	// ignored is worse than none.
	ByState map[string]int `json:"by_state,omitempty"`
	// Requests, Approvals, Denials, Revocations and Uses are the ledger's
	// own counters, and Refusals the sessions turned away by reason.
	Requests    uint64            `json:"requests"`
	Approvals   uint64            `json:"approvals"`
	Denials     uint64            `json:"denials"`
	Revocations uint64            `json:"revocations"`
	Uses        uint64            `json:"uses"`
	Refusals    map[string]uint64 `json:"refusals,omitempty"`
}

// AuthzSummary is what the status view and the exposition say about the
// authorisation policy: how it is set up and what it has decided.
type AuthzSummary struct {
	// DefaultAllows says which way an unmatched subject goes. It is here
	// because a hit count means the opposite thing depending on it, and
	// Shadow says whether any of it is being enforced at all.
	DefaultAllows bool `json:"default_allows"`
	Shadow        bool `json:"shadow"`
	// Allowed, Denied and NoRule are the decisions. NoRule is the gap
	// measure: high and rising means the rules cover less of the estate than
	// whoever wrote them believes.
	Allowed uint64 `json:"allowed"`
	Denied  uint64 `json:"denied"`
	NoRule  uint64 `json:"no_rule"`
	// Rules is every rule in order with its hit count, so a rule that has
	// never decided anything is visible as such -- which is either a rule
	// about traffic that does not happen or a rule shadowed by one above it.
	Rules []authorization.Status `json:"rules,omitempty"`
}

// CustodySummary is what the status view and the exposition say about key
// custody: how many keys are held where, whether a vault is configured and
// answering, and what the FIPS check found.
type CustodySummary struct {
	// KeysOnDisk, KeysReferenced and KeysExternal count the configured
	// certificates by custody arrangement. The interesting number is
	// KeysOnDisk: it is how many private keys an attacker who can read this
	// machine's file system gets.
	KeysOnDisk     int `json:"keys_on_disk"`
	KeysReferenced int `json:"keys_referenced"`
	KeysExternal   int `json:"keys_external"`
	// Vault is true when a vault is configured, and Stale lists the
	// references whose last refresh failed and which are therefore being
	// served from a value that may be out of date. A non-empty Stale is the
	// one thing here worth an alert: rotation has stopped without the proxy
	// stopping.
	Vault bool     `json:"vault"`
	Stale []string `json:"stale,omitempty"`
	// Rotations is how many certificates have had their key replaced from a
	// reference since start, and RefreshFailures how many refreshes could
	// not resolve. The pair is what tells "rotation is working" from
	// "rotation has not been tried": zero of both means neither.
	Rotations       uint64 `json:"rotations"`
	RefreshFailures uint64 `json:"refresh_failures"`
	// FIPSEnabled is whether the FIPS 140-3 module is active in this
	// process, FIPSRequired whether the configuration insists on it, and
	// FIPSRefused the configured algorithms the active module will not do.
	FIPSEnabled  bool     `json:"fips_enabled"`
	FIPSRequired bool     `json:"fips_required"`
	FIPSRefused  []string `json:"fips_refused,omitempty"`
}

type AssetSummary struct {
	Assets   int            `json:"assets"`
	New      int            `json:"new"`
	Unknown  int            `json:"unknown"`
	Dropped  uint64         `json:"dropped"`
	Expired  uint64         `json:"expired"`
	Refused  uint64         `json:"refused"`
	Findings uint64         `json:"findings"`
	Frozen   bool           `json:"baseline_frozen"`
	Baseline int            `json:"baseline_size"`
	ByRole   map[string]int `json:"by_role,omitempty"`
}
