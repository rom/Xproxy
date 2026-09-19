// Package config defines the xproxy configuration model, its loader and its
// validation rules.
//
// Design rules for this package (see docs/AMR.md, decision AMR-007):
//
//   - The configuration is a single YAML document. Unknown fields are a hard
//     error so that typos can never silently disable a security control.
//   - Every value has a safe default. Omitting a section must never make the
//     proxy more permissive than the documented default.
//   - Validation is exhaustive and returns all problems at once, so operators
//     do not iterate one error at a time.
//   - Secrets are never inline. Certificates and keys are referenced by path.
//   - The loaded Config is immutable after Load returns. Reload builds a new
//     Config and the proxy swaps it atomically.
package config

import (
	"strings"
	"time"
)

// CurrentVersion is the configuration schema version this build understands.
const CurrentVersion = 1

// Config is the root of the configuration document.
type Config struct {
	// Version is the schema version. Must equal CurrentVersion.
	Version int `yaml:"version"`
	// Includes are absolute glob patterns of fragment files whose
	// upstreams, routes, rate_limits and filters are appended to this
	// document, in lexical order of path. Fragments may contain nothing
	// else; names must not repeat. Read at every load and reload.
	Includes []string `yaml:"includes"`
	// IncludedFiles lists the fragments the last load read.
	IncludedFiles []string `yaml:"-"`

	Server     Server     `yaml:"server"`
	Management Management `yaml:"management"`
	Logging    Logging    `yaml:"logging"`

	// TrustedProxies lists CIDRs whose X-Forwarded-For / Forwarded headers are
	// trusted for client IP derivation. Empty means never trust such headers.
	TrustedProxies []string `yaml:"trusted_proxies"`

	RateLimits []RateLimit `yaml:"rate_limits"`
	Upstreams  []Upstream  `yaml:"upstreams"`
	Routes     []Route     `yaml:"routes"`

	// Bans enables the ban list when present.
	Bans *Bans `yaml:"bans"`
	// WAF enables the web application firewall when present.
	WAF *WAF `yaml:"waf"`
	// Cluster enables sharing of rate limit consumption and bans between
	// proxies when present.
	Cluster *Cluster `yaml:"cluster"`
	// VirtualPatches block known vulnerabilities by request shape.
	VirtualPatches []VirtualPatch `yaml:"virtual_patches"`
	// Fleet makes this node fetch its configuration bundle from a fleet
	// controller and report its status there (xproxy-fleet).
	Fleet *Fleet `yaml:"fleet"`
	// APIInventory records the endpoints the proxy serves and reports
	// shadow, zombie and superseded APIs.
	APIInventory *APIInventory `yaml:"api_inventory"`
	// Shedding enables adaptive load shedding by priority class when
	// present.
	Shedding *Shedding `yaml:"shedding"`
	// Challenge configures the browser challenge used by routes with a
	// challenge block.
	Challenge *Challenge `yaml:"challenge"`
	// JWT configures token providers referenced by routes.
	JWT *JWT `yaml:"jwt"`
	// Metrics tunes exposition and the time series buffer.
	Metrics Metrics `yaml:"metrics"`
	// ICAP configures external scanning services referenced by routes.
	ICAP *ICAP `yaml:"icap"`
	// Filters are middleware instances of registered kinds (see
	// docs/EXTENDING.md) that routes attach by name.
	Filters []FilterConfig `yaml:"filters"`
	// GeoIP names the country database used by routes[].geo and by rate
	// limits keyed on country.
	GeoIP *GeoIP `yaml:"geoip"`
	// Ingress turns Kubernetes Ingress resources into routes, upstreams
	// and certificates (ingress controller mode).
	Ingress *Ingress `yaml:"ingress"`
	// Sandbox configures the in-process hardening applied once the
	// listeners are bound: Landlock file system rules, a seccomp system
	// call filter, capability dropping and debugger denial on Linux;
	// debugger denial and core dump suppression on macOS. On by default.
	Sandbox Sandbox `yaml:"sandbox"`
	// Cache sizes the in-memory response cache used by routes[].cache.
	Cache *Cache `yaml:"cache"`
	// Compression enables gzip of eligible responses on every route
	// (routes[].compress overrides per route).
	Compression *Compression `yaml:"compression"`
	// Tracing gives requests a W3C trace context and exports spans.
	Tracing *Tracing `yaml:"tracing"`
	// ACME configures automatic certificates for listeners with tls.acme.
	ACME *ACME `yaml:"acme"`
}

// Metrics configures Prometheus exposition and sampled series (AMR-026).
// The management socket always serves /metrics; Listen adds a TCP
// endpoint for scrapers.
type Metrics struct {
	// Listen is an optional host:port serving only /metrics. Binding all
	// interfaces requires TLS with a client CA.
	Listen string `yaml:"listen"`
	// AllowCIDRs restricts scrapers by source address. Empty allows any
	// address that reaches the listener.
	AllowCIDRs []string `yaml:"allow_cidrs"`
	// TLS makes the listener HTTPS; ClientCAFile requires client
	// certificates.
	TLS *MetricsTLS `yaml:"tls"`
	// PerRoute exposes request counters per route (one series per route
	// and status class). Default true.
	PerRoute *bool `yaml:"per_route"`
	// EndpointSeries exposes five series per upstream endpoint. Default
	// true; turn off above a few thousand endpoints (about 1 KiB per
	// endpoint per scrape).
	EndpointSeries *bool `yaml:"endpoint_series"`
	// SampleInterval and Retention size the time series buffer. Defaults
	// 10s and 1h.
	SampleInterval Duration `yaml:"sample_interval"`
	Retention      Duration `yaml:"retention"`
	// OTLP pushes the same metrics to an OpenTelemetry collector.
	OTLP *OTLP `yaml:"otlp"`
}

// MetricsTLS is the metrics listener certificate and optional client CA.
type MetricsTLS struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
}

// PerRouteEnabled reports whether per-route counters are exposed.
func (m *Metrics) PerRouteEnabled() bool { return m.PerRoute == nil || *m.PerRoute }

// Server holds listener and global limit settings for the data plane.
type Server struct {
	Listeners []Listener `yaml:"listeners"`
	Limits    Limits     `yaml:"limits"`
	// Normalization checks and canonicalises the request target before
	// routing and analysis.
	Normalization Normalization `yaml:"normalization"`
	// ServerHeader is the value sent in the Server response header. Empty
	// removes the header entirely (the default) to avoid fingerprinting.
	ServerHeader string `yaml:"server_header"`
	// ErrorPages replaces the proxy's plain status bodies for every route
	// (routes may override).
	ErrorPages *ErrorPages `yaml:"error_pages"`
	// SessionTickets derives the TLS session ticket keys of every TLS
	// listener from a master secret file and the time, so nodes sharing
	// the file resume each other's sessions and keys rotate on schedule
	// without a restart. Without the section each process uses random
	// keys that rotate every 24 hours and are never shared.
	SessionTickets *SessionTickets `yaml:"session_tickets"`
	// ShutdownTimeout bounds graceful drain on stop or reload.
	ShutdownTimeout Duration `yaml:"shutdown_timeout"`
}

// EndpointSeriesEnabled reports whether per-endpoint series are exposed.
func (m *Metrics) EndpointSeriesEnabled() bool {
	return m.EndpointSeries == nil || *m.EndpointSeries
}

// Protocol identifies an application protocol a listener accepts.
type Protocol string

const (
	ProtocolH1 Protocol = "h1"
	ProtocolH2 Protocol = "h2"
	ProtocolH3 Protocol = "h3"
)

// Listener describes a single accepting socket.
type Listener struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	// Protocols accepted. Defaults to [h1, h2] with TLS and [h1] without.
	Protocols []Protocol `yaml:"protocols"`
	TLS       *TLS       `yaml:"tls"`
	// ProxyProtocol enables PROXY protocol v1/v2 parsing on accepted
	// connections. Only enable behind a trusted L4 balancer.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// RedirectToHTTPS makes a plaintext listener answer every request with a
	// 308 redirect to https. Useful for the :80 listener.
	RedirectToHTTPS bool `yaml:"redirect_to_https"`
	// H3 tunes HTTP/3 when the protocols include h3.
	H3 *H3 `yaml:"h3"`
	// H2C accepts HTTP/2 without TLS (prior knowledge and Upgrade) on a
	// plaintext http listener, for gRPC clients inside a trusted network.
	// Default false.
	H2C bool `yaml:"h2c"`
	// Kind is http (default), tcp (an L4 listener that forwards
	// connections by TLS server name without terminating TLS), forward
	// (an explicit HTTP proxy for clients: CONNECT tunnels and absolute
	// URI requests to destinations the policy allows) or dns (a DNS
	// proxy).
	Kind string `yaml:"kind"`
	// TCP configures a kind: tcp listener.
	TCP *TCPListener `yaml:"tcp"`
	// Forward configures a kind: forward listener.
	Forward *ForwardListener `yaml:"forward"`
	// DNS configures a kind: dns listener.
	DNS *DNSListener `yaml:"dns"`
}

// DNSListener is a forwarding DNS proxy on the listener address over UDP
// and TCP: a bounded cache, a block policy and forwarding to upstream
// resolvers with fresh transaction ids and source ports. The policy,
// upstreams and cache bounds reload; the address needs a restart.
type DNSListener struct {
	// Upstreams are resolvers tried in turn: host:port (UDP with TCP
	// fallback), tls://host:port (DNS over TLS) or https://host/path
	// (DNS over HTTPS). Required.
	Upstreams []string `yaml:"upstreams"`
	// UpstreamCAFile pins the CA of tls:// and https:// upstreams.
	// Default: system pool.
	UpstreamCAFile string `yaml:"upstream_ca_file"`
	// Timeout bounds one upstream attempt. Default 2s.
	Timeout Duration `yaml:"timeout"`
	// AllowClients restricts clients to these CIDRs (others get
	// REFUSED). Empty allows any client.
	AllowClients []string `yaml:"allow_clients"`
	// Block lists names: a bare name blocks it and its subdomains,
	// *.suffix only subdomains, =name only that name.
	Block []string `yaml:"block"`
	// BlockFile adds names from a file (one per line, hosts file lines
	// accepted), read at load and reload.
	BlockFile string `yaml:"block_file"`
	// BlockAction is nxdomain (default), refuse or sinkhole.
	BlockAction string `yaml:"block_action"`
	// SinkholeIPv4 and SinkholeIPv6 answer A and AAAA for blocked names
	// with block_action sinkhole. Default 0.0.0.0 and ::.
	SinkholeIPv4 string `yaml:"sinkhole_ipv4"`
	SinkholeIPv6 string `yaml:"sinkhole_ipv6"`
	// Cache bounds the response cache.
	Cache *DNSCache `yaml:"cache"`
	// RateLimit bounds queries per client; over it queries are dropped.
	RateLimit *DNSRateLimit `yaml:"rate_limit"`
	// MaxInFlight bounds queries being handled. Default 1024.
	MaxInFlight int `yaml:"max_in_flight"`
	// LogQueries writes one dns line per query to the access log.
	// Default false (query logs are personal data).
	LogQueries bool `yaml:"log_queries"`
	// DoHPath is the DNS over HTTPS path served on an encrypted dns
	// listener (one with tls). Default /dns-query.
	DoHPath string `yaml:"doh_path"`
	// DNSSEC validates upstream answers against a trust anchor.
	DNSSEC *DNSSEC `yaml:"dnssec"`
}

// DNSSEC configures validation on a dns listener: answers are fetched
// with the DO bit, signatures and denial proofs are checked up to a
// trust anchor, secure answers carry AD, bogus answers become SERVFAIL
// (unless the client set CD), insecure answers pass without AD.
type DNSSEC struct {
	// Enabled defaults to true when the section is present.
	Enabled *bool `yaml:"enabled"`
	// TrustAnchors are DS records ("zone keytag algorithm digesttype
	// digest"); the IANA root keys are built in.
	TrustAnchors []string `yaml:"trust_anchors"`
	// TrustAnchorsFile adds DS lines from a file (comments with #).
	TrustAnchorsFile string `yaml:"trust_anchors_file"`
	// MaxLookups bounds DNSKEY and DS queries per answer. Default 48.
	MaxLookups int `yaml:"max_lookups"`
}

// IsEnabled reports whether validation is on.
func (d *DNSSEC) IsEnabled() bool { return d != nil && (d.Enabled == nil || *d.Enabled) }

// DNSCache bounds the cache of a dns listener.
type DNSCache struct {
	// MaxEntries. Default 10000.
	MaxEntries int `yaml:"max_entries"`
	// MinTTL and MaxTTL clamp what upstream answers say. Default 5s and
	// 1h.
	MinTTL Duration `yaml:"min_ttl"`
	MaxTTL Duration `yaml:"max_ttl"`
	// NegativeTTL caches NXDOMAIN and empty answers. Default 60s; 0
	// disables.
	NegativeTTL Duration `yaml:"negative_ttl"`
}

// DNSRateLimit is a per client token bucket.
type DNSRateLimit struct {
	QPS   float64 `yaml:"qps"`
	Burst int     `yaml:"burst"`
}

// Ingress is Kubernetes ingress controller mode: the proxy reads
// Ingress, Service, EndpointSlice and TLS Secret resources of one
// ingress class from the API server with the pod's service account,
// appends the resulting routes, upstreams and certificates to this
// configuration and reloads when they change. Routes and upstreams in
// this file are kept and take precedence by name.
type Ingress struct {
	Enabled bool `yaml:"enabled"`
	// APIServer URL. Default https://kubernetes.default.svc.
	APIServer string `yaml:"api_server"`
	// TokenFile is the bearer token (the service account token). Default
	// /var/run/secrets/kubernetes.io/serviceaccount/token.
	TokenFile string `yaml:"token_file"`
	// CAFile verifies the API server. Default
	// /var/run/secrets/kubernetes.io/serviceaccount/ca.crt.
	CAFile string `yaml:"ca_file"`
	// AllowHTTP permits a plain http api_server (tests, kubectl proxy).
	AllowHTTP bool `yaml:"allow_http"`
	// Class is the ingressClassName served. Default xproxy.
	Class string `yaml:"class"`
	// Namespaces restricts the watch. Empty watches every namespace.
	Namespaces []string `yaml:"namespaces"`
	// Listener names the TLS listener that receives certificates from
	// Ingress TLS secrets. Empty ignores TLS secrets.
	Listener string `yaml:"listener"`
	// CertDir receives the certificate files. Default
	// /var/lib/xproxy/ingress.
	CertDir string `yaml:"cert_dir"`
	// Resync is the polling interval. Default 30s. With watches on it
	// is the fallback; with them off it is the propagation delay.
	Resync Duration `yaml:"resync"`
	// Timeout bounds one API request. Default 10s.
	Timeout Duration `yaml:"timeout"`
	// Watch opens watch streams on the resources so that a change syncs
	// within debounce instead of resync. Default true.
	Watch *bool `yaml:"watch"`
	// Debounce collects a burst of watch events into one sync. Default
	// 500ms.
	Debounce Duration `yaml:"debounce"`
}

// Watches reports whether watch streams are used.
func (i *Ingress) Watches() bool { return i.Watch == nil || *i.Watch }

// OTLP is the OpenTelemetry push exporter: every interval the metric
// families are sent as OTLP/HTTP with JSON encoding to a collector
// (counters as cumulative monotonic sums, gauges, histograms as
// cumulative explicit bucket histograms).
type OTLP struct {
	// Endpoint is the collector's metrics URL, for example
	// https://otel.example.com:4318/v1/metrics.
	Endpoint string `yaml:"endpoint"`
	// AllowHTTP permits a plain http endpoint.
	AllowHTTP bool `yaml:"allow_http"`
	// Interval between pushes. Default 30s; 1s to 1h.
	Interval Duration `yaml:"interval"`
	// Timeout of one push. Default 10s.
	Timeout Duration `yaml:"timeout"`
	// Headers added to every request (for example Authorization).
	Headers map[string]string `yaml:"headers"`
	// CAFile pins the collector's CA. Default: system pool.
	CAFile string `yaml:"ca_file"`
	// ServiceName is the service.name resource attribute. Default xproxy.
	ServiceName string `yaml:"service_name"`
	// Attributes are extra resource attributes.
	Attributes map[string]string `yaml:"attributes"`
	// Compress gzips the request body. Default true.
	Compress *bool `yaml:"compress"`
}

// ForwardListener is an explicit forward proxy: clients send CONNECT
// host:port for tunnels (TLS stays end to end) or absolute http:// URIs
// for plain requests. Destinations are policy checked by name, resolved
// address and port; private and loopback addresses are refused unless
// allow_private is set, and the checked address is the one dialled.
type ForwardListener struct {
	// Ports destinations may be reached on (CONNECT and plain). Default
	// [80, 443].
	Ports []int `yaml:"ports"`
	// Allow restricts destinations to these names (exact or *.suffix),
	// addresses or CIDRs. Empty allows any destination not denied.
	Allow []string `yaml:"allow"`
	// Deny refuses destinations matching these names, addresses or
	// CIDRs. Deny wins over allow and is checked against the resolved
	// addresses too.
	Deny []string `yaml:"deny"`
	// AllowPrivate permits loopback, link local, private and unique
	// local destination addresses. Default false.
	AllowPrivate bool `yaml:"allow_private"`
	// Auth requires Proxy-Authorization Basic credentials.
	Auth *ForwardAuth `yaml:"auth"`
	// ConnectTimeout bounds the dial to the destination. Default 10s.
	ConnectTimeout Duration `yaml:"connect_timeout"`
	// IdleTimeout closes a tunnel with no bytes in either direction.
	// Default 10m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// MaxTunnels bounds open CONNECT tunnels on this listener. Default
	// 10000.
	MaxTunnels int `yaml:"max_tunnels"`
	// MaxResponseBytes bounds the body of a plain (non CONNECT) response
	// relayed to the client. Default 64 MiB; 0 disables.
	MaxResponseBytes int64 `yaml:"max_response_bytes"`
}

// ForwardAuth is the credential source of a forward listener.
type ForwardAuth struct {
	// UsersFile holds name:hash lines from xproxyctl htpasswd. Re-read on
	// reload.
	UsersFile string `yaml:"users_file"`
	// Realm is sent in Proxy-Authenticate. Default "proxy".
	Realm string `yaml:"realm"`
}

// TCPListener routes raw connections to upstream pools. TLS connections
// are routed by the server name of the ClientHello (peeked, never
// terminated); other connections and unmatched names go to the default
// upstream when one is set and are closed otherwise.
type TCPListener struct {
	Routes []TCPRoute `yaml:"routes"`
	// Default is the upstream for connections without a matching SNI
	// (including non-TLS ones).
	Default string `yaml:"default"`
	// IdleTimeout closes a connection with no bytes in either direction.
	// Default 10m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// ProxyProtocol sends a PROXY protocol v2 header to the upstream with
	// the client address.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// MaxConnections bounds open connections on this listener (in
	// addition to the global limits). Default 10000.
	MaxConnections int `yaml:"max_connections"`
	// QUIC also relays QUIC (UDP on the same address): the ClientHello
	// of each flow is read from the Initial packet and routed by server
	// name to the same upstreams. Default false.
	QUIC bool `yaml:"quic"`
	// QUICIdleTimeout ends a QUIC flow with no datagrams either way.
	// Default 30s.
	QUICIdleTimeout Duration `yaml:"quic_idle_timeout"`
}

// TCPRoute maps server names (exact or *.suffix) to an upstream.
type TCPRoute struct {
	SNI      []string `yaml:"sni"`
	Upstream string   `yaml:"upstream"`
}

// H3 configures the QUIC listener of a TLS listener (AMR-024).
type H3 struct {
	// MaxStreams bounds concurrent request streams per connection. Default
	// 100.
	MaxStreams int `yaml:"max_streams"`
	// ValidateAddresses is always (every new client address must complete a
	// Retry round trip before any state is allocated) or under_load (only
	// when open connections exceed a quarter of max_connections). Default
	// always.
	ValidateAddresses string `yaml:"validate_addresses"`
	// AltSvcMaxAge is the ma value advertised in Alt-Svc. Default 24h.
	AltSvcMaxAge Duration `yaml:"alt_svc_max_age"`
	// WebTransport accepts WebTransport sessions (extended CONNECT with
	// HTTP/3 datagrams) on this endpoint; routes with webtransport relay
	// them. Default false.
	WebTransport bool `yaml:"webtransport"`
}

// TLS configures server side TLS for a listener.
type TLS struct {
	Certificates []Certificate `yaml:"certificates"`
	// MinVersion is "1.2" or "1.3". Default "1.2".
	MinVersion string `yaml:"min_version"`
	// ClientAuth is one of none, request, require. Default none.
	ClientAuth string `yaml:"client_auth"`
	// ClientCAFile is a PEM bundle used to verify client certificates.
	ClientCAFile string `yaml:"client_ca_file"`
	// CipherSuites optionally restricts TLS 1.2 suites (TLS 1.3 suites are
	// not configurable in Go). Names as in crypto/tls, e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
	CipherSuites []string `yaml:"cipher_suites"`
	// ACME lists host groups that get an automatically issued certificate
	// each (one certificate per group, hosts as SANs). Requires the
	// top-level acme section.
	ACME []ACMEGroup `yaml:"acme"`
	// OCSPStapling fetches OCSP responses for the served certificates
	// and staples them into handshakes.
	OCSPStapling *OCSPStapling `yaml:"ocsp_stapling"`
	// CT checks the signed certificate timestamps embedded in the file
	// certificates at load.
	CT *CT `yaml:"ct"`
}

// OCSPStapling configures the background OCSP fetcher of a listener.
type OCSPStapling struct {
	Enabled *bool `yaml:"enabled"`
	// Timeout of one responder request. Default 5s.
	Timeout Duration `yaml:"timeout"`
	// Refresh is the longest interval between fetches; responses are
	// also refreshed at half their validity. Default 1h.
	Refresh Duration `yaml:"refresh"`
}

// IsEnabled reports whether stapling is on.
func (o *OCSPStapling) IsEnabled() bool { return o != nil && (o.Enabled == nil || *o.Enabled) }

// CT is the Certificate Transparency policy for file certificates.
type CT struct {
	// Require is the number of embedded SCTs a certificate must carry
	// (verified ones when LogListFile is set). 0 only reports.
	Require int `yaml:"require"`
	// LogListFile is a log list in Google's JSON format with the logs'
	// keys; with it SCT signatures are verified.
	LogListFile string `yaml:"log_list_file"`
	// Enforce fails the load or reload of a certificate below Require
	// instead of logging it.
	Enforce bool `yaml:"enforce"`
}

// ACMEGroup is one automatically managed certificate.
type ACMEGroup struct {
	Hosts []string `yaml:"hosts"`
}

// Certificate references a PEM certificate chain and private key on disk.
type Certificate struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Normalization decides what the proxy does with encoding tricks in the
// request target before anything else looks at it. Routing already
// decodes and cleans the path; these checks refuse the forms that make
// two components disagree about what a request means, and optionally
// fold Unicode spellings for routing.
type Normalization struct {
	// RejectControlChars refuses a decoded path or query containing a
	// control character (below 0x20, or 0x7f), NUL included. Default true.
	RejectControlChars *bool `yaml:"reject_control_chars"`
	// RejectInvalidUTF8 refuses a decoded path that is not valid UTF-8
	// (overlong and truncated sequences). Default true.
	RejectInvalidUTF8 *bool `yaml:"reject_invalid_utf8"`
	// RejectDoubleEncoding refuses a path that still contains a percent
	// escape after one decoding (%252e%252e). Default false.
	RejectDoubleEncoding bool `yaml:"reject_double_encoding"`
	// RejectEncodedSlashes refuses %2F and %5C in the raw path: the
	// routing decoder turns them into separators that the upstream may
	// treat as data. Default false.
	RejectEncodedSlashes bool `yaml:"reject_encoded_slashes"`
	// RejectBackslashes refuses a backslash anywhere in the decoded path,
	// which some servers read as a separator. Default false.
	RejectBackslashes bool `yaml:"reject_backslashes"`
	// RejectAmbiguousFraming refuses HTTP/1 requests whose framing is
	// ambiguous: both Transfer-Encoding and Content-Length, several
	// differing Content-Length values, or a transfer coding other than
	// chunked. The Go parser already refuses most of these; the check
	// closes the rest and counts them. Default true.
	RejectAmbiguousFraming *bool `yaml:"reject_ambiguous_framing"`
	// Unicode is off, nfc or nfkc: the decoded path is normalised to that
	// form for routing (the upstream receives the original), so composed
	// and decomposed spellings, and with nfkc compatibility forms such as
	// fullwidth letters, match the same route. Default off.
	Unicode string `yaml:"unicode"`
}

// ControlChars reports the setting with its default.
func (n *Normalization) ControlChars() bool {
	return n.RejectControlChars == nil || *n.RejectControlChars
}

// InvalidUTF8 reports the setting with its default.
func (n *Normalization) InvalidUTF8() bool { return n.RejectInvalidUTF8 == nil || *n.RejectInvalidUTF8 }

// AmbiguousFraming reports the setting with its default.
func (n *Normalization) AmbiguousFraming() bool {
	return n.RejectAmbiguousFraming == nil || *n.RejectAmbiguousFraming
}

// Limits are the global resource protections of the data plane. Every limit
// has a conservative default and can only be raised deliberately.
type Limits struct {
	MaxHeaderBytes        int      `yaml:"max_header_bytes"`
	MaxBodyBytes          int64    `yaml:"max_body_bytes"`
	MaxURILength          int      `yaml:"max_uri_length"`
	ReadHeaderTimeout     Duration `yaml:"read_header_timeout"`
	ReadTimeout           Duration `yaml:"read_timeout"`
	WriteTimeout          Duration `yaml:"write_timeout"`
	IdleTimeout           Duration `yaml:"idle_timeout"`
	MaxConnections        int      `yaml:"max_connections"`
	MaxConnectionsPerIP   int      `yaml:"max_connections_per_ip"`
	MaxConcurrentRequests int      `yaml:"max_concurrent_requests"`
	// MaxTarpits bounds requests held in a tarpit at once. A tarpitted
	// request releases its concurrency slot first; above this bound the
	// request is rejected at once instead of held. Default 1024.
	MaxTarpits int `yaml:"max_tarpits"`
}

// Management configures the control plane listener used by xproxyctl.
type Management struct {
	// Socket is the path of the Unix domain socket. Empty disables management.
	Socket string `yaml:"socket"`
	// SocketMode is the octal permission mode of the socket, default 0660.
	SocketMode string `yaml:"socket_mode"`
	// HistoryDir keeps every applied configuration as a file for
	// xproxyctl history, diff and rollback. Empty disables history.
	HistoryDir string `yaml:"history_dir"`
	// HistoryKeep is how many entries are kept. Default 20.
	HistoryKeep int `yaml:"history_keep"`
}

// Logging configures the four log streams (AMR-014).
type Logging struct {
	Directory string    `yaml:"directory"`
	Access    LogStream `yaml:"access"`
	Error     LogStream `yaml:"error"`
	Security  LogStream `yaml:"security"`
	Audit     LogStream `yaml:"audit"`
	// Level is the minimum level for the error log: debug, info, warn, error.
	Level string `yaml:"level"`
	// Stdout mirrors all streams to standard output (useful under journald
	// and in containers).
	Stdout bool `yaml:"stdout"`
	// Journald configures the journald sink used by streams listing it.
	Journald *Journald `yaml:"journald"`
	// Syslog configures the syslog sink used by streams listing it.
	Syslog *Syslog `yaml:"syslog"`
	// Redaction removes or pseudonymises personal data before any sink.
	Redaction *Redaction `yaml:"redaction"`
	// OTLP configures the OpenTelemetry log sink used by streams listing
	// otlp in their sinks.
	OTLP *OTLPExport `yaml:"otlp"`
	// SIEM configures the HTTPS batch sink for security information and
	// event management systems, used by streams listing siem.
	SIEM *SIEM `yaml:"siem"`
}

// SIEM is an HTTP collector of a SIEM: Splunk HTTP Event Collector,
// Elastic or OpenSearch ingest, Microsoft Sentinel, or any endpoint that
// accepts newline delimited JSON, CEF or LEEF.
type SIEM struct {
	// Endpoint is the collector URL.
	Endpoint string `yaml:"endpoint"`
	// AllowHTTP permits a plain http endpoint.
	AllowHTTP bool `yaml:"allow_http"`
	// Format is json (newline delimited JSON lines), hec (the Splunk HTTP
	// Event Collector envelope), cef or leef. Default json.
	Format string `yaml:"format"`
	// Headers added to every request.
	Headers map[string]string `yaml:"headers"`
	// AuthFile holds the Authorization header value ("Splunk <token>",
	// "Bearer <token>", "ApiKey <key>"), kept out of the configuration.
	AuthFile string `yaml:"auth_file"`
	// Timeout of one push. Default 10s.
	Timeout Duration `yaml:"timeout"`
	// CAFile pins the collector's CA; CertFile and KeyFile present a
	// client certificate.
	CAFile   string `yaml:"ca_file"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Compress gzips the request body. Default true.
	Compress *bool `yaml:"compress"`
	// Batch is the largest number of records per push. Default 512.
	Batch int `yaml:"batch"`
	// Interval is the longest time a record waits before a push. Default 5s.
	Interval Duration `yaml:"interval"`
	// Queue bounds records waiting for a push. Default 8192.
	Queue int `yaml:"queue"`
	// Vendor and Product fill the CEF and LEEF header fields. Defaults
	// Sysctl and Xproxy.
	Vendor  string `yaml:"vendor"`
	Product string `yaml:"product"`
	// Hostname is the device host name reported (dvchost, identHostName,
	// the HEC host). Default the OS host name.
	Hostname string `yaml:"hostname"`
}

// Compresses reports the compress setting with its default.
func (s *SIEM) Compresses() bool { return s.Compress == nil || *s.Compress }

// OTLPExport is a collector endpoint for traces or logs.
type OTLPExport struct {
	// Endpoint is the collector URL (/v1/traces or /v1/logs).
	Endpoint string `yaml:"endpoint"`
	// AllowHTTP permits a plain http endpoint.
	AllowHTTP bool `yaml:"allow_http"`
	// Timeout of one push. Default 10s.
	Timeout Duration `yaml:"timeout"`
	// Headers added to every request.
	Headers map[string]string `yaml:"headers"`
	// CAFile pins the collector's CA. Default: system pool.
	CAFile string `yaml:"ca_file"`
	// ServiceName is the service.name resource attribute. Default xproxy.
	ServiceName string `yaml:"service_name"`
	// Attributes are extra resource attributes.
	Attributes map[string]string `yaml:"attributes"`
	// Compress gzips the request body. Default true.
	Compress *bool `yaml:"compress"`
	// Batch is the largest number of items per push. Default 512.
	Batch int `yaml:"batch"`
	// Interval is the longest time an item waits before a push. Default 5s.
	Interval Duration `yaml:"interval"`
	// Queue bounds items waiting for a push. Default 8192.
	Queue int `yaml:"queue"`
}

// Compresses reports the compress setting with its default.
func (o *OTLPExport) Compresses() bool { return o.Compress == nil || *o.Compress }

// Tracing configures W3C trace context handling and span export.
type Tracing struct {
	// Enabled defaults to true when the section is present.
	Enabled *bool `yaml:"enabled"`
	// SamplePercent is the share of new traces (no incoming traceparent)
	// that are recorded. Default 100.
	SamplePercent *float64 `yaml:"sample_percent"`
	// Propagate sends traceparent and tracestate to the upstream. Default
	// true.
	Propagate *bool `yaml:"propagate"`
	// TrustIncoming honours the sampled flag of an incoming traceparent.
	// Off (the default) the incoming trace id is continued for
	// correlation but the sampling decision stays local, so a client
	// cannot force every request into the exporter.
	TrustIncoming bool `yaml:"trust_incoming"`
	// OTLP exports spans; without it the context is only propagated and
	// logged.
	OTLP *OTLPExport `yaml:"otlp"`
}

// IsEnabled reports whether tracing is on.
func (t *Tracing) IsEnabled() bool { return t != nil && (t.Enabled == nil || *t.Enabled) }

// Sample returns the sampling share with its default.
func (t *Tracing) Sample() float64 {
	if t == nil || t.SamplePercent == nil {
		return 100
	}
	return *t.SamplePercent
}

// Propagates reports whether trace context is forwarded.
func (t *Tracing) Propagates() bool { return t != nil && (t.Propagate == nil || *t.Propagate) }

// LogStream configures one stream.
type LogStream struct {
	Enabled *bool  `yaml:"enabled"`
	File    string `yaml:"file"`
	// MaxSizeMB triggers rotation when the file exceeds this size. 0 disables
	// internal rotation (use logrotate or journald instead).
	MaxSizeMB int `yaml:"max_size_mb"`
	MaxFiles  int `yaml:"max_files"`
	// Sinks lists where the stream goes: file, journald, syslog. Default
	// [file].
	Sinks []string `yaml:"sinks"`
	// Format is json (default), or for the access stream common
	// (Common Log Format), combined (NCSA combined) or custom with
	// Template. The other streams are structured and stay JSON.
	Format string `yaml:"format"`
	// Template is the line for format custom: literal text with {field}
	// placeholders naming access log attributes plus time_clf, time_iso,
	// time_unix, request, user and bytes_out_clf; a missing field prints "-".
	Template string `yaml:"template"`
}

// Journald is the native journald sink.
type Journald struct {
	// Socket is the journald datagram socket. Default
	// /run/systemd/journal/socket.
	Socket string `yaml:"socket"`
	// Identifier is SYSLOG_IDENTIFIER. Default xproxy.
	Identifier string `yaml:"identifier"`
}

// Syslog is the syslog sink.
type Syslog struct {
	// Network is unix, udp, tcp or tcp+tls. Default unix.
	Network string `yaml:"network"`
	// Address is the socket path for unix (default /dev/log) or host:port.
	Address string `yaml:"address"`
	// Format is rfc5424 or rfc3164 with the JSON line as the message, or
	// cef or leef with the record rendered in that format behind an RFC
	// 5424 header (RFC 3164 for unix). Default rfc3164 for unix, rfc5424
	// otherwise.
	Format string `yaml:"format"`
	// Facility is kern, user, daemon, auth, authpriv, syslog, local0 to
	// local7. Default local0.
	Facility string `yaml:"facility"`
	// AppName is the APP-NAME or tag. Default xproxy.
	AppName string `yaml:"app_name"`
	// Hostname overrides the HOSTNAME field. Default the OS host name.
	Hostname string `yaml:"hostname"`
	// TLS settings for tcp+tls.
	CAFile     string `yaml:"ca_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ServerName string `yaml:"server_name"`
	// QueueSize bounds messages waiting for a slow or unreachable
	// collector; beyond it messages are dropped and counted. Default 8192.
	QueueSize int `yaml:"queue_size"`
}

// Redaction rules. Presence enables them; Enabled false switches them off
// without removing the configuration.
type Redaction struct {
	Enabled *bool `yaml:"enabled"`
	// Streams the rules apply to. Default [access, security, error]; the
	// audit stream keeps full detail unless listed.
	Streams []string `yaml:"streams"`
	// ClientIP is keep, truncate (IPv4 /24, IPv6 /48) or hash (keyed
	// HMAC-SHA256, stable per installation). Default truncate.
	ClientIP string `yaml:"client_ip"`
	// HashSecretFile holds the key for hash mode; created on first use.
	HashSecretFile string `yaml:"hash_secret_file"`
	// UserAgent is keep or drop. Default keep.
	UserAgent string `yaml:"user_agent"`
	// Referer is keep, origin (scheme and host only) or drop. Default origin.
	Referer string `yaml:"referer"`
	// Claims is keep, hash or drop and applies to jwt_* attributes and
	// client_cn. Default hash.
	Claims string `yaml:"claims"`
	// DropFields lists further attribute names removed from log lines.
	DropFields []string `yaml:"drop_fields"`
}

// IsEnabled reports whether redaction is switched on.
func (r *Redaction) IsEnabled() bool { return r != nil && (r.Enabled == nil || *r.Enabled) }

// RateLimit is a named rate limit policy referenced by routes: a token
// bucket (rate and burst) or a sliding window (limit per window).
type RateLimit struct {
	Name string `yaml:"name"`
	// Key selects the bucket identity: client_ip, client_net, route,
	// country, endpoint, ja4, header:<name>, cookie:<name> or
	// jwt:<claim>. Keys that a request may lack fall back to the client
	// address.
	Key string `yaml:"key"`
	// NetV4 and NetV6 are the prefix lengths for key client_net. Default
	// 24 and 48.
	NetV4 int `yaml:"net_v4"`
	NetV6 int `yaml:"net_v6"`
	// Algorithm is token_bucket (default; rate and burst) or
	// sliding_window (limit and window).
	Algorithm string `yaml:"algorithm"`
	// Rate is tokens per second (token_bucket).
	Rate float64 `yaml:"rate"`
	// Burst is the bucket capacity (token_bucket).
	Burst int `yaml:"burst"`
	// Limit is the number of requests allowed per Window (sliding_window).
	Limit int `yaml:"limit"`
	// Window is the sliding window length (sliding_window). Default 1s.
	Window Duration `yaml:"window"`
	// Distributed selects the cluster semantics: approximate (default;
	// each node refills at the rate minus its peers' reported
	// consumption) or exact (one node owns each key, chosen by
	// rendezvous hashing over the connected members, and decides for
	// the others; a node that cannot reach the owner within
	// cluster.exact_timeout decides locally). Needs the cluster section.
	Distributed string `yaml:"distributed"`
	// Action is reject (429) or tarpit. Default reject.
	Action string `yaml:"action"`
	// TarpitDelay is how long a tarpitted request is held before rejection.
	TarpitDelay Duration `yaml:"tarpit_delay"`
}

// Upstream is a named pool of endpoints.
type Upstream struct {
	Name string `yaml:"name"`
	// Balancer is round_robin, weighted, least_conn or hash.
	Balancer  string     `yaml:"balancer"`
	Endpoints []Endpoint `yaml:"endpoints"`
	// Discovery adds endpoints resolved from DNS (A/AAAA records of a
	// name, or SRV records) and re-resolves them periodically. Static
	// endpoints and discovered ones coexist; a pool needs at least one
	// of the two.
	Discovery *Discovery `yaml:"discovery"`
	// OriginSignature signs every forwarded request with a key shared
	// with the origin, so the origin can refuse traffic that did not pass
	// through the proxy.
	OriginSignature *OriginSignature `yaml:"origin_signature"`
	// SlowStart ramps the share of an endpoint that (re)joins the pool,
	// from 10 % to full weight over this duration, so a cold instance is
	// not hit with its full share at once. Applies to endpoints added by
	// discovery and to endpoints returning from unhealthy or ejected.
	// Default 0 (off).
	SlowStart Duration `yaml:"slow_start"`
	// Scheme is http or https. Default http.
	Scheme string `yaml:"scheme"`
	// H2C speaks HTTP/2 without TLS to http endpoints (gRPC backends).
	// Default false.
	H2C bool `yaml:"h2c"`
	// H3 speaks HTTP/3 (QUIC) to https endpoints. Health probes use it
	// too. Default false.
	H3 bool `yaml:"h3"`
	// H3Fallback retries a request over TCP (HTTP/2 or HTTP/1.1) on the
	// same endpoint when the QUIC connection cannot be established or
	// fails before a response, so a network that drops UDP degrades to
	// TCP rather than to errors. Default true.
	H3Fallback  *bool           `yaml:"h3_fallback"`
	TLS         *UpstreamTLS    `yaml:"tls"`
	HealthCheck *HealthCheck    `yaml:"health_check"`
	Timeouts    UpstreamTimeout `yaml:"timeouts"`
	// MaxIdleConnsPerHost bounds the pooled connections per endpoint.
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host"`
	// Retries is the number of times an idempotent request is retried on a
	// connection error against a different endpoint. Default 1.
	Retries *int `yaml:"retries"`
	// RetryOn adds response statuses that are retried like connection
	// errors, on another endpoint, within the same Retries budget and
	// only for replayable requests: "5xx", "500", "502", "503", "504",
	// "429". A retried status counts as a passive failure of the
	// endpoint. Default none.
	RetryOn []string `yaml:"retry_on"`
	// HashOn selects the hash input for the hash balancer: client_ip,
	// header:<name> or cookie:<name>.
	HashOn string `yaml:"hash_on"`
	// Affinity enables signed cookie session affinity.
	Affinity *Affinity `yaml:"affinity"`
	// OutlierEjection removes endpoints that fail passively.
	OutlierEjection *OutlierEjection `yaml:"outlier_ejection"`
	// CircuitBreaker stops sending to the pool as a whole after
	// consecutive failures and probes it back with half open trials.
	CircuitBreaker *CircuitBreaker `yaml:"circuit_breaker"`
	// MaxConcurrent bounds requests in flight to the pool; 0 is unbounded.
	MaxConcurrent int `yaml:"max_concurrent"`
	// Queue holds requests beyond MaxConcurrent for a bounded time.
	Queue *UpstreamQueue `yaml:"queue"`
	// Canary sends selected requests to endpoints marked canary.
	Canary *Canary `yaml:"canary"`
}

// Endpoint is a single upstream address.
type Endpoint struct {
	Address string `yaml:"address"`
	Weight  int    `yaml:"weight"`
	// Canary marks the endpoint as the pool's canary: it receives the
	// requests the pool's canary policy selects and no others.
	Canary bool `yaml:"canary"`
}

// Discovery resolves a pool's endpoints from DNS.
type Discovery struct {
	// Type is dns (A and AAAA records of Name, each with Port) or srv
	// (SRV records of Name; targets and ports come from the records, the
	// lowest priority group is used and record weights become endpoint
	// weights).
	Type string `yaml:"type"`
	// Name is the DNS name to resolve (for srv the full _service._proto
	// name).
	Name string `yaml:"name"`
	// Port is the endpoint port for type dns. Ignored for srv.
	Port int `yaml:"port"`
	// Interval between resolutions. Default 30s; 1s to 1h.
	Interval Duration `yaml:"interval"`
	// Resolver is an optional host:port of the DNS server to ask instead
	// of the system resolver.
	Resolver string `yaml:"resolver"`
	// Weight given to discovered endpoints of type dns. Default 1.
	Weight int `yaml:"weight"`
	// Canary marks discovered endpoints as canaries.
	Canary bool `yaml:"canary"`
	// Timeout of one resolution and of the initial synchronous one at
	// start. Default 5s.
	Timeout Duration `yaml:"timeout"`
}

// Canary routes selected requests to the pool's canary endpoints: those
// carrying Header or Cookie (with one of Values when listed) and a
// Percent share of the rest. Other requests avoid the canaries. Each
// side falls back to the other when its endpoints are all unavailable
// unless Fallback is false.
type Canary struct {
	Header   string   `yaml:"header"`
	Cookie   string   `yaml:"cookie"`
	Values   []string `yaml:"values"`
	Percent  float64  `yaml:"percent"`
	Fallback *bool    `yaml:"fallback"`
}

// OriginSignature is the bypass protection an origin verifies: an HMAC
// over method, host, path, query, time, client address, request id and
// the listed extra headers, carried in one header.
type OriginSignature struct {
	// Header carries the signature. Default X-Xproxy-Signature.
	Header string `yaml:"header"`
	// SecretFile is the keyring shared with the origin (created when
	// missing; rotate with xproxyctl rotate-secret, the previous key
	// stays valid for verification).
	SecretFile string `yaml:"secret_file"`
	// TTL is how long the origin should accept a signature. Default 5m.
	TTL Duration `yaml:"ttl"`
	// Include lists extra request headers covered by the signature.
	Include []string `yaml:"include"`
}

// UpstreamTLS configures TLS towards upstream endpoints.
type UpstreamTLS struct {
	ServerName string `yaml:"server_name"`
	CAFile     string `yaml:"ca_file"`
	// MinVersion is "1.2" or "1.3". Default "1.2".
	MinVersion string `yaml:"min_version"`
	// ClientCertFile / ClientKeyFile enable mTLS to the upstream. The pair
	// is re-read by reload-certs and by configuration reload.
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`
	// SPKIPins are base64 SHA-256 digests of the upstream leaf public key
	// (as in HTTP Public Key Pinning). When set, the connection is refused
	// unless the presented leaf matches one pin, in addition to chain
	// verification.
	SPKIPins []string `yaml:"spki_pins"`
	// InsecureSkipVerify disables verification. Refused unless
	// allow_insecure is also true; logged as a security warning at start.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	AllowInsecure      bool `yaml:"allow_insecure"`
}

// HealthCheck configures active health probing of an upstream.
type HealthCheck struct {
	// Type is http (GET path, expected_status) or grpc (the standard
	// grpc.health.v1 Check over HTTP/2, needs h2c or https). Default http.
	Type string `yaml:"type"`
	// GRPCService is the service name asked in a grpc check. Default ""
	// (the server as a whole).
	GRPCService        string   `yaml:"grpc_service"`
	Path               string   `yaml:"path"`
	Interval           Duration `yaml:"interval"`
	Timeout            Duration `yaml:"timeout"`
	HealthyThreshold   int      `yaml:"healthy_threshold"`
	UnhealthyThreshold int      `yaml:"unhealthy_threshold"`
	ExpectedStatus     []int    `yaml:"expected_status"`
	// MaxConcurrent bounds probes in flight per pool so that a pool with
	// thousands of endpoints does not burst. Default 32.
	MaxConcurrent int `yaml:"max_concurrent"`
	// KeepAlive reuses pooled connections for probes. Off (the default)
	// opens a fresh connection per probe, which verifies the whole connect
	// path and holds no descriptor between probes; on saves the handshake
	// at the cost of one idle connection per endpoint.
	KeepAlive bool `yaml:"keep_alive"`
	// BodyContains requires the first 64 KiB of the probe response to
	// contain this text (type http); BodyRegex an RE2 pattern to match
	// anywhere in it. Both may be set; both must hold.
	BodyContains string `yaml:"body_contains"`
	BodyRegex    string `yaml:"body_regex"`
}

// UpstreamTimeout bounds each phase of an upstream exchange.
type UpstreamTimeout struct {
	Connect        Duration `yaml:"connect"`
	ResponseHeader Duration `yaml:"response_header"`
	Idle           Duration `yaml:"idle"`
	// Total bounds the complete upstream request including the body.
	Total Duration `yaml:"total"`
}

// Affinity is signed cookie session affinity.
type Affinity struct {
	CookieName string   `yaml:"cookie_name"`
	TTL        Duration `yaml:"ttl"`
	// SecretFile holds the HMAC key. Generated at first start when absent
	// and the directory is writable.
	SecretFile string `yaml:"secret_file"`
}

// OutlierEjection configures passive health checking: consecutive
// failures and, when latency_threshold or latency_factor is set, an
// endpoint whose smoothed time to first byte is slow.
type OutlierEjection struct {
	ConsecutiveFailures int      `yaml:"consecutive_failures"`
	BaseEjectionTime    Duration `yaml:"base_ejection_time"`
	MaxEjectionPercent  int      `yaml:"max_ejection_percent"`
	// LatencyThreshold ejects an endpoint whose smoothed latency
	// (exponential moving average of the time to first byte, factor 0.2)
	// exceeds it. 0 disables.
	LatencyThreshold Duration `yaml:"latency_threshold"`
	// LatencyFactor ejects an endpoint whose smoothed latency exceeds
	// the pool's smoothed latency times this factor (at least 1.5),
	// when the pool has two or more endpoints. 0 disables.
	LatencyFactor float64 `yaml:"latency_factor"`
	// LatencyMinSamples is how many responses an endpoint must have
	// answered since it last became available before its latency is
	// judged. Default 20.
	LatencyMinSamples int `yaml:"latency_min_samples"`
}

// CircuitBreaker is a pool wide breaker: closed counts consecutive
// failures (connection errors, timeouts, 503 and retry_on statuses),
// open refuses requests with 503 for OpenFor (times the number of
// reopens, at most ten), half open lets HalfOpenRequests trials through.
type CircuitBreaker struct {
	ConsecutiveFailures int      `yaml:"consecutive_failures"`
	OpenFor             Duration `yaml:"open_for"`
	HalfOpenRequests    int      `yaml:"half_open_requests"`
}

// UpstreamQueue bounds the requests waiting for a MaxConcurrent slot.
type UpstreamQueue struct {
	// Size is the number of waiting requests; more are refused at once.
	Size int `yaml:"size"`
	// Timeout is how long a request waits before 503. Default 1s.
	Timeout Duration `yaml:"timeout"`
}

// Route maps a request to an upstream and attaches policies.
type Route struct {
	Name string `yaml:"name"`
	// Hosts are exact host names or wildcard patterns ("*.example.com").
	// Empty matches any host.
	Hosts []string `yaml:"hosts"`
	// Paths are prefixes. "/" matches everything. Longest prefix wins.
	Paths []string `yaml:"paths"`
	// PathRegex lists RE2 patterns that must match the whole cleaned
	// path (anchored at both ends by the proxy). A regex entry ranks by
	// the length of its literal prefix; at equal length it beats a
	// prefix entry. With PathRegex set, Paths has no default.
	PathRegex []string `yaml:"path_regex"`
	Methods   []string `yaml:"methods"`
	// Headers and Cookies are conditions on the request: every listed
	// match must hold. Entries with conditions rank above entries
	// without at the same path length (more conditions first).
	Headers []HeaderMatch `yaml:"headers"`
	Cookies []HeaderMatch `yaml:"cookies"`
	// Tenant is a free label that groups routes for quota reporting
	// (GET /v1/quotas, xproxyctl quotas) and the per route metrics.
	Tenant string `yaml:"tenant"`
	// When is a condition in the expression language (docs/CONFIG.md,
	// "Expressions") that must hold in addition to the matches above;
	// it counts as one condition for specificity.
	When string `yaml:"when"`
	// Priority breaks ties between routes with identical specificity. Higher
	// wins. Default 0.
	Priority int `yaml:"priority"`

	Upstream string `yaml:"upstream"`
	// Redirect answers with a redirect instead of proxying.
	Redirect *Redirect `yaml:"redirect"`
	// Respond answers with a static status instead of proxying.
	Respond *Respond `yaml:"respond"`
	// Honeypot serves a decoy and marks the client instead of proxying.
	Honeypot *Honeypot `yaml:"honeypot"`

	StripPrefix string `yaml:"strip_prefix"`
	RewritePath string `yaml:"rewrite_path"`
	// RewriteRegex rewrites the outbound path with a regular expression
	// and capture groups; exclusive with rewrite_path, applied after
	// strip_prefix. A path that does not match is sent unchanged.
	RewriteRegex *RewriteRegex `yaml:"rewrite_regex"`
	// ErrorPages overrides the server's error pages for this route.
	ErrorPages *ErrorPages `yaml:"error_pages"`
	// HostHeader overrides the Host header sent upstream. Default keeps the
	// client Host.
	HostHeader string `yaml:"host_header"`

	RequestHeaders  HeaderOps `yaml:"request_headers"`
	ResponseHeaders HeaderOps `yaml:"response_headers"`

	RateLimits []string `yaml:"rate_limits"`
	// AllowCIDRs / DenyCIDRs implement simple IP access control. Deny is
	// evaluated first. Empty allow means allow all.
	AllowCIDRs []string `yaml:"allow_cidrs"`
	DenyCIDRs  []string `yaml:"deny_cidrs"`
	// MaxBodyBytes overrides the global body limit for this route (may only
	// lower it unless allow_raise is set).
	MaxBodyBytes *int64 `yaml:"max_body_bytes"`
	// Timeout bounds the entire request on this route.
	Timeout Duration `yaml:"timeout"`
	// WebSocket allows Upgrade: websocket to be forwarded. Default false.
	WebSocket bool `yaml:"websocket"`
	// WebTransport relays WebTransport sessions (extended CONNECT over
	// HTTP/3 on a listener with h3) to the upstream, which must speak
	// HTTP/3 (h3: true): bidirectional and unidirectional streams and
	// datagrams in both directions. Default false.
	WebTransport bool `yaml:"webtransport"`
	// WAF overrides the global WAF mode and profile for this route.
	WAF *RouteWAF `yaml:"waf"`
	// PriorityClass is low, normal, high or critical (never shed). Default
	// normal.
	PriorityClass string `yaml:"priority_class"`
	// Challenge gates unverified clients with the browser challenge.
	Challenge *RouteChallenge `yaml:"challenge"`
	// JWT requires or accepts a validated token from a provider.
	JWT *RouteJWT `yaml:"jwt"`
	// ICAP hands requests and/or responses to a scanning service.
	ICAP *RouteICAP `yaml:"icap"`
	// Filters names entries of the top-level filters list, run in the
	// listed order within their stage.
	Filters []string `yaml:"filters"`
	// Geo allows or denies by client country (needs the geoip section).
	Geo *RouteGeo `yaml:"geo"`
	// Policy is the route's positive security model: what a request may
	// look like; everything else is refused before any other processing.
	Policy *RoutePolicy `yaml:"policy"`
	// Cache stores responses of this route (needs the cache section).
	Cache *RouteCache `yaml:"cache"`
	// Mirror copies requests of this route to a second upstream.
	Mirror *RouteMirror `yaml:"mirror"`
	// GRPC restricts the route to gRPC requests, optionally to listed
	// services or methods.
	GRPC *RouteGRPC `yaml:"grpc"`
	// DoH answers DNS over HTTPS on this route through a dns listener.
	DoH *RouteDoH `yaml:"doh"`
	// Static serves files from a directory instead of proxying.
	Static *RouteStatic `yaml:"static"`
	// Compress overrides the compression section for this route: false
	// turns it off, true requires the section.
	Compress *bool `yaml:"compress"`
	// CORS answers cross-origin requests for this route: it short-circuits
	// preflight OPTIONS and adds the response headers to actual requests.
	CORS *RouteCORS `yaml:"cors"`
}

// RouteCORS is a Cross-Origin Resource Sharing policy for a route. It is
// independent of the gRPC-web preflight handling (grpc.web_origins).
type RouteCORS struct {
	// AllowOrigins are the permitted Origin values: exact ("https://a.example"),
	// a single "*" (any origin; incompatible with allow_credentials), or a
	// wildcard host pattern ("https://*.example.com"). Required.
	AllowOrigins []string `yaml:"allow_origins"`
	// AllowMethods default to GET, HEAD, POST, PUT, PATCH, DELETE.
	AllowMethods []string `yaml:"allow_methods"`
	// AllowHeaders are the request headers a preflight may allow; "*"
	// reflects the requested headers. Default: reflect the request's
	// Access-Control-Request-Headers.
	AllowHeaders []string `yaml:"allow_headers"`
	// ExposeHeaders are added to Access-Control-Expose-Headers.
	ExposeHeaders []string `yaml:"expose_headers"`
	// AllowCredentials sets Access-Control-Allow-Credentials: true and
	// echoes the specific origin (never "*").
	AllowCredentials bool `yaml:"allow_credentials"`
	// MaxAge is how long a preflight result may be cached. Default 10m.
	MaxAge Duration `yaml:"max_age"`
}

// RoutePolicy is a positive security model for a route: allowed
// methods, media types and query parameters, and bounds on the URI,
// headers and query. A request outside the policy is refused (405, 415,
// 400, 414 or 431) with reason policy before rate limits, filters and
// the WAF run, and the refusal feeds ban triggers under policy.
type RoutePolicy struct {
	// Methods allowed; others get 405 with an Allow header. Unlike
	// routes[].methods, which selects the route, this refuses. Empty
	// allows any method.
	Methods []string `yaml:"methods"`
	// ContentTypes allowed for requests with a body: media types or
	// type/* patterns; others get 415. Empty allows any.
	ContentTypes []string `yaml:"content_types"`
	// RequireContentType refuses a body without a Content-Type header.
	RequireContentType bool `yaml:"require_content_type"`
	// MaxURILength lowers server.limits.max_uri_length for the route.
	MaxURILength int `yaml:"max_uri_length"`
	// MaxQueryBytes bounds the raw query string; MaxQueryParams the
	// number of parameters (repeats counted). 0 means no bound.
	MaxQueryBytes  int `yaml:"max_query_bytes"`
	MaxQueryParams int `yaml:"max_query_params"`
	// MaxHeaders bounds the number of header fields; MaxHeaderBytes the
	// sum of their names and values. 0 means no bound (the server limit
	// still applies).
	MaxHeaders     int `yaml:"max_headers"`
	MaxHeaderBytes int `yaml:"max_header_bytes"`
	// Query describes the parameters; with DenyUnknown, parameters not
	// listed are refused.
	Query       []QueryParamPolicy `yaml:"query"`
	DenyUnknown bool               `yaml:"deny_unknown_query"`
}

// QueryParamPolicy describes one allowed query parameter.
type QueryParamPolicy struct {
	Name string `yaml:"name"`
	// Type is string (default), int, number, bool, uuid or enum (with
	// Values).
	Type string `yaml:"type"`
	// Required refuses requests without the parameter.
	Required bool `yaml:"required"`
	// MaxLength bounds each value; 0 means no bound.
	MaxLength int `yaml:"max_length"`
	// Pattern is an RE2 expression every value must match in full.
	Pattern string `yaml:"pattern"`
	// Values are the allowed values for type enum.
	Values []string `yaml:"values"`
	// MaxRepeat bounds how many times the parameter may appear. Default 1.
	MaxRepeat int `yaml:"max_repeat"`
}

// VirtualPatch blocks a known vulnerability by its request shape while
// the application is being fixed: every listed condition must hold for
// the patch to apply. Patches run right after route matching, before
// rate limits, filters and the WAF, so they cost nothing for other
// traffic and work without a WAF section.
type VirtualPatch struct {
	// ID names the patch in logs, status and metrics (for example
	// cve-2024-1234).
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	// Hosts and Routes narrow the patch to host patterns (exact or
	// "*.example.com") and route names. Empty means every host or route.
	Hosts  []string `yaml:"hosts"`
	Routes []string `yaml:"routes"`
	// Paths are prefixes of the cleaned path; PathRegex patterns match the
	// whole path. At least one condition among paths, path_regex, query,
	// headers, cookies and body is required.
	Paths     []string `yaml:"paths"`
	PathRegex []string `yaml:"path_regex"`
	// Methods narrows the patch to these methods.
	Methods []string `yaml:"methods"`
	// Query, Headers and Cookies are conditions on parameters, header
	// fields and cookies: the name must be present and, with a pattern,
	// some value must match it.
	Query   []PatchMatch `yaml:"query"`
	Headers []PatchMatch `yaml:"headers"`
	Cookies []PatchMatch `yaml:"cookies"`
	// Body matches the request body (buffered up to max_bytes and
	// replayed to the upstream).
	Body *PatchBody `yaml:"body"`
	// Action is block (default) or log.
	Action string `yaml:"action"`
	// Status is the response for block. Default 403.
	Status int `yaml:"status"`
	// Expires disables the patch after this date (RFC 3339 or
	// YYYY-MM-DD) so a temporary measure does not outlive the fix
	// unnoticed; the status shows expired patches.
	Expires string `yaml:"expires"`
	// Enabled false keeps the patch in the configuration without
	// applying it. Default true.
	Enabled *bool `yaml:"enabled"`
}

// IsEnabled reports whether the patch applies.
func (p *VirtualPatch) IsEnabled() bool { return p.Enabled == nil || *p.Enabled }

// PatchMatch is one condition on a named parameter, header or cookie.
type PatchMatch struct {
	Name string `yaml:"name"`
	// Pattern is an RE2 expression matched anywhere in a value; empty
	// means presence suffices.
	Pattern string `yaml:"pattern"`
}

// PatchBody matches the request body.
type PatchBody struct {
	// Pattern is an RE2 expression matched anywhere in the body.
	Pattern string `yaml:"pattern"`
	// MaxBytes bounds the body inspected; a larger body does not match
	// the patch. Default 64 KiB.
	MaxBytes int64 `yaml:"max_bytes"`
	// ContentTypes narrows the inspection to these media types (type/*
	// allowed). Empty inspects every body.
	ContentTypes []string `yaml:"content_types"`
}

// HeaderMatch is one condition on a request header or cookie: exactly
// one of Exact, Prefix, Regex or Present. Header names are matched case
// insensitively and the first value is used; cookie names are exact.
type HeaderMatch struct {
	Name string `yaml:"name"`
	// Exact requires the value to equal this string.
	Exact string `yaml:"exact"`
	// Prefix requires the value to start with this string.
	Prefix string `yaml:"prefix"`
	// Regex is an RE2 pattern matched against the whole value.
	Regex string `yaml:"regex"`
	// Present true requires the header or cookie to exist with any
	// value; false requires it to be absent.
	Present *bool `yaml:"present"`
}

// RouteStatic serves files from a directory. Paths are resolved inside
// Root with os.Root, so neither ".." nor a symbolic link can leave it.
type RouteStatic struct {
	// Root is the absolute directory served.
	Root string `yaml:"root"`
	// Index is the file served for a directory. Default index.html; empty
	// string disables ("" in YAML).
	Index *string `yaml:"index"`
	// Listing renders a directory without an index. Default false.
	Listing bool `yaml:"listing"`
	// Fallback is a path inside Root served when the requested file does
	// not exist (single page applications: /index.html). Default none.
	Fallback string `yaml:"fallback"`
	// CacheControl is sent with every file. Default none.
	CacheControl string `yaml:"cache_control"`
	// DotFiles serves names starting with a dot. Default false.
	DotFiles bool `yaml:"dot_files"`
	// MaxFileBytes refuses larger files with 404. Default 0 (no bound).
	MaxFileBytes int64 `yaml:"max_file_bytes"`
}

// IndexFile returns the index file name with the default applied.
func (r *RouteStatic) IndexFile() string {
	if r.Index == nil {
		return "index.html"
	}
	return *r.Index
}

// RouteDoH is the DNS over HTTPS action (RFC 8484): GET with a base64url
// dns parameter or POST with an application/dns-message body, answered
// by the named kind: dns listener's policy and cache.
type RouteDoH struct {
	Listener string `yaml:"listener"`
}

// RouteGRPC matches gRPC requests (content type application/grpc) by
// the service and method in the path (/package.Service/Method). Empty
// lists match every gRPC request. Denials and proxy errors on such a
// route are answered as gRPC statuses.
type RouteGRPC struct {
	// Services are fully qualified service names.
	Services []string `yaml:"services"`
	// Methods are Service/Method pairs.
	Methods []string `yaml:"methods"`
	// Web accepts gRPC-web requests from browsers (application/grpc-web
	// and grpc-web-text, over HTTP/1.1 or HTTP/2) and translates them to
	// gRPC for the upstream: the response trailers become a trailer
	// frame in the body and the text variant is base64 encoded. Default
	// false.
	Web bool `yaml:"web"`
	// WebOrigins answers CORS preflights of gRPC-web clients from these
	// origins (exact, or "*") and adds the allow and expose headers to
	// responses. Empty handles no CORS.
	WebOrigins []string `yaml:"web_origins"`
}

// RouteMirror sends a copy of each request (sampled by percent) to
// another upstream in the background. The copy carries the same path
// rules, host and header operations as the live request plus
// X-Xproxy-Mirror: 1; its response is discarded and never affects the
// client. Bodies are buffered up to max_body_bytes; larger requests are
// proxied but not mirrored.
type RouteMirror struct {
	Upstream string `yaml:"upstream"`
	// Percent of requests copied. Default 100.
	Percent int `yaml:"percent"`
	// Methods restricts copies to these methods. Empty copies every
	// method except upgrades.
	Methods []string `yaml:"methods"`
	// MaxBodyBytes bounds the buffered body. Default 1 MiB.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
	// Timeout bounds the copy including its response. Default 5s.
	Timeout Duration `yaml:"timeout"`
	// MaxInFlight bounds copies in flight for this route; beyond it
	// copies are dropped and counted. Default 64.
	MaxInFlight int `yaml:"max_in_flight"`
}

// Cache bounds the response cache. Default 64 MiB total, 1 MiB per
// object.
type Cache struct {
	MaxBytes       int64 `yaml:"max_bytes"`
	MaxObjectBytes int64 `yaml:"max_object_bytes"`
}

// Compression is the gzip policy for responses the proxy writes: proxied,
// cached, static and respond bodies alike. Responses the upstream already
// encoded, ranges, `no-transform` and unlisted media types pass through.
type Compression struct {
	// Enabled defaults to true when the section is present.
	Enabled *bool `yaml:"enabled"`
	// Level is the gzip level 1 (fastest) to 9 (smallest). Default 5.
	Level int `yaml:"level"`
	// Encodings lists the content encodings offered, in the order the
	// proxy prefers them when a client accepts several with equal
	// quality: br (Brotli), zstd and gzip. Default [br, zstd, gzip].
	Encodings []string `yaml:"encodings"`
	// BrotliLevel is 0 (fastest) to 11 (smallest). Default 4.
	BrotliLevel *int `yaml:"brotli_level"`
	// ZstdLevel is 1 (fastest), 2 (default), 3 (better) or 4 (best).
	// Default 2.
	ZstdLevel int `yaml:"zstd_level"`
	// MinBytes is the smallest body compressed when its length is known
	// or once that much has been buffered. Default 1024.
	MinBytes int `yaml:"min_bytes"`
	// Types lists the media types compressed (without parameters).
	// Default: the common text, script, style, JSON, XML, SVG and wasm
	// types.
	Types []string `yaml:"types"`
}

// DefaultCompressionTypes are the media types compressed unless
// compression.types is set.
var DefaultCompressionTypes = []string{
	"text/html", "text/plain", "text/css", "text/csv", "text/xml", "text/javascript",
	"application/javascript", "application/json", "application/ld+json", "application/manifest+json",
	"application/xml", "application/xhtml+xml", "application/rss+xml", "application/atom+xml",
	"image/svg+xml", "application/wasm", "font/ttf", "font/otf", "application/vnd.api+json",
}

// Enable reports whether the section is active.
func (c *Compression) Enable() bool { return c != nil && (c.Enabled == nil || *c.Enabled) }

// RouteCache is a route's caching policy.
type RouteCache struct {
	// TTL is the lifetime of a stored response when the response carries
	// no max-age (or when ignore_cache_control is set). Default 60s.
	TTL Duration `yaml:"ttl"`
	// Methods cached. Default [GET, HEAD].
	Methods []string `yaml:"methods"`
	// Statuses cached. Default [200, 203, 204, 300, 301, 404, 410].
	Statuses []int `yaml:"statuses"`
	// Query is "all" (default), "none" (ignore the query string in the
	// key) or "listed" (only the names in query_params, sorted).
	Query       string   `yaml:"query"`
	QueryParams []string `yaml:"query_params"`
	// Headers are request headers whose values join the key (for example
	// Accept-Encoding when the upstream does not send Vary).
	Headers []string `yaml:"headers"`
	// Cookies allows caching requests that carry a Cookie header. Default
	// false: such requests bypass the cache.
	Cookies bool `yaml:"cookies"`
	// IgnoreCacheControl stores responses regardless of Cache-Control and
	// applies ttl. Default false.
	IgnoreCacheControl bool `yaml:"ignore_cache_control"`
}

// GeoIP configures the country database: a MaxMind DB file (GeoLite2 or
// GeoIP2 Country, or any MMDB with country.iso_code) or a CSV of
// "network,country" lines.
type GeoIP struct {
	Database string `yaml:"database"`
	CSV      string `yaml:"csv"`
}

// RouteGeo is a country policy. Deny is evaluated first; a non-empty
// Allow admits only the listed countries. Unknown says what happens to
// an address the database does not know: allow (default) or deny.
type RouteGeo struct {
	Allow   []string `yaml:"allow"`
	Deny    []string `yaml:"deny"`
	Unknown string   `yaml:"unknown"`
}

// FilterConfig is one middleware instance.
type FilterConfig struct {
	Name string `yaml:"name"`
	// Kind is a registered filter kind (xproxyctl filters lists them).
	Kind string `yaml:"kind"`
	// Stage places the filter relative to the built-in chain: before_auth
	// (before JWT), after_auth (default; after JWT, before the WAF),
	// after_waf (before ICAP) or after_scan (last).
	Stage string `yaml:"stage"`
	// Options are kind specific and validated by the kind at load.
	Options map[string]any `yaml:"options"`
}

// Filter stages in chain order.
const (
	StageBeforeAuth = "before_auth"
	StageAfterAuth  = "after_auth"
	StageAfterWAF   = "after_waf"
	StageAfterScan  = "after_scan"
)

// SessionTickets configures shared, rotating TLS session ticket keys.
type SessionTickets struct {
	// SecretFile is the master keyring (created when missing, 0600);
	// deploy the same file to every node of a cluster. Rotate the master
	// with xproxyctl rotate-secret.
	SecretFile string `yaml:"secret_file"`
	// Rotate is the epoch length: the current epoch's key encrypts new
	// tickets and the previous epoch's key still decrypts. Default 24h;
	// 1h to 168h.
	Rotate Duration `yaml:"rotate"`
}

// RewriteRegex is a regular expression path rewrite. Replace may use
// ${1} to ${9} and ${name} for the pattern's groups, and the request
// variables of header templates (docs/CONFIG.md, "Variables").
type RewriteRegex struct {
	Pattern string `yaml:"pattern"`
	Replace string `yaml:"replace"`
}

// ErrorPages replaces the plain status bodies the proxy writes (denials,
// upstream failures, unknown routes, static misses) with documents from
// a directory, chosen by exact status ("404"), class ("4xx", "5xx") or
// "default". Documents are read at load and may use ${status},
// ${status_text}, ${request_id}, ${host}, ${path}, ${reason} and the other
// request variables; unknown ${...} sequences are kept as they are.
type ErrorPages struct {
	// Dir holds the documents; page values are file names inside it or
	// absolute paths.
	Dir   string            `yaml:"dir"`
	Pages map[string]string `yaml:"pages"`
	// ContentType of the documents. Default text/html; charset=utf-8.
	ContentType string `yaml:"content_type"`
	// JSON answers clients whose Accept prefers application/json with a
	// small JSON document instead of the page. Default true.
	JSON *bool `yaml:"json"`
	// InterceptUpstream lists upstream response statuses whose bodies are
	// replaced by the matching page (typically 502, 503, 504). Default
	// none: upstream bodies pass through.
	InterceptUpstream []int `yaml:"intercept_upstream"`
}

// Redirect is a static redirect action. To may use the request variables
// (${path}, ${raw_query}, ${host}, ${1}...) to build the target.
type Redirect struct {
	To     string `yaml:"to"`
	Status int    `yaml:"status"`
}

// IdentityKeyed reports whether the limit keys on an authenticated
// identity, so the data plane evaluates it after the filter chain that
// establishes the identity rather than before it.
func (r *RateLimit) IdentityKeyed() bool {
	return r.Key == "identity" || strings.HasPrefix(r.Key, "identity:")
}

// Respond is a static response action.
type Respond struct {
	Status int    `yaml:"status"`
	Body   string `yaml:"body"`
}

// Honeypot is a decoy action: the response looks like a real page of the
// chosen kind, the client is logged as a security event, marked for
// `mark` so later requests on any route carry the label, and counted
// towards the `honeypot` ban reason.
type Honeypot struct {
	// Decoy names a built-in body: wp-login, env, git-config, phpinfo,
	// admin-login or robots. Exclusive with body and body_file.
	Decoy string `yaml:"decoy"`
	// Status of the decoy response. Default 200.
	Status int `yaml:"status"`
	// ContentType of body or body_file. Default text/html; charset=utf-8.
	ContentType string `yaml:"content_type"`
	// Body is an inline decoy, at most 64 KiB.
	Body string `yaml:"body"`
	// BodyFile is a decoy read at load and reload, at most 1 MiB.
	BodyFile string `yaml:"body_file"`
	// Delay holds the connection before answering, in a tarpit slot.
	// Default 0, at most 60s.
	Delay Duration `yaml:"delay"`
	// Mark is how long the client stays marked. Default 1h.
	Mark Duration `yaml:"mark"`
}

// HeaderOps describes header mutations.
type HeaderOps struct {
	Set    map[string]string `yaml:"set"`
	Add    map[string]string `yaml:"add"`
	Remove []string          `yaml:"remove"`
	// When restricts the operations to requests for which the expression
	// holds (docs/CONFIG.md, "Expressions"); empty applies them always.
	When string `yaml:"when"`
}

// Duration is a time.Duration that unmarshals from strings like "30s".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Enabled reports whether a stream is enabled (default true).
func (s LogStream) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// Bans configures the ban list: addresses that are refused outright for a
// period after repeated security denies or by operator action.
type Bans struct {
	// StateFile persists bans across restarts (bbolt). Empty keeps them in
	// memory only.
	StateFile string `yaml:"state_file"`
	// MaxEntries bounds the number of banned addresses. Default 100000.
	MaxEntries int `yaml:"max_entries"`
	// ExemptCIDRs are never banned (monitoring, office ranges).
	ExemptCIDRs []string `yaml:"exempt_cidrs"`
	// Action is drop (close connections at accept and answer 403 when the
	// client is derived from a trusted proxy) or reject (403 only). Default
	// drop.
	Action string `yaml:"action"`
	// Triggers turn repeated denies into bans.
	Triggers []BanTrigger `yaml:"triggers"`
}

// BanTrigger bans a client after Threshold denies within Window.
type BanTrigger struct {
	Name string `yaml:"name"`
	// Reasons restricts which deny reasons count (acl, rate_limit, waf,
	// body_size, uri_length, bad_host, no_route, websocket, concurrency).
	// Empty counts every deny.
	Reasons   []string `yaml:"reasons"`
	Threshold int      `yaml:"threshold"`
	Window    Duration `yaml:"window"`
	Duration  Duration `yaml:"duration"`
	// Escalation multiplies the duration for every repeat ban of the same
	// address. Default 2. MaxDuration caps it, default 24h.
	Escalation  float64  `yaml:"escalation"`
	MaxDuration Duration `yaml:"max_duration"`
	// Aggregate is what the trigger counts and bans: address (default),
	// net (the client network of NetV4 or NetV6 bits, for attacks spread
	// over one allocation) or ja4 (the TLS client fingerprint, for
	// attacks spread over many networks from one tool).
	Aggregate string `yaml:"aggregate"`
	// NetV4 and NetV6 are the prefix lengths of aggregate net. Default 24
	// and 48.
	NetV4 int `yaml:"net_v4"`
	NetV6 int `yaml:"net_v6"`
	// MinSources is how many distinct client addresses must contribute
	// to the window before a net or ja4 aggregate bans, so one noisy host
	// does not ban its neighbours. Default 1.
	MinSources int `yaml:"min_sources"`
}

// Sandbox configures the in-process hardening (docs/HARDENING.md). Every
// mechanism is applied after the listeners, log files, state files and
// the management socket are open, so the rules describe what the process
// still needs afterwards: the directories of every configured file for
// reading, the log, state and history directories for writing. A reload
// that names a file outside those directories is refused with a message
// to restart, because Landlock rules cannot be widened once applied.
type Sandbox struct {
	// Enabled applies the sandbox. Default true.
	Enabled *bool `yaml:"enabled"`
	// Strict refuses to start when a mechanism the platform should
	// offer is unavailable (old kernel, container without the syscall)
	// instead of logging and continuing. Default false.
	Strict bool `yaml:"strict"`
	// Landlock restricts file system access to the derived directories
	// (Linux 5.13 or newer) and, on ABI 4 or newer, refuses new TCP
	// binds.
	Landlock SandboxLandlock `yaml:"landlock"`
	// Seccomp installs a system call deny list: process tracing,
	// module loading, mounts, namespaces, keyrings, BPF, io_uring,
	// identity changes, exec and the kernel administration calls
	// return EPERM (Linux).
	Seccomp SandboxSeccomp `yaml:"seccomp"`
	// Capabilities clears the bounding, ambient, permitted, effective
	// and inheritable sets (Linux). Default true.
	Capabilities SandboxCapabilities `yaml:"capabilities"`
	// NoNewPrivs sets PR_SET_NO_NEW_PRIVS so that no later exec (there
	// is none) could regain privileges; Landlock and unprivileged
	// seccomp require it. Default true.
	NoNewPrivs *bool `yaml:"no_new_privs"`
	// Debuggable keeps the process attachable by a debugger and able to
	// dump core. Default false: the process is made non dumpable and
	// the core size limit is set to zero, so memory holding keys and
	// request data cannot be read by another process of the same user
	// or written to disk.
	Debuggable bool `yaml:"debuggable"`
}

// SandboxLandlock tunes the Landlock rules.
type SandboxLandlock struct {
	// Enabled applies Landlock when the kernel offers it. Default true.
	Enabled *bool `yaml:"enabled"`
	// ReadPaths are extra files or directories the process may read
	// (a filter that opens files of its own, a certificate directory
	// that reloads will add files to).
	ReadPaths []string `yaml:"read_paths"`
	// WritePaths are extra directories the process may write.
	WritePaths []string `yaml:"write_paths"`
	// Bind refuses TCP binds after start (Landlock ABI 4, Linux 6.7 or
	// newer). Listeners are bound before the sandbox; a reload that adds
	// a listener requires a restart in any case. Default true.
	Bind *bool `yaml:"bind"`
}

// SandboxSeccomp tunes the system call filter.
type SandboxSeccomp struct {
	// Enabled installs the filter. Default true.
	Enabled *bool `yaml:"enabled"`
}

// SandboxCapabilities tunes capability handling.
type SandboxCapabilities struct {
	// Drop clears every capability set. Default true.
	Drop *bool `yaml:"drop"`
}

// On reports whether the sandbox applies.
func (s *Sandbox) On() bool { return s.Enabled == nil || *s.Enabled }

// WAF configures the web application firewall engine.
type WAF struct {
	Profiles []WAFProfile `yaml:"profiles"`
	// DefaultMode applies to routes without a waf block: off, detect or
	// block. Default block when the section is present.
	DefaultMode string `yaml:"default_mode"`
	// DefaultProfile applies to routes without a waf block. Default
	// "default".
	DefaultProfile string `yaml:"default_profile"`
	// RequestBodyLimit bounds the request body inspected. Default 1 MiB.
	RequestBodyLimit int64 `yaml:"request_body_limit"`
	// RequestBodyLimitAction is reject (413) or partial (inspect the first
	// RequestBodyLimit bytes and pass the rest). Default reject.
	RequestBodyLimitAction string `yaml:"request_body_limit_action"`
	// InspectResponses enables response header and body inspection.
	InspectResponses bool `yaml:"inspect_responses"`
	// ResponseBodyLimit bounds the response body inspected. Default 512 KiB;
	// larger bodies are passed uninspected.
	ResponseBodyLimit int64 `yaml:"response_body_limit"`
	// ResponseMIMETypes lists content types whose bodies are inspected.
	ResponseMIMETypes []string `yaml:"response_mime_types"`
	// Learning collects the variables that trigger detection rules and
	// proposes exclusions (GET /v1/waf, xproxyctl waf proposals).
	Learning *WAFLearning `yaml:"learning"`
	// Anomaly detects clients whose behaviour departs from the population
	// (request rate, rule match ratio, error ratio, path spread) rather
	// than requests that match a rule.
	Anomaly *WAFAnomaly `yaml:"anomaly"`
}

// WAFAnomaly tunes behavioural anomaly detection. Every WAF protected
// request is attributed to its client; at the end of each window the
// clients' feature vectors update a population baseline (mean and
// variance per feature) and a client whose largest z-score reaches the
// threshold is flagged until it looks normal again.
type WAFAnomaly struct {
	Enabled bool `yaml:"enabled"`
	// Window is the observation period. Default 5m.
	Window Duration `yaml:"window"`
	// MinRequests is the number of requests a client needs in a window
	// before it is scored. Default 30.
	MinRequests int `yaml:"min_requests"`
	// Threshold is the z-score at which a client is flagged. Default 4.
	Threshold float64 `yaml:"threshold"`
	// Action for requests of a flagged client: log, challenge or block.
	// Default log.
	Action string `yaml:"action"`
	// MaxClients bounds the tracked clients per window. Default 65536.
	MaxClients int `yaml:"max_clients"`
}

// WAFLearning tunes exclusion learning. Matches are aggregated per rule,
// target variable and route across block and detect mode alike; a triple
// seen min_hits times becomes a proposal.
type WAFLearning struct {
	Enabled bool `yaml:"enabled"`
	// MinHits is the number of matches before a proposal appears. Default 5.
	MinHits int `yaml:"min_hits"`
	// MaxEntries bounds the learning table. Default 10000.
	MaxEntries int `yaml:"max_entries"`
}

// WAFProfile is a named rule set.
type WAFProfile struct {
	Name string `yaml:"name"`
	// CRS enables the OWASP Core Rule Set bundled with the binary.
	CRS *CRS `yaml:"crs"`
	// DirectiveFiles are SecLang files loaded after the CRS setup and before
	// the CRS rules (the right place for exclusions).
	DirectiveFiles []string `yaml:"directive_files"`
	// Directives is inline SecLang loaded in the same position.
	Directives string `yaml:"directives"`
	// JSONSchemas enforce a JSON Schema on request bodies under a path
	// prefix, before the rules run.
	JSONSchemas []WAFJSONSchema `yaml:"json_schemas"`
}

// WAFJSONSchema binds a schema file to request paths.
type WAFJSONSchema struct {
	Name string `yaml:"name"`
	// Paths are the request path prefixes the schema applies to.
	Paths []string `yaml:"paths"`
	// Methods restricts enforcement to these methods. Default POST, PUT
	// and PATCH.
	Methods []string `yaml:"methods"`
	// SchemaFile is a JSON Schema document (JSON or YAML).
	SchemaFile string `yaml:"schema_file"`
	// Required rejects requests under Paths without a JSON body. Default
	// false: a request without a body or with another media type passes
	// to the rules.
	Required bool `yaml:"required"`
}

// CRS tunes the Core Rule Set.
type CRS struct {
	// Dir loads the rule set from a directory laid out like a CRS release
	// (crs-setup.conf or crs-setup.conf.example, rules/*.conf and the data
	// files) instead of the copy embedded in the binary, so that rules can
	// be updated with a reload. Default: embedded.
	Dir string `yaml:"dir"`
	// PluginsDir holds CRS plugins, each a directory or a set of files
	// named <plugin>-config.conf, <plugin>-before.conf and
	// <plugin>-after.conf. Config and before files load before the CRS
	// rules, after files after them.
	PluginsDir string `yaml:"plugins_dir"`
	// Plugins names the plugins under PluginsDir to load. Default: every
	// plugin found.
	Plugins []string `yaml:"plugins"`
	// ParanoiaLevel 1 to 4. Default 1.
	ParanoiaLevel int `yaml:"paranoia_level"`
	// InboundThreshold is the anomaly score at which a request is blocked.
	// Default 5 (one critical rule).
	InboundThreshold int `yaml:"inbound_threshold"`
	// OutboundThreshold is the anomaly score at which a response is
	// blocked. Default 4.
	OutboundThreshold int `yaml:"outbound_threshold"`
}

// RouteWAF selects the WAF profile and mode for a route.
type RouteWAF struct {
	// Mode is off, detect or block.
	Mode    string `yaml:"mode"`
	Profile string `yaml:"profile"`
	// BlockPercent rolls block mode out gradually: this share of the
	// clients (a stable function of the client address) gets block mode,
	// the rest detect mode. Default 100. Only with mode block.
	BlockPercent *int `yaml:"block_percent"`
	// BlockCIDRs always get block mode whatever the share: the canary
	// clients (internal testers, a pilot customer). Only with mode block.
	BlockCIDRs []string `yaml:"block_cidrs"`
}

// Percent returns the block share with its default.
func (r *RouteWAF) Percent() int {
	if r == nil || r.BlockPercent == nil {
		return 100
	}
	return *r.BlockPercent
}

// Gradual reports whether the route splits clients between block and
// detect mode.
func (r *RouteWAF) Gradual() bool {
	return r != nil && r.Mode == "block" && (r.Percent() < 100 || len(r.BlockCIDRs) > 0)
}

// Cluster configures peer to peer sharing over mutual TLS (AMR-009).
type Cluster struct {
	// NodeID identifies this node to peers. Default: host name.
	NodeID string `yaml:"node_id"`
	// Listen is the address of the cluster listener (TCP, mTLS). Bind it to
	// an internal interface.
	Listen string `yaml:"listen"`
	// Peers are the cluster addresses of the other nodes.
	Peers []string   `yaml:"peers"`
	TLS   ClusterTLS `yaml:"tls"`
	// GossipInterval is how often consumption reports are sent. Default 1s.
	GossipInterval Duration `yaml:"gossip_interval"`
	// PeerStale is how long a peer report keeps influencing local limits
	// after the last update. Default 3 x gossip_interval.
	PeerStale Duration `yaml:"peer_stale"`
	// ShareRateLimits, ShareBans and ShareEvents select what is exchanged.
	// All default to true. Events are honeypot marks and revoked OIDC
	// sessions; nodes older than 1.3 close a connection that carries them.
	ShareRateLimits *bool `yaml:"share_rate_limits"`
	ShareBans       *bool `yaml:"share_bans"`
	ShareEvents     *bool `yaml:"share_events"`
	// MaxKeysPerReport bounds one report. Default 4096.
	MaxKeysPerReport int `yaml:"max_keys_per_report"`
	// ExactTimeout bounds the wait for a key owner's decision under
	// distributed: exact; on expiry the request is decided locally.
	// Default 50ms.
	ExactTimeout Duration `yaml:"exact_timeout"`
}

// APIInventory discovers the API surface from traffic: every proxied
// request is attributed to a host, method and path template, with
// counts, credentials seen, media types and the version in the path.
// Routes with an openapi filter contribute their documented operations,
// which makes shadow endpoints (traffic outside the description) and
// zombies (documented operations without traffic) visible.
type APIInventory struct {
	// Enabled defaults to true when the section is present.
	Enabled *bool `yaml:"enabled"`
	// MaxEndpoints bounds the table. Default 10000.
	MaxEndpoints int `yaml:"max_endpoints"`
	// Hosts and Routes narrow the inventory to these host patterns and
	// route names. Default: every proxied route.
	Hosts  []string `yaml:"hosts"`
	Routes []string `yaml:"routes"`
	// ZombieAfter is how long a documented endpoint may go without
	// traffic before it is reported as a zombie. Default 720h.
	ZombieAfter Duration `yaml:"zombie_after"`
	// StateFile keeps the inventory across restarts. Optional.
	StateFile string `yaml:"state_file"`
	// SaveInterval is how often the state file is written. Default 5m.
	SaveInterval Duration `yaml:"save_interval"`
}

// IsEnabled reports whether the inventory records traffic.
func (a *APIInventory) IsEnabled() bool { return a != nil && (a.Enabled == nil || *a.Enabled) }

// Fleet is the agent side of central configuration management: the node
// long polls the controller for a bundle whose digest differs from the
// applied one, writes the files under Dir, reloads and reports its
// status. Changing the section requires a restart.
type Fleet struct {
	// Controller is the controller's base URL (https).
	Controller string `yaml:"controller"`
	// NodeID is the node's name at the controller; it must match the
	// certificate name unless the controller runs with -any-name. Default
	// cluster.node_id, else the host name.
	NodeID string `yaml:"node_id"`
	// TLS holds the node certificate, key and the fleet CA.
	TLS FleetTLS `yaml:"tls"`
	// Interval is the long poll length and the status report period.
	// Default 30s.
	Interval Duration `yaml:"interval"`
	// Timeout bounds one request beyond the poll length. Default 10s.
	Timeout Duration `yaml:"timeout"`
	// Dir receives the bundle files; the configuration file must be
	// Dir/xproxy.yaml (the -config path). Default: the directory of the
	// configuration file.
	Dir string `yaml:"dir"`
	// Apply false reports status and pending bundles without writing or
	// reloading anything. Default true.
	Apply *bool `yaml:"apply"`
	// Tags are reported to the controller for grouping.
	Tags []string `yaml:"tags"`
}

// Applies reports the apply setting with its default.
func (f *Fleet) Applies() bool { return f.Apply == nil || *f.Apply }

// FleetTLS is the agent's client certificate and the controller CA.
type FleetTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
	// ServerName overrides the name verified in the controller's
	// certificate. Default: the host of Controller.
	ServerName string `yaml:"server_name"`
}

// ClusterTLS holds the node certificate and the cluster CA. Every peer
// must present a certificate from this CA; there is no other
// authentication.
type ClusterTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
	// AllowedNames optionally restricts peers to these certificate common
	// names or DNS SANs.
	AllowedNames []string `yaml:"allowed_names"`
}

// Sharing helpers with defaults applied.
func (c *Cluster) SharesRateLimits() bool { return c.ShareRateLimits == nil || *c.ShareRateLimits }

// SharesBans reports whether bans are exchanged.
func (c *Cluster) SharesBans() bool { return c.ShareBans == nil || *c.ShareBans }

// SharesEvents reports whether security events are exchanged.
func (c *Cluster) SharesEvents() bool { return c.ShareEvents == nil || *c.ShareEvents }

// Shedding configures adaptive load shedding (AMR-022). The load level is
// the larger of the in-flight ratio (in-flight requests over
// max_concurrent_requests) and the latency level (how far recent upstream
// latency exceeds target_latency, reaching 1 at twice the target). A
// priority class is shed while the level is at or above its threshold,
// with hysteresis so that admission does not flap.
type Shedding struct {
	// TargetLatency is the upstream time to first byte the site is designed
	// for. Default 250ms.
	TargetLatency Duration `yaml:"target_latency"`
	// Window is the period over which latency is averaged. Default 10s.
	Window Duration `yaml:"window"`
	// Thresholds per class as a load level between 0 and 1. Defaults: low
	// 0.6, normal 0.8, high 0.95. Critical is never shed.
	Low    float64 `yaml:"low"`
	Normal float64 `yaml:"normal"`
	High   float64 `yaml:"high"`
	// Hysteresis is subtracted from a threshold before a class is admitted
	// again. Default 0.1.
	Hysteresis float64 `yaml:"hysteresis"`
	// RetryAfter is the Retry-After value sent with shed responses. Default
	// 2s.
	RetryAfter Duration `yaml:"retry_after"`
}

// Challenge configures the browser proof-of-work challenge (AMR-023).
type Challenge struct {
	// SecretFile persists the HMAC key so cookies survive restarts.
	SecretFile string `yaml:"secret_file"`
	// Difficulty is the number of leading zero bits required. Default 16
	// (about 65 000 hashes, well under a second in a browser).
	Difficulty int `yaml:"difficulty"`
	// TTL is the validity of a passed challenge. Default 1h.
	TTL Duration `yaml:"ttl"`
	// BindIP ties the cookie to the client address. Default true.
	BindIP *bool `yaml:"bind_ip"`
	// CookieName defaults to XPCHAL.
	CookieName string `yaml:"cookie_name"`
	// ExemptCIDRs are never challenged.
	ExemptCIDRs []string `yaml:"exempt_cidrs"`
	// Title is the heading shown on the page.
	Title string `yaml:"title"`
	// Captcha adds a hosted CAPTCHA tier: verdicts that ask for one
	// (an account_guard captcha step) show the provider's widget instead
	// of the proof of work; with mode always every challenge page does.
	Captcha *Captcha `yaml:"captcha"`
	// Device includes a device identifier, computed by the challenge
	// script from stable browser properties, in the cookie; it becomes
	// the device attribute, Info.DeviceID for filters and the device
	// rate limit key. Default true.
	Device *bool `yaml:"device"`
}

// BindsIP reports whether cookies are bound to the client address.
func (c *Challenge) BindsIP() bool { return c.BindIP == nil || *c.BindIP }

// DevicesOn reports whether device identifiers are collected.
func (c *Challenge) DevicesOn() bool { return c.Device == nil || *c.Device }

// Captcha configures a hosted CAPTCHA provider for the challenge.
type Captcha struct {
	// Provider is turnstile, hcaptcha or recaptcha.
	Provider string `yaml:"provider"`
	// SiteKey is the public key rendered into the widget.
	SiteKey string `yaml:"site_key"`
	// SecretFile holds the provider's secret key (one line).
	SecretFile string `yaml:"secret_file"`
	// VerifyURL overrides the provider's siteverify endpoint (tests,
	// enterprise endpoints).
	VerifyURL string `yaml:"verify_url"`
	// Timeout for the verification call. Default 5s.
	Timeout Duration `yaml:"timeout"`
	// MinScore refuses tokens the provider scores below it (reCAPTCHA v3
	// and Enterprise return one). Default 0 (not checked).
	MinScore float64 `yaml:"min_score"`
	// Mode is escalation (default: the widget only for verdicts that ask
	// for a CAPTCHA) or always (every challenge page).
	Mode string `yaml:"mode"`
	// Hostnames the provider may report the token was solved on. Empty
	// checks the token against the host the challenge page was served on,
	// so a token solved for another site is refused. HostnameCheck off
	// disables the check for providers that do not return a hostname.
	Hostnames     []string `yaml:"hostnames"`
	HostnameCheck *bool    `yaml:"hostname_check"`
}

// ChecksHostname reports whether the CAPTCHA hostname is verified.
func (c *Captcha) ChecksHostname() bool { return c.HostnameCheck == nil || *c.HostnameCheck }

// RouteChallenge selects when a route challenges unverified clients.
type RouteChallenge struct {
	// Mode is off, always or load. In load mode clients are challenged only
	// while the shedding load level is at or above Level.
	Mode string `yaml:"mode"`
	// Level is the load level that activates load mode. Default 0.5.
	Level float64 `yaml:"level"`
}

// JWT holds token providers (AMR-025).
type JWT struct {
	Providers []JWTProvider `yaml:"providers"`
}

// JWTProvider describes one issuer and where its keys come from.
type JWTProvider struct {
	Name string `yaml:"name"`
	// Issuer must equal the token's iss claim.
	Issuer string `yaml:"issuer"`
	// Audiences: the token's aud must contain at least one. Empty accepts
	// any audience (not recommended).
	Audiences []string `yaml:"audiences"`
	// Algorithms allowed, from RS256, RS384, RS512, PS256, PS384, PS512,
	// ES256, ES384, ES512, EdDSA, HS256, HS384, HS512. "none" is never
	// allowed. Default: [RS256, ES256, EdDSA].
	Algorithms []string `yaml:"algorithms"`
	// JWKSFile is a JSON Web Key Set on disk (re-read on reload).
	JWKSFile string `yaml:"jwks_file"`
	// JWKSURL fetches the key set over HTTPS at start and every
	// JWKSRefresh, and on an unknown key id (rate limited).
	JWKSURL string `yaml:"jwks_url"`
	// JWKSCAFile pins the CA for the JWKS fetch. Default: system pool.
	JWKSCAFile  string   `yaml:"jwks_ca_file"`
	JWKSRefresh Duration `yaml:"jwks_refresh"`
	// HMACSecretFile holds the shared secret for HS* algorithms.
	HMACSecretFile string `yaml:"hmac_secret_file"`
	// ClockSkew tolerated on exp and nbf. Default 30s.
	ClockSkew Duration `yaml:"clock_skew"`
	// RequiredClaims must be present. exp is always required.
	RequiredClaims []string `yaml:"required_claims"`
	// Source is where the token is read from: bearer (Authorization:
	// Bearer), header:<Name> or cookie:<Name>. Default bearer.
	Source string `yaml:"source"`
	// ForwardClaims maps upstream header names to claim names. Client
	// supplied values of these headers are always removed first.
	ForwardClaims map[string]string `yaml:"forward_claims"`
	// StripToken removes the token from the forwarded request. Default
	// true.
	StripToken *bool `yaml:"strip_token"`
	// LogClaims lists claims copied into the access log (for example sub).
	LogClaims []string `yaml:"log_claims"`
	// Introspection validates tokens at an OAuth 2.0 token introspection
	// endpoint (RFC 7662): opaque tokens always, signed tokens too with
	// always. A provider may have introspection alone, without keys.
	Introspection *TokenIntrospection `yaml:"introspection"`
}

// TokenIntrospection is an RFC 7662 introspection endpoint.
type TokenIntrospection struct {
	// URL is the introspection endpoint (https).
	URL string `yaml:"url"`
	// ClientID and ClientSecretFile authenticate the proxy to the
	// endpoint with HTTP basic authentication.
	ClientID         string `yaml:"client_id"`
	ClientSecretFile string `yaml:"client_secret_file"`
	// CAFile pins the CA for the endpoint. Default: system pool.
	CAFile string `yaml:"ca_file"`
	// CacheTTL keeps a decision for a token this long, bounded by the
	// token's exp; 0 caches nothing. Default 60s.
	CacheTTL Duration `yaml:"cache_ttl"`
	// Timeout bounds one introspection call. Default 3s.
	Timeout Duration `yaml:"timeout"`
	// Always introspects signed tokens too (revocation checks); default
	// false introspects only tokens that are not JWS compact serialisations.
	Always bool `yaml:"always"`
}

// Strips reports whether the token is removed before forwarding.
func (p *JWTProvider) Strips() bool { return p.StripToken == nil || *p.StripToken }

// RouteJWT attaches a provider to a route.
type RouteJWT struct {
	Provider string `yaml:"provider"`
	// Required rejects requests without a token with 401. Default true.
	// When false, a missing token passes and an invalid one is rejected.
	Required *bool `yaml:"required"`
}

// IsRequired reports whether a token must be present.
func (r *RouteJWT) IsRequired() bool { return r.Required == nil || *r.Required }

// ICAP holds scanning services (RFC 3507; AMR-015, AMR-028).
type ICAP struct {
	Services []ICAPService `yaml:"services"`
}

// ICAPService is one ICAP endpoint.
type ICAPService struct {
	Name string `yaml:"name"`
	// URL is icap://host[:port]/service or icaps://... for TLS.
	URL string   `yaml:"url"`
	TLS *ICAPTLS `yaml:"tls"`
	// ConnectTimeout and Timeout bound the dial and the whole exchange.
	// Defaults 2s and 5s.
	ConnectTimeout Duration `yaml:"connect_timeout"`
	Timeout        Duration `yaml:"timeout"`
	// MaxConns bounds pooled idle connections. Default 8.
	MaxConns int `yaml:"max_conns"`
	// MaxBody bounds the body sent for scanning. Default 10 MiB.
	MaxBody int64 `yaml:"max_body"`
	// BodyLimitAction is bypass (pass without scanning) or reject (413)
	// for bodies above MaxBody. Default reject.
	BodyLimitAction string `yaml:"body_limit_action"`
	// Fail is open (pass when the service errors or times out) or closed
	// (answer 502). Default closed.
	Fail string `yaml:"fail"`
	// Preview is auto (from OPTIONS), off, or a byte count.
	Preview string `yaml:"preview"`
}

// ICAPTLS pins the CA and name for icaps.
type ICAPTLS struct {
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
}

// RouteICAP attaches a service to a route.
type RouteICAP struct {
	Service string `yaml:"service"`
	// Request sends requests (REQMOD); Response sends responses (RESPMOD).
	// Request defaults to true, Response to false.
	Request  *bool `yaml:"request"`
	Response *bool `yaml:"response"`
}

// ScansRequests reports whether REQMOD is enabled.
func (r *RouteICAP) ScansRequests() bool { return r.Request == nil || *r.Request }

// ScansResponses reports whether RESPMOD is enabled.
func (r *RouteICAP) ScansResponses() bool { return r.Response != nil && *r.Response }

// ACME configures the certificate authority account (RFC 8555; AMR-029).
type ACME struct {
	// Directory is the CA's directory URL.
	Directory string `yaml:"directory"`
	// Email is the account contact.
	Email string `yaml:"email"`
	// AcceptTerms must be true; the CA's terms are agreed on registration.
	AcceptTerms bool `yaml:"accept_terms"`
	// CAFile pins the CA of the directory server (private CAs, tests).
	CAFile string `yaml:"ca_file"`
	// StateDir holds the account key and issued certificates. Default
	// /var/lib/xproxy/acme.
	StateDir string `yaml:"state_dir"`
	// Challenge is http-01 (needs a plaintext listener on port 80) or
	// tls-alpn-01 (needs the TLS listener on port 443). Default http-01.
	Challenge string `yaml:"challenge"`
	// RenewBefore renews when less than this remains. Default 720h (30 days).
	RenewBefore Duration `yaml:"renew_before"`
	// CheckInterval is how often expiry is checked. Default 12h.
	CheckInterval Duration `yaml:"check_interval"`
}
