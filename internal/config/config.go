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
	// Cache sizes the in-memory response cache used by routes[].cache.
	Cache *Cache `yaml:"cache"`
	// Compression enables gzip of eligible responses on every route
	// (routes[].compress overrides per route).
	Compression *Compression `yaml:"compression"`
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
	// ServerHeader is the value sent in the Server response header. Empty
	// removes the header entirely (the default) to avoid fingerprinting.
	ServerHeader string `yaml:"server_header"`
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
	// connections by TLS server name without terminating TLS) or forward
	// (an explicit HTTP proxy for clients: CONNECT tunnels and absolute
	// URI requests to destinations the policy allows).
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
}

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
}

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
	// Format is rfc5424 or rfc3164. Default rfc3164 for unix, rfc5424
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

// RateLimit is a named token bucket policy referenced by routes.
type RateLimit struct {
	Name string `yaml:"name"`
	// Key selects the bucket identity: client_ip, route, or header:<name>.
	Key string `yaml:"key"`
	// Rate is tokens per second.
	Rate float64 `yaml:"rate"`
	// Burst is the bucket capacity.
	Burst int `yaml:"burst"`
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
	// Scheme is http or https. Default http.
	Scheme string `yaml:"scheme"`
	// H2C speaks HTTP/2 without TLS to http endpoints (gRPC backends).
	// Default false.
	H2C         bool            `yaml:"h2c"`
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

// OutlierEjection configures passive health checking.
type OutlierEjection struct {
	ConsecutiveFailures int      `yaml:"consecutive_failures"`
	BaseEjectionTime    Duration `yaml:"base_ejection_time"`
	MaxEjectionPercent  int      `yaml:"max_ejection_percent"`
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

// Redirect is a static redirect action.
type Redirect struct {
	To     string `yaml:"to"`
	Status int    `yaml:"status"`
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
}

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
}

// CRS tunes the Core Rule Set.
type CRS struct {
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
}

// BindsIP reports whether cookies are bound to the client address.
func (c *Challenge) BindsIP() bool { return c.BindIP == nil || *c.BindIP }

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
