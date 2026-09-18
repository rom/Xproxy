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
}

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
}

// Management configures the control plane listener used by xproxyctl.
type Management struct {
	// Socket is the path of the Unix domain socket. Empty disables management.
	Socket string `yaml:"socket"`
	// SocketMode is the octal permission mode of the socket, default 0660.
	SocketMode string `yaml:"socket_mode"`
}

// Logging configures the four log streams.
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
}

// LogStream configures one log file.
type LogStream struct {
	Enabled *bool  `yaml:"enabled"`
	File    string `yaml:"file"`
	// MaxSizeMB triggers rotation when the file exceeds this size. 0 disables
	// internal rotation (use logrotate or journald instead).
	MaxSizeMB int `yaml:"max_size_mb"`
	MaxFiles  int `yaml:"max_files"`
}

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
	Scheme      string          `yaml:"scheme"`
	TLS         *UpstreamTLS    `yaml:"tls"`
	HealthCheck *HealthCheck    `yaml:"health_check"`
	Timeouts    UpstreamTimeout `yaml:"timeouts"`
	// MaxIdleConnsPerHost bounds the pooled connections per endpoint.
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host"`
	// Retries is the number of times an idempotent request is retried on a
	// connection error against a different endpoint. Default 1.
	Retries *int `yaml:"retries"`
	// HashOn selects the hash input for the hash balancer: client_ip,
	// header:<name> or cookie:<name>.
	HashOn string `yaml:"hash_on"`
	// Affinity enables signed cookie session affinity.
	Affinity *Affinity `yaml:"affinity"`
	// OutlierEjection removes endpoints that fail passively.
	OutlierEjection *OutlierEjection `yaml:"outlier_ejection"`
}

// Endpoint is a single upstream address.
type Endpoint struct {
	Address string `yaml:"address"`
	Weight  int    `yaml:"weight"`
}

// UpstreamTLS configures TLS towards upstream endpoints.
type UpstreamTLS struct {
	ServerName string `yaml:"server_name"`
	CAFile     string `yaml:"ca_file"`
	// ClientCertFile / ClientKeyFile enable mTLS to the upstream.
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`
	// InsecureSkipVerify disables verification. Refused unless
	// allow_insecure is also true; logged as a security warning at start.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	AllowInsecure      bool `yaml:"allow_insecure"`
}

// HealthCheck configures active health probing of an upstream.
type HealthCheck struct {
	Path               string   `yaml:"path"`
	Interval           Duration `yaml:"interval"`
	Timeout            Duration `yaml:"timeout"`
	HealthyThreshold   int      `yaml:"healthy_threshold"`
	UnhealthyThreshold int      `yaml:"unhealthy_threshold"`
	ExpectedStatus     []int    `yaml:"expected_status"`
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

// Route maps a request to an upstream and attaches policies.
type Route struct {
	Name string `yaml:"name"`
	// Hosts are exact host names or wildcard patterns ("*.example.com").
	// Empty matches any host.
	Hosts []string `yaml:"hosts"`
	// Paths are prefixes. "/" matches everything. Longest prefix wins.
	Paths   []string `yaml:"paths"`
	Methods []string `yaml:"methods"`
	// Priority breaks ties between routes with identical specificity. Higher
	// wins. Default 0.
	Priority int `yaml:"priority"`

	Upstream string `yaml:"upstream"`
	// Redirect answers with a redirect instead of proxying.
	Redirect *Redirect `yaml:"redirect"`
	// Respond answers with a static status instead of proxying.
	Respond *Respond `yaml:"respond"`

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
}

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
	// ShareRateLimits and ShareBans select what is exchanged. Both default
	// to true.
	ShareRateLimits *bool `yaml:"share_rate_limits"`
	ShareBans       *bool `yaml:"share_bans"`
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
