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
	"strconv"
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
	// advice holds what the last validation thought was a bad idea; see
	// Advice. It is not part of the document, so it never round-trips
	// through a dump, a diff or the history.
	advice []string `yaml:"-"`

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
	// SecurityTxt serves a virtual security.txt (RFC 9116) for the hosts
	// each entry names, before routing.
	SecurityTxt []SecurityTxt `yaml:"security_txt"`
	// Honeytokens are planted credentials. A request presenting one has
	// read something it should not have.
	Honeytokens []Honeytoken `yaml:"honeytokens"`
	// Handshake refuses clients before the TLS handshake completes.
	Handshake *Handshake `yaml:"handshake"`
	// Degradation serves a suspect client slowly rather than refusing
	// it outright.
	Degradation *Degradation `yaml:"degradation"`
	// Capture writes the exchanges the proxy handled as pcapng files,
	// for the flows its rules select.
	Capture *Capture `yaml:"capture"`
	// Fleet makes this node fetch its configuration bundle from a fleet
	// controller and report its status there (xproxy-fleet).
	Fleet *Fleet `yaml:"fleet"`
	// APIInventory records the endpoints the proxy serves and reports
	// shadow, zombie and superseded APIs.
	APIInventory *APIInventory `yaml:"api_inventory"`
	// Shedding enables adaptive load shedding by priority class when
	// present.
	Shedding *Shedding `yaml:"shedding"`
	// Maintenance serves a 503 to everyone but an allowlist while it is
	// on. The section sets the policy and the boot state; the state is
	// toggled at runtime (POST /v1/maintenance, xproxyctl maintenance).
	Maintenance *Maintenance `yaml:"maintenance"`
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
	// ShutdownTimeout bounds graceful drain on stop. On a reload it is
	// the minimum the superseded generation is kept for: one still
	// serving a request when it expires is kept until that request
	// ends, under a hard cap, so a long upload or a stream is not cut.
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
	// URI requests to destinations the policy allows), dns (a DNS
	// proxy) or smtp (a protocol-aware SMTP and submission proxy).
	Kind string `yaml:"kind"`
	// TCP configures a kind: tcp listener.
	TCP *TCPListener `yaml:"tcp"`
	// Forward configures a kind: forward listener.
	Forward *ForwardListener `yaml:"forward"`
	// DNS configures a kind: dns listener.
	DNS *DNSListener `yaml:"dns"`
	// SMTP configures a kind: smtp listener.
	SMTP *SMTPListener `yaml:"smtp"`
	// MQTT configures a kind: mqtt listener.
	MQTT *MQTTListener `yaml:"mqtt"`
	// SSH configures a kind: ssh listener.
	SSH *SSHListener `yaml:"ssh"`
	// FTP configures a kind: ftp listener.
	FTP *FTPListener `yaml:"ftp"`
	// Syslog configures a kind: syslog listener.
	Syslog *SyslogListener `yaml:"syslog"`
}

// SyslogListener is a syslog relay that reads what it forwards.
//
// A relay that forwards syslog without reading it is a pipe. The reason
// to read it is that almost every field is written by the sender and
// believed by the collector: the host name, the facility, the severity,
// the time. A message claiming to be auth.emerg from another machine
// costs nothing to send, and a message carrying a newline in its text
// becomes two records in any collector that frames on newlines — the
// second one saying whatever the sender wanted a record to say.
//
// So every message is parsed, and every message is re-emitted as RFC
// 5424 in one framing, whatever arrived. One dialect out is what makes
// the record a collector stores the record the relay decided about.
type SyslogListener struct {
	// Upstream is the collector pool. Required.
	Upstream string `yaml:"upstream"`
	// UDP also listens on the same address for datagrams, which is
	// what most senders still use (RFC 5426). Default true.
	UDP *bool `yaml:"udp"`
	// Framing accepted on the stream side: octet_counting (RFC 6587
	// section 3.4.1), non_transparent (section 3.4.2, line endings) or
	// auto. Default auto.
	Framing string `yaml:"framing"`
	// UpstreamFraming is what the relay writes: octet_counting or
	// non_transparent. Default octet_counting, which is the only one
	// that cannot be confused by what a message contains and the only
	// one RFC 5425 allows over TLS.
	UpstreamFraming string `yaml:"upstream_framing"`
	// TLSMode is implicit (TLS from the first octet on the stream
	// side, as RFC 5425 defines) or none. Default implicit when tls is
	// set.
	TLSMode string `yaml:"tls_mode"`
	// UpstreamTLSMode is none or implicit. Default none.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS verifies the collector when upstream_tls_mode is not
	// none.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// Hostname decides what the HOSTNAME field says: keep takes the
	// sender's word, observed replaces it with the address the message
	// arrived from, and annotate keeps it and records the address in
	// structured data. Default annotate — the sender's name is often
	// the useful one and is never the true one.
	Hostname string `yaml:"hostname"`
	// AllowFacilities and DenySeverities filter by what the message
	// claims to be. Empty allows everything.
	AllowFacilities []string `yaml:"allow_facilities"`
	DenyFacilities  []string `yaml:"deny_facilities"`
	// MinSeverity drops anything less severe, by name: "warning" keeps
	// emerg through warning. Empty keeps everything.
	MinSeverity string `yaml:"min_severity"`
	// AllowSenders restricts senders to these CIDRs. On UDP this is
	// the only authentication there is.
	AllowSenders []string `yaml:"allow_senders"`
	// DenyPatterns drop a message whose text matches, as RE2. It is a
	// filter, not a redaction: a message that matches does not arrive.
	DenyPatterns []string `yaml:"deny_patterns"`
	// Redact replaces what matches with a fixed string, so the record
	// still arrives without the part that should not be stored.
	Redact []SyslogRedaction `yaml:"redact"`
	// MaxMessageBytes bounds one message. Default 8192. RFC 5426
	// requires every receiver to take 480, and most estates send more.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// RateLimit is messages per second accepted from one sender, with
	// a burst. 0 is no limit. A log flood is a denial of service on
	// the collector and a way to push older records out of whatever
	// window it keeps.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// MaxSenders bounds the rate limit table. Default 65536.
	MaxSenders int `yaml:"max_senders"`
	// MaxConnections bounds stream connections. Default 1000.
	MaxConnections int `yaml:"max_connections"`
	// IdleTimeout closes a stream connection with no traffic. Default
	// 5m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// Queue is how many parsed messages wait for the collector.
	// Default 4096. When it is full the relay drops and counts rather
	// than blocking every sender behind one slow collector.
	Queue int `yaml:"queue"`
}

// SyslogRedaction replaces what matches a pattern in a message.
type SyslogRedaction struct {
	// Name appears in the structured data the relay adds, so a reader
	// knows something was taken out and which rule took it.
	Name string `yaml:"name"`
	// Pattern is RE2, matched against the message text.
	Pattern string `yaml:"pattern"`
	// With replaces every match. Default "[redacted]".
	With string `yaml:"with"`
}

// FTPListener is a protocol-aware FTP proxy. The proxy is an FTP server
// to the client and an FTP client to the target, and it mediates the
// data connection as well as the control one.
//
// The data connection is the reason this cannot be a layer 4 listener.
// Every transfer happens on a second connection whose address one side
// announces to the other, in the body of a reply. A proxy that forwards
// that reply has told the client to go round it: the file then travels
// between the client and the target with nothing in the middle, and the
// control connection it did read is a list of instructions for a
// transfer it never saw. So the addresses are rewritten, and the proxy
// is one end of both connections.
//
// The other reason is that FTP is old enough to have an attack named
// after it. A client can name any address in PORT, and a proxy that
// obeys is a port scanner and a relay for anyone who can log in — the
// bounce attack of CERT CA-1997-27. Active mode is therefore off by
// default, and when it is on the announced address has to be the
// client's own.
type FTPListener struct {
	// Upstream is the server pool. Required.
	Upstream string `yaml:"upstream"`
	// Banner replaces the target's 220 greeting. A banner is a legal
	// notice; the target's own greeting usually names its software and
	// version, which is a different thing.
	Banner string `yaml:"banner"`
	// TLSMode is starttls (the client may send AUTH TLS, and the
	// listener's tls section provides the certificate), implicit (TLS
	// from the first octet, as on 990) or none. Default starttls when
	// tls is set.
	TLSMode string `yaml:"tls_mode"`
	// RequireTLS refuses every command but the ones that get to TLS
	// until the control connection is encrypted. Defaults on wherever
	// TLS is reachable: a control connection in clear carries the
	// password.
	RequireTLS bool `yaml:"require_tls"`
	// UpstreamTLSMode is none, starttls or implicit. Default none.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS verifies the target when upstream_tls_mode is not
	// none.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// Commands a client may send. Everything else is refused with 502.
	// The default is every command this proxy understands the effect
	// of, which is the list it can hold to a policy.
	Commands []string `yaml:"commands"`
	// ReadOnly refuses every command that changes the server: STOR,
	// STOU, APPE, DELE, RNFR, RNTO, MKD, RMD, SITE, ALLO.
	ReadOnly bool `yaml:"read_only"`
	// AllowPaths are the paths a command may name, matched as the sftp
	// policy matches them: a glob where "*" does not cross a slash, or
	// a prefix ending in "/" or "/**" for a whole tree. They may carry
	// {user}, which is the login the client authenticated as. Empty
	// allows every path the deny list does not refuse.
	AllowPaths []string `yaml:"allow_paths"`
	// DenyPaths are refused whatever the allow list says.
	DenyPaths []string `yaml:"deny_paths"`
	// AllowExtensions and DenyExtensions decide what a file may be
	// called, on the commands that settle a name. Every extension a
	// name carries is read, so "invoice.pdf.exe" is an exe.
	AllowExtensions []string `yaml:"allow_extensions"`
	DenyExtensions  []string `yaml:"deny_extensions"`
	// MaxFileBytes bounds one transfer in either direction. 0 is no
	// bound. The connection is cut when it is passed, because a
	// transfer cannot be un-sent.
	MaxFileBytes int64 `yaml:"max_file_bytes"`
	// YARA scans what is uploaded. A match cuts the data connection
	// and, with action close, the session.
	YARA *YARAPolicy `yaml:"yara"`
	// AllowActive accepts PORT and EPRT. Default false. With it on, the
	// address announced must be the client's own, which is the only
	// form of active mode that is not a way to make the proxy connect
	// somewhere on request.
	AllowActive bool `yaml:"allow_active"`
	// DataAddress is the address the proxy advertises for passive data
	// connections. Default the address the control connection arrived
	// on, which is right unless the proxy is itself behind a NAT.
	DataAddress string `yaml:"data_address"`
	// DataPorts is the range the proxy listens on for passive data,
	// written "low-high". Default "0-0", which is any free port. A
	// range is what lets a firewall in front of the proxy be narrow.
	DataPorts string `yaml:"data_ports"`
	// DataTimeout bounds how long a data connection may be arranged
	// and not used. Default 30s.
	DataTimeout Duration `yaml:"data_timeout"`
	// MaxCommandLine bounds one control line. Default 4096.
	MaxCommandLine int `yaml:"max_command_line"`
	// MaxErrors ends the session after this many refused commands.
	// Default 10.
	MaxErrors int `yaml:"max_errors"`
	// MaxConnections bounds control connections on this listener.
	// Default 1000.
	MaxConnections int `yaml:"max_connections"`
	// IdleTimeout is no traffic on the control connection. Default
	// 5m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// SessionTimeout bounds a whole session however active. Default 0,
	// no bound.
	SessionTimeout Duration `yaml:"session_timeout"`
	// ProxyProtocol sends a PROXY protocol v2 header with the client
	// address to the target.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// AllowClients restricts clients to these CIDRs.
	AllowClients []string `yaml:"allow_clients"`
}

// SSHListener is an SSH bastion: the proxy is an SSH server to the
// client and an SSH client to the target, with its own host key, its
// own authentication and its own credential onwards.
//
// The two connections are the point. A jump host that forwards the
// stream cannot see which channel is a shell and which is a port
// forward, so the only policy it can hold is "may connect". Here every
// channel and every request inside the session is a decision: a service
// account can be given sftp to one directory and nothing else, and a
// port forward to a database is a rule rather than an assumption.
//
// It also means the target never sees the client's key. The client
// authenticates to the proxy; the proxy authenticates to the target
// with a credential the client never holds, so a key that leaves the
// estate is not a key that opens a server in it.
type SSHListener struct {
	// Upstream is the pool of target hosts. Required.
	Upstream string `yaml:"upstream"`
	// HostKeys are the proxy's own host key files, in OpenSSH or PEM
	// form. At least one is required. Clients pin these, so replacing
	// them is a fleet-wide known_hosts change: add the new key
	// alongside the old one and remove the old one later.
	HostKeys []string `yaml:"host_keys"`
	// AuthorizedKeys is an OpenSSH authorized_keys file of the public
	// keys that may connect. Options in the file are ignored; the
	// policy lives here.
	AuthorizedKeys string `yaml:"authorized_keys"`
	// UsersFile is a users file (as in forward.auth) for password
	// authentication. Public keys are the better answer; a bastion with
	// only passwords is one credential away from open.
	UsersFile string `yaml:"users_file"`
	// Banner is sent before authentication. A legal notice belongs
	// here; a version string does not.
	Banner string `yaml:"banner"`
	// ServerVersion is the identification string, which must begin with
	// "SSH-2.0-". Default "SSH-2.0-xproxy".
	ServerVersion string `yaml:"server_version"`
	// MaxAuthTries bounds authentication attempts per connection.
	// Default 3.
	MaxAuthTries int `yaml:"max_auth_tries"`
	// MaxSessions bounds connections on this listener. Default 1000.
	MaxSessions int `yaml:"max_sessions"`
	// MaxChannels bounds open channels per connection. Default 16.
	MaxChannels int `yaml:"max_channels"`
	// HandshakeTimeout bounds the key exchange and authentication.
	// Default 30s.
	HandshakeTimeout Duration `yaml:"handshake_timeout"`
	// IdleTimeout closes a connection with no traffic either way.
	// Default 30m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// SessionTimeout bounds a whole connection. 0 is no bound. Default
	// 0.
	SessionTimeout Duration `yaml:"session_timeout"`
	// AllowChannels are the channel types a client may open: session,
	// direct-tcpip (local port forwarding), direct-streamlocal (unix
	// socket forwarding). Default [session].
	AllowChannels []string `yaml:"allow_channels"`
	// AllowRequests are the session requests a client may send:
	// pty-req, env, shell, exec, subsystem, window-change, signal,
	// x11-req, auth-agent-req. Default everything but x11-req and
	// auth-agent-req, which each hand the target a channel back into
	// the client.
	AllowRequests []string `yaml:"allow_requests"`
	// AllowSubsystems are the subsystems a client may start. Default
	// [sftp].
	AllowSubsystems []string `yaml:"allow_subsystems"`
	// AllowCommands are RE2 patterns an exec command must match,
	// anchored as written. Empty allows any command when exec is in
	// allow_requests.
	AllowCommands []string `yaml:"allow_commands"`
	// Forward are the destinations direct-tcpip channels may reach:
	// "host:port", "*.suffix:port", "10.0.0.0/8:port", with "*" for any
	// port. Empty refuses every forward even when the channel type is
	// allowed, because a forward with no destination policy is a tunnel
	// to anywhere the target can reach.
	Forward []string `yaml:"forward"`
	// RemoteForward accepts tcpip-forward, which asks the target to
	// listen on the client's behalf. Default false: it turns a session
	// into an inbound path.
	RemoteForward bool `yaml:"remote_forward"`
	// UpstreamUser is the account on the target. Empty uses the name
	// the client authenticated as.
	UpstreamUser string `yaml:"upstream_user"`
	// UpstreamKeyFile is the private key the proxy authenticates to the
	// target with. Required.
	UpstreamKeyFile string `yaml:"upstream_key_file"`
	// UpstreamKnownHosts verifies the target's host key against an
	// OpenSSH known_hosts file. Required unless
	// upstream_insecure_host_key is set.
	UpstreamKnownHosts string `yaml:"upstream_known_hosts"`
	// UpstreamInsecureHostKey accepts any host key from the target.
	// Refused unless allow_insecure is also set, and logged at start:
	// it is the one setting here that turns the bastion into a machine
	// in the middle with nothing to notice it.
	UpstreamInsecureHostKey bool `yaml:"upstream_insecure_host_key"`
	AllowInsecure           bool `yaml:"allow_insecure"`
	// TrustedUserCAKeys is a file of CA public keys, in authorized_keys
	// form. A client may then authenticate with a certificate signed by
	// one of them instead of appearing in authorized_keys, and the
	// certificate's principals decide which entry of principals applies
	// to it. A certificate that has expired, is not yet valid, or does
	// not list the name the client is connecting as is refused.
	TrustedUserCAKeys string `yaml:"trusted_user_ca_keys"`
	// Principals give one key or one certificate principal its own
	// policy. Without them the listener's policy is the same for
	// everyone who gets past authentication, which is the policy a jump
	// host can hold and not much more.
	//
	// The first entry that matches decides. When any are configured, a
	// client matching none of them is refused: the list is the policy,
	// so falling back to the listener's would be the opposite of what
	// it says. An entry naming neither a fingerprint nor a certificate
	// principal is the default, and must be last.
	Principals []SSHPrincipal `yaml:"principals"`
	// AllowEnv are the environment variables a client may set, as names
	// or name prefixes ending in "*". Default TERM, LANG and LC_*. The
	// loader and interpreter variables (LD_*, BASH_ENV, PERL5OPT,
	// PYTHONPATH and their kin) are refused whatever this says: passing
	// one to a target is handing it code to run before the command the
	// policy approved.
	AllowEnv []string `yaml:"allow_env"`
	// AllowFileTransferCommands accepts exec commands that are file
	// transfer helpers: scp, rsync --server, sftp-server. Default false
	// when sftp is configured and true when it is not.
	//
	// The default is the point. An estate that carefully sets a
	// read-only sftp policy and then allows exec has left "scp -t" wide
	// open, because scp moves files without touching the sftp
	// subsystem at all.
	AllowFileTransferCommands *bool `yaml:"allow_file_transfer_commands"`
	// Recording writes what a session showed, and optionally what was
	// typed into it, to a file per channel.
	Recording *SSHRecording `yaml:"recording"`
	// MFA requires a second factor after the key or the password: the
	// client is told authentication partially succeeded and must then
	// answer a keyboard-interactive prompt with a one-time code.
	MFA *MFAPolicy `yaml:"mfa"`
	// SFTP inspects the sftp subsystem's own protocol; without it the
	// proxy can say only that a session may use sftp, which is the
	// difference between reading a file and deleting a tree.
	SFTP *SFTPPolicy `yaml:"sftp"`
	// ProxyProtocol sends a PROXY protocol v2 header with the client
	// address to the target before the SSH banner.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// AllowClients restricts clients to these CIDRs.
	AllowClients []string `yaml:"allow_clients"`
}

// SSHRecording records an interactive session to a file that can be
// replayed.
//
// A bastion's access log says a session happened; it cannot say what
// was done in it, because what was done is a stream of control
// sequences inside the channel. This writes that stream, in the
// asciicast v2 format, so the question "what did they actually run"
// has an answer that is watched rather than reconstructed.
//
// The files hold everything the session showed, which on an
// administrative session is a list of everything worth having: keys
// printed, configuration read, tokens echoed. They are treated the way
// the capture files are — the proxy user's alone, in a directory the
// operator names — and they are a reason to keep that directory as
// carefully as the credentials it will end up holding.
type SSHRecording struct {
	// Enabled is how a principal turns off a listener's recording; it
	// defaults to true wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Directory is where the files are written. Required. It must
	// exist: the proxy does not create it, because where these files
	// live is a decision to make rather than to inherit.
	Directory string `yaml:"directory"`
	// FilePrefix begins each file name. Default "session".
	FilePrefix string `yaml:"file_prefix"`
	// Input records what was typed as well as what was shown. Default
	// false, and it warns: a terminal's input stream carries what the
	// screen never showed, which includes every password typed into a
	// sudo or a su prompt. Recording output is watching over a
	// shoulder; recording input is a keylogger, and the difference
	// matters both to the people recorded and to whoever holds the
	// files.
	Input bool `yaml:"input"`
	// MaxFileBytes bounds one recording. Past it the session goes on
	// unrecorded and the file says so, rather than one command that
	// prints for an hour filling a disk. Default 33554432.
	MaxFileBytes int64 `yaml:"max_file_bytes"`
	// MaxFiles keeps this many recordings, removing the oldest this
	// listener wrote. Default 1000. It bounds what the proxy leaves
	// behind; anything that must be kept belongs somewhere the proxy
	// does not prune.
	MaxFiles int `yaml:"max_files"`
	// Commands records exec sessions too, not only the ones with a
	// terminal. Default true: a command run without a pty is still a
	// command run on the target.
	Commands *bool `yaml:"commands"`
}

// SFTPPolicy inspects the SFTP protocol inside an sftp subsystem
// channel. Refused requests are answered with a permission-denied
// status, so the session continues and the client is told which
// operation was refused rather than losing its connection.
type SFTPPolicy struct {
	// ReadOnly refuses every request that changes the server: write,
	// setstat, remove, mkdir, rmdir, rename, symlink, an open with any
	// writing flag, and the extensions whose meaning the proxy does not
	// know.
	ReadOnly bool `yaml:"read_only"`
	// AllowPaths are the paths a request may name: a glob where "*"
	// does not cross a slash, or a prefix ending in "/" or "/**" for a
	// whole tree. Empty allows every path the deny list does not
	// refuse.
	//
	// A pattern may carry {user} or {principal}, which are the login
	// the session authenticated as and the principals entry that
	// covers it. They are substituted once per session, which is what
	// lets one listener say "your own directory and no other" instead
	// of one list naming everybody's.
	AllowPaths []string `yaml:"allow_paths"`
	// DenyPaths are refused whatever the allow list says. They take
	// the same {user} and {principal} substitutions.
	DenyPaths []string `yaml:"deny_paths"`
	// DenyOperations refuses operations by name (open, read, write,
	// remove, rename, symlink, setstat, ...), on top of read_only.
	DenyOperations []string `yaml:"deny_operations"`
	// AllowExtensions are the file extensions a name may carry, without
	// the dot and compared without case. Empty allows every extension
	// the deny list does not refuse. It is checked on open, and on both
	// names of a rename or a symlink, which are the requests that
	// decide what a file is called.
	AllowExtensions []string `yaml:"allow_extensions"`
	// DenyExtensions are refused whatever the allow list says. A name
	// is read for every extension it carries, so "invoice.pdf.exe" is
	// an exe whatever the list allows.
	DenyExtensions []string `yaml:"deny_extensions"`
	// MaxFileBytes bounds what one open file may be written. 0 is no
	// bound. It is counted per handle, from the highest offset a write
	// reaches, so a client cannot walk past it by writing out of
	// order.
	MaxFileBytes int64 `yaml:"max_file_bytes"`
	// MaxOpenFiles bounds the handles one session may have open at
	// once, which is what the per file state costs. Default 256.
	MaxOpenFiles int `yaml:"max_open_files"`
	// YARA scans what is written, per file rather than per stream: a
	// rule about a file's first bytes is a rule about a file, and two
	// uploads interleaved on one channel are two files. A match refuses
	// that write; directions is not read here, because only what the
	// client writes is a file this proxy is choosing to accept.
	YARA *YARAPolicy `yaml:"yara"`
	// MaxPacketSize bounds one SFTP packet. Default 262144, a little
	// over the 32 KiB read and write sizes clients use.
	MaxPacketSize int `yaml:"max_packet_size"`
}

// MQTTListener is a protocol-aware MQTT proxy for 3.1.1 and 5.0. It
// reads every control packet, decides on the ones that carry a policy
// question — who is connecting, what they publish, what they subscribe
// to — and forwards the rest untouched.
//
// The reason it is not a layer 4 listener: an MQTT broker's
// authorisation is per topic, and a topic is a string inside a packet.
// Without reading the packets there is no place to say that a device
// may publish its own telemetry and nothing else, and every device that
// holds a broker credential holds the whole tree.
type MQTTListener struct {
	// Upstream is the broker pool. Required.
	Upstream string `yaml:"upstream"`
	// TLSMode is implicit (TLS from the first octet, as on 8883, and
	// needs the listener's tls section) or none. Default implicit when
	// tls is set.
	TLSMode string `yaml:"tls_mode"`
	// UpstreamTLSMode is none or implicit. Default none.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS verifies the broker when upstream_tls_mode is not
	// none.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// Versions are the protocol versions accepted: "3.1.1", "5.0".
	// Default both. A version the proxy does not parse cannot be
	// checked, so anything else is refused at CONNECT.
	Versions []string `yaml:"versions"`
	// RequireAuth refuses a CONNECT without a username. The broker
	// still verifies the password; this only stops an anonymous session
	// reaching it. Default false.
	RequireAuth bool `yaml:"require_auth"`
	// AllowEmptyClientID accepts the empty client id, which 3.1.1 allows
	// with a clean session and 5.0 answers with an assigned one. Default
	// true; turning it off is what makes every session identifiable in
	// the logs.
	AllowEmptyClientID *bool `yaml:"allow_empty_client_id"`
	// MaxClientID bounds the client id. Default 128.
	MaxClientID int `yaml:"max_client_id"`
	// ClientIDPattern is an RE2 the client id must match, anchored as
	// written. Empty accepts any.
	ClientIDPattern string `yaml:"client_id_pattern"`
	// MaxPacketSize bounds one control packet including its header, and
	// is what a 5.0 client is told in CONNACK. Default 1048576.
	MaxPacketSize int `yaml:"max_packet_size"`
	// MaxTopicLength and MaxTopicLevels bound a topic or filter.
	// Defaults 512 and 16.
	MaxTopicLength int `yaml:"max_topic_length"`
	MaxTopicLevels int `yaml:"max_topic_levels"`
	// PublishAllow and PublishDeny are topic filters checked against
	// the topic of every PUBLISH from the client, and against the will
	// topic of its CONNECT. Deny wins. An empty allow list allows
	// everything the deny list does not refuse.
	PublishAllow []string `yaml:"publish_allow"`
	PublishDeny  []string `yaml:"publish_deny"`
	// SubscribeAllow and SubscribeDeny are topic filters checked
	// against every filter a client subscribes to. A subscription is
	// allowed only when an entry of the allow list covers everything it
	// could deliver, and refused when it could reach anything denied —
	// a filter is not a topic, and matching it as one would let "#"
	// through an allow list of "sensors/+".
	SubscribeAllow []string `yaml:"subscribe_allow"`
	SubscribeDeny  []string `yaml:"subscribe_deny"`
	// MaxSubscriptions bounds live subscriptions per session. Default
	// 64.
	MaxSubscriptions int `yaml:"max_subscriptions"`
	// AllowRetain accepts PUBLISH with the retain flag. A retained
	// message outlives the session that set it, so a device that can
	// retain can leave something behind. Default true.
	AllowRetain *bool `yaml:"allow_retain"`
	// AllowWildcardSubscribe accepts "+" and "#" in a subscription at
	// all. Default true; with an allow list it rarely needs turning
	// off, and without one it is the difference between a client
	// reading its own topics and reading the estate's.
	AllowWildcardSubscribe *bool `yaml:"allow_wildcard_subscribe"`
	// KeepAliveMax bounds the keep alive a client asks for, so a
	// session cannot sit idle indefinitely on the broker's side.
	// 0 accepts any. Default 0.
	KeepAliveMax Duration `yaml:"keep_alive_max"`
	// MaxConnections bounds sessions on this listener. Default 10000.
	MaxConnections int `yaml:"max_connections"`
	// ConnectTimeout bounds the wait for the CONNECT packet. Default
	// 30s, which is what 3.1.1 section 3.1 asks a server to do.
	ConnectTimeout Duration `yaml:"connect_timeout"`
	// IdleTimeout closes a session with no packet in either direction.
	// Default 10m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// Action on a refused PUBLISH or SUBSCRIBE: disconnect (the
	// default) ends the session, drop refuses the one packet and
	// acknowledges it so the session continues.
	Action string `yaml:"action"`
	// ProxyProtocol sends a PROXY protocol v2 header with the client
	// address to the broker.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// AllowClients restricts clients to these CIDRs.
	AllowClients []string `yaml:"allow_clients"`
}

// SMTPListener is a protocol-aware SMTP proxy: it speaks the session to
// the client, speaks a second one to the upstream, and decides for
// itself where each command and each message ends. That is the point of
// it. A layer 4 splice would carry the same bytes, but the client and
// the mail server would each parse them on their own, and every
// SMTP smuggling bug there has ever been lives in the gap between two
// such parses.
//
// It terminates STARTTLS (RFC 3207) for the client and may start its
// own to the upstream, so the hop the proxy makes is never the plaintext
// one by accident.
type SMTPListener struct {
	// Upstream is the pool to relay to. Required.
	Upstream string `yaml:"upstream"`
	// TLSMode is how the client reaches this listener: starttls (plain
	// on 25 or 587, upgraded by the STARTTLS command), implicit (TLS
	// from the first octet, as on 465) or none. starttls and implicit
	// need the listener's tls section. Default starttls when tls is set
	// and none otherwise.
	TLSMode string `yaml:"tls_mode"`
	// RequireTLS refuses AUTH, MAIL and VRFY until the session is
	// encrypted. On a submission listener this is the difference between
	// offering TLS and requiring it. Default true when TLSMode is
	// starttls or implicit.
	RequireTLS bool `yaml:"require_tls"`
	// RequireAuth refuses MAIL until the session has authenticated,
	// which keeps a submission listener from relaying for anyone who can
	// reach it. Default false: a listener taking inbound mail for its
	// own domains has no authentication to require.
	RequireAuth bool `yaml:"require_auth"`
	// Banner replaces the upstream greeting. The proxy's own name
	// belongs here; leaving the upstream's banner in place tells every
	// prober which mail server is behind this address.
	Banner string `yaml:"banner"`
	// Hostname is the name the proxy gives as its own in a synthesised
	// greeting and in its EHLO to the upstream. Default the banner's
	// first word, else the system hostname.
	Hostname string `yaml:"hostname"`
	// MaxCommandLine bounds a command line including CRLF. Default 512,
	// the limit in RFC 5321 section 4.5.3.1.1.
	MaxCommandLine int `yaml:"max_command_line"`
	// MaxTextLine bounds a message line including CRLF. Default 1000.
	MaxTextLine int `yaml:"max_text_line"`
	// MaxMessageSize bounds one message in octets and is advertised as
	// the SIZE capability. 0 keeps the upstream's own limit. Default 0.
	MaxMessageSize int64 `yaml:"max_message_size"`
	// MaxRecipients bounds RCPT commands per message. Default 100.
	MaxRecipients int `yaml:"max_recipients"`
	// MaxMessages bounds messages per connection. Default 100.
	MaxMessages int `yaml:"max_messages"`
	// MaxErrors closes the session after this many refused commands,
	// which is what stops a prober walking the command space. Default 10.
	MaxErrors int `yaml:"max_errors"`
	// MaxConnections bounds sessions on this listener. Default 1000.
	MaxConnections int `yaml:"max_connections"`
	// ReadTimeout bounds waiting for one command or message line.
	// Default 5m, the minimum RFC 5321 section 4.5.3.2 asks for.
	ReadTimeout Duration `yaml:"read_timeout"`
	// SessionTimeout bounds a whole session. Default 30m.
	SessionTimeout Duration `yaml:"session_timeout"`
	// Commands is the verbs a client may send. Everything else is
	// refused with 502 and counts towards max_errors. Default: EHLO,
	// HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT, AUTH, STARTTLS.
	Commands []string `yaml:"commands"`
	// HideCapabilities are EHLO keywords stripped from the upstream's
	// answer, on top of the ones the proxy always removes (STARTTLS,
	// which it answers itself, and CHUNKING, whose BDAT has no dot
	// terminator to agree on). Default: none.
	HideCapabilities []string `yaml:"hide_capabilities"`
	// BareNewlines is reject (the default) or convert. A line ended by
	// LF alone is forbidden by RFC 5321 section 2.3.8 and is how a
	// message ends in one place for the proxy and another for the next
	// hop; convert repairs it to CRLF instead of refusing the session,
	// which is safe because the proxy re-emits every line itself.
	BareNewlines string `yaml:"bare_newlines"`
	// UpstreamTLSMode is how the proxy reaches the upstream: none,
	// starttls or implicit. Default none, which is right when the hop
	// is inside a trusted network and wrong everywhere else.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS verifies the upstream when upstream_tls_mode is not
	// none.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// ProxyProtocol sends a PROXY protocol v2 header to the upstream so
	// it logs the client address rather than the proxy's.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// AllowClients restricts clients to these CIDRs. Empty allows all,
	// which is right for inbound mail and wrong for submission.
	AllowClients []string `yaml:"allow_clients"`
	// XClientName sends the client address to the upstream with the
	// XCLIENT command (a Postfix extension) after EHLO, when the
	// upstream advertises it.
	XClient bool `yaml:"xclient"`
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
	// DoQ also serves DNS over QUIC (RFC 9250) on this listener's
	// address over UDP. Needs tls; the certificate is shared with DoT
	// and DoH, since they are the same service.
	DoQ bool `yaml:"doq"`
	// Discovery advertises this resolver's encrypted endpoints at
	// _dns.resolver.arpa (RFC 9462), so a client handed this address by
	// DHCP can upgrade itself from plaintext DNS.
	Discovery []DNSDesignated `yaml:"discovery"`
	// Records are SVCB and HTTPS records this resolver answers itself,
	// most usefully the ECH configuration of a name this proxy
	// terminates.
	Records []DNSRecord `yaml:"records"`
	// TunnelDetection watches for data leaving inside the query names.
	TunnelDetection *DNSTunnel `yaml:"tunnel_detection"`
}

// DNSTunnel configures detection of data leaving inside DNS queries.
//
// A tunnel puts its payload in the name — a few dozen encoded
// characters per label — and takes the answer back in a TXT record.
// The domain is delegated to the other end, so every query reaches
// them whatever this resolver forwards to: blocking the upstream does
// nothing, and a block list only helps if somebody already knew the
// name.
//
// No single signal decides here, because each one has honest traffic
// behind it. A content delivery network's names really are random. A
// reputation service really does encode a hash into a name and answer
// TXT. A laptop waking up really does produce a burst of NXDOMAIN.
// What does not happen by accident is several of them at once, under
// one registered domain, from one client — which is what min_signals
// says out loud instead of burying it in a weighting nobody can read.
type DNSTunnel struct {
	// Window is the period the signals are measured over. Default 5m.
	Window Duration `yaml:"window"`
	// MinQueries is how many queries a client must send under one
	// domain before any judgement is made. Default 50: below it there
	// is not enough to be wrong about.
	MinQueries int `yaml:"min_queries"`
	// MinSignals is how many signals must fire together. Default 2.
	// One is a false positive generator; this is the setting that
	// decides whether this feature helps or cries wolf.
	MinSignals int `yaml:"min_signals"`
	// Entropy is the bits per character at which a label is counted as
	// encoded rather than named. Default 3.6: words sit below it, and
	// base32 and base64 payloads run near 5 and 6.
	Entropy float64 `yaml:"entropy"`
	// EntropyShare is the share of a domain's queries that must reach
	// it. Default 0.5; an explicit 0 switches the signal off.
	EntropyShare *float64 `yaml:"entropy_share"`
	// MinLabelLength is the shortest label measured. Default 12: a
	// short string cannot carry much and its entropy is mostly noise.
	MinLabelLength int `yaml:"min_label_length"`
	// DistinctSubdomains is the cardinality under one domain that
	// belongs to a tunnel rather than a service. Default 50; an
	// explicit 0 switches the signal off.
	DistinctSubdomains *int `yaml:"distinct_subdomains"`
	// TXTShare is the share of queries asking for the record types a
	// tunnel returns data in (TXT, NULL, CNAME, MX, SRV). Default 0.5;
	// an explicit 0 switches the signal off.
	TXTShare *float64 `yaml:"txt_share"`
	// NXDOMAINShare is the share answering NXDOMAIN. Default 0.5; an
	// explicit 0 switches the signal off.
	NXDOMAINShare *float64 `yaml:"nxdomain_share"`
	// PayloadBytes is the encoded bytes below the domain in a window,
	// counting each name once: the exfiltration itself rather than a
	// proxy for it. Default 4096; an explicit 0 switches the signal off.
	//
	// These five are pointers so that a 0 an operator wrote means what
	// it says. A plain zero value cannot be told apart from a key that
	// was never set, and a signal silently switched back on is a
	// detector doing something other than what its configuration reads.
	PayloadBytes *int64 `yaml:"payload_bytes"`
	// AllowDomains are never judged, in the forms the block list takes.
	// Reputation services, antivirus lookups and telemetry that
	// legitimately look exactly like this belong here.
	AllowDomains []string `yaml:"allow_domains"`
	// Action is log (default) or block. block answers NXDOMAIN for the
	// detected domain, for the client it was detected for, until the
	// cooldown runs out.
	Action string `yaml:"action"`
	// Cooldown is how long that lasts. Default 10m.
	Cooldown Duration `yaml:"cooldown"`
	// MaxTracked bounds the windows held. Default 65536. The key is a
	// client and a domain and both are chosen by whoever sends the
	// queries, so this is not a tuning knob but the thing that stops
	// the detector being the attack.
	MaxTracked int `yaml:"max_tracked"`
}

// DNSDesignated is one encrypted endpoint advertised by discovery.
type DNSDesignated struct {
	// Transport is dot, doh or doq.
	Transport string `yaml:"transport"`
	// Name is the certificate name clients verify. It must be a name
	// the endpoint's certificate covers, or the upgrade fails closed.
	Name string `yaml:"name"`
	// Port the endpoint listens on. Default 853 for dot and doq, 443
	// for doh.
	Port int `yaml:"port"`
	// DoHPath is the URI template for a doh endpoint. Default
	// /dns-query{?dns}.
	DoHPath string `yaml:"doh_path"`
	// IPv4 and IPv6 are address hints, so a client need not resolve the
	// name it was just handed.
	IPv4 []string `yaml:"ipv4"`
	IPv6 []string `yaml:"ipv6"`
	// TTL of the discovery records. Default 300.
	TTL int `yaml:"ttl"`
}

// DNSRecord is one locally served SVCB or HTTPS record.
type DNSRecord struct {
	// Name the record is published for.
	Name string `yaml:"name"`
	// Type is https (default) or svcb.
	Type string `yaml:"type"`
	// Priority 0 makes it an alias record, which takes no parameters.
	Priority int `yaml:"priority"`
	// Target is the endpoint name; "." means the owner name itself.
	Target string `yaml:"target"`
	// TTL in seconds. Default 300.
	TTL int `yaml:"ttl"`
	// Params are service parameters in presentation form:
	// {alpn: "h2,h3", port: "443", ech: "AEr+DQ...", ipv4hint: "..."}.
	Params map[string]string `yaml:"params"`
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
	// Intercept terminates TLS inside a CONNECT tunnel, so the proxy
	// sees the requests rather than only the destination.
	Intercept *ForwardIntercept `yaml:"intercept"`
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
	// SOCKS5 also accepts SOCKS5 (RFC 1928) on this listener. The two
	// protocols share the port: a greeting starts with the version byte
	// and an HTTP request with a method, so one byte tells them apart.
	// Destinations, ports, credentials, bans and logging are the same.
	SOCKS5 bool `yaml:"socks5"`
	// SOCKSUDP allows UDP ASSOCIATE, which is how DNS and QUIC travel
	// through a SOCKS proxy. Each association is bound to the client
	// address that opened it and dies with its control connection.
	SOCKSUDP bool `yaml:"socks_udp"`
	// Masque enables the MASQUE proxying protocols on this listener.
	Masque *Masque `yaml:"masque"`
}

// Masque configures UDP proxying (RFC 9298) and IP proxying (RFC 9484)
// over extended CONNECT. Both need HTTP/2 or HTTP/3, so the listener
// needs tls with h2 in its protocols.
type Masque struct {
	// UDP accepts connect-udp. The destination policy applies to each
	// association exactly as it does to a CONNECT tunnel.
	UDP bool `yaml:"udp"`
	// IP accepts connect-ip. It also needs ip_device, ip_assign and
	// ip_routes: a userspace process cannot put an arbitrary IP packet
	// on the wire without a tunnel device.
	IP bool `yaml:"ip"`
	// MaxSessions bounds concurrent MASQUE sessions. Default 1024.
	MaxSessions int `yaml:"max_sessions"`
	// IPDevice is an existing tun interface the operator created,
	// addressed, routed and firewalled (Linux only).
	IPDevice string `yaml:"ip_device"`
	// IPAssign are the prefixes a client is told to use as its source
	// address; packets from anything else are dropped.
	IPAssign []string `yaml:"ip_assign"`
	// IPRoutes are the ranges a client may send to; packets to
	// anything else are dropped.
	IPRoutes []string `yaml:"ip_routes"`
}

// ForwardIntercept terminates TLS inside a CONNECT tunnel: the proxy
// answers the client's handshake with a certificate it signs itself,
// opens its own TLS connection to the destination, and relays what
// passes between them in clear.
//
// This is the one feature here that makes a proxy less safe if it is
// built carelessly, because it replaces a connection the client
// verified end to end with two connections the client cannot see past.
// Three things follow, and none of them is optional:
//
// The proxy verifies the real server itself, with the ordinary rules,
// and a client only ever sees a forged certificate for a server whose
// own certificate verified. verify_upstream exists as a key so that
// turning it off is a decision somebody wrote down; it warns loudly,
// because an interception proxy that does not verify turns every
// client's verified connection into an unverified one while leaving
// the padlock in place.
//
// The signing key can impersonate every site to every client that
// trusts the CA. It is refused if anybody but its owner can read it.
//
// And some traffic must not be read at all, whatever the estate's
// policy is. bypass_hosts is where that is written, and it is checked
// before anything is decrypted.
type ForwardIntercept struct {
	// CACertFile and CAKeyFile are the signing identity. Clients have
	// to trust the certificate, which is what makes this visible to
	// the people whose traffic it reads.
	CACertFile string `yaml:"ca_cert_file"`
	CAKeyFile  string `yaml:"ca_key_file"`
	// Hosts are the destinations to intercept: a name, *.suffix, or a
	// CIDR. Empty intercepts every destination the listener allows,
	// which is a large decision to leave implicit — it warns.
	Hosts []string `yaml:"hosts"`
	// BypassHosts are never intercepted, whatever hosts says. This is
	// where the traffic an estate must not read goes: banking, health,
	// anything carrying somebody's own credentials.
	BypassHosts []string `yaml:"bypass_hosts"`
	// VerifyUpstream verifies the destination's certificate with the
	// ordinary rules. Default true, and false warns.
	VerifyUpstream *bool `yaml:"verify_upstream"`
	// CAFile is the roots the destination is verified against. Empty
	// uses the system store.
	CAFile string `yaml:"ca_file"`
	// MinVersion of the TLS the proxy speaks to the destination.
	// Default 1.2.
	MinVersion string `yaml:"min_version"`
	// LeafTTL is how long an issued certificate is valid. Default 24h:
	// a forged certificate that outlives the proxy that made it is one
	// somebody else can still be holding.
	LeafTTL Duration `yaml:"leaf_ttl"`
	// MaxCache bounds the issued certificates kept in memory. Default
	// 1024.
	MaxCache int `yaml:"max_cache"`
	// ALPN is what the proxy offers the destination and accepts from
	// the client. Default ["http/1.1"]: a stream the proxy relays is
	// one it has to be able to read, and offering h2 without reading
	// h2 is how an interception proxy breaks a site.
	ALPN []string `yaml:"alpn"`
	// YARA scans the decrypted stream, which is the point of doing any
	// of this.
	YARA *YARAPolicy `yaml:"yara"`
}

// ForwardAuth is the credential source of a forward listener.
type ForwardAuth struct {
	// UsersFile holds name:hash lines from xproxyctl htpasswd. Re-read on
	// reload.
	UsersFile string `yaml:"users_file"`
	// Realm is sent in Proxy-Authenticate. Default "proxy".
	Realm string `yaml:"realm"`
}

// WebSocketGuard is the frame policy of an upgraded connection. Every
// bound applies to both directions; the rate applies to the client,
// whose traffic the estate does not control.
type WebSocketGuard struct {
	// MaxFrameBytes is the largest single frame. Default 1 MiB.
	MaxFrameBytes int64 `yaml:"max_frame_bytes"`
	// MaxMessageBytes is the largest reassembled message. Default 8 MiB.
	MaxMessageBytes int64 `yaml:"max_message_bytes"`
	// MessagesPerSecond bounds the client's message rate. 0 is no bound.
	MessagesPerSecond int `yaml:"messages_per_second"`
	// AllowOpcodes names the opcodes a peer may use. Default text,
	// binary, close, ping and pong.
	AllowOpcodes []string `yaml:"allow_opcodes"`
	// AllowSubprotocols restricts the negotiated Sec-WebSocket-Protocol.
	AllowSubprotocols []string `yaml:"allow_subprotocols"`
	// RequireMasked enforces RFC 6455 masking: set on client frames,
	// clear on server frames. Default true.
	RequireMasked *bool `yaml:"require_masked"`
	// ValidateUTF8 refuses a text message that is not UTF-8. Default
	// true.
	ValidateUTF8 *bool `yaml:"validate_utf8"`
	// Inspect is none, text or all: which messages are kept for
	// pattern matching. Default text.
	Inspect string `yaml:"inspect"`
	// MaxInspectBytes bounds the prefix of a message kept for matching.
	// Default 64 KiB.
	MaxInspectBytes int64 `yaml:"max_inspect_bytes"`
	// DenyPatterns are RE2 patterns matched against inspected messages.
	DenyPatterns []string `yaml:"deny_patterns"`
	// Action is close or log. Default close.
	Action string `yaml:"action"`
	// CloseCode overrides the close code sent on a violation.
	CloseCode int `yaml:"close_code"`
}

// Masked reports the effective require_masked.
func (w *WebSocketGuard) Masked() bool { return w == nil || w.RequireMasked == nil || *w.RequireMasked }

// UTF8 reports the effective validate_utf8.
func (w *WebSocketGuard) UTF8() bool { return w == nil || w.ValidateUTF8 == nil || *w.ValidateUTF8 }

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
	// YARA applies rules to the bytes of each connection. It does not
	// apply to QUIC flows: those are encrypted, and a rule over
	// ciphertext matches nothing.
	YARA *YARAPolicy `yaml:"yara"`
}

// YARAPolicy applies YARA rules to a stream. The engine is a subset of
// the language implemented in Go — this proxy links no C library into
// the data plane — and what it supports is listed in the reference;
// anything outside it is refused at load rather than quietly matching
// nothing.
//
// On a stream, two things differ from scanning a file. A rule is
// reported the first time its condition becomes true, because a
// decision that arrives after the last byte is a decision about a
// transfer that already happened. And filesize means the bytes seen so
// far, which is the only honest reading when there is no end yet.
type YARAPolicy struct {
	// RulesFile or RulesDir is where the rules are. Exactly one is
	// required. A directory takes every .yar and .yara file in it, in
	// name order, as one set.
	RulesFile string `yaml:"rules_file"`
	RulesDir  string `yaml:"rules_dir"`
	// Action on a match: close (the default) ends the connection, log
	// records it and lets the bytes through.
	Action string `yaml:"action"`
	// Directions are the sides scanned: client (what the client sends)
	// and upstream (what comes back). Default both. Scanning one side
	// halves the work where only one carries what the rules are about.
	Directions []string `yaml:"directions"`
	// MaxWindow is the buffer one direction scans in. It also bounds
	// the overlap carried between windows, which is what lets a match
	// straddling two reads still be found. Default 262144.
	MaxWindow int `yaml:"max_window"`
	// MaxBytes stops scanning a direction after this many bytes; the
	// connection carries on unscanned. 0 scans everything. Default
	// 33554432, which covers the start of a transfer without turning a
	// long download into unbounded work.
	MaxBytes int64 `yaml:"max_bytes"`
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
	// KeyExchange is the offered key agreement groups in preference
	// order: X25519MLKEM768 (post-quantum hybrid), X25519, P-256, P-384,
	// P-521. Empty means the default, which leads with the hybrid.
	KeyExchange []string `yaml:"key_exchange"`
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
	// ECH accepts Encrypted Client Hello on this listener.
	ECH *ECH `yaml:"ech"`
}

// ECH configures Encrypted Client Hello: the client encrypts the real
// ClientHello (SNI included) to a key published in DNS, and sends it
// inside an outer hello that names a shared public name.
type ECH struct {
	// Keys are the configurations this listener can decrypt. Several
	// are live at once during a rotation.
	Keys []ECHKey `yaml:"keys"`
	// Require refuses a handshake that did not use ECH. It cuts off
	// every client that has not got the key — including one whose DNS
	// answer was stripped — so it is for a listener that exists only
	// for ECH clients.
	Require bool `yaml:"require"`
}

// ECHKey is one ECH configuration and its private key.
type ECHKey struct {
	// ConfigFile holds the ECHConfig, raw or base64, as written by
	// `xproxyctl ech keygen`.
	ConfigFile string `yaml:"config_file"`
	// KeyFile holds the X25519 private key, raw, base64 or hex. It
	// must not be world readable.
	KeyFile string `yaml:"key_file"`
	// Retry offers this config to a client whose key was stale, which
	// is how a rotation heals itself. Default true.
	Retry *bool `yaml:"retry"`
}

// RetryOffered reports whether this key is sent as a retry config.
func (k *ECHKey) RetryOffered() bool { return k == nil || k.Retry == nil || *k.Retry }

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
	// RejectBackslashes refuses a backslash anywhere in the decoded path.
	// IIS, Apache on Windows and .NET read it as a separator while this
	// proxy reads it as an ordinary character, so "/static\\..\\admin" is
	// one opaque segment under /static here and "/admin" there: the
	// route's access lists, filters, WAF profile and rate limits are all
	// skipped for a resource the origin serves. Default true.
	RejectBackslashes *bool `yaml:"reject_backslashes"`
	// RejectPathParams refuses a ";" in the decoded path. Tomcat, Jetty,
	// JBoss and Spring strip a path parameter from every segment before
	// mapping, so "/admin;x" or "/admin;jsessionid=..." misses this
	// proxy's /admin route and its policy while the origin serves
	// /admin. Default true.
	RejectPathParams *bool `yaml:"reject_path_params"`
	// RejectDotSegments refuses a "." or ".." segment in the decoded path
	// (including the "..;" form servlet containers resolve). Routing
	// resolves dot segments while the upstream receives the path as sent,
	// so "/static/../admin" would be routed as "/admin" but reach the
	// origin unchanged; browsers never send such paths. Default true.
	RejectDotSegments *bool `yaml:"reject_dot_segments"`
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

// DotSegments reports the setting with its default.
func (n *Normalization) DotSegments() bool {
	return n.RejectDotSegments == nil || *n.RejectDotSegments
}

// Backslashes reports the setting with its default.
func (n *Normalization) Backslashes() bool {
	return n.RejectBackslashes == nil || *n.RejectBackslashes
}

// PathParams reports the setting with its default.
func (n *Normalization) PathParams() bool {
	return n.RejectPathParams == nil || *n.RejectPathParams
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
	// MaxBufferedBodyBytes is the process-wide ceiling on request bodies
	// held in memory at once by the features that materialise one
	// (upload_guard, sensitive_data, account_guard, openapi, graphql,
	// body_rewrite, wasm, the WAF's body inspection, a virtual patch's
	// body pattern, a mirrored request). Default 512 MiB; 0 is
	// unbounded.
	//
	// Each of those is bounded per request, and the product was the real
	// ceiling: max_connections_per_ip times max_body_bytes is about
	// 2.5 GiB of heap from one address at the defaults, sent slowly
	// enough to stay inside read_timeout. A request that does not fit
	// the budget is refused with 503 rather than buffered.
	MaxBufferedBodyBytes int64 `yaml:"max_buffered_body_bytes"`
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
	// RedactClientAddress runs a span's client.address through
	// logging.redaction's client_ip rule. Default true.
	//
	// A span is not a log line, so nothing took it through the
	// redactor: a deployment that turned redaction on to pseudonymise
	// addresses still exported the full address to its trace collector,
	// and the access log carries the trace id, so holding both stores
	// reversed the pseudonymisation by design.
	RedactClientAddress *bool `yaml:"redact_client_address"`
}

// RedactsClientAddress reports the setting with its default.
func (t *Tracing) RedactsClientAddress() bool {
	return t == nil || t.RedactClientAddress == nil || *t.RedactClientAddress
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
	// SamplePercent logs this percentage of access lines (0 to 100,
	// default 100). Metrics count every request regardless. Access stream
	// only.
	SamplePercent *float64 `yaml:"sample_percent"`
	// AlwaysLog logs a line whatever the sampling when the response is a
	// 4xx/5xx or the request was denied. Default true. Access stream only.
	AlwaysLog *bool `yaml:"always_log"`
	// Fields, when set, keeps only these attributes on the access line
	// (request_id, client_ip, method, host, path, status, ...); empty
	// keeps them all. Access stream only.
	Fields []string `yaml:"fields"`
}

// AccessSamplePercent returns the effective sampling percentage.
func (l *LogStream) AccessSamplePercent() float64 {
	if l.SamplePercent == nil {
		return 100
	}
	return *l.SamplePercent
}

// AlwaysLogsErrors reports whether denied and error responses are always
// logged despite sampling.
func (l *LogStream) AlwaysLogsErrors() bool { return l.AlwaysLog == nil || *l.AlwaysLog }

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
	// RetryBudget caps retries as a share of live traffic so a struggling
	// pool is not buried under a retry storm. Without it every retry the
	// Retries budget allows is sent.
	RetryBudget *RetryBudget `yaml:"retry_budget"`
	// Hedge sends a second copy of an idempotent request to another
	// endpoint when the first is slow, and takes whichever answers first,
	// trading a little extra load for a shorter tail latency.
	Hedge *Hedge `yaml:"hedge"`
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

// RetryBudget limits the rate of retries relative to live requests. A
// retry (or a hedged copy) is only sent while the number of retries in
// flight to the pool stays below Percent of the requests in flight, with
// MinConcurrency always allowed so a low-traffic pool can still retry.
type RetryBudget struct {
	// Percent caps retries in flight at this share of requests in flight.
	// Default 20; 1 to 1000.
	Percent float64 `yaml:"percent"`
	// MinConcurrency is the number of concurrent retries always allowed
	// regardless of Percent, so a pool with little live traffic can still
	// retry. Default 3; 1 to 10000.
	MinConcurrency int `yaml:"min_concurrency"`
}

// Hedge sends extra copies of a slow idempotent request to other
// endpoints. The first usable response wins and the others are cancelled.
type Hedge struct {
	// Delay is how long to wait for the request in flight before sending
	// the next copy. 1ms to 1m.
	Delay Duration `yaml:"delay"`
	// Max is the number of extra copies beyond the first, each keyed to a
	// distinct endpoint and gated by the retry budget. Default 1; 1 to 4.
	Max int `yaml:"max"`
}

// Endpoint is a single upstream address.
type Endpoint struct {
	Address string `yaml:"address"`
	Weight  int    `yaml:"weight"`
	// Canary marks the endpoint as the pool's canary: it receives the
	// requests the pool's canary policy selects and no others.
	Canary bool `yaml:"canary"`
}

// Discovery resolves a pool's endpoints from DNS or an HTTP registry.
type Discovery struct {
	// Type is dns (A and AAAA records of Name, each with Port), srv (SRV
	// records of Name; targets and ports come from the records, the lowest
	// priority group is used and record weights become endpoint weights)
	// or http (Name is a URL polled on the interval; see Format).
	Type string `yaml:"type"`
	// Name is the DNS name to resolve (for srv the full _service._proto
	// name), or, for type http, the registry URL to poll.
	Name string `yaml:"name"`
	// Port is the endpoint port for type dns, and the default port for
	// type http when the registry omits one. Ignored for srv.
	Port int `yaml:"port"`
	// Format is the response shape for type http: list (default, a JSON
	// array of {address|host,port, weight?, canary?}) or consul (the
	// Consul /v1/health/service response; only passing instances are
	// used and their Weights.Passing becomes the endpoint weight).
	Format string `yaml:"format"`
	// Headers are extra request headers for type http, for example an
	// authentication token (Consul: X-Consul-Token).
	Headers map[string]string `yaml:"headers"`
	// Interval between resolutions. Default 30s; 1s to 1h.
	Interval Duration `yaml:"interval"`
	// Resolver is an optional host:port of the DNS server to ask instead
	// of the system resolver. DNS types only.
	Resolver string `yaml:"resolver"`
	// Weight given to discovered endpoints (type dns and http list format
	// entries without their own weight). Default 1.
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
	// BodyDigest makes the signature cover the request body of methods
	// that carry one, as a SHA-256 the proxy also sends in
	// Content-Digest. Default false.
	//
	// Without it a signature proves that a request passed through the
	// proxy, not what it carried: anything that can reach the origin
	// can replay a captured header set with a body of its own while the
	// timestamp is inside the TTL. It costs buffering the body, and a
	// bodied request larger than 8 MiB is refused rather than forwarded
	// with a signature that stops at the headers.
	BodyDigest bool `yaml:"body_digest"`
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
	// KeyExchange is the offered key agreement groups in preference
	// order, as in the listener section. Empty means the default.
	KeyExchange []string `yaml:"key_exchange"`
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
	// Deceive answers a client this route no longer trusts with a
	// plausible response instead of the origin's.
	Deceive *Deceive `yaml:"deceive"`

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
	// Timeout bounds the entire request on this route (the total, from
	// accept to the last response byte). Timeouts is the named form and
	// adds an idle timeout; the two are mutually exclusive.
	Timeout  Duration       `yaml:"timeout"`
	Timeouts *RouteTimeouts `yaml:"timeouts"`
	// WebSocket allows Upgrade: websocket to be forwarded. Default false.
	WebSocket bool `yaml:"websocket"`
	// WebSocketGuard inspects the frames of an upgraded connection.
	// Without it an upgrade is an opaque tunnel.
	WebSocketGuard *WebSocketGuard `yaml:"websocket_guard"`
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
	// CompressAuthenticated overrides compression.compress_authenticated
	// for this route.
	CompressAuthenticated *bool `yaml:"compress_authenticated"`
	// Maintenance overrides the global maintenance gate for this route:
	// false always serves it (health, status), true always holds it.
	Maintenance *bool `yaml:"maintenance"`
	// CORS answers cross-origin requests for this route: it short-circuits
	// preflight OPTIONS and adds the response headers to actual requests.
	CORS *RouteCORS `yaml:"cors"`
}

// RouteTimeouts are a route's named timeouts. Connect and the response
// header timeout are configured per upstream (upstreams[].timeouts),
// since the connection pool is shared; these bound the exchange as a
// whole and the gaps between response bytes.
type RouteTimeouts struct {
	// Total bounds the whole exchange, accept to last response byte.
	Total Duration `yaml:"total"`
	// Idle cancels a response that produces no bytes for this long, for
	// a streaming or long-poll route where Total would be too coarse.
	Idle Duration `yaml:"idle"`
}

// TotalTimeout returns the effective total request timeout.
func (r *Route) TotalTimeout() Duration {
	if r.Timeouts != nil {
		return r.Timeouts.Total
	}
	return r.Timeout
}

// IdleTimeout returns the route's idle response timeout, or 0.
func (r *Route) IdleTimeout() Duration {
	if r.Timeouts != nil {
		return r.Timeouts.Idle
	}
	return 0
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
	// MaxBytes bounds the body inspected. Default 64 KiB.
	MaxBytes int64 `yaml:"max_bytes"`
	// ContentTypes narrows the inspection to these media types (type/*
	// allowed). Empty inspects every body.
	ContentTypes []string `yaml:"content_types"`
	// OverLimit decides a body larger than MaxBytes, or one the filter
	// could not read: "match" (default) treats it as matching the
	// patch, "skip" lets it through unmatched.
	//
	// A virtual patch is the emergency control that holds a known
	// vulnerability while the application is fixed, and every sibling
	// control here refuses an oversize body rather than passing it. With
	// "skip", 64 KiB of padding carries the same payload straight to the
	// origin.
	OverLimit string `yaml:"over_limit"`
}

// MatchesOverLimit reports the setting with its default.
func (b *PatchBody) MatchesOverLimit() bool { return b == nil || b.OverLimit != "skip" }

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
	// Diff compares the shadow response with the live one and reports the
	// differences, turning the mirror into traffic shadowing for
	// validating a new backend against the current one. Off when unset.
	Diff *MirrorDiff `yaml:"diff"`
}

// MirrorDiff configures the comparison of a shadow response with the live
// response. Status is always compared; headers are compared for the listed
// names; bodies are compared by length and digest up to MaxBodyBytes. The
// outcome is counted in xproxy_mirror_diff_total and a sampled share of the
// differing exchanges is logged.
type MirrorDiff struct {
	// SamplePercent is the share of shadowed requests whose difference is
	// logged (metrics count every one). Default 100.
	SamplePercent int `yaml:"sample_percent"`
	// Headers are the response header names compared between the two
	// responses. Empty compares no headers (status and body only).
	Headers []string `yaml:"headers"`
	// MaxBodyBytes bounds the bytes of each response digested for the body
	// comparison. Default 64 KiB.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
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
	// CompressAuthenticated compresses a response to a request that
	// carried Authorization or Cookie. Default false.
	//
	// Compressing a response that mixes a secret with attacker-chosen
	// text leaks the secret through the compressed length, one character
	// at a time (BREACH). The condition is a request the attacker can
	// make the browser send with the victim's credentials, which is
	// exactly a request carrying a cookie. Turn it on per route where
	// the response holds no secret, or where the application already
	// masks its tokens.
	CompressAuthenticated *bool `yaml:"compress_authenticated"`
}

// CompressesAuthenticated reports the setting with its default.
func (c *Compression) CompressesAuthenticated() bool {
	return c != nil && c.CompressAuthenticated != nil && *c.CompressAuthenticated
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

// Deceive answers a client the proxy no longer trusts with something
// plausible instead of with the origin's answer — or with a refusal.
//
// A refusal is information. A scanner that gets 403 knows the request
// it sent was the interesting one, and varies it until something is
// not refused; the refusal is the oracle that tells it when it has
// found the way through. An answer that looks ordinary gives it
// nothing to steer by: the crawl completes, the data is wrong, and the
// request that would have worked looks exactly like the one that did
// not.
//
// It is a deliberately sharp tool, and the rules follow from that:
//
//   - It applies only to clients the proxy already has a reason to
//     distrust — a honeypot or honeytoken mark, a bot score, a named
//     network. A route with no condition is refused at validation,
//     because a deceive that admits everyone is an outage that looks
//     like a feature.
//   - The write never reaches the origin. That is the point for a
//     POST, and it means a false positive loses a client's data, so
//     the conditions are worth being sure of.
//   - It is loud on the inside. The access log line carries
//     deceived: <route>, a security event records it, and the counter
//     and metric are separate from every other refusal, so nobody
//     debugs a "working" endpoint for a week.
type Deceive struct {
	// Marked admits a client a honeypot route or a honeytoken marked.
	Marked bool `yaml:"marked"`
	// BotScoreAt admits a request a bot_score filter scored at or above
	// this. 0 does not look at the score.
	BotScoreAt int `yaml:"bot_score_at"`
	// ClientCIDRs admits these client networks.
	ClientCIDRs []string `yaml:"client_cidrs"`
	// Methods narrows the deception to these methods; empty is all of
	// them.
	Methods []string `yaml:"methods"`
	// Status answers the deceived request. Default 200: the whole
	// point is an answer that does not look like a refusal.
	Status int `yaml:"status"`
	// Decoy names a built-in decoy body (see routes[].honeypot), Body
	// is a literal one and BodyFile is read from disk at load and
	// reload. Exactly one is required.
	Decoy    string `yaml:"decoy"`
	Body     string `yaml:"body"`
	BodyFile string `yaml:"body_file"`
	// ContentType of Body and BodyFile. Default text/html; a decoy
	// brings its own.
	ContentType string `yaml:"content_type"`
	// Mark labels the client for this long, as a honeypot does, so a
	// client that was deceived once stays deceived while the mark
	// lasts. Default 0: the condition that admitted it decides.
	Mark Duration `yaml:"mark"`
}

// Honeypot is a decoy action: the response looks like a real page of the
// chosen kind, the client is logged as a security event, marked for
// `mark` so later requests on any route carry the label, and counted
// towards the `honeypot` ban reason.
type Honeypot struct {
	// Decoy names a built-in body; xproxyctl honeypot lists them, and
	// docs/CONFIG.md has the table. Exclusive with body and body_file.
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
	// Mark is how long the client stays marked. Default 1h; an
	// explicit 0 marks nobody, which is what a decoy served honestly
	// (robots.txt, sitemap.xml) wants: a crawler that reads it has
	// done nothing wrong yet.
	Mark *Duration `yaml:"mark"`
}

// MarkFor is how long a client that touched this honeypot stays
// marked, or 0 for a honeypot that marks nobody.
func (h *Honeypot) MarkFor() time.Duration {
	if h == nil || h.Mark == nil {
		return 0
	}
	return h.Mark.D()
}

// SecurityTxt is one virtual security.txt document (RFC 9116) and the
// requests it answers. The proxy serves it at /.well-known/security.txt
// and at the legacy /security.txt, before routing, so a host with no
// route of its own still has one — which is the parked name a finder
// tries first.
//
// Entries are tried in order and the first whose selectors all match
// answers, so an entry with no selectors placed last is the fallback for
// every other host. A request that matches no entry is routed as usual,
// so an origin serving its own file keeps doing so.
type SecurityTxt struct {
	// Name identifies the entry in the status view and the access log.
	Name string `yaml:"name"`

	// Hosts are exact names or wildcard patterns ("*.example.com",
	// which matches a label or more and not the bare name). Empty
	// matches every host.
	Hosts []string `yaml:"hosts"`
	// HostRegex additionally matches the host against an RE2 expression,
	// for a naming scheme a wildcard cannot express.
	HostRegex string `yaml:"host_regex"`
	// HostCIDRs match a request whose Host is an address literal rather
	// than a name, against these networks: the parked addresses, a
	// range a provider assigned, or "0.0.0.0/0" and "::/0" for every
	// literal there is. This is the selector for the host a scanner
	// reaches by address because no name points at it, which is exactly
	// where a finder has nothing else to go on. A Host that is a name
	// is never matched by it, whatever that name resolves to: the proxy
	// does not resolve the Host header.
	HostCIDRs []string `yaml:"host_cidrs"`
	// ClientCIDRs restrict the entry to clients inside these networks, so
	// an internal document can differ from the public one.
	ClientCIDRs []string `yaml:"client_cidrs"`
	// Listeners restrict the entry to these listener names.
	Listeners []string `yaml:"listeners"`

	// Contact is one or more ways to report, most preferred first
	// (mailto:, tel: or https:). Required unless body or body_file is
	// set.
	Contact []string `yaml:"contact"`
	// Expires is an RFC 3339 instant after which the document should not
	// be used. Exclusive with valid_for.
	Expires string `yaml:"expires"`
	// ValidFor sets Expires to this far ahead of the load, refreshed on
	// every reload, so the document cannot quietly go stale. Default
	// 8760h (a year), which is the longest RFC 9116 recommends.
	ValidFor Duration `yaml:"valid_for"`
	// Encryption points at a key a finder should encrypt to.
	Encryption []string `yaml:"encryption"`
	// Acknowledgments points at a page thanking finders.
	Acknowledgments []string `yaml:"acknowledgments"`
	// PreferredLanguages are BCP 47 tags, rendered as one field.
	PreferredLanguages []string `yaml:"preferred_languages"`
	// Canonical is where this document is expected to be found; it is
	// what makes a copy found elsewhere recognisable as a copy.
	Canonical []string `yaml:"canonical"`
	// Policy points at the disclosure policy.
	Policy []string `yaml:"policy"`
	// Hiring points at security job openings.
	Hiring []string `yaml:"hiring"`
	// CSAF points at a provider-metadata.json (RFC 9116 section 2.5.4).
	CSAF []string `yaml:"csaf"`
	// Extra carries fields this build does not know by name, rendered
	// after the known ones in name order.
	Extra map[string][]string `yaml:"extra"`
	// Comment is placed at the top of the document, each line prefixed
	// with "# ".
	Comment string `yaml:"comment"`

	// Body is the document verbatim, for a signed file kept elsewhere.
	// Exclusive with the fields above.
	Body string `yaml:"body"`
	// BodyFile is read at load and on every reload, at most 64 KiB. Use
	// it for a clear-signed document, which cannot be assembled from
	// fields without breaking the signature.
	BodyFile string `yaml:"body_file"`

	// CacheFor sets the Cache-Control max-age of the response. Default
	// 1h; 0 sends no Cache-Control.
	CacheFor Duration `yaml:"cache_for"`
}

// Degradation serves a suspect client slowly instead of refusing it.
//
// The proxy's other answers are binary: served, or refused. For a
// client that has done something wrong but not enough to ban — touched
// a decoy, scored badly, arrived from a range with a history — both
// are wrong. Serving it in full funds the next request. Refusing it
// tells it exactly which request to change, and hands a scanner a
// clean signal to tune against.
//
// A degraded client is served, correctly, slowly. There is nothing to
// tune against and nothing to report as broken, and a crawl that cost
// the scanner nothing now costs it the thing it has least of.
//
// Levels are tried in order and the first that admits the request
// decides, so the narrowest goes first.
type Degradation struct {
	Levels []DegradeLevel `yaml:"levels"`
}

// DegradeLevel is one rule: who is degraded, and by how much.
type DegradeLevel struct {
	// Name identifies the level in the access log, the metrics and the
	// management view.
	Name string `yaml:"name"`
	// Marked admits a client a honeypot route or a honeytoken marked.
	Marked bool `yaml:"marked"`
	// BotScoreAt admits a request whose bot_score filter scored it at
	// or above this. 0 does not look at the score.
	BotScoreAt int `yaml:"bot_score_at"`
	// ClientCIDRs narrows the level to these client networks.
	ClientCIDRs []string `yaml:"client_cidrs"`
	// Routes narrows it to these route names.
	Routes []string `yaml:"routes"`
	// Methods narrows it to these methods.
	Methods []string `yaml:"methods"`
	// BytesPerSecond shapes the response body. 0 does not shape.
	BytesPerSecond int64 `yaml:"bytes_per_second"`
	// Delay holds the response for this long before it is written, in a
	// tarpit slot rather than a request slot. At most 60s.
	Delay Duration `yaml:"delay"`
	// Close ends the connection after the response, so the client pays
	// for a new one every time.
	Close bool `yaml:"close"`
}

// Handshake decides who is refused before a TLS handshake completes.
//
// Every other control in this file answers a request: the handshake
// runs, a certificate is chosen, keys are agreed, the request is
// parsed, and then the proxy says no. For a client already known to be
// unwelcome that is a lot of asymmetric cryptography spent on saying
// no, and an answer — a status, a page, a header set — that tells a
// scanner something about what is in front of it.
//
// Refusing in the ClientHello is the cheapest possible no and the
// quietest: the connection fails to negotiate and there is nothing to
// fingerprint.
//
// It applies to every TLS listener, including HTTP/3, and to nothing
// else: a plain HTTP listener has no handshake to refuse in, and what
// arrives there is still refused the ordinary way.
type Handshake struct {
	// RefuseBanned refuses a client whose address or TLS fingerprint is
	// on the ban list. Default false: a ban that answers 403 is
	// visible to the operator in the access log, and this makes the
	// refusal invisible there, which is a deliberate trade.
	RefuseBanned bool `yaml:"refuse_banned"`
	// DenyFingerprints refuses these TLS fingerprints outright,
	// whatever the ban list says. An entry is a JA4 or JA3 string, or
	// one prefixed "ja4:" or "ja3:" to name which it is; a JA4 entry
	// ending in "*" matches by prefix, which is how a family of
	// clients is named without pinning every extension order.
	DenyFingerprints []string `yaml:"deny_fingerprints"`
	// Log records each refusal in the security log (reason
	// "handshake"). Default true.
	Log *bool `yaml:"log"`
}

// LogRefusals reports whether handshake refusals are logged (default
// true).
func (h *Handshake) LogRefusals() bool { return h == nil || h.Log == nil || *h.Log }

// Honeytoken is a credential that exists only to be stolen. It is
// planted where an attacker will find it — in a decoy this proxy
// serves, in a repository, in a paste, in a backup — and registered
// here. Nothing legitimate ever sends one, so a request that presents
// one is not a signal to weigh against others: it is an attacker
// replaying what they read, and the only question is what to do about
// it.
//
// The value is not a secret in the usual sense. Its whole purpose is
// to be read, so it is compared as an ordinary string and it is never
// written to a log; the logs name the token instead, which is what
// tells an operator which plant was found.
//
// Bodies are not searched. Every request would have to be buffered to
// do it, and the places a stolen credential is actually presented —
// the authorization header, an API key header, a cookie, a query
// parameter — are all in the head.
type Honeytoken struct {
	// Name identifies the token in the logs, the metrics and the
	// management view. It is what an operator sees instead of the value.
	Name string `yaml:"name"`
	// Description says where this one was planted, so the alert names
	// the leak rather than only the token.
	Description string `yaml:"description"`
	// Values are the planted strings. At least one of Values and
	// ValuesFile is required.
	Values []string `yaml:"values"`
	// ValuesFile holds one value per line (blank lines and # comments
	// ignored), for tokens generated by something else. Re-read on
	// reload; must not be world readable.
	ValuesFile string `yaml:"values_file"`
	// In narrows where to look: "headers", "cookies", "query",
	// "path". Default: all of them.
	In []string `yaml:"in"`
	// Headers narrows the header search to these names. Empty searches
	// every header value, which is the point for a token that might be
	// presented anywhere.
	Headers []string `yaml:"headers"`
	// Match is "exact" (default) or "contains". Exact compares the whole
	// field value once the common credential prefixes ("Bearer ",
	// "Basic ", "token ") are stripped; contains finds the token
	// anywhere in the value, for a token planted inside a larger
	// document a client echoes back.
	Match string `yaml:"match"`
	// Action is "block" (default) or "log". Log records the hit and
	// lets the request continue, which is what a token planted in a
	// place legitimate traffic might also reach needs until it is
	// proven quiet.
	Action string `yaml:"action"`
	// Status answers a blocked request. Default 403.
	Status int `yaml:"status"`
	// Mark labels the client for this long, as a honeypot route does,
	// so its later requests carry honeypot_marked. Default 24h: a
	// stolen credential says more about the client than one probe for
	// a decoy path does, so the label lasts longer. An explicit 0
	// marks nobody.
	Mark *Duration `yaml:"mark"`
	// Enabled is false to keep a token configured without acting on it.
	Enabled *bool `yaml:"enabled"`
}

// IsEnabled reports whether the token is active (default true).
func (h Honeytoken) IsEnabled() bool { return h.Enabled == nil || *h.Enabled }

// MarkFor is how long a client that presented this token stays marked,
// or 0 for a token that marks nobody.
func (h *Honeytoken) MarkFor() time.Duration {
	if h == nil || h.Mark == nil {
		return 0
	}
	return h.Mark.D()
}

// Capture writes the exchanges the proxy handled as pcapng files that
// Wireshark and tshark read. The proxy terminates TLS, so a capture
// taken on the wire in front of it is ciphertext and one taken behind
// it has lost the client; this is the proxy's own view of the
// decrypted exchange, synthesised into a TCP conversation so a
// dissector reads it as HTTP.
//
// A capture file holds request and response bytes in the clear:
// cookies, bearer tokens, personal data, whatever the application
// carries. It is written 0600 into a directory the operator names,
// nothing else is ever put there, and `redact` blanks the header
// values that should not be in it at all. Treat the directory as you
// would treat the access log with redaction turned off.
type Capture struct {
	// Enabled builds the subsystem. Without it nothing is recorded and
	// the runtime switch has nothing to turn on.
	Enabled bool `yaml:"enabled"`
	// StartActive begins recording at start-up. Default false: the
	// usual shape is a configuration that is ready and a switch an
	// operator throws for one reproduction.
	StartActive bool `yaml:"start_active"`
	// Directory holds the files. Absolute, and owned by the proxy user.
	Directory string `yaml:"directory"`
	// FilePrefix begins each file name; the rest is the time it was
	// opened. Default "xproxy".
	FilePrefix string `yaml:"file_prefix"`
	// MaxFileBytes rotates to a new file past this size. Default 64 MiB.
	MaxFileBytes int64 `yaml:"max_file_bytes"`
	// MaxFiles keeps this many files, removing the oldest. Default 4.
	MaxFiles int `yaml:"max_files"`
	// MaxDuration bounds one recording window, so a capture started
	// during an incident cannot be left running for a month. Default 1h.
	MaxDuration Duration `yaml:"max_duration"`
	// SnapLen is the largest frame written. Default 262144.
	SnapLen int `yaml:"snap_len"`
	// Bodies captures request and response bodies as well as the heads.
	// Default false: the heads answer most questions and carry far less
	// of what should not be on disk.
	Bodies bool `yaml:"bodies"`
	// MaxBodyBytes bounds each captured body; the rest is left out and
	// the frame is marked truncated. Default 65536.
	MaxBodyBytes int `yaml:"max_body_bytes"`
	// Redact blanks these request and response header values in the
	// captured bytes. Default: the authorization, cookie and API key
	// headers.
	Redact []string `yaml:"redact"`
	// Rules select which exchanges are written. No rules means every
	// exchange, which is what a section with only a directory means.
	Rules []CaptureRule `yaml:"rules"`
}

// CaptureRule selects exchanges. Every selector it names must hold, and
// a rule that names none matches everything; the first rule that
// matches decides. Selectors on the answer (statuses, reasons, denied)
// are only known once the exchange is over, so a rule using them
// captures the whole exchange retrospectively.
type CaptureRule struct {
	// Name identifies the rule in the status view.
	Name string `yaml:"name"`
	// Hosts are exact names or "*.example.com" patterns.
	Hosts []string `yaml:"hosts"`
	// Routes are route names.
	Routes []string `yaml:"routes"`
	// Methods are upper-case tokens.
	Methods []string `yaml:"methods"`
	// Paths are prefixes of the routing path.
	Paths []string `yaml:"paths"`
	// ClientCIDRs restrict the rule to these client networks.
	ClientCIDRs []string `yaml:"client_cidrs"`
	// Statuses are response statuses, or classes 1 to 5.
	Statuses []int `yaml:"statuses"`
	// Reasons are deny reasons ("waf", "rate_limit", ...), matched
	// against the reason and against the reason with its detail.
	Reasons []string `yaml:"reasons"`
	// Denied selects every refusal, whatever the reason.
	Denied bool `yaml:"denied"`
	// Percent samples the exchanges this rule would take. Default 100.
	Percent int `yaml:"percent"`
	// MaxFlows bounds how many exchanges this rule ever writes, so a
	// rule left on cannot fill a disk. 0 is unbounded.
	MaxFlows int `yaml:"max_flows"`
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
	// body_size, uri_length, bad_host, no_route, websocket, concurrency,
	// smtp_denied and the rest; validation lists them). Empty counts
	// every deny.
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
	// Listen is the address of the cluster listener. Either a host:port
	// for a networked cluster (TCP with mutual TLS; bind it to an
	// internal interface) or "unix:/path/to/socket" for a local one,
	// where the peers are the sibling daemons on this machine.
	Listen string `yaml:"listen"`
	// Peers are the cluster addresses of the other nodes, in the same
	// form as Listen. A cluster is one or the other: every address is a
	// host:port or every address is a Unix socket.
	Peers []string   `yaml:"peers"`
	TLS   ClusterTLS `yaml:"tls"`
	// Local configures a Unix socket cluster: who may open the socket,
	// and which peers may speak on it. It is refused on a networked
	// cluster, where the certificate answers both questions.
	Local *ClusterLocal `yaml:"local"`
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
// ClusterLocal is the authentication of a cluster that runs over Unix
// sockets between the daemons of one machine.
//
// There is no certificate here and none is wanted: the peers are
// processes on this host, and the kernel already knows exactly who they
// are. What admits a peer is the socket's own permissions — the
// directory it sits in and the mode it is created with — and what this
// section adds is a second statement of the same thing that a
// compromised directory cannot quietly change.
type ClusterLocal struct {
	// SocketMode is the octal permission mode of the listening socket.
	// Default 0660: the owner and the group the siblings share, and
	// nobody else. A mode granting anything to others is refused.
	SocketMode string `yaml:"socket_mode"`
	// AllowUIDs are the user ids that may connect, read from the
	// connected socket itself rather than announced by the peer.
	//
	// Empty means any process that could open the socket, which leaves
	// the whole decision to the file permissions. A cluster peer is
	// trusted completely — it places bans, decides rate limits and is
	// named in the audit trail — so listing the three daemons' uids
	// here is worth the trouble.
	AllowUIDs []int `yaml:"allow_uids"`
}

type ClusterTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
	// AllowedNames optionally restricts peers to these certificate common
	// names or DNS SANs.
	AllowedNames []string `yaml:"allowed_names"`
	// BindNodeID requires a peer's announced node_id to be a name its
	// certificate carries. Default true.
	//
	// The id is not a label: key ownership for exact rate limits is a
	// rendezvous hash over node ids, so a peer free to choose its id
	// chooses which keys it decides for every node. Set it false only
	// for an existing cluster whose certificate names and node ids
	// differ, and fix the certificates: a cluster certificate is full
	// trust within the cluster, and the id is the only thing that
	// distinguishes one holder of one from another. The id is not a label: key
	// ownership for exact rate limits is a rendezvous hash over node
	// ids, and bans and marks are attributed to them, so a peer that
	// chooses its own id chooses which keys it decides and whose name
	// appears in the audit trail. Set it false only for an existing
	// cluster whose certificate names differ from its node ids, and fix
	// the certificates.
	BindNodeID *bool `yaml:"bind_node_id"`
}

// BindsNodeID reports the setting with its default applied.
func (t ClusterTLS) BindsNodeID() bool { return t.BindNodeID == nil || *t.BindNodeID }

// Sharing helpers with defaults applied.
// UnixSocketPrefix marks a cluster address as a Unix socket path.
const UnixSocketPrefix = "unix:"

// UnixSocket returns the path of a "unix:" cluster address, and whether
// the address was one.
func UnixSocket(addr string) (string, bool) {
	p, ok := strings.CutPrefix(addr, UnixSocketPrefix)
	return p, ok
}

// IsLocal reports a cluster that runs over Unix sockets between the
// daemons of one machine, rather than over TCP between hosts.
func (c *Cluster) IsLocal() bool {
	_, ok := UnixSocket(c.Listen)
	return ok
}

// LocalSocketMode is the mode the listening socket is created with.
func (c *Cluster) LocalSocketMode() uint32 {
	if c.Local != nil && c.Local.SocketMode != "" {
		if n, err := strconv.ParseUint(c.Local.SocketMode, 8, 32); err == nil {
			return uint32(n)
		}
	}
	return 0o660
}

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

// Maintenance is the maintenance-mode policy.
type Maintenance struct {
	// Enabled is the state at start; the runtime toggle overrides it.
	Enabled bool `yaml:"enabled"`
	// Status answers held requests. Default 503.
	Status int `yaml:"status"`
	// RetryAfter sets the Retry-After header in seconds. Default 300.
	RetryAfter Duration `yaml:"retry_after"`
	// Message is the response body. Default a short text.
	Message string `yaml:"message"`
	// AllowCIDRs are always served (operators, health checkers).
	AllowCIDRs []string `yaml:"allow_cidrs"`
	// AllowHeader, "Name: value", exempts a request carrying it (a shared
	// bypass token behind another gate).
	AllowHeader string `yaml:"allow_header"`
}

// Challenge configures the browser proof-of-work challenge (AMR-023).
type Challenge struct {
	// SecretFile persists the HMAC key so cookies survive restarts.
	SecretFile string `yaml:"secret_file"`
	// CookieScope is "shared" (default) or "host". A pass cookie is
	// bound to the client address and its TLS fingerprint; with "host"
	// it is bound to the host that served the challenge as well, so a
	// client cannot earn a cheap pass on one host and spend it on
	// another that asks for more work. Use "host" when hosts behind one
	// proxy differ in difficulty or tier; leave it "shared" when a pass
	// is meant to cover a site's several names, since "host" makes every
	// outstanding cookie stop working once.
	CookieScope string `yaml:"cookie_scope"`
	// Difficulty is the number of leading zero bits required. Default 16
	// (about 65 000 hashes, well under a second in a browser).
	Difficulty int `yaml:"difficulty"`
	// TTL is the validity of a passed challenge. Default 1h.
	TTL Duration `yaml:"ttl"`
	// BindIP ties the cookie to the client address. Default true.
	BindIP *bool `yaml:"bind_ip"`
	// BindJA4 ties the cookie to the client's JA4 TLS fingerprint (token
	// binding): a cookie earned by one TLS client is refused when replayed
	// by another, even from the same address. Off by default; TLS only.
	BindJA4 bool `yaml:"bind_ja4"`
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

// BindsJA4 reports whether cookies are bound to the client's JA4 fingerprint.
func (c *Challenge) BindsJA4() bool { return c.BindJA4 }

// BindsHost reports whether a pass cookie is bound to the host that
// issued it (cookie_scope: host).
func (c *Challenge) BindsHost() bool { return c.CookieScope == "host" }

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

// The SMTP line bounds of RFC 5321 section 4.5.3.1, repeated here
// because config must not import the smtp package (which imports this
// one for nothing, but the direction is the point).
const (
	smtpMaxCommandLine = 512
	smtpMaxTextLine    = 1000
)

// DefaultSMTPCommands is the verb set a session allows when the
// configuration names none: enough for submission and for inbound mail,
// and nothing that asks the upstream to enumerate its users. VRFY and
// EXPN are left out on purpose; a listener that wants them says so.
var DefaultSMTPCommands = []string{"EHLO", "HELO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "AUTH", "STARTTLS"}

// SMTPAlwaysHidden are EHLO keywords the proxy never passes through.
// STARTTLS because the proxy answers it itself and the upstream's
// offer is about a different hop; CHUNKING because BDAT carries a
// length instead of a dot terminator, so relaying it would mean two
// parsers deciding where a message ends, which is the one thing this
// listener exists to prevent.
var SMTPAlwaysHidden = []string{"STARTTLS", "CHUNKING", "BDAT"}

// DefaultMQTTVersions is the protocol set an mqtt listener accepts when
// the configuration names none: both versions this proxy can parse. A
// version it cannot parse is a packet it cannot check, so there is no
// "accept anything" setting.
var DefaultMQTTVersions = []string{"3.1.1", "5.0"}

// The default policy of an ssh listener: a shell and sftp, and nothing
// that hands the target a channel back into the client.
var (
	DefaultSSHChannels   = []string{"session"}
	DefaultSSHRequests   = []string{"pty-req", "env", "shell", "exec", "subsystem", "window-change", "signal"}
	DefaultSSHSubsystems = []string{"sftp"}

	// SSHChannelTypes and SSHRequestTypes are what the allow lists may
	// name. A type the proxy does not relay is not a type an operator
	// can allow by writing it down.
	SSHChannelTypes = map[string]bool{
		"session": true, "direct-tcpip": true, "direct-streamlocal@openssh.com": true,
	}
	SSHRequestTypes = map[string]bool{
		"pty-req": true, "env": true, "shell": true, "exec": true, "subsystem": true,
		"window-change": true, "signal": true, "x11-req": true, "auth-agent-req@openssh.com": true,
		"break": true, "eow@openssh.com": true,
	}
)

// SFTPOperations are the names deny_operations may use.
var SFTPOperations = map[string]bool{
	"open": true, "close": true, "read": true, "write": true, "lstat": true, "fstat": true,
	"setstat": true, "fsetstat": true, "opendir": true, "readdir": true, "remove": true,
	"mkdir": true, "rmdir": true, "realpath": true, "stat": true, "rename": true,
	"readlink": true, "symlink": true, "extended": true,
}

// MFAPolicy is a second factor, shared by every protocol that can ask
// for one. It is one shape rather than one per protocol because a
// second factor that means different things on different ports is not
// a second factor: the same enrolment, the same replay rule and the
// same lockout have to hold everywhere, or the weakest door decides.
type MFAPolicy struct {
	// File is the enrolment file (xproxyctl mfa enrol writes the
	// lines). Required. It must not be world readable.
	File string `yaml:"file"`
	// Issuer is the name an authenticator application shows. Default
	// "xproxy".
	Issuer string `yaml:"issuer"`
	// Prompt is what the user is asked. Default "One-time code: ".
	Prompt string `yaml:"prompt"`
	// Skew is how many time steps either side of now are accepted.
	// Default 1, which is the usual allowance for a clock that is a
	// little off. Each step accepted is a step an observer could
	// replay in, so this is not a knob to raise casually.
	Skew int `yaml:"skew"`
	// RequireEnrolment refuses a user who has no enrolment. Default
	// true: an optional second factor is one an attacker can decline
	// by using an account that never enrolled.
	RequireEnrolment *bool `yaml:"require_enrolment"`
	// MaxFailures within Window locks a user out for Duration.
	// Defaults 5, 5m and 15m. A six-digit code has a million values
	// and a step lasts thirty seconds, so without a bound a fast
	// client gets a real chance at every step.
	MaxFailures int      `yaml:"max_failures"`
	Window      Duration `yaml:"window"`
	Duration    Duration `yaml:"lockout"`
	// MaxUsers bounds the table that remembers spent codes and recent
	// failures. Default 10000.
	MaxUsers int `yaml:"max_users"`
}

// SSHPrincipal gives one key, or one certificate principal, its own
// policy on an ssh listener.
type SSHPrincipal struct {
	// Name appears in the access log and the security events, so a
	// refusal names a person rather than a fingerprint.
	Name string `yaml:"name"`
	// Fingerprints are SHA256 fingerprints of the keys this entry
	// covers, in the form ssh-keygen prints: "SHA256:" and the base64
	// of the digest.
	Fingerprints []string `yaml:"fingerprints"`
	// CertPrincipals are the principals of a certificate this entry
	// covers; they need trusted_user_ca_keys.
	CertPrincipals []string `yaml:"cert_principals"`
	// Users restricts the entry to these login names. Empty matches any
	// name the key authenticated as.
	Users []string `yaml:"users"`
	// Policy is what this principal may do. Anything it leaves unset
	// falls back to the listener's own setting, so an entry that only
	// changes the target account says only that.
	Policy *SSHPolicy `yaml:"policy"`
}

// SSHPolicy is the part of an ssh listener's policy a principal can
// have its own copy of. Every field is optional: unset means the
// listener's value.
type SSHPolicy struct {
	UpstreamUser    string      `yaml:"upstream_user"`
	AllowChannels   []string    `yaml:"allow_channels"`
	AllowRequests   []string    `yaml:"allow_requests"`
	AllowSubsystems []string    `yaml:"allow_subsystems"`
	AllowCommands   []string    `yaml:"allow_commands"`
	AllowEnv        []string    `yaml:"allow_env"`
	Forward         []string    `yaml:"forward"`
	RemoteForward   *bool       `yaml:"remote_forward"`
	SFTP            *SFTPPolicy `yaml:"sftp"`
	// Recording replaces the listener's, which is how one entry is
	// recorded and another is not. A principal that should not be
	// recorded where the listener is sets enabled: false.
	Recording *SSHRecording `yaml:"recording"`
	// Deny refuses this principal outright, which is how a key stays in
	// authorized_keys while the person it belongs to is off.
	Deny bool `yaml:"deny"`
}

// SSHDeniedEnv are the variables no allow list can admit. Each one is a
// way to run code before the command that was approved.
var SSHDeniedEnv = []string{
	"LD_*", "DYLD_*", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "IFS", "PS4",
	"PERL5OPT", "PERL5LIB", "PERLLIB", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
	"RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "GLIBC_TUNABLES", "GCONV_PATH", "LOCPATH",
	"TMPDIR", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "PATH",
}

// DefaultSSHEnv is what a client may set when allow_env says nothing: a
// terminal type and a locale, which is what an interactive session
// needs and all it needs.
// DefaultFTPCommands is every command this proxy can read the effect
// of, which is the set it can hold to a policy. A verb outside it is
// refused: applying a policy to an argument nobody understands is not
// applying a policy.
var DefaultFTPCommands = []string{
	"USER", "PASS", "ACCT", "QUIT", "NOOP", "SYST", "FEAT", "OPTS",
	"TYPE", "MODE", "STRU", "PWD", "XPWD", "CWD", "XCWD", "CDUP", "XCUP",
	"PASV", "EPSV", "PORT", "EPRT", "RETR", "STOR", "STOU", "APPE",
	"DELE", "RNFR", "RNTO", "MKD", "XMKD", "RMD", "XRMD", "LIST", "NLST",
	"MLSD", "MLST", "SIZE", "MDTM", "STAT", "ABOR", "REST", "HELP",
	"AUTH", "PBSZ", "PROT",
}

// SFTPPathVars are the substitutions an sftp path pattern may carry.
// They are deliberately few: a pattern is a security decision, and a
// substitution the operator cannot predict the value of is not one.
var SFTPPathVars = map[string]bool{"user": true, "principal": true}

var DefaultSSHEnv = []string{"TERM", "LANG", "LC_*"}

// SSHFileTransferCommands are the exec commands that move files past an
// sftp policy. The name is matched on the command's first word, with
// any directory part removed.
var SSHFileTransferCommands = map[string]bool{
	"scp": true, "rsync": true, "sftp-server": true, "internal-sftp": true,
	"lftp": true, "rclone": true,
}

// Effective values of the tunnel signals that may be switched off. A
// nil pointer never reaches these -- defaults fill them in -- but they
// hold anyway, so a configuration assembled another way cannot make the
// detector read a nil.
func (t *DNSTunnel) entropyShare() float64 { return derefFloat(t.EntropyShare) }
func (t *DNSTunnel) txtShare() float64     { return derefFloat(t.TXTShare) }
func (t *DNSTunnel) nxShare() float64      { return derefFloat(t.NXDOMAINShare) }
func (t *DNSTunnel) distinct() int {
	if t.DistinctSubdomains == nil {
		return 0
	}
	return *t.DistinctSubdomains
}

func (t *DNSTunnel) payloadBytes() int64 {
	if t.PayloadBytes == nil {
		return 0
	}
	return *t.PayloadBytes
}

func derefFloat(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}
