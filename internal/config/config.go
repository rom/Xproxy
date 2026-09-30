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
	// Policy is the estate's enforcement mode: whether the listeners
	// enforce their policies or only evaluate them and write down what
	// they would have refused.
	Policy *Policy `yaml:"policy"`
	// ThreatIntel imports lists of client addresses and TLS
	// fingerprints somebody else attributed, with what to do about a
	// match.
	ThreatIntel *ThreatIntel `yaml:"threat_intel"`
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
	// SCIM serves a SCIM 2.0 provisioning endpoint (RFC 7644) so the
	// directory that owns the joiner and leaver process provisions and
	// deprovisions the credentials this proxy holds.
	SCIM *SCIM `yaml:"scim"`
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
	// AssetInventory records the *devices* the proxy has seen and works
	// out what each one is, from the traffic it was already carrying.
	// Where api_inventory answers "what does this estate serve", this one
	// answers "what is on this estate's network" -- the question an
	// operational network cannot answer with a scanner.
	AssetInventory *AssetInventory `yaml:"asset_inventory"`
	// Correlation is the short cross-listener memory: what each address
	// has done on every listener of this daemon for the last window. It
	// is what the detections no single listener can make are built on --
	// one host touching three control protocols, an OT session that
	// followed a bastion session, a clock step followed by time-tagged
	// commands.
	Correlation *Correlation `yaml:"correlation"`
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
	// Access is just-in-time access: the grants a gate listener with
	// require_grant admits sessions against, who has to approve one and how
	// long it may last.
	Access *Access `yaml:"access"`
	// Secrets says where secret references resolve from: a vault, and how
	// often a resolved value is fetched again. Without it a reference may
	// still name a file or an environment variable.
	Secrets *Secrets `yaml:"secrets"`
	// FIPS is what the estate requires of the runtime's FIPS 140-3 mode.
	FIPS *FIPS `yaml:"fips"`
	// Authorization is the estate's own answer to "who may reach what",
	// asked by every listener kind rather than written per kind.
	Authorization *Authorization `yaml:"authorization"`
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
	// Zone names the failure domain this node is in -- an availability
	// zone, a rack, a site. It is what an upstream's locality policy
	// compares an endpoint's zone against, so a node prefers the
	// endpoints beside it. Empty means the node does not know where it
	// is, and a locality policy then prefers nothing.
	Zone string `yaml:"zone"`
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
	// Daemon names the program that binds this listener, for the few
	// kinds more than one of them serves: syslog, snmp, tftp, dhcp,
	// dhcp6, ntp and ntske are run both by a data centre's relay and by
	// a plant's own, so the code is linked into xrelay and xot alike.
	//
	// Empty means the kind's default, which is xrelay for those seven
	// and the only daemon that serves it for every other kind -- so a
	// configuration written before xot existed means what it meant. A
	// plant that wants its field equipment's syslog, time and
	// provisioning served by the daemon that speaks to the plant writes
	// `daemon: xot` on those listeners.
	//
	// It is a field rather than a deployment convention because a shared
	// estate configuration is read by every daemon, and two of them
	// treating one listener as theirs would race for the port.
	Daemon string `yaml:"daemon"`
	// ConnectionRate and ConnectionRatePerSource bound how fast this
	// listener accepts, replacing server.limits' own for it. See
	// server.limits.connection_rate: it is the bound max_connections
	// does not give, and it matters most on the listeners that do
	// expensive work before they know who is calling -- a key exchange,
	// a TLS handshake -- which is every access gateway.
	ConnectionRate          *ConnectionRate `yaml:"connection_rate"`
	ConnectionRatePerSource *SourceRate     `yaml:"connection_rate_per_source"`
	// TCP configures a kind: tcp listener.
	TCP *TCPListener `yaml:"tcp"`
	// UDP configures a kind: udp listener.
	UDP *UDPListener `yaml:"udp"`
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
	// Telnet configures a kind: telnet listener.
	Telnet *TelnetListener `yaml:"telnet"`
	// VNC configures a kind: vnc listener.
	VNC *VNCListener `yaml:"vnc"`
	// RDP configures a kind: rdp listener.
	RDP *RDPListener `yaml:"rdp"`
	// FTP configures a kind: ftp listener.
	FTP *FTPListener `yaml:"ftp"`
	// Syslog configures a kind: syslog listener.
	Syslog *SyslogListener `yaml:"syslog"`
	// Modbus configures a kind: modbus listener.
	Modbus *ModbusListener `yaml:"modbus"`
	// NTP configures a kind: ntp listener.
	NTP *NTPListener `yaml:"ntp"`
	// NTSKE configures a kind: ntske listener.
	NTSKE *NTSKEListener `yaml:"ntske"`
	// IEC104 configures a kind: iec104 listener.
	IEC104 *IEC104Listener `yaml:"iec104"`
	// SNMP configures a kind: snmp listener.
	SNMP *SNMPListener `yaml:"snmp"`
	// LDAP configures a kind: ldap listener.
	LDAP *LDAPListener `yaml:"ldap"`
	// TFTP configures a kind: tftp listener.
	TFTP *TFTPListener `yaml:"tftp"`
	// Postgres is the kind: postgres section.
	Postgres *PostgresListener `yaml:"postgres"`
	// MySQL is the kind: mysql section.
	MySQL *MySQLListener `yaml:"mysql"`
	// TDS is the kind: tds section.
	TDS *TDSListener `yaml:"tds"`
	// Redis is the kind: redis section.
	Redis *RedisListener `yaml:"redis"`
	// DHCP configures a kind: dhcp listener.
	DHCP *DHCPListener `yaml:"dhcp"`
	// DHCP6 configures a kind: dhcp6 listener.
	DHCP6 *DHCP6Listener `yaml:"dhcp6"`
	// CoAP configures a kind: coap listener.
	CoAP *CoAPListener `yaml:"coap"`
	// BACnet configures a kind: bacnet listener.
	BACnet *BACnetListener `yaml:"bacnet"`
	// AMQP configures a kind: amqp listener.
	AMQP *AMQPListener `yaml:"amqp"`
	// S7 configures a kind: s7 listener.
	S7 *S7Listener `yaml:"s7"`
	// OPCUA configures a kind: opcua listener.
	OPCUA *OPCUAListener `yaml:"opcua"`
	// MMS configures a kind: mms listener.
	MMS *MMSListener `yaml:"mms"`
	// Policy is whether this listener enforces its policy or only
	// evaluates it. It overrides the estate's own policy section.
	Policy *ListenerPolicy `yaml:"policy"`
}

// Shadowing reports whether this listener evaluates its policy without
// enforcing it. The default is to enforce: a proxy that shadowed by
// accident would be a proxy with no policy at all, and the one thing that
// must never be a default is "allow everything and write it down".
func (l Listener) Shadowing() bool { return l.Policy != nil && l.Policy.Mode == "shadow" }

// ListenerPolicy is the enforcement mode of one listener.
type ListenerPolicy struct {
	// Mode is enforce (the default) or shadow. In shadow mode the policy
	// is evaluated on real traffic and every decision it would have made
	// is recorded, and nothing is refused for policy -- which is how an
	// operator finds out what a new allow list, command policy or
	// register range would have broken before it breaks it.
	//
	// What shadow mode does NOT stop: a malformed message, a failed
	// authentication or second factor, a ban, a rate limit, a bound
	// (packet size, table full, connection limit) and a TLS handshake
	// refusal are refused in shadow mode too. Forwarding those would mean
	// acting on bytes the code could not read, or admitting somebody who
	// did not authenticate, which is not a policy question.
	Mode string `yaml:"mode"`
}

// ModbusListener is a Modbus relay that reads every frame.
//
// Modbus has no authentication, no integrity and no session. A frame
// says which device it is for, what to do and where, and the device does
// it -- which is why it still runs plants built before the word firewall
// meant anything, and why the only place a policy can exist is between
// the master and the slave.
//
// So this listener is a policy enforcement point written in Modbus's own
// terms: the unit identifier, the function code, the register range and
// the value being written. It works in both directions. A *reverse*
// listener fronts the devices: masters connect to it and it dials the
// PLC, which is how a device that cannot be patched gets an allow list
// and an audit trail. A *forward* listener is the other way round: it is
// the egress a plant's masters use to reach a slave somewhere else, and
// the routes decide which destination each unit identifier is allowed to
// reach.
type ModbusListener struct {
	// Mode is reverse (the default: masters connect here and the
	// listener dials the devices) or forward (this listener is the
	// controlled egress a plant's masters use to reach devices
	// elsewhere). The frame handling is the same; what differs is which
	// side the policy is written about, and forward requires the routes
	// to name every destination that may be reached.
	Mode string `yaml:"mode"`
	// Upstream is the device pool a frame goes to when no route claims
	// its unit identifier. Required in reverse mode; in forward mode a
	// default is optional, because a forward listener with no route for
	// a unit is usually a mistake rather than a default.
	Upstream string `yaml:"upstream"`
	// Framing is what arrives from the master: tcp (MBAP, the default),
	// rtu or ascii. The serial framings are here because every "Modbus
	// gateway" ever sold tunnels them over TCP, and a relay that could
	// not read them would be a relay the estate goes around.
	Framing string `yaml:"framing"`
	// UpstreamFraming is what this listener writes to the device.
	// Default: the same as Framing. Setting them differently makes this
	// a protocol converter, which is what a serial device behind a
	// terminal server needs.
	UpstreamFraming string `yaml:"upstream_framing"`
	// Routes send a unit identifier to a pool of its own, which is what
	// a gateway multiplexing several devices onto one address does, and
	// what a forward listener uses to say which destinations may be
	// reached at all.
	Routes []ModbusRoute `yaml:"routes"`
	// TLSMode is implicit (Modbus/TCP Security, which is TLS from the
	// first octet on port 802) or none. Default implicit when the
	// listener has a tls section.
	TLSMode string `yaml:"tls_mode"`
	// UpstreamTLSMode is none or implicit: whether this listener speaks
	// Modbus/TCP Security to the device.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS verifies the device when upstream_tls_mode is not
	// none.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// Security is the Modbus/TCP Security role policy.
	Security *ModbusSecurity `yaml:"security"`
	// AllowClients and DenyClients are the networks a master may
	// connect from. Deny is evaluated first. An empty allow list allows
	// every client the deny list does not refuse, which validation
	// advises against on a listener that reaches a PLC.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// Units is the shorthand allow list of unit identifiers, written as
	// numbers or "1-16" ranges. Empty allows every unit the rules do.
	Units []string `yaml:"units"`
	// ReadOnly refuses every function code that changes anything, for
	// every client, before any rule is read. It is the shorthand for the
	// commonest requirement in a plant -- a historian that must never
	// write -- and it cannot be overridden by a rule, because a
	// read-only listener that could be written through by one rule is
	// not a read-only listener.
	ReadOnly bool `yaml:"read_only"`
	// RefuseUnsafeSubFunctions refuses a frame whose sub-function stops a
	// device, changes what it runs, clears the record of either, or is
	// one this relay cannot read -- unless the allow rule that permitted
	// it named the sub-function, with diagnostics, umas_commands or
	// effects. Default true.
	//
	// It is here because of what a function code covers. A rule allowing
	// `diagnostic` was written by somebody thinking of counter polls, and
	// the same rule allows sub-function 4, Force Listen Only Mode, which
	// is four bytes that take a device off the bus until something
	// restarts it. A rule allowing `umas` was written for an engineering
	// station, and the same rule allows stop_plc. So a rule that does not
	// mention the sub-function does not permit those: naming them is how
	// a policy says it meant them.
	RefuseUnsafeSubFunctions *bool `yaml:"refuse_unsafe_sub_functions"`
	// Rules decide each frame, in order, first match wins. A frame that
	// matches no rule takes DefaultAction.
	Rules []ModbusRule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow: what happens to a
	// frame no rule matched. Allow with no rules is a relay that only
	// watches, which is what learning mode is for.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is how a refused request is answered: exception (the
	// default, an illegal-function or illegal-address exception the
	// master understands), drop (no answer at all, which a master reads
	// as a timeout) or close (end the connection).
	DenyResponse string `yaml:"deny_response"`
	// MaxValuePoints bounds the addresses whose last value this relay
	// remembers for the value rules that need one (max_delta,
	// transitions, require_before). Default 65536. A plant has hundreds;
	// the bound is here because the addresses come off the network.
	MaxValuePoints int `yaml:"max_value_points"`
	// Deception answers a refused frame, or a whole listener, as a device
	// that is not there. See ModbusDeception.
	Deception *ModbusDeception `yaml:"deception"`
	// Learn records what actually crosses this listener -- the clients,
	// the roles, the units, the function codes, the address ranges and
	// the value ranges -- and writes it out as a rule set to start from.
	Learn *ModbusLearn `yaml:"learn"`
	// Anomaly watches what each master has been doing and reports when it
	// stops: a function code it has never used, a write to a register it
	// has never written, a burst of writes. It needs no rules, which is
	// the point of it.
	Anomaly *ModbusAnomaly `yaml:"anomaly"`
	// Trace writes one line per frame for as long as it is enabled: the
	// engineer's tool for "what is this master actually doing".
	Trace *ModbusTrace `yaml:"trace"`
	// MaxConnections bounds live sessions. Default 64, which is more
	// masters than a plant usually has and fewer than a scan can open.
	MaxConnections int `yaml:"max_connections"`
	// MaxPending bounds the requests one session may have outstanding.
	// Default 1 for the serial framings, where the protocol has no
	// transaction identifier and a second request in flight cannot be
	// told from the first; 16 for MBAP.
	MaxPending int `yaml:"max_pending"`
	// IdleTimeout closes a session that says nothing. Default 120s.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// RequestTimeout bounds how long the device has to answer one
	// request. Default 5s.
	RequestTimeout Duration `yaml:"request_timeout"`
	// ConnectTimeout bounds dialling the device. Default 5s.
	ConnectTimeout Duration `yaml:"connect_timeout"`
	// MaxFrameBytes bounds one frame. Default 260, the longest ADU the
	// specification has; a smaller value is a tighter bound on a
	// listener whose devices only speak short frames.
	MaxFrameBytes int `yaml:"max_frame_bytes"`
	// RateLimit and RateBurst bound requests per second per client
	// address. Zero disables them. A PLC's scan budget is finite and a
	// master that asks faster than the device can answer is an outage.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// LogFrames writes an access line per frame rather than per
	// session. It is the audit trail a plant is asked for, and it is a
	// line per request: a scan of a thousand registers a second is a
	// thousand lines a second, which is why it is a choice.
	LogFrames bool `yaml:"log_frames"`
	// AlertOnDeny writes a security event for every refusal. Default
	// true. Turning it off keeps the counters and loses the record,
	// which is a decision to make deliberately on a listener whose
	// refusals are routine.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// ProxyProtocol sends a PROXY protocol v2 header to the device, so
	// a device or a collector behind this listener sees the master's
	// address rather than the relay's.
	ProxyProtocol bool `yaml:"proxy_protocol"`
}

// IEC104Listener configures a kind: iec104 listener: an
// IEC 60870-5-104 relay for electricity transmission and distribution.
//
// The protocol is the grid's Modbus, with the same absence of security --
// no authentication, no integrity, no session -- and the same reason a
// relay is the only place a policy can live: the controlled stations are
// substation gateways and RTUs with twenty-year service lives.
//
// What it *has*, and Modbus does not, is a structure that says what a
// message means. Every I-format frame carries a type identification (what
// this is), a cause of transmission (why it was sent) and a common address
// (which station), and the process commands are a small numbered set. So
// the policy here is written in those terms rather than in register
// numbers: which stations a control centre may address, which commands it
// may send them, whether a dangerous command has to be selected before it
// is executed, and which information object addresses each command may
// name.
type IEC104Listener struct {
	// Mode is reverse (the default: a controlling station connects here
	// and the listener dials the controlled station) or forward (this
	// listener is the controlled egress a control centre uses to reach
	// stations elsewhere).
	Mode string `yaml:"mode"`
	// Upstream is the station pool this listener relays to. Required.
	//
	// There is deliberately no per-address routing here, and the reason is
	// the protocol's own shape: an IEC 104 connection is a long-lived
	// *association* between one controlling station and one controlled
	// station, and the first thing a control centre sends is STARTDT_act,
	// a U-format frame that carries no common address at all. A relay that
	// chose a pool from the common address could not choose one until the
	// first I frame, by which time the association is already up and the
	// handshake already answered -- so a route would be a pool selector
	// that cannot select in time. One listener per association is the
	// honest shape; common_addresses is what bounds which stations may be
	// addressed through it.
	Upstream string `yaml:"upstream"`
	// TLSMode is implicit (IEC 62351-3: TLS from the first octet) or
	// none. Default implicit when the listener has a tls section. The
	// standard's own port for it is 2404 either way, which is why the
	// mode is a setting rather than inferred from the port.
	TLSMode string `yaml:"tls_mode"`
	// UpstreamTLSMode is none or implicit: whether this listener speaks
	// TLS to the station.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS verifies the station when upstream_tls_mode is not none.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// AllowClients and DenyClients are the networks a controlling station
	// may connect from. Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// CommonAddresses is the shorthand allow list of common addresses,
	// written as numbers or "1-16" ranges. Empty allows every address the
	// rules do. A control centre that may address one substation and
	// reaches ten is the commonest finding in this protocol.
	CommonAddresses []string `yaml:"common_addresses"`
	// MonitorOnly refuses every command and every system command, for
	// every client, before any rule is read: the relay carries telemetry
	// up and nothing down. It is the shorthand for a historian or a
	// neighbouring utility's data link, and no rule can override it,
	// because a monitor-only listener that one rule could command
	// through is not a monitor-only listener.
	MonitorOnly bool `yaml:"monitor_only"`
	// Rules decide each frame, in order, first match wins. A frame that
	// matches no rule takes DefaultAction.
	Rules []IEC104Rule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is how a refused activation is answered: negative
	// (the default: the same ASDU returned with the negative-confirm bit
	// and cause actcon, which is what the standard says a station does
	// and what a control centre's alarm list understands), drop (no
	// answer, which the centre reads as a timeout) or close.
	DenyResponse string `yaml:"deny_response"`
	// Deception answers as a substation that is not there: a refused
	// activation confirmed instead of refused, or a whole listener that is
	// a fabricated station. See IEC104Deception.
	Deception *IEC104Deception `yaml:"deception"`
	// Learn records what crosses this listener and writes a proposed policy,
	// because a policy written from the substation drawings refuses half the
	// traffic on the first shift. See IEC104Learn.
	Learn *IEC104Learn `yaml:"learn"`
	// Setpoints bound the *value* a setpoint command may carry, per
	// information object address. Without them a setpoint is bounded only
	// by which point it names and when it may be sent, so a control
	// centre that may move a setpoint at all may move it to anything the
	// encoding can hold -- which on a scaled value is -32768 to 32767 and
	// on a short float is most of the real line.
	Setpoints []IEC104Setpoint `yaml:"setpoints"`
	// Measurements bound the value a *station* may report on a point, which
	// is the same arithmetic pointed the other way.
	Measurements []IEC104Measurement `yaml:"measurements"`
	// Quality is what to do about the quality descriptor a monitored value
	// carries: which bits are worth an alert, and which -- if any -- refuse
	// the frame.
	Quality *IEC104Quality `yaml:"quality"`
	// Timestamps is the policy about the time tag a command carries, which
	// is this protocol's own replay check.
	Timestamps *IEC104Timestamps `yaml:"timestamps"`
	// Authentication is the posture on IEC 60870-5-7 secure authentication,
	// which IEC 62351-5 specifies.
	Authentication *IEC104Authentication `yaml:"authentication"`
	// RequireSelect makes the two-step form mandatory for every command
	// type that has one: a command must be selected, by the same client
	// on the same connection, before it is executed. The standard
	// describes select-before-operate; the equipment mostly does not
	// enforce it, which is the gap this closes.
	RequireSelect bool `yaml:"require_select"`
	// SelectTimeout is how long a selection stays valid. Default 30s. A
	// selection that never expired would let an execute sent hours later
	// ride on it.
	SelectTimeout Duration `yaml:"select_timeout"`
	// MaxSelections bounds the outstanding selections this relay
	// remembers. Default 4096.
	MaxSelections int `yaml:"max_selections"`
	// Redundancy declares the connection groups of edition 2: the sets of
	// connections that are one controlling station, of which exactly one
	// carries data at a time.
	Redundancy *IEC104Redundancy `yaml:"redundancy"`
	// AllowControls is the U-format control functions a client may send:
	// STARTDT_act, STOPDT_act, TESTFR_act and their confirmations. Empty
	// allows all of them. STOPDT_act is the one worth naming: it stops
	// data transfer, which blinds a control room without refusing
	// anything.
	AllowControls []string `yaml:"allow_controls"`
	// K and W are the protocol's window parameters: k is how many
	// I frames an end may have unacknowledged before it stops sending, w
	// is after how many received frames it acknowledges. Defaults 12 and
	// 8, the standard's own.
	//
	// The relay uses them as an end, not only as a checker. It cannot
	// forward the sequence numbers the two ends chose, because it refuses
	// frames and answers some itself, and a stream with a hole in its
	// numbering is one a conforming implementation drops the association
	// over -- so it numbers what it writes, acknowledges what it reads at
	// w, and refuses an end that has k frames outstanding that it has not
	// yet acknowledged.
	K int `yaml:"k"`
	W int `yaml:"w"`
	// CheckSequence refuses an I frame whose send sequence number is not
	// the next one, which is a lost frame, a duplicated station or a
	// replayed command. Default true: this protocol numbers its frames
	// precisely so that the gap can be seen.
	CheckSequence *bool `yaml:"check_sequence"`
	// MaxUnacknowledged refuses a station that has more than k
	// unacknowledged I frames outstanding. Default true.
	MaxUnacknowledged *bool `yaml:"max_unacknowledged"`
	// MaxConnections bounds live sessions. Default 32.
	MaxConnections int `yaml:"max_connections"`
	// IdleTimeout closes a session that says nothing. Default 120s,
	// which is longer than the standard's t3 so that a station's own
	// keepalive keeps a quiet link open.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// ConnectTimeout bounds dialling the station. Default 5s.
	ConnectTimeout Duration `yaml:"connect_timeout"`
	// MaxFrameBytes bounds one APDU. Default 255, which is the protocol's
	// own bound because the length is one octet.
	MaxFrameBytes int `yaml:"max_frame_bytes"`
	// RateLimit and RateBurst bound frames per second per client address.
	// Zero disables them.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// CommandRateLimit and CommandRateBurst bound *commands* per second
	// per client, separately from the frames, because a control centre
	// that sends a thousand breaker commands a second is not a busy
	// control centre. Zero disables them.
	CommandRateLimit int `yaml:"command_rate_limit"`
	CommandRateBurst int `yaml:"command_rate_burst"`
	// LogFrames writes an access line per frame rather than per session.
	// On this protocol a station's periodic telemetry is most of the
	// traffic, so this is a lot of lines; LogCommands is usually what an
	// operator wants instead.
	LogFrames bool `yaml:"log_frames"`
	// LogCommands writes an access line for every command and system
	// command, in both directions, and leaves the telemetry alone.
	// Default true: a record of what was commanded is the thing a grid
	// operator is asked for after an incident.
	LogCommands *bool `yaml:"log_commands"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// ProxyProtocol sends a PROXY protocol v2 header to the station.
	ProxyProtocol bool `yaml:"proxy_protocol"`
}

// SNMPListener configures a kind: snmp listener: an SNMP relay in front of
// the equipment that management protocol actually manages.
//
// SNMP runs every switch, router, printer, UPS and building controller in an
// estate, and versions 1 and 2c authenticate with a *community string*: a
// cleartext password in every datagram, "public" to read and "private" to
// write on anything nobody reconfigured. No integrity, no replay protection,
// no confidentiality. One datagram with the right string reads a device's
// whole configuration; one with the write string changes it. Version 3 has a
// real security model and also has noAuthNoPriv, which is version 2c with
// more fields.
//
// The devices cannot be fixed, so the policy lives here. What it is written
// about is what the protocol says out loud: the version, the credential, the
// operation, and the object identifiers being read or written.
type SNMPListener struct {
	// Mode is reverse (the default: managers connect here and the listener
	// forwards to the agents) or forward (this listener is the controlled
	// egress a management station uses to reach agents elsewhere).
	Mode string `yaml:"mode"`
	// Upstream is the agent pool a request goes to. Required in reverse
	// mode.
	Upstream string `yaml:"upstream"`
	// Transport is udp (the default) or tcp, and it decides whether this
	// listener takes datagrams as well as streams. It always takes
	// streams: SNMP over TCP is what RFC 3430 defines and what the TLS
	// transport of RFC 6353 runs over, and a bound port nothing accepts on
	// would leave a client hanging instead of being decided about. udp adds
	// the datagram socket every poller and every agent actually speaks.
	Transport string `yaml:"transport"`
	// Traps makes this a trap listener rather than an agent front: the
	// datagrams arrive from agents and go to a manager, which is the
	// opposite direction and a different policy. Port 162 rather than 161.
	Traps bool `yaml:"traps"`
	// TLSMode is implicit (RFC 6353, TLS from the first octet on TCP
	// 10161) or none. Default implicit when the listener has a tls
	// section. This is the half of the secure upgrade that faces the
	// manager: TLS and a certificate towards the management station, plain
	// v2c towards a switch that will never speak either.
	TLSMode string `yaml:"tls_mode"`
	// UpstreamTLSMode is none or implicit: whether this listener speaks
	// RFC 6353 TLS to the agent.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS verifies the agent when upstream_tls_mode is not none.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// DTLSMode puts RFC 6353's transport model on the transport this
	// protocol actually uses: none (the default), implicit, or detect.
	//
	// implicit is the standard's own arrangement -- UDP 10161, DTLS from the
	// first octet, every datagram inside a session. A manager authenticates
	// with a certificate, which is an identity an estate already knows how
	// to issue, revoke and rotate, rather than a USM pass phrase per user
	// per engine; and because the session carries the security, the relay
	// can answer a refusal and rebuild a response without holding a
	// credential of the manager's. That is the half of the secure upgrade
	// facing the management station, with plain v2c going on towards a
	// switch whose firmware has nothing else.
	//
	// detect takes both on one port: a datagram beginning with a DTLS
	// content type is a record, one beginning with a BER SEQUENCE is a plain
	// SNMP message, and the two cannot be confused because 0x30 is not a
	// content type and no content type is 0x30. It is not what RFC 6353
	// describes -- the standard gives DTLS a port of its own -- and it
	// exists for the estate that is moving: the new managers speak DTLS and
	// the old pollers do not, and nobody is going to reconfigure two hundred
	// switches to change a port. What it costs is stated plainly: a client
	// chooses which of the two it speaks, so the *policy* has to be what
	// requires the certificate. Write rules naming transports, keep
	// default_action at deny, and validation will say so if you do not.
	//
	// Either mode needs a tls section for the certificate, and a
	// client_ca_file with client_auth: require_and_verify is what makes the
	// identity worth naming -- without it a peer presents whatever it likes.
	DTLSMode string `yaml:"dtls_mode"`
	// DTLSHandshakeTimeout is how long a peer has to finish a handshake.
	// Default 10s. It is the bound that matters most on a datagram
	// listener: a handshake is where a peer that has proved nothing already
	// costs a socket, a goroutine and a slot in the peer table.
	DTLSHandshakeTimeout Duration `yaml:"dtls_handshake_timeout"`
	// DTLSIdleTimeout is how long a session with nothing on it is kept.
	// Default 5m. A poller on a thirty-second cycle keeps its session,
	// which matters because the handshake is the expensive part of the
	// exchange; something that handshook and went quiet does not.
	DTLSIdleTimeout Duration `yaml:"dtls_idle_timeout"`
	// MaxDTLSPeers bounds the DTLS sessions this listener holds. Default
	// 64. Past it a new peer's datagrams are dropped and counted, because
	// there is no session to refuse them in.
	MaxDTLSPeers int `yaml:"max_dtls_peers"`
	// CertToName is RFC 6353 s5.3's snmpTlstmCertToTSNTable: how a peer's
	// certificate becomes the security name a rule names. Rows are ordered
	// and the first whose fingerprint matches decides.
	//
	// Without it a message under the transport security model has no name,
	// and what happens then is require_security_name's business. See
	// SNMPCertName.
	CertToName []SNMPCertName `yaml:"cert_to_name"`
	// RequireSecurityName refuses a transport security model message whose
	// certificate maps to no name. Default true.
	//
	// It is true by default because the alternative is a message with no
	// credential at all: the transport model carries no user, no engine and
	// no digest, so if the certificate maps to nothing then nothing
	// identifies the sender and every rule naming a security name is
	// unmatchable. Turning it off is for a listener whose policy decides on
	// the address and the objects alone, and which wants DTLS for
	// confidentiality rather than for identity.
	RequireSecurityName *bool `yaml:"require_security_name"`
	// AllowClients and DenyClients are the networks a manager may send
	// from. Deny is evaluated first. On this protocol the client list is
	// the most valuable line in the file after read_only, because a
	// community string is not a secret in any useful sense.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// Versions is the allow list of protocol versions: v1, v2c, v3. Empty
	// allows all three, which validation advises against. "v3 only" is the
	// single most useful line an operator can write here.
	Versions []string `yaml:"versions"`
	// Communities is the allow list of community strings for v1 and v2c.
	// Empty allows any, which validation warns about: the defaults are
	// known to everyone and scanned for constantly.
	Communities []string `yaml:"communities"`
	// Users is the allow list of v3 USM user names. Empty allows any.
	Users []string `yaml:"users"`
	// MinSecurityLevel refuses a v3 message below a level:
	// noAuthNoPriv (the default, which refuses nothing), authNoPriv or
	// authPriv. noAuthNoPriv is v2c with more fields, so a listener that
	// went to the trouble of requiring v3 usually wants authNoPriv at
	// least.
	MinSecurityLevel string `yaml:"min_security_level"`
	// ReadOnly refuses every SetRequest, for every client, before any rule
	// is read, and no rule can override it. SNMP has exactly one writing
	// operation, so this is a one-line policy that covers the whole of
	// "nobody reconfigures anything through this relay" -- and a read-only
	// listener that one rule could write through is not a read-only
	// listener.
	ReadOnly bool `yaml:"read_only"`
	// UpgradeVersion rewrites the version a message is forwarded in.
	// Empty forwards the version that arrived.
	//
	// It is a relay of intent rather than a translation of credentials:
	// the community string sent upstream is upstream_community, and the
	// manager never needs to know it. A response is rebuilt in the version
	// its request arrived in, so the manager sees the version it spoke.
	//
	// Producing v3 needs upstream_usm: an identity of this relay's own.
	// Without one there is no pass phrase to authenticate with and the
	// relay will not forge an authentication that did not happen, so
	// upgrade_version: v3 is refused at load. With one the relay
	// terminates the manager's security and originates its own, which is
	// the secure upgrade this protocol needs most -- and which means the
	// relay is a party to the security rather than a reader of it. See
	// upstream_usm.
	//
	// Downgrading a v3 *request* is a different matter and is still
	// refused: the answer would come back as v3 from an engine this
	// relay did not ask as itself, so there would be nothing to
	// authenticate it with. A v3 *notification* downgrades cleanly,
	// because nothing comes back: that is the modern-device,
	// legacy-collector case, and it is what traps: true plus
	// upgrade_version: v2c is for.
	UpgradeVersion string `yaml:"upgrade_version"`
	// UpstreamCommunity is the community string sent to the agent, which
	// is what lets the manager stop knowing it. Required with
	// upgrade_version v1 or v2c when the arriving message is v3, because
	// there is no community string in a v3 message to carry over.
	UpstreamCommunity string `yaml:"upstream_community"`
	// UpstreamUSM is the version 3 identity this relay presents to the
	// agent, and it is what `upgrade_version: v3` needs. With it the relay
	// terminates whatever security the manager used and originates a USM
	// session of its own: a v1 or v2c poller reaches a v3-only agent, at a
	// level the poller cannot speak, with a pass phrase the poller never
	// holds.
	//
	// That is the point and it is also the cost, so it is said plainly:
	// the relay becomes a party to the security rather than a reader of
	// it. Two sessions exist, this process holds the agent's keys, and
	// there is no end-to-end authentication between the manager and the
	// agent any more -- the manager authenticates to the relay (or does
	// not, on v1 and v2c) and the relay authenticates to the agent. An
	// estate that wants end-to-end USM wants `upgrade_version` unset and
	// `usm_users` for reading.
	//
	// The engine identifier is discovered from the agent rather than
	// configured, because it is the agent's to state; engine_id pins it
	// where an operator knows it, and then a message from an engine that
	// calls itself something else is not answered.
	UpstreamUSM *SNMPUser `yaml:"upstream_usm"`
	// UpstreamSecurityLevel is the level this relay originates at:
	// noAuthNoPriv, authNoPriv or authPriv. Default authPriv when
	// upstream_usm has a privacy protocol and authNoPriv when it does not,
	// because the reason to configure a privacy pass phrase is to use it.
	UpstreamSecurityLevel string `yaml:"upstream_security_level"`
	// USMUsers are the version 3 users whose traffic this listener can
	// read. Without them a v3 message is a header and an opaque payload:
	// the user, the engine and the security level are visible and nothing
	// else is, so no rule about an operation or an object can apply to it.
	// With the user's pass phrases the digest is verified and, at authPriv,
	// the payload is decrypted -- and then the ordinary rules decide about
	// a v3 message exactly as they do about a v2c one.
	//
	// Nothing is re-encrypted or re-signed with these keys: the octets
	// forwarded to the agent are the octets that arrived. They are here so
	// that this relay can *read*, which is the only thing it needs them
	// for. Originating a message of this relay's own is upstream_usm,
	// which is a separate decision with separate consequences.
	USMUsers []SNMPUser `yaml:"usm_users"`
	// ReplayWindow is how far behind an authenticated message's notion of
	// the agent's clock may be before it is refused as a replay, which is
	// RFC 3414 s2.2.3's own check. Default 150s, which is the value the
	// standard names. Zero disables it.
	//
	// It applies only to messages this listener can verify -- an
	// unverifiable message has no trustworthy clock in it -- and only to
	// authenticated ones, because discovery is unauthenticated and carries
	// a clock of zero by design.
	ReplayWindow Duration `yaml:"replay_window"`
	// MaxUSMEngines bounds the distinct authoritative engines one user's
	// keys are derived for. Default 8.
	//
	// It is a bound on work rather than on policy. Deriving a key is a
	// megabyte of hashing by design (RFC 3414 s2.6, so that a dictionary
	// attack costs a megabyte per candidate), and the engine identifier
	// that decides which key is needed comes out of the message. Without a
	// bound, a sender that varied that field would be buying milliseconds
	// of this relay's processor per datagram.
	MaxUSMEngines int `yaml:"max_usm_engines"`
	// Deception answers as an agent that is not there: a refused request
	// answered by a fabricated device, or a whole listener that is one.
	// See SNMPDeception.
	Deception *SNMPDeception `yaml:"deception"`
	// Rules decide each message, in order, first match wins. A message
	// that matches no rule takes DefaultAction.
	Rules []SNMPRule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is how a refused request is answered: error (the
	// default: a Response PDU carrying the noAccess error, which is what
	// an agent sends and what every manager already displays), drop (no
	// answer, which the manager reads as a timeout) or close (end the
	// connection, on a TCP listener only).
	DenyResponse string `yaml:"deny_response"`
	// MaxRepetitions bounds a GETBULK's max-repetitions field, which is
	// the amplification factor of the best-known SNMP reflection attack: a
	// request of forty octets asking for a response of megabytes. Default
	// 100. Zero leaves the protocol's own absence of a bound, which
	// validation warns about.
	MaxRepetitions int `yaml:"max_repetitions"`
	// MaxVarBinds bounds the variable bindings one message may carry.
	// Default 128.
	MaxVarBinds int `yaml:"max_var_binds"`
	// MaxResponseBytes bounds one response. Default 8192. It is the other
	// half of the amplification bound: max_repetitions bounds what was
	// asked for and this bounds what came back, and an agent that ignores
	// the first still cannot get past the second.
	MaxResponseBytes int `yaml:"max_response_bytes"`
	// MaxResponseRatio refuses a response more than this many times the
	// size of the request that asked for it. Default 50. It is the bound
	// that is about *reflection* rather than about size: a large response
	// to a large request is a walk, and a large response to a tiny request
	// is an amplifier.
	MaxResponseRatio int `yaml:"max_response_ratio"`
	// MaxPending bounds the requests this listener has outstanding towards
	// agents on the datagram path, where the request identifier is what
	// pairs an answer with its question. Default 32. A full table refuses
	// the new request rather than forgetting an old one, because forgetting
	// would make that pairing -- which is the check that finds an
	// unsolicited response -- unreliable.
	MaxPending int `yaml:"max_pending"`
	// MaxConnections bounds live TCP sessions. Default 32; ignored on a
	// UDP listener.
	MaxConnections int `yaml:"max_connections"`
	// IdleTimeout closes a TCP session that says nothing, and expires a
	// UDP client's association. Default 60s.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// RequestTimeout bounds how long the agent has to answer. Default 5s.
	RequestTimeout Duration `yaml:"request_timeout"`
	// ConnectTimeout bounds dialling the agent on a TCP listener.
	// Default 5s.
	ConnectTimeout Duration `yaml:"connect_timeout"`
	// MaxMessageBytes bounds one message. Default 8192; the protocol's own
	// floor is 484 octets and 1472 is what fits an Ethernet datagram.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// RateLimit and RateBurst bound messages per second per client
	// address. Zero disables them. An SNMP poll is periodic and its rate
	// is known, so this bound is unusually easy to set correctly.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// LogMessages writes an access line per message rather than per
	// session. A poller asks the same questions every thirty seconds, so
	// this is a lot of lines; LogWrites is usually what an operator wants.
	LogMessages bool `yaml:"log_messages"`
	// LogWrites writes an access line for every SetRequest and every
	// refusal, and leaves the polling alone. Default true: what was
	// *changed* through this relay is the record an estate is asked for.
	LogWrites *bool `yaml:"log_writes"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// ProxyProtocol sends a PROXY protocol v2 header to the agent on a TCP
	// listener.
	ProxyProtocol bool `yaml:"proxy_protocol"`
}

// LDAPListener is a kind: ldap listener: an LDAP and LDAPS relay in front of
// a directory.
type LDAPListener struct {
	// Mode is reverse (the default: clients connect here and the listener
	// forwards to the directory) or forward (this listener is the
	// controlled egress an application uses to reach a directory
	// elsewhere).
	Mode string `yaml:"mode"`
	// Upstream is the directory pool. Required.
	Upstream string `yaml:"upstream"`
	// TLSMode is implicit (LDAPS: TLS from the first octet, port 636),
	// starttls (the extended operation of RFC 4513 on port 389, which this
	// relay terminates itself) or none. Default implicit when the listener
	// has a tls section and starttls is not asked for.
	TLSMode string `yaml:"tls_mode"`
	// RequireTLS refuses a simple bind that carries a password on an
	// unprotected connection. Default true, and it is the most valuable
	// line in the file: LDAP on port 389 with a simple bind puts a
	// directory password in the clear on the wire, and the client library
	// that did it will not tell anyone.
	RequireTLS *bool `yaml:"require_tls"`
	// UpstreamTLSMode is none, implicit or starttls: how this listener
	// reaches the directory. Together with tls_mode this is the secure
	// upgrade -- TLS towards the client, whatever the directory will take
	// towards the directory, or the reverse for a client library nobody
	// can reconfigure.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS verifies the directory when upstream_tls_mode is not
	// none.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// AllowClients and DenyClients are the networks a client may connect
	// from. Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// MinVersion is the lowest LDAP version accepted. Default 3. LDAPv2 is
	// a different protocol wearing the same tags and its bind has no
	// SASL; a directory that still answers it is one nobody has looked at.
	MinVersion int `yaml:"min_version"`
	// Methods is the allow list of bind methods: anonymous,
	// unauthenticated, simple, sasl. Empty allows simple and sasl, which
	// is to say it refuses the two that are anonymous binds wearing a
	// name.
	//
	// unauthenticated is the one to read twice. A simple bind with a name
	// and an *empty* password is an anonymous bind by RFC 4513 §5.1.2, and
	// a great many directories answer it with success -- which the
	// application behind them reads as "the password was right". Allowing
	// it is almost never what anyone means.
	Methods []string `yaml:"methods"`
	// SASLMechanisms is the allow list of SASL mechanisms by name
	// (GSSAPI, DIGEST-MD5, EXTERNAL, PLAIN). Empty allows any. PLAIN puts
	// a password in the clear exactly as a simple bind does, which is why
	// naming the mechanisms is worth doing.
	SASLMechanisms []string `yaml:"sasl_mechanisms"`
	// BaseDNs are the suffixes any request may name at all: the naming
	// contexts this relay fronts. A request naming an object outside all
	// of them is refused before the rules and whatever default_action
	// says, which is what stops one listener from being a way into a
	// directory's other trees. Empty allows any, which validation advises
	// against.
	//
	// The comparison is per relative name from the root, so
	// dc=example,dc=com does not cover dc=notexample,dc=com -- which a
	// string suffix test would.
	BaseDNs []string `yaml:"base_dns"`
	// ReadOnly refuses every operation that changes the directory -- add,
	// delete, modify, modifyDN -- for every client, before any rule is
	// read, and no rule can override it.
	ReadOnly bool `yaml:"read_only"`
	// DenyAttributes are the attributes this relay will not carry: it
	// refuses a request that names one and removes it from an answer that
	// carries it anyway. Both halves are needed, because a search that
	// asks for "*" gets every user attribute without naming one.
	//
	// Unset means the built-in list, which is the password and key
	// material of the directories people actually run: userPassword,
	// unicodePwd, dBCSPwd, ntPwdHistory, lmPwdHistory, pwdHistory,
	// supplementalCredentials, msDS-ManagedPassword, ms-Mcs-AdmPwd,
	// ms-Mcs-AdmPwdExpirationTime, krbPrincipalKey, sambaNTPassword,
	// sambaLMPassword, sambaPasswordHistory and userPKCS12. Setting the
	// list replaces it; validation warns if the replacement drops
	// userPassword.
	DenyAttributes []string `yaml:"deny_attributes"`
	// OnDeniedAttribute is strip (the default: remove it from the answer
	// and carry the rest) or deny (refuse the whole operation). strip is
	// the useful one: an application that asked for everything still works
	// and no longer receives a password hash.
	OnDeniedAttribute string `yaml:"on_denied_attribute"`
	// MaxEntries bounds the entries one search may return. Default 500. It
	// is this protocol's amplification bound: an unbounded subtree search
	// with (objectClass=*) is how a directory is copied, and the client's
	// own size limit is a request rather than a bound.
	MaxEntries int `yaml:"max_entries"`
	// MaxFilterTerms and MaxFilterDepth bound a search filter's shape.
	// Defaults 64 and 12. A filter is the one part of a request whose size
	// the client chooses and whose cost the directory pays.
	MaxFilterTerms int `yaml:"max_filter_terms"`
	MaxFilterDepth int `yaml:"max_filter_depth"`
	// AllowLeadingWildcard permits a substring filter whose first
	// component is a wildcard -- (cn=*smith) -- which no index can serve
	// and which is therefore a scan of the subtree. Default true, because
	// every address book does it; set it false on a listener that fronts a
	// large directory.
	AllowLeadingWildcard *bool `yaml:"allow_leading_wildcard"`
	// ExtendedOperations is the allow list of extended operation OIDs.
	// Empty allows only StartTLS, which this relay terminates rather than
	// forwards. The two worth naming if you allow more are
	// 1.3.6.1.4.1.4203.1.11.1 (password modify) and
	// 1.3.6.1.4.1.4203.1.11.3 (who am I).
	ExtendedOperations []string `yaml:"extended_operations"`
	// DenyControls are control OIDs this relay refuses to carry. Empty
	// carries any control, which is the right default: a control this
	// relay does not know is one the directory decides about, and RFC 4511
	// already says an unrecognised critical control is refused there.
	DenyControls []string `yaml:"deny_controls"`
	// Rules decide each request, in order, first match wins.
	Rules []LDAPRule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is how a refused request is answered: insufficient (the
	// default: result code 50, insufficientAccessRights, which is what a
	// directory sends and what every client already displays), unwilling
	// (53), drop (no answer, which the client reads as a hang) or close
	// (end the connection).
	DenyResponse string `yaml:"deny_response"`
	// MaxOutstanding bounds the requests one connection may have in flight.
	// Default 32. LDAP is asynchronous and multiplexed, so this is what
	// keeps the table that pairs a response with its request bounded.
	MaxOutstanding int `yaml:"max_outstanding"`
	// MaxConnections bounds live sessions. Default 256.
	MaxConnections int `yaml:"max_connections"`
	// IdleTimeout closes a session that says nothing. Default 300s: a
	// pooled directory connection is idle by design.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// RequestTimeout bounds how long the directory has to answer one
	// request. Default 30s.
	RequestTimeout Duration `yaml:"request_timeout"`
	// ConnectTimeout bounds dialling the directory. Default 5s.
	ConnectTimeout Duration `yaml:"connect_timeout"`
	// MaxMessageBytes bounds one message. Default 262144: a directory entry
	// with a photograph or a certificate in it is real.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// RateLimit and RateBurst bound requests per second per client
	// address. Zero disables them.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// BindRateLimit and BindRateBurst bound *binds* per second per client
	// address, separately, because a rate loose enough for an
	// application's searches says nothing about somebody trying passwords.
	// Zero disables them.
	BindRateLimit int `yaml:"bind_rate_limit"`
	BindRateBurst int `yaml:"bind_rate_burst"`
	// LogRequests writes an access line per request. A directory front
	// carries a great many searches, so this is a lot of lines.
	LogRequests bool `yaml:"log_requests"`
	// LogBinds writes an access line for every bind and its outcome.
	// Default true: who authenticated, from where, as whom, and whether it
	// worked is the record an estate is asked for.
	LogBinds *bool `yaml:"log_binds"`
	// LogWrites writes an access line for every operation that changes the
	// directory, and for every refusal. Default true.
	LogWrites *bool `yaml:"log_writes"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// ProxyProtocol sends a PROXY protocol v2 header to the directory.
	ProxyProtocol bool `yaml:"proxy_protocol"`
}

// LDAPRule decides one request.
type LDAPRule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before it
	// decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the client is in.
	Clients []string `yaml:"clients"`
	// BindDNs are the identities this rule covers, as distinguished names.
	// A name here covers itself and everything below it, so
	// ou=services,dc=example,dc=com covers every service account in that
	// container. An empty name matches an unbound or anonymous connection,
	// which is how "before you authenticate, you may do this and no more"
	// is written.
	BindDNs []string `yaml:"bind_dns"`
	// Methods are the bind methods this rule covers, for a rule about how
	// the connection authenticated rather than as whom.
	Methods []string `yaml:"methods"`
	// Operations are the operations by name: bind, search, compare,
	// modify, add, delete, modify_dn, extended, abandon, unbind.
	Operations []string `yaml:"operations"`
	// Access matches what the operation does: read, write, bind. It is the
	// durable way to write a policy, because it does not change when a
	// later revision adds an operation.
	Access []string `yaml:"access"`
	// BaseDNs are the suffixes the request may name. A request naming an
	// object outside all of them does not match. The comparison is per
	// relative name.
	BaseDNs []string `yaml:"base_dns"`
	// DenyDNs are suffixes this rule does not cover even when BaseDNs
	// would match, which is how an exception inside an allowed subtree is
	// written: all of the directory except the administrators container.
	DenyDNs []string `yaml:"deny_dns"`
	// Scopes are the search scopes this rule covers: base, one, sub. A
	// rule that omits them covers any scope, which on a wide base is
	// usually not what was meant: a subtree search from a naming context
	// is a request for the whole tree.
	Scopes []string `yaml:"scopes"`
	// Attributes are the attributes a request may name and an answer may
	// carry. Empty allows any that the listener's deny_attributes does not
	// refuse.
	Attributes []string `yaml:"attributes"`
	// DenyAttributes are refused or stripped for the traffic this rule
	// covers, in addition to the listener's own list.
	DenyAttributes []string `yaml:"deny_attributes"`
	// MaxEntries overrides the listener's bound on entries returned, for
	// the searches this rule covers.
	MaxEntries int `yaml:"max_entries"`
	// MaxFilterTerms and MaxFilterDepth override the listener's filter
	// bounds. A rule does not cover a filter past its own bound, so the
	// next rule -- or the default -- decides; matching and then allowing
	// would make the bound a suggestion.
	MaxFilterTerms int `yaml:"max_filter_terms"`
	MaxFilterDepth int `yaml:"max_filter_depth"`
	// AllowLeadingWildcard overrides the listener's setting for this
	// rule's traffic.
	AllowLeadingWildcard *bool `yaml:"allow_leading_wildcard"`
	// Schedule limits the rule to a time window.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// TFTPListener is a kind: tftp listener: a TFTP relay in front of the
// servers that move firmware, configurations and boot images around an
// estate.
//
// There is nothing to authenticate with in this protocol, so the whole of
// the policy is the address it came from, the direction of the transfer,
// the path it asked for and the size of what comes back.
// MySQLListener is the settings of a kind: mysql listener: a relay in front of a
// MySQL or MariaDB server.
//
// PostgreSQL's dangerous operations are statements, so a statement policy reaches
// them all. MySQL's are **commands** -- one octet each, with no SQL involved --
// and that is why this section has an `allow_commands` list where the postgres
// one does not. COM_SHUTDOWN is one octet and stops the server; the three
// replication commands are a copy of every change to every database;
// COM_CREATE_DB and COM_DROP_DB predate the DDL statements and bypass any
// statement policy entirely.
//
// The other MySQL-specific move is `deny_capabilities`, which *strips* bits from
// the server's greeting rather than refusing the connection. A client that never
// sees CLIENT_LOCAL_FILES offered cannot negotiate it, so the server can never
// ask that client for a file -- and the application still works. Refusing
// instead would mean everything on the segment breaks until somebody
// reconfigures a driver, which is how a security control gets turned off.
type MySQLListener struct {
	// Upstream is the server pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may connect from.
	// Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`

	// RequireTLS refuses a client that does not set CLIENT_SSL. Default true.
	//
	// The negotiation is a capability flag and nothing signs the server's
	// greeting, so anything on the path can clear CLIENT_SSL from the
	// advertised capabilities and the client will never ask. This is
	// PostgreSQL's SSLRequest problem with a different encoding, and it gets
	// the same answer: the relay decides, not the octets.
	RequireTLS *bool `yaml:"require_tls"`
	// UpstreamTLSMode is how the relay speaks to the server: require (the
	// default), prefer or disable.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS is the certificate and verification settings for that leg.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`

	// AllowUsers, DenyUsers, AllowDatabases and DenyDatabases are the identity
	// claims a connection may make. They are re-checked on COM_CHANGE_USER,
	// which re-authenticates a live connection as somebody else -- a relay that
	// did not would have a user policy that applied to the first message and
	// nothing after it.
	AllowUsers     []string `yaml:"allow_users"`
	DenyUsers      []string `yaml:"deny_users"`
	AllowDatabases []string `yaml:"allow_databases"`
	DenyDatabases  []string `yaml:"deny_databases"`

	// AllowAuth is the allow list of authentication plugins, named as the
	// server names them: caching_sha2_password, mysql_native_password,
	// sha256_password, mysql_clear_password, mysql_old_password. Empty allows
	// any that is not weak.
	AllowAuth []string `yaml:"allow_auth"`
	// AllowWeakAuth permits mysql_clear_password (the password itself) and
	// mysql_old_password (the pre-4.1 scramble, removed from the server in
	// 5.7). Default false.
	//
	// mysql_native_password is deliberately not in that set: its
	// challenge-response discloses no reusable secret, and treating it as weak
	// would make this setting one operators turn off wholesale.
	AllowWeakAuth bool `yaml:"allow_weak_auth"`

	// AllowCommands is the allow list of protocol commands. Empty allows what
	// an application driver sends and nothing administrative: query,
	// stmt_prepare, stmt_execute, stmt_send_long_data, stmt_close, stmt_reset,
	// stmt_fetch, init_db, ping, quit, statistics, reset_connection,
	// set_option and change_user.
	//
	// The absences are the point: shutdown, debug, process_kill, the three
	// replication commands, table_dump, create_db, drop_db, refresh,
	// process_info, clone and field_list are all off unless named.
	AllowCommands []string `yaml:"allow_commands"`
	// DenyCommands is the deny list, which no rule can override.
	DenyCommands []string `yaml:"deny_commands"`

	// DenyCapabilities are the capability bits stripped from the server's
	// greeting so a client cannot negotiate them. Empty strips local_files,
	// multi_statements and compress.
	//
	// local_files lets the server ask the *client* to open a path and send its
	// contents, which is how a hostile server reads the filesystem of whatever
	// connected to it. multi_statements lets one query carry several statements
	// separated by semicolons, which is how every injection ending in
	// `; DROP TABLE` is delivered. compress hides the protocol from the relay
	// -- and from everything else that inspects it.
	//
	// `ssl` cannot be named here: stripping it would be performing the
	// downgrade this kind exists to prevent.
	DenyCapabilities []string `yaml:"deny_capabilities"`

	// ReadOnly refuses every statement that can change data, including call and
	// do.
	ReadOnly bool `yaml:"read_only"`
	// AllowStatements and DenyStatements are the statement kinds, as the
	// postgres kind names them. A statement the classifier cannot name is
	// refused whatever this says.
	AllowStatements []string `yaml:"allow_statements"`
	DenyStatements  []string `yaml:"deny_statements"`
	// AllowLoad names which LOAD DATA forms may cross: `file` (a path on the
	// server) or `local` (a path on the *client*). Empty allows neither, which
	// is the right default: bulk loading is a job, not something an
	// application connection does by accident.
	AllowLoad []string `yaml:"allow_load"`

	// MaxStatements bounds statements per query message. Default 1, because
	// multi_statements is stripped by default and a message carrying more than
	// one when the capability was refused is a client working around the
	// policy.
	MaxStatements int `yaml:"max_statements"`
	// MaxStatementBytes bounds one statement. Default 64 KiB.
	MaxStatementBytes int `yaml:"max_statement_bytes"`
	// MaxMessageBytes bounds one reassembled message. Default 1 MiB. The
	// protocol has no bound at all: a sender may chain 16 MiB packets for ever.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// MaxSessions and MaxSessionsPerClient bound concurrent connections.
	MaxSessions          int `yaml:"max_sessions"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	// IdleTimeout, SessionDuration and HandshakeTimeout bound a connection.
	IdleTimeout      Duration `yaml:"idle_timeout"`
	SessionDuration  Duration `yaml:"session_duration"`
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// AllowPrograms matches the client's `program_name` connection attribute,
	// with a trailing * allowed. It is chosen by the client and is not a
	// credential; it is useful for telling a migration tool from a reporting
	// dashboard when both connect as the same user.
	AllowPrograms []string `yaml:"allow_programs"`

	// Deception answers as a server that is not there: a refused statement
	// answered by a fabricated database, or a whole listener that is one. See
	// MySQLDeception.
	Deception *MySQLDeception `yaml:"deception"`

	// Rules narrow or widen the listener for traffic that matches them.
	Rules []MySQLRule `yaml:"rules"`
	// DefaultAction is allow or deny when no rule matched. Default deny.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is error (the default: an error packet the client's own
	// library reports) or drop.
	DenyResponse string `yaml:"deny_response"`
	// MonitorOnly evaluates and enforces nothing, except the hard decisions:
	// the client list, the TLS requirement, the authentication plugins, a
	// command or statement the relay could not read, a replication command, a
	// LOAD DATA LOCAL the capability forbids, and the capability stripping
	// itself -- which is not a refusal at all, so there is nothing to shadow.
	MonitorOnly bool `yaml:"monitor_only"`
}

// MySQLDeception answers as a MySQL server that is not there.
//
// On this protocol the reconnaissance is the attack's first half and it is
// entirely made of legitimate statements. A scanner finds the port, reads the
// greeting for a version, and then asks the questions that decide what is
// possible: which databases are there, what is `@@datadir`, is
// `@@secure_file_priv` empty, does this account have FILE. The answers decide
// whether the next statement writes a web shell with `INTO OUTFILE`, reads
// `/etc/passwd` with `LOAD_FILE`, asks the *client* for a file with
// `LOAD DATA LOCAL INFILE`, or installs a shared object with
// `CREATE FUNCTION ... SONAME`.
//
// A refusal ends that at the greeting. Answering it says which of those four
// they were reaching for.
type MySQLDeception struct {
	// Enabled turns the section off without removing it; it defaults to true
	// wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a statement this listener was going to
	// refuse is answered by the fabrication instead, and never reaches the
	// server) or decoy (the whole listener is a fabricated server: no
	// upstream, and nothing behind it).
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client, which is what a
	// honeypot wants.
	Clients []string `yaml:"clients"`
	// Profile is the fabricated server's shape: generic-mysql (the default),
	// mariadb or wordpress. It decides the version reported, the flavour, and
	// the databases and tables it claims to hold.
	Profile string `yaml:"profile"`
	// Version is the server version string in the greeting, which is the first
	// thing a scanner records and what a vulnerability database is indexed by.
	// Empty takes the profile's.
	//
	// **A decoy should say what the estate's own servers say.** A version
	// nobody on the site runs is the tell that ends the pretence, and only you
	// know what that is.
	Version string `yaml:"version"`
	// Databases replaces the profile's schema list, which is what SHOW
	// DATABASES answers and the first thing asked after the version.
	Databases []string `yaml:"databases"`
	// Tables replaces the profile's table list, as `database.table` names. It
	// is what SHOW TABLES answers, and it is the part of the fabrication a
	// visitor reads most closely.
	Tables []string `yaml:"tables"`
	// RequireAuth makes the fabrication refuse the login rather than accept it.
	//
	// Default false: accepting is what lets the reconnaissance happen at all,
	// and an account that works is what the scanning is looking for. Where it
	// is set, the attempt is still recorded -- the user name and the password
	// field's length, never the password.
	RequireAuth bool `yaml:"require_auth"`
	// Tripwire are object names -- a table, a function, a system variable --
	// that raise a mysql_tripwire security event when a statement mentions one.
	//
	// They are in addition to a built-in set, which is the escalation chain and
	// nothing else: mysql.user, LOAD_FILE, INTO OUTFILE, INTO DUMPFILE,
	// LOAD DATA LOCAL, CREATE FUNCTION with SONAME, secure_file_priv, SLEEP and
	// BENCHMARK. Nothing legitimate sends any of those to a fabricated
	// database, so they do not need to be configured to be worth waking
	// somebody for.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated values reproducible. Zero derives one from the
	// listener name, which is stable across restarts.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a counter or a gauge lasts. Default 30s;
	// 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
}

// MySQLRule is one rule of a mysql listener's policy.
type MySQLRule struct {
	// Name identifies the rule in logs and counters.
	Name string `yaml:"name"`
	// Clients, Users, Databases and Programs select the traffic. Programs
	// matches the client's `program_name` connection attribute, with a
	// trailing * allowed.
	Clients   []string `yaml:"clients"`
	Users     []string `yaml:"users"`
	Databases []string `yaml:"databases"`
	Programs  []string `yaml:"programs"`
	// Schedule is when this rule allows what it allows.
	Schedule *ModbusSchedule `yaml:"schedule"`
	// Action is allow (the default), deny or observe.
	Action string `yaml:"action"`
	// The rule's own narrowing. A rule that names a command or a statement kind
	// widens the listener for its own traffic; the deny lists always win.
	AllowCommands   []string `yaml:"allow_commands"`
	DenyCommands    []string `yaml:"deny_commands"`
	AllowStatements []string `yaml:"allow_statements"`
	DenyStatements  []string `yaml:"deny_statements"`
	AllowLoad       []string `yaml:"allow_load"`
	ReadOnly        *bool    `yaml:"read_only"`
	MaxStatements   int      `yaml:"max_statements"`
}

// RedisListener is the settings of a kind: redis listener: a relay in front of a
// Redis or Valkey server.
//
// This is the protocol with the least structure and the most dangerous default
// posture in the project. A command is an array of opaque byte strings; there is
// no schema, no statement grammar, and nothing to classify by shape the way a SQL
// statement can be. What there is instead is a command name, and on this protocol
// the distance between "administrative" and "remote code execution" is one
// command:
//
//	CONFIG SET dir /var/spool/cron + CONFIG SET dbfilename root + SAVE
//
// writes a file of the attacker's choosing wherever the server can write. Pointed
// at a cron directory or an authorized_keys it is a shell, and it has been used
// that way for a decade against instances exposed with no password because the
// default configuration had none.
//
// So this kind's policy is an allow list of commands defaulting to what an
// application does to a cache, a set that is refused even in monitor mode, and a
// key prefix policy -- which is the closest this protocol has to the
// database-and-table boundary the SQL kinds leave to GRANT, and which only works
// because the wire package knows where each command's keys are and says so when it
// does not.
type RedisListener struct {
	// Upstream is the server pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may connect from.
	// Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`

	// RequireTLS refuses a client that is not speaking TLS. Default true.
	//
	// Redis has no in-protocol upgrade: TLS is either on for the port or it is
	// not, which makes this simpler than the three database kinds and no less
	// important. A Redis AUTH sends the password as an argument of an ordinary
	// command, so an unencrypted connection discloses it to anybody on the path
	// -- and the same is true of every value written or read.
	RequireTLS *bool `yaml:"require_tls"`
	// UpstreamTLSMode is how the relay speaks to the server: require, prefer or
	// disable. Default disable, which is the one honest default here: a great
	// many Redis instances are deployed with no TLS at all and there is no
	// negotiation to discover it, so requiring it by default would refuse every
	// upstream in the common case rather than protecting anything.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS is the certificate and verification settings for that leg.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`

	// RequireAuth refuses any command before the connection has authenticated.
	// Default true.
	//
	// This is the setting that matters most after require_tls, because Redis's
	// own default is no password at all: a server with no `requirepass` accepts
	// every command from anybody who can reach the port. A relay that enforces
	// authentication in front of such a server turns "reachable" back into
	// "authorised", which is the property the estate thought it had.
	RequireAuth *bool `yaml:"require_auth"`
	// AllowUsers is the ACL usernames a connection may authenticate as, from the
	// two-argument form of AUTH and from HELLO's AUTH clause. Empty allows any.
	// The one-argument AUTH form names no user and authenticates as `default`,
	// which is what this list calls it.
	AllowUsers []string `yaml:"allow_users"`
	DenyUsers  []string `yaml:"deny_users"`

	// AllowCommands is the allow list of command names, case-insensitive. Empty
	// allows what an application does to a cache: the data-type commands, the
	// transaction commands, AUTH, HELLO, PING and SELECT.
	//
	// The absences are the point. Every `CONFIG`, `MODULE`, `EVAL`, `DEBUG`,
	// `SCRIPT`, `FUNCTION`, `ACL`, `CLIENT`, `CLUSTER`, `REPLICAOF`, `MIGRATE`,
	// `FLUSHALL`, `SHUTDOWN`, `MONITOR`, `SAVE`, `KEYS` and `RANDOMKEY` is off
	// until named.
	AllowCommands []string `yaml:"allow_commands"`
	// DenyCommands is the deny list, which no rule can override.
	DenyCommands []string `yaml:"deny_commands"`
	// AllowSubcommands narrows a container command to particular subcommands,
	// written as "CONFIG GET" or "CLIENT SETNAME". A container command named in
	// allow_commands without any subcommand listed here allows all of its
	// subcommands, which for CONFIG means CONFIG SET -- so naming the
	// subcommands is how an operator allows the read and not the write.
	AllowSubcommands []string `yaml:"allow_subcommands"`
	DenySubcommands  []string `yaml:"deny_subcommands"`

	// AllowKeyPrefixes restricts which keys a connection may name. Empty allows
	// any.
	//
	// A command whose key positions depend on an option -- SORT with STORE,
	// XREAD, MIGRATE with KEYS -- is refused while this is set, because the
	// relay cannot say which argument is the key and checking the wrong one
	// would be a policy that passes what it was meant to stop. The refusal names
	// the command, so an operator can decide whether to allow it with no prefix
	// policy on a rule of its own.
	AllowKeyPrefixes []string `yaml:"allow_key_prefixes"`
	// DenyKeyPrefixes is the deny list, evaluated first.
	DenyKeyPrefixes []string `yaml:"deny_key_prefixes"`
	// AllowDatabases restricts which numbered databases SELECT may switch to.
	// Empty allows any. A Redis database is not an access boundary -- the
	// password is the same for all of them -- but it is how an estate separates
	// one application's keys from another's, and a relay can hold that line
	// where the server will not.
	AllowDatabases []int `yaml:"allow_databases"`

	// ReadOnly refuses every command that can change data or the server. A
	// command the relay has never heard of counts as a write, because Redis
	// gains commands every release and a module adds its own.
	ReadOnly bool `yaml:"read_only"`

	// MaxMessageBytes bounds one reassembled command. Default 8 MiB.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// MaxBulkBytes bounds one argument, which for a SET is the value. Default
	// 1 MiB. A value above max_message_bytes is brought down to it.
	MaxBulkBytes int `yaml:"max_bulk_bytes"`
	// MaxElements bounds the number of elements in one command's array. Default
	// 1024. An ordinary command has single digits; a pipeline is several
	// commands rather than one long array, so a large value here is not what a
	// client library needs.
	MaxElements int `yaml:"max_elements"`
	// MaxCommands bounds commands per connection, 0 for no bound. A cache
	// connection is long-lived and chatty, so this is off by default; it is here
	// for a bastion front where a session is a person.
	MaxCommands int `yaml:"max_commands"`
	// MaxSessions and MaxSessionsPerClient bound concurrent connections.
	MaxSessions          int `yaml:"max_sessions"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	// IdleTimeout, SessionDuration and HandshakeTimeout bound a connection.
	IdleTimeout      Duration `yaml:"idle_timeout"`
	SessionDuration  Duration `yaml:"session_duration"`
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// AllowInline permits the space-separated command form. Default false.
	//
	// No client library sends it -- it exists for a human with a telnet session
	// -- and a great many exploitation scripts use it because it needs no length
	// arithmetic. The relay reads it either way, so refusing it costs an
	// operator nothing and removes a form the policy would otherwise have to
	// cover twice.
	AllowInline bool `yaml:"allow_inline"`

	// Deception answers as a server that is not there: a refused command
	// answered by a fabricated cache, or a whole listener that is one. See
	// RedisDeception.
	Deception *RedisDeception `yaml:"deception"`

	// Rules narrow or widen the listener for traffic that matches them.
	Rules []RedisRule `yaml:"rules"`
	// DefaultAction is allow or deny when no rule matched. Default deny.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is error (the default: a -NOPERM error reply the client's own
	// library reports) or drop.
	DenyResponse string `yaml:"deny_response"`
	// MonitorOnly evaluates and enforces nothing, except the hard decisions: the
	// client list, the TLS requirement, a command before authentication, a
	// message the relay could not read, and the commands in the dangerous set --
	// which on this protocol includes KEYS, because it is O(n) on the single
	// thread that serves every client and one of them stops the estate.
	MonitorOnly bool `yaml:"monitor_only"`
}

// RedisDeception answers as a Redis server that is not there.
//
// This protocol is the one where a fabricated server is worth the most, because
// the attack on it is a script rather than a person. An exposed Redis with no
// password is found by a scanner, and what arrives next is a fixed sequence:
// INFO to see what it is, CONFIG GET dir and dbfilename to find where it writes,
// CONFIG SET to point that somewhere executable, SET to put a cron line or an
// SSH key in a value, and SAVE to write the file. A refusal stops the script at
// the first step and tells its author to look elsewhere. Answering it collects
// the whole payload.
type RedisDeception struct {
	// Enabled turns the section off without removing it; it defaults to true
	// wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a command this listener was going to refuse
	// is answered by the fabrication instead, and never reaches the server) or
	// decoy (the whole listener is a fabricated server: no upstream, and nothing
	// behind it).
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client, which is what a
	// honeypot wants.
	Clients []string `yaml:"clients"`
	// Profile is the fabricated server's shape: generic-cache (the default),
	// session-store or queue. It decides the version it reports, the key names
	// it holds and the size of the dataset it claims.
	Profile string `yaml:"profile"`
	// Version is the redis_version INFO reports, which is the first thing a
	// scanner records and the thing a vulnerability database is indexed by.
	// Empty takes the profile's.
	//
	// **A decoy should say what the estate's own servers say.** A version
	// nobody on the site runs is the tell that ends the pretence, and only you
	// know what that is.
	Version string `yaml:"version"`
	// Keys are the key names the fabrication holds, in addition to the ones the
	// profile generates. They are what KEYS and SCAN list and what GET answers
	// for, so they are the part of the fabrication a visitor reads most
	// closely.
	Keys []string `yaml:"keys"`
	// KeyCount is how many keys the fabrication generates from the profile's
	// naming pattern, 0 to 4096. Zero takes the profile's.
	KeyCount int `yaml:"key_count"`
	// RequireAuth makes the fabrication demand AUTH before anything else, and
	// then accept any password.
	//
	// Default false, which is what a honeypot usually wants: an unprotected
	// Redis is what the scanning is looking for, and a decoy that asks for a
	// password is a decoy most scripts move on from. Where it is set, the
	// attempt is recorded -- the user name and the password's length, never the
	// password, because a log holding every credential sprayed at the estate is
	// a list of the estate's own credentials as often as not.
	RequireAuth bool `yaml:"require_auth"`
	// Tripwire are command names, or "NAME SUB" pairs, that raise a
	// redis_tripwire security event when they arrive.
	//
	// They are in addition to a built-in set, which is the remote-code-execution
	// chain and its neighbours: CONFIG SET, MODULE, SLAVEOF, REPLICAOF, DEBUG,
	// EVAL, EVALSHA, FUNCTION, SCRIPT, MIGRATE, SHUTDOWN, SAVE, BGSAVE,
	// BGREWRITEAOF, FLUSHALL, FLUSHDB and ACL. Nothing legitimate sends those to
	// a fabricated server, so they do not need to be configured to be worth
	// waking somebody for.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated values reproducible. Zero derives one from the
	// listener name, which is stable across restarts.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a counter or a gauge lasts. Default 30s;
	// 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
}

// RedisRule is one rule of a redis listener's policy.
type RedisRule struct {
	// Name identifies the rule in logs and counters.
	Name string `yaml:"name"`
	// Clients and Users select the traffic.
	Clients []string `yaml:"clients"`
	Users   []string `yaml:"users"`
	// Schedule is when this rule allows what it allows.
	Schedule *ModbusSchedule `yaml:"schedule"`
	// Action is allow (the default), deny or observe.
	Action string `yaml:"action"`
	// The rule's own narrowing. The deny lists always win.
	AllowCommands    []string `yaml:"allow_commands"`
	DenyCommands     []string `yaml:"deny_commands"`
	AllowSubcommands []string `yaml:"allow_subcommands"`
	DenySubcommands  []string `yaml:"deny_subcommands"`
	AllowKeyPrefixes []string `yaml:"allow_key_prefixes"`
	DenyKeyPrefixes  []string `yaml:"deny_key_prefixes"`
	ReadOnly         *bool    `yaml:"read_only"`
	MaxCommands      int      `yaml:"max_commands"`
}

// S7Listener is the settings of a kind: s7 listener: a relay in front of a
// Siemens PLC.
//
// The protocol is three layers on TCP 102 -- TPKT, COTP and S7comm -- and
// what matters about it is what it does not have. There is **no
// authentication worth the name**: the optional password protects a handful
// of functions on some CPU families and nothing on others, an S7-300 with no
// password accepts a stop from anybody who can open a socket, and the
// protocol has no transport security at all, which is why this listener
// takes no TLS section. An engineering station on the same segment can read
// and write every byte of memory in every controller on it.
//
// So a relay's job here is to know what an operation *is*, and this protocol
// spreads that across two layers: a function code for reading and writing
// memory, and a user-data group and subfunction for everything else -- the
// diagnostic buffer, the block list, the clock, the password, the debugger.
// `internal/s7` maps both onto one vocabulary of nineteen words, and the
// policy is written in those words.
//
// Four things shape the settings.
//
// **The default is what an HMI does.** `operations` defaults to reading
// memory, reading the system status lists, listing blocks, subscribing to
// cyclic data, reading the clock and the diagnostic machinery -- and nothing
// that changes anything. Writing, downloading a program, uploading one,
// stopping the CPU, setting the clock, the password functions and the
// programmer commands are each off until named.
//
// **The address is the rack and the slot**, and it arrives in the connection
// request rather than in any request that follows: the called TSAP's two
// octets hold a connection resource and the rack and slot of the CPU. A
// listener that named nothing else could still say which controller a client
// may reach -- and `resources` says *how*, because `pg` is the programming
// device connection an engineering station opens and `op` is an operator
// panel.
//
// **An upload is a read, and it is the one that takes the plant with it.**
// Reading a block out of a PLC is how control logic leaves the site, so it
// is off by default even though nothing about it changes the machine.
//
// **The areas and the data blocks are the boundary inside the CPU.**
// `areas` and `dbs` say which memory a client may reach at all, and
// `addresses` and `write_addresses` bound it by byte -- which is how an
// operator thinks about a data block, so the relay divides the protocol's
// bit address by eight rather than making anybody else do it.
type S7Listener struct {
	// Upstream is the PLC pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may connect
	// from. Deny is evaluated first. An empty allow list allows every
	// client the deny list does not refuse, which validation advises
	// against on a listener that reaches a controller.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`

	// Racks and Slots are the rack and slot numbers a client may address,
	// written as numbers or "0-1" ranges. Empty allows any. A rack is 0 to
	// 7 and a slot 0 to 31, which is what the two octets hold.
	Racks []string `yaml:"racks"`
	Slots []string `yaml:"slots"`
	// Resources are the connection types a client may ask for: pg (the
	// programming device connection), op (an operator panel) or basic (what
	// one PLC opens to another). Empty allows any.
	//
	// It is the cheapest useful line in this section: a listener that
	// admits only `op` has said an engineering station may not connect
	// through it, without naming a single function.
	Resources []string `yaml:"resources"`

	// ReadOnly refuses every operation that changes the PLC, for every
	// client, before any rule is read: writing memory, downloading,
	// controlling, stopping, the mode transitions, setting the clock, the
	// password functions and the programmer commands. It cannot be
	// overridden by a rule, because a read-only listener that one rule
	// could write through is not a read-only listener.
	ReadOnly bool `yaml:"read_only"`
	// Operations is the allow list, in the vocabulary above: read, write,
	// setup, upload, download, control, stop, cpu_services, szl,
	// diagnostics, blocks, cyclic, time_read, time_write, security,
	// programmer, mode, pbc, nc. Empty allows what an HMI does.
	Operations []string `yaml:"operations"`
	// DenyOperations is the deny list, which no rule can override.
	DenyOperations []string `yaml:"deny_operations"`

	// Areas is the memory areas a request may name: db, inputs, outputs,
	// flags, timer, counter, instance_db, local, peripheral and the
	// 200-family areas. Empty allows any.
	Areas []string `yaml:"areas"`
	// DenyAreas is the deny list. `peripheral` is worth putting on it on a
	// listener that allows writing: it is direct access to the I/O
	// hardware, past the process image the program reads.
	DenyAreas []string `yaml:"deny_areas"`
	// DBs is the data block numbers a request may name, as numbers or
	// ranges. Empty allows any.
	DBs []string `yaml:"dbs"`
	// Addresses is the byte ranges a request may name, as "0-255" or single
	// numbers. A request whose whole span is not inside one of them is
	// refused: a read of bytes 0 to 200 against a range of 0 to 99 is a
	// read of bytes the policy does not name, and splitting it is not this
	// relay's decision.
	Addresses []string `yaml:"addresses"`
	// WriteAddresses applies to writing operations when set, so one
	// listener can allow a wide read and a narrow write.
	WriteAddresses []string `yaml:"write_addresses"`
	// BlockTypes is the block types an upload or a download may name: db,
	// fb, fc, sdb, sfb, sfc. Empty allows any, which matters only where
	// upload or download is allowed at all.
	BlockTypes []string `yaml:"block_types"`

	// MaxItems bounds the items one read or write may carry, 0 for no
	// bound. A read of a hundred items is one PDU that occupies the CPU
	// for as long as a hundred reads.
	MaxItems int `yaml:"max_items"`
	// MaxReadBytes and MaxWriteBytes bound the octets one request may read
	// or write across all of its items, 0 for no bound.
	MaxReadBytes  int `yaml:"max_read_bytes"`
	MaxWriteBytes int `yaml:"max_write_bytes"`
	// MaxPDULength bounds the PDU length the two sides negotiate, 0 for no
	// bound beyond the frame bound. The families in the field negotiate
	// 240, 480 or 960 octets and an S7-1500 negotiates 2048; a
	// negotiation above this is refused rather than rewritten, because
	// rewriting it would make this relay a party to it.
	MaxPDULength int `yaml:"max_pdu_length"`
	// MaxFrameBytes bounds one TPKT frame. Default 8 KiB.
	MaxFrameBytes int `yaml:"max_frame_bytes"`
	// MaxRequests bounds the requests one connection may send, 0 for no
	// bound. A plant connection is long-lived, so this is off by default.
	MaxRequests int `yaml:"max_requests"`
	// RateLimit and RateBurst bound requests per second per client
	// address, 0 for no limit.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// MaxSessions and MaxSessionsPerClient bound concurrent connections.
	// A CPU has very few connection resources -- an S7-300 has sixteen
	// altogether -- so a bound here is what stops one client from taking
	// them all.
	MaxSessions          int `yaml:"max_sessions"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	// IdleTimeout, SessionDuration and HandshakeTimeout bound a
	// connection.
	IdleTimeout      Duration `yaml:"idle_timeout"`
	SessionDuration  Duration `yaml:"session_duration"`
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// CommPlus decides what happens to S7comm-plus: the protocol an
	// S7-1200 or S7-1500 speaks to TIA Portal, announced by a protocol
	// identifier of 0x72 where classic S7comm uses 0x32.
	//
	// It needs its own section because it is a different protocol with a
	// different vocabulary, and because a relay can see much less of it: from
	// firmware 4 onward the session is integrity-protected and the interesting
	// parts of a request are encrypted, so what is left to police is the
	// function code. Absent this section an S7comm-plus PDU is refused --
	// which is what a listener written for classic S7comm meant.
	CommPlus *S7CommPlus `yaml:"s7comm_plus"`

	// Deception answers as a controller that is not there: a refused
	// request answered by a fabricated CPU, or a whole listener that is
	// one. See S7Deception.
	Deception *S7Deception `yaml:"deception"`
	// Learn records what crosses this listener and writes a proposed policy,
	// because the drawings say which blocks a controller has and the traffic
	// says which of them anything actually reads. See S7Learn.
	Learn *S7Learn `yaml:"learn"`

	// Rules decide each request, in order, first match wins. A request
	// that matches no rule takes DefaultAction.
	Rules []S7Rule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is error (the default: an S7 acknowledgement carrying
	// an access-fault error, which is what a protected CPU answers, so the
	// client's own library reports a refusal), drop or close.
	DenyResponse string `yaml:"deny_response"`
	// LogRequests writes an access line per request, which on a plant
	// polling every second is a great many lines.
	LogRequests bool `yaml:"log_requests"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// MonitorOnly evaluates and enforces nothing, except the hard
	// decisions: the client list, the rack and slot, a frame the relay
	// could not read, the bounds, and every operation that changes the PLC
	// -- because a write forwarded so that it could be written down is a
	// moved actuator, and a stop forwarded is a stopped machine.
	MonitorOnly bool `yaml:"monitor_only"`
}

// S7Deception answers as a controller that is not there.
//
// A refusal is information here as it is everywhere else on a plant, and on
// this protocol it is unusually cheap to collect. A read of a data block the
// policy does not name is answered with an access fault; one it does name is
// answered with data. So a sweep of data block numbers reports which blocks
// exist, and a sweep of the rack and slot numbers reports where the CPU is --
// and the system status list, which every scanner reads first, hands over the
// order number, the module type and the firmware version of the controller
// itself.
//
// This section answers instead, as a CPU whose blocks hold values that are
// stable per address and move slowly with time.
//
// **The rule that bounds it is the same one the Modbus and IEC 104 sections
// hold to**: a request that was going to reach the controller is never
// answered from here. Deception replaces a refusal -- a policy denial, or a
// block the fabrication does not have -- and never an answer, because the
// failure mode on a plant floor is not a confused scanner but an engineer
// reading a fabricated value off a real machine. mode: answer therefore
// refuses to load without clients.
type S7Deception struct {
	// Enabled turns the section off without removing it; it defaults to
	// true wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a request this listener was going to
	// refuse is answered by the fabrication instead, and never reaches the
	// controller) or decoy (the whole listener is a fabricated CPU: no
	// upstream, and nothing behind it).
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client, which is what
	// a honeypot wants.
	Clients []string `yaml:"clients"`
	// Profile is the fabricated controller's shape: generic-s7-300 (the
	// default) or generic-s7-400.
	//
	// Both are classic S7comm families on purpose. An S7-1200 or S7-1500
	// driven by TIA Portal speaks S7comm-plus, whose session is
	// integrity-protected from firmware 4 onward, so a decoy answering
	// classic S7comm while claiming to be a 1500 is a contradiction a
	// scanner sees in one exchange.
	Profile string `yaml:"profile"`
	// OrderNumber is the MlfB -- the order number the module identification
	// list reports, such as "6ES7 315-2EH14-0AB0". ModuleType is the name
	// the component identification list reports ("CPU 315-2 PN/DP"), Plant
	// the plant designation, Serial the module serial number and Version
	// the firmware version as "3.2.7".
	//
	// **A decoy should claim the make the plant actually runs.** A 315 on a
	// site that is all 416s is the tell that ends the pretence, and only you
	// know which it is. An unset serial is derived from the seed, so the
	// controller keeps one and keeps the same one.
	OrderNumber string `yaml:"order_number"`
	ModuleType  string `yaml:"module_type"`
	Plant       string `yaml:"plant"`
	Serial      string `yaml:"serial"`
	Version     string `yaml:"version"`
	// PDULength is the length the fabrication negotiates in its answer to
	// Setup Communication: 240, 480 or 960, the sizes the families use.
	// Zero takes the profile's.
	PDULength int `yaml:"pdu_length"`
	// Blocks are the data blocks the fabricated controller has. A read of a
	// block outside them is answered the way a CPU answers a block it does
	// not have, because a controller with 65535 data blocks is not a
	// controller.
	Blocks []S7DecoyBlocks `yaml:"blocks"`
	// Bands are how the bytes inside a block behave; see S7DecoyBand.
	// Empty takes the profile's.
	Bands []S7DecoyBand `yaml:"bands"`
	// Tripwire are data block numbers no legitimate client reads. A read of
	// one is answered -- the answer is what keeps the visitor reading -- and
	// raised as an s7_tripwire security event, which is what somebody acts
	// on.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated values reproducible. Zero derives one from
	// the listener name, which is stable across restarts.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a value lasts. Default 30s; 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
}

// S7DecoyBlocks is a run of data block numbers the fabrication has, and how
// large each of them is.
type S7DecoyBlocks struct {
	// DBs is the run, as "1-8" or a single number.
	DBs string `yaml:"dbs"`
	// Bytes is the size of each block in the run. Default 512. A read past
	// the end of a block is answered the way a CPU answers one: with an
	// address error, because a block whose length nothing bounds is not a
	// block.
	Bytes int `yaml:"bytes"`
}

// S7DecoyBand is how one run of byte addresses inside a block behaves.
type S7DecoyBand struct {
	// Addresses is the run of byte addresses, as "0-199".
	Addresses string `yaml:"addresses"`
	// Shape is analogue (a measurement inside min..max that drifts),
	// discrete (a bit that mostly stays where it is) or counter (a
	// totaliser that only increases).
	Shape string `yaml:"shape"`
	// Min and Max bound an analogue band. Defaults 0 and 27648, which is
	// what a scaled analogue input reports on much of the installed base.
	Min int `yaml:"min"`
	Max int `yaml:"max"`
	// Rate is how much a counter adds each period.
	Rate int `yaml:"rate"`
}

// S7CommPlus is the policy for S7comm-plus on an s7 listener.
//
// **Why this is a smaller policy than the classic one.** Classic S7comm says
// on the wire which memory area a request names, which data block and which
// bytes, so a policy can be written about the plant. S7comm-plus does not: on
// the controllers that speak it the session is integrity-protected and the
// object and variable addressing is encrypted under a key the two ends derive,
// so a relay in the middle can read the outer framing and nothing under it.
// What is left is the *function code* -- whether this is a read, a write, a
// method call or a program change -- and that is what this section decides
// about. A section here that claimed to bound data blocks would be claiming to
// read something no relay can see.
//
// **The function names are read from the wire, not from a specification.**
// Siemens publishes none, for either protocol. The names come from public
// reverse engineering, and a function code this relay cannot name is reported
// as unnamed and decided by DefaultAction -- so a table that is wrong or out
// of date fails closed rather than passing an operation through unexamined.
type S7CommPlus struct {
	// Mode is what happens to S7comm-plus on this listener:
	//
	//   refuse      (the default) no S7comm-plus reaches the controller. This
	//               is what an s7 listener written before this section existed
	//               meant, so adding the section changes nothing until a mode
	//               is chosen -- but the refusal is now answered and named
	//               rather than being a connection this relay dropped without
	//               saying why.
	//   policy      decide each PDU by the lists below. This is what makes an
	//               S7-1500 usable through this relay.
	//   passthrough forward every S7comm-plus PDU, with the session's frame
	//               bounds and rate limits still in force. It is here for the
	//               estate that must have TIA Portal working today and will
	//               write the policy next week, and the reference says plainly
	//               what it gives up.
	Mode string `yaml:"mode"`
	// Functions is the allow list, by the names public reverse engineering
	// uses -- explore, get_link, get_multi_variables, get_var_sub_streamed,
	// set_variable, set_multi_variables, create_object, delete_object,
	// invoke, begin_sequence, end_sequence -- or by number ("0x054c"). Empty
	// names none, and then Classes decides.
	Functions []string `yaml:"functions"`
	// DenyFunctions is the deny list, which no allow can override.
	DenyFunctions []string `yaml:"deny_functions"`
	// Classes is the allow list in the three words a plant policy is written
	// in: read, write, admin. The fourth, unknown, is every function this
	// relay could not name -- nameable so that an estate can decide about it
	// rather than inherit a default it cannot see.
	//
	// The mapping from function to class is a judgement rather than something
	// the protocol states: a download and a run-stop on this protocol family
	// are both Invoke calls, so invoke is admin. An engineer who disagrees
	// can name the function itself in Functions, which is checked first.
	Classes []string `yaml:"classes"`
	// DenyClasses is the deny list, which no allow can override.
	DenyClasses []string `yaml:"deny_classes"`
	// DefaultAction is deny (the default) or allow: what a PDU no list names
	// gets. It is the switch that decides an unnamed function, so `allow` here
	// is the one setting in this section that can let an operation through
	// that this relay did not recognise.
	DefaultAction string `yaml:"default_action"`
}

// S7Learn records what crosses the listener and writes a proposed policy.
//
// The drawings say which blocks a controller has. They do not say which of them
// the integrator's HMI reads every second, which block the historian polls, or
// that a commissioning laptop has been reading DB1 since the plant was built. A
// policy written from the drawings refuses half of it on the first shift, which
// is how a security control gets turned off and stays off.
type S7Learn struct {
	// Enabled turns the recording on.
	Enabled bool `yaml:"enabled"`
	// File is where the report is written, as YAML. Required when enabled.
	File string `yaml:"file"`
	// Interval is how often it is rewritten. Default 5m; it is also written
	// when the listener shuts down.
	Interval Duration `yaml:"interval"`
	// MaxSubjects bounds the observations held: one per client, function, area
	// and data block seen. Default 8192; past it the newest is dropped and the
	// drops are counted, because a learning run that quietly stopped learning
	// is worse than one that says so.
	MaxSubjects int `yaml:"max_subjects"`
	// Enforce keeps the policy in force while learning. Default false: a
	// learning run is normally observe-only, and saying so here is what stops
	// one being left on by accident.
	Enforce bool `yaml:"enforce"`
}

// S7Rule is one rule of an s7 listener's policy.
type S7Rule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow (the default), deny or observe.
	Action string `yaml:"action"`
	// Clients, Racks, Slots and Resources select the traffic.
	Clients   []string `yaml:"clients"`
	Racks     []string `yaml:"racks"`
	Slots     []string `yaml:"slots"`
	Resources []string `yaml:"resources"`
	// The rule's own narrowing. The deny lists always win.
	Operations     []string `yaml:"operations"`
	DenyOperations []string `yaml:"deny_operations"`
	Areas          []string `yaml:"areas"`
	DenyAreas      []string `yaml:"deny_areas"`
	DBs            []string `yaml:"dbs"`
	Addresses      []string `yaml:"addresses"`
	WriteAddresses []string `yaml:"write_addresses"`
	BlockTypes     []string `yaml:"block_types"`
	MaxItems       int      `yaml:"max_items"`
	// Schedule limits the rule to a time window, which is how "the
	// integrator may download during the shutdown window" is written.
	Schedule *ModbusSchedule `yaml:"schedule"`
	// Comment is carried into the logs when the rule decides, for the
	// change record a plant keeps.
	Comment string `yaml:"comment"`
}

// AMQPListener is the settings of a kind: amqp listener: a relay in front of
// a message broker.
//
// Two protocols arrive on this port. A client picks one in its first eight
// octets: AMQP 0-9-1, which is what RabbitMQ speaks and what almost every
// deployment means by AMQP, or AMQP 1.0, which is a different protocol that
// kept the name. Both are read, and the same policy is written once for
// both -- the nouns are an exchange, a queue and a routing key on 0-9-1, and
// a link address on 1.0, which the brokers that serve both versions spell
// as `/exchange/X/key` and `/queue/Q`.
//
// Four things make a relay worth having in front of a broker.
//
// **A broker's permissions are per user and per virtual host, and nothing
// finer in practice.** RabbitMQ's model is a regular expression per vhost
// over configure, write and read -- powerful, and administered in the
// broker by whoever administers the broker. A relay holds the same boundary
// in the estate's own configuration, reviewed with the rest of it, and it
// holds it for brokers whose permission model is weaker than RabbitMQ's.
//
// **Topology is not work.** Declaring an exchange, deleting a queue,
// binding and unbinding are the broker's configuration, and almost no
// application needs to do any of it: a service that publishes to an
// exchange somebody else declared needs no topology method at all. So
// `allow_topology` is false by default, and a client library that declares
// its own queue on connect is a decision an operator makes rather than a
// default nobody noticed.
//
// **The credential is in the clear.** Both versions authenticate with SASL,
// and PLAIN -- which is what every deployment uses -- is the username and
// the password in one field separated by zero octets. `require_tls` is
// therefore the setting that matters most; the relay reads the username out
// of the exchange for its logs and rules and never the password.
//
// **The dangerous arguments are not the obvious ones.**
// `x-dead-letter-exchange` on a queue and `alternate-exchange` on an
// exchange both name an exchange the broker will route to, and a policy
// that checked only the name being declared would let a client have the
// broker deliver to an exchange it may not publish to. Both are checked
// against the exchange policy, as is the `reply-to` in a message's own
// properties.
type AMQPListener struct {
	// Upstream is the broker pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may connect
	// from. Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`

	// RequireTLS refuses a client that is not speaking TLS. Default true.
	//
	// AMQP has no in-protocol upgrade on 0-9-1: TLS is the port (5671
	// rather than 5672), so this is about which port a client reached.
	// AMQP 1.0 has a TLS protocol identifier in its header, which this
	// listener refuses rather than answering -- a client that asked to
	// negotiate TLS inside the protocol should be given a TLS port
	// instead, and answering the request would mean this relay deciding
	// the connection's cryptography from a client's first octet.
	RequireTLS *bool `yaml:"require_tls"`
	// UpstreamTLSMode is how the relay speaks to the broker: require,
	// prefer or disable. Default disable, which is the honest default for
	// the same reason as on redis: a great many brokers are reached over a
	// private network with no TLS and there is nothing to negotiate, so
	// requiring it by default would refuse every upstream rather than
	// protect anything.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS is the certificate and verification settings for that
	// leg.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`

	// Versions is the protocol versions a client may ask for: 0-9-1 and
	// 1.0. Empty allows both. 0-8 and 0-9 are never allowed: they are
	// answered by brokers for compatibility, their catalogue is a subset
	// nobody writes new clients against, and a relay that read them would
	// be deciding a policy on a protocol revision from 2006.
	Versions []string `yaml:"versions"`

	// AllowMechanisms is the SASL mechanisms a client may choose. Empty
	// allows PLAIN and EXTERNAL.
	//
	// ANONYMOUS is not in that default. It is a login with no identity: a
	// broker that accepts it has no account to attribute anything to, and
	// a relay in front of one can refuse to pass it on.
	AllowMechanisms []string `yaml:"allow_mechanisms"`
	// DenyMechanisms is the deny list, evaluated first.
	DenyMechanisms []string `yaml:"deny_mechanisms"`
	// RequireAuth refuses every operation until the broker has accepted a
	// credential. Default true.
	//
	// The outcome is the broker's answer and not the client's claim: the
	// relay waits for the connection.tune that follows a successful
	// 0-9-1 handshake, or for the sasl-outcome on 1.0, exactly as the
	// redis and postgres kinds wait for a server's answer to an AUTH.
	RequireAuth *bool `yaml:"require_auth"`
	// AllowUsers and DenyUsers are the identities a connection may
	// authenticate as, read out of the SASL exchange. Empty allows any.
	AllowUsers []string `yaml:"allow_users"`
	DenyUsers  []string `yaml:"deny_users"`

	// AllowVhosts and DenyVhosts are the virtual hosts a connection may
	// open: connection.open's virtual-host on 0-9-1 and open's hostname on
	// 1.0. Empty allows any.
	//
	// This is the broker's own access boundary, and it is checked before
	// the exchange and queue lists because a name means something
	// different in each vhost.
	AllowVhosts []string `yaml:"allow_vhosts"`
	DenyVhosts  []string `yaml:"deny_vhosts"`

	// AllowMethods is the allow list of 0-9-1 method names, spelled
	// `basic.publish` and `queue.declare`. Empty allows the handshake, the
	// channel methods, publishing, consuming, acknowledging, publisher
	// confirms and transactions -- and no topology method at all.
	AllowMethods []string `yaml:"allow_methods"`
	// DenyMethods is the deny list, which no rule can override.
	DenyMethods []string `yaml:"deny_methods"`
	// AllowPerformatives and DenyPerformatives are the same for AMQP 1.0,
	// spelled `attach`, `transfer`, `flow`. Empty allows all nine, because
	// on that version the policy is about the address a link attaches to
	// rather than about which performative carries it.
	AllowPerformatives []string `yaml:"allow_performatives"`
	DenyPerformatives  []string `yaml:"deny_performatives"`

	// AllowTopology permits the methods that change the broker's
	// configuration: declaring, deleting, binding and unbinding exchanges
	// and queues, and purging. Default false.
	AllowTopology bool `yaml:"allow_topology"`
	// AllowPublish and AllowConsume permit putting messages in and taking
	// them out. Both default true; a listener in front of a broker that
	// only ingests events sets consume false, and one in front of a read
	// model sets publish false.
	AllowPublish *bool `yaml:"allow_publish"`
	AllowConsume *bool `yaml:"allow_consume"`

	// AllowExchanges, AllowQueues, AllowRoutingKeys and AllowAddresses are
	// the names a connection may use, as glob patterns (`orders.*`,
	// `app-?`, `*`). Empty allows any. The deny lists are evaluated first
	// and no rule can override them.
	//
	// A name is checked wherever it appears, which is the part a policy
	// written against the obvious fields would miss: the exchange of a
	// publish, the queue of a consume, the dead-letter exchange of a
	// declare, the alternate exchange, the reply-to of a message, and the
	// node address of a 1.0 attach.
	AllowExchanges   []string `yaml:"allow_exchanges"`
	DenyExchanges    []string `yaml:"deny_exchanges"`
	AllowQueues      []string `yaml:"allow_queues"`
	DenyQueues       []string `yaml:"deny_queues"`
	AllowRoutingKeys []string `yaml:"allow_routing_keys"`
	DenyRoutingKeys  []string `yaml:"deny_routing_keys"`
	// AllowAddresses and DenyAddresses are the 1.0 link addresses. A
	// listener that names exchanges and queues covers the addresses whose
	// shape says which they are; these are for the node names that have no
	// shape, which is what Azure Service Bus and Qpid use.
	AllowAddresses []string `yaml:"allow_addresses"`
	DenyAddresses  []string `yaml:"deny_addresses"`

	// DenyManagementNodes refuses the names a broker keeps for
	// administering itself: `$management` and `$cbs` on 1.0, and the
	// `amq.rabbitmq.*` exchanges on 0-9-1. Default true.
	//
	// These are how a client reads the broker's own configuration, its
	// logs and its trace stream over the same connection it publishes on.
	// An operator who needs one names it in allow_exchanges or
	// allow_addresses, which is a line a reviewer can see.
	DenyManagementNodes *bool `yaml:"deny_management_nodes"`

	// RequireUserID refuses a published message that does not carry the
	// user-id property. Default false.
	//
	// It is the one field on this protocol that ties a message to a
	// person, and RabbitMQ already checks it against the connection's
	// authenticated user when a publisher sets it. Nothing makes a
	// publisher set it; requiring it turns "somebody published this" into
	// an attributable act.
	RequireUserID bool `yaml:"require_user_id"`
	// MatchUserID refuses a published message whose user-id is not the
	// identity this connection authenticated as. Default true, and it
	// costs nothing when nobody sets the property.
	MatchUserID *bool `yaml:"match_user_id"`
	// AllowNoAck permits basic.consume with no-ack, which takes messages
	// off a queue without acknowledging them: whatever was in flight when
	// the consumer died is gone. Default true, because a great deal of
	// working software uses it deliberately.
	AllowNoAck *bool `yaml:"allow_no_ack"`
	// MaxPriority bounds the priority property of a published message, 0
	// for no bound. A priority queue serves the highest first, so a
	// publisher that sets the maximum on everything starves the others.
	MaxPriority int `yaml:"max_priority"`

	// MaxFrameBytes bounds one frame, and with it the frame-max the two
	// sides negotiate. Default 128 KiB, which is RabbitMQ's own default.
	//
	// A negotiation that settles above this bound is refused rather than
	// rewritten, and the refusal says so: rewriting it would make this
	// relay a party to the negotiation, and a client that agreed a frame
	// size with the broker and then had a frame refused in the middle of a
	// message is a harder fault to find than a connection that failed at
	// the start.
	MaxFrameBytes int `yaml:"max_frame_bytes"`
	// MaxChannels bounds the channels one connection may open (the
	// sessions, on 1.0). Default 256.
	MaxChannels int `yaml:"max_channels"`
	// MaxLinks bounds the links one 1.0 session may attach. Default 256.
	MaxLinks int `yaml:"max_links"`
	// MaxMessageBytes bounds one message, 0 for no bound. On 0-9-1 it is
	// checked against the size the content header declares, before the
	// body arrives; on 1.0 it is the sum over a run of transfers, because
	// a message may be split across them.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// RequireHeartbeat refuses a connection that negotiated no heartbeat
	// at all. Default false.
	//
	// A connection with no heartbeat holds the broker's resources until
	// the kernel notices the socket is gone, which on a network that
	// dropped a client can be hours. It is off by default because a client
	// behind a proxy that keeps the socket open is not doing anything
	// wrong, and because turning it on refuses those clients.
	RequireHeartbeat bool `yaml:"require_heartbeat"`
	// MaxMethods bounds the methods or performatives one connection may
	// send, 0 for no bound. A broker connection is long-lived, so this is
	// off by default; it is here for a bastion front where a session is a
	// person.
	MaxMethods int `yaml:"max_methods"`
	// RateLimit and RateBurst bound methods per second per client address,
	// 0 for no limit.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// MaxSessions and MaxSessionsPerClient bound concurrent connections.
	MaxSessions          int `yaml:"max_sessions"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	// IdleTimeout, SessionDuration and HandshakeTimeout bound a
	// connection.
	IdleTimeout      Duration `yaml:"idle_timeout"`
	SessionDuration  Duration `yaml:"session_duration"`
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// Rules narrow or widen the listener for traffic that matches them.
	Rules []AMQPRule `yaml:"rules"`
	// DefaultAction is allow or deny when no rule matched. Default deny.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is close (the default: the protocol's own
	// channel.close or detach, so the client library reports a refusal) or
	// drop.
	DenyResponse string `yaml:"deny_response"`
	// LogMethods writes an access line per method, which on a busy broker
	// is a great many lines. Default false.
	LogMethods bool `yaml:"log_methods"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// MonitorOnly evaluates and enforces nothing, except the hard
	// decisions: the client list, the TLS requirement, the protocol
	// version, a frame the relay could not read, an operation before
	// authentication, the bounds, and the destructive methods -- deleting
	// an exchange or a queue and purging one, because a purge forwarded so
	// that it could be written down is a queue that is empty.
	MonitorOnly bool `yaml:"monitor_only"`
}

// AMQPRule is one rule of an amqp listener's policy.
type AMQPRule struct {
	// Name identifies the rule in logs and counters.
	Name string `yaml:"name"`
	// Clients, Users and Vhosts select the traffic.
	Clients []string `yaml:"clients"`
	Users   []string `yaml:"users"`
	Vhosts  []string `yaml:"vhosts"`
	// Schedule is when this rule allows what it allows.
	Schedule *ModbusSchedule `yaml:"schedule"`
	// Action is allow (the default), deny or observe.
	Action string `yaml:"action"`
	// The rule's own narrowing. The deny lists always win.
	AllowMethods       []string `yaml:"allow_methods"`
	DenyMethods        []string `yaml:"deny_methods"`
	AllowPerformatives []string `yaml:"allow_performatives"`
	DenyPerformatives  []string `yaml:"deny_performatives"`
	AllowExchanges     []string `yaml:"allow_exchanges"`
	DenyExchanges      []string `yaml:"deny_exchanges"`
	AllowQueues        []string `yaml:"allow_queues"`
	DenyQueues         []string `yaml:"deny_queues"`
	AllowRoutingKeys   []string `yaml:"allow_routing_keys"`
	DenyRoutingKeys    []string `yaml:"deny_routing_keys"`
	AllowAddresses     []string `yaml:"allow_addresses"`
	DenyAddresses      []string `yaml:"deny_addresses"`
	AllowTopology      *bool    `yaml:"allow_topology"`
	AllowPublish       *bool    `yaml:"allow_publish"`
	AllowConsume       *bool    `yaml:"allow_consume"`
	MaxMessageBytes    int      `yaml:"max_message_bytes"`
	MaxMethods         int      `yaml:"max_methods"`
}

// TDSListener is the settings of a kind: tds listener: a relay in front of a
// Microsoft SQL Server, or anything else speaking TDS.
//
// Three things make this protocol different from the other two database kinds.
//
// The encryption negotiation happens in a PRELOGIN message whose ENCRYPTION
// option is one octet, unsigned, and answered by the server. `off` means "I would
// rather not" and is what a great deal of deployed software sends; `not_supported`
// means "I cannot" and is what anything on the path rewrites the server's answer
// to, because a client that asked for `off` and hears `not_supported` proceeds in
// the clear without complaint. This is PostgreSQL's SSLRequest octet and MySQL's
// CLIENT_SSL bit for the third time, and it gets the same answer: the relay
// negotiates with each side itself rather than forwarding what it read.
//
// The password in a LOGIN7 is not encrypted. It is XOR 0xA5 with the nibbles
// swapped -- an encoding, with no key -- so `require_tls` here is not hardening,
// it is the difference between a password on the wire and no password on the
// wire. There is no equivalent of choosing a stronger authentication method,
// because there is no stronger one short of integrated security.
//
// And the statement an application runs does not arrive as a statement. Every
// client library that uses parameters sends `sp_executesql` with the SQL in a
// parameter, so the procedure policy and the statement policy are the same
// policy here: the relay reads the statement out of the call and classifies it.
type TDSListener struct {
	// Upstream is the server pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may connect from.
	// Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`

	// RequireTLS makes the relay answer every client's PRELOGIN with
	// ENCRYPT_REQ, so a client that asked for `off` upgrades anyway. Default
	// true, and on this protocol it is the setting that matters most: the
	// password field is obfuscated rather than encrypted.
	//
	// A client too old to speak TLS will fail to connect when this is on. That
	// is the honest outcome -- it was sending a recoverable password in
	// cleartext -- and the relay logs a `tds_encryption_forced` event on every
	// connection whose negotiation it raised, so the ones affected can be found
	// before the switch is thrown.
	RequireTLS *bool `yaml:"require_tls"`
	// UpstreamTLSMode is how the relay speaks to the server: require (the
	// default), prefer or disable.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS is the certificate and verification settings for that leg.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`

	// AllowCleartextPassword permits a LOGIN7 carrying a password over an
	// unencrypted connection. Default false.
	//
	// It is named for what it is. There is no weak-authentication setting on
	// this kind because there is no strong option to contrast it with: every
	// TDS password is a cleartext password once the nibble swap is undone.
	AllowCleartextPassword bool `yaml:"allow_cleartext_password"`

	// AllowUsers, DenyUsers, AllowDatabases and DenyDatabases are the identity
	// claims a login may make.
	AllowUsers     []string `yaml:"allow_users"`
	DenyUsers      []string `yaml:"deny_users"`
	AllowDatabases []string `yaml:"allow_databases"`
	DenyDatabases  []string `yaml:"deny_databases"`
	// AllowApps matches the client's APPNAME, with a trailing * allowed. Like
	// MySQL's program_name it is chosen by the client and is not a credential;
	// it tells a reporting dashboard from a migration tool when both connect as
	// the same login.
	AllowApps []string `yaml:"allow_apps"`

	// AllowIntegrated permits a login that uses integrated security, where the
	// credential is an SSPI blob and the LOGIN7 carries no user name.
	//
	// It defaults to true, and to false the moment allow_users or deny_users is
	// set -- because a user list cannot be applied to a login that names no
	// user, and a relay that let one past would have a user policy with a hole
	// exactly the shape of Windows authentication. Setting it explicitly says
	// which you meant.
	AllowIntegrated *bool `yaml:"allow_integrated"`

	// AllowTypes and DenyTypes are the message types a client may send:
	// sql_batch, rpc, bulk_load, transaction_manager, attention, sspi,
	// fedauth_token, prelogin, login7, login. Empty allows what a client
	// library sends.
	//
	// `bulk_load` is off by default because its data stream is not SQL and
	// carries no policy, and `login` -- the pre-TDS7 shape -- is off because
	// the relay does not read it, and forwarding a message it had not
	// understood is the thing this kind exists not to do.
	AllowTypes []string `yaml:"allow_types"`
	DenyTypes  []string `yaml:"deny_types"`

	// AllowProcedures and DenyProcedures are the RPC procedures a client may
	// call, lower-cased. Empty allows the dynamic-SQL family, the cursor
	// family, and the metadata calls a driver makes -- and nothing else, so
	// every xp_, every sp_oa, sp_configure and sp_addlinkedserver are refused
	// until named.
	//
	// A name matches whether the client called the procedure by name or by the
	// numeric identifier the protocol also allows, because they are the same
	// call and a policy that matched one spelling would be bypassed by the
	// other.
	AllowProcedures []string `yaml:"allow_procedures"`
	DenyProcedures  []string `yaml:"deny_procedures"`

	// ReadOnly refuses every statement that can change data, including exec.
	ReadOnly bool `yaml:"read_only"`
	// AllowStatements and DenyStatements are the statement kinds, as the
	// postgres and mysql kinds name them. They apply to a SQLBATCH and to the
	// statement inside an sp_executesql, which is the same policy reaching the
	// same SQL by two routes. A statement the classifier cannot name is
	// refused whatever this says.
	AllowStatements []string `yaml:"allow_statements"`
	DenyStatements  []string `yaml:"deny_statements"`

	// MaxStatements bounds statements per batch. Default 1: T-SQL separates
	// statements with nothing but whitespace, so a batch carrying several is
	// ordinary -- and that is exactly why a bound belongs here rather than in a
	// capability flag as it does on MySQL.
	MaxStatements int `yaml:"max_statements"`
	// MaxStatementBytes bounds one statement. Default 64 KiB.
	MaxStatementBytes int `yaml:"max_statement_bytes"`
	// MaxMessageBytes bounds one reassembled message. Default 4 MiB. The
	// protocol has no bound: a sender may chain 64 KiB packets for ever, and
	// only the EOM status bit ends a message.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// MaxSessions and MaxSessionsPerClient bound concurrent connections.
	MaxSessions          int `yaml:"max_sessions"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	// IdleTimeout, SessionDuration and HandshakeTimeout bound a connection.
	IdleTimeout      Duration `yaml:"idle_timeout"`
	SessionDuration  Duration `yaml:"session_duration"`
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// Rules narrow or widen the listener for traffic that matches them.
	Rules []TDSRule `yaml:"rules"`
	// DefaultAction is allow or deny when no rule matched. Default deny.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is error (the default: an error token the client's own
	// library reports, with the number SQL Server uses for a permission
	// refusal) or drop.
	DenyResponse string `yaml:"deny_response"`
	// MonitorOnly evaluates and enforces nothing, except the hard decisions:
	// the client list, the TLS requirement, a cleartext password, an
	// unnameable login, a message or statement the relay could not read, and
	// the procedures in the dangerous set -- xp_cmdshell, the OLE automation
	// family, the registry procedures, sp_addlinkedserver, sp_configure and
	// the rest. Forwarding a shell command and writing down that it was
	// noticed is not a trial of a policy.
	MonitorOnly bool `yaml:"monitor_only"`
}

// TDSRule is one rule of a tds listener's policy.
type TDSRule struct {
	// Name identifies the rule in logs and counters.
	Name string `yaml:"name"`
	// Clients, Users, Databases and Apps select the traffic. Apps matches the
	// client's APPNAME, with a trailing * allowed.
	Clients   []string `yaml:"clients"`
	Users     []string `yaml:"users"`
	Databases []string `yaml:"databases"`
	Apps      []string `yaml:"apps"`
	// Schedule is when this rule allows what it allows.
	Schedule *ModbusSchedule `yaml:"schedule"`
	// Action is allow (the default), deny or observe.
	Action string `yaml:"action"`
	// The rule's own narrowing. The deny lists always win.
	AllowProcedures []string `yaml:"allow_procedures"`
	DenyProcedures  []string `yaml:"deny_procedures"`
	AllowTypes      []string `yaml:"allow_types"`
	DenyTypes       []string `yaml:"deny_types"`
	AllowStatements []string `yaml:"allow_statements"`
	DenyStatements  []string `yaml:"deny_statements"`
	ReadOnly        *bool    `yaml:"read_only"`
	MaxStatements   int      `yaml:"max_statements"`
}

// PostgresListener is the settings of a kind: postgres listener: a relay in
// front of a PostgreSQL server that reads the frontend/backend protocol.
//
// A database proxy must not pretend to be a SQL firewall. Knowing which tables a
// statement touches means parsing SQL properly -- every alias, subquery, CTE,
// view, function body and search_path interaction -- and a relay that got that
// 95% right would have a policy with a hole in exactly the place somebody is
// looking. Restricting a role's tables is the database's own job, with GRANT.
//
// What a relay can do is everything that happens before the database has an
// opinion, and two things it does better than the database: refuse the
// encryption downgrade that libpq's default sslmode accepts silently, and refuse
// the authentication methods that put a reusable credential on the wire. Plus
// one thing the database cannot do at all: decide by the *shape* of a statement,
// as an allow list of kinds where anything unclassifiable is refused.
type PostgresListener struct {
	// Upstream is the server pool a connection goes to. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may connect
	// from. Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`

	// RequireTLS refuses a client that will not encrypt. Default true, and
	// this is the single most valuable line in a postgres listener's
	// configuration.
	//
	// The protocol negotiates encryption in cleartext: the client sends eight
	// octets asking for TLS and the server answers with one octet, 'S' or 'N'.
	// Nothing signs that octet. libpq's default sslmode is `prefer`, which
	// means "ask for TLS and carry on in the clear if refused, without telling
	// anybody" -- so the default configuration of the most widely deployed
	// client in the world downgrades silently when something on the path says
	// no. The relay answers the request itself rather than forwarding it, so
	// the decision is made here and not by whatever rewrote the octet.
	RequireTLS *bool `yaml:"require_tls"`
	// UpstreamTLSMode is how the relay speaks to the server: require (the
	// default), prefer or disable. A relay that terminated TLS from the
	// client and then spoke plaintext to the server would have moved the
	// exposure rather than removed it, which is why the default is require
	// rather than matching the client's leg.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS is the certificate and verification settings for the leg to
	// the server.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`

	// AllowUsers, DenyUsers, AllowDatabases and DenyDatabases are the
	// identity claims a connection may make. They are claims rather than
	// credentials -- the client says who it wants to be and the server
	// decides -- so these lists say which attempts may even be made, which is
	// smaller and still useful: an estate where nothing should ever connect as
	// `postgres` can say so and have it hold before a single password is
	// guessed at.
	AllowUsers     []string `yaml:"allow_users"`
	DenyUsers      []string `yaml:"deny_users"`
	AllowDatabases []string `yaml:"allow_databases"`
	DenyDatabases  []string `yaml:"deny_databases"`
	// AllowApplications matches the application_name startup parameter, with
	// a trailing * allowed. It is chosen by the client and is not a
	// credential; it is useful for telling a migration tool from a reporting
	// dashboard when both connect as the same role, which is the ordinary
	// state of affairs.
	AllowApplications []string `yaml:"allow_applications"`

	// AllowAuth is the allow list of authentication methods the relay will
	// carry, named as pg_hba.conf names them: password, md5, scram, gss,
	// sspi, kerberos, scm. Empty allows any that is not weak.
	AllowAuth []string `yaml:"allow_auth"`
	// AllowWeakAuth permits a method whose credential an observer can reuse:
	// `password` is the password in cleartext, and `md5` is worse than it
	// looks -- the stored verifier is md5(password+username), so the hash *is*
	// a password-equivalent and anybody who reads pg_authid can authenticate
	// without cracking anything. PostgreSQL has shipped SCRAM since 10.
	// Default false.
	AllowWeakAuth bool `yaml:"allow_weak_auth"`

	// ReadOnly refuses every statement that can change data, which includes
	// CALL and DO: a procedure and an anonymous block can do anything the
	// role can, so a relay that called them reads would have a read_only
	// setting that is decorative.
	ReadOnly bool `yaml:"read_only"`
	// AllowStatements is the allow list of statement kinds. Empty allows any
	// kind the classifier can name, subject to read_only and the deny list.
	//
	// The kinds are select, insert, update, delete, merge, copy, call, do,
	// explain, show, set, reset, begin, commit, rollback, savepoint, lock,
	// prepare, execute, deallocate, declare, fetch, move, close_cursor,
	// listen, notify, unlisten, ddl, grant, maintenance, two_phase, empty.
	//
	// A statement the classifier cannot name is refused whatever this says,
	// and cannot be allowed: the whole design is an allow list of shapes, and
	// a shape nobody could read is not one of them.
	AllowStatements []string `yaml:"allow_statements"`
	// DenyStatements is the deny list, which no rule can override.
	DenyStatements []string `yaml:"deny_statements"`
	// AllowCopy names which COPY operations may cross: in (FROM STDIN), out
	// (TO STDOUT) or file (a path on the server, which needs a privileged
	// role). Empty allows in and out.
	//
	// `program` cannot be named here at all. COPY ... FROM PROGRAM runs a
	// shell command as the server's operating-system user: it is remote code
	// execution with a SQL keyword in front of it, and a setting that could
	// switch it on through a relay is one somebody switches on by accident.
	AllowCopy []string `yaml:"allow_copy"`
	// AllowReplication permits a connection whose startup packet asks for
	// one. Default false. A physical replication stream is a byte-for-byte
	// copy of every database on the server including the role passwords, and
	// it is a startup *parameter* rather than a statement, so no statement
	// policy would ever see it.
	AllowReplication bool `yaml:"allow_replication"`
	// AllowFunctionCall permits the legacy fast-path interface, which names a
	// function by object identifier and bypasses the parser completely.
	// Nothing written this century sends it. Default false.
	AllowFunctionCall bool `yaml:"allow_function_call"`
	// AllowCancel permits a CancelRequest. Default true, because cancelling a
	// runaway query is something operators legitimately do -- and it is worth
	// knowing that the server acts on one with no authentication at all: the
	// whole credential is a process identifier and a 32-bit secret. The relay
	// cannot check the secret, so what it does is refuse one from an address
	// that is not an admitted client, and count them.
	AllowCancel *bool `yaml:"allow_cancel"`

	// MaxStatements bounds how many statements one message may carry. Default
	// 8. The simple query protocol allows several separated by semicolons,
	// which is also how every injection ending in `; DROP TABLE` is
	// delivered.
	MaxStatements int `yaml:"max_statements"`
	// MaxStatementBytes bounds one statement. Default 64 KiB.
	MaxStatementBytes int `yaml:"max_statement_bytes"`
	// MaxMessageBytes bounds one protocol message. Default 1 MiB. The
	// protocol's own limit is the 4-byte length field, which is two
	// gigabytes.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// MaxSessions bounds concurrent connections through this listener, and
	// MaxSessionsPerClient bounds them per source address.
	MaxSessions          int `yaml:"max_sessions"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	// IdleTimeout ends a connection that has said nothing, and
	// SessionDuration one that has lasted too long whatever it is doing.
	IdleTimeout     Duration `yaml:"idle_timeout"`
	SessionDuration Duration `yaml:"session_duration"`
	// HandshakeTimeout bounds the TLS handshake and the startup exchange.
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// Rules narrow or widen the listener for traffic that matches them.
	// Deception answers as a server that is not there: a refused statement
	// answered by a fabricated database, or a whole listener that is one. See
	// PostgresDeception.
	Deception *PostgresDeception `yaml:"deception"`

	Rules []PostgresRule `yaml:"rules"`
	// DefaultAction is allow or deny when no rule matched. Default deny.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is error (the default: an ErrorResponse the client's own
	// library reports) or drop (close without a word).
	DenyResponse string `yaml:"deny_response"`
	// MonitorOnly evaluates the policy and enforces nothing, except the
	// decisions marked hard: the client list, the TLS requirement, the
	// authentication methods, a statement the classifier could not read, a
	// replication connection and COPY ... FROM PROGRAM. Forwarding any of
	// those and writing it down is not a trial of anything.
	MonitorOnly bool `yaml:"monitor_only"`
}

// PostgresDeception answers as a PostgreSQL server that is not there.
//
// The reconnaissance here is the same shape as MySQL's and the escalations are
// worse, because this server can run a shell command by design. A scanner reads
// the version out of the startup exchange and then asks which databases there
// are, what `data_directory` is, and whether this role is a superuser -- and the
// answer to the last one decides whether the next statement is
// `COPY ... FROM PROGRAM 'sh -c …'`, which is documented remote code execution,
// or `pg_read_file('/etc/passwd')`, or `CREATE FUNCTION ... LANGUAGE c`.
//
// A refusal ends that at the startup message. Answering it says which one they
// were reaching for.
type PostgresDeception struct {
	// Enabled turns the section off without removing it; it defaults to true
	// wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a statement this listener was going to
	// refuse is answered by the fabrication instead, and never reaches the
	// server) or decoy (the whole listener is a fabricated server: no
	// upstream, and nothing behind it).
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client, which is what a
	// honeypot wants.
	Clients []string `yaml:"clients"`
	// Profile is the fabricated server's shape: generic-postgres (the default),
	// django or rails. It decides the version reported and the databases,
	// schemas and tables it claims to hold.
	Profile string `yaml:"profile"`
	// Version is the server_version it announces, which is the first thing a
	// scanner records and what a vulnerability database is indexed by. Empty
	// takes the profile's.
	//
	// **A decoy should say what the estate's own servers say.** A version
	// nobody on the site runs is the tell that ends the pretence, and only you
	// know what that is.
	Version string `yaml:"version"`
	// Databases replaces the profile's list, which is what a client's \l
	// answers and the first thing asked after the version.
	Databases []string `yaml:"databases"`
	// Tables replaces the profile's list, as `schema.table` names. It is what a
	// catalogue query answers, and the part of the fabrication a visitor reads
	// most closely.
	Tables []string `yaml:"tables"`
	// Superuser says whether the fabricated role is one.
	//
	// Default false, and it is the most consequential field here: a superuser
	// can COPY FROM PROGRAM, which is a shell command. Saying no is both safer
	// to impersonate and the more common truth on an estate's application
	// accounts -- and a visitor who asks and is told no, and tries anyway, has
	// told you more than one who was told yes.
	Superuser bool `yaml:"superuser"`
	// RequireAuth makes the fabrication refuse the login rather than accept it.
	//
	// Default false: the reconnaissance happens after the login, so a decoy
	// that refuses it collects nothing. Where it is set the attempt is still
	// recorded -- the role, the database and the password field's length, never
	// the password.
	RequireAuth bool `yaml:"require_auth"`
	// Tripwire are object names -- a catalogue table, a function -- that raise
	// a postgres_tripwire security event when a statement mentions one.
	//
	// They are in addition to a built-in set, which is the escalation chain:
	// pg_shadow, pg_authid, pg_read_file, pg_read_binary_file, pg_ls_dir,
	// lo_import, lo_export, pg_sleep, dblink, and COPY's PROGRAM and file
	// forms. Nothing legitimate sends any of them to a fabricated database.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated values reproducible. Zero derives one from the
	// listener name, which is stable across restarts.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a counter or a gauge lasts. Default 30s;
	// 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
}

// PostgresRule is one rule of a postgres listener's policy.
type PostgresRule struct {
	// Name identifies the rule in logs and counters.
	Name string `yaml:"name"`
	// Clients, Users, Databases and Applications select the traffic this rule
	// is about. Selectors within a rule are AND; values within a selector are
	// OR. A rule with no selectors matches everything.
	Clients      []string `yaml:"clients"`
	Users        []string `yaml:"users"`
	Databases    []string `yaml:"databases"`
	Applications []string `yaml:"applications"`
	// Schedule is when this rule allows what it allows.
	Schedule *ModbusSchedule `yaml:"schedule"`
	// Action is allow (the default), deny or observe.
	Action string `yaml:"action"`
	// AllowStatements, DenyStatements, AllowCopy and ReadOnly are the rule's
	// own narrowing. A rule that names a kind widens the listener for its own
	// traffic, which is what makes one listener serve a reporting account that
	// may only select and a migration account that may also change the schema.
	// The deny lists always win, on the rule and on the listener both.
	AllowStatements []string `yaml:"allow_statements"`
	DenyStatements  []string `yaml:"deny_statements"`
	AllowCopy       []string `yaml:"allow_copy"`
	ReadOnly        *bool    `yaml:"read_only"`
	// MaxStatements is the rule's own bound on statements per message.
	MaxStatements int `yaml:"max_statements"`
}

type TFTPListener struct {
	// Mode is reverse (the default: clients send here and the listener
	// forwards to the servers) or forward (this listener is the controlled
	// egress a device uses to reach a server elsewhere).
	Mode string `yaml:"mode"`
	// Upstream is the server pool a transfer goes to. Required in reverse
	// mode.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may send
	// from. Deny is evaluated first. On this protocol the client list is
	// the most valuable line in the file, because it is the only thing
	// resembling an identity that exists at all.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// Operations is the allow list of transfer directions: read, write.
	// Empty allows read only, and that default is deliberate. A write is a
	// device putting a file onto the server, which is how a configuration
	// leaves an estate and how firmware arrives in it, and a protocol with
	// no authentication should not be how either happens by default.
	Operations []string `yaml:"operations"`
	// Modes is the allow list of transfer modes: octet, netascii, mail.
	// Empty allows octet and netascii. mail is obsolete -- RFC 1350
	// removed it -- and asked a server to deliver the file as mail to the
	// address in the filename field, so a server that still implements it
	// is a mail injection vector reachable with one datagram.
	Modes []string `yaml:"modes"`
	// AllowPathClasses names the shapes of filename this listener accepts
	// besides an ordinary relative path: absolute, backslash, drive,
	// traversal, trailing, non_ascii. Empty accepts only the ordinary one.
	//
	// The classes exist because a deny list of strings is a list of the
	// spellings somebody thought of. Three of them -- empty, nul, control
	// -- cannot be named here at all: each means this relay and the server
	// behind it are reading different filenames, and a decision about a
	// name the server will not see is not a decision.
	AllowPathClasses []string `yaml:"allow_path_classes"`
	// Directories are the directories a filename may name, compared
	// element by element from the top of the server's own directory: a
	// name outside all of them is refused before the rules and whatever
	// default_action says. Empty allows any, which validation advises
	// against.
	//
	// The comparison is per element, so firmware does not cover
	// firmware-staging.
	Directories []string `yaml:"directories"`
	// DenyDirectories are directories no rule can allow, which is how an
	// exception inside an allowed tree is written.
	DenyDirectories []string `yaml:"deny_directories"`
	// Filenames and DenyFilenames are shell patterns matched against the
	// whole cleaned path (as in firmware/*.bin). Deny is evaluated first
	// and no rule can override it.
	Filenames     []string `yaml:"filenames"`
	DenyFilenames []string `yaml:"deny_filenames"`
	// MaxDepth bounds how many elements a path may have. Default 8.
	MaxDepth int `yaml:"max_depth"`
	// MaxFilenameBytes bounds the filename field. Default 256.
	MaxFilenameBytes int `yaml:"max_filename_bytes"`
	// MaxTransferBytes bounds one transfer in either direction. Default
	// 64 MiB. It is the bound that matters most on a write, because a
	// write has no natural end: the client stops when it stops.
	MaxTransferBytes int64 `yaml:"max_transfer_bytes"`
	// MaxBlockSize bounds RFC 2348's blksize option. Default 1468, which
	// is a data packet that still fits an Ethernet frame. A larger block
	// fragments at the IP layer, which is a lever rather than a feature.
	MaxBlockSize int `yaml:"max_block_size"`
	// MaxWindowSize bounds RFC 7440's windowsize option: how many data
	// packets a server may send before one acknowledgement. Default 4.
	//
	// This is the protocol's amplification factor. A twenty-octet read
	// request yields a whole file to whatever address the datagram claimed
	// to come from, and a window of sixty-four makes that sixty-four
	// packets per acknowledgement rather than one. A request asking for
	// more than the bound is *rewritten* to it rather than refused, so a
	// device nobody can reconfigure still transfers.
	MaxWindowSize int `yaml:"max_window_size"`
	// MaxTransfers bounds the transfers this listener has in flight.
	// Default 64. Each one holds a socket of its own, because TFTP moves
	// to an ephemeral port pair after the first packet.
	MaxTransfers int `yaml:"max_transfers"`
	// MaxTransfersPerClient bounds them per client address. Default 8.
	MaxTransfersPerClient int `yaml:"max_transfers_per_client"`
	// Rules decide each transfer, in order, first match wins. A request
	// that matches no rule takes DefaultAction.
	Rules []TFTPRule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is how a refused request is answered: error (the
	// default: an error packet, which every client displays and stops on)
	// or drop (nothing, which the client retries and then reads as a
	// timeout). error is almost always right: a device that is told no
	// stops, and a device that hears nothing retransmits.
	DenyResponse string `yaml:"deny_response"`
	// TransferTimeout bounds one whole transfer. Default 5m.
	TransferTimeout Duration `yaml:"transfer_timeout"`
	// IdleTimeout ends a transfer that has gone quiet. Default 15s, which
	// is a few of the protocol's own retransmissions.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// RateLimit and RateBurst bound requests per second per client
	// address. Zero disables them.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// LogTransfers writes an access line per transfer: who, which
	// direction, which path, how much moved and how it ended. Default
	// true. This is the record an estate is asked for when somebody wants
	// to know which switch got which firmware.
	LogTransfers *bool `yaml:"log_transfers"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// Learn records what crosses this listener and writes a proposed policy.
	Learn *TFTPLearn `yaml:"learn"`
}

// TFTPLearn is a tftp listener's learning mode.
type TFTPLearn struct {
	// Enabled turns the recording on.
	Enabled bool `yaml:"enabled"`
	// File is where the report is written, as YAML. Required when enabled.
	File string `yaml:"file"`
	// Interval is how often it is rewritten. Default 5m; it is also written
	// when the listener shuts down.
	Interval Duration `yaml:"interval"`
	// MaxSubjects bounds the observations held: one per client, direction and
	// directory seen. Default 8192; past it the newest is dropped and the drops
	// are counted, because a learning run that quietly stopped learning is
	// worse than one that says so.
	MaxSubjects int `yaml:"max_subjects"`
	// Enforce keeps the policy in force while learning. Default false: a
	// learning run is normally observe-only, and saying so here is what stops
	// one being left on by accident.
	//
	// What it never relaxes is the block, window and transfer-size bounds.
	// Those are what stop this listener being an amplifier, they are not
	// policy, and no report proposes them.
	Enforce bool `yaml:"enforce"`
}

// TFTPRule decides one transfer.
type TFTPRule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before
	// it decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the client is in.
	Clients []string `yaml:"clients"`
	// Operations are the directions this rule covers: read, write.
	Operations []string `yaml:"operations"`
	// Modes are the transfer modes this rule covers.
	Modes []string `yaml:"modes"`
	// Directories are the directories this rule covers, and
	// DenyDirectories the ones it does not cover even when Directories
	// would match.
	Directories     []string `yaml:"directories"`
	DenyDirectories []string `yaml:"deny_directories"`
	// Filenames and DenyFilenames are shell patterns against the cleaned
	// path.
	Filenames     []string `yaml:"filenames"`
	DenyFilenames []string `yaml:"deny_filenames"`
	// AllowPathClasses widens the listener's list for this rule's traffic
	// only, which is how one legacy server that really does serve
	// absolute paths is written down. The three classes the listener
	// cannot allow, a rule cannot allow either.
	AllowPathClasses []string `yaml:"allow_path_classes"`
	// MaxTransferBytes, MaxBlockSize and MaxWindowSize override the
	// listener's bounds for this rule's traffic.
	MaxTransferBytes int64 `yaml:"max_transfer_bytes"`
	MaxBlockSize     int   `yaml:"max_block_size"`
	MaxWindowSize    int   `yaml:"max_window_size"`
	// Schedule limits the rule to a time window, which is what a firmware
	// window is: writes allowed during the change window and not outside
	// it.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// AssetInventory is the estate's own record of what is on its network, built
// from the traffic the proxy was already carrying.
//
// An operational network cannot be scanned: an active scan is how a
// programmable controller gets knocked over, and on a safety network it is a
// thing people lose their jobs for. So the inventory is a by-product. Nothing
// here probes, connects or sends anything.
// Correlation is the cross-listener window (internal/correlate).
//
// It is one section for the daemon rather than one per listener, because
// the whole point is that it spans listeners: a question like "has this
// address been on another control protocol in the last ten minutes" has
// no answer inside one listener's own state.
//
// Enabled by default, because the cost is a bounded table and a lock on
// the events that matter -- a session opened, a refusal, an engineering
// operation, a clock step -- rather than anything per frame, and because
// a detection that needs it is not available at all without it. Turning
// it off is for the estate that wants nothing remembered between
// listeners.
type Correlation struct {
	// Enabled turns it on. Default true; false keeps no cross-listener
	// memory at all, and the detections built on it then report nothing
	// rather than reporting less.
	Enabled *bool `yaml:"enabled"`
	// Window is how long a fact is remembered. Default 30m, ceiling 24h.
	// It bounds what every question can reach back to, so it is also
	// what decides whether "the bastion session before this" is still
	// there to be found.
	Window Duration `yaml:"window"`
	// MaxActors bounds the addresses remembered; the least recently
	// active is evicted. Default 4096.
	MaxActors int `yaml:"max_actors"`
	// MaxFacts bounds one address's facts; the oldest is dropped, and
	// the drop is counted so a truncated window says so rather than
	// answering "no" for the wrong reason. Default 64.
	MaxFacts int `yaml:"max_facts"`
	// Share sends the facts worth sharing -- a gate session, a clock
	// step, an engineering operation -- to the cluster peers, so the
	// daemon in front of the plant can see the bastion session that
	// preceded an OT session. Those are two processes on this design,
	// and without this the pivot is invisible to both. Default true when
	// a cluster is configured; it does nothing without one.
	Share *bool `yaml:"share"`
}

// CorrelationEnabled reports whether the cross-listener window is on.
func (c *Config) CorrelationEnabled() bool {
	if c.Correlation == nil {
		return true
	}
	if c.Correlation.Enabled == nil {
		return true
	}
	return *c.Correlation.Enabled
}

// CorrelationShares reports whether facts are shared with cluster peers.
func (c *Config) CorrelationShares() bool {
	if !c.CorrelationEnabled() {
		return false
	}
	if c.Correlation == nil || c.Correlation.Share == nil {
		return true
	}
	return *c.Correlation.Share
}

type AssetInventory struct {
	// Enabled turns it on. Default false: an inventory is a record of
	// somebody's estate, and a proxy that started keeping one without being
	// asked would be making a decision about their data for them.
	Enabled bool `yaml:"enabled"`
	// StateFile is where the inventory is written and read back. Empty keeps it
	// in memory only, which means the estate is reported as new after every
	// restart -- the fastest way to teach an operator to ignore it.
	StateFile string `yaml:"state_file"`
	// SaveInterval is how often the file is written. Default 5m.
	SaveInterval Duration `yaml:"save_interval"`
	// MaxAssets bounds the inventory. Default 8192. Past the bound the least
	// recently seen asset goes, which is the opposite of the pairing tables in
	// the relay kinds and is deliberate: forgetting here loses history rather
	// than making a decision wrong, and refusing would stop the inventory
	// noticing the estate at the moment something is filling it up.
	MaxAssets int `yaml:"max_assets"`
	// TTL is how long an asset nobody has seen is kept, so that a
	// decommissioned device leaves the record instead of being reported for
	// ever. Default 720h, which is thirty days.
	TTL Duration `yaml:"ttl"`
	// VendorFile is a list of hardware prefixes and manufacturer names, one per
	// line, which replaces nothing and adds to the built-in seed list. The
	// built-in list is two dozen entries weighted towards the vendors an
	// operational estate is made of; an estate that wants the IEEE's registry
	// points this at a copy of it.
	//
	// The format is a prefix, whitespace or a comma, and a name. A malformed
	// line refuses the file rather than being skipped: a list an operator
	// trusted and which silently dropped half its entries is worse than one
	// that would not load.
	VendorFile string `yaml:"vendor_file"`
	// AlertOnNew writes a security event for a device that was not in the
	// frozen baseline. It does nothing until a baseline exists
	// (`xproxyctl assets baseline`), because before that everything is new.
	// Default true.
	AlertOnNew *bool `yaml:"alert_on_new"`
	// AlertOnChange writes a security event when a device's identity changes:
	// its address taken over by another device, its role changed, its vendor
	// re-resolved. Default true, and this is the setting worth leaving on --
	// a steady-state inventory is a reference document, and the deltas are the
	// security value.
	AlertOnChange *bool `yaml:"alert_on_change"`
	// Roles, when set, is the allow list of roles this estate expects to see.
	// A device classified as something else raises a finding, which is how
	// "there are no engineering workstations on the process network" is
	// written down.
	Roles []string `yaml:"roles"`
	// Advisories matches the firmware versions in the inventory against CSAF
	// 2.0 security advisories, which is the question an estate that cannot
	// patch actually has: not "is there an advisory for this controller" but
	// "is the version we are running one of the affected ones".
	Advisories *Advisories `yaml:"advisories"`
}

// Advisories matches the inventory against published CSAF 2.0 advisories.
//
// The documents come from a directory on disk and nothing here fetches them.
// That is deliberate twice over: a relay on a process network dialling a
// vendor's website every hour is a network dependency in the one place that is
// supposed to have none, and advisory distribution already has downloaders --
// the CSAF standard defines one, and every publisher in scope (Siemens
// ProductCERT, Schneider Electric, the CISA ICS advisories) offers a feed or a
// directory listing. The machine that is allowed out runs that, and is also
// where the detached signatures are verified.
type Advisories struct {
	// Enabled turns the matching on. Default false: reading advisories is
	// cheap and *reporting* against them is a claim about somebody's estate,
	// so it is asked for rather than assumed.
	Enabled bool `yaml:"enabled"`
	// Sources are the directories and files the documents come from, each
	// named so that a stale one is attributable in the status view.
	Sources []AdvisorySource `yaml:"sources"`
	// Refresh is how often the sources are re-read. Default 1h, minimum 1m,
	// 0 for never -- a reload of the configuration still re-reads them. A
	// source that fails a refresh keeps the advisories already loaded and is
	// counted, which is the opposite of the rule at load: there, a source that
	// cannot be read is a startup error, because a proxy reporting no
	// advisories because a path was misspelled would be claiming an estate has
	// nothing against it.
	Refresh *Duration `yaml:"refresh"`
	// AlertOnAffected writes a security event for a device an advisory names,
	// once per device per version rather than once per observation: a
	// controller that is affected is affected until somebody updates it, and
	// an event per Modbus frame would bury the estate. Default true.
	AlertOnAffected *bool `yaml:"alert_on_affected"`
	// AlertOnNotAssessed writes an event for a device whose exposure could not
	// be established -- its firmware string is not a version anything can
	// compare, or the advisory's own range carries a condition this cannot
	// evaluate. Default false, because on a first run it is most of the estate
	// and it is a list to work through rather than an alert to answer. The
	// list is always in `xproxyctl assets advisories`.
	AlertOnNotAssessed *bool `yaml:"alert_on_not_assessed"`
	// MinSeverity is the floor for an event: critical, high, medium or low.
	// Empty means every severity. A finding the vendor scored with nothing is
	// reported whatever the floor says, because a record nobody scored is not
	// a record to hide behind a threshold.
	MinSeverity string `yaml:"min_severity"`
}

// AdvisorySource is one place advisories are read from.
type AdvisorySource struct {
	// Name is what an operator calls it: siemens-productcert, cisa-ics. It
	// appears in the status view beside the document count and the time of the
	// last read, so that a directory nobody has updated for a year is visible
	// as itself rather than as a total.
	Name string `yaml:"name"`
	// File is one document and Directory a directory of them, walked into
	// subdirectories because every publisher's distribution is a directory per
	// year. Exactly one of the two.
	File      string `yaml:"file"`
	Directory string `yaml:"directory"`
}

// RefreshInterval is how often the advisory sources are re-read, with the
// default filled in.
func (a *Advisories) RefreshInterval() Duration {
	switch {
	case a == nil:
		return 0
	case a.Refresh == nil:
		return Duration(time.Hour)
	default:
		return *a.Refresh
	}
}

// AlertsOnAffected reports whether a device an advisory names becomes a
// security event.
func (a *Advisories) AlertsOnAffected() bool {
	return a == nil || a.AlertOnAffected == nil || *a.AlertOnAffected
}

// AlertsOnNotAssessed reports whether a device whose exposure could not be
// established becomes a security event.
func (a *Advisories) AlertsOnNotAssessed() bool {
	return a != nil && a.AlertOnNotAssessed != nil && *a.AlertOnNotAssessed
}

// DHCPListener is a kind: dhcp listener: a DHCP relay agent that reads what it
// relays.
//
// DHCP is the one protocol where *answering* is the attack. A client broadcasts
// "who will configure me", and whatever answers first tells it its address, its
// default route, its resolvers, its proxy and -- if it boots from the network --
// the file it boots. Nothing in the exchange authenticates anybody.
type DHCPListener struct {
	// Mode is reverse (the default: clients send here and the relay forwards
	// to the servers) or forward (this listener is the controlled egress a
	// downstream relay agent uses to reach a server elsewhere).
	Mode string `yaml:"mode"`
	// Upstream is the server pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a message may arrive
	// from. Deny is evaluated first.
	//
	// On a segment this is every client, which is why it is not the main
	// control here: a DHCP client has no address yet, so it sends from
	// 0.0.0.0 and the list cannot distinguish it from any other. It is the
	// useful control on a listener that fronts *other relay agents*, where
	// every sender is a known address.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// AllowServers are the addresses a reply may come from, and it is the
	// single most valuable line in the file. Every switch vendor sells this
	// as DHCP snooping with a trusted port; here it is an address list, and
	// an OFFER or an ACK from anywhere else is dropped and counted.
	//
	// Empty means the endpoints of the upstream pool, which is almost always
	// what an operator means and is why it can be left out.
	AllowServers []string `yaml:"allow_servers"`
	// MessageTypes is the allow list of message types a client may send:
	// discover, request, decline, release, inform, lease_query. Empty allows
	// the four of the ordinary lease cycle plus inform, which is to say it
	// leaves out the lease-query family -- a relay agent's own diagnostic,
	// and an inventory of every lease in the estate to anything else.
	MessageTypes []string `yaml:"message_types"`
	// DenyOptions are the options a *server* may not send. Empty uses the
	// built-in list, which is the options that carry a configuration rather
	// than a value: the two classless route options and the obsolete one,
	// the WPAD URL, the TFTP server and boot file, and the vendor-specific
	// blob that can be any of them. Setting the list replaces it.
	DenyOptions []string `yaml:"deny_options"`
	// AllowOptions turns the answer policy inside out: when it is set, an
	// option outside it is removed. It is the positive model, and on a
	// network whose clients need six options it is a shorter and safer thing
	// to write than a deny list.
	AllowOptions []string `yaml:"allow_options"`
	// OnDeniedOption is strip (the default) or deny. strip removes the option
	// and forwards the rest, so a client still gets its address and no longer
	// gets a route it should not have; deny refuses the whole reply, which
	// leaves the client with no address at all.
	OnDeniedOption string `yaml:"on_denied_option"`
	// DenyRequestedOptions are options a client may not *ask* for, in its
	// option 55 parameter list. A client asking for the WPAD URL is a client
	// that will use a proxy if anything offers one, and an estate that has
	// decided not to have that can say so here; the ask is removed rather
	// than the message refused.
	DenyRequestedOptions []string `yaml:"deny_requested_options"`
	// AllowGateways, AllowResolvers and AllowBootServers are the addresses
	// the router, DNS and boot-server options may name. These are the
	// positive form of the same policy as DenyOptions, and the more useful
	// one: an estate knows its own gateways and resolvers, so a reply naming
	// anything else is wrong whoever sent it.
	AllowGateways    []string `yaml:"allow_gateways"`
	AllowResolvers   []string `yaml:"allow_resolvers"`
	AllowBootServers []string `yaml:"allow_boot_servers"`
	// AllowRoutes are the destinations the classless static route options
	// (121 and Microsoft's 249) may carry, for an estate that uses them. A
	// route outside the list is refused, and the refusal names the route.
	AllowRoutes []string `yaml:"allow_routes"`
	// BootFiles are shell patterns the boot filename may match, for the
	// machines that boot from the network. This is where a PXE estate says
	// which images exist.
	BootFiles []string `yaml:"boot_files"`
	// MinLeaseTime and MaxLeaseTime bound the lease a server may hand out. A
	// very long lease is a pool exhausted by every device that ever visited;
	// a very short one is a client that renews constantly. Zero leaves
	// either end unbounded.
	MinLeaseTime Duration `yaml:"min_lease_time"`
	MaxLeaseTime Duration `yaml:"max_lease_time"`
	// RequireClientIDMatch refuses a message whose option 61 client
	// identifier is an Ethernet identifier naming a different hardware
	// address from the one in the header. Default false: it is a real signal
	// and there are real clients that get it wrong, so it is a decision
	// rather than a default.
	RequireClientIDMatch bool `yaml:"require_client_id_match"`
	// RefuseHiddenOptions refuses a message that carried an option in the
	// sname or file field (option 52) or split across instances (RFC 3396).
	// Default true: both are legal, almost nothing in an estate sends them,
	// and both make one message say different things to different parsers.
	RefuseHiddenOptions *bool `yaml:"refuse_hidden_options"`
	// MaxHops bounds the hops field, which counts the relay agents a message
	// has crossed. Default 4; RFC 2131 makes 16 the outer limit. A message
	// arriving with a large hop count has been somewhere.
	MaxHops int `yaml:"max_hops"`
	// RelayAddress is the address this relay puts in giaddr, which is what
	// tells the server which segment to allocate from and where to answer.
	// Required in reverse mode: a relay agent that left giaddr empty would be
	// asking the server to answer a broadcast it never saw.
	RelayAddress string `yaml:"relay_address"`
	// CircuitID and RemoteID fill in the two suboptions of RFC 3046's option
	// 82, which is how a server learns which segment a request came from.
	// Empty leaves the option out.
	CircuitID string `yaml:"circuit_id"`
	RemoteID  string `yaml:"remote_id"`
	// OnClientAgentOption is what to do when a *client* sends option 82:
	// strip (the default, which is what RFC 3046 §2.1 requires) or deny. A
	// client has no business asserting which circuit it is on, because that
	// assertion is exactly what the option exists to make on its behalf.
	OnClientAgentOption string `yaml:"on_client_agent_option"`
	// Rules decide each message, in order, first match wins. A message that
	// matches no rule takes DefaultAction.
	Rules []DHCPRule `yaml:"rules"`
	// DefaultAction is allow (the default) or deny.
	//
	// Unlike the other relay kinds here, the default is allow. DHCP is
	// infrastructure: a listener that refused every request until somebody
	// wrote a rule would be a listener that stops an estate booting, and the
	// protections in this kind are the *answer* policy and the server list,
	// which are on by default and do not depend on a rule existing.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is drop (the default) or nak. drop leaves the client
	// retrying, which is what it does anyway when nothing answers; nak sends
	// a DHCPNAK, which makes a client stop and start over. nak is honest and
	// it is also a way to stop a client dead, so it is not the default.
	DenyResponse string `yaml:"deny_response"`
	// MaxPending bounds the requests outstanding towards servers, which is
	// the table that pairs a reply with the client that asked. Default 256.
	MaxPending int `yaml:"max_pending"`
	// RequestTimeout is how long a server has to answer before its answer is
	// too late to pair. Default 10s.
	RequestTimeout Duration `yaml:"request_timeout"`
	// MaxMessageBytes bounds one message. Default 1500.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// RateLimit and RateBurst bound messages per second per *hardware
	// address*, which is the key that matters on this protocol: address pool
	// exhaustion is one client sending thousands of DISCOVERs with a made-up
	// address in each, and a limit keyed on the source address would see one
	// sender doing nothing unusual.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// MaxClients bounds the distinct hardware addresses this listener will
	// track at once. It is the other half of the starvation bound: the rate
	// limit slows one address down, and this one stops a flood of *new*
	// addresses from filling the table that does the limiting. Default 8192.
	MaxClients int `yaml:"max_clients"`
	// LogMessages writes an access line per message. A segment's DHCP is
	// quiet by the standards of a proxy, so this is affordable here in a way
	// it is not on a directory front.
	LogMessages bool `yaml:"log_messages"`
	// LogLeases writes a line for every address handed out: which hardware
	// address got which lease, for how long, from which server, and what it
	// was told. Default true, and it is the record an estate is asked for --
	// it is also the beginning of an asset inventory.
	LogLeases *bool `yaml:"log_leases"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
}

// DHCPRule decides one message.
type DHCPRule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before it
	// decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the message arrived from.
	Clients []string `yaml:"clients"`
	// HardwareAddresses are the addresses this rule covers, each either a
	// whole address (02:11:22:33:44:55) or a vendor prefix (02:11:22). The
	// prefix form is what a rule about "the telephones" is actually written
	// with, because nobody lists every handset.
	HardwareAddresses []string `yaml:"hardware_addresses"`
	// MessageTypes are the message types this rule covers.
	MessageTypes []string `yaml:"message_types"`
	// VendorClasses and UserClasses match options 60 and 77 as shell
	// patterns, which is how a rule about PXE clients is written:
	// "PXEClient*" is what every one of them sends.
	VendorClasses []string `yaml:"vendor_classes"`
	UserClasses   []string `yaml:"user_classes"`
	// DenyOptions, AllowGateways, AllowResolvers, AllowBootServers,
	// AllowRoutes and BootFiles narrow the answer policy for this rule's
	// traffic, which is how "the PXE segment may be told a boot server and
	// nothing else may" is written.
	DenyOptions      []string `yaml:"deny_options"`
	AllowGateways    []string `yaml:"allow_gateways"`
	AllowResolvers   []string `yaml:"allow_resolvers"`
	AllowBootServers []string `yaml:"allow_boot_servers"`
	AllowRoutes      []string `yaml:"allow_routes"`
	BootFiles        []string `yaml:"boot_files"`
	// MaxLeaseTime overrides the listener's lease bound for this rule.
	MaxLeaseTime Duration `yaml:"max_lease_time"`
	// CircuitID overrides the listener's circuit identifier, so that a rule
	// about one segment can tell the server which segment it is.
	CircuitID string `yaml:"circuit_id"`
	// Schedule limits the rule to a time window.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// DHCP6Listener is a DHCPv6 relay agent (RFC 8415) that reads what it
// relays.
//
// It is a separate kind from dhcp because DHCPv6 is a separate protocol:
// a different packet format, different message types, a nested relay
// mechanism rather than a field, a client identified by a DUID rather
// than a hardware address, and its own options -- including prefix
// delegation, which has no DHCPv4 equivalent at all. An estate running
// both runs both listeners, and writing both down is the point.
//
// The shape of the policy is the same as the DHCPv4 one because the
// shape of the threat is the same: answering is the attack, so the
// interesting half faces upstream. What differs is what an answer can
// carry.
type DHCP6Listener struct {
	// Mode is reverse (the default: clients send here and the relay
	// forwards to the servers) or forward (this listener is the
	// controlled egress a downstream relay agent uses).
	Mode string `yaml:"mode"`
	// Upstream is the server pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a message may arrive
	// from. Deny is evaluated first.
	//
	// On a segment these are link-local addresses, which every client has
	// before it has anything else -- so unlike DHCPv4, where a client
	// sends from 0.0.0.0 and cannot be told apart at all, this list does
	// say something here. It says less than it looks: a link-local
	// address is the sender's own choice.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// AllowServers are the addresses a reply may come from, and it is the
	// single most valuable line in the file. An ADVERTISE or a REPLY from
	// anywhere else is dropped and counted, whatever it says.
	//
	// Empty means the endpoints of the upstream pool, which is almost
	// always what an operator means.
	AllowServers []string `yaml:"allow_servers"`
	// MessageTypes is the allow list of message types a client may send.
	// Empty allows the ordinary lease cycle -- solicit, request, renew,
	// rebind, confirm, release, decline and information_request -- which
	// leaves out the lease-query family: a relay agent's own diagnostic,
	// and an inventory of every lease in the estate to anything else.
	MessageTypes []string `yaml:"message_types"`
	// DenyOptions are the options a *server* may not send. Empty uses the
	// built-in list, which is longer than DHCPv4's and says why in the
	// protocol page: the resolvers and the search list, the boot file URL
	// and its parameters, the captive portal URL, the bootstrap server,
	// the DS-Lite and S46 transition options -- which put a host's IPv4
	// traffic through a border relay of the sender's choosing -- and the
	// Server Unicast option, which tells a client to stop using the relay
	// and so turns off every policy this listener has.
	DenyOptions []string `yaml:"deny_options"`
	// AllowOptions turns the answer policy inside out: when it is set, an
	// option outside it is removed. On a network whose clients need three
	// options it is a shorter and safer thing to write than a deny list.
	AllowOptions []string `yaml:"allow_options"`
	// OnDeniedOption is strip (the default) or deny. strip removes the
	// option and forwards the rest, so a client still gets its address
	// and no longer gets a resolver it should not have; deny refuses the
	// whole reply, which leaves the client with no address at all.
	OnDeniedOption string `yaml:"on_denied_option"`
	// DenyRequestedOptions are options a client may not *ask* for, in its
	// Option Request Option. A client asking for the captive portal URL is
	// a client that will open one if anything offers it; the ask is
	// removed rather than the message refused.
	DenyRequestedOptions []string `yaml:"deny_requested_options"`
	// AllowResolvers are the addresses the DNS server option may name, and
	// AllowDomains are shell patterns the domain search list may match.
	// These are the positive form of the same policy as DenyOptions and
	// the more useful one: an estate knows its own resolvers, so a reply
	// naming anything else is wrong whoever sent it.
	AllowResolvers []string `yaml:"allow_resolvers"`
	AllowDomains   []string `yaml:"allow_domains"`
	// AllowBootURLs are shell patterns the boot file URL (RFC 5970) may
	// match, for the machines that boot from the network. This is where an
	// estate says which images exist.
	AllowBootURLs []string `yaml:"allow_boot_urls"`
	// PrefixDelegation bounds what a reply may delegate and what a client
	// may ask for. It has no DHCPv4 equivalent and it is the setting worth
	// reading twice: a reply delegating ::/0 has handed a host the whole
	// of IPv6 to route.
	PrefixDelegation *DHCP6PrefixPolicy `yaml:"prefix_delegation"`
	// AllowTemporaryAddresses accepts an IA_TA. Default true: temporary
	// addresses are the privacy mechanism of RFC 8415 s6.5 and refusing
	// them would be refusing clients that are doing the right thing.
	AllowTemporaryAddresses *bool `yaml:"allow_temporary_addresses"`
	// AllowReconfigure forwards a RECONFIGURE from a server. Default
	// false: it is a message to a client that answers nothing, RFC 8415
	// s18.3.11 requires it to be authenticated with a key nobody deploys,
	// and a client that accepts one can be made to re-ask a server of the
	// sender's choosing.
	AllowReconfigure bool `yaml:"allow_reconfigure"`
	// MinLeaseTime and MaxLeaseTime bound the valid lifetime a server may
	// hand out, on an address or a delegated prefix. Zero leaves either
	// end unbounded. A valid lifetime of zero is not bounded: it is how a
	// server withdraws an address, and rewriting it would be turning a
	// withdrawal into a lease.
	MinLeaseTime Duration `yaml:"min_lease_time"`
	MaxLeaseTime Duration `yaml:"max_lease_time"`
	// RefuseRepeatedOptions refuses a message carrying an option twice
	// where the standard has no meaning for a second one. Default true:
	// two implementations read such a message differently, and a relay
	// that decided about the first value while the server acted on the
	// last would be the reason nobody could find the bug. The identity
	// associations are exempt, because a client legitimately sends several.
	RefuseRepeatedOptions *bool `yaml:"refuse_repeated_options"`
	// MaxRelayHops bounds the relay chain. Default 4; RFC 8415 s19.1.1
	// makes 32 the outer limit. A message arriving already wrapped several
	// times has been somewhere.
	MaxRelayHops int `yaml:"max_relay_hops"`
	// LinkAddress is the address this relay puts in a RELAY-FORW's link
	// address field, which is what tells the server which segment to
	// allocate from. Required in reverse mode: a relay that left it
	// unspecified would be asking the server to guess.
	LinkAddress string `yaml:"link_address"`
	// InterfaceID, RemoteID and SubscriberID fill in the relay's own
	// options (RFC 8415 s21.18, RFC 4649, RFC 4580), which is how a server
	// learns which circuit and which subscriber a message came from.
	// Empty leaves each out. RemoteID needs an enterprise number, which is
	// the first four octets of that option.
	InterfaceID        string `yaml:"interface_id"`
	RemoteID           string `yaml:"remote_id"`
	RemoteIDEnterprise int    `yaml:"remote_id_enterprise"`
	SubscriberID       string `yaml:"subscriber_id"`
	// OnClientRelayOption is what to do when a *client* sends one of the
	// relay's own options: strip (the default) or deny. A client has no
	// business asserting which circuit it is on, because that assertion is
	// exactly what the option exists to make on its behalf.
	OnClientRelayOption string `yaml:"on_client_relay_option"`
	// Rules decide each message, in order, first match wins. A message
	// that matches no rule takes DefaultAction.
	Rules []DHCP6Rule `yaml:"rules"`
	// DefaultAction is allow (the default) or deny.
	//
	// Allow, as in the DHCPv4 kind and for the same reason: DHCP is
	// infrastructure, a listener that refused every request until somebody
	// wrote a rule would be a listener that stops an estate booting, and
	// the protections here are the answer policy and the server list,
	// which are on by default and do not depend on a rule existing.
	DefaultAction string `yaml:"default_action"`
	// MaxPending bounds the requests outstanding towards servers, which is
	// the table that pairs a reply with the client that asked. Default 256.
	MaxPending int `yaml:"max_pending"`
	// RequestTimeout is how long a server has to answer before its answer
	// is too late to pair. Default 10s.
	RequestTimeout Duration `yaml:"request_timeout"`
	// MaxMessageBytes bounds one message. Default 1500. A relay chain
	// grows a message, so this is the bound on what arrives rather than on
	// what a client sent.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// RateLimit and RateBurst bound messages a second per *DUID*, which is
	// the key that matters on this protocol: pool exhaustion is one host
	// sending thousands of SOLICITs with a made-up identifier in each, and
	// a limit keyed on the source address would see one sender doing
	// nothing unusual.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// MaxClients bounds the distinct identifiers this listener tracks at
	// once. It is the other half of the starvation bound: the rate limit
	// slows one identifier down, and this stops a flood of new ones from
	// filling the table that does the limiting. Default 8192.
	MaxClients int `yaml:"max_clients"`
	// LogMessages writes an access line per message.
	LogMessages bool `yaml:"log_messages"`
	// LogLeases writes a line for every address and prefix handed out:
	// which identifier got which lease, for how long, from which server.
	// Default true, and it is the record an estate is asked for.
	LogLeases *bool `yaml:"log_leases"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
}

// DHCP6PrefixPolicy bounds prefix delegation.
//
// Prefix delegation is the part of DHCPv6 with no DHCPv4 equivalent, and
// the part where a wrong answer is largest: a reply delegating ::/0 has
// handed a host the whole of IPv6 to route, and a request for a /48 where
// the estate delegates /56s is a client asking for two hundred and
// fifty-six times what it should have.
type DHCP6PrefixPolicy struct {
	// Enabled carries prefix delegation at all. Default true: an estate
	// that does not use it should say so, because then an IA_PD arriving
	// from anywhere is a question worth refusing.
	Enabled *bool `yaml:"enabled"`
	// Prefixes are the prefixes a delegation may come from. A delegated
	// prefix outside all of them is refused, and the refusal names it.
	Prefixes []string `yaml:"prefixes"`
	// MinLength and MaxLength bound the prefix length, in bits. An estate
	// that delegates /56s writes 56 in both, and then a /48 is refused
	// whoever offered it.
	MinLength int `yaml:"min_length"`
	MaxLength int `yaml:"max_length"`
}

// Delegating says whether prefix delegation is carried.
func (p *DHCP6PrefixPolicy) Delegating() bool {
	return p == nil || p.Enabled == nil || *p.Enabled
}

// DHCP6Rule decides one message.
type DHCP6Rule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before
	// it decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the message arrived from.
	Clients []string `yaml:"clients"`
	// DUIDs are shell patterns the client identifier's rendering matches,
	// which is "ll:0003*" for a vendor's whole fleet and the whole
	// identifier for one machine. The rendering is the type and the
	// hexadecimal octets, which is what the logs carry too.
	DUIDs []string `yaml:"duids"`
	// MessageTypes are the message types this rule covers.
	MessageTypes []string `yaml:"message_types"`
	// VendorClasses and UserClasses match the vendor class and user class
	// options as shell patterns, which is how a rule about PXE clients is
	// written.
	VendorClasses []string `yaml:"vendor_classes"`
	UserClasses   []string `yaml:"user_classes"`
	// DenyOptions, AllowResolvers, AllowDomains and AllowBootURLs narrow
	// the answer policy for this rule's traffic, which is how "the boot
	// segment may be told a boot URL and nothing else may" is written.
	DenyOptions    []string `yaml:"deny_options"`
	AllowResolvers []string `yaml:"allow_resolvers"`
	AllowDomains   []string `yaml:"allow_domains"`
	AllowBootURLs  []string `yaml:"allow_boot_urls"`
	// MaxLeaseTime overrides the listener's lease bound for this rule.
	MaxLeaseTime Duration `yaml:"max_lease_time"`
	// InterfaceID overrides the listener's interface identifier, so that a
	// rule about one segment can tell the server which segment it is.
	InterfaceID string `yaml:"interface_id"`
	// Schedule limits the rule to a time window.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// CoAPListener configures a kind: coap listener: a CoAP relay agent
// (RFC 7252) on UDP 5683, or on 5684 inside DTLS where the listener
// carries a tls section.
//
// The shape is unlike the other relay kinds in one way that is worth
// saying at the top. A CoAP request carries a method, a path and a
// content format, which is to say it says what is about to happen in
// fields a relay can read -- so the request side is where most of this
// policy lives, and a positive model ("GET anything under /3303, PUT
// only /3311/0/5850") is a sentence an estate can write about its own
// devices rather than an aspiration. The answer side exists for one
// reason: the size of an answer relative to the question, because CoAP
// over UDP is a reflection amplifier.
type CoAPListener struct {
	// Mode is reverse (the default: clients here and devices upstream) or
	// forward (this listener is the controlled egress a downstream client
	// uses to reach devices elsewhere).
	Mode string `yaml:"mode"`
	// Upstream is the device pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a message may arrive
	// from. Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// AllowServers are the addresses a response may come from. Empty means
	// the endpoints of the upstream pool, which is almost always what an
	// operator means and never "anybody".
	AllowServers []string `yaml:"allow_servers"`
	// MessageTypes is the allow list of message types a client may send.
	// Empty allows con and non, which are the two a client sends; an
	// acknowledgement and a reset carry no request and are decided before
	// this list is consulted.
	MessageTypes []string `yaml:"message_types"`
	// Methods is the allow list of methods. Empty allows the four of
	// RFC 7252 -- get, post, put, delete -- and not the three of RFC 8132.
	// fetch is the one worth naming: it puts its selector in the payload,
	// so a path policy sees less of a fetch than of a get, and an estate
	// should say so on purpose rather than inherit it.
	Methods []string `yaml:"methods"`
	// AllowPaths and DenyPaths are shell patterns over the request path,
	// deny evaluated first. Empty AllowPaths means any path, which is why
	// the rules below are where an estate says what it permits. A pattern
	// ending in "/..." matches the subtree; a "*" matches one segment,
	// because it does not cross a separator.
	AllowPaths []string `yaml:"allow_paths"`
	DenyPaths  []string `yaml:"deny_paths"`
	// AllowQueries are shell patterns each Uri-Query part must match.
	AllowQueries []string `yaml:"allow_queries"`
	// ContentFormats are the media types a payload may declare, in either
	// direction. Empty allows any.
	ContentFormats []string `yaml:"content_formats"`
	// AllowUnknownContentFormats carries a payload declaring a number this
	// relay cannot name. Default true: the registry grows, and an estate
	// that wants to name its formats writes ContentFormats.
	AllowUnknownContentFormats *bool `yaml:"allow_unknown_content_formats"`
	// AllowProxying carries Proxy-Uri and Proxy-Scheme. Default false, and
	// it is the most consequential default here: those options turn the
	// device at the far end into a forward proxy, which on a constrained
	// network is an open relay, an amplification stage and a way to reach
	// what the network was segmented to protect.
	AllowProxying bool `yaml:"allow_proxying"`
	// AllowObserve carries RFC 7641 registrations. Default true, because
	// observing is how telemetry works on this protocol; MaxObservers
	// bounds how many are outstanding.
	AllowObserve *bool `yaml:"allow_observe"`
	// MaxObservers bounds the registrations tracked at once. Default 256.
	MaxObservers int `yaml:"max_observers"`
	// AllowDiscovery carries a request for /.well-known/core (RFC 6690),
	// the resource whose purpose is to list every other resource. Default
	// true, because a management system uses it; refusing it is how an
	// estate stops the largest answer on a device being available to the
	// smallest question.
	AllowDiscovery *bool `yaml:"allow_discovery"`
	// RefuseSuspiciousPaths refuses a request whose path segments would
	// not mean what the joined path looks like: a segment containing a
	// separator, a segment that is "." or "..", a NUL, or bytes that are
	// not UTF-8. Default true. It is a refusal rather than a
	// normalisation, because normalising means guessing what the device
	// would have done with the original.
	RefuseSuspiciousPaths *bool `yaml:"refuse_suspicious_paths"`
	// RefuseUnknownOptions applies the rule RFC 7252 s5.4 and s5.7.1 give
	// a proxy for an option it cannot name: 4.02 for a Critical one, 5.02
	// for an UnSafe one. Default true. Turning it off carries options
	// whose meaning is unknown, which is carrying a request whose meaning
	// is unknown.
	RefuseUnknownOptions *bool `yaml:"refuse_unknown_options"`
	// RefuseRepeatedOptions refuses a message carrying an option twice
	// where the standard has no meaning for a second one. Default true.
	// The path and the query are exempt, because they are built out of
	// repetition.
	RefuseRepeatedOptions *bool `yaml:"refuse_repeated_options"`
	// RequireToken refuses a request with an empty token. RFC 7252 s5.3.1
	// permits one; requiring it is how an estate makes every answer
	// traceable to the question, because the token is the only thing that
	// pairs them.
	RequireToken bool `yaml:"require_token"`
	// MaxPayloadBytes bounds one message's payload. Default 1024.
	MaxPayloadBytes int `yaml:"max_payload_bytes"`
	// MaxTransferBytes bounds a whole block-wise transfer (RFC 7959),
	// which is the number that matters: a bound on one datagram bounds
	// nothing when a client can walk a device through sixty-four thousand
	// of them. Size1 and Size2 declare the total, so the intent is refused
	// at the first block. Default 65536.
	MaxTransferBytes int `yaml:"max_transfer_bytes"`
	// MaxBlockBytes bounds one block. Default 1024, which is the largest
	// RFC 7959 defines.
	MaxBlockBytes int `yaml:"max_block_bytes"`
	// MaxMessageBytes bounds what arrives. Default 1152, which is
	// RFC 7252 s4.6's figure for a message that fits an IPv6 datagram
	// with headroom.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// MaxResponseBytes bounds a device's answer.
	MaxResponseBytes int `yaml:"max_response_bytes"`
	// AmplificationFactor bounds a response's size as a multiple of the
	// request's. Zero is off. It is the check a per-datagram bound cannot
	// make: a kilobyte answer is unremarkable on its own and is a hundred
	// and fifty times the four-octet question that asked for it.
	AmplificationFactor int `yaml:"amplification_factor"`
	// Rules decide each message, in order, first match wins.
	Rules []CoAPRule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	//
	// Deny, unlike the DHCP kinds and for the opposite reason: CoAP is
	// actuation, the paths are the device's object model, and an estate
	// that can name its devices can name what may be done to them. A
	// listener with no rules refuses everything, and the validator says so.
	DefaultAction string `yaml:"default_action"`
	// MaxPending bounds the requests outstanding towards devices, which is
	// the table that pairs a response with the client that asked.
	// Default 256.
	MaxPending int `yaml:"max_pending"`
	// RequestTimeout is how long a device has to answer before its answer
	// is too late to pair. Default 10s.
	RequestTimeout Duration `yaml:"request_timeout"`
	// RateLimit and RateBurst bound messages a second per source address,
	// which is the only key this protocol offers in NoSec mode.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// MaxClients bounds the distinct sources tracked at once. Default 8192.
	MaxClients int `yaml:"max_clients"`
	// DTLSHandshakeTimeout is how long a peer has to finish a DTLS handshake,
	// where this listener carries a certificate. Default 10s.
	//
	// It is the bound that matters most on a datagram listener, because a
	// handshake is where a peer that has proved nothing already costs
	// something: a socket, a goroutine and a slot in the peer table. A peer
	// that sends one flight and stops would otherwise hold all three for as
	// long as the process runs.
	DTLSHandshakeTimeout Duration `yaml:"dtls_handshake_timeout"`
	// DTLSIdleTimeout is how long a session with nothing on it is kept.
	// Default 5m.
	//
	// It is worth raising where the devices report on a long cycle: a sensor
	// that speaks once an hour would otherwise handshake every time, which on
	// a battery-powered device is the expensive part of the exchange.
	DTLSIdleTimeout Duration `yaml:"dtls_idle_timeout"`
	// PSK serves RFC 7252 s9.1.3.1's pre-shared key mode, which is the one a
	// constrained device actually ships with. See CoAPPSK.
	PSK *CoAPPSK `yaml:"psk"`
	// PublicKeys pin peers by their public key rather than by an authority
	// that vouched for it, which is what RFC 7252 s9.1.3.2's raw public key
	// mode is about. See CoAPPublicKey.
	PublicKeys []CoAPPublicKey `yaml:"public_keys"`
	// RequireSecurityName refuses a message from a session whose peer maps to
	// no security name. Default true where a psk or public_keys table exists
	// and false where neither does, because a listener with no table has
	// nothing to map a peer to and would otherwise refuse every message.
	//
	// It is the switch that decides what a session established some other way
	// means. A listener with a key table and a certificate accepts both, and
	// a certificate that matches no row leaves the session with no name --
	// which is a peer this estate did not enrol, holding a certificate some
	// authority issued. Refusing it is the default for the same reason the
	// snmp kind's require_security_name is: a rule naming a security name is
	// unmatchable otherwise, and the policy silently becomes one about
	// addresses.
	RequireSecurityName *bool `yaml:"require_security_name"`
	// AnswerRefusals sends the response code the standard gives for a
	// refusal rather than dropping the datagram. Default true, and it
	// matters more here than elsewhere: a Confirmable request is
	// retransmitted until something answers, so a dropped refusal turns
	// one refused request into four or five -- and leaves the device's own
	// logs showing a timeout instead of a refusal.
	AnswerRefusals *bool `yaml:"answer_refusals"`
	// LogMessages writes an access line per message.
	LogMessages bool `yaml:"log_messages"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
}

// CoAPPSK is a listener's pre-shared key mode: the identity-to-key table, and
// the hint the server offers.
//
// RFC 7252 s9.1.3.1 makes TLS_PSK_WITH_AES_128_CCM_8 mandatory for this mode,
// which is why a device with sixty kilobytes of flash speaks it: a certificate
// chain, a clock to check it against and an asymmetric verification are things
// that part does not have. What it gives a relay in exchange is the one thing
// this protocol otherwise has none of -- a name the client states and then
// proves.
//
// That name is the security name a rule names, the same idea as the snmp
// kind's cert_to_name table, so that an operator running both sees one idea
// and not two.
type CoAPPSK struct {
	// Identities are the keys this listener holds. A handshake naming an
	// identity that is not here fails, and the attempt is counted and logged:
	// on a segment where the identity is the identity, a device announcing a
	// name nobody enrolled is either misconfigured or is somebody guessing.
	Identities []CoAPPSKIdentity `yaml:"identities"`
	// Hint is the PSK identity hint the server sends (RFC 4279 s5.2). Most
	// constrained clients ignore it; an estate running two key sets on one
	// segment uses it to say which one this listener is.
	Hint string `yaml:"hint"`
}

// CoAPPSKIdentity is one row of the pre-shared key table.
type CoAPPSKIdentity struct {
	// Identity is what the client sends in the clear, in its
	// ClientKeyExchange. Required, and an empty one is refused at load: it
	// would be the row reached by every client that names nothing.
	Identity string `yaml:"identity"`
	// Key is the shared secret, in the usual file:/env:/vault: form. It is
	// read as raw octets unless it is hexadecimal with a 0x prefix, in which
	// case it is decoded -- because half the devices in the field are
	// provisioned with a hex string and the other half with a pass phrase,
	// and guessing which would be the wrong kind of helpful.
	//
	// Sixteen octets is the least this accepts: that is the width of the
	// cipher key the mandatory suite uses, and a shorter secret is a shorter
	// cipher key whatever the suite says.
	Key string `yaml:"key"`
	// Name is the security name this identity maps to. Empty means the
	// identity itself, which is what an estate that names its devices
	// sensibly wants; a name is for the estate that wants several devices to
	// share one line in the policy ("hall-sensors") without sharing a key.
	Name string `yaml:"name"`
}

// CoAPPublicKey pins one peer by its public key.
//
// RFC 7252 s9.1.3.2's raw public key mode is the middle of the three: an
// asymmetric key with nothing vouching for it, no chain to walk and no expiry
// to check. For an estate with a hundred sensors and no certificate authority
// that is the right shape -- the policy names the key, and a device is
// whichever peer holds it.
//
// What this listener pins is the SHA-256 of the key's SubjectPublicKeyInfo,
// which is the key itself and not the envelope it arrived in: a certificate
// reissued around the same key has the same fingerprint here, and a
// certificate reissued with a *new* key does not. The transport carries the
// key inside a certificate rather than in RFC 7250's own structure, and
// docs/protocols/coap.md says plainly what that costs and why.
type CoAPPublicKey struct {
	// Fingerprint is the key: the SHA-256 of its SubjectPublicKeyInfo as
	// hexadecimal, with "sha256:" allowed in front and colons, spaces or
	// hyphens between octets ignored, so it can be pasted from whatever
	// printed it. `xproxyctl coap key-fingerprint FILE` prints one.
	Fingerprint string `yaml:"fingerprint"`
	// Name is the security name this key maps to. Required: a key with no
	// name would be a row that authenticated a peer and told the policy
	// nothing, which is the mode this table exists to avoid.
	Name string `yaml:"name"`
}

// CoAPRule is one per-message rule on a kind: coap listener.
type CoAPRule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before
	// it decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the message arrived from.
	Clients []string `yaml:"clients"`
	// Methods are the methods this rule covers.
	Methods []string `yaml:"methods"`
	// Paths are shell patterns over the request path. They both select the
	// rule and are checked by it, so a rule about one subtree does not
	// decide about another.
	Paths []string `yaml:"paths"`
	// Queries and ContentFormats narrow the listener's own lists for this
	// rule's traffic.
	Queries        []string `yaml:"queries"`
	ContentFormats []string `yaml:"content_formats"`
	// SecureOnly refuses the rule's traffic when it arrived in the clear
	// rather than inside DTLS, which is how "the actuators may only be
	// written by a client that authenticated" is written.
	SecureOnly bool `yaml:"secure_only"`
	// SecurityNames are the peer identities this rule covers: a pre-shared
	// key identity's name, or the name a pinned public key maps to. A rule
	// naming them covers no message from a session without one, and none from
	// a NoSec client at all -- a rule written about an authenticated device
	// must not apply to an unauthenticated one that happens to be at the same
	// address.
	//
	// This is the field that makes DTLS worth the handshake on this protocol.
	// Without it a policy decides on the source address, which on a shared
	// segment is a guess about which sensor sent something; with it the
	// policy names the device.
	SecurityNames []string `yaml:"security_names"`
	// AllowProxying and AllowObserve override the listener's own switches
	// for this rule's traffic.
	AllowProxying bool  `yaml:"allow_proxying"`
	AllowObserve  *bool `yaml:"allow_observe"`
	// MaxPayloadBytes overrides the listener's payload bound.
	MaxPayloadBytes int `yaml:"max_payload_bytes"`
	// Schedule limits the rule to a time window.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// RequiresSecurityName says whether a message from a session with no security
// name is refused. It is true by default exactly where there is a table to map
// a peer through.
func (m *CoAPListener) RequiresSecurityName() bool {
	if m == nil {
		return false
	}
	if m.RequireSecurityName != nil {
		return *m.RequireSecurityName
	}
	return len(m.PublicKeys) > 0 || (m.PSK != nil && len(m.PSK.Identities) > 0)
}

// Alerts says whether a refusal writes a security event.
func (m *DHCP6Listener) Alerts() bool {
	return m == nil || m.AlertOnDeny == nil || *m.AlertOnDeny
}

// Leases says whether a lease line is written.
func (m *DHCP6Listener) Leases() bool {
	return m == nil || m.LogLeases == nil || *m.LogLeases
}

// RefusesRepeated says whether a repeated option refuses the message.
func (m *DHCP6Listener) RefusesRepeated() bool {
	return m == nil || m.RefuseRepeatedOptions == nil || *m.RefuseRepeatedOptions
}

// TemporaryAddresses says whether an IA_TA is carried.
func (m *DHCP6Listener) TemporaryAddresses() bool {
	return m == nil || m.AllowTemporaryAddresses == nil || *m.AllowTemporaryAddresses
}

// SNMPDeception answers as an agent that is not there.
//
// A refusal is information here as it is on the plant protocols, and on this
// one it is the *credential* a refusal is about. A community string that is
// wrong is answered with noAccess or noSuchName; one that is right is
// answered with data. So a run through a password list finds the string, and
// the run before it finds which devices are there at all -- because an agent
// that exists answers something and an address that has nothing on it
// answers nothing.
//
// And the system group is the other half. Every scanner asks for sysDescr,
// sysObjectID and sysName first, which is exactly the inventory of an estate
// an intruder wants; no policy in this section can make that answer less
// informative, because the estate's own monitoring reads the same objects.
//
// This section answers instead, as a device whose counters rise, whose
// interfaces are up and whose uptime is the uptime of nothing.
//
// **The rule is the one the other kinds hold to**: a request that was going
// to reach the agent is never answered from here. Deception replaces a
// refusal -- a policy denial, or an object the fabrication does not have --
// and never an answer. mode: answer therefore refuses to load without
// clients.
//
// **And one bound of its own.** A fabricated agent is a UDP service that
// answers a small request with a larger response, which is an amplifier if
// it answers anybody. So the listener's own max_repetitions, max_var_binds
// and max_response_bytes apply to what the fabrication answers exactly as
// they apply to what an agent answers, and a GETBULK is bounded before it is
// fabricated rather than after.
type SNMPDeception struct {
	// Enabled turns the section off without removing it; it defaults to
	// true wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a request this listener was going to
	// refuse is answered by the fabrication instead, and never reaches the
	// agent) or decoy (the whole listener is a fabricated agent: no
	// upstream, and nothing behind it).
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client, which is what
	// a honeypot wants.
	Clients []string `yaml:"clients"`
	// Profile is the fabricated device's shape: generic-switch (the
	// default) or generic-router. It decides how many interfaces it has and
	// what it says it is.
	Profile string `yaml:"profile"`
	// SysDescr, SysObjectID, SysName, SysContact and SysLocation are the
	// system group: what every scanner reads first and what an inventory
	// tool records.
	//
	// **A decoy should say what the estate's own devices say.** A switch
	// that describes itself as something nobody on the site runs is the
	// tell that ends the pretence, and only you know what that is.
	SysDescr    string `yaml:"sys_descr"`
	SysObjectID string `yaml:"sys_object_id"`
	SysName     string `yaml:"sys_name"`
	SysContact  string `yaml:"sys_contact"`
	SysLocation string `yaml:"sys_location"`
	// Interfaces is how many ports the fabricated device has, 1 to 256.
	// Zero takes the profile's.
	Interfaces int `yaml:"interfaces"`
	// Tripwire are object identifier subtrees no legitimate manager reads:
	// a vendor's configuration-download branch, say. A binding under one is
	// answered -- the answer is what keeps the visitor reading -- and
	// raised as an snmp_tripwire security event, which is what somebody
	// acts on.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated values reproducible. Zero derives one from
	// the listener name, which is stable across restarts.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a counter or a gauge lasts. Default
	// 30s; 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
}

// SNMPUser is one version 3 USM user whose traffic this listener can read.
//
// The pass phrases are the same ones a manager is configured with -- what
// net-snmp's -A and -X take -- because the key is derived from the pass
// phrase and the agent's engine identifier, and both ends have to derive the
// same one. The relay derives it too, which is how it verifies a digest
// nobody else could have produced.
type SNMPUser struct {
	// Name is the USM user name, as it appears in the message.
	Name string `yaml:"name"`
	// EngineID pins the authoritative engine this user's messages must
	// name, as hexadecimal (with optional 0x, colons or dashes). Empty
	// accepts whatever engine the message names and derives a key for it,
	// up to max_usm_engines.
	//
	// Pinning it is the stronger setting where an operator knows the
	// identifier: a key is then derived once, at load, and a message
	// naming a different engine is refused rather than costing a
	// derivation.
	EngineID string `yaml:"engine_id"`
	// Auth is the authentication protocol: md5, sha1, sha224, sha256,
	// sha384 or sha512. Required.
	Auth string `yaml:"auth"`
	// AuthSecret is the authentication pass phrase, in the usual
	// file:/env:/vault: form. Required.
	AuthSecret string `yaml:"auth_secret"`
	// Privacy is the privacy protocol: des, aes128, aes192 or aes256.
	// Empty means this user is not expected to encrypt, and an authPriv
	// message from it is refused rather than forwarded unread -- a
	// listener that holds keys in order to read the traffic should not
	// have one user able to opt out of being read.
	Privacy string `yaml:"privacy"`
	// PrivacySecret is the privacy pass phrase. Required with privacy.
	PrivacySecret string `yaml:"privacy_secret"`
}

// SNMPCertName is one row of RFC 6353 s5.3's certificate-to-security-name
// table: which certificate it is about, and how the name is derived.
//
// The table is what turns a (D)TLS peer's proof that it holds a private key
// into an identity a rule can name. Rows are tried in order and the first whose
// fingerprint matches decides -- including deciding that there is no name, when
// the row matched and the certificate has nothing where the mapping looked.
type SNMPCertName struct {
	// Fingerprint is the certificate this row is about: a hexadecimal hash of
	// its DER, with the algorithm named ("sha256:4f:2a:...") or inferred from
	// the length. Colons, spaces and hyphens between octets are ignored, so a
	// fingerprint can be pasted from whatever printed it. RFC 6353 names
	// sha1, sha256, sha384 and sha512; md5 is refused, because a fingerprint
	// that can be collided is not an identity.
	//
	// "any" matches any certificate the handshake accepted. That is an
	// extension to the standard's table and it is there because an estate
	// running its own authority has already decided which authority to trust,
	// in tls.client_ca_file, and a row per certificate means a configuration
	// change every time one is reissued. It is safe exactly to the extent
	// that the listener requires and verifies a client certificate, and
	// validation warns when it does not.
	Fingerprint string `yaml:"fingerprint"`
	// Map is how the name is derived: specified (the name is in this row),
	// san_rfc822, san_dns, san_ip (a subject alternative name, lowercased
	// where the standard says to), san_any (the first of those three the
	// certificate has, in that order) or common_name. Default san_any.
	//
	// common_name is RFC 6353's own last resort and it advises against it:
	// a common name is free text that has meant several things over the
	// years, and two authorities can issue the same one.
	Map string `yaml:"map"`
	// Name is the security name, for map: specified only. With any other
	// mapping the name comes from the certificate, and a name here would
	// look like it applied and would not -- so it is refused at load.
	Name string `yaml:"name"`
}

// SNMPRule decides one message.
type SNMPRule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before it
	// decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the manager is in.
	Clients []string `yaml:"clients"`
	// Versions are the protocol versions this rule covers.
	Versions []string `yaml:"versions"`
	// Communities are the community strings (v1 and v2c) this rule covers.
	Communities []string `yaml:"communities"`
	// Users are the v3 USM user names this rule covers.
	Users []string `yaml:"users"`
	// SecurityNames are the transport security model names this rule
	// covers: the name RFC 6353 s5.3's mapping derived from the peer's
	// certificate. A rule naming them covers no other message, the way a
	// rule naming communities covers no v3 message -- a rule written about
	// one authentication scheme must not apply to another.
	SecurityNames []string `yaml:"security_names"`
	// Transports are the transports this rule covers: udp, tcp, tls, dtls.
	// Empty covers all four.
	//
	// It is the field that lets one listener hold two policies at once,
	// which is what an estate part-way through a migration has: the network
	// operations centre reaching it inside DTLS with a certificate, the
	// plant's own pollers still sending plain datagrams, and a different
	// answer for each.
	Transports []string `yaml:"transports"`
	// MinSecurityLevel is the lowest v3 security level this rule covers, so
	// that "this subtree only with authPriv" is one rule.
	MinSecurityLevel string `yaml:"min_security_level"`
	// PDUs are the operations by name: get, get_next, get_bulk, set, trap,
	// trap_v1, inform, response, report.
	PDUs []string `yaml:"pdus"`
	// Access matches what the operation does: read, write or notify. It is
	// the durable way to write a policy, because it does not change when a
	// later revision adds an operation.
	Access []string `yaml:"access"`
	// OIDs are the object identifier subtrees the message may name, as
	// "1.3.6.1.2.1" or a single object. A message naming an object outside
	// all of them does not match. The comparison is per sub-identifier, so
	// 1.3.6.1.2.1 does not cover 1.3.6.1.2.11.
	OIDs []string `yaml:"oids"`
	// DenyOIDs are subtrees this rule does not cover even when OIDs would
	// match, which is how an exception inside an allowed subtree is
	// written: all of mib-2 except the ARP table.
	DenyOIDs []string `yaml:"deny_oids"`
	// WriteOIDs apply instead of OIDs to a SetRequest when set, so one
	// rule can allow a wide read and a narrow write.
	WriteOIDs []string `yaml:"write_oids"`
	// MaxRepetitions overrides the listener's GETBULK bound for this rule.
	MaxRepetitions int `yaml:"max_repetitions"`
	// Contexts are the v3 context names this rule covers, for an engine
	// that fronts several agents.
	Contexts []string `yaml:"contexts"`
	// Schedule limits the rule to a time window.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// IEC104Learn records what crosses the listener and writes a proposed policy.
//
// A substation's drawings say what the traffic was meant to be. The traffic
// says what the integrator left behind: a control centre interrogating a
// station nobody documented, a gateway sending spontaneous data for points the
// drawings do not list, an engineering laptop that has been connected since
// commissioning. A policy written from the drawings refuses half of it on the
// first shift, which is how a security control gets turned off and stays off.
type IEC104Learn struct {
	// Enabled turns the recording on.
	Enabled bool `yaml:"enabled"`
	// File is where the report is written, as YAML. Required when enabled.
	File string `yaml:"file"`
	// Interval is how often it is rewritten. Default 5m; it is also written
	// when the listener shuts down.
	Interval Duration `yaml:"interval"`
	// MaxSubjects bounds the observations held: one per client, direction,
	// common address and type identification seen. Default 8192; past it the
	// newest is dropped and the drops are counted, because a learning run that
	// quietly stopped learning is worse than one that says so.
	MaxSubjects int `yaml:"max_subjects"`
	// Enforce keeps the policy in force while learning. Default false: a
	// learning run is normally observe-only, and saying so here is what stops
	// one being left on by accident.
	Enforce bool `yaml:"enforce"`
}

// IEC104Deception answers as a substation that is not there.
//
// A refusal is information. This relay answers a refused activation the
// way the standard says a station does -- the same ASDU back with the
// negative-confirm bit -- and a common address outside common_addresses
// the same way, so a control centre's alarm list says something true.
// Which means a scanner sweeping common addresses learns which stations
// exist, and one walking type identifications learns which the policy
// permits. The scan is refused and the survey completes.
//
// This answers instead. **On a grid the failure mode is not a confused
// scanner**: it is a control room acting on a measurement nothing
// measured, or believing a command landed that did not. So the same rule
// the modbus section holds to holds here, and it is a test rather than an
// intention: a frame that was going to reach a station is never answered
// by the fabrication. Deception replaces a refusal and never an answer,
// and mode answer will not load without clients.
type IEC104Deception struct {
	// Enabled turns the section off without removing it; it defaults to
	// true wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: an activation this listener was going
	// to refuse is confirmed by the fabrication instead, and never
	// reaches the station) or decoy (the whole listener is a fabricated
	// station: no upstream, and nothing behind it).
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client, which is
	// what a honeypot wants.
	Clients []string `yaml:"clients"`
	// Profile is the fabricated station's shape: generic-substation (the
	// default) or generic-rtu. It decides which points the station has
	// and what they report.
	Profile string `yaml:"profile"`
	// CommonAddresses are the stations the fabrication answers for, as
	// numbers or "1-4" ranges. Default "1". Everything else is answered
	// the way a station answers an address it is not, because one
	// association carrying twenty substations is not a substation.
	CommonAddresses []string `yaml:"common_addresses"`
	// Points are what the fabricated station has, in the order they are
	// reported to a general interrogation. Empty takes the profile's.
	Points []IEC104DecoyPoints `yaml:"points"`
	// Tripwire are information object addresses no legitimate control
	// centre reads. A read or a command naming one is answered -- the
	// answer is what keeps the visitor reading -- and raised as an
	// iec104_tripwire security event, which is what somebody acts on.
	Tripwire []string `yaml:"tripwire"`
	// Spontaneous sends unsolicited reports while data transfer is
	// started, which is what a live station does between interrogations.
	// Default true: a station that says nothing until spoken to is a
	// station somebody looks at twice.
	Spontaneous *bool `yaml:"spontaneous"`
	// Seed makes the fabricated values reproducible. Zero derives one from
	// the listener name, which is stable across restarts.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a value lasts, and how often a
	// spontaneous report is sent. Default 30s; 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
}

// IEC104DecoyPoints is one run of information object addresses and what
// the fabricated station reports them as.
type IEC104DecoyPoints struct {
	// Addresses is the run, as "1-32".
	Addresses string `yaml:"addresses"`
	// Type is the ASDU type identification these are reported as:
	// M_SP_NA_1 (a single point), M_DP_NA_1 (a double point), M_ME_NB_1
	// (a scaled measurement), M_ME_NC_1 (a short float) or M_IT_NA_1 (an
	// integrated total). A type outside that list is not something this
	// can fabricate a value for.
	Type string `yaml:"type"`
	// Min and Max bound a measurement. Defaults 0 and 27648.
	Min int `yaml:"min"`
	Max int `yaml:"max"`
	// Rate is how much a total adds each period.
	Rate int `yaml:"rate"`
}

// IEC104Setpoint bounds the value a setpoint command may carry.
//
// It is the bound a rule about type identifications cannot express. A rule says
// a control centre may send C_SE_NB_1 to point 4711; this says the value it
// carries has to be between 0 and 40, and may not move by more than 5 at a
// time. On a turbine or a tap changer that difference is the difference between
// a policy about who may act and a policy about what may happen.
//
// **What the number means depends on the encoding**, and this relay cannot always
// tell. A scaled value (C_SE_NB_1) is an integer in the point's own unit, which
// is what an engineer means by a setpoint. A short float (C_SE_NC_1) likewise.
// But a normalised value (C_SE_NA_1) is a *fraction of full scale*, from -1 to
// very nearly +1, and the full scale is configured in the device where this relay
// cannot see it -- so a bound on a normalised point is a bound on the fraction,
// and writing min: 0 / max: 40 for one is a mistake the load will not catch. The
// reference says so beside this, and the protocol page says it again.
// IEC104Authentication is an iec104 listener's posture on the secure
// authentication of IEC 60870-5-7, which is the application layer IEC 62351-5
// specifies.
//
// **This relay recognises the exchange and carries it; it does not verify it.**
// Verifying means holding the update keys, and a relay holding them would be a
// second place for an attacker to take them from; one that failed closed on a key
// it had got wrong would stop a control centre operating a grid. So no HMAC is
// computed, no key is stored, and nothing is asserted about whether an
// authentication was *valid*.
//
// What can be asserted is that the exchange took place, which on this protocol is
// the difference between a controlling station running the standard's
// authentication and one that has it switched off.
type IEC104Authentication struct {
	// Require refuses a command on an association where no authentication reply
	// (S_RP_NA_1) or aggressive-mode request (S_AS_NA_1) has been seen inside
	// Window. The refusal is hard: monitor and shadow mode do not carry it,
	// because a command forwarded so that the missing authentication could be
	// written down is a moved actuator.
	//
	// Off by default. An estate whose stations do not implement 60870-5-7 --
	// which is most of them -- would refuse every command on the first day.
	Require bool `yaml:"require"`
	// Window is how long an authentication counts for on an association.
	// Default 5m. The standard's own session keys expire, and an authentication
	// that never did would let one exchange at connection time authorise every
	// command for a week.
	Window Duration `yaml:"window"`
}

// IEC104Quality is an iec104 listener's policy about the quality descriptor a
// monitored value carries.
//
// It is an alerting policy by default and not a refusing one, because refusing
// telemetry blinds a control room -- which is its own kind of incident, and a
// worse one than a substituted value reaching a trend. `deny` exists for the
// estate that has decided otherwise about a particular bit, and it is empty
// until somebody writes it.
type IEC104Quality struct {
	// AlertOn names the quality bits worth a security event: invalid,
	// not_topical, substituted, blocked, overflow. Empty alerts on
	// substituted, which is the bit that means a person typed the value in
	// rather than an instrument measuring it -- a control centre acting on it
	// is acting on somebody's opinion of the plant, and no HMI shows it.
	AlertOn []string `yaml:"alert_on"`
	// Deny names the bits that refuse the frame carrying them. Empty, and
	// deliberately: a refusal here is a reading a control room does not get.
	// It is a soft refusal, so monitor and shadow mode carry it and say so.
	Deny []string `yaml:"deny"`
}

// IEC104Timestamps is an iec104 listener's policy about the time tag a command
// carries.
//
// This is the protocol's own replay check, and nothing in IEC 60870-5-104 makes
// anybody perform it: a time-tagged command replayed an hour later carries the
// hour-old timestamp with it, and a station that does not compare it against its
// clock executes the command again. IEC 62351-5 exists in part for this reason.
//
// The comparison is against this relay's clock, so a station whose clock is wrong
// trips it. That is a finding rather than a false positive -- an estate whose
// substations and control centre disagree about the time cannot investigate
// anything afterwards either -- and it is why the `ntp` listener kind exists.
type IEC104Timestamps struct {
	// RequireOnCommands refuses a time-tagged command type that carries no
	// readable timestamp: absent, or with fields outside their ranges. A
	// command type without a time tag at all is not affected -- C_SC_NA_1 has
	// no timestamp to require.
	RequireOnCommands bool `yaml:"require_on_commands"`
	// MaxCommandAge refuses a time-tagged command whose timestamp is older
	// than this. 0 disables the check, which is the default: a substation
	// estate with no time discipline would refuse every command on the first
	// day, and turning this on is a decision to have that discipline.
	MaxCommandAge Duration `yaml:"max_command_age"`
	// MaxCommandFuture refuses one whose timestamp is further ahead than this.
	// A command from the future is the same replay with the clocks the other
	// way round. 0 disables it.
	MaxCommandFuture Duration `yaml:"max_command_future"`
	// DenyInvalid refuses a command whose time tag carries the IV bit: the
	// controlling station has said its own clock is not to be trusted, which is
	// a thing to refuse rather than to accept silently on a command that moves
	// plant.
	DenyInvalid bool `yaml:"deny_invalid"`
}

// IEC104Measurement bounds what a station may report on a point.
//
// It is the arithmetic of `setpoints` pointed the other way: `setpoints` says how
// far a control centre may drive a point, and this says what a station may claim
// to have measured there. A pressure of 900 bar on a 40 bar transmitter is either
// a broken instrument or a forged frame, and either way it is something an
// operator should be told about rather than something that sits on a trend.
//
// The default action is alert and not deny, for the reason IEC104Quality is:
// refusing telemetry blinds a control room.
type IEC104Measurement struct {
	// Name is what an alert and a refusal call this bound. Required and
	// unique.
	Name string `yaml:"name"`
	// Points is the information object addresses this bound covers, as
	// "4711", "100-199" or "0x1000-0x1fff". Required.
	Points []string `yaml:"points"`
	// Types narrows the bound to particular monitored types by their standard
	// names (M_ME_NC_1 and so on). Empty covers every monitored type whose
	// value this relay decodes, which is usually right: a point is normally
	// reported with one encoding, and a bound covering only the encoding the
	// author thought of would be silent about the others.
	Types []string `yaml:"types"`
	// CommonAddresses narrows it to particular stations. Empty covers every
	// station this listener carries.
	CommonAddresses []string `yaml:"common_addresses"`
	// Min and Max bound the reported value, inclusive. Both required, for the
	// reason a setpoint bound needs both: a bound with one end open is a bound
	// in one direction.
	//
	// What the number means depends on the encoding, and the two that are not
	// in engineering units are worth knowing about: a normalised value is a
	// fraction of a full scale configured in the device, between -1 and just
	// under +1, and a scaled value is an integer in whatever unit the point was
	// configured with. A short float is the only one that arrives in
	// engineering units with no scale factor kept elsewhere.
	Min *float64 `yaml:"min"`
	Max *float64 `yaml:"max"`
	// Action is alert (the default: a security event and a counter, and the
	// reading goes through) or deny (the frame is refused). deny is a soft
	// refusal, so monitor and shadow mode carry it and record that they would
	// not have.
	Action string `yaml:"action"`
}

type IEC104Setpoint struct {
	// Name is what a refusal and the status view call this bound. Required
	// and unique: a decision nobody can name is one nobody can find.
	Name string `yaml:"name"`
	// Points is the information object addresses this bound covers, as
	// "4711", "100-199" or "0x1000-0x1fff". Required -- a bound over every
	// point on a substation is a bound somebody wrote without looking.
	Points []string `yaml:"points"`
	// Types narrows the bound to particular setpoint types, by their
	// standard names (C_SE_NA_1 and so on). Empty covers every setpoint
	// type, which is usually right: a point is normally commanded with one
	// encoding, and a bound that covered only the encoding the author
	// happened to think of would be silent about the others.
	Types []string `yaml:"types"`
	// CommonAddresses narrows it to particular stations. Empty covers
	// every station this listener carries.
	CommonAddresses []string `yaml:"common_addresses"`
	// Min and Max bound the value, inclusive. Both required: a bound with
	// one end open is a bound in one direction, and a setpoint driven to
	// the other end is the failure this exists to stop.
	Min *float64 `yaml:"min"`
	Max *float64 `yaml:"max"`
	// MaxDelta bounds how far one command may move the value from the last
	// one this relay saw for that point: a setpoint that may be nudged and
	// not jumped. 0 disables it.
	//
	// "The last one this relay saw" is exactly that, and it is the honest
	// limit of the check. A value changed by another control centre, by a
	// local panel, or by the process itself is not seen here -- so
	// OnUnknown says what to do about a command to a point whose value
	// this relay does not know.
	MaxDelta float64 `yaml:"max_delta"`
	// OnUnknown is what happens when MaxDelta needs a previous value and
	// this relay has none: after a restart, or before the station has
	// reported the point. allow (the default) carries the command with Min
	// and Max still in force and writes down that the delta could not be
	// checked; refuse holds it.
	//
	// It is a real choice rather than a default to accept. allow means the
	// first command after a restart is bounded by the range but not by the
	// step; refuse means a control centre cannot move the point until the
	// station has reported it, which is usually one interrogation away and
	// occasionally an outage in the middle of one.
	OnUnknown string `yaml:"on_unknown"`
}

type IEC104Rule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before
	// it decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the controlling station is in.
	Clients []string `yaml:"clients"`
	// CommonAddresses are the stations this rule covers: numbers or
	// ranges.
	CommonAddresses []string `yaml:"common_addresses"`
	// Originators are the originator addresses: which controlling
	// station, where a controlled station serves several. Numbers or
	// ranges.
	Originators []string `yaml:"originators"`
	// Types are type identifications by the standard's name
	// (C_SC_NA_1) or by number.
	Types []string `yaml:"types"`
	// Class matches what a type *does*, which is the durable way to
	// write a policy: monitoring (information travelling up), command
	// (the process commands that operate equipment), system (the system
	// commands, which include the clock and the reset), parameter or
	// file. A class outlives a standard revision that adds a type.
	Class []string `yaml:"class"`
	// Causes are causes of transmission by name (act, actcon, spont) or
	// by number. A rule that names none matches any cause, which is
	// usually wrong for a rule about commands: `act` is the control
	// centre commanding and `actcon` is the station answering.
	Causes []string `yaml:"causes"`
	// Addresses are the information object address ranges the frame may
	// name, as "0-65535" or single numbers. A frame naming an address
	// outside all of them does not match. On a sequence only the first
	// address is on the wire, and that is the one checked -- which the
	// documentation says plainly, because it is a real limit.
	Addresses []string `yaml:"addresses"`
	// MaxObjects bounds the information objects one ASDU may carry. 0
	// leaves the protocol's own bound of 127.
	MaxObjects int `yaml:"max_objects"`
	// Select restricts the rule by the select bit: "select" matches only
	// the first half of a two-step command, "execute" only the second,
	// and empty matches either. It is how "this client may select
	// anything and execute nothing" is written -- a four-eyes control
	// where one operator arms and another fires.
	Select string `yaml:"select"`
	// Schedule limits the rule to a time window. The shape is the same
	// as a Modbus rule's, because "during the day shift" does not change
	// with the protocol.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// ModbusRoute sends a range of unit identifiers to one pool.
type ModbusRoute struct {
	// Name identifies the route in the logs and the counters.
	Name string `yaml:"name"`
	// Units are the unit identifiers this route claims: numbers or
	// "1-16" ranges. Required.
	Units []string `yaml:"units"`
	// Upstream is the pool they go to. Required.
	Upstream string `yaml:"upstream"`
	// Framing overrides the listener's upstream framing for this route,
	// which is how one listener fronts a TCP PLC and a serial device
	// behind a terminal server at once.
	Framing string `yaml:"framing"`
	// UnitOverride rewrites the unit identifier sent to the device.
	// A gateway that presents unit 5 and speaks to a device that
	// answers only to unit 1 needs it; 0 leaves the identifier alone.
	UnitOverride *int `yaml:"unit_override"`
}

// ModbusSecurity is the Modbus/TCP Security policy (MB-TCP-Security
// v21): TLS with mutual authentication, and authorisation by the role
// the client certificate carries.
type ModbusSecurity struct {
	// Mode is off (the default), allow (a role is read when the client
	// presents one and rules that name a role only match then) or
	// require (a client with no usable role is refused). require is
	// what the specification describes; allow is the migration.
	Mode string `yaml:"mode"`
	// RoleSource is extension (the default: the x.509 extension under
	// the Modbus arc, 1.3.6.1.4.1.50316.802.1, which is what the
	// specification defines), cn or ou. The subject fields are a
	// documented compromise for an authority that cannot issue the
	// extension yet: a subject field says who a certificate is for, so
	// using it as a role means trusting whoever issues certificates to
	// keep to a naming convention.
	RoleSource string `yaml:"role_source"`
	// Roles is the allow list of role names. Empty accepts any role the
	// rules name.
	Roles []string `yaml:"roles"`
	// RequireClientCert refuses a connection that presents no client
	// certificate. Default true when mode is require.
	RequireClientCert *bool `yaml:"require_client_cert"`
}

// IEC104Redundancy declares the redundancy groups of edition 2 of
// IEC 60870-5-104.
//
// A control centre reaches a substation over several connections -- different
// routers, different bearers -- and the standard calls that set a redundancy
// group: exactly one of them carries data at a time, and the controlling
// station moves data transfer with STARTDT when a path fails.
//
// Declaring it here buys two things. A frame from a connection in the group
// that does not hold data transfer is refused before it reaches the station,
// so a second connection from the control centre's own network cannot
// command anything while it is standby. And a selection can survive the
// failover, so a two-step command whose select and execute land either side
// of one is not refused -- which is what makes require_select survivable in
// a control room.
type IEC104Redundancy struct {
	// Groups are the connection groups. No groups means no redundancy
	// handling, which is how every listener written before this behaves.
	Groups []IEC104RedundancyGroup `yaml:"groups"`
}

// IEC104RedundancyGroup is one set of connections that are one controlling
// station.
type IEC104RedundancyGroup struct {
	// Name identifies the group in the logs, the counters and the status
	// view. Required.
	Name string `yaml:"name"`
	// Clients are the networks whose connections belong to this group.
	// Required: the client list is what says which connections are one
	// controlling station, and a group without one would claim every client
	// on the listener is the same peer.
	Clients []string `yaml:"clients"`
	// MaxConnections bounds the connections the group may hold at once.
	// Default 4; 1 to 8. A redundancy group is two or three paths, so a
	// number well past that is a client list that has caught something it
	// should not, and the connection past the bound is refused rather than
	// admitted into a set the operator described as three paths.
	MaxConnections int `yaml:"max_connections"`
	// Takeover is what happens when a connection asks for data transfer
	// while another connection in the group holds it: switch (the default,
	// which is what a failover is) or refuse. refuse is for the estate
	// where the paths are moved deliberately and a concurrent takeover
	// means something is wrong.
	Takeover string `yaml:"takeover"`
	// CarrySelects keeps a selection across a failover inside this group,
	// so a select on one path and the execute on another is one two-step
	// command. Default true -- it is most of the reason to declare a group.
	//
	// What it trusts is the client list: any address in it can consume a
	// selection another connection made. What bounds that is the group's
	// own rule that only the connection holding data transfer may send
	// anything, so taking over a live selection means winning a STARTDT
	// first -- which is a logged failover, and refusable with
	// takeover: refuse.
	CarrySelects *bool `yaml:"carry_selects"`
}

// ModbusRule decides frames. Every selector that is set must match, and
// a rule with no selectors matches everything -- which is how the last
// rule in a list is written.
type ModbusRule struct {
	// Name identifies the rule in the logs, the counters and the
	// learning report. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts the
	// frame and then keeps looking, which is how a rule is tried out on
	// live traffic before it decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the master is in.
	Clients []string `yaml:"clients"`
	// Roles are the Modbus/TCP Security roles this rule covers. A rule
	// naming a role never matches a session that has none.
	Roles []string `yaml:"roles"`
	// Units are the unit identifiers: numbers or ranges.
	Units []string `yaml:"units"`
	// Functions are function codes by name (read_holding_registers) or
	// by number.
	Functions []string `yaml:"functions"`
	// Access matches what the function code does: read, write,
	// diagnostic, identify or vendor. It is the durable way to write
	// "no writing" without listing every code that writes.
	Access []string `yaml:"access"`
	// Diagnostics are the sub-functions of function code 8 this rule
	// covers, by name (force_listen_only, clear_counters,
	// return_bus_message_count) or by number. A rule naming them matches
	// only a diagnostic request, which is what lets "the counters yes,
	// listen-only mode never" be written at all.
	Diagnostics []string `yaml:"diagnostics"`
	// UMASCommands are the Schneider UMAS commands of function code 90
	// this rule covers, by name (stop_plc, upload_block, read_variables)
	// or by number. A rule naming them matches only a UMAS request.
	UMASCommands []string `yaml:"umas_commands"`
	// Effects match what the sub-function does, whichever function code
	// carried it: read, write, control (stop, start, restart,
	// listen-only), program (a control program in either direction),
	// clear (counters and the event log), session, or unknown (a
	// sub-function this relay cannot read, and the CANopen tunnel). It is
	// the durable way to write "nothing that stops a PLC", and a rule
	// naming it matches only a frame that has a sub-function.
	Effects []string `yaml:"effects"`
	// Addresses are the register or coil ranges the request may name,
	// as "0-999" or single numbers. A request whose range is not
	// entirely inside one of them does not match.
	Addresses []string `yaml:"addresses"`
	// WriteAddresses apply to the write half of function code 23 and to
	// every writing function code when set, so one rule can allow a
	// wide read and a narrow write.
	WriteAddresses []string `yaml:"write_addresses"`
	// MaxQuantity bounds the registers or coils one request may name.
	// 0 leaves the protocol's own bound.
	MaxQuantity int `yaml:"max_quantity"`
	// Values bound what may be written, which is the deep inspection a
	// plant actually needs: a setpoint register that may hold 0 to 100
	// and nothing else.
	Values []ModbusValueRule `yaml:"values"`
	// Schedule limits the rule to a time window. A rule with no
	// schedule is always in force, so "these rules during the shift and
	// those outside it" is written as scheduled rules first and
	// unscheduled ones after them.
	Schedule *ModbusSchedule `yaml:"schedule"`
	// Comment is carried into the logs when the rule decides, for the
	// change record a plant keeps.
	Comment string `yaml:"comment"`
}

// ModbusValueRule bounds the values a write may carry.
type ModbusValueRule struct {
	// Registers is the address range this bound applies to, as "400-499"
	// or a single address. Empty applies it to every address the rule
	// covers.
	Registers string `yaml:"registers"`
	// Min and Max bound each 16-bit value written into that range,
	// inclusive. Both are required.
	Min *int `yaml:"min"`
	Max *int `yaml:"max"`
	// Signed reads the value as a signed 16-bit integer, which is how
	// most setpoints are actually encoded.
	Signed bool `yaml:"signed"`
	// Coils, when set, bounds a coil write instead: true allows setting
	// a coil in the range, false allows only clearing it.
	Coils *bool `yaml:"coils"`
	// MaxDelta bounds how far one write may move the value from the last
	// one this relay saw at that address: a setpoint that may be nudged
	// but not jumped. 0 disables it.
	//
	// "The last one this relay saw" is exactly that, and it is the honest
	// limit of the check: a value changed by another master, by a local
	// panel or by the process itself is not seen here, so OnUnknown says
	// what to do about a write to an address whose value this relay does
	// not know.
	MaxDelta int `yaml:"max_delta"`
	// Transitions are the value changes permitted, as "from->to" pairs
	// with numbers or "*" on either side: ["0->1", "1->0"] is a state
	// register that may be started and stopped but not driven to any
	// other state. Empty permits every change the other bounds allow.
	Transitions []string `yaml:"transitions"`
	// Rate bounds how often this range may be written.
	Rate *ModbusValueRate `yaml:"rate"`
	// RequireBefore is select-before-operate: this write is refused
	// unless another register was set to a given value first, recently.
	// It is how a two-step confirmation is enforced by the relay rather
	// than hoped for in the client.
	RequireBefore *ModbusPrecondition `yaml:"require_before"`
	// OnUnknown is what happens when a check needs the address's current
	// value and this relay has not seen one -- after a restart, or before
	// any master has read it: allow (the default, with a counter and an
	// event, leaving the absolute Min and Max bounds in force) or refuse.
	//
	// It is a real choice. allow means a write straight after a restart
	// is bounded by the range but not by the delta or the transition
	// list; refuse means a plant cannot be driven until something has
	// read the register, which for a relay in front of a running process
	// is usually a poll away and occasionally an outage.
	OnUnknown string `yaml:"on_unknown"`
}

// ModbusValueRate bounds how often a range of addresses may be written.
//
// It is not the listener's rate limit, which is about frames from a
// client. This is about one address: "the setpoint may be moved once a
// minute" is a statement about the process, and a master that moves it
// sixty times a minute is either broken or not the master it claims to
// be -- in both cases the device should not see the writes.
type ModbusValueRate struct {
	// Max is how many writes are allowed per Period, counted per unit
	// identifier and address. Required.
	Max int `yaml:"max"`
	// Period is the window. Required, 1s..24h.
	Period Duration `yaml:"period"`
	// PerClient counts each master's writes separately rather than
	// counting every write to the address together. Default false: the
	// bound is usually about the device, not about who is asking.
	PerClient bool `yaml:"per_client"`
}

// ModbusPrecondition is select-before-operate: a write this rule covers
// is refused unless another register was recently set to a given value.
//
// The pattern exists because the dangerous operations in a plant are the
// ones where a single frame does something physical. IEC 60870-5-104 has
// it in the protocol; Modbus does not, so a plant that wants it either
// implements it in every client or has the relay enforce it -- and a
// client-side confirmation is not a control at all, because the frame
// that skips it looks exactly like the frame that did not.
type ModbusPrecondition struct {
	// Registers is the address that has to have been written, as a
	// single address or a range. Required.
	Registers string `yaml:"registers"`
	// Equals is the value it has to have been given. Required.
	Equals int `yaml:"equals"`
	// Within is how long the select stays good. Default 30s: long enough
	// for an operator to confirm, short enough that a select left behind
	// yesterday does not arm a write today.
	Within Duration `yaml:"within"`
	// Unit is the unit identifier the select was written to, when it is
	// not the unit this write is for.
	Unit *int `yaml:"unit"`
}

// ModbusSchedule is when a rule is in force. The times are local to the
// named zone, so a shift that starts at six starts at six whatever the
// host's clock is set to.
type ModbusSchedule struct {
	// Days are mon, tue, wed, thu, fri, sat, sun. Empty means every
	// day.
	Days []string `yaml:"days"`
	// From and To are "HH:MM" in Timezone. A window whose To is before
	// its From spans midnight, which is how a night shift is written.
	From string `yaml:"from"`
	To   string `yaml:"to"`
	// Timezone is an IANA name. Default UTC, because a schedule in the
	// host's local time is a schedule that moves when somebody fixes
	// the host's time zone.
	Timezone string `yaml:"timezone"`
}

// ModbusLearn records what crosses the listener and writes it out as a
// rule set to start from.
//
// It exists because nobody knows what a plant's Modbus traffic actually
// is. The drawings say what it was meant to be; the traffic says what
// the integrator left behind. Run this for a week and the file is the
// answer, written as rules that can be pasted in.
type ModbusLearn struct {
	// Enabled turns the recording on.
	Enabled bool `yaml:"enabled"`
	// File is where the report is written, as YAML. Required when
	// enabled.
	File string `yaml:"file"`
	// Interval is how often it is rewritten. Default 5m; it is also
	// written when the listener shuts down.
	Interval Duration `yaml:"interval"`
	// MaxSubjects bounds the observations held: one per client, role,
	// unit and function code seen. Default 8192; past it the oldest is
	// dropped and the drops are counted, because a learning run that
	// quietly stopped learning is worse than one that says so.
	MaxSubjects int `yaml:"max_subjects"`
	// Enforce keeps the policy in force while learning. Default false:
	// a learning run is normally observe-only, and saying so here is
	// what stops one being left on by accident.
	Enforce bool `yaml:"enforce"`
}

// DefaultModbusWriteBurst is the write burst applied when the key is
// unset: twenty writes in ten seconds across every address. It lives here
// rather than in the kind because validation has to know whether the burst
// is on in order to refuse a detector with nothing to detect, and a number
// kept in two places is a number that drifts.
const DefaultModbusWriteBurst = 20

// ModbusAnomaly is behavioural detection: what a master has been doing,
// and when it stops.
//
// The rules answer "is this permitted", from what somebody wrote down.
// This answers "is this what this master has been doing", and answers it
// without anybody having written anything. Control traffic is repetitive
// in a way other traffic is not -- a master's scan cycle is the same few
// function codes over the same few address ranges, every cycle, for
// years -- so "this client has never done this before" is a signal here
// where elsewhere it would be noise.
//
// It alerts. A detector built on "I have not seen this before" refuses
// the first legitimate thing anybody does after a quiet year, so the
// default is an event and a counter, the events do not reach the ban
// ladder, and `action: deny` is there for the plants that want it.
type ModbusAnomaly struct {
	// Enabled turns the detection on.
	Enabled bool `yaml:"enabled"`
	// Settle is how long a client's traffic is recorded before anything
	// about novelty is reported for it. Default 10m, because when the
	// relay starts everything is new and a master's first minutes are its
	// startup rather than its work. The write burst is not suppressed
	// during it: that bound is a number set here rather than something
	// learned, and a burst while settling is still a burst.
	//
	// A pointer so that 0s means no settling at all rather than the
	// default: on a relay that has been running for months and was
	// restarted in place there is an argument for reporting from the first
	// frame, and an operator who writes 0s should get what they wrote.
	Settle *Duration `yaml:"settle"`
	// NewFunction reports a function code this client has not used.
	// Default true.
	NewFunction *bool `yaml:"new_function"`
	// NewWriteAddress reports a write to an address this client has not
	// written. Default true.
	NewWriteAddress *bool `yaml:"new_write_address"`
	// WriteBurst and BurstPeriod bound one client's writes across every
	// address: default 20 in 10s. It is not the per-address rate of a
	// value rule, and the difference is the point -- a rate of "this
	// setpoint may move once a minute" does not notice a master that
	// wrote forty different registers once each, which is the shape of
	// somebody walking the address space. 0 disables it.
	//
	// A pointer for the same reason `settle` is one: 0 means off, and an
	// unset key means the default. Read as a plain int, `write_burst: 0`
	// silently kept the default of twenty, so a listener configured with
	// the burst turned off went on reporting bursts.
	WriteBurst  *int     `yaml:"write_burst"`
	BurstPeriod Duration `yaml:"burst_period"`
	// Action is alert (the default) or deny. deny refuses the request the
	// detection fired on, which on a signal derived from novelty means
	// refusing a maintenance write nobody has made before. It is a real
	// choice and not a default.
	//
	// It refuses the *first* occurrence and records it, so a retry goes
	// through. That is deliberate: refusing every occurrence until
	// somebody intervened would mean a plant that could not be driven
	// after any novelty, with nothing here to do the intervening. deny
	// buys a hard stop on the first attempt and an operator's attention.
	// It is not a block, and the rules are what block.
	Action string `yaml:"action"`
	// MaxClients bounds the masters remembered. Default 1024; past it
	// the drops are counted rather than silent.
	MaxClients int `yaml:"max_clients"`
}

// ModbusDeception answers as a device that is not there.
//
// A refusal is information. A relay that answers "gateway path
// unavailable" for every unit identifier nothing is behind is doing
// exactly what the specification says, and a sweep of 1 to 247 therefore
// draws the map: which units exist, and by the same argument which
// function codes the policy permits. The scan is refused and the survey
// completes.
//
// This answers instead, from a fabricated device whose values are stable
// per address and move slowly with time, so the crawl finishes and the map
// is wrong.
//
// **On a plant floor the failure mode of this tool is not a confused
// scanner.** It is an operator reading a fabricated tank level off an HMI
// and acting on it. So one rule holds, and it is tested rather than
// intended: a frame the policy allowed is never deceived -- deception
// replaces a refusal and never an answer. In mode answer, where there are
// real devices behind the listener, clients is required: a section that
// would lie to anybody who connects is not something to arrive at by
// leaving a field out.
type ModbusDeception struct {
	// Enabled turns the section off without removing it; it defaults to
	// true wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a frame this listener was going to
	// refuse is answered by the fabricated device instead) or decoy (the
	// whole listener is the fabricated device and no frame reaches
	// anything -- this is a honeypot, and it needs no upstream).
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client, which is
	// what a honeypot wants, since nothing real is behind it.
	Clients []string `yaml:"clients"`
	// Profile is the fabricated device's shape: generic-plc (the
	// default), generic-rtu or generic-meter. It decides which function
	// codes the device implements and how its address ranges behave.
	Profile string `yaml:"profile"`
	// Vendor, Product, Revision and Serial are what the device says about
	// itself, in the server identity of function code 17 and the device
	// identification of 43/14 -- which is what a scanner fingerprints on.
	// The defaults are deliberately generic: **a decoy should claim the
	// make of device the plant actually runs**, and only the operator
	// knows what that is. A Schneider identity on a Rockwell site is the
	// tell that ends the pretence.
	Vendor   string `yaml:"vendor"`
	Product  string `yaml:"product"`
	Revision string `yaml:"revision"`
	Serial   string `yaml:"serial"`
	// Units are the unit identifiers the fabricated device answers for,
	// as numbers or "1-8" ranges. Default "1". Everything outside it is
	// answered the way a real gateway answers an address nothing is
	// behind, because a decoy that answers for all 247 units is a decoy:
	// no gateway has 247 devices on it.
	Units []string `yaml:"units"`
	// Functions are the function codes the fabricated device implements,
	// by name or number. Empty takes the profile's list. A code outside
	// it is answered with an illegal-function exception, which is what the
	// real device would say -- a decoy that implements everything is
	// answering for a PLC nobody makes.
	Functions []string `yaml:"functions"`
	// Bands describe how the address space behaves. Empty takes the
	// profile's.
	Bands []ModbusDecoyBand `yaml:"bands"`
	// Tripwire are register or coil addresses no legitimate master has a
	// reason to touch. Reading one is not refused -- it is answered, and
	// raised as a security event, because the answer is what keeps the
	// visitor reading and the event is what an operator acts on.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated values reproducible. Zero derives one
	// from the listener name, which is stable across restarts: a decoy
	// whose serial number changes when the proxy is upgraded is a decoy
	// somebody has noticed.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a value lasts. Default 30s: slow
	// enough that reading an address twice gives the same answer, fast
	// enough that a trend moves.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default
	// 1024.
	MaxClients int `yaml:"max_clients"`
}

// ModbusDecoyBand is how one run of addresses behaves.
type ModbusDecoyBand struct {
	// Addresses is the run this band covers, as "0-999".
	Addresses string `yaml:"addresses"`
	// Shape is analogue (a measurement inside min..max that drifts),
	// discrete (a bit that mostly stays where it is) or counter (a
	// totaliser that only increases). A totaliser that goes backwards is
	// the tell that ends the pretence, so counter is monotone by
	// construction.
	Shape string `yaml:"shape"`
	// Min and Max bound an analogue band. Default 0..27648, which is the
	// range a scaled analogue input reports on much of the installed base.
	Min int `yaml:"min"`
	Max int `yaml:"max"`
	// Rate is how much a counter adds each period.
	Rate int `yaml:"rate"`
}

// ModbusTrace writes one line per frame.
type ModbusTrace struct {
	// File is the trace file, one JSON object per line. Required.
	File string `yaml:"file"`
	// MaxBytes bounds it. Default 104857600 (100 MiB); at the bound the
	// trace stops and says so rather than filling the disk a plant's
	// historian is also on.
	MaxBytes int64 `yaml:"max_bytes"`
	// IncludeData writes the frame's data bytes as hex. Off by default:
	// a trace is usually about who asked for what, and the data is
	// process data.
	IncludeData bool `yaml:"include_data"`
	// Requests and Responses select the directions traced. Default
	// both.
	Requests  *bool `yaml:"requests"`
	Responses *bool `yaml:"responses"`
}

// Advice reports whether this listener's frames are logged at all.
func (m *ModbusListener) Logs() bool { return m != nil && m.LogFrames }

// Alerts says whether a refusal writes a security event.
func (m *ModbusListener) Alerts() bool {
	return m == nil || m.AlertOnDeny == nil || *m.AlertOnDeny
}

// Pending is the outstanding-request bound, with the default that
// depends on the framing: a serial framing has no transaction
// identifier, so a second request in flight cannot be told from the
// first.
func (m *ModbusListener) Pending() int {
	if m == nil {
		return 1
	}
	if m.MaxPending > 0 {
		return m.MaxPending
	}
	if m.Framing == "rtu" || m.Framing == "ascii" {
		return 1
	}
	return 16
}

// NTPListener is an NTP and NTS security gateway.
//
// A time packet is small, has no session, carries no identity and is
// believed absolutely: the device on the other side will step its clock
// to whatever it is told, and a clock is what every certificate, every
// log line and every ordering of events in a plant depends on. So the
// three jobs on this port are kept apart deliberately:
//
//   - forwarding time packets, which is what this listener does;
//   - authenticating them, which belongs to whoever holds the key --
//     symmetric keys this listener can check, NTS it deliberately cannot;
//   - keeping an accurate clock, which is the local time daemon's job.
//     A relay that tried to be a time source would be one nobody
//     calibrated.
//
// What it can do that a client cannot is compare. It sees every server
// the estate has, measures each the same way, and refuses to pass on an
// answer from one that disagrees with its peers or says not to trust it.
//
// It works in both directions. A *reverse* listener fronts the estate's
// own time servers: the devices point at it and it forwards to them,
// which is where the allow lists, the version profile and the audit trail
// live. A *forward* listener is the controlled egress towards servers
// somewhere else, where `allow_servers` bounds the destinations and the
// quality rules are the estate's protection against what the internet
// answers.
type NTPListener struct {
	// Mode is reverse (the default: clients here, servers upstream) or
	// forward (this listener is the estate's egress to servers
	// elsewhere).
	Mode string `yaml:"mode"`
	// Upstream is the pool of time servers. Required.
	Upstream string `yaml:"upstream"`
	// Versions are the protocol versions accepted, as numbers. Default
	// 4 and 3: version 4 is the protocol, version 3 is the legacy
	// profile a plant still has devices on. Versions 1 and 2 are only
	// accepted when they are named, because a version 1 packet has no
	// mode field and accepting one by default would be guessing what it
	// is.
	Versions []int `yaml:"versions"`
	// Modes are the association modes accepted: client, server,
	// symmetric_active, symmetric_passive, broadcast. Default client
	// and server. The symmetric modes and broadcast are relationships
	// rather than requests and are only ever between named peers.
	// Modes 6 (control) and 7 (private, which monlist belongs to) are
	// always refused and cannot be named.
	Modes []string `yaml:"modes"`
	// AllowVersion5 forwards NTPv5 packets as opaque bytes, on a
	// transaction socket of its own. It is off by default: version 5 is
	// experimental and its packet format is not version 4's, so it is
	// never parsed with the version 4 parser.
	AllowVersion5 bool `yaml:"allow_version5"`
	// Peers are the networks a symmetric or broadcast association may
	// come from. A symmetric association is a relationship in which each
	// end accepts the other's time, so it is never open to whoever asks.
	Peers []string `yaml:"peers"`
	// AllowManycast opts into manycast discovery, whose responders are
	// the addresses this listener will accept an answer from. It is a
	// separate switch from broadcast because it is a separate
	// mechanism: bounded discovery rather than an unsolicited stream.
	AllowManycast      bool     `yaml:"allow_manycast"`
	ManycastResponders []string `yaml:"manycast_responders"`
	// AllowClients and DenyClients are the networks a client may ask
	// from. Deny is evaluated first. An empty allow list allows every
	// client the deny list does not refuse, which validation advises
	// against: an open NTP port is an amplifier.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// AllowServers bounds the addresses this listener will send to,
	// whatever the pool resolves to. It is the egress policy: a pool
	// whose name starts resolving somewhere new does not quietly become
	// a new destination, and an NTS key exchange that names another
	// server cannot move the time traffic outside this list.
	AllowServers []string `yaml:"allow_servers"`
	// Auth is symmetric authentication: the pre-shared keys and whether
	// a packet without one is refused.
	Auth *NTPAuth `yaml:"auth"`
	// NTS is how Network Time Security is handled.
	NTS *NTPNTS `yaml:"nts"`
	// Extensions bounds the extension fields a packet may carry.
	Extensions *NTPExtensions `yaml:"extensions"`
	// Quality is what the listener requires of a server's answer, and
	// how it compares the servers with each other.
	Quality *NTPQuality `yaml:"quality"`
	// Holdover bounds how long a server whose time cannot be verified
	// is still used.
	Holdover *NTPHoldover `yaml:"holdover"`
	// ChangeDetection watches each server for a change in what it is
	// rather than in what it answered: a new time source, a stratum that
	// jumped, an offset that stepped, a dispersion that exploded, NTS
	// that stopped, a leap second announced out of season.
	ChangeDetection *NTPChangeDetection `yaml:"change_detection"`
	// KoD is the kiss-o'-death policy: the protocol's own way of saying
	// "not now".
	KoD *NTPKoD `yaml:"kod"`
	// Interleaved accepts interleaved mode, where a server's answer
	// echoes its own previous transmit timestamp rather than the
	// client's. Default true: it is how a server gives a client a
	// hardware-quality transmit timestamp, and a relay that refused it
	// would be refusing the most accurate exchange there is.
	Interleaved *bool `yaml:"interleaved"`
	// Learn records what actually asks this listener for the time and
	// writes it out as an allow list, a version profile and a mode
	// profile.
	Learn *NTPLearn `yaml:"learn"`
	// Trace writes one line per packet for as long as it is enabled.
	Trace *NTPTrace `yaml:"trace"`
	// MaxPacketBytes bounds one packet. Default 1280. A time packet is
	// 48 octets plus its extension fields; NTS makes it a few hundred.
	MaxPacketBytes int `yaml:"max_packet_bytes"`
	// MaxExtensions bounds the extension fields in one packet. Default
	// 8.
	MaxExtensions int `yaml:"max_extensions"`
	// MaxAssociations bounds the client associations held. Default
	// 16384. An association is a client address and port, so the bound
	// is also what stops a flood of forged sources filling the table.
	MaxAssociations int `yaml:"max_associations"`
	// MaxOutstanding bounds the requests waiting for an answer, which is
	// a separate table from the associations on purpose: a client may
	// have several in flight, and an answer may arrive after its
	// association moved to another server.
	MaxOutstanding int `yaml:"max_outstanding"`
	// IdleTimeout forgets an association that has said nothing. Default
	// 30m, which is longer than any sane poll interval.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// RequestTimeout is how long a server has to answer. Default 3s.
	RequestTimeout Duration `yaml:"request_timeout"`
	// RateLimit and RateBurst bound packets a second from one client
	// address; PrefixRateLimit and PrefixRateBurst do the same for a
	// network, because a subnet asking in unison is one problem rather
	// than many. RatePrefixLength is the network they are counted by:
	// default /24 for IPv4 and /56 for IPv6.
	RateLimit        int `yaml:"rate_limit"`
	RateBurst        int `yaml:"rate_burst"`
	PrefixRateLimit  int `yaml:"prefix_rate_limit"`
	PrefixRateBurst  int `yaml:"prefix_rate_burst"`
	RatePrefixLength int `yaml:"rate_prefix_length"`
	// LogPackets writes an access line per packet rather than per
	// association. It is the record an estate asked to show who asked
	// for the time and what they were told, and it is a line per poll.
	LogPackets bool `yaml:"log_packets"`
	// AlertOnDeny writes a security event for every refusal. Default
	// true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
}

// NTPAuth is symmetric authentication with pre-shared keys.
//
// RFC 8573 makes AES-CMAC the algorithm: the older construction is MD5
// over the key followed by the packet, which is a length-extension shape
// with a broken hash in it. The legacy algorithms are therefore an
// explicit exception rather than a default, because a device from 2006
// cannot be taught a new one and pretending otherwise ends with no
// authentication at all rather than weak authentication somebody knows
// about. Autokey (RFC 5906) is not implemented and will not be.
type NTPAuth struct {
	// Require refuses a packet that carries no authentication this
	// listener can check. NTS counts as authentication for this
	// purpose -- and the listener says plainly that it has not verified
	// it, because only the party holding the key can.
	Require bool `yaml:"require"`
	// AllowLegacyAlgorithms accepts a key whose algorithm is md5 or
	// sha1. It warns.
	AllowLegacyAlgorithms bool `yaml:"allow_legacy_algorithms"`
	// ProbeKeyID is the key the listener signs its own monitoring
	// probes with, for a server that requires authentication.
	ProbeKeyID int `yaml:"probe_key_id"`
	// Keys are the shared keys, by identifier.
	Keys []NTPKey `yaml:"keys"`
}

// NTPKey is one pre-shared key.
type NTPKey struct {
	// ID is the key identifier the packet carries: 1 to 65535.
	ID int `yaml:"id"`
	// Algorithm is aes-cmac (the default), md5 or sha1.
	Algorithm string `yaml:"algorithm"`
	// KeyFile holds the key, as hexadecimal or as the ASCII a
	// ntp.keys file uses. Owner-readable only.
	KeyFile string `yaml:"key_file"`
}

// NTPNTS is how Network Time Security is handled.
//
// The time exchanges are UDP 123 with authentication in extension
// fields; the key establishment is TLS on TCP 4460 with the ALPN
// "ntske/1", and it is a listener of its own (kind: ntske). This section
// is about the time side.
type NTPNTS struct {
	// Mode is passthrough (the default), terminate or off.
	//
	// Pass-through forwards NTS-protected packets whole and unaltered,
	// which is the only honest thing a relay that does not hold the keys
	// can do with them: the authentication is between the client and the
	// server, and every visible NTS field is readable by anybody on the
	// path and proves nothing.
	//
	// Terminate verifies them. The relay holds the keys, because the
	// kind: ntske listener named by key_listener issued the cookie the
	// packet carries: it opens the cookie, verifies the authenticator
	// over the whole packet, and only then asks the time source --
	// which does not have to speak NTS at all. The answer is built
	// here and authenticated with the client's own server-to-client
	// key, with replacement cookies sealed inside it. This is the mode
	// that puts NTS in front of a time server that cannot do it, and
	// it is the mode in which "authenticated" means this relay checked.
	//
	// Off refuses NTS-protected packets outright.
	Mode string `yaml:"mode"`
	// Require refuses a packet that carries no NTS fields. It is how a
	// listener says "this estate is NTS only", and it is the setting
	// that makes the no-downgrade rule visible: an answer that arrives
	// without NTS fields for a request that had them is refused, never
	// passed on as plain NTP.
	Require bool `yaml:"require"`
	// KeyListener is the kind: ntske listener whose cookie keys this
	// listener opens cookies with. It is required with mode:
	// terminate and means nothing otherwise: the two halves of NTS are
	// two listeners on two ports, and termination only works when the
	// one holding the keys is named by the one spending them.
	KeyListener string `yaml:"key_listener"`
	// Source makes the relay hold its own NTS association with the time
	// source: its own key establishment, its own cookies, its own
	// authenticator on every request it sends, and verification of every
	// answer.
	//
	// It goes with mode: terminate, because the two are the same
	// decision seen from either side. Terminating means the client's
	// authentication ends here; this says what happens on the other
	// side of that. Without it the relay asks the source in plain NTP,
	// which is right when the source cannot do better and a choice an
	// estate should make deliberately when it can.
	Source *NTPSourceNTS `yaml:"source"`
}

// NTPSourceNTS is the relay's own NTS association with the time source.
//
// The cost of this is worth being plain about: there is no end-to-end
// authentication between the client and the time source any more. The
// client authenticates to this relay and this relay authenticates to the
// source, so the process is a party to the security rather than a reader
// of it. What it buys is a relay that can compare, police and log what
// the source says while both halves are still authenticated -- which a
// pass-through relay cannot do at all.
type NTPSourceNTS struct {
	// KEAddress is the source's key establishment server, host:port. A
	// bare host takes port 4460. Required.
	//
	// It is configured rather than discovered: the time servers are the
	// upstream pool, and a key establishment server that named a
	// different one would be moving the estate's time traffic. This
	// relay reports such a record and does not follow it.
	KEAddress string `yaml:"ke_address"`
	// ServerName is the name to verify in the source's certificate,
	// when it is not the host in ke_address.
	ServerName string `yaml:"server_name"`
	// CAFile pins the authorities that may have issued it. Empty uses
	// the system trust store, which on a plant network is usually not
	// what an operator means.
	CAFile string `yaml:"ca_file"`
	// CertFile and KeyFile are a client certificate, for a source that
	// asks for one. NTS-KE says nothing about the client, so this is
	// the only thing that can name this relay to the source.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// RefreshBelow re-establishes keys when fewer than this many
	// cookies are left. Default 2. A cookie is spent per exchange and
	// one comes back, so the pool only shrinks when answers are lost --
	// and a relay that ran out would stop asking for the time.
	RefreshBelow int `yaml:"refresh_below"`
	// Timeout bounds one key establishment. Default 10s.
	Timeout Duration `yaml:"timeout"`
}

// SourceRefreshBelow is when to establish keys again.
func (n *NTPSourceNTS) SourceRefreshBelow() int {
	if n == nil || n.RefreshBelow <= 0 {
		return DefaultNTSRefreshBelow
	}
	return n.RefreshBelow
}

// DefaultNTSRefreshBelow is the cookie count that triggers a fresh key
// establishment with the source.
const DefaultNTSRefreshBelow = 2

// NTPExtensions bounds the extension fields a packet may carry.
type NTPExtensions struct {
	// AllowUnknown forwards a field whose type this relay does not
	// know. Off by default: a relay cannot decide about an instruction
	// it cannot read, and that includes every field Autokey defined.
	AllowUnknown bool `yaml:"allow_unknown"`
	// RefuseAmbiguousMAC refuses a packet whose tail is both a valid
	// MAC and a valid extension field -- the ambiguity RFC 7822
	// documents and cannot remove. Default true: a packet whose meaning
	// depends on which reading the receiver picks is a packet two
	// implementations will disagree about.
	RefuseAmbiguousMAC *bool `yaml:"refuse_ambiguous_mac"`
	// Max is the number of fields one packet may carry. Default 8.
	Max int `yaml:"max"`
}

// NTPQuality is what the listener requires of a server's answer, and how
// it compares the servers with each other.
//
// Every bound here is about *responses*. A client's request carries a
// stratum, a root delay and a root dispersion too, and they mean nothing
// -- the protocol does not ask a client to fill them in -- so a listener
// that applied these to requests would be refusing clients for empty
// fields.
type NTPQuality struct {
	// CompareSources runs the monitor: the listener sends its own
	// probes to every server, measures each the same way, and compares
	// them. Default true, because a server that is reachable,
	// synchronised, authenticated and wrong is the case every other
	// check passes.
	CompareSources *bool `yaml:"compare_sources"`
	// ProbeInterval is how often each server is measured. Default 64s,
	// which is an ordinary poll interval.
	ProbeInterval Duration `yaml:"probe_interval"`
	// MaxDisagreement is how far apart two sources may be before the
	// listener says so. Default 100ms.
	MaxDisagreement Duration `yaml:"max_disagreement"`
	// MaxOffset and MaxDelay refuse an answer whose measured offset or
	// round trip is past them. 0 disables each.
	MaxOffset Duration `yaml:"max_offset"`
	MaxDelay  Duration `yaml:"max_delay"`
	// MaxRootDelay and MaxRootDispersion refuse an answer whose own
	// statement of its error is past them: the server's uncertainty,
	// as the server reports it.
	MaxRootDelay      Duration `yaml:"max_root_delay"`
	MaxRootDispersion Duration `yaml:"max_root_dispersion"`
	// MaxStratum refuses an answer from too far down the tree. 0 leaves
	// the protocol's own bound of 15.
	MaxStratum int `yaml:"max_stratum"`
	// AllowStrata is the exhaustive list of strata accepted, for an
	// estate that knows exactly what its time tree looks like: [1, 2]
	// says the servers are a reference clock and its immediate clients
	// and nothing else may answer. Empty leaves max_stratum to decide.
	AllowStrata []int `yaml:"allow_strata"`
	// MaxRootDistance refuses an answer whose synchronisation distance
	// -- half the root delay plus the root dispersion, RFC 5905's own
	// measure -- is past it. It is the bound that cannot be satisfied by
	// reporting a small delay and a large dispersion or the other way
	// about. 0 disables it.
	MaxRootDistance Duration `yaml:"max_root_distance"`
	// RefuseBogusTimestamps refuses an answer whose four timestamps
	// cannot describe an exchange: a zero transmit or receive
	// timestamp, an answer sent before the request arrived, a last
	// synchronisation later than the request. Default true. The check is
	// between the packet's own fields, never against this relay's clock,
	// so a relay whose own time is wrong does not refuse correct
	// answers.
	RefuseBogusTimestamps *bool `yaml:"refuse_bogus_timestamps"`
	// RefuseBogusRefID refuses an answer whose reference identifier does
	// not match the stratum that says how to read it: a stratum 1 answer
	// whose identifier is not a reference clock's name, or a stratum 2
	// or worse answer with no identifier at all. Default true.
	RefuseBogusRefID *bool `yaml:"refuse_bogus_refid"`
	// ExpectRefID is the reference identifiers a server may report: the
	// four-character name at stratum 0 and 1 ("GPS", "PPS", "DCFa") and
	// the dotted quad at stratum 2 and above. Empty accepts any. It is
	// the cheapest statement of server identity the protocol allows
	// without authentication: a GPS-backed clock that starts answering
	// as something else is either a different device or the same device
	// with a different upstream.
	ExpectRefID []string `yaml:"expect_refid"`
	// LeapPolicy is what happens when an answer announces a leap
	// second: alert (the default -- an announcement outside the window
	// when a leap second can really happen is a security event), allow
	// (say nothing), window (refuse an announcement outside the window)
	// or refuse (refuse every announcement, for an estate that handles
	// leap seconds another way).
	//
	// A leap announcement makes every client that hears it plan to move
	// its clock, and the IERS only ever uses the end of June, December,
	// March or September -- so an announcement in August says something.
	LeapPolicy string `yaml:"leap_policy"`
	// LeapWindow is how long before the end of such a month an
	// announcement is plausible. Default 744h, a month, because RFC 5905
	// sets the indicator during the last day and some servers announce
	// from the start of the month.
	LeapWindow Duration `yaml:"leap_window"`
	// RefuseUnsynchronised refuses an answer from a server that says
	// its own clock is not synchronised -- by the leap indicator or by
	// stratum 16, which are two separate statements. Default true.
	RefuseUnsynchronised *bool `yaml:"refuse_unsynchronised"`
	// HealthyAfter and UnhealthyAfter are the hysteresis: how many
	// probes in a row it takes to change a server's state. Default 3
	// each, because one slow answer on a busy network is not a fault
	// and a relay that moved every client on one sample would be an
	// outage generator with a health check attached.
	HealthyAfter   int `yaml:"healthy_after"`
	UnhealthyAfter int `yaml:"unhealthy_after"`
	// OnAllSuspect is what happens when no server is usable: pass (the
	// default -- keep forwarding and keep saying so) or refuse. A
	// blanket fail-closed here stops the plant's clocks, which is
	// itself an outage, so it is a decision an estate makes in writing.
	OnAllSuspect string `yaml:"on_all_suspect"`
}

// NTPHoldover bounds how long a server whose time cannot be verified is
// still used.
type NTPHoldover struct {
	// MaxDuration is how long a server may stay unverifiable before the
	// listener says the holdover has expired. 0 disables the bound.
	MaxDuration Duration `yaml:"max_duration"`
}

// NTPChangeDetection watches each time source for a change in what it
// is, which is a different question from whether one answer was
// acceptable.
//
// Every bound in quality asks "is this answer good enough". These ask
// "is this still the same server, answering the same way". A source that
// was a GPS clock at stratum 1 and is now something else at stratum 4,
// an offset that stepped by fourteen seconds between two polls, a
// dispersion that grew by two orders of magnitude, a server that stopped
// carrying NTS: each of those is within every static bound an estate
// would set, and each is the shape of a time source being replaced,
// re-pointed or stood in front of.
type NTPChangeDetection struct {
	// Enabled turns the watching on. Default true.
	Enabled *bool `yaml:"enabled"`
	// MaxStep is how far the measured offset to one server may move
	// between two measurements. Default 1s. A real clock drifts; it does
	// not step.
	MaxStep Duration `yaml:"max_step"`
	// MaxStratumJump is how far a server's stratum may move at once.
	// Default 2: a server whose own upstream failed over moves by one or
	// two, and one that moved by eight is answering for somebody else.
	MaxStratumJump int `yaml:"max_stratum_jump"`
	// DispersionGrowth is the factor by which a server's root dispersion
	// may grow between measurements before it is said. Default 8.
	DispersionGrowth int `yaml:"dispersion_growth"`
	// Action is what a detection does: alert (the default -- a security
	// event and a counter) or refuse (that, and the answer does not
	// reach the client).
	//
	// Refusing is a real choice with a real cost: the estate's clocks
	// stop being corrected until an operator looks. Alerting keeps the
	// time flowing and makes somebody read the event, which for most
	// estates is the right order.
	Action string `yaml:"action"`
}

// NTPKoD is the kiss-o'-death policy: a stratum-0 answer whose four
// reference identifier octets are a code. It is the protocol's own way of
// saying "not now", and a client that gets one backs off.
type NTPKoD struct {
	// OnRateLimit answers a rate-limited client with a RATE kiss rather
	// than dropping its packet. Default true: a drop teaches a client
	// nothing and it asks again.
	OnRateLimit *bool `yaml:"on_rate_limit"`
	// OnDeny answers a policy refusal with a DENY kiss. Default false:
	// a refusal usually should not tell the client what the policy is.
	OnDeny bool `yaml:"on_deny"`
	// Forward passes a server's own kiss-o'-death on to the client.
	// Default true: the client is the thing that has to back off.
	Forward *bool `yaml:"forward"`
}

// NTPLearn records what asks this listener for the time.
type NTPLearn struct {
	// Enabled turns the recording on.
	Enabled bool `yaml:"enabled"`
	// File is where the report is written, as YAML. Required when
	// enabled.
	File string `yaml:"file"`
	// Interval is how often it is rewritten. Default 5m; it is also
	// written at shutdown.
	Interval Duration `yaml:"interval"`
	// MaxSubjects bounds the observations held: one per client,
	// version and mode. Default 8192.
	MaxSubjects int `yaml:"max_subjects"`
	// Enforce keeps the policy in force while learning. Default false.
	Enforce bool `yaml:"enforce"`
}

// NTPTrace writes one JSON object per packet.
type NTPTrace struct {
	// File is the trace file. Required.
	File string `yaml:"file"`
	// MaxBytes bounds it. Default 104857600 (100 MiB); at the bound the
	// trace says it stopped and stops.
	MaxBytes int64 `yaml:"max_bytes"`
	// Requests and Responses select the directions traced. Default
	// both.
	Requests  *bool `yaml:"requests"`
	Responses *bool `yaml:"responses"`
}

// Alerts says whether a refusal writes a security event.
func (n *NTPListener) Alerts() bool {
	return n == nil || n.AlertOnDeny == nil || *n.AlertOnDeny
}

// InterleavedAllowed says whether an interleaved answer is accepted.
func (n *NTPListener) InterleavedAllowed() bool {
	return n == nil || n.Interleaved == nil || *n.Interleaved
}

// NTSKEListener is NTS key establishment: TLS on TCP 4460 with the ALPN
// "ntske/1" (RFC 8915).
//
// It is a listener of its own because it is a different port, a different
// transport and a different security property from the time service, and
// because running one without the other should be something a deployment
// writes down.
//
// It relays rather than terminates. The TLS session is between the client
// and the key establishment server, so this listener reads the one thing
// the handshake shows in the clear -- the server name and the application
// protocol the client offers -- refuses anything that is not an NTS
// client, and hands the rest to the pool. Terminating it would mean
// deriving the NTS keys from the TLS exporter, holding the cookie keys the
// time servers use, and rotating them with overlap; none of that is
// faked here.
type NTSKEListener struct {
	// Upstream is the pool of key establishment servers. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may
	// connect from. Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// ServerNames is the allow list of server names a client may ask
	// for. Empty accepts any name, including none.
	ServerNames []string `yaml:"server_names"`
	// RequireALPN refuses a connection that does not offer "ntske/1".
	// Default true: a connection to this port that is not an NTS client
	// is something else entirely, and this is the only port where that
	// can be told from the handshake alone.
	RequireALPN *bool `yaml:"require_alpn"`
	// MaxConnections bounds live sessions. Default 256.
	MaxConnections int `yaml:"max_connections"`
	// MaxConcurrentHandshakes bounds the handshakes in flight, because
	// a TLS handshake is the expensive part of NTS and a flood of them
	// is the denial of service this port has. Default 32.
	MaxConcurrentHandshakes int `yaml:"max_concurrent_handshakes"`
	// HandshakeTimeout bounds how long a client has to get through the
	// handshake. Default 10s.
	HandshakeTimeout Duration `yaml:"handshake_timeout"`
	// IdleTimeout closes a session that says nothing. Default 30s: a
	// key establishment is a handshake and a short exchange, not a
	// session anybody holds open.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// MaxBytes bounds one session's traffic each way. Default 65536.
	MaxBytes int64 `yaml:"max_bytes"`
	// LogSessions writes an access line per session.
	LogSessions bool `yaml:"log_sessions"`
	// AlertOnDeny writes a security event for every refusal. Default
	// true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// Terminate makes this listener answer key establishment itself
	// rather than relaying it: it terminates the TLS, derives the NTS
	// keys from the exporter, and issues cookies of its own that the
	// kind: ntp listener beside it opens. With it, upstream is not used
	// and a tls section is required -- the certificate is the whole of
	// what a client authenticates.
	Terminate *NTSKETerminate `yaml:"terminate"`
}

// Terminating says whether this listener answers key establishment
// itself.
func (k *NTSKEListener) Terminating() bool { return k != nil && k.Terminate != nil }

// NTSKETerminate is key establishment answered by this relay.
//
// Terminating NTS means holding the cookie keys, and holding them means
// rotating them with an overlap and keeping them across a restart. Both
// are here rather than assumed: a rotation that invalidated the cookies
// already issued, or a restart that started with fresh keys, would take
// the estate's time service down for as long as it took every client to
// establish keys again -- a TLS handshake each, all at the same moment.
type NTSKETerminate struct {
	// Server and Port tell the client where to spend the cookies. Both
	// are optional: empty means "where you already are", which is the
	// answer when this relay fronts the time service on its own
	// address.
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
	// Cookies is how many cookies one exchange hands out. Default 8,
	// which is what RFC 8915 recommends: a client spends one per time
	// exchange and gets one back, so eight is the depth of the buffer
	// that absorbs lost packets.
	Cookies int `yaml:"cookies"`
	// RotateEvery is how often a new cookie key becomes the current
	// one. Default 24h. Zero and negative are refused rather than read
	// as "never": a key that is never rotated is a decision, and it is
	// spelled rotate_every: 0s nowhere -- set keep_keys and a long
	// interval instead.
	RotateEvery Duration `yaml:"rotate_every"`
	// KeepKeys is how many retired keys still open cookies already
	// issued. Default 2: a cookie issued just before a rotation is
	// spent after it, and a client switched off over a weekend comes
	// back with cookies from two rotations ago. Zero is allowed and
	// means a rotation invalidates every cookie at once, which is a
	// thing an operator may want and never a thing to default to.
	KeepKeys *int `yaml:"keep_keys"`
	// State is where the cookie keys are kept across a restart. It is
	// secret material -- whoever can read it can forge a cookie, which
	// is to say forge an authenticated time answer -- so it is written
	// 0600 and belongs somewhere only this daemon can read. Empty means
	// the keys live only in memory, and a restart then invalidates
	// every cookie in the estate.
	State string `yaml:"state"`
}

// CookieCount is how many cookies one exchange hands out.
func (t *NTSKETerminate) CookieCount() int {
	if t == nil || t.Cookies <= 0 {
		return DefaultNTSCookies
	}
	return t.Cookies
}

// Rotation is how often the cookie key changes.
func (t *NTSKETerminate) Rotation() time.Duration {
	if t == nil || t.RotateEvery.D() <= 0 {
		return DefaultNTSRotation
	}
	return t.RotateEvery.D()
}

// History is how many retired cookie keys still open a cookie.
func (t *NTSKETerminate) History() int {
	if t == nil || t.KeepKeys == nil {
		return DefaultNTSKeepKeys
	}
	return *t.KeepKeys
}

// The defaults of the terminating side, named because two packages read
// them: the listener that applies them and the documentation test that
// checks the reference says what the code does.
const (
	DefaultNTSCookies  = 8
	DefaultNTSRotation = 24 * time.Hour
	DefaultNTSKeepKeys = 2
)

// Alerts says whether a refusal writes a security event.
func (k *NTSKEListener) Alerts() bool {
	return k == nil || k.AlertOnDeny == nil || *k.AlertOnDeny
}

// ALPNRequired says whether a client must offer the NTS key
// establishment protocol.
func (k *NTSKEListener) ALPNRequired() bool {
	return k == nil || k.RequireALPN == nil || *k.RequireALPN
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
	// Recording writes the control channel -- every command and every
	// reply -- to a file per session, with a note where each transfer
	// happened. The transferred bytes are not in it: a recording is
	// what was done, and a copy of every file moved through the proxy
	// is a second copy of the data to look after.
	Recording *SessionRecording `yaml:"recording"`
	// ICAP hands transferred files to a scanning service.
	ICAP *TransferICAP `yaml:"icap"`
	// MFA asks for a second factor after the password is accepted, on
	// the control channel, before any other command is allowed. An FTP
	// client has no prompt of its own, so the code is taken the only
	// way the protocol allows: as the argument of ACCT, or appended to
	// the password.
	MFA *MFAPolicy `yaml:"mfa"`
	// RequireGrant admits a session only against a live grant from the
	// access ledger: one somebody asked for, somebody else approved, and
	// that ends by itself. Needs the access section. See docs/CONFIG.md.
	RequireGrant bool `yaml:"require_grant"`
}

// TransferICAP scans the files a session moves (RFC 3507), for the
// kinds that move files rather than requests: ftp and sftp.
//
// A transfer is not an HTTP message, so the file is wrapped in the
// request or the response a scanner expects, which is what every ICAP
// scanner is built to read; the URL it sees names the real file, so a
// log at the scanner points at something an operator can find.
//
// Scanning holds the file: a verdict that arrives after the bytes is
// not a control. What that costs differs by protocol, and is written
// down under each listener.
type TransferICAP struct {
	// Service names an entry in icap.services. Required.
	Service string `yaml:"service"`
	// Uploads scans the files a client sends through REQMOD. Default
	// true: a file arriving on a server is the direction that matters
	// most.
	Uploads *bool `yaml:"uploads"`
	// Downloads scans the files a client fetches through RESPMOD.
	// Default false, because a download doubles the bytes on the wire
	// and most deployments trust what their own server already holds.
	Downloads bool `yaml:"downloads"`
}

// ScansUploads reports whether what a client sends is scanned.
func (f *TransferICAP) ScansUploads() bool { return f != nil && (f.Uploads == nil || *f.Uploads) }

// ScansDownloads reports whether what a client fetches is scanned.
func (f *TransferICAP) ScansDownloads() bool { return f != nil && f.Downloads }

// TelnetListener is a telnet gateway: the proxy is a telnet server to
// the client and a telnet client to the target, reading the NVT
// protocol of RFC 854 in both directions.
//
// The reason it is not a tcp listener: telnet's options are commands
// escaped into the byte stream, so a proxy that does not parse them
// cannot tell a window size from the characters a person typed. Every
// control this listener has needs that parse -- a session recording
// that holds what was seen rather than what was negotiated, an option
// policy, and a second factor asked for before the target is dialled
// at all.
//
// Telnet carries everything in clear. Wrapping the listener in TLS
// (the tls section, as telnets does on 992) is the only thing that
// changes that, and validation says so when it is left off.
type TelnetListener struct {
	// Upstream is the pool of targets. Required.
	Upstream string `yaml:"upstream"`
	// Banner replaces what the proxy says before the target is
	// dialled. A banner naming the equipment is a banner that saves an
	// attacker a question.
	Banner string `yaml:"banner"`
	// AllowOptions are the telnet options a session may negotiate, by
	// the names in docs/CONFIG.md. Default is the set an interactive
	// session needs and nothing else. An option this proxy has no name
	// for is always refused: one whose effect it cannot name is one it
	// cannot hold to a policy.
	AllowOptions []string `yaml:"allow_options"`
	// DenyOptions removes from AllowOptions, for changing one thing
	// without restating the list.
	DenyOptions []string `yaml:"deny_options"`
	// MaxSubnegotiation bounds one subnegotiation. Default 4096.
	MaxSubnegotiation int `yaml:"max_subnegotiation"`
	// Recording writes the session -- what the target showed, and
	// optionally what was typed -- to a file.
	Recording *SessionRecording `yaml:"recording"`
	// MFA asks for a login name and a one-time code before the target
	// is dialled. Telnet has no authentication of its own for a proxy
	// to read, so this is a prompt the proxy writes and reads itself;
	// the target's own login happens afterwards, unchanged.
	MFA *MFAPolicy `yaml:"mfa"`
	// RequireGrant admits a session only against a live grant from the
	// access ledger: one somebody asked for, somebody else approved, and
	// that ends by itself. Needs the access section. See docs/CONFIG.md.
	RequireGrant bool `yaml:"require_grant"`
	// IdleTimeout is no traffic in either direction. Default 5m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// SessionTimeout bounds a whole session however active. Default 0,
	// no bound.
	SessionTimeout Duration `yaml:"session_timeout"`
	// MaxConnections bounds sessions on this listener. Default 1000.
	MaxConnections int `yaml:"max_connections"`
	// ProxyProtocol sends a PROXY protocol v2 header with the client
	// address to the target.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// AllowClients restricts clients to these CIDRs.
	AllowClients []string `yaml:"allow_clients"`
	// Deception answers as a device that is not there: a login this
	// listener was going to refuse answered by a fabricated shell, or a
	// whole listener that is one. See TelnetDeception.
	Deception *TelnetDeception `yaml:"deception"`
}

// TelnetDeception answers as a device that is not there.
//
// Telnet on a public address is found in minutes, and what finds it is a
// dictionary: the Mirai family and everything after it walk a list of the
// credentials that shipped on recorders, cameras and routers. A refusal collects
// the address. Answering collects the *list* -- and then, because the login is
// accepted, the commands the thing had in mind: the busybox check, the echo
// liveness test, and the `wget` that names the payload.
//
// Nothing is ever run and nothing is ever fetched. And no password is recorded in
// any form a guess can be tested against: what is kept is the user name, the
// credential's length, and a handle computed under a key the process made at
// startup and never writes down.
type TelnetDeception struct {
	// Enabled turns the section off without removing it; it defaults to
	// true wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a session this listener was going to
	// refuse gets the fabrication instead of the refusal, and never
	// reaches the equipment) or decoy (the whole listener is a fabricated
	// device, with no upstream).
	//
	// In mode answer it replaces the refusals that happen after the proxy
	// has spoken: a failed or locked second factor, the estate's
	// authorisation policy, and a missing access grant. It does not
	// replace allow_clients or a ban -- an address that may not connect
	// gets nothing, which is what the list means -- and it never replaces
	// an outage: a target that cannot be reached is an outage, and a real
	// operator must not be given a fabricated device during one.
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client, which is
	// what a honeypot wants.
	Clients []string `yaml:"clients"`
	// Profile is the machine being impersonated: busybox (the default, a
	// recorder or camera -- what is actually on port 23) or linux.
	Profile string `yaml:"profile"`
	// Hostname replaces the profile's, and is what a visitor reads in the
	// login prompt and the shell prompt. Name it after something this
	// estate really has.
	Hostname string `yaml:"hostname"`
	// Attempts is how many credentials are taken before the login is
	// accepted. Default 1.
	//
	// More than one collects more of the dictionary, and two or three is
	// what a real device's login looks like. What it must never depend on
	// is *which* credential was offered: a trap that accepted the right
	// password and refused the wrong one would be a credential oracle,
	// which is the one thing a password list needs.
	Attempts int `yaml:"attempts"`
	// Tripwire are command names that raise a telnet_tripwire security
	// event in addition to the built-in set: the escalation, in the order
	// it happens -- fetch a payload (wget, curl, tftp), make it
	// executable, run it, keep it running, and clear what would have
	// stopped it.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated numbers reproducible. Zero derives one
	// from the listener name.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a fabricated number lasts, which
	// here is the load average and the number of users logged in.
	// Default 30s; 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
}

// DefaultTelnetOptions are what an interactive session needs: the
// echo and go-ahead negotiation every client does, the terminal type
// and size a full screen program reads, and end-of-record for the line
// mode equipment that uses it. Everything else -- the environment
// options that carry variables to the target, the authentication and
// encryption options nothing implements the same way twice, X display
// forwarding -- is left out, and can be added by name.
var DefaultTelnetOptions = []string{
	"echo", "suppress-go-ahead", "binary", "terminal-type", "naws",
	"terminal-speed", "end-of-record", "timing-mark", "status",
}

// VNCListener is a VNC gateway: the proxy is an RFB server to the
// client and an RFB client to the target, terminating the handshake of
// RFC 6143 on both legs.
//
// The reason it is not a tcp listener: RFB's whole policy surface is
// in the handshake. Which security type is used, whether the session
// is encrypted and how, what the desktop is called -- all of it is
// negotiated in the first few hundred bytes, and a proxy that does not
// sit in that negotiation cannot decide any of it, nor record what
// follows.
type VNCListener struct {
	// Upstream is the pool of targets. Required.
	Upstream string `yaml:"upstream"`
	// SecurityTypes are the RFB security types a client may use, by
	// name. Default is the ones this proxy mediates: none, vncauth and
	// vencrypt. A type not listed is refused.
	SecurityTypes []string `yaml:"security_types"`
	// VeNCryptSubtypes are the VeNCrypt subtypes offered when
	// vencrypt is in SecurityTypes. Default x509-vnc and x509-none,
	// which are the ones with a certificate to check.
	VeNCryptSubtypes []string `yaml:"vencrypt_subtypes"`
	// Password is a file holding the VNC password this proxy answers
	// its own vncauth challenge with. Without it, vncauth towards the
	// client is refused: a challenge nobody can answer is not
	// authentication.
	PasswordFile string `yaml:"password_file"`
	// UpstreamPasswordFile is the password this proxy uses towards the
	// target, when the target asks for vncauth.
	UpstreamPasswordFile string `yaml:"upstream_password_file"`
	// TLSMode says what the listener's tls section is for.
	//
	// negotiated (the default) leaves the socket plain and presents
	// the certificate inside RFB, which is what VeNCrypt does and what
	// a modern viewer offers by itself. wrap makes the socket TLS from
	// the first byte, with RFB inside it, which is what a viewer
	// reaching an stunnel-wrapped port expects.
	//
	// A port is one or the other and cannot be both: the first byte a
	// client sends is either a TLS record or "RFB 003.008".
	TLSMode string `yaml:"tls_mode"`
	// RSAKeyFile is the RSA private key this proxy presents in the
	// rsa-aes security types. Required with any of them, in PEM,
	// PKCS#1 or PKCS#8, and at least 2048 bits.
	RSAKeyFile string `yaml:"rsa_key_file"`
	// UpstreamRSAFingerprint pins the target's rsa-aes public key.
	// Required to use rsa-aes towards a target: nothing else
	// authenticates the far end of that exchange, and there is nobody
	// at a proxy to show a fingerprint to. The log prints the key a
	// target offered, which is how this gets filled in.
	UpstreamRSAFingerprint string `yaml:"upstream_rsa_fingerprint"`
	// UpstreamUser is the login this proxy presents to a target whose
	// security type carries a name, which among the types here means
	// MS-Logon II. Its password is UpstreamPasswordFile.
	UpstreamUser string `yaml:"upstream_user"`
	// UpstreamSecurity is the security type to prefer towards the
	// target, by name. Default is the strongest the target offers
	// among the ones this proxy mediates.
	UpstreamSecurity string `yaml:"upstream_security"`
	// UpstreamTLSMode is none or vencrypt. Default none.
	UpstreamTLSMode string `yaml:"upstream_tls_mode"`
	// UpstreamTLS pins the CA and name for the target's leg.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// SSH reaches the target through an SSH connection this proxy
	// makes, so the RFB never crosses the network in clear. This is
	// the usual way a VNC server is reached safely, done by the
	// gateway rather than by every operator.
	SSH *VNCOverSSH `yaml:"ssh"`
	// ViewOnly drops the client's pointer and keyboard messages, so a
	// session can be watched and not driven.
	ViewOnly bool `yaml:"view_only"`
	// PixelStream says whether the gateway reads the desktop's picture.
	//
	// framed (the default) reads every message the desktop sends and
	// every rectangle inside it, which is what makes Bounds possible:
	// an image protocol's numbers are the viewer's allocations, and a
	// gateway that forwards them unread cannot refuse one that is a
	// bomb. It also decides what a client may ask for, because framing
	// needs every encoding in play to be one the gateway can measure,
	// so the encodings it cannot are removed from the client's list and
	// the desktop never uses them -- tight among them.
	//
	// opaque forwards the desktop's bytes without reading them, which
	// is what a listener that must have tight sets. Only the announced
	// framebuffer size is then bounded; the rest of Bounds cannot be.
	// The client's own messages are framed either way, because that is
	// what lets a gateway refuse one and forward the next.
	PixelStream string `yaml:"pixel_stream"`
	// Bounds bound what the desktop may ask the viewer to allocate.
	Bounds *VNCBounds `yaml:"bounds"`
	// Clipboard says which way a clipboard transfer may travel: both
	// (the default), to_client, to_target or none. A bastion whose
	// sessions are recorded usually wants to_client at most: a
	// clipboard into the desktop is an upload with no name and no size
	// in the log.
	Clipboard string `yaml:"clipboard"`
	// AllowResize lets a client ask the desktop to change size
	// (SetDesktopSize). Default true. The size asked for is bounded by
	// Bounds.MaxFramebufferPixels whatever this says, because a client
	// asking a desktop to allocate a framebuffer is the same attack in
	// the other direction.
	AllowResize *bool `yaml:"allow_resize"`
	// Recording writes the RFB stream to a file.
	Recording *SessionRecording `yaml:"recording"`
	// MFA asks for a login name and a one-time code before the target
	// is dialled.
	MFA *MFAPolicy `yaml:"mfa"`
	// RequireGrant admits a session only against a live grant from the
	// access ledger: one somebody asked for, somebody else approved, and
	// that ends by itself. Needs the access section. See docs/CONFIG.md.
	RequireGrant bool `yaml:"require_grant"`
	// IdleTimeout is no traffic in either direction. Default 5m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// SessionTimeout bounds a whole session however active. Default 0.
	SessionTimeout Duration `yaml:"session_timeout"`
	// HandshakeTimeout bounds the negotiation before the session
	// begins. Default 30s: a peer that never finishes the handshake is
	// a connection held open for nothing.
	HandshakeTimeout Duration `yaml:"handshake_timeout"`
	// MaxConnections bounds sessions on this listener. Default 200.
	MaxConnections int `yaml:"max_connections"`
	// ProxyProtocol sends a PROXY protocol v2 header to the target.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// AllowClients restricts clients to these CIDRs.
	AllowClients []string `yaml:"allow_clients"`
}

// VNCBounds bound the pixel stream: what the desktop may declare, and
// therefore what the viewer at the other end is asked to allocate.
//
// Image protocols are where a decompression bomb is cheapest to send. A
// rectangle's header is twelve bytes and says how many pixels it
// covers; a viewer sizes its decode buffer from that. A desktop that
// says 4096x4096 in twelve bytes of zlib is asking for sixty-four
// megabytes, and it can ask again immediately. None of these bounds
// requires decompressing anything: they compare what was declared with
// what arrived.
//
// A zero field is no bound.
type VNCBounds struct {
	// MaxFramebufferPixels bounds the desktop size, in pixels: the one
	// the target announces, the one a resize changes it to, and the one
	// a client asks for. Default 33177600, which is 7680x4320.
	MaxFramebufferPixels int `yaml:"max_framebuffer_pixels"`
	// MaxRectanglesPerUpdate bounds one framebuffer update's
	// rectangles. Default 4096. A thousand one-pixel rectangles cost
	// the viewer a thousand decode calls for one screen.
	MaxRectanglesPerUpdate int `yaml:"max_rectangles_per_update"`
	// MaxEncodedRectangle bounds one rectangle's encoded payload in
	// bytes. Default 16777216.
	MaxEncodedRectangle int `yaml:"max_encoded_rectangle"`
	// MaxDecodeRatio bounds the declared picture over the bytes that
	// carry it, for the compressed encodings. Default 1000: a
	// thousandfold is past any real screen and well short of what a
	// bomb needs to be worth sending.
	MaxDecodeRatio int `yaml:"max_decode_ratio"`
	// MaxCutText bounds one clipboard transfer in either direction, in
	// bytes. Default 1048576.
	MaxCutText int `yaml:"max_cut_text"`
}

// VNCClipboard directions.
const (
	VNCClipboardBoth     = "both"
	VNCClipboardToClient = "to_client"
	VNCClipboardToTarget = "to_target"
	VNCClipboardNone     = "none"
)

// VNCPixelStream modes.
const (
	VNCPixelsFramed = "framed"
	VNCPixelsOpaque = "opaque"
)

// VNCOverSSH reaches a VNC target through an SSH connection the
// gateway makes itself.
type VNCOverSSH struct {
	// User is the login on the SSH host. Required.
	User string `yaml:"user"`
	// KeyFile is the private key the gateway authenticates with.
	// Required.
	KeyFile string `yaml:"key_file"`
	// KnownHosts pins the SSH host keys. Required: an unpinned tunnel
	// authenticates nothing, which is the whole reason for the tunnel.
	KnownHosts string `yaml:"known_hosts"`
	// Address is the SSH host, host:port. Default is the upstream
	// endpoint's host with port 22.
	Address string `yaml:"address"`
	// Target is what to reach from the SSH host, host:port. Default
	// 127.0.0.1:5900, which is where a VNC server bound to loopback
	// is.
	Target string `yaml:"target"`
}

// DefaultVNCSecurityTypes are the types this proxy mediates: it can
// complete the handshake on both legs, so it can record the session
// and decide the rest.
var DefaultVNCSecurityTypes = []string{"none", "vncauth", "vencrypt"}

// DefaultVeNCryptSubtypes are the ones with a certificate to check.
// The anonymous ones encrypt without authenticating, which stops a
// reader and not an active attacker.
var DefaultVeNCryptSubtypes = []string{"x509-vnc", "x509-none"}

// RDPListener is a Remote Desktop gateway: the proxy terminates the
// connection sequence on both legs, which is what lets it decide the
// security protocol, rewrite the virtual channel list, check a second
// factor against the credential in flight, substitute the credential
// that opens the desktop, and record what the session showed.
//
// The channel list is the important one. Every redirection RDP has --
// drives, printers, serial and parallel ports, smart cards, the
// clipboard, audio -- rides a virtual channel, and nothing can be used
// that was not both announced and granted. A gateway that rewrites the
// list decides what a session is able to do, before it does it.
type RDPListener struct {
	// Upstream is the pool of desktops. Required.
	Upstream string `yaml:"upstream"`
	// Security is what a client may use, by name: tls or rdp. Default
	// tls. nla is not offered to clients and cannot be: checking it
	// would need every person's password, which is the one thing a
	// gateway should not hold. See docs/CONFIG.md.
	Security []string `yaml:"security"`
	// UpstreamSecurity is what this proxy uses towards the desktop, by
	// name: tls, nla or rdp. Default tls.
	UpstreamSecurity string `yaml:"upstream_security"`
	// UpstreamTLS pins the CA and name for the desktop's leg.
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	// UpstreamUser and UpstreamPasswordFile are the credential this
	// proxy opens the desktop with, where an operator would rather the
	// person's own never reached it. Without them the person's
	// credential is forwarded as it arrived.
	UpstreamUser         string `yaml:"upstream_user"`
	UpstreamDomain       string `yaml:"upstream_domain"`
	UpstreamPasswordFile string `yaml:"upstream_password_file"`
	// Channels is the static virtual channel policy.
	Channels *RDPChannelPolicy `yaml:"channels"`
	// Devices is the redirected device policy, which is what decides
	// whether a session can move a file or reach a port.
	Devices *RDPDevicePolicy `yaml:"devices"`
	// Recording writes the session stream to a file.
	Recording *SessionRecording `yaml:"recording"`
	// MFA asks for a one-time code, carried with the password since
	// RDP has nowhere to ask a question.
	MFA *MFAPolicy `yaml:"mfa"`
	// RequireGrant admits a session only against a live grant from the
	// access ledger: one somebody asked for, somebody else approved, and
	// that ends by itself. Needs the access section. See docs/CONFIG.md.
	RequireGrant bool `yaml:"require_grant"`
	// IdleTimeout is no traffic in either direction. Default 5m.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// SessionTimeout bounds a whole session however active. Default 0.
	SessionTimeout Duration `yaml:"session_timeout"`
	// HandshakeTimeout bounds the connection sequence before the
	// session begins. Default 30s.
	HandshakeTimeout Duration `yaml:"handshake_timeout"`
	// MaxConnections bounds sessions on this listener. Default 200.
	MaxConnections int `yaml:"max_connections"`
	// ProxyProtocol sends a PROXY protocol v2 header to the desktop.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// AllowClients restricts clients to these CIDRs.
	AllowClients []string `yaml:"allow_clients"`
}

// RDPChannelPolicy decides which static virtual channels a session
// has. A channel that is not allowed is taken out of the list the
// desktop is asked for, so the desktop never learns it was wanted.
type RDPChannelPolicy struct {
	// Allow names the channels a client may have. The default is
	// none: a session that can see the desktop and nothing else.
	Allow []string `yaml:"allow"`
	// Dynamic is the policy for the channels opened *inside* `drdynvc`.
	//
	// `drdynvc` is not a channel, it is a multiplexer: channels are opened
	// and closed by name inside it at any point in a session, and on a current
	// Windows client the graphics pipeline, display control, geometry, camera,
	// audio and device and clipboard redirection all ride there. So allowing
	// `drdynvc` in Allow -- which an operator must do for a usable session on
	// anything recent -- allows every dynamic channel inside it unless this
	// says otherwise, including ones Allow refused by name.
	//
	// Absent this block the dynamic channels are carried and counted, and the
	// load warns that they are not being decided about. They are not refused
	// by default, because that would break every working session on an
	// upgrade; the warning is what makes the gap visible.
	Dynamic *RDPDynamicChannelPolicy `yaml:"dynamic"`
}

// RDPDynamicChannelPolicy decides the channels opened inside `drdynvc`.
//
// **The desktop opens them, not the client.** The create request travels from
// the desktop to the client carrying the channel's name, and the client answers
// with a status -- so this policy is applied in the direction a gateway has
// least reason to be reading, and a refusal is written as the answer a client
// with no such listener would have sent.
type RDPDynamicChannelPolicy struct {
	// Allow names the dynamic channels a session may have, matched without
	// regard to case as the static list is. Empty allows none once this block
	// exists, which is the same shape as the static policy's default.
	//
	// The names are the listener names the desktop asks for, and they are long
	// and vendor-shaped: `Microsoft::Windows::RDS::Graphics` is the graphics
	// pipeline a modern session draws through, and a session without it falls
	// back to the slower path or fails outright. The protocol page lists the
	// ones worth knowing.
	Allow []string `yaml:"allow"`
	// Deny names the ones refused whatever Allow says, which is how an estate
	// allows the pipeline it needs and keeps redirection out of it.
	Deny []string `yaml:"deny"`
}

// RDPDevicePolicy decides which kinds of redirected device a session
// has, among the ones the rdpdr channel carries: drive, printer,
// serial, parallel, smartcard. It applies only where rdpdr is an
// allowed channel, since without the channel there is nothing to
// announce a device on.
type RDPDevicePolicy struct {
	// Allow names the device kinds a client may redirect. The default
	// is none, so allowing the rdpdr channel without naming a device
	// kind gives a session no redirection at all.
	Allow []string `yaml:"allow"`
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
	// Deception answers as a bastion that is not there: a credential this
	// listener refused answered by a fabricated shell, or a whole listener
	// that is one. See SSHDeception.
	Deception *SSHDeception `yaml:"deception"`
	// HostKeys are the proxy's own host key files, in OpenSSH or PEM
	// form. At least one is required. Clients pin these, so replacing
	// them is a fleet-wide known_hosts change: add the new key
	// alongside the old one and remove the old one later.
	HostKeys []string `yaml:"host_keys"`
	// AuthorizedKeys is an OpenSSH authorized_keys file of the public
	// keys that may connect. Options in the file are ignored; the
	// policy lives here. The one exception is no-touch-required, which
	// is about whether a credential is a credential at all: see
	// require_touch.
	AuthorizedKeys string `yaml:"authorized_keys"`
	// RequireHardwareKey accepts only a key held in a security token:
	// sk-ssh-ed25519@openssh.com or sk-ecdsa-sha2-nistp256@openssh.com,
	// and a certificate whose own key is one of those.
	//
	// It is the difference between a credential that can be copied and
	// one that cannot. Every other key here is a file: a backup, a
	// laptop somebody left on a train and an agent forwarded to the
	// wrong host are all copies of it, and nothing about the protocol
	// can tell a copy from the original. A token's key never leaves the
	// token; what crosses the wire is a signature the token made, and
	// making one needs the token in somebody's hand.
	RequireHardwareKey bool `yaml:"require_hardware_key"`
	// RequireTouch demands that each signature assert user presence --
	// the touch -- and refuses the opt-outs that would waive it: the
	// no-touch-required option on an authorized_keys line and the
	// extension of the same name in a certificate. Default true.
	//
	// Without presence a hardware key still cannot be copied, but it can
	// be used by anything that reaches the machine it is plugged into,
	// which is most of what the token was bought to prevent. false
	// honours the opt-outs, as OpenSSH does, for the keys that have to
	// work unattended.
	RequireTouch *bool `yaml:"require_touch"`
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
	// MaxCertificateLifetime refuses a user certificate whose validity
	// window is longer than this. Default 0, no bound.
	//
	// The point of certificates over authorized_keys is that they
	// expire; a CA that issues for a year has made a credential nobody
	// can take back for a year, and a bastion is entitled to say how
	// soon. A certificate with no expiry at all is refused whenever
	// this is set.
	MaxCertificateLifetime Duration `yaml:"max_certificate_lifetime"`
	// RevokedKeys is a file of public keys, in authorized_keys format,
	// that are refused whatever else says otherwise: the key itself, a
	// certificate whose key it is, and a certificate signed by it. It is
	// the one list that overrides the CA, which is what makes a
	// certificate revocable before it expires.
	RevokedKeys string `yaml:"revoked_keys"`
	// MaxForwards bounds the port forwards one session may hold open at
	// once. Default 8. A session that may forward at all can otherwise
	// open one per file descriptor the proxy has.
	MaxForwards int `yaml:"max_forwards"`
	// MaxSessionsPerPrincipal bounds the sessions one principal may hold
	// at once, which max_sessions cannot: a listener bounded at five
	// hundred is five hundred for one key as much as for the fleet.
	// Default 0, no bound.
	MaxSessionsPerPrincipal int `yaml:"max_sessions_per_principal"`
	// RekeyBytes is how many bytes pass before the transport agrees a
	// fresh key. Default 0, which leaves the crypto library's own
	// threshold (1 GiB, or 1 << 32 for a 64 bit block cipher).
	RekeyBytes int64 `yaml:"rekey_bytes"`
	// AllowShellSyntax lets an exec command carry shell metacharacters.
	// Default false.
	//
	// allow_commands is a list of regular expressions over the command
	// line, and a regular expression is a weak thing to hold a shell to:
	// "^journalctl .*$" matches "journalctl -u x; rm -rf /" exactly as
	// happily as it matches what it was written for. So the command line
	// is read as a shell would split it first, and one carrying an
	// operator -- a semicolon, a pipe, an ampersand, a redirection, a
	// backquote, a $( -- is refused before any pattern is tried. A
	// listener that genuinely needs shell syntax sets this and writes
	// its patterns accordingly.
	AllowShellSyntax bool `yaml:"allow_shell_syntax"`
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
	// CommandRules read the file transfer families structurally and
	// hold each to what it may actually do, instead of to a pattern
	// over its command line. See SSHCommandRule.
	//
	// A rule is what makes allow_file_transfer_commands a decision
	// rather than a switch: instead of "scp and rsync, yes or no", a
	// rule says which direction, which paths and whether recursion,
	// and the command is read the way the program reads it before that
	// is applied.
	CommandRules []SSHCommandRule `yaml:"command_rules"`
	// Recording writes what a session showed, and optionally what was
	// typed into it, to a file per channel.
	Recording *SessionRecording `yaml:"recording"`
	// MFA requires a second factor after the key or the password: the
	// client is told authentication partially succeeded and must then
	// answer a keyboard-interactive prompt with a one-time code.
	MFA *MFAPolicy `yaml:"mfa"`
	// RequireGrant admits a session only against a live grant from the
	// access ledger: one somebody asked for, somebody else approved, and
	// that ends by itself. Needs the access section. See docs/CONFIG.md.
	RequireGrant bool `yaml:"require_grant"`
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

// SessionRecording records an interactive session to a file that can be
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
type SessionRecording struct {
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
	// Integrity hash-chains each recording into a manifest beside it, so
	// that a file edited after the session can be told from one that was
	// not.
	Integrity *RecordingIntegrity `yaml:"integrity"`
	// Encryption writes the recording as ciphertext, under a key from
	// custody, so a file taken off the host is unreadable.
	Encryption *RecordingEncryption `yaml:"encryption"`
}

// RecordingEncryption encrypts each recording at rest.
//
// A recording holds everything the session showed, which on an
// administrative session is the most valuable file on the machine: keys
// printed, configuration read, tokens echoed. The proxy writes them 0600
// into a directory an operator names, which protects them from another
// user on the same host and from nothing else -- not from a backup that
// leaves the building, not from a stolen disk, and not from somebody who
// reaches the file system with the proxy user's rights.
//
// With this the bytes on the disk are ciphertext (AES-256-GCM in framed
// chunks, the file key derived per recording from the configured key) and
// the name ends in .enc. It is a symmetric key, so whoever can read the
// key can read every recording it covers, and **a key that is lost is
// every recording lost**: rotating it does not re-encrypt what is already
// written, so the old key has to be kept for as long as the recordings it
// wrote are kept.
type RecordingEncryption struct {
	// Enabled turns encryption off where a section above turned it on;
	// it defaults to true wherever this section is present.
	Enabled *bool `yaml:"enabled"`
	// Key is a secret reference (a path, env:NAME, vault:path#field)
	// whose material the file key is derived from. Required: there is no
	// encryption without one.
	Key string `yaml:"key"`
	// ChunkBytes is how much of the recording one sealed frame covers.
	// Default 65536. It decides the overhead (sixteen octets a frame) and
	// the memory each open recording holds -- one chunk while it fills,
	// and one while a reader opens it -- so a gate with many sessions at
	// once has a reason to leave it where it is.
	ChunkBytes int `yaml:"chunk_bytes"`
}

// RecordingIntegrity writes a hash-chained manifest beside each
// recording.
//
// The access ledger is hash-chained and the recordings were not, which
// is the wrong way round for what the two are used for: the ledger says
// a session was approved, and the recording is the only account of what
// happened inside it. After an incident the recording is the artefact
// somebody is asked to stand behind, and a file that can be edited
// afterwards with nothing to show it had been is not evidence.
//
// The manifest is <recording>.chain, one JSON record per line, each
// carrying the previous record's hash and the digest of a run of the
// recording's bytes. Without a key that detects corruption, a shortened
// file and any partial edit by somebody who does not rewrite every
// record after it. With a key -- and the key is a secret reference, so
// it can live in a vault or an HSM rather than on the recording host --
// the records cannot be rewritten by somebody who holds filesystem
// access and not the key, which is the case that matters: an intruder
// on the box, or an administrator editing their own session. It is a
// MAC and not a signature, so anybody who can read the key can forge a
// record too.
type RecordingIntegrity struct {
	// Enabled turns the manifest off where a section above turned it on;
	// it defaults to true wherever this section is present.
	Enabled *bool `yaml:"enabled"`
	// Key is a secret reference (a path, env:NAME, vault:path#field)
	// whose material keys the chain. Without it the manifest is still a
	// chain and still detects corruption and truncation, and anybody who
	// can write the recording can recompute it.
	Key string `yaml:"key"`
	// SegmentBytes is how much of a recording one record covers, which is
	// how precisely an edit is located. Default 1048576.
	SegmentBytes int64 `yaml:"segment_bytes"`
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
	// ICAP hands written files to a scanning service.
	//
	// SFTP has no whole-file transfer: a file is a handle, a run of
	// writes at offsets, and a close. So the proxy holds the writes
	// rather than forwarding them, answers the client itself, scans
	// what the file turned out to be when the handle is closed, and
	// only then replays the writes to the server. A file the scanner
	// refuses never reaches it, at the cost of holding it in memory
	// until the close -- bounded by the service's max_body, past which
	// body_limit_action decides.
	ICAP *TransferICAP `yaml:"icap"`
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
	// MaxPayloadBytes bounds the payload of one PUBLISH. It is not
	// max_packet_size, which bounds the packet: a policy about payloads is
	// a policy about what a device sends, and a fleet whose telemetry is
	// two hundred octets has no business sending a megabyte. 0 leaves
	// max_packet_size to decide.
	MaxPayloadBytes int `yaml:"max_payload_bytes"`
	// Topics are per-topic rules: the payload bound, the QoS window and
	// whether retain is allowed, for the topics each entry names. The
	// first entry whose filters match the topic decides; a topic no entry
	// matches is left to the listener's own bounds.
	Topics []MQTTTopicRule `yaml:"topics"`
	// MaxQoS is the highest quality of service a publication or a
	// subscription may ask for, 0 to 2. Default 2. QoS 2 costs a broker
	// four packets and a stored state per message, which is what makes it
	// worth bounding on a fleet that does not need it.
	MaxQoS *int `yaml:"max_qos"`
	// Sparkplug is the Sparkplug B policy: the convention that turns MQTT
	// into an industrial protocol, and whose command messages are the
	// MQTT equivalent of a Modbus write.
	Sparkplug *MQTTSparkplug `yaml:"sparkplug"`
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
	// Learn records what crosses this listener and writes a proposed policy.
	Learn *MQTTLearn `yaml:"learn"`
}

// MQTTLearn is an mqtt listener's learning mode.
type MQTTLearn struct {
	// Enabled turns the recording on.
	Enabled bool `yaml:"enabled"`
	// File is where the report is written, as YAML. Required when enabled.
	File string `yaml:"file"`
	// Interval is how often it is rewritten. Default 5m; it is also written
	// when the listener shuts down.
	Interval Duration `yaml:"interval"`
	// MaxSubjects bounds the observations held: one per client, direction and
	// topic depth. Default 8192; past it the newest is dropped and the drops
	// are counted, because a learning run that quietly stopped learning is
	// worse than one that says so.
	MaxSubjects int `yaml:"max_subjects"`
	// Enforce keeps the policy in force while learning. Default false: a
	// learning run is normally observe-only, and saying so here is what stops
	// one being left on by accident.
	//
	// What it never relaxes is the packet, payload and subscription bounds, nor
	// a packet this proxy could not read: those are not policy.
	Enforce bool `yaml:"enforce"`
}

// MQTTTopicRule is what one set of topics may carry: how large a payload,
// which qualities of service, and whether a publication may be retained.
//
// It exists because those three are properties of the *topic* rather than
// of the listener. A command topic wants QoS at least 1 and a small
// payload; a firmware topic wants a large payload and retain; telemetry
// wants QoS 0 and neither. One bound for the listener would be the loosest
// of the three, which is the same as no bound.
type MQTTTopicRule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Filters are MQTT topic filters ("plant/+/control", "spBv1.0/#").
	// Required.
	Filters []string `yaml:"filters"`
	// MaxPayloadBytes bounds the payload of a publication to these
	// topics. 0 leaves the listener's own bound.
	MaxPayloadBytes int `yaml:"max_payload_bytes"`
	// MinQoS and MaxQoS bound the quality of service: min_qos 1 on a
	// command topic is "a command must be acknowledged", which is a
	// statement about the process and not about the transport.
	MinQoS *int `yaml:"min_qos"`
	MaxQoS *int `yaml:"max_qos"`
	// AllowRetain overrides the listener's own retain policy for these
	// topics: a configuration topic is the case where a retained message
	// is the point, and telemetry is the case where it is a device
	// leaving something behind.
	AllowRetain *bool `yaml:"allow_retain"`
}

// MQTTSparkplug is the Sparkplug B policy.
//
// Sparkplug B is the convention that makes MQTT an industrial protocol,
// and it belongs in a proxy for one reason: two of its message types,
// NCMD and DCMD, are commands to equipment. Everything else is telemetry
// going up. In most estates the list of publishers with any business
// sending a command is short and known, and the topic says which is which
// -- so a relay can enforce it, and a broker's own topic ACLs usually
// cannot tell a command from a reading.
//
// Two more things the convention states, which a relay can check: data
// from a node nobody has heard a birth from is out of order, and every
// message carries a sequence number that increments by one and wraps at
// 255, with a birth resetting it to zero.
//
// The metrics are not decoded. A Sparkplug payload is protobuf and the
// metric set is the plant's own; only the two top-level fields -- the
// timestamp and the sequence -- are read, and the rest is forwarded
// untouched.
type MQTTSparkplug struct {
	// Enabled turns the policy on. Without it a Sparkplug topic is an
	// ordinary topic and the publish and subscribe lists are all that
	// apply.
	Enabled bool `yaml:"enabled"`
	// Namespace is the first topic level. Default spBv1.0. A publication
	// under another namespace is refused when require_namespace is set.
	Namespace string `yaml:"namespace"`
	// RequireNamespace refuses a publication whose topic is not a
	// Sparkplug topic at all, which is how a listener is declared to
	// carry nothing but Sparkplug.
	RequireNamespace bool `yaml:"require_namespace"`
	// AllowMessageTypes are the types accepted. Empty accepts every type
	// the convention defines.
	AllowMessageTypes []string `yaml:"allow_message_types"`
	// CommandClients are the networks that may publish NCMD and DCMD --
	// the commands to equipment. Empty leaves commands to the ordinary
	// publish policy, and validation says so, because a Sparkplug
	// listener whose commands anybody may send is the case this section
	// exists for.
	CommandClients []string `yaml:"command_clients"`
	// RequireBirthBeforeData refuses NDATA or DDATA from an edge node no
	// birth has been seen from. It is the convention's own ordering, and
	// a relay is where it can be checked: the broker forwards whatever
	// arrives.
	RequireBirthBeforeData bool `yaml:"require_birth_before_data"`
	// CheckSequence refuses a message whose sequence number is not the
	// next one for its edge node. A gap or a repeat is a lost message, a
	// duplicated publisher, or somebody replaying one.
	CheckSequence bool `yaml:"check_sequence"`
	// MaxNodes bounds the edge nodes remembered for the birth and
	// sequence checks. Default 8192; the identifiers come off the network.
	MaxNodes int `yaml:"max_nodes"`
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
	// UpstreamResumption keeps TLS session tickets for encrypted
	// upstreams, so a reconnect resumes instead of running a full
	// handshake. Default true.
	//
	// It is most of the cost of DoT and DoQ on a resolver that
	// reconnects whenever an idle connection is dropped. Nothing is
	// replayable: the client sends no early data, and DoQ keeps 0-RTT
	// off. Turn it off for an upstream whose tickets are broken, or for
	// a policy that forbids resumption.
	UpstreamResumption *bool `yaml:"upstream_resumption"`
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
	// Records are records this resolver answers itself: SVCB and HTTPS
	// (most usefully the ECH configuration of a name this proxy
	// terminates), and A, AAAA, TXT and PTR.
	Records []DNSRecord `yaml:"records"`
	// DNS64 synthesises AAAA answers for IPv4-only names (RFC 6147), so
	// an IPv6-only client can reach an IPv4-only service through a
	// translator.
	DNS64 *DNS64 `yaml:"dns64"`
	// Views answer the same name differently by who asked: split
	// horizon. The first view whose networks contain the client wins; a
	// client in none of them gets this listener's own records and block
	// list.
	Views []DNSView `yaml:"views"`
	// RPZ are response policy zones: the file format a DNS threat feed
	// ships in, where the policy is in the records rather than in a key
	// per behaviour.
	RPZ *DNSRPZ `yaml:"rpz"`
	// TunnelDetection watches for data leaving inside the query names.
	TunnelDetection *DNSTunnel `yaml:"tunnel_detection"`
	// AnswerPolicy screens where an upstream answer points, which is
	// what a name list cannot do: rebinding and the cloud metadata
	// endpoint are good names pointing somewhere they should not.
	AnswerPolicy *DNSAnswerPolicy `yaml:"answer_policy"`
	// Cookies is what this listener does with DNS cookies (RFC 7873):
	// off, respond (the default) or require.
	//
	// A UDP datagram proves nothing about where it came from, and
	// everything unpleasant about an open resolver follows from that: an
	// answer sent to an address that did not ask, a small question
	// drawing a large reply for somebody else's link, a cache poisoned
	// by a race the attacker enters with no packets of their own to
	// lose, and a security event recorded against an address chosen by
	// whoever sent the packet. A cookie makes the client prove it can
	// receive what it asked for, which is the one thing underneath all
	// of them.
	//
	// respond answers a client that sent a cookie with one and never
	// refuses a query for the want of one, so a client that has never
	// heard of cookies is unaffected. require refuses a UDP query
	// without a valid cookie, which is the amplification defence and
	// also breaks every client that does not implement them: it belongs
	// on a listener whose clients are known.
	Cookies string `yaml:"cookies"`
	// CookieLifetime is how long a server cookie stays valid before the
	// client has to take a fresh one. Default 1h; a cookie past half its
	// life is replaced in the answer, so a client that keeps asking
	// never reaches the end of one.
	CookieLifetime Duration `yaml:"cookie_lifetime"`
	// Deception answers as a resolver that is not there: a query this
	// listener was going to refuse answered by a fabrication, or a whole
	// listener that is one. See DNSDeception.
	Deception *DNSDeception `yaml:"deception"`
	// ECS is what happens to a client's EDNS Client Subnet option on
	// the way upstream: strip (the default) or forward.
	//
	// strip, because the cache is keyed by the question and nothing
	// else. An answer tailored to one client's subnet would be stored
	// for every client of the listener, so a client that chooses the
	// subnet chooses what the next thousand are told. Forward it only
	// where the clients of this listener are one network.
	ECS string `yaml:"ecs"`
}

// DNSDeception answers as a DNS resolver that is not there.
//
// On this protocol the refusal is itself information, and the query that drew it
// is the only thing the other end ever sends. A name on a threat feed answered
// NXDOMAIN tells an implant that something here is deciding, and a tunnel told
// NXDOMAIN moves to another channel -- which is the channel nobody is watching.
// A fabricated answer does not: the name resolves, the client keeps going, and
// every query after the first is collected.
//
// Two things are specific to DNS and both are about not becoming a weapon.
//
// A resolver is an amplifier: a datagram proves nothing about its source, so a
// fabricated answer to a client whose address is unproved is bounded against the
// query that asked for it and truncated past that bound -- a real client comes
// back over TCP and a spoofed source cannot.
//
// And a fabricated address is somewhere a visitor then goes, so the default pool
// is the documentation range of RFC 5737 and RFC 3849, which nothing routes.
type DNSDeception struct {
	// Enabled turns the section off without removing it; it defaults to
	// true wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a query this listener was going to
	// refuse is answered by the fabrication instead) or decoy (the whole
	// listener is a fabricated resolver, with no upstreams).
	//
	// In mode answer the fabrication replaces the four refusals that say
	// "this name does not exist": the block list, an imported name list,
	// a response policy zone whose action is nxdomain, and the cooldown
	// on a domain a client was caught tunnelling under. It never replaces
	// an answer a rule named, and never a query on its way upstream.
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in
	// mode answer. In mode decoy an empty list means every client, which
	// is what a honeypot wants.
	Clients []string `yaml:"clients"`
	// Profile decides where a fabricated answer points, which on this
	// protocol is the whole of the shape: documentation (the default,
	// RFC 5737 and RFC 3849, which nothing routes), loopback (the
	// client's own machine, so an implant connects to itself) or
	// unroutable (0.0.0.0 and ::, the classic sinkhole).
	Profile string `yaml:"profile"`
	// Addresses replaces the profile's pools: one IPv4 prefix, one IPv6
	// prefix, or both.
	//
	// **A pool inside the estate is a pool a visitor is then sent to.**
	// Point it at a honeypot deliberately -- an http listener of this
	// proxy's own is a good answer -- and never at a host that does
	// something else.
	//
	// A name is answered with a different address from the pool each
	// time, stable for the life of the configuration. That is the
	// difference between this and sinkhole_ipv4: a sinkhole answers one
	// address for everything, which is how a sinkhole is recognised in
	// one extra lookup.
	Addresses []string `yaml:"addresses"`
	// TTL is the TTL a fabricated answer carries. Default 5m; 1s to 1h.
	// It is never zero: a zero TTL is a tell, and it also makes every
	// client ask again for every lookup.
	TTL Duration `yaml:"ttl"`
	// Tripwire are names -- a domain and its subdomains -- that raise a
	// dns_tripwire security event when a query asks for one.
	//
	// They are in addition to a built-in set, which is what nothing
	// legitimate asks a fabricated resolver: the fingerprint names
	// (version.bind, hostname.bind, id.server and the rest), a zone
	// transfer, a signature set, the NULL record type, a query in a
	// class that is not IN, and a name long enough to be the payload.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated values reproducible. Zero derives one
	// from the listener name, which is stable across restarts.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a fabricated value lasts, which
	// on this kind is the nonce a TXT answer is built from. Default 30s;
	// 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
}

// DNSAnswerPolicy screens the addresses an upstream answer carries.
//
// A block list decides by name, and the name is the part an attacker
// picks last: blocking one costs them a registration. The address is
// what they cannot move, because it is where they want the client to
// go, and two attacks live entirely there.
//
// DNS rebinding answers a name the attacker owns with a public address
// while the page loads and with 127.0.0.1 a moment later, and a browser
// keeps calling the two one origin. The cloud metadata endpoint at
// 169.254.169.254 hands instance credentials to any process that can
// make an HTTP request, so a name resolving there turns "fetch this
// URL" into "read my keys". Neither is a name a list could hold.
type DNSAnswerPolicy struct {
	// DenyPrivate denies every range RFC 6890 calls not globally
	// reachable, and the IPv4-mapped IPv6 range with them. Default
	// true: a section written at all is written to deny these.
	DenyPrivate *bool `yaml:"deny_private"`
	// Deny are further CIDRs to refuse, in either family.
	Deny []string `yaml:"deny"`
	// Allow are carved back out of the denied set: the ranges this
	// network really does resolve names into. An operator writes
	// deny_private and names their own /16 here rather than
	// enumerating what is left of RFC 6890.
	Allow []string `yaml:"allow"`
	// AllowNames are the names allowed to point into a denied range,
	// in the forms block takes. A split-horizon zone belongs here;
	// both the name asked for and the owner name of the record are
	// matched, so exempting either end of a CNAME is enough.
	AllowNames []string `yaml:"allow_names"`
	// Action is nxdomain (default), refuse, servfail or strip. strip
	// removes the denied records and keeps the rest, for a name that
	// legitimately has a public address as well as an internal one;
	// what is left may be an empty answer, which is the correct thing
	// to say.
	Action string `yaml:"action"`
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
	// Type is https (default), svcb, a, aaaa, txt or ptr.
	//
	// a and aaaa are what a split-horizon view needs: the same name
	// answered with an internal address inside the estate and left to
	// the upstream everywhere else. A name in this set is answered
	// authoritatively for the types it holds and NODATA for the ones it
	// does not, and is never forwarded -- an upstream answer would
	// contradict the local one.
	Type string `yaml:"type"`
	// Address is the address of an a or aaaa record.
	Address string `yaml:"address"`
	// Text is the string of a txt record, or the target name of a ptr
	// record.
	Text string `yaml:"text"`
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

// DNS64 is RFC 6147 address synthesis on a dns listener: an AAAA query
// for a name that has only an A record is answered with that IPv4 address
// embedded in a prefix (RFC 6052) routed to a translator.
//
// The answer is one this resolver invented, which is why the address
// policy sees the IPv4 address before it is embedded rather than the
// synthesised address afterwards: 64:ff9b::7f00:1 is not inside
// 127.0.0.0/8 and no prefix list would catch it, but it is 127.0.0.1 to
// everything past the translator. A synthesised answer also carries no
// AD bit, because there is nothing signed about it.
type DNS64 struct {
	// Prefix is the translation prefix. Default 64:ff9b::/96, the
	// well-known prefix of RFC 6052; a network-specific prefix must be a
	// /32, /40, /48, /56, /64 or /96, which are the only lengths with a
	// defined place to put the address.
	Prefix string `yaml:"prefix"`
	// Clients are the networks this applies to; empty is every client of
	// the listener. Name the IPv6-only networks: a dual-stack client
	// handed a synthesised address reaches the service the long way
	// round, through the translator, for no reason.
	Clients []string `yaml:"clients"`
	// TTL overrides the TTL of a synthesised record; 0 keeps the A
	// record's own, which is what RFC 6147 prefers.
	TTL int `yaml:"ttl"`
}

// DNSView is a client-scoped answer set on a dns listener: split
// horizon. One name with two answers is an ordinary requirement -- a
// private address inside the estate and a public one outside, a
// laboratory network pointed at the test system, a guest network held to
// a stricter list.
//
// A view decides only what this resolver settles before it asks anything:
// the records it answers itself and the names it refuses. It has no
// upstream of its own on purpose: two views with different upstreams
// would answer the same question differently out of one shared cache,
// and a cache per view is a second resolver -- which is a second
// listener, said plainly, rather than hidden inside a view.
// DNSRPZ configures response policy zones read from zone files. Zones
// are tried in order, so a local exception zone goes in front of a
// subscription.
type DNSRPZ struct {
	// Refresh is how often a zone file's size and modification time are
	// checked. Unset takes 5m; 0 means never, and then a reload is what
	// picks a feed up.
	Refresh *Duration `yaml:"refresh"`
	// Zones are the policy zones, in order.
	Zones []DNSRPZZone `yaml:"zones"`
}

// RefreshInterval is the configured interval or the default.
func (r *DNSRPZ) RefreshInterval() time.Duration {
	if r == nil {
		return 0
	}
	if r.Refresh == nil {
		return 5 * time.Minute
	}
	return r.Refresh.D()
}

// DNSRPZZone is one zone file.
type DNSRPZZone struct {
	// Name identifies the zone in the access log, the security log and
	// the status view.
	Name string `yaml:"name"`
	// File is the zone file, in the master format a feed publishes.
	File string `yaml:"file"`
	// Action replaces every rule's own action: nxdomain, nodata,
	// passthru, drop, tcp_only, or "zone" (the default) to honour what
	// the file says. An override is how a new feed is tried out.
	Action string `yaml:"action"`
	// IgnoreUnsupported loads a zone that carries a trigger this
	// resolver does not implement (rpz-ip, rpz-client-ip, rpz-nsdname,
	// rpz-nsip), skipping those rules and counting them. Without it such
	// a zone fails the load, because a policy that half applies is worse
	// than one that does not load.
	IgnoreUnsupported bool `yaml:"ignore_unsupported"`
}

type DNSView struct {
	// Name identifies the view in the access log (as `view`) and in the
	// status view.
	Name string `yaml:"name"`
	// Clients are the networks this view serves. Required: a view that
	// matched everybody would be the listener's own policy with another
	// name.
	Clients []string `yaml:"clients"`
	// Records replace the listener's own record set while this view is
	// selected; empty keeps it.
	Records []DNSRecord `yaml:"records"`
	// Block, BlockFile and BlockAction replace the listener's block
	// list and what a block answers; empty keeps them.
	Block       []string `yaml:"block"`
	BlockFile   string   `yaml:"block_file"`
	BlockAction string   `yaml:"block_action"`
	// SinkholeIPv4 and SinkholeIPv6 replace the sinkhole addresses of
	// this view's own block_action.
	SinkholeIPv4 string `yaml:"sinkhole_ipv4"`
	SinkholeIPv6 string `yaml:"sinkhole_ipv6"`
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
	// AggressiveNSEC answers a name that a validated NSEC record already
	// placed inside an empty gap without asking the upstream again
	// (RFC 8198). Default false.
	//
	// The traffic it saves is the traffic that produces it:
	// random-subdomain floods and junk top-level queries, where every
	// name is a sibling of the last and one signed proof covers them all.
	//
	// It is narrowed on purpose. A proof is reused only for a sibling of
	// the name it was collected for -- same parent, therefore the same
	// closest encloser and the same wildcard denial the validator already
	// checked -- and only for a client that did not set DO, since a
	// synthesised NXDOMAIN carries no signatures and a client that asked
	// for them should get them.
	AggressiveNSEC bool `yaml:"aggressive_nsec"`
	// NSECEntries bounds the parents whose proofs are remembered.
	// Default 8192.
	NSECEntries int `yaml:"nsec_entries"`
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
	// ServeStale keeps an expired entry this much longer so it can be
	// served when the upstream has nothing (RFC 8767). Default 0, which
	// keeps nothing; 1h is a reasonable window.
	//
	// It is the difference between a resolver outage taking the network
	// with it and a resolver outage nobody notices for an hour. The
	// answer is out of date by definition, and a name almost always
	// still resolves where it did a minute ago -- while a client that
	// cannot be told anything cannot reach the upstream itself either.
	ServeStale Duration `yaml:"serve_stale"`
	// StaleTTL is the TTL a stale answer carries, so the client comes
	// back soon rather than keeping an answer this resolver already
	// knows is old. Default 30s, which is what RFC 8767 recommends.
	StaleTTL Duration `yaml:"stale_ttl"`
	// Prefetch refreshes a nearly expired entry when a query arrives
	// for it, instead of making one client per TTL wait for the
	// upstream. Default false.
	Prefetch bool `yaml:"prefetch"`
	// PrefetchThreshold is the share of the TTL that must be left for a
	// query to start a refresh. Default 0.1; at most 0.5, because
	// refreshing an entry with half its life left is a resolver doing
	// twice the upstream traffic for nothing.
	PrefetchThreshold float64 `yaml:"prefetch_threshold"`
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
	// SessionTimeout bounds a whole connection however active. Default
	// 0, no bound. A listener with no parser in the path has only time
	// and bytes to bound a session with, because nothing here can say
	// what the connection is doing.
	SessionTimeout Duration `yaml:"session_timeout"`
	// MaxBytesIn bounds what one connection relays from the client and
	// MaxBytesOut what it relays back. Past either the connection is
	// closed, rather than the stream being truncated: a relay that
	// silently stopped forwarding would look to both peers like a
	// network that had gone quiet. Both default 0, no bound.
	MaxBytesIn  int64 `yaml:"max_bytes_in"`
	MaxBytesOut int64 `yaml:"max_bytes_out"`
	// ProxyProtocol sends a PROXY protocol v2 header to the upstream with
	// the client address.
	ProxyProtocol bool `yaml:"proxy_protocol"`
	// MaxConnections bounds open connections on this listener (in
	// addition to the global limits). Default 10000.
	MaxConnections int `yaml:"max_connections"`
	// Transparent makes the upstream connection carry the client's own
	// source address, for an upstream that must see the client and has
	// no PROXY protocol to read it from.
	Transparent bool `yaml:"transparent"`
	// OriginalDestination takes the target from the socket rather than
	// from routes or default: a transparently intercepted connection was
	// addressed to some service and a routing rule put it on this
	// listener, so which upstream is not a configuration question.
	//
	// With it, allow_destinations is required: a listener that dials
	// whatever the firewall hands it, with nothing to say where that may
	// be, is a relay to anywhere for anyone who can reach the port.
	OriginalDestination bool `yaml:"original_destination"`
	// AllowDestinations are the CIDRs an original destination may be in,
	// and DestinationPorts the ports; empty ports allow any.
	AllowDestinations []string `yaml:"allow_destinations"`
	DestinationPorts  []int    `yaml:"destination_ports"`
	// ConnectTimeout bounds the dial to an original destination, which
	// has no upstream pool to take a timeout from. Default 10s.
	ConnectTimeout Duration `yaml:"connect_timeout"`
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

// UDPListener is a generic datagram relay: the symmetric primitive to
// kind: tcp for services whose protocol this proxy does not parse.
//
// A datagram has no connection, so the relay keeps a session table
// instead. The first datagram from a client address picks an endpoint
// through the pool's balancer and opens a connected socket towards it;
// every later datagram from that address goes to the same endpoint, and
// what the endpoint sends back goes to that address. The session ends
// when it has been idle, when it hits a bound, or at shutdown. Nothing
// in the payload is read: a kind: udp listener is a router and a set of
// bounds, not a parser.
//
// The thing to get right about a UDP relay is that it is a reflector.
// Anyone can put anybody's address in a datagram's source, so an open
// relay answers a victim with traffic the victim never asked for, at
// whatever gain the service behind it provides. That is why
// allow_clients and rate_limit exist here and why validation insists on
// one of them for a listener on a public address. The session table is
// bounded for the same reason: spoofed sources must not be able to fill
// it, which is what max_sessions_per_ip is for.
type UDPListener struct {
	// Upstream is the pool of endpoints. Required.
	Upstream string `yaml:"upstream"`
	// IdleTimeout ends a session with no datagram in either direction.
	// Default 30s. It is what stands in for a connection close, since
	// nothing in the protocol says a client has finished.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// SessionTimeout bounds a whole session however active. Default 0,
	// no bound.
	SessionTimeout Duration `yaml:"session_timeout"`
	// MaxSessions bounds the session table. Default 10000. A datagram
	// from a new client when the table is full is dropped and counted:
	// there is no way to refuse a datagram, because a refusal would be
	// a datagram to an address that may not have sent anything.
	MaxSessions int `yaml:"max_sessions"`
	// MaxSessionsPerIP bounds sessions from one address, which is what
	// keeps a single source -- or a single forged source -- from
	// filling the table. Default 64; 0 removes the bound.
	MaxSessionsPerIP int `yaml:"max_sessions_per_ip"`
	// MaxDatagramBytes is the largest datagram relayed in either
	// direction. Default 65535, which is the largest a UDP socket
	// carries. A larger one is dropped and counted rather than
	// truncated, because half a datagram is not a shorter datagram.
	MaxDatagramBytes int `yaml:"max_datagram_bytes"`
	// MaxDatagrams bounds the datagrams of one session, both directions
	// together. MaxBytesIn bounds what the session relays from the
	// client and MaxBytesOut what it relays back, the same two names a
	// kind: tcp listener uses. Past any of them the session ends and is
	// counted. All default 0, no bound.
	MaxDatagrams int64 `yaml:"max_datagrams"`
	MaxBytesIn   int64 `yaml:"max_bytes_in"`
	MaxBytesOut  int64 `yaml:"max_bytes_out"`
	// RateLimit bounds datagrams per second from one source address.
	// Without it a single source can drive the whole relay.
	RateLimit *UDPRateLimit `yaml:"rate_limit"`
	// AllowClients restricts clients to these CIDRs. On a public
	// address this or rate_limit is what stops the listener being
	// somebody else's amplifier.
	AllowClients []string `yaml:"allow_clients"`
}

// UDPRateLimit bounds datagrams per second from one source address.
type UDPRateLimit struct {
	// PPS is datagrams per second. Required when the section is set.
	PPS float64 `yaml:"pps"`
	// Burst is how many may arrive at once. Default is PPS rounded up.
	Burst int `yaml:"burst"`
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
	// ClientAuth is one of none, request, require and require_any. Default
	// none.
	//
	// The first three take a client_ca_file and mean what they say: ask and
	// check if given, or demand and check. require_any demands a certificate
	// and checks it against *nothing*, which is only ever right where
	// something else decides whether the peer is anybody -- and the one place
	// that is true here is a coap listener with a public_keys table, where the
	// key inside the certificate is pinned by the table and there is no
	// authority in the picture at all (RFC 7252 s9.1.3.2's raw public key
	// mode). Validation refuses it anywhere else, because a certificate
	// nobody verified is not an identity.
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
	// Expiry decides what an expired certificate does. Without it an
	// expired certificate is served and every client fails the
	// handshake on its own, which is an outage nobody can read.
	Expiry *CertExpiry `yaml:"expiry"`
}

// CertExpiry is what a listener does about a certificate that has
// expired, or is about to.
//
// A certificate outliving its validity is not an exotic failure: it is
// the single most common way a working service stops working. What the
// proxy can do about it is limited -- it cannot issue a new one, and
// serving an expired certificate is not a security hole, because the
// client is the one that decides whether to trust it. What it can do is
// say so, loudly and in one place, rather than leaving every client to
// discover it separately.
//
// So the refusal is opt-in and it is about *starting*: a certificate
// already expired when the configuration is loaded is a configuration
// error with refuse_expired, and a reload that would install one is
// refused, which is the case where refusing is strictly better than
// serving -- the old certificate keeps working. A certificate that
// expires while the proxy is running is reported and counted, never
// unloaded, because a listener that stops answering is worse than one
// answering with a certificate clients will reject for themselves.
type CertExpiry struct {
	// RefuseExpired makes a certificate that has already expired a load
	// error rather than something to serve.
	RefuseExpired bool `yaml:"refuse_expired"`
	// Warn is how long before expiry to start warning. Default 336h
	// (fourteen days); zero with an expiry section means no warning.
	Warn Duration `yaml:"warn"`
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
	// Key is where the private key comes from when it is not a plain file on
	// this machine: a reference (file:, env: or vault:). Exactly one of
	// key_file, key and signer is required.
	Key string `yaml:"key"`
	// Signer holds the private key in another process: the proxy sends a
	// digest over a Unix socket and gets a signature back, so the material
	// never enters this address space at all. That is where an HSM through
	// PKCS#11, a TPM or a smartcard belongs -- each needs cgo or a device,
	// and both are better outside the thing that terminates TLS.
	Signer *CertSigner `yaml:"signer"`
}

// CertSigner is the helper that holds a certificate's private key.
type CertSigner struct {
	// Socket is the Unix socket the helper listens on.
	Socket string `yaml:"socket"`
	// Key names which key the helper should use, since one helper may hold
	// several.
	Key string `yaml:"key"`
	// Timeout bounds one signature. It is on the handshake path: a helper
	// that hangs must fail a handshake rather than hold one. Default 3s.
	Timeout Duration `yaml:"timeout"`
	// MaxConns bounds the connections held to the helper, which is the
	// parallelism of signing. Default 8.
	MaxConns int `yaml:"max_conns"`
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
	// body_rewrite, wasm, the SAML assertion consumer endpoint, the WAF's
	// body inspection, a virtual patch's body pattern, a mirrored
	// request). Default 512 MiB; 0 is
	// unbounded.
	//
	// Each of those is bounded per request, and the product was the real
	// ceiling: max_connections_per_ip times max_body_bytes is about
	// 2.5 GiB of heap from one address at the defaults, sent slowly
	// enough to stay inside read_timeout. A request that does not fit
	// the budget is refused with 503 rather than buffered.
	MaxBufferedBodyBytes int64 `yaml:"max_buffered_body_bytes"`
	// ConnectionRate bounds how fast connections are accepted across
	// every listener, and ConnectionRatePerSource how fast from one
	// source network. Both are off by default.
	//
	// They are the bound max_connections does not give. A concurrency
	// limit says how many connections may be open at once and nothing
	// about churn: a client that connects, makes the server do the
	// expensive half of a handshake and disconnects never holds two
	// connections and can still cost a core. A listener sets its own in
	// its connection_rate sections, which replace these for it.
	ConnectionRate          *ConnectionRate `yaml:"connection_rate"`
	ConnectionRatePerSource *SourceRate     `yaml:"connection_rate_per_source"`
}

// ConnectionRate bounds accepts per second.
type ConnectionRate struct {
	// PerSecond is the sustained rate. Required when the section is set.
	PerSecond float64 `yaml:"per_second"`
	// Burst is how many may arrive at once. Default is PerSecond
	// rounded up, which is one second's worth.
	Burst int `yaml:"burst"`
}

// SourceRate bounds accepts per second from one source network.
//
// The key is a network rather than an address on purpose: an attacker
// with a /64 of IPv6 has more addresses than any table could hold, so a
// per address bound is no bound at all, while a per address table is
// itself the thing that fills up.
type SourceRate struct {
	PerSecond float64 `yaml:"per_second"`
	Burst     int     `yaml:"burst"`
	// IPv4Prefix and IPv6Prefix are the network sizes the rate is
	// counted over. Defaults 32 and 64: one IPv4 address, and the
	// smallest IPv6 block an operator is normally given.
	IPv4Prefix int `yaml:"ipv4_prefix"`
	IPv6Prefix int `yaml:"ipv6_prefix"`
	// MaxSources bounds the table of tracked networks. Default 65536.
	MaxSources int `yaml:"max_sources"`
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
	// Locality prefers the endpoints in this node's own zone.
	Locality *Locality `yaml:"locality"`
	// AddressFamily decides which of a dual-stack endpoint's addresses
	// may be dialled: any (the default), ipv4 or ipv6.
	//
	// With any, the two families are raced as RFC 8305 describes -- the
	// first family is tried, and after FallbackDelay the other is tried
	// in parallel, with whichever connects first winning. That is what
	// keeps a host whose IPv6 route is broken from costing a connect
	// timeout on every request, and it is the default because an estate
	// that has just turned IPv6 on should not have to know about it.
	//
	// ipv4 or ipv6 is for the estate where one family is the only one
	// that works: it dials that family only, so a name with both kinds
	// of record does not silently use the one the policy meant to
	// exclude.
	AddressFamily string `yaml:"address_family"`
	// FallbackDelay is how long the second family is held back in the
	// race. Default 300ms, the value RFC 8305 recommends; a negative
	// value disables the race, so the families are tried in order.
	// Ignored when AddressFamily names one family.
	FallbackDelay Duration `yaml:"fallback_delay"`
	// NodeZone is server.zone, copied here when defaults are applied so
	// that a pool knows where it is running without being handed the
	// whole configuration. It is not a key of its own: an upstream's
	// zone is the node's, and two answers to that question would be one
	// too many.
	NodeZone string `yaml:"-"`
	// MaxConnectionAge bounds how long one upstream connection is kept,
	// so that a pool's traffic follows its endpoints rather than
	// sticking to whichever ones were there when the connections were
	// made: a keep-alive connection can outlive a deploy, a scale-out
	// and an endpoint's whole useful life, and every request on it goes
	// where that connection goes.
	//
	// It does not close anything mid-exchange. A connection past the
	// age is closed at the end of the exchange that found it, so it is
	// never reused and nothing in flight is cut.
	//
	// That end only exists for HTTP/1.1, where a connection carries one
	// exchange at a time; an HTTP/2 or HTTP/3 connection carries many
	// streams at once and is never between exchanges, so the bound does
	// not apply to one and validation warns where it would be ignored.
	// 0 is no bound.
	MaxConnectionAge Duration `yaml:"max_connection_age"`
	// MaxConnectionsPerEndpoint is the default for every endpoint's own
	// max_connections. An endpoint that names one uses that instead.
	MaxConnectionsPerEndpoint int `yaml:"max_connections_per_endpoint"`
	// Maintenance takes the whole pool out of rotation: it offers no
	// endpoint, so a route over it answers as it does when everything
	// is unhealthy. For the planned outage of a whole service, where
	// draining each endpoint would be a list to keep in step with the
	// pool. As with an endpoint's drain, the management API overrides
	// this until the daemon restarts.
	Maintenance bool `yaml:"maintenance"`
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
	// MaxConnections bounds the requests or connections in flight to
	// this endpoint at once. Past it the endpoint is passed over as if
	// it were unavailable, and the pool's other endpoints take the
	// work; when every endpoint is at its bound the caller sees what it
	// sees when every endpoint is unhealthy.
	//
	// It is for the endpoint that cannot take what the pool can give
	// it: a small instance beside large ones, a database-bound service
	// with a connection pool of its own, a machine that answers slowly
	// under load rather than refusing. 0 is no bound, and
	// upstreams[].max_connections_per_endpoint sets it for a whole pool
	// at once.
	MaxConnections int `yaml:"max_connections"`
	// Priority tiers the endpoint. The pool uses the endpoints of the
	// lowest priority number that has an available member and ignores
	// the rest; when every endpoint of that tier is unavailable, the
	// next tier takes the traffic. 0 is the first tier.
	//
	// It is how a failover pool is written: the endpoints that should
	// carry the traffic at priority 0, the ones that should carry it
	// only when those are gone at priority 1. A backup endpoint is
	// simply one in a later tier.
	Priority int `yaml:"priority"`
	// Zone names the failure domain this endpoint is in, for a pool with
	// a locality policy. An endpoint with no zone is neutral: it is
	// preferred wherever the node is, because "somewhere unknown" is not
	// a reason to send traffic across a site.
	Zone string `yaml:"zone"`
	// Drain takes the endpoint out of rotation while leaving it in the
	// pool: no new work, and what is already running finishes. It is
	// the declarative form of what the management API sets, for a
	// machine that is out of service for long enough to be written
	// down. A decision made through the API overrides this one until
	// the daemon restarts, because the person who made it knew
	// something the file did not.
	Drain bool `yaml:"drain"`
}

// Discovery resolves a pool's endpoints from DNS or an HTTP registry.
type Discovery struct {
	// Type is dns (A and AAAA records of Name, each with Port), srv (SRV
	// records of Name; targets and ports come from the records, the lowest
	// priority group is used and record weights become endpoint weights),
	// http (Name is a URL polled on the interval; see Format) or consul
	// (a Consul agent asked about a service; see Consul).
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
	// MaxEndpoints bounds how many endpoints one resolution may install.
	// A registry is a remote input: a DNS answer with thousands of A
	// records, or a registry response filled with entries, would
	// otherwise become thousands of health check goroutines and a hash
	// ring rebuilt around them. Beyond the bound the resolution is
	// truncated (lowest addresses first, so the set is stable between
	// resolutions), warned about and counted. Default 4096; 1 to 65536.
	MaxEndpoints int `yaml:"max_endpoints"`
	// Consul configures type consul.
	Consul *ConsulDiscovery `yaml:"consul"`
}

// ConsulDiscovery asks a Consul agent which instances of a service are
// healthy, and -- this being the point of a native type rather than a
// polled URL -- uses Consul's blocking queries, so a change is learned
// when it happens rather than at the next interval.
//
// A blocking query is an ordinary request that the agent holds open until
// something changes or the wait expires, and answers with an index the
// next request carries. The effect is a long poll: an instance that goes
// away is out of the pool in about the time it takes Consul to notice,
// instead of up to an interval later. The interval is still there as the
// period between attempts when the agent is unreachable, and as a
// ceiling on how long one query may be held.
type ConsulDiscovery struct {
	// Address is the agent, host:port. Default 127.0.0.1:8500 -- a
	// Consul deployment runs an agent on every node, and asking the
	// local one is both faster and what survives a partition.
	Address string `yaml:"address"`
	// Service is the name to ask about. Required.
	Service string `yaml:"service"`
	// Tag narrows it to the instances carrying that tag, which is how a
	// Consul estate usually separates environments or versions.
	Tag string `yaml:"tag"`
	// Datacenter asks about another datacenter than the agent's own.
	Datacenter string `yaml:"datacenter"`
	// TokenFile holds the ACL token, sent as X-Consul-Token. A token is
	// a credential, so it lives in a file the proxy user can read and
	// not in this document -- which is dumped by the management API and
	// kept in the configuration history.
	TokenFile string `yaml:"token_file"`
	// TLS reaches an agent over HTTPS. Without it the scheme is http,
	// which for a local agent over loopback is the usual arrangement.
	TLS *UpstreamTLS `yaml:"tls"`
	// AllowStale lets the agent answer from its own state without asking
	// a server, which is faster and may be a moment behind. Off by
	// default: a load balancer acting on stale membership sends traffic
	// to an instance that has gone.
	AllowStale bool `yaml:"allow_stale"`
	// Wait is how long one blocking query may be held open. Default 5m,
	// which is Consul's own; the agent adds jitter of its own accord.
	Wait Duration `yaml:"wait"`
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
	// Type is http (GET path, expected_status), grpc (the standard
	// grpc.health.v1 Check over HTTP/2, needs h2c or https), tcp (the
	// connect succeeds) or udp (a datagram is sent and an answer comes
	// back). Default http.
	//
	// The last two are for the pools a layer 4 listener uses, where
	// there is no request to make. tcp proves the port accepts; udp has
	// to prove more than that, because a UDP socket accepts nothing and
	// a closed port is only sometimes reported -- so a udp check sends
	// something the service answers, and silence is the failure.
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
	// Send is what a udp probe sends, as text; SendHex the same as
	// hexadecimal, for the services whose smallest question is not text
	// (a DNS query, a RADIUS request, a game server's ping). Exactly one
	// is required for type udp: a probe that sends nothing learns
	// nothing, because a UDP service answers a question and there is no
	// handshake to observe instead.
	Send    string `yaml:"send"`
	SendHex string `yaml:"send_hex"`
	// Expect requires the answer to contain this text, ExpectHex the
	// same as hexadecimal. Both empty accepts any answer at all, which
	// is already much more than silence proves.
	Expect    string `yaml:"expect"`
	ExpectHex string `yaml:"expect_hex"`
}

// Locality prefers the endpoints in the node's own zone (server.zone)
// over the ones elsewhere, which is what keeps traffic off the links
// between sites and away from their latency -- while still using the
// other sites when this one has nothing left.
//
// It is expressed as a preference rather than a restriction on purpose:
// an estate that pinned traffic to one zone would lose a service
// entirely when that zone lost it, which is the opposite of what zones
// are for.
type Locality struct {
	// PreferZone turns the preference on. Without server.zone set there
	// is nothing to compare against, and validation says so.
	PreferZone bool `yaml:"prefer_zone"`
	// MinLocal is how many endpoints of this node's own zone must be
	// available before the others are ignored. Below it the pool uses
	// every endpoint, so a zone with one surviving endpoint does not
	// take the whole load alone. Default 1.
	MinLocal int `yaml:"min_local"`
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
	// ClientCertHeaders states the client's TLS certificate to the
	// backend: none (the default), rfc9440 (Client-Cert and
	// Client-Cert-Chain, RFC 9440) or xfcc (Envoy's
	// X-Forwarded-Client-Cert).
	//
	// Whatever this says, a client's own copy of any of those headers is
	// removed from every request that did not arrive from a peer inside
	// trusted_proxies: the backend cannot tell the proxy's header from
	// the client's, so a client that can send one chooses its own
	// identity.
	ClientCertHeaders string `yaml:"client_cert_headers"`

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
	// ClientPriority says what to do with a client's RFC 9218 Priority
	// header: ignore (default) or lower, which lets a stated urgency
	// above the default move this request down the shedding order. It
	// can only ever lower: a header that could raise a request's class
	// would be a promotion anybody can ask for, and shedding would then
	// protect whoever claimed urgency rather than whatever the operator
	// called important.
	ClientPriority string `yaml:"client_priority"`
	// EarlyHints says what to do with the upstream's 1xx informational
	// responses, of which 103 Early Hints (RFC 8297) is the one in use:
	// pass (default) relays them to the client, strip drops them.
	EarlyHints string `yaml:"early_hints"`
	// EarlyData says what to do with a request that arrived as
	// unconfirmed TLS early data, which a terminating proxy in front
	// marks with Early-Data: 1 (RFC 8470): safe_methods (default) answers
	// 425 Too Early to anything but a safe method, reject answers 425 to
	// all of it, allow passes it through. Early data can be replayed by
	// whoever captured it, and this proxy cannot know what a second POST
	// would do.
	EarlyData string `yaml:"early_data"`
	// Ranges bounds byte range requests on this route. Without the
	// section a Range header is relayed as it arrived.
	Ranges *RouteRanges `yaml:"ranges"`
	// ThreatIntel applies the imported lists to this route. Default
	// true; false exempts it, which is what a health endpoint or a
	// status page wants -- a list with one wrong line in it should not
	// take the thing an operator watches the outage with.
	ThreatIntel *bool `yaml:"threat_intel"`
	// Trailers says what to do with the response's trailers: pass
	// (default) or strip. gRPC carries its status in them, so a gRPC
	// route cannot strip them.
	Trailers string `yaml:"trailers"`
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

// RouteRanges bounds byte range requests (RFC 9110 section 14).
//
// A Range header is a small request that asks for a large answer, and a
// set of ranges is a small request that asks for many: each range costs
// the origin a read and the response a multipart part, so a few hundred
// of them in one header is the oldest amplification bug in HTTP. RFC 9110
// section 14.2 leaves the decision to the server, which may coalesce
// overlapping and adjacent ranges in any order, or ignore a set it will
// not satisfy -- so this rewrites the set rather than inventing a rule:
// the same bytes, fewer parts.
type RouteRanges struct {
	// MaxRanges is how many ranges a set may still hold after
	// coalescing. Default 4, which is a resuming download or a media
	// player seeking; 0 means the default, and up to 1024 is accepted
	// for a route that really serves such clients.
	MaxRanges int `yaml:"max_ranges"`
	// Coalesce merges overlapping and adjacent ranges into the fewest
	// that cover the same bytes, and sorts them. Default true. It is
	// explicitly a server's right (RFC 9110 section 14.2), and it is what
	// turns most oversized sets into one range rather than a refusal.
	Coalesce *bool `yaml:"coalesce"`
	// Action is what happens to a set still over MaxRanges after that:
	// ignore (default) drops the header, so the whole representation is
	// served, which is what RFC 9110 permits a server that will not
	// satisfy the set to do; refuse answers 416 with Accept-Ranges, so a
	// client can ask again for fewer.
	Action string `yaml:"action"`
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
// SCIM is the provisioning endpoint. It is answered before routing, like
// the virtual security.txt, so the endpoint needs no route of its own and
// cannot be taken away by one.
//
// The endpoint is an administrative interface with the power to create
// and destroy credentials, which is why it carries its own token and its
// own address list rather than borrowing a route's: a provisioning
// endpoint reachable from the internet is an account factory.
type SCIM struct {
	// Path is the base the endpoints hang off. Default "/scim/v2"; the
	// provider is given this plus "/Users".
	Path string `yaml:"path"`
	// Hosts are exact names or wildcard patterns the endpoint answers
	// on. Empty answers on every host, which validation advises
	// against.
	Hosts []string `yaml:"hosts"`
	// Listeners restrict the endpoint to these listener names.
	Listeners []string `yaml:"listeners"`
	// ClientCIDRs restrict it to clients inside these networks. Empty
	// allows every client, which validation advises against.
	ClientCIDRs []string `yaml:"client_cidrs"`

	// TokenFile holds the bearer token the provider presents, one line.
	// Required: this endpoint is never open.
	TokenFile string `yaml:"token_file"`
	// StateFile holds the provisioned resources. It is not the
	// credentials: those live in the enrolment and key files, and a
	// resource has to survive a deactivation that takes both away.
	StateFile string `yaml:"state_file"`
	// MFAUsersFile is the enrolment file a second factor is provisioned
	// in, the same file the mfa filter and the gate listeners read.
	MFAUsersFile string `yaml:"mfa_users_file"`
	// KeysFile is the API key file a key is issued in and revoked in,
	// the same file the api_key filter reads.
	KeysFile string `yaml:"keys_file"`
	// KeyScopes are the scopes an issued key gets when the request
	// names none.
	KeyScopes []string `yaml:"key_scopes"`
	// KeyTTL expires an issued key. Unset never expires it.
	KeyTTL *Duration `yaml:"key_ttl"`
	// Issuer names this estate in the otpauth enrolment URI. Default
	// "xproxy".
	Issuer string `yaml:"issuer"`
	// ReturnSecrets lets a response carry the credentials it just made:
	// the enrolment URI, the recovery codes and the key plaintext. Off
	// by default, because they then exist wherever the provider keeps
	// its logs.
	ReturnSecrets *bool `yaml:"return_secrets"`
	// MaxResults bounds a page and is reported in the service provider
	// configuration. Default 100.
	MaxResults int `yaml:"max_results"`
	// ExternalURL is the base the provider reaches this endpoint at,
	// with scheme and host. Locations in the responses are built from
	// it; without it they are built from the request, which is wrong
	// behind a terminator this proxy is not.
	ExternalURL string `yaml:"external_url"`
}

// SCIMPath is the base path when none is configured.
const SCIMPath = "/scim/v2"

// Base returns the configured base path, or the default.
func (s *SCIM) Base() string {
	if s == nil || s.Path == "" {
		return SCIMPath
	}
	return s.Path
}

// Secrets says whether a response may carry the credentials it made.
func (s *SCIM) Secrets() bool { return s != nil && s.ReturnSecrets != nil && *s.ReturnSecrets }

// Results is the page bound.
func (s *SCIM) Results() int {
	if s == nil || s.MaxResults == 0 {
		return 100
	}
	return s.MaxResults
}

// TTL is the expiry an issued key gets, and zero for none.
func (s *SCIM) TTL() time.Duration {
	if s == nil || s.KeyTTL == nil {
		return 0
	}
	return s.KeyTTL.D()
}

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

// Policy is the estate's enforcement mode.
//
// A policy nobody dares switch on is not a control, and the reason nobody
// dares is always the same: no one knows what it would refuse at three in
// the morning. So the mode that answers that question is a first-class
// setting rather than a per-protocol learning flag -- the policy runs on
// real traffic, every decision is written down, and nothing is refused.
// `xproxyctl policy report` is then the list of what to fix before
// enforcement goes on.
type Policy struct {
	// Mode is enforce (the default) or shadow, for every listener that
	// does not say otherwise in its own policy section.
	Mode string `yaml:"mode"`
	// MaxReasons bounds the ledger: distinct combinations of kind,
	// listener, reason and rule. Default 4096. Past it the report says it
	// is full rather than quietly stopping.
	MaxReasons int `yaml:"max_reasons"`
}

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

// ThreatIntel imports lists of client addresses and TLS fingerprints,
// each with its own action.
//
// It is deliberately not the ban list. A ban is earned here -- this proxy
// watched a client do something and decided -- while a list is imported
// and says nothing about what the client did *here*. That is why the
// default action is the careful one: a feed whose provenance an operator
// cannot check, with one wrong line in it, is an outage nobody can
// explain from the logs.
type ThreatIntel struct {
	// Lists are the lists, in order. The first one that matches decides,
	// so a narrow list belongs before the broad one it softens.
	Lists []ThreatList `yaml:"lists"`
	// Refresh is how often the files are checked for changes; only a
	// file whose size or modification time moved is re-read. Default 5m,
	// minimum 10s, 0 for never (a reload of the configuration still
	// re-reads them). A pointer so that 0 is a decision rather than an
	// unset field.
	Refresh *Duration `yaml:"refresh"`
	// LogMatches writes a security event for every match, including the
	// ones whose action is log. Default true: a list nobody can see
	// matching is a list nobody can tune.
	LogMatches *bool `yaml:"log_matches"`
}

// RefreshInterval is how often the files are re-checked, with the
// default filled in. A section that says 0 means never, and a reload of
// the configuration still re-reads every list.
func (t *ThreatIntel) RefreshInterval() Duration {
	switch {
	case t == nil:
		return 0
	case t.Refresh == nil:
		return Duration(5 * time.Minute)
	default:
		return *t.Refresh
	}
}

// Logs reports whether a match is written to the security log.
func (t *ThreatIntel) Logs() bool { return t == nil || t.LogMatches == nil || *t.LogMatches }

// ThreatList is one imported list.
type ThreatList struct {
	Name string `yaml:"name"`
	// Kind is what the list is matched against:
	//
	//	cidr    client addresses and networks (the default)
	//	ja4     TLS client fingerprints
	//	domain  host names, and every name under them
	//	url     a host and path, matched at a path boundary
	//	hash    MD5, SHA-1 or SHA-256 digests of a payload
	//
	// The first two are about who is connecting; the rest are about what the
	// client asked for, which is a different question and often a better one.
	Kind string `yaml:"kind"`
	// File holds the entries: one per line, with #, ; and // comments
	// and a trailing comment after whitespace. A network may be written
	// with host bits set; it is masked.
	//
	// Exactly one of file, url, taxii and misp is the source.
	File string `yaml:"file"`
	// URL is a feed fetched over HTTP, conditionally: an unchanged feed costs
	// a 304 rather than a download.
	URL string `yaml:"url"`
	// TAXII is a TAXII 2.1 collection to poll.
	TAXII *TAXIIFeed `yaml:"taxii"`
	// MISP is a MISP instance to search.
	MISP *MISPFeed `yaml:"misp"`
	// HTTP is how a network source is reached: the credential, the trust and
	// the timeout. Ignored for a file.
	HTTP *FeedHTTP `yaml:"http"`
	// Format is how the source is written: lines (one indicator per line),
	// stix (a STIX 2.1 bundle), misp (a MISP export) or auto. Default auto for
	// a file or a url; a taxii source is always stix and a misp source always
	// misp, and saying otherwise is refused.
	//
	// Naming it is better than letting it be sniffed. A feed whose format is
	// named fails loudly when its publisher changes shape; a sniffed one
	// quietly starts yielding nothing.
	Format string `yaml:"format"`
	// Action is log (record it and serve the request), challenge (make
	// the client prove it is a browser, which needs the challenge
	// section) or block. Default log.
	Action string `yaml:"action"`
}

// TAXIIFeed is a TAXII 2.1 collection.
type TAXIIFeed struct {
	// APIRoot is the API root URL as the server's discovery document gives it,
	// for example https://taxii.example/api1/.
	APIRoot string `yaml:"api_root"`
	// Collection is the collection's id.
	Collection string `yaml:"collection"`
	// AddedAfter asks the server for objects added after this RFC 3339
	// timestamp. It is a floor on age rather than incremental state: every
	// fetch sends the same value, so the list stays the whole answer to the
	// same question and an indicator the publisher revokes disappears.
	AddedAfter string `yaml:"added_after"`
}

// MISPFeed is a MISP instance searched for attributes.
type MISPFeed struct {
	// URL is the instance, for example https://misp.example.
	URL string `yaml:"url"`
	// Types narrows the attribute types asked for. Empty asks for the ones
	// this proxy can match on, which is the useful default: asking for all two
	// hundred and discarding most of them makes the instance do work for
	// nothing.
	Types []string `yaml:"types"`
	// Tags narrows by MISP tag, which is how an estate subscribes to part of a
	// sharing community rather than all of it.
	Tags []string `yaml:"tags"`
	// Published asks only for attributes of published events, which is MISP's
	// own boundary between a draft and intelligence. Default true.
	Published *bool `yaml:"published"`
	// Limit bounds the attributes one search returns; 0 lets the instance
	// decide.
	Limit int `yaml:"limit"`
}

// FeedHTTP is how a network feed is reached.
type FeedHTTP struct {
	// Timeout bounds one fetch, including every page of a paginated TAXII
	// collection. Default 60s, between 1s and 10m.
	Timeout Duration `yaml:"timeout"`
	// Token is the credential: a bearer token for a TAXII server or a plain
	// feed, and the API key for MISP, which sends it bare as MISP expects.
	// A reference (env: or vault:) rather than the value keeps it out of the
	// configuration; see the secrets section.
	Token string `yaml:"token"`
	// Header and HeaderValue are one extra header, for the feeds whose
	// credential is neither of the above.
	Header      string `yaml:"header"`
	HeaderValue string `yaml:"header_value"`
	// CAFile is the trust anchor for the server's certificate; empty means the
	// system roots.
	CAFile string `yaml:"ca_file"`
	// ServerName overrides the name verified in the certificate.
	ServerName string `yaml:"server_name"`
	// Insecure and AllowInsecure together skip verification, and are refused
	// for anything but a loopback address. A feed nobody authenticated becomes
	// this proxy's block list, so this exists for a development instance and
	// nowhere else.
	Insecure      bool `yaml:"insecure"`
	AllowInsecure bool `yaml:"allow_insecure"`
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

// Access is just-in-time access to the gate listeners: nobody opens a session
// unless a live grant names them, the listener and the target.
//
// It is one section for the daemon rather than one per listener because the
// ledger is one file with one writer, and because an approval is about a person
// and a machine rather than about a port. Which listeners require a grant is
// each listener's own require_grant.
type Access struct {
	// Ledger is the append-only file the grants and every act on them are
	// written to, with a hash chain over the records. Without it the grants
	// live only in this process: they are gone on a restart and there is no
	// trail, which is warned about rather than refused because a test estate
	// legitimately runs that way.
	Ledger string `yaml:"ledger"`
	// Approvals is how many approvals a grant needs in addition to the
	// request. Default 1, which is four eyes: the person who asked and one
	// other. 0 means a request is in force as soon as it is made, which is
	// still just-in-time and time-boxed but is not four eyes, and is warned
	// about -- so it is a pointer, to tell "the operator wrote 0" from "the
	// operator wrote nothing".
	Approvals *int `yaml:"approvals"`
	// MaxDuration bounds the window a grant may cover. Default 4h.
	MaxDuration Duration `yaml:"max_duration"`
	// MaxLead bounds how far ahead of now a window may start, so that an
	// approval today cannot be a key for next quarter. Default 24h.
	MaxLead Duration `yaml:"max_lead"`
	// MaxUses bounds the sessions one grant may open; 0 leaves the window as
	// the only bound.
	MaxUses int `yaml:"max_uses"`
	// MaxOpen bounds the grants that may be pending or in force at once.
	// Default 256.
	MaxOpen int `yaml:"max_open"`
	// SelfApproval lets the requester approve their own request. It exists
	// for the estate with one operator, where the alternative is switching
	// the requirement off altogether; it is warned about every time.
	SelfApproval bool `yaml:"self_approval"`
}

// Secrets says where a secret reference resolves from.
//
// Every secret this proxy holds was a path until this existed, and a path means
// the material is on this machine's file system: readable by whatever else reads
// the machine, in its backups, replaced by whatever writes there. A reference
// says where a secret comes from instead --
//
//	/etc/xproxy/tls/edge.key       a path, as before
//	file:/etc/xproxy/tls/edge.key  the same, said explicitly
//	env:EDGE_KEY                   the environment of this process
//	vault:secret/tls/edge#key      a field of a secret in HashiCorp Vault
//
// -- and because the *configuration* holds the reference rather than the
// material, the management dump, the history and a diff show where each secret
// comes from and never what it is.
//
// The strongest arrangement is not here but in tls.certificates[].signer, where
// the private key never enters this process at all.
type Secrets struct {
	// Vault is the HashiCorp Vault to read vault: references from. Without
	// it a vault reference fails the load rather than falling back to
	// anything.
	Vault *VaultSecrets `yaml:"vault"`
	// RefreshInterval is how long a resolved value is used before its source
	// is asked again, so a rotation reaches a running proxy without a
	// reload. Default 5m; 1m to 24h. A failed refresh keeps the previous
	// value and warns -- a vault that is down must not take a TLS key away
	// from a proxy already serving with it.
	RefreshInterval Duration `yaml:"refresh_interval"`
}

// VaultSecrets is the Vault a vault: reference reads from. Only reading is
// implemented, and deliberately: a proxy that could write to the vault would be
// a proxy whose compromise rewrites the estate's secrets.
type VaultSecrets struct {
	// Address is the API base. https unless insecure is set, because http
	// hands the token and every secret to the network.
	Address string `yaml:"address"`
	// Mount is the KV mount a reference uses when it names none. Default
	// "secret".
	Mount string `yaml:"mount"`
	// KVVersion is 2 (the default) or 1. They differ in the request path and
	// in where the fields sit in the answer, and guessing between them
	// answers "not found" for a secret that is there.
	KVVersion int `yaml:"kv_version"`
	// TokenFile holds the token, and TokenEnv names an environment variable
	// holding it. Exactly one is required. A token in this document would be
	// a token in the management dump, the history and every diff; a token in
	// the environment is readable by more than this process, which is why it
	// is warned about.
	TokenFile string `yaml:"token_file"`
	TokenEnv  string `yaml:"token_env"`
	// Namespace is the Vault Enterprise namespace, sent as a header. Without
	// it an estate that uses namespaces gets "not found" for every secret.
	Namespace string `yaml:"namespace"`
	// CAFile pins the authority the server's certificate is checked against;
	// empty uses the system pool. ServerName overrides the name verified.
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
	// Insecure allows http and skips verification, and needs allow_insecure
	// as well: one flag is a typo, two are a decision.
	Insecure      bool `yaml:"insecure"`
	AllowInsecure bool `yaml:"allow_insecure"`
}

// FIPS is what the estate requires of the runtime's FIPS 140-3 mode.
//
// The mode itself is a property of the Go toolchain and the fips140 GODEBUG
// rather than of this file: nothing here turns it on. What this section does is
// refuse to serve without it, and -- because a list of approved algorithms in
// this proxy would be a claim about somebody else's validation certificate --
// find out what this runtime actually refuses by handshaking with each
// configured algorithm at start.
type FIPS struct {
	// Required refuses to start when the runtime is not in FIPS mode, with
	// the remedy in the message.
	Required bool `yaml:"required"`
	// Probe handshakes once per configured key exchange group and cipher
	// suite at start and reports the ones this runtime will not do. Default
	// true when required is set: an estate that asked for the mode is an
	// estate that wants to know its configuration works in it, at start
	// rather than at the first client that offers one of them.
	Probe *bool `yaml:"probe"`
	// ProbeFails makes a refused algorithm fail the load rather than being
	// reported. Off by default: a listener that also offers approved
	// algorithms still serves, and an operator who would rather not serve at
	// all can say so.
	ProbeFails bool `yaml:"probe_fails"`
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
	// DPoP requires the client to prove it holds the key the token is
	// bound to (RFC 9449).
	DPoP *DPoP `yaml:"dpop"`
	// TokenExchange swaps the client's token for one issued to the
	// backend (RFC 8693), so what is forwarded is not a credential that
	// works at the front door.
	TokenExchange *TokenExchange `yaml:"token_exchange"`
	// CertificateBinding requires the client to present the certificate
	// its token is bound to (RFC 8705).
	CertificateBinding *CertificateBinding `yaml:"certificate_binding"`
}

// TokenExchange is an RFC 8693 exchange at the token endpoint.
//
// A token the client sent to the gateway is a token the gateway forwards,
// and everything behind the gateway then holds a credential that works at
// the gateway. That is the confused-deputy problem in one sentence: a
// backend with a bug — a log line, an error page, an outbound request to
// somewhere it should not go — leaks a token that reaches the front door
// again with all of the client's scopes on it.
//
// Exchange replaces it. The proxy presents the verified client token to
// the authorization server and asks for one issued for *this* backend: a
// different audience, usually fewer scopes, and no standing anywhere else.
// The backend never sees the client's token, so there is nothing there to
// leak that would work at the gateway. The client's identity survives —
// the authorization server puts the same subject in the new token, which
// is what makes this an exchange rather than an impersonation.
type TokenExchange struct {
	// URL is the token endpoint (https).
	URL string `yaml:"url"`
	// ClientID and ClientSecretFile authenticate the proxy to the
	// authorization server with HTTP basic authentication.
	ClientID         string `yaml:"client_id"`
	ClientSecretFile string `yaml:"client_secret_file"`
	// CAFile pins the CA for the endpoint. Default: system pool.
	CAFile string `yaml:"ca_file"`
	// Audience and Resource say who the new token is for: the backend's
	// identifier at the authorization server, or its URI. At least one is
	// required — an exchange that names neither asks for a token as broad
	// as the one it replaces, which is the whole point undone.
	Audience string `yaml:"audience"`
	Resource string `yaml:"resource"`
	// Scopes asks for a subset. Empty leaves the decision to the
	// authorization server, which will usually issue what the audience is
	// entitled to.
	Scopes []string `yaml:"scopes"`
	// RequestedTokenType asks for a particular token type. Default: the
	// authorization server's choice, which must be an access token or a
	// JWT — a refresh token forwarded as an access token would be a
	// long-lived credential handed to a backend.
	RequestedTokenType string `yaml:"requested_token_type"`
	// Header is where the new token goes. Default Authorization, as
	// "Bearer <token>"; any other name carries the token alone.
	Header string `yaml:"header"`
	// CacheTTL keeps one exchange this long, bounded by the new token's
	// own expiry; 0 exchanges on every request. Default 60s.
	CacheTTL Duration `yaml:"cache_ttl"`
	// Timeout bounds one exchange. Default 3s.
	Timeout Duration `yaml:"timeout"`
	// Required refuses the request when the exchange fails. Default true:
	// forwarding the client's token after failing to replace it would
	// quietly undo the control on exactly the requests where it went
	// wrong.
	Required *bool `yaml:"required"`
}

// Requires reports whether a failed exchange refuses the request.
func (t *TokenExchange) Requires() bool { return t.Required == nil || *t.Required }

// DPoP is demonstrating proof of possession, RFC 9449.
//
// A bearer token is a password: whoever holds it is whoever it says. That
// is why a token stolen from a log, a browser's storage, a proxy's cache
// or a crash dump is as good as the original — nothing about the request
// says it came from the client the token was issued to.
//
// DPoP adds that. The client keeps a key pair, the authorization server
// records the public key's thumbprint in the token (cnf.jkt), and every
// request carries a small JWT signed with the private key over this
// method, this URI and this moment. A stolen token without the key
// produces no proof, and a proof captured from one request does not fit
// another.
type DPoP struct {
	// Mode is off (default), allow or require.
	//
	// allow verifies a proof whenever the access token says it is bound
	// to a key, and refuses a bound token presented without one — which
	// is the replay this exists to stop — while leaving an ordinary
	// bearer token alone. It therefore costs nothing to turn on.
	//
	// require additionally refuses an access token that carries no
	// cnf.jkt: on that route, only sender-constrained tokens are
	// accepted.
	Mode string `yaml:"mode"`
	// Algorithms allowed in a proof, from the asymmetric set (RS*, PS*,
	// ES*, EdDSA). Default ES256, ES384, ES512, PS256, PS384, PS512,
	// EdDSA. Nothing symmetric is permitted: a proof the verifier could
	// have written itself proves nothing about the client.
	Algorithms []string `yaml:"algorithms"`
	// MaxAge is how old a proof's iat may be. Default 60s. The provider's
	// clock_skew is allowed on top, in both directions.
	MaxAge Duration `yaml:"max_age"`
	// ReplayEntries bounds the table of spent proof identifiers. Default
	// 65536. The identifiers come from clients, so the bound is a
	// decision rather than an accident.
	ReplayEntries int `yaml:"replay_entries"`
	// ExternalURL is the scheme and authority the client sees, for the
	// htu comparison, when this proxy is behind another one that
	// terminates TLS. Without it the scheme comes from the connection and
	// the authority from the Host header — never from X-Forwarded-Proto,
	// because a client that can set that header could otherwise choose
	// which URI its proof has to match.
	ExternalURL string `yaml:"external_url"`
}

// CertificateBinding is RFC 8705 mutual-TLS client certificate bound
// access tokens: the token carries the SHA-256 thumbprint of the
// client's certificate in cnf["x5t#S256"], and a request presenting it on
// a connection with another certificate -- or none -- is not the client
// the token was issued to.
//
// It is the cheaper sibling of DPoP and the more limited one: no proof is
// signed per request, because the TLS handshake already proved possession
// of the key, but only a client that can present a certificate can use
// it. The two can be on together; a token bound both ways must satisfy
// both.
type CertificateBinding struct {
	// Mode is off (default), allow or require.
	//
	// allow checks the binding whenever the token carries one, and
	// refuses a bound token presented on the wrong connection, while
	// leaving an ordinary bearer token alone.
	//
	// require additionally refuses a token with no cnf["x5t#S256"]: on
	// that route, only certificate-bound tokens are accepted.
	Mode string `yaml:"mode"`
	// TrustForwardedHeader reads the certificate from the RFC 9440
	// Client-Cert request header when the immediate peer is inside
	// trusted_proxies, for a deployment where TLS is terminated in front
	// of this proxy. Without trusted_proxies it never fires: a client
	// that could set the header would otherwise choose which certificate
	// its own token is checked against.
	TrustForwardedHeader bool `yaml:"trust_forwarded_header"`
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
	// lines). Required unless push is configured. It must not be world
	// readable.
	File string `yaml:"file"`
	// Push is an approval sent to a device the user already carries,
	// instead of a code they type.
	//
	// With both, a user in the enrolment file is asked for a code and
	// everyone else is pushed, which is the shape an estate migrating
	// between the two has. With push alone, every user is pushed and the
	// approval service is what decides whether they exist.
	Push *MFAPush `yaml:"push"`
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

// MFAPush is the second factor that is not typed: a notification the user
// approves on a device they already carry.
//
// It is the factor people actually use, and the one with an attack of its own.
// A code is only as good as the user's typing; a push is only as good as their
// attention, and somebody who has the password can send notification after
// notification until the person taps approve to stop the buzzing. The bounds
// below are that attack refused: one request in flight per user, a bound per
// window, and a number the user has to recognise.
type MFAPush struct {
	// URL is the approval service. A request is POSTed to it and the answer
	// says approved, denied or pending; a pending request is polled at the
	// same URL with its nonce, which sends no second notification. See
	// docs/CONFIG.md for the two messages.
	URL string `yaml:"url"`
	// Timeout is how long a person has to answer, and bounds the whole
	// approval including every poll. Default 60s, between 5s and 5m.
	Timeout Duration `yaml:"timeout"`
	// Poll is how often a pending request is asked about. Default 2s.
	Poll Duration `yaml:"poll"`
	// Token is the credential, sent as a bearer token; header and
	// header_value are one extra header for a service whose credential is
	// neither. A reference (env: or vault:) keeps it out of the file.
	Token       string `yaml:"token"`
	Header      string `yaml:"header"`
	HeaderValue string `yaml:"header_value"`
	// CAFile is the trust anchor for the service's certificate, and
	// ServerName overrides the name verified in it.
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
	// Insecure and AllowInsecure together skip verification, and are refused
	// for anything but a loopback address: whatever can answer for the
	// approval service decides who gets in.
	Insecure      bool `yaml:"insecure"`
	AllowInsecure bool `yaml:"allow_insecure"`
	// PerWindow and Window bound the notifications one user may be sent.
	// Defaults 3 and 5m. This is the fatigue attack's rate limit, so it is
	// not a knob to raise for convenience.
	PerWindow int      `yaml:"per_window"`
	Window    Duration `yaml:"window"`
	// Numbers asks the user to recognise a number this proxy generates and
	// shows them. Default true: it is what makes an approval about the
	// session in front of them rather than about a notification.
	Numbers *bool `yaml:"numbers"`
}

// Pushes reports whether the policy has an approval service.
func (m *MFAPolicy) Pushes() bool { return m != nil && m.Push != nil }

// ShowsNumbers reports whether a push asks the user to recognise a number.
func (p *MFAPush) ShowsNumbers() bool { return p == nil || p.Numbers == nil || *p.Numbers }

// Touch reports whether user presence is demanded, with the default
// filled in.
func (h *SSHListener) Touch() bool { return h == nil || h.RequireTouch == nil || *h.RequireTouch }

// Authorization is the estate's authorisation policy: which identity may reach
// which listener, target and operation.
//
// Every kind here already decides things about a session -- an ssh listener's
// channels and commands, a postgres relay's statements, a modbus relay's
// function codes -- and those stay where they are, because nothing else can say
// what a write to holding register 40001 means. What this adds is the question
// above them: may this person reach this thing at all, from where they are, at
// this hour. Asked in nineteen places, that question has nineteen answers.
//
// It decides nothing on its own authority. Every value a rule matches on was
// established by the listener: a name it authenticated, a principal it
// resolved, groups something signed for, the target the client asked for.
type Authorization struct {
	// Default is what happens when no rule matches: deny (the default) or
	// allow. Deny, because a policy that lets through whatever nobody wrote a
	// rule for is a policy whose gaps are invisible.
	Default string `yaml:"default"`
	// Rules are tried in order and the first one that matches decides, which
	// is how every other list here works. At least one is required: a section
	// with no rules and a deny default refuses the estate.
	Rules []AuthzRule `yaml:"rules"`
	// Shadow evaluates the policy and writes down what it would have refused
	// without refusing it, so a policy can be read against real traffic before
	// it decides anything. It is a section-wide switch rather than per rule
	// because half a policy in force is not a policy.
	Shadow bool `yaml:"shadow"`
}

// Allows reports whether an unmatched subject is allowed, with the default
// filled in.
func (a *Authorization) Allows() bool { return a != nil && a.Default == "allow" }

// AuthzRule is one decision. Every selector it names has to hold, and a rule
// that names none matches everything -- which is how a catch-all is written,
// and why the order matters.
//
// The negative forms are separate keys rather than a "!" prefix on a value,
// because a user name, a group name or a target may begin with any character
// and a policy language in which a name cannot be written literally has a hole
// in it.
type AuthzRule struct {
	// Name is what the security event and the status view call this rule. A
	// decision nobody can name is a decision nobody can find in a log.
	Name string `yaml:"name"`
	// Allow is what the rule does when it matches. Default false: a rule
	// somebody forgot to finish refuses rather than permits.
	Allow bool `yaml:"allow"`

	// Who: the name the listener authenticated, the principal it resolved,
	// and the groups something it trusts said the identity is in. Groups are
	// compared without case, because a directory returns a distinguished name
	// in whatever case it likes.
	Users      []string `yaml:"users"`
	Principals []string `yaml:"principals"`
	Groups     []string `yaml:"groups"`
	// The negative forms: everybody but these.
	NotUsers      []string `yaml:"not_users"`
	NotPrincipals []string `yaml:"not_principals"`
	NotGroups     []string `yaml:"not_groups"`

	// Where from: the client address the listener decided on, which behind a
	// trusted proxy chain is the forwarded one. A bare address means that
	// address.
	Networks    []string `yaml:"networks"`
	NotNetworks []string `yaml:"not_networks"`

	// Where to: listener names, listener kinds, and the target the client
	// asked for. A target pattern is a glob in which * does not cross a colon
	// or a slash, so "10.0.0.5:*" is one host's ports and "/srv/*" is one
	// directory's entries.
	Listeners  []string `yaml:"listeners"`
	Kinds      []string `yaml:"kinds"`
	Targets    []string `yaml:"targets"`
	NotTargets []string `yaml:"not_targets"`

	// What: the operations this rule is about, in the policy's own vocabulary
	// rather than each protocol's -- connect, session, exec, forward, read,
	// write, admin. Each kind's own documentation says which of its operations
	// map to which, and a rule written for "write" means the same thing on
	// SFTP as on Modbus.
	Actions []string `yaml:"actions"`

	// Schedule limits the rule to certain hours, in the one spelling the rest
	// of the configuration uses. A rule outside its window does not match, so
	// the next rule -- or the default -- decides.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// AuthzActions are the operations a rule may name. It is one list, used by
// validation here and by the runtime through the configuration, so the
// vocabulary cannot differ between what loads and what is enforced.
var AuthzActions = map[string]bool{
	"connect": true, "session": true, "exec": true, "forward": true,
	"read": true, "write": true, "admin": true,
}

// SSHDeception answers as a bastion that is not there.
//
// Port 22 is the most attacked port there is, and what arrives on it is not one
// thing: a dictionary walking root and admin and oracle, a list of stolen keys
// being tried against everything, and -- the reason this is worth answering rather
// than only refusing -- somebody who already holds a credential and is looking for
// the machine it opens. A refusal tells all three the same nothing. Answering says
// which of the three is at the other end, and then what they do with a shell.
//
// Nothing is run, nothing is fetched, and nothing is forwarded: a direct-tcpip
// channel on a fabricated bastion is a client asking to use this proxy as an open
// relay. And no password is recorded in any form a guess can be tested against.
type SSHDeception struct {
	// Enabled turns the section off without removing it; it defaults to
	// true wherever the section is present.
	Enabled *bool `yaml:"enabled"`
	// Mode is answer (the default: a credential this listener refused gets
	// the fabrication instead of a refusal, and never reaches a machine) or
	// decoy (the whole listener is a fabricated bastion, with no upstream).
	//
	// In mode answer the fabrication wraps the authentication methods this
	// listener already offers and adds none: a bastion that started
	// advertising passwords because a deception section was added would have
	// had its front door changed by a logging feature. A key-only bastion
	// therefore collects key fingerprints here, and mode decoy is how an
	// estate collects passwords on purpose.
	Mode string `yaml:"mode"`
	// Clients are the networks that get the fabrication. Required in mode
	// answer. In mode decoy an empty list means every client.
	Clients []string `yaml:"clients"`
	// Profile is the machine being impersonated: linux (a small server) or
	// busybox. Default linux, because that is what an SSH port fronts.
	Profile string `yaml:"profile"`
	// Hostname replaces the profile's, and is what a visitor reads in the
	// shell prompt, uname -a and /etc/hostname. Name it after something
	// this estate really has.
	Hostname string `yaml:"hostname"`
	// Attempts is how many credentials are taken before the login is
	// accepted. Default 1; at most 16, and bounded further by
	// max_auth_tries, which is what the protocol lets a client try.
	//
	// What it must never depend on is *which* credential was offered: a trap
	// that accepted the right password and refused the wrong one would be a
	// credential oracle, which is the one thing a password list needs.
	Attempts int `yaml:"attempts"`
	// Tripwire are command names that raise an ssh_tripwire security event
	// in addition to the built-in set: the escalation, in the order it
	// happens -- fetch a payload, make it executable, run it, keep it
	// running, and clear what would have stopped it.
	Tripwire []string `yaml:"tripwire"`
	// Seed makes the fabricated numbers reproducible. Zero derives one from
	// the listener name.
	Seed uint64 `yaml:"seed"`
	// Period is how long one sample of a fabricated number lasts, which
	// here is the load average and the number of users logged in. Default
	// 30s; 1s to 1h.
	Period Duration `yaml:"period"`
	// MaxClients bounds the record of who has been answered. Default 1024.
	MaxClients int `yaml:"max_clients"`
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
	// RequireHardwareKey overrides the listener's setting for this
	// principal: unset takes the listener's, true demands a token where
	// the listener does not, and false exempts this principal from a
	// requirement the listener makes.
	//
	// The exemption exists because an estate that moves to tokens moves
	// one person at a time, and a service account that has no hands
	// cannot touch anything. It is what it looks like: this principal's
	// key is a file, and the load says so.
	RequireHardwareKey *bool `yaml:"require_hardware_key"`
}

// SSHPolicy is the part of an ssh listener's policy a principal can
// have its own copy of. Every field is optional: unset means the
// listener's value.
type SSHPolicy struct {
	UpstreamUser    string   `yaml:"upstream_user"`
	AllowChannels   []string `yaml:"allow_channels"`
	AllowRequests   []string `yaml:"allow_requests"`
	AllowSubsystems []string `yaml:"allow_subsystems"`
	AllowCommands   []string `yaml:"allow_commands"`
	// CommandRules hold the command families this gateway can read the
	// meaning of -- scp, rsync, the sftp server binary and git's
	// transport commands -- to what they actually ask for, instead of
	// to a pattern over their command line.
	//
	// A pattern is a weak boundary for these. "^scp -t /srv/incoming$"
	// is somebody writing "uploads into that directory only", and
	// "scp -f /srv/incoming" (the other direction, the same words),
	// "scp -rt /srv/incoming" (bundled flags), "/usr/bin/scp -t
	// /srv/incoming" (a path) and "scp -t /srv/incoming/../../etc/ssh"
	// each walk past it. A rule says the direction, whether recursion
	// is allowed and which paths are in reach, and the command is read
	// the way the program reads it before that is applied.
	//
	// With any rule present, a command of a family named by no rule is
	// refused: a positive model for the commands that move files, while
	// everything else stays with allow_commands.
	CommandRules  []SSHCommandRule `yaml:"command_rules"`
	AllowEnv      []string         `yaml:"allow_env"`
	Forward       []string         `yaml:"forward"`
	RemoteForward *bool            `yaml:"remote_forward"`
	SFTP          *SFTPPolicy      `yaml:"sftp"`
	// Recording replaces the listener's, which is how one entry is
	// recorded and another is not. A principal that should not be
	// recorded where the listener is sets enabled: false.
	Recording *SessionRecording `yaml:"recording"`
	// Deny refuses this principal outright, which is how a key stays in
	// authorized_keys while the person it belongs to is off.
	Deny bool `yaml:"deny"`
}

// SSHCommandRule is what one command family may do. The family is read
// structurally, so every field is a statement about the command's
// meaning rather than about its spelling.
type SSHCommandRule struct {
	// Command is the family: scp, rsync, sftp_server or git.
	Command string `yaml:"command"`
	// Directions are the file movements allowed, as "upload" (files
	// onto the target) and "download" (files off it). It is the
	// movement and not the program's own verb: a git fetch is
	// "upload-pack" because the sense is the server's, and it is a
	// download here. Required except for sftp_server, whose direction
	// the sftp policy decides.
	Directions []string `yaml:"directions"`
	// Paths are the paths in reach, as the sftp policy's patterns
	// ("/srv/incoming/**"). Empty means every path, which is a
	// deliberate choice to have to make.
	Paths []string `yaml:"paths"`
	// DenyPaths are refused whatever Paths says.
	DenyPaths []string `yaml:"deny_paths"`
	// Recursive allows scp -r. Default false: a recursive copy into a
	// directory is a different permission from a file into it.
	Recursive bool `yaml:"recursive"`
	// Delete allows the rsync options that remove files at the far end
	// (--delete and its family, --remove-source-files, --force).
	// Default false.
	Delete bool `yaml:"delete"`
	// EnforceSFTPPolicy relays an approved exec of the sftp server
	// binary through the sftp policy, which is what makes allowing it
	// safe: the channel carries the same protocol the subsystem does,
	// so the same path, operation and scanning rules apply. Required
	// for a sftp_server rule, and refused without an sftp section.
	EnforceSFTPPolicy bool `yaml:"enforce_sftp_policy"`
}

// SSHCommandFamilies are the families a rule may name.
var SSHCommandFamilies = map[string]bool{
	"scp": true, "rsync": true, "sftp_server": true, "git": true,
}

// SSHDeniedEnv are the variables no allow list can admit. Each one is a
// way to run code before the command that was approved.
var SSHDeniedEnv = []string{
	"LD_*", "DYLD_*", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "IFS", "PS4",
	"PERL5OPT", "PERL5LIB", "PERLLIB", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
	"RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "GLIBC_TUNABLES", "GCONV_PATH", "LOCPATH",
	"TMPDIR", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "PATH",
}

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

// DefaultSSHEnv is what a client may set when allow_env says nothing: a
// terminal type and a locale, which is what an interactive session
// needs and all it needs.
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

// BACnetListener is the kind: bacnet section.
//
// A BACnet/IP listener is a relay in front of a building: the controllers
// behind it hold the setpoints for air handling, heating, lighting, lifts
// and smoke control, and the protocol they speak has no user, no session
// and no authentication of any kind. Every control here is therefore about
// the three things a datagram does carry -- where it came from, what it
// asks for, and which object and property it names.
type BACnetListener struct {
	// Upstream is the pool of devices, routers or BBMDs this listener
	// relays to. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may send
	// from. Deny is evaluated first. On a protocol with no identity this
	// is the most valuable line in the file: it is the only thing
	// resembling authentication that exists.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`
	// Services is the allow list of application services, by the
	// standard's own names (readProperty, writeProperty, who-Is). Empty
	// allows the reading, discovery and notification services and nothing
	// that changes anything -- an estate that wants this relay to carry
	// writes says which ones, one at a time.
	Services []string `yaml:"services"`
	// DenyServices are services no rule can allow, which is how an
	// exception inside an allowed set is written.
	DenyServices []string `yaml:"deny_services"`
	// MaxCommandPriority is the most privileged write priority a client
	// may ask for, from 1 (highest) to 16. Default 8.
	//
	// This is BACnet's own privilege ladder and it is the control this
	// protocol most needs a relay for. A commandable object holds sixteen
	// slots and the plant follows the highest-priority one that is filled;
	// slots 1 and 2 are manual and automatic life safety and cannot be
	// overridden by the management system, by a schedule or by an operator
	// at a workstation. A client writing there has taken a piece of plant
	// away from everything else that commands it. The default refuses the
	// seven slots above 8, which are where life safety and manual override
	// live, and leaves the ordinary supervisory range alone.
	MaxCommandPriority int `yaml:"max_command_priority"`
	// Objects is the allow list of object types a request may name
	// (analog-output, binary-value, device), by the standard's names or by
	// number for a vendor's proprietary type. Empty allows any.
	Objects []string `yaml:"objects"`
	// DenyObjects are object types no rule can allow.
	DenyObjects []string `yaml:"deny_objects"`
	// Properties and DenyProperties are the properties a request may name,
	// by the standard's names (present-value, out-of-service) or by
	// number. Empty allows any.
	Properties     []string `yaml:"properties"`
	DenyProperties []string `yaml:"deny_properties"`
	// DenySensitiveWrites refuses a write to a property whose value is the
	// device's own behaviour rather than a measurement or a setpoint:
	// object-name, out-of-service, program-change, the recipient lists and
	// the MS/TP timing properties. Default true.
	//
	// out-of-service is the one to understand. Writing it true cuts a
	// point loose from the physical world: its present value becomes
	// whatever was last written, and every graphics page, trend and alarm
	// in the estate then reports that number as the truth. It is how a
	// sensor is made to lie without touching the sensor.
	DenySensitiveWrites *bool `yaml:"deny_sensitive_writes"`
	// RefuseUnlocatedObjects refuses a request whose object this relay
	// could not find, when object or property rules are configured.
	// Default true.
	//
	// A handful of services keep their object somewhere a fixed position
	// cannot describe: createObject names a type or an identifier inside a
	// choice, who-Has names an object or a name. A listener with rules
	// about objects cannot apply them to a request whose object it has not
	// found, and the two ways to get that wrong are to check the wrong
	// field and to let the request through unchecked.
	RefuseUnlocatedObjects *bool `yaml:"refuse_unlocated_objects"`
	// AllowBroadcast carries a broadcast from a client: an
	// Original-Broadcast-NPDU, or a Distribute-Broadcast-To-Network that
	// asks every BBMD in the estate to repeat it. Default false.
	//
	// A broadcast is how BACnet discovers, and it is also the protocol's
	// amplifier: one Who-Is yields an I-Am from every device that hears
	// it. MaxBroadcastReplies bounds the answers either way.
	AllowBroadcast *bool `yaml:"allow_broadcast"`
	// MaxBroadcastReplies bounds the answers one broadcast may bring back
	// to the client that sent it. Default 64.
	MaxBroadcastReplies int `yaml:"max_broadcast_replies"`
	// BroadcastReplyWindow is how long answers to a broadcast are matched
	// back to the client that sent it. Default 5s.
	BroadcastReplyWindow Duration `yaml:"broadcast_reply_window"`
	// AllowBBMD carries the broadcast management functions:
	// Register-Foreign-Device, the distribution and foreign device tables.
	// Default false.
	//
	// Two of them are a whole attack. Register-Foreign-Device asks a BBMD
	// to send the registering address every broadcast on a network it is
	// not on, from one unauthenticated datagram;
	// Read-Broadcast-Distribution-Table hands the estate's BACnet routing
	// to whoever asks.
	AllowBBMD *bool `yaml:"allow_bbmd"`
	// AllowForwarded carries a Forwarded-NPDU from a client. Default
	// false. The function exists for a BBMD to relay a broadcast it
	// received, and it carries the originating address inside the payload
	// -- where whoever sent the datagram chose it. A client that is not a
	// BBMD has no reason to send one.
	AllowForwarded *bool `yaml:"allow_forwarded"`
	// AllowNetworkMessages carries the network layer's own messages: the
	// router discovery and routing table messages of clause 6.4. Default
	// false.
	AllowNetworkMessages *bool `yaml:"allow_network_messages"`
	// AllowRouting carries the three that change how the internetwork is
	// routed: Initialize-Routing-Table, and the two that dial and drop a
	// half-router's link. Default false, and it requires
	// allow_network_messages as well.
	AllowRouting *bool `yaml:"allow_routing"`
	// AllowSecurityMessages carries clause 24's network security messages:
	// the challenge, the wrapped payloads and the key distribution.
	// Default false. A relay cannot read inside a Security-Payload, which
	// is the point of it -- so an estate that has deployed BACnet network
	// security has a stronger control than this relay and can turn this
	// on, and one that has not should not be seeing key distribution
	// arrive from a client network.
	AllowSecurityMessages *bool `yaml:"allow_security_messages"`
	// Networks is the allow list of destination network numbers (DNET) a
	// request may be routed to. Empty allows the local network only, which
	// is a message with no destination field at all.
	Networks []int `yaml:"networks"`
	// MaxHopCount is the largest hop count a routed message may carry.
	// Default 8. A message arriving with more is rewritten down to it
	// rather than refused: the hop count is what stops a routing loop, and
	// lowering it is the safe direction.
	MaxHopCount int `yaml:"max_hop_count"`
	// MaxPriority is the highest network priority a client may claim:
	// normal, urgent, critical-equipment or life-safety. Default urgent.
	// The priority decides what a congested router drops, so a client that
	// sends everything as life safety has claimed a queue it has not
	// earned.
	MaxPriority string `yaml:"max_priority"`
	// AllowSegmented carries a segmented request or reply. Default true.
	// A relay sees one segment at a time and decides about the one that
	// carries the service choice, so an estate that wants every request
	// decided whole turns this off -- at the cost of the large reads a
	// trend log download needs.
	AllowSegmented *bool `yaml:"allow_segmented"`
	// MaxWhoIsRange bounds the device instance range a Who-Is may ask
	// about. Zero allows any. A Who-Is with no range at all asks every
	// device there is to answer at once, which RequireWhoIsRange refuses.
	MaxWhoIsRange     int   `yaml:"max_whois_range"`
	RequireWhoIsRange *bool `yaml:"require_whois_range"`
	// MaxMessageBytes bounds one datagram. Default 1497, which is Annex
	// J's own maximum.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// MaxPending bounds the confirmed requests this listener is waiting
	// for answers to. Default 512. Each one holds a slot until the answer
	// arrives or the timeout passes.
	MaxPending int `yaml:"max_pending"`
	// RequestTimeout is how long a confirmed request's slot is held.
	// Default 10s, which is longer than the protocol's own default APDU
	// timeout and shorter than a client's patience.
	RequestTimeout Duration `yaml:"request_timeout"`
	// RateLimit and RateBurst bound requests per second per client
	// address. Zero disables them.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// Rules decide each request, in order, first match wins. A request
	// that matches no rule takes DefaultAction.
	Rules []BACnetRule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is how a refused request is answered: reject (the
	// default, for a confirmed request: a Reject-PDU, which every client
	// displays and stops on), error (an Error-PDU) or drop (nothing, which
	// the client retries and then reads as a timeout).
	//
	// An unconfirmed request has nothing to answer, so it is always
	// dropped -- the protocol gives a relay nothing to say back.
	DenyResponse string `yaml:"deny_response"`
	// LogRequests writes an access line per request: who, which service,
	// which object and property, and how it was decided. Default true.
	// This is the record an estate is asked for when somebody wants to
	// know who set the setpoint.
	LogRequests *bool `yaml:"log_requests"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
}

// BACnetRule decides one request.
type BACnetRule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before
	// it decides anything.
	Action string `yaml:"action"`
	// Clients are the networks the client is in.
	Clients []string `yaml:"clients"`
	// Services are the services this rule covers.
	Services []string `yaml:"services"`
	// Objects and DenyObjects are the object types this rule covers, and
	// the ones it does not cover even when Objects would match.
	Objects     []string `yaml:"objects"`
	DenyObjects []string `yaml:"deny_objects"`
	// Instances is the range of object instance numbers this rule covers,
	// written as 1-100 or as a single number. Empty covers any.
	Instances []string `yaml:"instances"`
	// Properties and DenyProperties are the properties this rule covers.
	Properties     []string `yaml:"properties"`
	DenyProperties []string `yaml:"deny_properties"`
	// Networks are the destination networks this rule covers.
	Networks []int `yaml:"networks"`
	// MaxCommandPriority overrides the listener's bound for this rule's
	// traffic, which is how the one workstation that really does command
	// at priority 8 is written down.
	MaxCommandPriority int `yaml:"max_command_priority"`
	// Schedule limits the rule to a time window. A change window is what
	// this is for: writes allowed while the engineers are on site and not
	// at three in the morning.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// OPCUAListener is the settings of a kind: opcua listener: a relay in front of
// an OPC UA server, on TCP 4840.
//
// OPC UA is the protocol the last fifteen years of industrial automation
// standardised on, and it is the first one in this file that was designed with
// security in it rather than beside it: certificates on both ends, a signed
// and encrypted channel, a session with a user identity. That makes a relay's
// job different here than it is in front of Modbus or S7comm, where the
// protocol has nothing and the relay supplies everything.
//
// Four things shape these settings.
//
// **Most of what is worth enforcing is in the handshake, and all of it is in
// the clear.** Before any service call there is a Hello that names an
// endpoint, an OpenSecureChannel that names a security policy and carries
// both certificates, and a CreateSession/ActivateSession pair that names an
// application and a user. Those fields are readable by construction — they
// are how the two ends agree on what to encrypt — so `security_policies`,
// `security_modes`, `application_uris`, `token_kinds` and `users` work on
// every channel regardless of what it then does to its bodies. They are also
// the cheapest lines in this section: a listener that admits only
// Basic256Sha256 in mode sign_and_encrypt, from two named applications, with
// no anonymous token, has excluded most of what goes wrong without naming a
// single node.
//
// **Whether the service rules apply at all is a property of the channel.**
// MessageSecurityMode has three values and they mean three different things
// to a reader. With `none` everything is plaintext. With `sign` the body is
// signed and *not* encrypted, so this relay reads every node id and method
// argument — and never modifies one, because the signature is over exactly
// the octets the client sent. With `sign_and_encrypt` the body is ciphertext
// and the relay sees the channel, the sizes and the timing and nothing else.
// So `nodes`, `services`, `attributes` and `methods` decide traffic on a
// none or sign channel and are silent on a sign_and_encrypt one. That is a
// genuine trade-off and not a gap: confidentiality on the wire and
// service-level enforcement in the middle are alternatives, and
// `require_readable_bodies` is how a listener says which it wants. Validation
// warns when service rules are configured alongside a mode that makes them
// inert, because a rule that never runs is worse than no rule.
//
// **This relay does not terminate the secure channel.** It holds no private
// key of the plant's and performs no key agreement: a relay that decrypted
// here would be a man in the middle of the one industrial protocol that was
// designed to notice, and the certificates the two ends check would have to
// be this relay's. Everything below works on what the channel leaves
// readable.
//
// **A write and a call are not the same risk.** `services` is the coarse
// allow list; `attributes` and `write_attributes` are what separate reading a
// process value from changing who may write it, and they matter because a
// write to attribute 13 moves an actuator while a write to attribute 17
// changes the permissions on it. Both arrive as a Write, and a policy that
// named only the node would have allowed either.
type OPCUAListener struct {
	// Upstream is the server pool. Required.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may connect
	// from. Deny is evaluated first. An empty allow list allows every client
	// the deny list does not refuse, which validation advises against on a
	// listener that reaches a plant.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`

	// Endpoints are the endpoint URLs a client may name in its Hello and its
	// CreateSession, as glob patterns. Empty allows any.
	//
	// Behind a relay a client's endpoint URL names the relay rather than the
	// server, because the client is saying where it believes it connected. A
	// server that insists on its own hostname will reject it, which is an
	// interoperability fact to configure around rather than a fault: name the
	// relay's own address in the server's endpoint list.
	Endpoints []string `yaml:"endpoints"`
	// AllowReverseHello carries a ReverseHello: a server dialling outward to
	// reach a client behind a firewall. Default false.
	//
	// It inverts the direction everything else here assumes. The peer that
	// dialled is the one that will be trusted as a server, so a listener that
	// does not mean to support the pattern should refuse the message rather
	// than pass it and find out.
	AllowReverseHello bool `yaml:"allow_reverse_hello"`

	// SecurityPolicies are the policy URIs a channel may be opened with,
	// by short name: None, Basic128Rsa15, Basic256, Basic256Sha256,
	// Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss. Empty allows the three
	// the standard has not withdrawn.
	SecurityPolicies []string `yaml:"security_policies"`
	// DenySecurityPolicies is the deny list, which no rule can override.
	DenySecurityPolicies []string `yaml:"deny_security_policies"`
	// AllowDeprecatedPolicies carries Basic128Rsa15 and Basic256: SHA-1
	// based, withdrawn in IEC 62541 1.04, and usually still switched on
	// because one old client needs them. Default false.
	//
	// It is a separate knob from naming them in SecurityPolicies so that the
	// deprecation is stated where somebody reviewing the file will read it,
	// rather than hidden in a list of six similar-looking URIs.
	AllowDeprecatedPolicies bool `yaml:"allow_deprecated_policies"`
	// SecurityModes are the message security modes a channel may ask for:
	// none, sign, sign_and_encrypt. Empty allows sign and sign_and_encrypt,
	// so a channel with no protection at all is refused until named.
	SecurityModes []string `yaml:"security_modes"`
	// RequireReadableBodies refuses a channel in mode sign_and_encrypt, so
	// that the service-level rules below apply to every message this listener
	// carries. Default false.
	//
	// Turning it on trades confidentiality on this hop for enforcement in the
	// middle: mode sign still authenticates every message and still detects
	// modification, and it leaves the body readable. It is the right choice
	// where the segment between the relay and the server is trusted and the
	// clients are not, and the wrong one where the wire itself is the threat.
	RequireReadableBodies bool `yaml:"require_readable_bodies"`
	// MaxTokenLifetime bounds the security token lifetime a client may ask
	// for, 0 for no bound. A client asking for a very long one is a client
	// asking not to rotate its keys; the standard's own default is an hour.
	MaxTokenLifetime Duration `yaml:"max_token_lifetime"`

	// ApplicationURIs are the client application URIs a CreateSession may
	// name, as glob patterns. Empty allows any.
	//
	// The URI must also appear in the client's own certificate, which is the
	// cheapest identity check the protocol has: a server checks it and so does
	// this relay when RequireCertificateURI is on.
	ApplicationURIs []string `yaml:"application_uris"`
	// RequireCertificateURI refuses a CreateSession whose application URI is
	// not a subjectAltName of the certificate it presented. Default true.
	RequireCertificateURI *bool `yaml:"require_certificate_uri"`
	// RequireClientCertificate refuses a CreateSession that presents none.
	// Default true: a session with no certificate is a session with no
	// application identity, whatever user it then activates as.
	RequireClientCertificate *bool `yaml:"require_client_certificate"`
	// TokenKinds are the user identity token kinds an ActivateSession may
	// present: anonymous, username, x509, issued. Empty allows all but
	// anonymous.
	TokenKinds []string `yaml:"token_kinds"`
	// Users are the user names a username token may name, as glob patterns.
	// Empty allows any, which on a plant is worth narrowing: the accounts a
	// server has are usually four or five and they do not change.
	Users []string `yaml:"users"`
	// DenyUsers is the deny list, which no rule can override.
	DenyUsers []string `yaml:"deny_users"`
	// RefusePlaintextPasswords refuses a username token whose password
	// carries no encryption algorithm. Default true.
	//
	// Under mode none such a password is on the wire as the operator typed
	// it. Under sign it is readable by anything on the path, this relay
	// included, which is the reason this defaults on rather than being left to
	// the mode: a relay that can see a plant's passwords is a relay worth
	// attacking for them.
	RefusePlaintextPasswords *bool `yaml:"refuse_plaintext_passwords"`

	// ReadOnly refuses every service that changes anything, for every
	// client, before any rule is read: Write, Call, AddNodes, DeleteNodes,
	// AddReferences, DeleteReferences, HistoryUpdate, RegisterServer and
	// TransferSubscriptions. It cannot be overridden by a rule, because a
	// read-only listener that one rule could write through is not a read-only
	// listener.
	//
	// TransferSubscriptions is on that list and it is the one worth explaining.
	// It moves a subscription from one session to another, which is how a client
	// takes over another client's stream of values — and on a plant, taking over
	// the stream an operator's screen is drawing from is a change to what that
	// operator sees.
	//
	// Creating and modifying subscriptions is not on that list: it changes
	// state the server holds rather than anything the plant does, and a
	// read-only listener that could not subscribe would be a listener no HMI
	// can use. The subscription bounds below are what police it instead.
	ReadOnly bool `yaml:"read_only"`
	// Services is the allow list, by name: read, write, browse, call,
	// create_subscription and the rest. Empty allows what an HMI does —
	// the discovery and session services, read, browse, the subscription and
	// monitored-item services, history_read — and nothing that changes a
	// value, a node or the plant.
	Services []string `yaml:"services"`
	// DenyServices is the deny list, which no rule can override.
	DenyServices []string `yaml:"deny_services"`

	// Namespaces are the namespace indices a node id may name, as numbers or
	// "2-4" ranges, or namespace URIs. Empty allows any.
	//
	// A URI is the portable form and the one to prefer: an index only means
	// something against the server's own namespace table, and that table's
	// order is not guaranteed across a firmware update. A rule written with
	// indices can silently start naming different nodes.
	Namespaces []string `yaml:"namespaces"`
	// Nodes are the node ids a request may name, as glob patterns against the
	// canonical form: "ns=3;i=1001", "ns=4;s=Motor/*", "ns=3;i=*". Empty allows
	// any.
	Nodes []string `yaml:"nodes"`
	// WriteNodes applies to writing services when set, so one listener can
	// allow a wide read and a narrow write.
	WriteNodes []string `yaml:"write_nodes"`
	// DenyNodes is the deny list, which no rule can override.
	DenyNodes []string `yaml:"deny_nodes"`
	// Methods are the method node ids a Call may invoke, as glob patterns.
	// Empty, with call allowed, allows any method on any allowed node.
	//
	// A Call names two nodes: the object it is on and the method itself. Both
	// are checked — the object against Nodes and the method against Methods —
	// because allowing Reset on one pump is not allowing it on every pump of
	// that model.
	Methods []string `yaml:"methods"`
	// DenyMethods is the deny list, which no rule can override.
	DenyMethods []string `yaml:"deny_methods"`
	// Attributes are the node attributes a Read or a monitored item may name:
	// value, browse_name, display_name, description, data_type, access_level
	// and the rest. Empty allows any.
	Attributes []string `yaml:"attributes"`
	// WriteAttributes are the attributes a Write may change. Empty allows
	// `value` alone, which is the line that separates moving an actuator from
	// changing who may move it: write_mask, access_level, user_access_level,
	// executable, user_executable and historizing all govern permissions, and
	// all arrive as an ordinary Write.
	WriteAttributes []string `yaml:"write_attributes"`

	// MaxOperations bounds the operations one request may carry — the nodes
	// in a Read, the values in a Write, the methods in a Call, the items in a
	// CreateMonitoredItems. 0 for no bound beyond the parser's.
	//
	// A Read naming ten thousand nodes is one request and ten thousand
	// operations, which is how a legitimate session becomes a load problem.
	MaxOperations int `yaml:"max_operations"`
	// MaxWriteOperations applies to writing services when set.
	MaxWriteOperations int `yaml:"max_write_operations"`
	// MaxMonitoredItems bounds the monitored items one subscription may hold,
	// 0 for no bound.
	MaxMonitoredItems int `yaml:"max_monitored_items"`
	// MinPublishingInterval is the fastest publishing interval a
	// CreateSubscription may ask for, 0 for no bound.
	//
	// It is the bound that matters most on this protocol, because the
	// amplification is arithmetic rather than accidental: a one-millisecond
	// interval over a thousand monitored items is a server asked to send a
	// thousand values a millisecond, from one session, in valid protocol.
	MinPublishingInterval Duration `yaml:"min_publishing_interval"`
	// MinSamplingInterval is the fastest sampling interval a monitored item
	// may ask for, 0 for no bound. A sampling interval faster than the device
	// can answer is a device polled as fast as it will go.
	MinSamplingInterval Duration `yaml:"min_sampling_interval"`
	// MaxSubscriptions bounds the subscriptions one session may hold, 0 for
	// no bound.
	MaxSubscriptions int `yaml:"max_subscriptions"`

	// MaxMessageSize bounds one assembled message, 0 for the package default.
	MaxMessageSize int `yaml:"max_message_size"`
	// MaxChunkSize bounds one chunk, which is also the buffer size this
	// listener will let the two ends negotiate. 0 for the package default.
	//
	// It is worth setting rather than leaving open, because the negotiation
	// is a minimum of the two proposals and a relay that passed both through
	// unchanged has let the ends agree on a chunk larger than its own buffer.
	MaxChunkSize int `yaml:"max_chunk_size"`
	// MaxChunks bounds the chunks in one message, 0 for the package default.
	MaxChunks int `yaml:"max_chunks"`
	// MaxRequests bounds the requests one connection may send, 0 for no
	// bound. A plant session is long-lived, so this is off by default.
	MaxRequests int `yaml:"max_requests"`
	// RateLimit and RateBurst bound requests per second per client address,
	// 0 for no limit.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// MaxSessions and MaxSessionsPerClient bound concurrent connections.
	MaxSessions          int `yaml:"max_sessions"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	// IdleTimeout, SessionDuration and HandshakeTimeout bound a connection.
	// HandshakeTimeout covers the Hello and the first OpenSecureChannel,
	// which is where a peer that has opened a socket and said nothing sits.
	IdleTimeout      Duration `yaml:"idle_timeout"`
	SessionDuration  Duration `yaml:"session_duration"`
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// Learn records what crosses this listener and writes a proposed policy,
	// because the drawings say which nodes a server has and the traffic says
	// which of them anything actually reads. See OPCUALearn.
	Learn *OPCUALearn `yaml:"learn"`

	// Rules decide each message, in order, first match wins. A message that
	// matches no rule takes DefaultAction.
	Rules []OPCUARule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is fault (the default: a ServiceFault carrying a bad
	// status code, which is what a server answers when it refuses, so the
	// client's own library reports a refusal), error (an ERR message and a
	// close, which ends the connection with a reason on the wire) or close.
	//
	// A fault is the one to prefer for a service-level refusal and it is only
	// available where the body was readable: a refusal decided from the
	// channel alone, before any session exists, has no request identifier to
	// answer and becomes an error instead.
	DenyResponse string `yaml:"deny_response"`
	// LogRequests writes an access line per message, which on a plant polling
	// every second is a great many lines.
	LogRequests bool `yaml:"log_requests"`
	// AlertOnDeny writes a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// MonitorOnly evaluates and enforces nothing, except the hard decisions:
	// the client list, a message the relay could not read, the bounds, and
	// every service that changes anything — because a Write forwarded so that
	// it could be written down is a moved actuator, and a Call forwarded is a
	// machine that did something.
	MonitorOnly bool `yaml:"monitor_only"`
}

// OPCUARule is one rule of an opcua listener's policy.
type OPCUARule struct {
	// Name identifies the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow (the default), deny or observe.
	Action string `yaml:"action"`
	// Clients, ApplicationURIs, Users and TokenKinds select the traffic by
	// who it is from. A rule naming a user matches only a session that
	// activated as one, which is every session after ActivateSession and no
	// session before it.
	Clients         []string `yaml:"clients"`
	ApplicationURIs []string `yaml:"application_uris"`
	Users           []string `yaml:"users"`
	TokenKinds      []string `yaml:"token_kinds"`
	// SecurityPolicies and SecurityModes select by what secures the channel,
	// which is how "this client may write, but only over an encrypted
	// channel" is written.
	SecurityPolicies []string `yaml:"security_policies"`
	SecurityModes    []string `yaml:"security_modes"`
	// The rule's own narrowing. The deny lists always win.
	Services        []string `yaml:"services"`
	DenyServices    []string `yaml:"deny_services"`
	Namespaces      []string `yaml:"namespaces"`
	Nodes           []string `yaml:"nodes"`
	WriteNodes      []string `yaml:"write_nodes"`
	DenyNodes       []string `yaml:"deny_nodes"`
	Methods         []string `yaml:"methods"`
	DenyMethods     []string `yaml:"deny_methods"`
	Attributes      []string `yaml:"attributes"`
	WriteAttributes []string `yaml:"write_attributes"`
	MaxOperations   int      `yaml:"max_operations"`
	// Schedule limits the rule to a time window, which is how "the
	// integrator may call methods during the shutdown window" is written.
	Schedule *ModbusSchedule `yaml:"schedule"`
	// Comment is carried into the logs when the rule decides, for the change
	// record a plant keeps.
	Comment string `yaml:"comment"`
}

// OPCUALearn records what crosses an opcua listener and writes a proposal.
//
// The reason learning exists at all is that nobody knows what an estate's OPC UA
// traffic is. A server's address space has thousands of nodes and its own
// documentation lists all of them; the traffic uses a few dozen. A policy written
// from the documentation allows everything, and one written from a guess refuses
// the half nobody wrote down — which on a plant means an HMI screen that stops
// updating during a shift, and a security control that gets turned off and stays
// off.
//
// Two things about learning on *this* protocol have no counterpart in the other
// kinds.
//
// **A channel that encrypts its bodies teaches nothing about nodes.** Under
// `sign_and_encrypt` the relay sees the channel, the session and the sizes and no
// node identifier at all. So a learning run over such a channel produces a report
// with an identity and no address space, and the report says so per subject and in
// its header rather than leaving an operator to conclude the plant reads almost
// nothing. A run meant to learn nodes wants `security_modes: [sign]` or
// `require_readable_bodies: true` for its duration.
//
// **What the report will not propose is the part that bounds amplification.**
// `min_publishing_interval`, `min_sampling_interval`, `max_operations` and
// `max_monitored_items` appear as observations, under names no rule uses, because a
// report that proposed the fastest interval it happened to see would widen the one
// setting learning must not touch. Nor will it propose a security policy or mode:
// seeing a channel in mode `none` is not a reason to allow mode `none`, and no run
// proposes `allow_deprecated_policies`.
type OPCUALearn struct {
	// Enabled turns the recording on.
	Enabled bool `yaml:"enabled"`
	// File is where the report is written, as YAML. Required when enabled.
	File string `yaml:"file"`
	// Interval is how often it is rewritten. Default 5m; it is also written
	// when the listener shuts down.
	Interval Duration `yaml:"interval"`
	// MaxSubjects bounds the observations held: one per identity, service class
	// and node group seen. Default 8192; past it the newest is dropped and the
	// drops are counted, because a learning run that quietly stopped learning is
	// worse than one that says so.
	MaxSubjects int `yaml:"max_subjects"`
	// Enforce keeps the policy in force while learning. Default false: a
	// learning run is normally observe-only, and saying so here is what stops one
	// being left on by accident.
	//
	// It does not disable the hard decisions. A client the lists refuse, a
	// message the relay could not read, a bound, and every service that changes
	// the plant are refused whether or not a learning run is in progress —
	// because a Write forwarded so that it could be written down is a moved
	// actuator.
	Enforce bool `yaml:"enforce"`
}

// MMSListener configures a kind: mms listener: an IEC 61850 MMS relay in front
// of substation IEDs on TCP 102.
//
// What makes this listener different from every other relay kind here is that
// the protocol's own object names carry the semantics. In front of Modbus the
// relay has to be told which register is a setpoint; here the name says so. A
// Write to `XCBR1$CO$Pos$Oper` operates a circuit breaker, a Write to
// `PTOC1$SG$StrVal$setMag$f` changes a protection relay's trip characteristic,
// and a Write to `LLN0$BR$brcbST$RptEna` stops the control centre hearing about
// either. The functional constraint -- the segment between the dollar signs --
// is what a rule is written about, and it means that a useful policy can be
// written for an estate whose SCL files nobody has read.
type MMSListener struct {
	// Upstream is the IED pool this listener relays to. Required.
	//
	// There is no per-name routing, for the same reason IEC 104 has none: an
	// MMS association is long-lived and its first exchange -- the transport
	// connection, the association request, the initiate -- names no logical
	// device at all. A route chosen from the domain could not be chosen until
	// the first confirmed request, by which time the association is up.
	Upstream string `yaml:"upstream"`
	// AllowClients and DenyClients are the networks a client may connect
	// from. Deny is evaluated first.
	AllowClients []string `yaml:"allow_clients"`
	DenyClients  []string `yaml:"deny_clients"`

	// APTitles are the calling AP-titles an association may present, as
	// object identifiers in dotted form, glob patterns allowed:
	// `1.1.999.*`. Empty allows any.
	//
	// The AP-title is not a credential -- nothing proves it -- but it is what
	// an SCL file configured and what the IEDs themselves check, so it is the
	// field an estate's own drawings are written in. Treat it as an address.
	APTitles []string `yaml:"ap_titles"`
	// DenyAPTitles is the deny list, which no rule can override.
	DenyAPTitles []string `yaml:"deny_ap_titles"`
	// AEQualifiers are the calling AE-qualifiers an association may present,
	// as numbers or "1-16" ranges. Empty allows any.
	AEQualifiers []string `yaml:"ae_qualifiers"`
	// RequireAPTitle refuses an association that presents no calling
	// AP-title. Default false: a good part of the installed base sends none,
	// and a listener that refused those would be a listener nobody switches
	// on. Turn it on where the estate is known to send them.
	RequireAPTitle bool `yaml:"require_ap_title"`

	// RefusePlaintextPasswords refuses an association whose ACSE
	// authentication value is a cleartext password. Default false.
	//
	// It defaults off, unlike the same knob on the opcua listener, and the
	// reason is which way the trade falls: IEC 61850-8-1 specifies the
	// charstring form and IEC 62351-4 is what replaces it, so on most of the
	// installed base the password *is* the authentication. Refusing it removes
	// the only check the IED has. What this listener can honestly do is say it
	// happened -- an alert and a counter on every association that carries one
	// -- and let an estate that has moved to 62351-4 refuse the ones that have
	// not.
	RefusePlaintextPasswords bool `yaml:"refuse_plaintext_passwords"`
	// AlertOnPlaintextPassword raises a security event for every association
	// carrying one. Default true, because it is the finding an estate most
	// often does not know it has.
	AlertOnPlaintextPassword *bool `yaml:"alert_on_plaintext_password"`

	// Services are the MMS services a client may call, by name: read, write,
	// get_name_list, file_open, initiate_download_sequence and the rest.
	// Empty allows what a control centre and an HMI do, which excludes every
	// domain service, every file write and every program-invocation control.
	Services []string `yaml:"services"`
	// DenyServices is the deny list, which no rule can override.
	DenyServices []string `yaml:"deny_services"`
	// ServiceClasses is the coarse form of the same list, by what a service
	// does: browse, read, write, report, dataset, control, domain, file,
	// session. It is the list to write first, because a substation's services
	// are eighty and its classes nine.
	ServiceClasses []string `yaml:"service_classes"`
	// DenyServiceClasses is its deny list.
	DenyServiceClasses []string `yaml:"deny_service_classes"`

	// Domains are the logical devices a request may address, as glob
	// patterns: `AA1J1Q01A1LD0`, `*LD0`. Empty allows any.
	Domains []string `yaml:"domains"`
	// DenyDomains is the deny list.
	DenyDomains []string `yaml:"deny_domains"`
	// Objects are the object names a request may address, as glob patterns
	// against `domain/item`: `AA1J1Q01A1LD0/MMXU1$MX$*`. Empty allows any.
	Objects []string `yaml:"objects"`
	// DenyObjects is the deny list.
	DenyObjects []string `yaml:"deny_objects"`
	// WriteObjects narrows what a Write may address, where reading a wider
	// set is wanted. Empty means Objects decides both.
	WriteObjects []string `yaml:"write_objects"`

	// FunctionalConstraints are the constraints a request may address: ST,
	// MX, CO, SP, CF, SG, SE, BR, RP, LG, GO and the rest. Empty allows any.
	FunctionalConstraints []string `yaml:"functional_constraints"`
	// WriteConstraints narrows which constraints a Write may address. Empty
	// means the listener's own default: ST, MX, SP and CO, which is what an
	// HMI and a control centre write -- and not SG, SE or CF, because those
	// change what the device will do in a fault rather than what it is doing
	// now.
	WriteConstraints []string `yaml:"write_constraints"`
	// DenyConstraints is the deny list, which no rule can override.
	DenyConstraints []string `yaml:"deny_constraints"`

	// AllowOperate carries a Write to a control attribute that operates:
	// `$CO$...$Oper`. Default true where the constraint is allowed at all,
	// so that turning CO on does not silently turn operating on.
	AllowOperate *bool `yaml:"allow_operate"`
	// RequireSelectBeforeOperate refuses an operate on an object this
	// association has not selected. Default false.
	//
	// It is the one check in this protocol a relay can make that the device
	// may not: IEC 61850's ctlModel decides whether select-before-operate is
	// required, ctlModel lives in `$CF$` and is therefore writable, and an IED
	// configured for direct-operate accepts an Oper from anybody the policy
	// lets through. A listener that requires the select has put the
	// interlock back where the configuration can no longer remove it.
	RequireSelectBeforeOperate bool `yaml:"require_select_before_operate"`
	// SelectTimeout bounds how long a selection stays good, 0 for the
	// standard's own 30s.
	SelectTimeout Duration `yaml:"select_timeout"`

	// ReadOnly refuses every service that changes anything, for every client,
	// before any rule is read: Write, the domain services, the file writes,
	// the program-invocation controls, the dataset definitions and the report
	// enrollments. No rule can override it.
	//
	// It is the shorthand for a historian, a neighbouring utility's data link
	// or an engineering network that has no business commanding. Note that it
	// refuses more than a Write: deleting a domain is not a Write and changes
	// a great deal more.
	ReadOnly bool `yaml:"read_only"`
	// AllowDomainServices carries the download, upload and delete services
	// that replace what is inside an IED. Default false, and separate from
	// the service list so that the decision is stated where a reviewer reads
	// it rather than hidden among eighty names.
	AllowDomainServices bool `yaml:"allow_domain_services"`

	// Files are the file paths a file service may name, as glob patterns
	// against the joined path: `COMTRADE/*`. Empty allows any.
	Files []string `yaml:"files"`
	// DenyFiles is the deny list.
	DenyFiles []string `yaml:"deny_files"`

	// MaxNames bounds the object names one request may address, 0 for no
	// bound. A Read naming ten thousand objects is one request and ten
	// thousand reads of an IED that answers them one at a time.
	MaxNames int `yaml:"max_names"`
	// MaxWriteNames bounds the same for a Write, 0 to inherit MaxNames.
	MaxWriteNames int `yaml:"max_write_names"`
	// MaxFrame bounds one TPKT frame, 0 for 64 KiB.
	MaxFrame int `yaml:"max_frame"`
	// MaxRequests bounds the confirmed requests one association may send, 0
	// for no bound. A substation association is long-lived and polls
	// continuously, so this is off by default.
	MaxRequests int `yaml:"max_requests"`
	// MaxPendingRequests bounds the requests one association may have
	// outstanding, 0 for the relay's own 64.
	MaxPendingRequests int `yaml:"max_pending_requests"`
	// RateLimit and RateBurst bound confirmed requests a second per client
	// address, 0 for no bound.
	RateLimit int `yaml:"rate_limit"`
	RateBurst int `yaml:"rate_burst"`
	// MaxSessions and MaxSessionsPerClient bound concurrent associations.
	MaxSessions          int `yaml:"max_sessions"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	// IdleTimeout and SessionDuration bound one association, 0 for no bound.
	IdleTimeout     Duration `yaml:"idle_timeout"`
	SessionDuration Duration `yaml:"session_duration"`
	// HandshakeTimeout bounds the transport connection, the association
	// request and the initiate, which is where a peer that opened a socket
	// and said nothing sits. Default 30s.
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// Rules decide each request, in order, first match wins. A request that
	// matches no rule takes DefaultAction.
	Rules []MMSRule `yaml:"rules"`
	// DefaultAction is deny (the default) or allow.
	DefaultAction string `yaml:"default_action"`
	// DenyResponse is how a refused request is answered: error (the default:
	// a confirmed-error PDU, which is what an IED sends and what a client's
	// library understands), reject (a reject PDU), drop or close.
	DenyResponse string `yaml:"deny_response"`
	// LogRequests logs a line per request, which on a substation polling every
	// second is a great many lines. A Write, a control operation, a domain
	// service and an association are logged regardless, because those are
	// what a change record is about.
	LogRequests bool `yaml:"log_requests"`
	// AlertOnDeny raises a security event for every refusal. Default true.
	AlertOnDeny *bool `yaml:"alert_on_deny"`
	// MonitorOnly evaluates and enforces nothing, except the hard decisions:
	// the client list, a message the relay could not read, the bounds, and
	// every service that changes anything -- because a Write forwarded so it
	// could be written down is a moved breaker.
	MonitorOnly bool `yaml:"monitor_only"`
	// Learn records what crosses this listener and writes a proposed rule
	// set. See MMSLearn.
	Learn *MMSLearn `yaml:"learn"`
}

// MMSRule is one rule of an mms listener's policy.
type MMSRule struct {
	// Name names the rule in the logs and the counters. Required.
	Name string `yaml:"name"`
	// Action is allow, deny or observe. Observe logs and counts and then
	// keeps looking, which is how a rule is tried on live traffic before it
	// decides anything.
	Action string `yaml:"action"`
	// Comment is carried into the logs when the rule decides, for the change
	// record a substation keeps.
	Comment string `yaml:"comment"`

	// Clients are the networks the association came from.
	Clients []string `yaml:"clients"`
	// APTitles and AEQualifiers select by who is calling.
	APTitles     []string `yaml:"ap_titles"`
	AEQualifiers []string `yaml:"ae_qualifiers"`

	// Services, ServiceClasses and their deny lists narrow the listener's own
	// for this rule's traffic.
	Services           []string `yaml:"services"`
	DenyServices       []string `yaml:"deny_services"`
	ServiceClasses     []string `yaml:"service_classes"`
	DenyServiceClasses []string `yaml:"deny_service_classes"`
	// Domains, Objects, WriteObjects and their deny lists are the rule's own
	// name narrowing.
	Domains      []string `yaml:"domains"`
	DenyDomains  []string `yaml:"deny_domains"`
	Objects      []string `yaml:"objects"`
	DenyObjects  []string `yaml:"deny_objects"`
	WriteObjects []string `yaml:"write_objects"`
	// FunctionalConstraints, WriteConstraints and DenyConstraints are the
	// rule's own constraint narrowing.
	FunctionalConstraints []string `yaml:"functional_constraints"`
	WriteConstraints      []string `yaml:"write_constraints"`
	DenyConstraints       []string `yaml:"deny_constraints"`
	// AllowOperate is the rule's own answer about operating.
	AllowOperate *bool `yaml:"allow_operate"`
	// Files and DenyFiles are the rule's own file narrowing.
	Files     []string `yaml:"files"`
	DenyFiles []string `yaml:"deny_files"`
	// MaxNames is the rule's own bound on the names one request may address.
	MaxNames int `yaml:"max_names"`
	// Schedule limits the rule to a time window, which is how "the integrator
	// may download during the outage window" is written.
	Schedule *ModbusSchedule `yaml:"schedule"`
}

// MMSLearn configures a learning run on an mms listener.
type MMSLearn struct {
	// Enabled turns the recording on.
	Enabled bool `yaml:"enabled"`
	// File is where the report is written, as YAML. Required when enabled.
	File string `yaml:"file"`
	// Interval is how often it is rewritten, 10s..24h. Default 5m. It is
	// also written at shutdown.
	Interval Duration `yaml:"interval"`
	// MaxSubjects bounds the table: one subject per calling identity, service
	// class and logical device. Default 8192.
	MaxSubjects int `yaml:"max_subjects"`
	// Enforce keeps the policy in force while learning. Default false, which
	// is the only honest way to find out what a policy would have broken.
	Enforce bool `yaml:"enforce"`
}
