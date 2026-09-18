package config

import (
	"github.com/rom/xproxy/internal/filter"
	"mime"
	"time"

	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ValidationError collects all problems found in a configuration.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "config: " + e.Problems[0]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "config: %d problems:\n", len(e.Problems))
	for _, p := range e.Problems {
		b.WriteString("  - ")
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

type validator struct {
	problems []string
	// fileCheck is true when file existence should be verified. Tests turn
	// this off.
	fileCheck bool
}

func (v *validator) errf(format string, args ...interface{}) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// Validate checks a defaulted configuration and returns a *ValidationError
// describing every problem found.
func Validate(c *Config) error {
	return validate(c, true)
}

// ValidateNoFiles is Validate without file existence checks.
func ValidateNoFiles(c *Config) error {
	return validate(c, false)
}

func validate(c *Config, files bool) error {
	v := &validator{fileCheck: files}
	v.config(c)
	if len(v.problems) == 0 {
		return nil
	}
	return &ValidationError{Problems: v.problems}
}

func (v *validator) config(c *Config) {
	if c.Version != CurrentVersion {
		v.errf("version: got %d, this build supports %d", c.Version, CurrentVersion)
	}
	v.server(&c.Server)
	for i := range c.Server.Listeners {
		ln := &c.Server.Listeners[i]
		if ln.ProxyProtocol && ln.Kind != "tcp" && len(c.TrustedProxies) == 0 {
			v.errf("server.listeners[%d].proxy_protocol: needs trusted_proxies naming the balancers that send the header", i)
		}
	}
	v.management(&c.Management)
	v.logging(&c.Logging)
	for i, cidr := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			v.errf("trusted_proxies[%d]: %q is not a CIDR", i, cidr)
		}
	}

	rateLimits := map[string]bool{}
	for i := range c.RateLimits {
		v.rateLimit(i, &c.RateLimits[i], rateLimits)
	}
	upstreams := map[string]bool{}
	for i := range c.Upstreams {
		v.upstream(i, &c.Upstreams[i], upstreams)
	}
	if c.Bans != nil {
		v.bans(c.Bans)
	}
	profiles := map[string]bool{}
	if c.WAF != nil {
		v.waf(c.WAF, profiles)
	}
	if c.Cluster != nil {
		v.cluster(c.Cluster)
	}
	if c.Shedding != nil {
		v.shedding(c.Shedding)
	}
	v.metrics(&c.Metrics)
	acmeUsed := false
	for _, ln := range c.Server.Listeners {
		if ln.TLS != nil && len(ln.TLS.ACME) > 0 {
			acmeUsed = true
		}
	}
	if acmeUsed && c.ACME == nil {
		v.errf("acme: listeners use tls.acme but there is no top-level acme section")
	}
	if c.ACME != nil {
		v.acme(c.ACME)
	}
	if c.Ingress != nil {
		byName := map[string]*Listener{}
		for i := range c.Server.Listeners {
			byName[c.Server.Listeners[i].Name] = &c.Server.Listeners[i]
		}
		v.ingress(c.Ingress, byName)
	}
	if c.Challenge != nil {
		v.challenge(c.Challenge)
	}
	jwtProviders := map[string]bool{}
	if c.JWT != nil {
		v.jwt(c.JWT, jwtProviders)
	}
	icapServices := map[string]bool{}
	if c.ICAP != nil {
		v.icap(c.ICAP, icapServices)
	}
	filters := map[string]bool{}
	for i := range c.Filters {
		v.filter(i, &c.Filters[i], filters)
	}
	if g := c.GeoIP; g != nil {
		if (g.Database == "") == (g.CSV == "") {
			v.errf("geoip: exactly one of database or csv is required")
		}
		if g.Database != "" {
			v.file("geoip.database", g.Database)
		}
		if g.CSV != "" {
			v.file("geoip.csv", g.CSV)
		}
	}
	if cp := c.Compression; cp != nil {
		if cp.Level < 1 || cp.Level > 9 {
			v.errf("compression.level: must be between 1 and 9")
		}
		if cp.MinBytes < 0 || cp.MinBytes > 1<<20 {
			v.errf("compression.min_bytes: must be between 0 and 1048576")
		}
		for j, t := range cp.Types {
			if mt, _, err := mime.ParseMediaType(t); err != nil || mt != strings.ToLower(t) {
				v.errf("compression.types[%d]: %q is not a media type without parameters", j, t)
			}
		}
	}
	for i := range c.Routes {
		if r := &c.Routes[i]; r.Compress != nil && *r.Compress && !c.Compression.Enable() {
			v.errf("routes[%d].compress: true needs an enabled compression section", i)
		}
	}
	if cc := c.Cache; cc != nil {
		if cc.MaxBytes < 1<<20 || cc.MaxBytes > 64<<30 {
			v.errf("cache.max_bytes: must be between 1 MiB and 64 GiB")
		}
		if cc.MaxObjectBytes < 1024 || cc.MaxObjectBytes > cc.MaxBytes {
			v.errf("cache.max_object_bytes: must be between 1024 and max_bytes")
		}
	}
	for i := range c.RateLimits {
		if c.RateLimits[i].Key == "country" && c.GeoIP == nil {
			v.errf("rate_limits[%d].key: country needs a geoip section", i)
		}
	}
	for i := range c.Server.Listeners {
		if t := c.Server.Listeners[i].TCP; t != nil {
			p := fmt.Sprintf("server.listeners[%d].tcp", i)
			if t.Default != "" && !upstreams[t.Default] {
				v.errf("%s.default: unknown upstream %q", p, t.Default)
			}
			for j, r := range t.Routes {
				if r.Upstream != "" && !upstreams[r.Upstream] {
					v.errf("%s.routes[%d].upstream: unknown upstream %q", p, j, r.Upstream)
				}
			}
		}
	}
	dnsListeners := map[string]bool{}
	for _, ln := range c.Server.Listeners {
		if ln.Kind == "dns" {
			dnsListeners[ln.Name] = true
		}
	}
	routes := map[string]bool{}
	for i := range c.Routes {
		v.route(i, &c.Routes[i], routes, upstreams, rateLimits)
		if d := c.Routes[i].DoH; d != nil && d.Listener != "" && !dnsListeners[d.Listener] {
			v.errf("routes[%d].doh.listener: %q is not a kind: dns listener", i, d.Listener)
		}
		for j, name := range c.Routes[i].Filters {
			if !filters[name] {
				v.errf("routes[%d].filters[%d]: unknown filter %q", i, j, name)
			}
		}
		if rc := c.Routes[i].Cache; rc != nil {
			p := fmt.Sprintf("routes[%d].cache", i)
			if c.Cache == nil {
				v.errf("%s: set but there is no cache section", p)
			}
			if c.Routes[i].Upstream == "" {
				v.errf("%s: only proxied routes can be cached", p)
			}
			if rc.TTL <= 0 || rc.TTL > Duration(365*24*time.Hour) {
				v.errf("%s.ttl: must be positive and at most a year", p)
			}
			for _, m := range rc.Methods {
				if m != "GET" && m != "HEAD" {
					v.errf("%s.methods: only GET and HEAD can be cached", p)
				}
			}
			for _, st := range rc.Statuses {
				if st < 200 || st > 599 || st == 206 {
					v.errf("%s.statuses: %d cannot be cached", p, st)
				}
			}
			switch rc.Query {
			case "all", "none", "listed":
			default:
				v.errf("%s.query: must be all, none or listed", p)
			}
			for _, h := range rc.Headers {
				if !headerNameOK(h) {
					v.errf("%s.headers: %q is not a header name", p, h)
				}
			}
		}
		if g := c.Routes[i].Geo; g != nil {
			p := fmt.Sprintf("routes[%d].geo", i)
			if c.GeoIP == nil {
				v.errf("%s: set but there is no geoip section", p)
			}
			if len(g.Allow) == 0 && len(g.Deny) == 0 {
				v.errf("%s: allow or deny must list at least one country", p)
			}
			for _, list := range [][]string{g.Allow, g.Deny} {
				for _, cc := range list {
					if len(cc) != 2 || strings.ToUpper(cc) != cc || strings.Trim(cc, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
						v.errf("%s: %q is not a two letter country code", p, cc)
					}
				}
			}
			if g.Unknown != "allow" && g.Unknown != "deny" {
				v.errf("%s.unknown: must be allow or deny", p)
			}
		}
		if c.Routes[i].WAF != nil {
			v.routeWAF(i, c.Routes[i].WAF, c.WAF, profiles)
		}
		switch c.Routes[i].PriorityClass {
		case "low", "normal", "high", "critical":
		default:
			v.errf("routes[%d].priority_class: must be low, normal, high or critical", i)
		}
		if ri := c.Routes[i].ICAP; ri != nil {
			p := fmt.Sprintf("routes[%d].icap", i)
			if c.ICAP == nil {
				v.errf("%s: set but there is no top-level icap section", p)
			} else if !icapServices[ri.Service] {
				v.errf("%s.service: unknown service %q", p, ri.Service)
			}
			if !ri.ScansRequests() && !ri.ScansResponses() {
				v.errf("%s: request and response are both disabled", p)
			}
		}
		if rj := c.Routes[i].JWT; rj != nil {
			p := fmt.Sprintf("routes[%d].jwt", i)
			if c.JWT == nil {
				v.errf("%s: set but there is no top-level jwt section", p)
			} else if !jwtProviders[rj.Provider] {
				v.errf("%s.provider: unknown provider %q", p, rj.Provider)
			}
		}
		if rc := c.Routes[i].Challenge; rc != nil {
			p := fmt.Sprintf("routes[%d].challenge", i)
			switch rc.Mode {
			case "off", "always":
			case "load":
				if c.Shedding == nil {
					v.errf("%s.mode: load requires a top-level shedding section", p)
				}
			default:
				v.errf("%s.mode: must be off, always or load", p)
			}
			if rc.Mode != "off" && c.Challenge == nil {
				v.errf("%s: set but there is no top-level challenge section", p)
			}
			if rc.Level <= 0 || rc.Level > 1 {
				v.errf("%s.level: must be between 0 and 1", p)
			}
		}
	}
	if len(c.Server.Listeners) == 0 {
		v.errf("server.listeners: at least one listener is required")
	}
}

func (v *validator) server(s *Server) {
	names := map[string]bool{}
	addrs := map[string]bool{}
	for i := range s.Listeners {
		ln := &s.Listeners[i]
		p := fmt.Sprintf("server.listeners[%d]", i)
		switch {
		case ln.Name == "":
			v.errf("%s.name: required", p)
		case !nameRE.MatchString(ln.Name):
			v.errf("%s.name: %q is not a valid name", p, ln.Name)
		case names[ln.Name]:
			v.errf("%s.name: duplicate %q", p, ln.Name)
		}
		names[ln.Name] = true
		if ln.Address == "" {
			v.errf("%s.address: required", p)
		} else if _, port, err := net.SplitHostPort(ln.Address); err != nil {
			v.errf("%s.address: %q: %v", p, ln.Address, err)
		} else if addrs[ln.Address] && port != "0" {
			v.errf("%s.address: duplicate %q", p, ln.Address)
		}
		addrs[ln.Address] = true
		h3 := false
		for _, proto := range ln.Protocols {
			switch proto {
			case ProtocolH1, ProtocolH2:
			case ProtocolH3:
				h3 = true
			default:
				v.errf("%s.protocols: unknown protocol %q", p, proto)
			}
		}
		switch ln.Kind {
		case "http":
			if ln.TCP != nil {
				v.errf("%s.tcp: set on an http listener (kind: tcp)", p)
			}
			if ln.DNS != nil {
				v.errf("%s.dns: set on an http listener (kind: dns)", p)
			}
			if ln.H2C && ln.TLS != nil {
				v.errf("%s.h2c: only for plaintext listeners (TLS negotiates HTTP/2 with ALPN)", p)
			}
			if ln.Forward != nil {
				v.errf("%s.forward: set on an http listener (kind: forward)", p)
			}
		case "tcp":
			if ln.TLS != nil || len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.Forward != nil {
				v.errf("%s: a tcp listener takes no tls, protocols, h3, redirect_to_https or forward", p)
			}
			if ln.TCP == nil {
				v.errf("%s.tcp: required for kind tcp", p)
			} else {
				v.tcpListener(p+".tcp", ln.TCP)
			}
		case "dns":
			if ln.TLS != nil || len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.H2C {
				v.errf("%s: a dns listener takes only address and dns", p)
			}
			if ln.DNS == nil {
				v.errf("%s.dns: required for kind dns", p)
			} else {
				v.dnsListener(p+".dns", ln.DNS)
			}
		case "forward":
			if ln.TCP != nil || ln.RedirectToHTTPS || h3 || ln.H2C {
				v.errf("%s: a forward listener takes no tcp, redirect_to_https, h3 or h2c", p)
			}
			if ln.Forward == nil {
				v.errf("%s.forward: required for kind forward", p)
			} else {
				v.forwardListener(p+".forward", ln.Forward)
			}
		default:
			v.errf("%s.kind: must be http, tcp, forward or dns", p)
		}
		if ln.TLS == nil {
			for _, proto := range ln.Protocols {
				if proto == ProtocolH2 || proto == ProtocolH3 {
					v.errf("%s: protocol %s requires tls", p, proto)
				}
			}
		} else {
			v.tls(p+".tls", ln.TLS)
		}
		if h3 {
			h1h2 := false
			for _, proto := range ln.Protocols {
				if proto == ProtocolH1 || proto == ProtocolH2 {
					h1h2 = true
				}
			}
			if !h1h2 {
				v.errf("%s.protocols: h3 requires h1 or h2 on the same listener (clients discover HTTP/3 through Alt-Svc)", p)
			}
			if ln.H3 != nil {
				if ln.H3.MaxStreams < 1 || ln.H3.MaxStreams > 10000 {
					v.errf("%s.h3.max_streams: must be 1..10000", p)
				}
				switch ln.H3.ValidateAddresses {
				case "always", "under_load":
				default:
					v.errf("%s.h3.validate_addresses: must be always or under_load", p)
				}
				if ln.H3.AltSvcMaxAge <= 0 {
					v.errf("%s.h3.alt_svc_max_age: must be positive", p)
				}
			}
		} else if ln.H3 != nil {
			v.errf("%s.h3: set but protocols do not include h3", p)
		}
		if ln.RedirectToHTTPS && ln.TLS != nil {
			v.errf("%s: redirect_to_https only makes sense on a plaintext listener", p)
		}
	}
	l := &s.Limits
	if l.MaxHeaderBytes < 1024 {
		v.errf("server.limits.max_header_bytes: must be at least 1024")
	}
	if l.MaxHeaderBytes > 1<<20 {
		v.errf("server.limits.max_header_bytes: must not exceed 1 MiB")
	}
	if l.MaxBodyBytes < 0 {
		v.errf("server.limits.max_body_bytes: must not be negative")
	}
	if l.MaxURILength < 256 || l.MaxURILength > 65536 {
		v.errf("server.limits.max_uri_length: must be between 256 and 65536")
	}
	for name, d := range map[string]Duration{
		"read_header_timeout": l.ReadHeaderTimeout,
		"read_timeout":        l.ReadTimeout,
		"write_timeout":       l.WriteTimeout,
		"idle_timeout":        l.IdleTimeout,
	} {
		if d <= 0 {
			v.errf("server.limits.%s: must be positive (a zero timeout disables a slowloris defence)", name)
		}
	}
	if l.MaxConnections < 1 || l.MaxConnectionsPerIP < 1 || l.MaxConcurrentRequests < 1 {
		v.errf("server.limits: connection and request limits must be positive")
	}
	if l.MaxTarpits < 1 || l.MaxTarpits > 1_000_000 {
		v.errf("server.limits.max_tarpits: must be between 1 and 1000000")
	}
	if l.MaxConnectionsPerIP > l.MaxConnections {
		v.errf("server.limits.max_connections_per_ip: exceeds max_connections")
	}
}

func (v *validator) tls(p string, t *TLS) {
	if len(t.Certificates) == 0 && len(t.ACME) == 0 {
		v.errf("%s: certificates or acme is required", p)
	}
	seen := map[string]bool{}
	for i, g := range t.ACME {
		gp := fmt.Sprintf("%s.acme[%d]", p, i)
		if len(g.Hosts) == 0 || len(g.Hosts) > 100 {
			v.errf("%s.hosts: 1 to 100 host names", gp)
		}
		for j, h := range g.Hosts {
			if !hostPatternOK(h) || strings.HasPrefix(h, "*.") || !strings.Contains(h, ".") {
				v.errf("%s.hosts[%d]: %q must be a fully qualified host name without wildcard (dns-01 is not supported)", gp, j, h)
			}
			if seen[h] {
				v.errf("%s.hosts[%d]: %q appears in more than one group", gp, j, h)
			}
			seen[h] = true
		}
	}
	for i, c := range t.Certificates {
		if c.CertFile == "" || c.KeyFile == "" {
			v.errf("%s.certificates[%d]: cert_file and key_file are required", p, i)
			continue
		}
		v.file(fmt.Sprintf("%s.certificates[%d].cert_file", p, i), c.CertFile)
		v.file(fmt.Sprintf("%s.certificates[%d].key_file", p, i), c.KeyFile)
	}
	switch t.MinVersion {
	case "1.2", "1.3":
	default:
		v.errf("%s.min_version: must be \"1.2\" or \"1.3\" (TLS 1.0 and 1.1 are never allowed)", p)
	}
	switch t.ClientAuth {
	case "none":
	case "request", "require":
		if t.ClientCAFile == "" {
			v.errf("%s.client_ca_file: required when client_auth is %s", p, t.ClientAuth)
		} else {
			v.file(p+".client_ca_file", t.ClientCAFile)
		}
	default:
		v.errf("%s.client_auth: must be none, request or require", p)
	}
	known := map[string]bool{}
	for _, cs := range tls.CipherSuites() {
		known[cs.Name] = true
	}
	insecure := map[string]bool{}
	for _, cs := range tls.InsecureCipherSuites() {
		insecure[cs.Name] = true
	}
	for i, name := range t.CipherSuites {
		if insecure[name] {
			v.errf("%s.cipher_suites[%d]: %s is insecure and cannot be enabled", p, i, name)
		} else if !known[name] {
			v.errf("%s.cipher_suites[%d]: unknown cipher suite %q", p, i, name)
		}
	}
}

func (v *validator) management(m *Management) {
	if m.Socket == "" {
		return
	}
	if !strings.HasPrefix(m.Socket, "/") {
		v.errf("management.socket: must be an absolute path")
	}
	mode, err := strconv.ParseUint(m.SocketMode, 8, 32)
	if err != nil || mode > 0o777 {
		v.errf("management.socket_mode: %q is not an octal mode", m.SocketMode)
	} else if mode&0o007 != 0 {
		v.errf("management.socket_mode: %q grants access to other; refuse", m.SocketMode)
	}
}

func (v *validator) logging(l *Logging) {
	if !strings.HasPrefix(l.Directory, "/") {
		v.errf("logging.directory: must be an absolute path")
	}
	switch l.Level {
	case "debug", "info", "warn", "error":
	default:
		v.errf("logging.level: must be debug, info, warn or error")
	}
	for name, s := range map[string]LogStream{"access": l.Access, "error": l.Error, "security": l.Security, "audit": l.Audit} {
		if strings.Contains(s.File, "/") || s.File == "" {
			v.errf("logging.%s.file: must be a bare file name inside logging.directory", name)
		}
		if s.MaxSizeMB < 0 || s.MaxFiles < 0 {
			v.errf("logging.%s: rotation values must not be negative", name)
		}
		for i, sink := range s.Sinks {
			switch sink {
			case "file":
			case "journald":
				if l.Journald == nil {
					v.errf("logging.%s.sinks[%d]: journald requires a logging.journald section", name, i)
				}
			case "syslog":
				if l.Syslog == nil {
					v.errf("logging.%s.sinks[%d]: syslog requires a logging.syslog section", name, i)
				}
			default:
				v.errf("logging.%s.sinks[%d]: must be file, journald or syslog", name, i)
			}
		}
	}
	if j := l.Journald; j != nil {
		if !strings.HasPrefix(j.Socket, "/") {
			v.errf("logging.journald.socket: must be an absolute path")
		}
		if !nameRE.MatchString(j.Identifier) {
			v.errf("logging.journald.identifier: %q is not a valid identifier", j.Identifier)
		}
	}
	if s := l.Syslog; s != nil {
		switch s.Network {
		case "unix":
			if !strings.HasPrefix(s.Address, "/") {
				v.errf("logging.syslog.address: must be an absolute socket path for unix")
			}
		case "udp", "tcp", "tcp+tls":
			if _, _, err := net.SplitHostPort(s.Address); err != nil {
				v.errf("logging.syslog.address: %q must be host:port", s.Address)
			}
		default:
			v.errf("logging.syslog.network: must be unix, udp, tcp or tcp+tls")
		}
		if s.Format != "rfc5424" && s.Format != "rfc3164" {
			v.errf("logging.syslog.format: must be rfc5424 or rfc3164")
		}
		if _, ok := syslogFacilities[s.Facility]; !ok {
			v.errf("logging.syslog.facility: unknown facility %q", s.Facility)
		}
		if !nameRE.MatchString(s.AppName) {
			v.errf("logging.syslog.app_name: %q is not valid", s.AppName)
		}
		if s.Network == "tcp+tls" {
			if s.CAFile != "" {
				v.file("logging.syslog.ca_file", s.CAFile)
			}
			if (s.CertFile == "") != (s.KeyFile == "") {
				v.errf("logging.syslog: cert_file and key_file must be set together")
			}
			if s.CertFile != "" {
				v.file("logging.syslog.cert_file", s.CertFile)
				v.file("logging.syslog.key_file", s.KeyFile)
			}
		}
		if s.QueueSize < 64 || s.QueueSize > 1_000_000 {
			v.errf("logging.syslog.queue_size: must be between 64 and 1000000")
		}
	}
	if r := l.Redaction; r != nil {
		for i, st := range r.Streams {
			switch st {
			case "access", "security", "error", "audit":
			default:
				v.errf("logging.redaction.streams[%d]: unknown stream %q", i, st)
			}
		}
		switch r.ClientIP {
		case "keep", "truncate", "hash":
		default:
			v.errf("logging.redaction.client_ip: must be keep, truncate or hash")
		}
		if r.ClientIP == "hash" && r.HashSecretFile != "" && !strings.HasPrefix(r.HashSecretFile, "/") {
			v.errf("logging.redaction.hash_secret_file: must be an absolute path")
		}
		if r.UserAgent != "keep" && r.UserAgent != "drop" {
			v.errf("logging.redaction.user_agent: must be keep or drop")
		}
		switch r.Referer {
		case "keep", "origin", "drop":
		default:
			v.errf("logging.redaction.referer: must be keep, origin or drop")
		}
		switch r.Claims {
		case "keep", "hash", "drop":
		default:
			v.errf("logging.redaction.claims: must be keep, hash or drop")
		}
		for i, f := range r.DropFields {
			if f == "" || len(f) > 64 || f == "time" || f == "level" || f == "msg" || f == "stream" {
				v.errf("logging.redaction.drop_fields[%d]: %q cannot be dropped", i, f)
			}
		}
	}
}

// SyslogFacilities maps facility names to their codes.
var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
	"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// SyslogFacility returns the numeric facility for a validated name.
func SyslogFacility(name string) int { return syslogFacilities[name] }

func (v *validator) rateLimit(i int, r *RateLimit, seen map[string]bool) {
	p := fmt.Sprintf("rate_limits[%d]", i)
	if !nameRE.MatchString(r.Name) {
		v.errf("%s.name: %q is not a valid name", p, r.Name)
	} else if seen[r.Name] {
		v.errf("%s.name: duplicate %q", p, r.Name)
	}
	seen[r.Name] = true
	switch {
	case r.Key == "client_ip", r.Key == "route", r.Key == "country":
	case strings.HasPrefix(r.Key, "header:") && len(r.Key) > len("header:"):
	default:
		v.errf("%s.key: must be client_ip, route, country or header:<name>", p)
	}
	if r.Rate <= 0 {
		v.errf("%s.rate: must be positive", p)
	}
	if r.Burst < 1 {
		v.errf("%s.burst: must be at least 1", p)
	}
	switch r.Action {
	case "reject", "tarpit":
	default:
		v.errf("%s.action: must be reject or tarpit", p)
	}
	if r.TarpitDelay <= 0 {
		v.errf("%s.tarpit_delay: must be positive", p)
	}
}

func (v *validator) upstream(i int, u *Upstream, seen map[string]bool) {
	p := fmt.Sprintf("upstreams[%d]", i)
	if !nameRE.MatchString(u.Name) {
		v.errf("%s.name: %q is not a valid name", p, u.Name)
	} else if seen[u.Name] {
		v.errf("%s.name: duplicate %q", p, u.Name)
	}
	seen[u.Name] = true
	switch u.Balancer {
	case "round_robin", "weighted", "least_conn", "hash":
	default:
		v.errf("%s.balancer: must be round_robin, weighted, least_conn or hash", p)
	}
	if u.Balancer == "hash" {
		switch {
		case u.HashOn == "client_ip":
		case strings.HasPrefix(u.HashOn, "header:") && len(u.HashOn) > 7:
		case strings.HasPrefix(u.HashOn, "cookie:") && len(u.HashOn) > 7:
		default:
			v.errf("%s.hash_on: must be client_ip, header:<name> or cookie:<name>", p)
		}
	}
	switch u.Scheme {
	case "http":
		if u.TLS != nil {
			v.errf("%s.tls: set only when scheme is https", p)
		}
	case "https":
		if u.H2C {
			v.errf("%s.h2c: only for scheme http (https negotiates HTTP/2 with ALPN)", p)
		}
		if u.TLS != nil {
			v.upstreamTLS(p+".tls", u.TLS)
		}
	default:
		v.errf("%s.scheme: must be http or https", p)
	}
	if len(u.Endpoints) == 0 {
		v.errf("%s.endpoints: at least one endpoint is required", p)
	}
	addrs := map[string]bool{}
	for j, e := range u.Endpoints {
		ep := fmt.Sprintf("%s.endpoints[%d]", p, j)
		host, port, err := net.SplitHostPort(e.Address)
		if err != nil || host == "" || port == "" {
			v.errf("%s.address: %q must be host:port", ep, e.Address)
		} else if addrs[e.Address] {
			v.errf("%s.address: duplicate %q", ep, e.Address)
		} else if pn, err := strconv.Atoi(port); err != nil || pn < 1 || pn > 65535 {
			v.errf("%s.address: bad port in %q", ep, e.Address)
		}
		addrs[e.Address] = true
		if e.Weight < 1 || e.Weight > 1000 {
			v.errf("%s.weight: must be between 1 and 1000", ep)
		}
	}
	if u.Timeouts.Connect <= 0 || u.Timeouts.ResponseHeader <= 0 || u.Timeouts.Total <= 0 {
		v.errf("%s.timeouts: connect, response_header and total must be positive", p)
	}
	if u.Retries != nil && (*u.Retries < 0 || *u.Retries > 5) {
		v.errf("%s.retries: must be between 0 and 5", p)
	}
	if u.MaxIdleConnsPerHost < 0 {
		v.errf("%s.max_idle_conns_per_host: must not be negative", p)
	}
	if hc := u.HealthCheck; hc != nil {
		switch hc.Type {
		case "http":
			if hc.GRPCService != "" {
				v.errf("%s.health_check.grpc_service: only for type grpc", p)
			}
		case "grpc":
			if !u.H2C && u.Scheme != "https" {
				v.errf("%s.health_check.type: grpc needs h2c or scheme https", p)
			}
			if hc.Path != DefaultHealthCheckPath {
				v.errf("%s.health_check.path: not used by type grpc", p)
			}
			if len(hc.GRPCService) > 253 || strings.ContainsAny(hc.GRPCService, " /\r\n") {
				v.errf("%s.health_check.grpc_service: %q is not a service name", p, hc.GRPCService)
			}
		default:
			v.errf("%s.health_check.type: must be http or grpc", p)
		}
		if !strings.HasPrefix(hc.Path, "/") {
			v.errf("%s.health_check.path: must start with /", p)
		}
		if hc.Interval < Duration(500_000_000) {
			v.errf("%s.health_check.interval: must be at least 500ms", p)
		}
		if hc.Timeout <= 0 || hc.Timeout >= hc.Interval {
			v.errf("%s.health_check.timeout: must be positive and shorter than interval", p)
		}
		if hc.MaxConcurrent < 1 || hc.MaxConcurrent > 4096 {
			v.errf("%s.health_check.max_concurrent: must be between 1 and 4096", p)
		}
		if hc.HealthyThreshold < 1 || hc.UnhealthyThreshold < 1 {
			v.errf("%s.health_check: thresholds must be at least 1", p)
		}
		for _, st := range hc.ExpectedStatus {
			if st < 100 || st > 599 {
				v.errf("%s.health_check.expected_status: %d is not an HTTP status", p, st)
			}
		}
	}
	if a := u.Affinity; a != nil {
		if !cookieNameOK(a.CookieName) {
			v.errf("%s.affinity.cookie_name: %q is not a valid cookie name", p, a.CookieName)
		}
		if a.TTL <= 0 {
			v.errf("%s.affinity.ttl: must be positive", p)
		}
		if a.SecretFile != "" && !strings.HasPrefix(a.SecretFile, "/") {
			v.errf("%s.affinity.secret_file: must be an absolute path", p)
		}
	}
	if o := u.OutlierEjection; o != nil {
		if o.ConsecutiveFailures < 1 {
			v.errf("%s.outlier_ejection.consecutive_failures: must be at least 1", p)
		}
		if o.BaseEjectionTime <= 0 {
			v.errf("%s.outlier_ejection.base_ejection_time: must be positive", p)
		}
		if o.MaxEjectionPercent < 0 || o.MaxEjectionPercent > 100 {
			v.errf("%s.outlier_ejection.max_ejection_percent: must be 0..100", p)
		}
	}
}

func (v *validator) upstreamTLS(p string, t *UpstreamTLS) {
	if t.CAFile != "" {
		v.file(p+".ca_file", t.CAFile)
	}
	switch t.MinVersion {
	case "1.2", "1.3":
	default:
		v.errf("%s.min_version: must be \"1.2\" or \"1.3\"", p)
	}
	for i, pin := range t.SPKIPins {
		if raw, err := base64.StdEncoding.DecodeString(pin); err != nil || len(raw) != 32 {
			v.errf("%s.spki_pins[%d]: must be a base64 SHA-256 digest", p, i)
		}
	}
	if len(t.SPKIPins) > 0 && t.InsecureSkipVerify {
		v.errf("%s: spki_pins cannot be combined with insecure_skip_verify", p)
	}
	if (t.ClientCertFile == "") != (t.ClientKeyFile == "") {
		v.errf("%s: client_cert_file and client_key_file must be set together", p)
	}
	if t.ClientCertFile != "" {
		v.file(p+".client_cert_file", t.ClientCertFile)
		v.file(p+".client_key_file", t.ClientKeyFile)
	}
	if t.InsecureSkipVerify && !t.AllowInsecure {
		v.errf("%s.insecure_skip_verify: refused unless allow_insecure is also true", p)
	}
}

func (v *validator) route(i int, r *Route, seen, upstreams, rateLimits map[string]bool) {
	p := fmt.Sprintf("routes[%d]", i)
	if !nameRE.MatchString(r.Name) {
		v.errf("%s.name: %q is not a valid name", p, r.Name)
	} else if seen[r.Name] {
		v.errf("%s.name: duplicate %q", p, r.Name)
	}
	seen[r.Name] = true

	for j, h := range r.Hosts {
		if !hostPatternOK(h) {
			v.errf("%s.hosts[%d]: %q is not a valid host pattern", p, j, h)
		}
	}
	for j, path := range r.Paths {
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\ ") {
			v.errf("%s.paths[%d]: %q must be an absolute, normalised prefix", p, j, path)
		}
	}
	for j, m := range r.Methods {
		if m != strings.ToUpper(m) || m == "" || strings.ContainsAny(m, " \t") {
			v.errf("%s.methods[%d]: %q must be an upper-case token", p, j, m)
		}
	}
	if len(r.PathRegex) > 32 {
		v.errf("%s.path_regex: at most 32 patterns", p)
	}
	for j, re := range r.PathRegex {
		switch {
		case re == "" || len(re) > 512:
			v.errf("%s.path_regex[%d]: must be 1 to 512 bytes", p, j)
		case !strings.HasPrefix(re, "/") && !strings.HasPrefix(re, "^/") && !strings.HasPrefix(re, "\\/"):
			v.errf("%s.path_regex[%d]: %q must start with / (patterns match the whole path)", p, j, re)
		default:
			if _, err := regexp.Compile("^(?:" + re + ")$"); err != nil {
				v.errf("%s.path_regex[%d]: %v", p, j, err)
			}
		}
	}
	if len(r.Headers)+len(r.Cookies) > 16 {
		v.errf("%s: at most 16 header and cookie conditions", p)
	}
	v.headerMatches(p+".headers", r.Headers, false)
	v.headerMatches(p+".cookies", r.Cookies, true)

	actions := 0
	if r.Upstream != "" {
		actions++
		if !upstreams[r.Upstream] {
			v.errf("%s.upstream: unknown upstream %q", p, r.Upstream)
		}
	}
	if r.Redirect != nil {
		actions++
		if r.Redirect.To == "" {
			v.errf("%s.redirect.to: required", p)
		} else if u, err := url.Parse(r.Redirect.To); err != nil || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https") {
			v.errf("%s.redirect.to: %q is not a valid http(s) URL or path", p, r.Redirect.To)
		}
		switch r.Redirect.Status {
		case 301, 302, 303, 307, 308:
		default:
			v.errf("%s.redirect.status: must be a redirect status", p)
		}
	}
	if r.Respond != nil {
		actions++
		if r.Respond.Status < 200 || r.Respond.Status > 599 {
			v.errf("%s.respond.status: %d is not a valid status", p, r.Respond.Status)
		}
		if len(r.Respond.Body) > 64<<10 {
			v.errf("%s.respond.body: exceeds 64 KiB", p)
		}
	}
	if hp := r.Honeypot; hp != nil {
		actions++
		if hp.Status < 200 || hp.Status > 599 {
			v.errf("%s.honeypot.status: %d is not a valid status", p, hp.Status)
		}
		sources := 0
		for _, set := range []bool{hp.Decoy != "", hp.Body != "", hp.BodyFile != ""} {
			if set {
				sources++
			}
		}
		if sources != 1 {
			v.errf("%s.honeypot: exactly one of decoy, body or body_file is required", p)
		}
		if hp.Decoy != "" && !HoneypotDecoys[hp.Decoy] {
			v.errf("%s.honeypot.decoy: unknown decoy %q", p, hp.Decoy)
		}
		if len(hp.Body) > 64<<10 {
			v.errf("%s.honeypot.body: exceeds 64 KiB", p)
		}
		if hp.BodyFile != "" && !strings.HasPrefix(hp.BodyFile, "/") {
			v.errf("%s.honeypot.body_file: must be an absolute path", p)
		}
		if strings.ContainsAny(hp.ContentType, "\r\n") {
			v.errf("%s.honeypot.content_type: invalid", p)
		}
		if hp.Delay < 0 || hp.Delay > Duration(60*time.Second) {
			v.errf("%s.honeypot.delay: must be between 0 and 60s", p)
		}
		if hp.Mark <= 0 || hp.Mark > Duration(30*24*time.Hour) {
			v.errf("%s.honeypot.mark: must be positive and at most 720h", p)
		}
	}
	if r.DoH != nil {
		actions++
		if r.DoH.Listener == "" {
			v.errf("%s.doh.listener: required", p)
		}
	}
	if st := r.Static; st != nil {
		actions++
		switch {
		case st.Root == "":
			v.errf("%s.static.root: required", p)
		case !strings.HasPrefix(st.Root, "/"):
			v.errf("%s.static.root: must be an absolute path", p)
		case v.fileCheck:
			if info, err := os.Stat(st.Root); err != nil {
				v.errf("%s.static.root: %v", p, err)
			} else if !info.IsDir() {
				v.errf("%s.static.root: %s is not a directory", p, st.Root)
			}
		}
		if idx := st.IndexFile(); strings.ContainsAny(idx, "/\\") || idx == "." || idx == ".." {
			v.errf("%s.static.index: must be a file name", p)
		}
		if st.Fallback != "" && (!strings.HasPrefix(st.Fallback, "/") || strings.Contains(st.Fallback, "..")) {
			v.errf("%s.static.fallback: must be an absolute path inside root", p)
		}
		if strings.ContainsAny(st.CacheControl, "\r\n") {
			v.errf("%s.static.cache_control: invalid", p)
		}
		if st.MaxFileBytes < 0 {
			v.errf("%s.static.max_file_bytes: must not be negative", p)
		}
		if r.Cache != nil || r.Mirror != nil || r.GRPC != nil || r.WebSocket {
			v.errf("%s.static: cache, mirror, grpc and websocket do not apply to a static route", p)
		}
	}
	if actions != 1 {
		v.errf("%s: exactly one of upstream, redirect, respond, honeypot, doh or static is required", p)
	}
	if g := r.GRPC; g != nil {
		for j, sv := range g.Services {
			if !grpcNameOK(sv) || strings.Contains(sv, "/") {
				v.errf("%s.grpc.services[%d]: %q is not a service name", p, j, sv)
			}
		}
		for j, m := range g.Methods {
			sv, mn, ok := strings.Cut(m, "/")
			if !ok || !grpcNameOK(sv) || !grpcNameOK(mn) || strings.Contains(mn, "/") {
				v.errf("%s.grpc.methods[%d]: %q is not Service/Method", p, j, m)
			}
		}
		if r.Redirect != nil || r.Respond != nil || r.Honeypot != nil {
			v.errf("%s.grpc: only a route with an upstream can match gRPC", p)
		}
	}
	if m := r.Mirror; m != nil {
		if r.Upstream == "" {
			v.errf("%s.mirror: only a route with an upstream can mirror", p)
		}
		switch {
		case m.Upstream == "":
			v.errf("%s.mirror.upstream: required", p)
		case !upstreams[m.Upstream]:
			v.errf("%s.mirror.upstream: unknown upstream %q", p, m.Upstream)
		case m.Upstream == r.Upstream:
			v.errf("%s.mirror.upstream: must differ from the route's upstream", p)
		}
		if m.Percent < 1 || m.Percent > 100 {
			v.errf("%s.mirror.percent: must be between 1 and 100", p)
		}
		for j, x := range m.Methods {
			if x == "" || strings.ToUpper(x) != x {
				v.errf("%s.mirror.methods[%d]: %q must be an upper-case token", p, j, x)
			}
		}
		if m.MaxBodyBytes < 0 || m.MaxBodyBytes > 64<<20 {
			v.errf("%s.mirror.max_body_bytes: must be between 0 and 64 MiB", p)
		}
		if m.Timeout <= 0 || m.Timeout > Duration(5*time.Minute) {
			v.errf("%s.mirror.timeout: must be positive and at most 5m", p)
		}
		if m.MaxInFlight < 1 || m.MaxInFlight > 10000 {
			v.errf("%s.mirror.max_in_flight: must be between 1 and 10000", p)
		}
	}
	if r.StripPrefix != "" && !strings.HasPrefix(r.StripPrefix, "/") {
		v.errf("%s.strip_prefix: must start with /", p)
	}
	if r.RewritePath != "" && !strings.HasPrefix(r.RewritePath, "/") {
		v.errf("%s.rewrite_path: must start with /", p)
	}
	if r.StripPrefix != "" && r.RewritePath != "" {
		v.errf("%s: strip_prefix and rewrite_path are mutually exclusive", p)
	}
	for j, name := range r.RateLimits {
		if !rateLimits[name] {
			v.errf("%s.rate_limits[%d]: unknown rate limit %q", p, j, name)
		}
	}
	for j, c := range r.AllowCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_cidrs[%d]: %q is not a CIDR", p, j, c)
		}
	}
	for j, c := range r.DenyCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.deny_cidrs[%d]: %q is not a CIDR", p, j, c)
		}
	}
	if r.MaxBodyBytes != nil && *r.MaxBodyBytes < 0 {
		v.errf("%s.max_body_bytes: must not be negative", p)
	}
	if r.Timeout < 0 {
		v.errf("%s.timeout: must not be negative", p)
	}
	v.headerOps(p+".request_headers", r.RequestHeaders)
	v.headerOps(p+".response_headers", r.ResponseHeaders)
}

var denyReasons = map[string]bool{
	"acl": true, "rate_limit": true, "waf": true, "body_size": true, "uri_length": true,
	"bad_host": true, "no_route": true, "websocket": true, "concurrency": true, "challenge": true, "jwt": true, "icap": true,
	"geo": true, "tcp_no_route": true, "forward_denied": true, "forward_auth": true, "honeypot": true, "dns_blocked": true,
}

// HoneypotDecoys are the built-in decoy names (bodies live in the proxy).
var HoneypotDecoys = map[string]bool{"wp-login": true, "env": true, "git-config": true, "phpinfo": true, "admin-login": true, "robots": true}

func (v *validator) bans(b *Bans) {
	if b.StateFile != "" && !strings.HasPrefix(b.StateFile, "/") {
		v.errf("bans.state_file: must be an absolute path")
	}
	if b.MaxEntries < 1 || b.MaxEntries > 10_000_000 {
		v.errf("bans.max_entries: must be between 1 and 10000000")
	}
	for i, c := range b.ExemptCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("bans.exempt_cidrs[%d]: %q is not a CIDR", i, c)
		}
	}
	switch b.Action {
	case "drop", "reject":
	default:
		v.errf("bans.action: must be drop or reject")
	}
	names := map[string]bool{}
	for i, t := range b.Triggers {
		p := fmt.Sprintf("bans.triggers[%d]", i)
		if !nameRE.MatchString(t.Name) {
			v.errf("%s.name: %q is not a valid name", p, t.Name)
		} else if names[t.Name] {
			v.errf("%s.name: duplicate %q", p, t.Name)
		}
		names[t.Name] = true
		for j, r := range t.Reasons {
			if !denyReasons[r] {
				v.errf("%s.reasons[%d]: unknown reason %q", p, j, r)
			}
		}
		if t.Threshold < 1 {
			v.errf("%s.threshold: must be at least 1", p)
		}
		if t.Window <= 0 || t.Window > Duration(24*3600*1e9) {
			v.errf("%s.window: must be positive and at most 24h", p)
		}
		if t.Duration <= 0 {
			v.errf("%s.duration: must be positive", p)
		}
		if t.Escalation < 1 || t.Escalation > 100 {
			v.errf("%s.escalation: must be between 1 and 100", p)
		}
		if t.MaxDuration < t.Duration {
			v.errf("%s.max_duration: must be at least duration", p)
		}
	}
}

func (v *validator) cluster(c *Cluster) {
	if !nameRE.MatchString(c.NodeID) {
		v.errf("cluster.node_id: %q is not a valid name", c.NodeID)
	}
	if c.Listen == "" {
		v.errf("cluster.listen: required")
	} else if host, port, err := net.SplitHostPort(c.Listen); err != nil {
		v.errf("cluster.listen: %q: %v", c.Listen, err)
	} else if host == "" || host == "0.0.0.0" || host == "::" {
		if port != "0" {
			v.errf("cluster.listen: bind to an internal interface address, not all interfaces")
		}
	}
	seen := map[string]bool{}
	for i, p := range c.Peers {
		if _, _, err := net.SplitHostPort(p); err != nil {
			v.errf("cluster.peers[%d]: %q must be host:port", i, p)
		} else if seen[p] {
			v.errf("cluster.peers[%d]: duplicate %q", i, p)
		}
		seen[p] = true
	}
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.CAFile == "" {
		v.errf("cluster.tls: cert_file, key_file and ca_file are all required (mutual TLS is mandatory)")
	} else {
		v.file("cluster.tls.cert_file", c.TLS.CertFile)
		v.file("cluster.tls.key_file", c.TLS.KeyFile)
		v.file("cluster.tls.ca_file", c.TLS.CAFile)
	}
	if c.GossipInterval < Duration(100_000_000) || c.GossipInterval > Duration(60_000_000_000) {
		v.errf("cluster.gossip_interval: must be between 100ms and 60s")
	}
	if c.PeerStale < c.GossipInterval*2 {
		v.errf("cluster.peer_stale: must be at least twice gossip_interval")
	}
	if c.MaxKeysPerReport < 1 || c.MaxKeysPerReport > 65536 {
		v.errf("cluster.max_keys_per_report: must be 1..65536")
	}
}

func (v *validator) acme(a *ACME) {
	if u, err := url.Parse(a.Directory); err != nil || u.Scheme != "https" || u.Host == "" {
		v.errf("acme.directory: must be an https URL")
	}
	if !a.AcceptTerms {
		v.errf("acme.accept_terms: must be true to register with the CA")
	}
	if a.Email != "" && (!strings.Contains(a.Email, "@") || strings.ContainsAny(a.Email, " <>,")) {
		v.errf("acme.email: %q is not an address", a.Email)
	}
	if !strings.HasPrefix(a.StateDir, "/") {
		v.errf("acme.state_dir: must be an absolute path")
	}
	if a.CAFile != "" {
		v.file("acme.ca_file", a.CAFile)
	}
	if a.Challenge != "http-01" && a.Challenge != "tls-alpn-01" {
		v.errf("acme.challenge: must be http-01 or tls-alpn-01")
	}
	if a.RenewBefore < Duration(24*3600*1e9) || a.RenewBefore > Duration(89*24*3600*1e9) {
		v.errf("acme.renew_before: must be between 24h and 89 days")
	}
	if a.CheckInterval < Duration(60*1e9) || a.CheckInterval > Duration(7*24*3600*1e9) {
		v.errf("acme.check_interval: must be between 1m and 7d")
	}
}

func (v *validator) metrics(m *Metrics) {
	if m.Listen != "" {
		host, _, err := net.SplitHostPort(m.Listen)
		if err != nil {
			v.errf("metrics.listen: %q: %v", m.Listen, err)
		} else if (host == "" || host == "0.0.0.0" || host == "::") && (m.TLS == nil || m.TLS.ClientCAFile == "") {
			v.errf("metrics.listen: binding all interfaces requires tls with client_ca_file")
		}
	}
	for i, c := range m.AllowCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("metrics.allow_cidrs[%d]: %q is not a CIDR", i, c)
		}
	}
	if t := m.TLS; t != nil {
		if t.CertFile == "" || t.KeyFile == "" {
			v.errf("metrics.tls: cert_file and key_file are required")
		} else {
			v.file("metrics.tls.cert_file", t.CertFile)
			v.file("metrics.tls.key_file", t.KeyFile)
		}
		if t.ClientCAFile != "" {
			v.file("metrics.tls.client_ca_file", t.ClientCAFile)
		}
	}
	if o := m.OTLP; o != nil {
		u, err := url.Parse(o.Endpoint)
		schemeOK := u.Scheme == "https" || (u.Scheme == "http" && o.AllowHTTP)
		if err != nil || u.Host == "" || !schemeOK {
			v.errf("metrics.otlp.endpoint: must be an https URL (http only with allow_http)")
		}
		if o.Interval < Duration(time.Second) || o.Interval > Duration(time.Hour) {
			v.errf("metrics.otlp.interval: must be between 1s and 1h")
		}
		if o.Timeout <= 0 || o.Timeout > o.Interval {
			v.errf("metrics.otlp.timeout: must be positive and at most interval")
		}
		for k, val := range o.Headers {
			if k == "" || strings.ContainsAny(k, " :\r\n") || strings.ContainsAny(val, "\r\n") {
				v.errf("metrics.otlp.headers: %q is not a header", k)
			}
		}
		if o.CAFile != "" {
			v.file("metrics.otlp.ca_file", o.CAFile)
		}
		if o.ServiceName == "" || len(o.ServiceName) > 255 {
			v.errf("metrics.otlp.service_name: must be 1 to 255 characters")
		}
		for k := range o.Attributes {
			if k == "" || len(k) > 255 {
				v.errf("metrics.otlp.attributes: empty or overlong key")
			}
		}
	}
	if m.SampleInterval < Duration(1_000_000_000) || m.SampleInterval > Duration(300_000_000_000) {
		v.errf("metrics.sample_interval: must be between 1s and 5m")
	}
	if m.Retention < m.SampleInterval*2 || m.Retention > Duration(7*24*3600*1e9) {
		v.errf("metrics.retention: must be at least twice sample_interval and at most 7d")
	}
	if m.Retention/m.SampleInterval > 100_000 {
		v.errf("metrics.retention: retention / sample_interval must not exceed 100000 points")
	}
}

func (v *validator) shedding(s *Shedding) {
	if s.TargetLatency < Duration(1_000_000) {
		v.errf("shedding.target_latency: must be at least 1ms")
	}
	if s.Window < Duration(1_000_000_000) || s.Window > Duration(600_000_000_000) {
		v.errf("shedding.window: must be between 1s and 10m")
	}
	for name, t := range map[string]float64{"low": s.Low, "normal": s.Normal, "high": s.High} {
		if t <= 0 || t > 1 {
			v.errf("shedding.%s: must be between 0 and 1", name)
		}
	}
	if !(s.Low <= s.Normal && s.Normal <= s.High) {
		v.errf("shedding: thresholds must satisfy low <= normal <= high")
	}
	if s.Hysteresis < 0 || s.Hysteresis >= s.Low {
		v.errf("shedding.hysteresis: must be non-negative and below the low threshold")
	}
	if s.RetryAfter <= 0 {
		v.errf("shedding.retry_after: must be positive")
	}
}

// filter validates one middleware instance against the registry.
func (v *validator) filter(i int, f *FilterConfig, seen map[string]bool) {
	p := fmt.Sprintf("filters[%d]", i)
	if !nameRE.MatchString(f.Name) {
		v.errf("%s.name: %q is not a valid name", p, f.Name)
	} else if seen[f.Name] {
		v.errf("%s.name: duplicate %q", p, f.Name)
	}
	seen[f.Name] = true
	switch f.Stage {
	case StageBeforeAuth, StageAfterAuth, StageAfterWAF, StageAfterScan:
	default:
		v.errf("%s.stage: %q must be before_auth, after_auth, after_waf or after_scan", p, f.Stage)
	}
	k, ok := filter.Lookup(f.Kind)
	if !ok {
		v.errf("%s.kind: %q is not a registered filter kind (registered: %s)", p, f.Kind, strings.Join(filter.KindNames(), ", "))
		return
	}
	if err := k.Validate(filter.Options(f.Options)); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			v.errf("%s.options: %s", p, line)
		}
	}
}

// tcpListener validates an L4 listener; upstream references are checked
// after the upstreams are known (see validate).
func (v *validator) tcpListener(p string, t *TCPListener) {
	if len(t.Routes) == 0 && t.Default == "" {
		v.errf("%s: routes or default is required", p)
	}
	seen := map[string]bool{}
	for i, r := range t.Routes {
		rp := fmt.Sprintf("%s.routes[%d]", p, i)
		if len(r.SNI) == 0 {
			v.errf("%s.sni: at least one server name is required", rp)
		}
		for _, n := range r.SNI {
			if !hostPatternOK(n) {
				v.errf("%s.sni: %q is not a valid name or *.suffix pattern", rp, n)
			}
			if seen[n] {
				v.errf("%s.sni: %q listed twice", rp, n)
			}
			seen[n] = true
		}
		if r.Upstream == "" {
			v.errf("%s.upstream: required", rp)
		}
	}
	if t.IdleTimeout <= 0 || t.IdleTimeout > Duration(24*time.Hour) {
		v.errf("%s.idle_timeout: must be positive and at most 24h", p)
	}
	if t.MaxConnections < 1 {
		v.errf("%s.max_connections: must be positive", p)
	}
	if t.QUICIdleTimeout <= 0 || t.QUICIdleTimeout > Duration(time.Hour) {
		v.errf("%s.quic_idle_timeout: must be positive and at most 1h", p)
	}
	if t.QUIC && t.ProxyProtocol {
		v.errf("%s.quic: the PROXY protocol header cannot be sent on a datagram flow; disable proxy_protocol or quic", p)
	}
}

// grpcNameOK accepts protobuf identifiers with dots (package.Service).
func grpcNameOK(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range s {
		ok := c == '.' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// destinationPatternOK accepts a host name, *.suffix pattern, IP address
// or CIDR for forward proxy allow and deny lists.
func destinationPatternOK(d string) bool {
	if _, err := netip.ParsePrefix(d); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return true
	}
	return hostPatternOK(d)
}

func (v *validator) ingress(in *Ingress, listeners map[string]*Listener) {
	if !in.Enabled {
		return
	}
	u, err := url.Parse(in.APIServer)
	schemeOK := u.Scheme == "https" || (u.Scheme == "http" && in.AllowHTTP)
	if err != nil || u.Host == "" || !schemeOK {
		v.errf("ingress.api_server: must be an https URL (http only with allow_http)")
	}
	if in.TokenFile != "" && !strings.HasPrefix(in.TokenFile, "/") {
		v.errf("ingress.token_file: must be an absolute path")
	}
	if in.CAFile != "" && !strings.HasPrefix(in.CAFile, "/") {
		v.errf("ingress.ca_file: must be an absolute path")
	}
	if !nameRE.MatchString(in.Class) {
		v.errf("ingress.class: %q is not a valid name", in.Class)
	}
	for i, ns := range in.Namespaces {
		if !hostPatternOK(ns) || strings.Contains(ns, ".") || strings.Contains(ns, "*") {
			v.errf("ingress.namespaces[%d]: %q is not a namespace", i, ns)
		}
	}
	if in.Listener != "" {
		ln, ok := listeners[in.Listener]
		switch {
		case !ok:
			v.errf("ingress.listener: unknown listener %q", in.Listener)
		case ln.Kind != "http" || ln.TLS == nil:
			v.errf("ingress.listener: %q must be an http listener with tls", in.Listener)
		}
	}
	if !strings.HasPrefix(in.CertDir, "/") {
		v.errf("ingress.cert_dir: must be an absolute path")
	}
	if in.Resync < Duration(time.Second) || in.Resync > Duration(time.Hour) {
		v.errf("ingress.resync: must be between 1s and 1h")
	}
	if in.Timeout <= 0 || in.Timeout > Duration(5*time.Minute) {
		v.errf("ingress.timeout: must be positive and at most 5m")
	}
	if in.Debounce < Duration(50*time.Millisecond) || in.Debounce > Duration(time.Minute) {
		v.errf("ingress.debounce: must be between 50ms and 1m")
	}
}

func (v *validator) dnsListener(p string, d *DNSListener) {
	if len(d.Upstreams) == 0 {
		v.errf("%s.upstreams: at least one resolver is required", p)
	}
	for i, u := range d.Upstreams {
		if err := dnsUpstreamOK(u); err != nil {
			v.errf("%s.upstreams[%d]: %v", p, i, err)
		}
	}
	if d.UpstreamCAFile != "" {
		v.file(p+".upstream_ca_file", d.UpstreamCAFile)
	}
	if d.Timeout <= 0 || d.Timeout > Duration(30*time.Second) {
		v.errf("%s.timeout: must be positive and at most 30s", p)
	}
	for i, c := range d.AllowClients {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR", p, i, c)
		}
	}
	for i, b := range d.Block {
		name := strings.TrimPrefix(strings.TrimPrefix(b, "*."), "=")
		if !hostPatternOK(strings.ToLower(strings.TrimSuffix(name, "."))) {
			v.errf("%s.block[%d]: %q is not a name, *.suffix or =name", p, i, b)
		}
	}
	if d.BlockFile != "" && !strings.HasPrefix(d.BlockFile, "/") {
		v.errf("%s.block_file: must be an absolute path", p)
	}
	switch d.BlockAction {
	case "nxdomain", "refuse", "sinkhole":
	default:
		v.errf("%s.block_action: must be nxdomain, refuse or sinkhole", p)
	}
	if a, err := netip.ParseAddr(d.SinkholeIPv4); err != nil || !a.Is4() {
		v.errf("%s.sinkhole_ipv4: %q is not an IPv4 address", p, d.SinkholeIPv4)
	}
	if a, err := netip.ParseAddr(d.SinkholeIPv6); err != nil || !a.Is6() || a.Is4In6() {
		v.errf("%s.sinkhole_ipv6: %q is not an IPv6 address", p, d.SinkholeIPv6)
	}
	if c := d.Cache; c != nil {
		if c.MaxEntries < 1 || c.MaxEntries > 10_000_000 {
			v.errf("%s.cache.max_entries: must be between 1 and 10000000", p)
		}
		if c.MinTTL < 0 || c.MaxTTL <= 0 || c.MinTTL > c.MaxTTL || c.MaxTTL > Duration(7*24*time.Hour) {
			v.errf("%s.cache: min_ttl must not exceed max_ttl, max_ttl at most 168h", p)
		}
		if c.NegativeTTL < 0 || c.NegativeTTL > Duration(24*time.Hour) {
			v.errf("%s.cache.negative_ttl: must be between 0 and 24h", p)
		}
	}
	if rl := d.RateLimit; rl != nil {
		if rl.QPS <= 0 || rl.QPS > 1_000_000 || rl.Burst < 1 {
			v.errf("%s.rate_limit: qps must be positive and burst at least 1", p)
		}
	}
	if d.MaxInFlight < 1 || d.MaxInFlight > 1_000_000 {
		v.errf("%s.max_in_flight: must be between 1 and 1000000", p)
	}
}

// dnsUpstreamOK mirrors dns.ParseUpstream without importing the package.
func dnsUpstreamOK(s string) error {
	switch {
	case strings.HasPrefix(s, "tls://"):
		host, port, err := net.SplitHostPort(strings.TrimPrefix(s, "tls://"))
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("%q must be tls://host:port", s)
		}
	case strings.HasPrefix(s, "https://"):
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.Path == "" || u.RawQuery != "" || u.User != nil {
			return fmt.Errorf("%q must be https://host[:port]/path", s)
		}
	case strings.Contains(s, "://"):
		return fmt.Errorf("%q: unknown transport (use host:port, tls:// or https://)", s)
	default:
		host, port, err := net.SplitHostPort(s)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("%q must be host:port", s)
		}
	}
	return nil
}

func (v *validator) forwardListener(p string, f *ForwardListener) {
	seen := map[int]bool{}
	for _, port := range f.Ports {
		if port < 1 || port > 65535 {
			v.errf("%s.ports: %d is not a port", p, port)
		}
		if seen[port] {
			v.errf("%s.ports: %d listed twice", p, port)
		}
		seen[port] = true
	}
	for _, d := range f.Allow {
		if !destinationPatternOK(d) {
			v.errf("%s.allow: %q is not a name, *.suffix, address or CIDR", p, d)
		}
	}
	for _, d := range f.Deny {
		if !destinationPatternOK(d) {
			v.errf("%s.deny: %q is not a name, *.suffix, address or CIDR", p, d)
		}
	}
	if f.Auth != nil {
		if f.Auth.UsersFile == "" {
			v.errf("%s.auth.users_file: required", p)
		}
		if strings.ContainsAny(f.Auth.Realm, "\"\r\n") {
			v.errf("%s.auth.realm: must not contain quotes or line breaks", p)
		}
	}
	if f.ConnectTimeout <= 0 || f.ConnectTimeout > Duration(5*time.Minute) {
		v.errf("%s.connect_timeout: must be positive and at most 5m", p)
	}
	if f.IdleTimeout <= 0 || f.IdleTimeout > Duration(24*time.Hour) {
		v.errf("%s.idle_timeout: must be positive and at most 24h", p)
	}
	if f.MaxTunnels < 1 {
		v.errf("%s.max_tunnels: must be positive", p)
	}
	if f.MaxResponseBytes < 0 {
		v.errf("%s.max_response_bytes: must not be negative", p)
	}
}

func (v *validator) icap(ic *ICAP, seen map[string]bool) {
	if len(ic.Services) == 0 {
		v.errf("icap.services: at least one service is required")
	}
	for i := range ic.Services {
		s := &ic.Services[i]
		p := fmt.Sprintf("icap.services[%d]", i)
		if !nameRE.MatchString(s.Name) {
			v.errf("%s.name: %q is not a valid name", p, s.Name)
		} else if seen[s.Name] {
			v.errf("%s.name: duplicate %q", p, s.Name)
		}
		seen[s.Name] = true
		u, err := url.Parse(s.URL)
		if err != nil || (u.Scheme != "icap" && u.Scheme != "icaps") || u.Host == "" || u.Path == "" {
			v.errf("%s.url: must be icap://host[:port]/service or icaps://...", p)
		}
		if s.TLS != nil {
			if u != nil && u.Scheme != "icaps" {
				v.errf("%s.tls: set only with an icaps:// url", p)
			}
			if s.TLS.CAFile != "" {
				v.file(p+".tls.ca_file", s.TLS.CAFile)
			}
		}
		if s.ConnectTimeout <= 0 || s.Timeout <= 0 || s.Timeout > Duration(120_000_000_000) {
			v.errf("%s: connect_timeout and timeout must be positive (timeout at most 2m)", p)
		}
		if s.MaxConns < 1 || s.MaxConns > 1024 {
			v.errf("%s.max_conns: must be 1..1024", p)
		}
		if s.MaxBody < 1024 || s.MaxBody > 1<<30 {
			v.errf("%s.max_body: must be between 1024 and 1 GiB", p)
		}
		if s.BodyLimitAction != "bypass" && s.BodyLimitAction != "reject" {
			v.errf("%s.body_limit_action: must be bypass or reject", p)
		}
		if s.Fail != "open" && s.Fail != "closed" {
			v.errf("%s.fail: must be open or closed", p)
		}
		if s.Preview != "auto" && s.Preview != "off" {
			if n, err := strconv.Atoi(s.Preview); err != nil || n < 0 || n > 1<<20 {
				v.errf("%s.preview: must be auto, off or a byte count up to 1 MiB", p)
			}
		}
	}
}

var jwtAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true, "PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true, "EdDSA": true, "HS256": true, "HS384": true, "HS512": true,
}

func (v *validator) jwt(j *JWT, seen map[string]bool) {
	if len(j.Providers) == 0 {
		v.errf("jwt.providers: at least one provider is required")
	}
	for i := range j.Providers {
		p := &j.Providers[i]
		pp := fmt.Sprintf("jwt.providers[%d]", i)
		if !nameRE.MatchString(p.Name) {
			v.errf("%s.name: %q is not a valid name", pp, p.Name)
		} else if seen[p.Name] {
			v.errf("%s.name: duplicate %q", pp, p.Name)
		}
		seen[p.Name] = true
		if p.Issuer == "" || len(p.Issuer) > 512 {
			v.errf("%s.issuer: required (at most 512 characters)", pp)
		}
		hmac := false
		for j, a := range p.Algorithms {
			if !jwtAlgorithms[a] {
				v.errf("%s.algorithms[%d]: %q is not allowed", pp, j, a)
			}
			if strings.HasPrefix(a, "HS") {
				hmac = true
			}
		}
		sources := 0
		if p.JWKSFile != "" {
			sources++
			v.file(pp+".jwks_file", p.JWKSFile)
		}
		if p.JWKSURL != "" {
			sources++
			if u, err := url.Parse(p.JWKSURL); err != nil || u.Scheme != "https" || u.Host == "" {
				v.errf("%s.jwks_url: must be an https URL", pp)
			}
			if p.JWKSRefresh < Duration(60_000_000_000) {
				v.errf("%s.jwks_refresh: must be at least 1m", pp)
			}
		}
		if p.JWKSCAFile != "" {
			v.file(pp+".jwks_ca_file", p.JWKSCAFile)
		}
		if p.HMACSecretFile != "" {
			v.file(pp+".hmac_secret_file", p.HMACSecretFile)
			if !hmac {
				v.errf("%s.hmac_secret_file: set but no HS algorithm is allowed", pp)
			}
		} else if hmac {
			v.errf("%s: HS algorithms require hmac_secret_file", pp)
		}
		if sources == 0 && p.HMACSecretFile == "" {
			v.errf("%s: jwks_file, jwks_url or hmac_secret_file is required", pp)
		}
		if p.ClockSkew < 0 || p.ClockSkew > Duration(600_000_000_000) {
			v.errf("%s.clock_skew: must be between 0 and 10m", pp)
		}
		switch {
		case p.Source == "bearer":
		case strings.HasPrefix(p.Source, "header:") && headerNameOK(p.Source[7:]):
		case strings.HasPrefix(p.Source, "cookie:") && cookieNameOK(p.Source[7:]):
		default:
			v.errf("%s.source: must be bearer, header:<Name> or cookie:<Name>", pp)
		}
		for h, claim := range p.ForwardClaims {
			if !headerNameOK(h) {
				v.errf("%s.forward_claims: %q is not a valid header name", pp, h)
			}
			if claim == "" || len(claim) > 128 {
				v.errf("%s.forward_claims[%s]: claim name required", pp, h)
			}
			if strings.EqualFold(h, "Authorization") || strings.EqualFold(h, "Cookie") || strings.EqualFold(h, "Host") {
				v.errf("%s.forward_claims: %s cannot be overwritten from a claim", pp, h)
			}
		}
		for _, c := range append(append([]string{}, p.RequiredClaims...), p.LogClaims...) {
			if c == "" || len(c) > 128 {
				v.errf("%s: claim names must be 1 to 128 characters", pp)
			}
		}
	}
}

func (v *validator) challenge(c *Challenge) {
	if c.SecretFile != "" && !strings.HasPrefix(c.SecretFile, "/") {
		v.errf("challenge.secret_file: must be an absolute path")
	}
	if c.Difficulty < 8 || c.Difficulty > 24 {
		v.errf("challenge.difficulty: must be between 8 and 24 bits")
	}
	if c.TTL < Duration(60_000_000_000) {
		v.errf("challenge.ttl: must be at least 1m")
	}
	if !cookieNameOK(c.CookieName) {
		v.errf("challenge.cookie_name: %q is not a valid cookie name", c.CookieName)
	}
	for i, cidr := range c.ExemptCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			v.errf("challenge.exempt_cidrs[%d]: %q is not a CIDR", i, cidr)
		}
	}
	if len(c.Title) > 200 || strings.ContainsAny(c.Title, "<>&\"'") {
		v.errf("challenge.title: at most 200 characters, no HTML special characters")
	}
}

func wafModeOK(m string) bool { return m == "off" || m == "detect" || m == "block" }

// headerMatches validates request conditions.
func (v *validator) headerMatches(p string, ms []HeaderMatch, cookie bool) {
	for j, m := range ms {
		q := fmt.Sprintf("%s[%d]", p, j)
		switch {
		case m.Name == "" || len(m.Name) > 128:
			v.errf("%s.name: required, at most 128 bytes", q)
		case !cookie && !headerNameOK(m.Name):
			v.errf("%s.name: %q is not a header name", q, m.Name)
		case cookie && strings.ContainsAny(m.Name, " \t;=,\r\n"):
			v.errf("%s.name: %q is not a cookie name", q, m.Name)
		}
		set := 0
		for _, on := range []bool{m.Exact != "", m.Prefix != "", m.Regex != "", m.Present != nil} {
			if on {
				set++
			}
		}
		if set != 1 {
			v.errf("%s: exactly one of exact, prefix, regex or present is required", q)
		}
		if m.Regex != "" {
			if len(m.Regex) > 512 {
				v.errf("%s.regex: at most 512 bytes", q)
			} else if _, err := regexp.Compile("^(?:" + m.Regex + ")$"); err != nil {
				v.errf("%s.regex: %v", q, err)
			}
		}
		if len(m.Exact) > 1024 || len(m.Prefix) > 1024 {
			v.errf("%s: values are at most 1024 bytes", q)
		}
	}
}

func (v *validator) waf(w *WAF, profiles map[string]bool) {
	if !wafModeOK(w.DefaultMode) {
		v.errf("waf.default_mode: must be off, detect or block")
	}
	if w.RequestBodyLimit < 1024 || w.RequestBodyLimit > 1<<30 {
		v.errf("waf.request_body_limit: must be between 1024 and 1 GiB")
	}
	switch w.RequestBodyLimitAction {
	case "reject", "partial":
	default:
		v.errf("waf.request_body_limit_action: must be reject or partial")
	}
	if w.ResponseBodyLimit < 1024 || w.ResponseBodyLimit > 1<<30 {
		v.errf("waf.response_body_limit: must be between 1024 and 1 GiB")
	}
	if len(w.Profiles) == 0 {
		v.errf("waf.profiles: at least one profile is required")
	}
	for i, p := range w.Profiles {
		pp := fmt.Sprintf("waf.profiles[%d]", i)
		if !nameRE.MatchString(p.Name) {
			v.errf("%s.name: %q is not a valid name", pp, p.Name)
		} else if profiles[p.Name] {
			v.errf("%s.name: duplicate %q", pp, p.Name)
		}
		profiles[p.Name] = true
		if p.CRS == nil && len(p.DirectiveFiles) == 0 && strings.TrimSpace(p.Directives) == "" {
			v.errf("%s: a profile needs crs, directive_files or directives", pp)
		}
		if crs := p.CRS; crs != nil {
			if crs.ParanoiaLevel < 1 || crs.ParanoiaLevel > 4 {
				v.errf("%s.crs.paranoia_level: must be 1 to 4", pp)
			}
			if crs.InboundThreshold < 1 || crs.OutboundThreshold < 1 {
				v.errf("%s.crs: thresholds must be at least 1", pp)
			}
		}
		for j, f := range p.DirectiveFiles {
			v.file(fmt.Sprintf("%s.directive_files[%d]", pp, j), f)
		}
		if len(p.Directives) > 1<<20 {
			v.errf("%s.directives: exceeds 1 MiB", pp)
		}
	}
	if w.DefaultMode != "off" && !profiles[w.DefaultProfile] {
		v.errf("waf.default_profile: unknown profile %q", w.DefaultProfile)
	}
}

func (v *validator) routeWAF(i int, rw *RouteWAF, w *WAF, profiles map[string]bool) {
	p := fmt.Sprintf("routes[%d].waf", i)
	if w == nil {
		v.errf("%s: set but there is no top-level waf section", p)
		return
	}
	if !wafModeOK(rw.Mode) {
		v.errf("%s.mode: must be off, detect or block", p)
	}
	if rw.Mode != "off" && !profiles[rw.Profile] {
		v.errf("%s.profile: unknown profile %q", p, rw.Profile)
	}
}

func (v *validator) headerOps(p string, h HeaderOps) {
	check := func(kind, name, value string) {
		if !headerNameOK(name) {
			v.errf("%s.%s: %q is not a valid header name", p, kind, name)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			v.errf("%s.%s[%s]: value contains control characters", p, kind, name)
		}
	}
	for k, val := range h.Set {
		check("set", k, val)
	}
	for k, val := range h.Add {
		check("add", k, val)
	}
	for _, k := range h.Remove {
		check("remove", k, "")
	}
}

func (v *validator) file(p, path string) {
	if !strings.HasPrefix(path, "/") {
		v.errf("%s: must be an absolute path", p)
		return
	}
	if !v.fileCheck {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		v.errf("%s: %v", p, errors.Unwrap(err))
		return
	}
	if st.IsDir() {
		v.errf("%s: %s is a directory", p, path)
	}
}

func hostPatternOK(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if strings.HasPrefix(h, "*.") {
		h = h[2:]
		if h == "" {
			return false
		}
	}
	if strings.Contains(h, "*") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

func headerNameOK(n string) bool {
	if n == "" || len(n) > 256 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

func cookieNameOK(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
			return false
		}
	}
	return true
}
