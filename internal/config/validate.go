package config

import (
	"crypto/tls"
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
	if c.Challenge != nil {
		v.challenge(c.Challenge)
	}
	routes := map[string]bool{}
	for i := range c.Routes {
		v.route(i, &c.Routes[i], routes, upstreams, rateLimits)
		if c.Routes[i].WAF != nil {
			v.routeWAF(i, c.Routes[i].WAF, c.WAF, profiles)
		}
		switch c.Routes[i].PriorityClass {
		case "low", "normal", "high", "critical":
		default:
			v.errf("routes[%d].priority_class: must be low, normal, high or critical", i)
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
			v.errf("%s: h3 is not yet supported by this build (planned for 1.0)", p)
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
	if l.MaxConnectionsPerIP > l.MaxConnections {
		v.errf("server.limits.max_connections_per_ip: exceeds max_connections")
	}
}

func (v *validator) tls(p string, t *TLS) {
	if len(t.Certificates) == 0 {
		v.errf("%s.certificates: at least one certificate is required", p)
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
	}
}

func (v *validator) rateLimit(i int, r *RateLimit, seen map[string]bool) {
	p := fmt.Sprintf("rate_limits[%d]", i)
	if !nameRE.MatchString(r.Name) {
		v.errf("%s.name: %q is not a valid name", p, r.Name)
	} else if seen[r.Name] {
		v.errf("%s.name: duplicate %q", p, r.Name)
	}
	seen[r.Name] = true
	switch {
	case r.Key == "client_ip", r.Key == "route":
	case strings.HasPrefix(r.Key, "header:") && len(r.Key) > len("header:"):
	default:
		v.errf("%s.key: must be client_ip, route or header:<name>", p)
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
		if !strings.HasPrefix(hc.Path, "/") {
			v.errf("%s.health_check.path: must start with /", p)
		}
		if hc.Interval < Duration(500_000_000) {
			v.errf("%s.health_check.interval: must be at least 500ms", p)
		}
		if hc.Timeout <= 0 || hc.Timeout >= hc.Interval {
			v.errf("%s.health_check.timeout: must be positive and shorter than interval", p)
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
	if actions != 1 {
		v.errf("%s: exactly one of upstream, redirect or respond is required", p)
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
	"bad_host": true, "no_route": true, "websocket": true, "concurrency": true, "challenge": true,
}

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
