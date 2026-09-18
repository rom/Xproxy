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
	routes := map[string]bool{}
	for i := range c.Routes {
		v.route(i, &c.Routes[i], routes, upstreams, rateLimits)
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
