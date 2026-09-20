package config

import (
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/expr"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/tmpl"
	"mime"
	"path/filepath"
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
	"slices"
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
	// anyRouteHosts records whether any route names a host, which the
	// CAPTCHA hostname check uses as its allowlist.
	anyRouteHosts bool
	// advice holds configurations that load but are a bad idea: an open
	// resolver, a cluster with no certificate name restriction. They are
	// not errors, because refusing them would break deployments that
	// mean it, but an operator should see them every time.
	advice []string
	// hasChallenge is set while validating a configuration with a
	// challenge section (the device rate limit key needs one).
	hasChallenge bool
	// fileCheck is true when file existence should be verified. Tests turn
	// this off.
	fileCheck bool
}

func (v *validator) errf(format string, args ...interface{}) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

// warnf records a configuration that loads but should be reconsidered.
func (v *validator) warnf(format string, args ...interface{}) {
	v.advice = append(v.advice, fmt.Sprintf(format, args...))
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
	c.advice = v.advice
	if len(v.problems) == 0 {
		return nil
	}
	return &ValidationError{Problems: v.problems}
}

// Advice returns the warnings the last validation produced: settings
// that load but weaken the deployment. The caller logs them; they never
// stop a start or a reload.
func (c *Config) Advice() []string { return c.advice }

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
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			v.errf("trusted_proxies[%d]: %q is not a CIDR", i, cidr)
			continue
		}
		// Trusting every address lets any client pick its own client IP
		// through X-Forwarded-For or a PROXY header, defeating bans, rate
		// limits, ACLs and the audit trail: name the balancers instead.
		// Shorter than /8 is refused too: "0.0.0.0/1" plus "128.0.0.0/1"
		// (or "::/1" plus "8000::/1") is the /0 in two lines.
		if p.Bits() < 8 {
			v.errf("trusted_proxies[%d]: %q would trust every client; list the load balancer networks", i, cidr)
		}
	}

	rateLimits := map[string]bool{}
	for i := range c.RateLimits {
		v.hasChallenge = c.Challenge != nil
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
	if c.Fleet != nil {
		v.fleet(c.Fleet)
	}
	if a := c.APIInventory; a != nil {
		if a.MaxEndpoints < 100 || a.MaxEndpoints > 1_000_000 {
			v.errf("api_inventory.max_endpoints: must be between 100 and 1000000")
		}
		for i, h := range a.Hosts {
			if !hostPatternOK(h) {
				v.errf("api_inventory.hosts[%d]: %q is not a valid host pattern", i, h)
			}
		}
		if a.ZombieAfter < Duration(time.Hour) || a.ZombieAfter > Duration(365*24*time.Hour) {
			v.errf("api_inventory.zombie_after: must be between 1h and 8760h")
		}
		if a.StateFile != "" && !strings.HasPrefix(a.StateFile, "/") {
			v.errf("api_inventory.state_file: must be an absolute path")
		}
		if a.SaveInterval < Duration(10*time.Second) || a.SaveInterval > Duration(24*time.Hour) {
			v.errf("api_inventory.save_interval: must be between 10s and 24h")
		}
	}
	v.sandbox(&c.Sandbox)
	if cp := c.Compression; cp != nil {
		seen := map[string]bool{}
		for i, e := range cp.Encodings {
			switch e {
			case "gzip", "br", "zstd":
			default:
				v.errf("compression.encodings[%d]: must be gzip, br or zstd", i)
			}
			if seen[e] {
				v.errf("compression.encodings[%d]: duplicate %q", i, e)
			}
			seen[e] = true
		}
		if cp.BrotliLevel != nil && (*cp.BrotliLevel < 0 || *cp.BrotliLevel > 11) {
			v.errf("compression.brotli_level: must be 0 to 11")
		}
		if cp.ZstdLevel < 1 || cp.ZstdLevel > 4 {
			v.errf("compression.zstd_level: must be 1 to 4")
		}
	}
	if c.Server.ErrorPages != nil {
		v.errorPages("server.error_pages", c.Server.ErrorPages)
	}
	if st := c.Server.SessionTickets; st != nil {
		if !strings.HasPrefix(st.SecretFile, "/") {
			v.errf("server.session_tickets.secret_file: must be an absolute path")
		}
		if st.Rotate < Duration(time.Hour) || st.Rotate > Duration(168*time.Hour) {
			v.errf("server.session_tickets.rotate: must be between 1h and 168h")
		}
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
		for _, r := range c.Routes {
			if len(r.Hosts) > 0 {
				v.anyRouteHosts = true
				break
			}
		}
		v.challenge(c.Challenge)
	}
	if c.Maintenance != nil {
		v.maintenance(c.Maintenance)
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
	if t := c.Tracing; t != nil {
		if p := t.Sample(); p < 0 || p > 100 {
			v.errf("tracing.sample_percent: must be between 0 and 100")
		}
		if t.OTLP != nil {
			v.otlpExport("tracing.otlp", t.OTLP)
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
			if mt, _, err := mime.ParseMediaType(t); err != nil || mt != strings.ToLower(t) || !strings.Contains(mt, "/") {
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
		if c.RateLimits[i].Distributed == "exact" && c.Cluster == nil {
			v.errf("rate_limits[%d].distributed: exact needs a cluster section", i)
		}
	}
	wtListener := false
	for i := range c.Server.Listeners {
		if h := c.Server.Listeners[i].H3; h != nil && h.WebTransport {
			wtListener = true
		}
	}
	for i := range c.Routes {
		r := &c.Routes[i]
		if !r.WebTransport {
			continue
		}
		if !wtListener {
			v.errf("routes[%d].webtransport: no listener has h3.webtransport: true", i)
		}
		for j := range c.Upstreams {
			if c.Upstreams[j].Name == r.Upstream && !c.Upstreams[j].H3 {
				v.errf("routes[%d].webtransport: upstream %q must set h3: true", i, r.Upstream)
			}
		}
		if r.Upstream == "" {
			v.errf("routes[%d].webtransport: needs an upstream", i)
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
	v.virtualPatches(c.VirtualPatches, routes)
	if a := c.APIInventory; a != nil {
		for i, r := range a.Routes {
			if !routes[r] {
				v.errf("api_inventory.routes[%d]: unknown route %q", i, r)
			}
		}
	}
	if len(c.Server.Listeners) == 0 {
		v.errf("server.listeners: at least one listener is required")
	}
}

func (v *validator) server(s *Server) {
	switch s.Normalization.Unicode {
	case "off", "nfc", "nfkc":
	default:
		v.errf("server.normalization.unicode: must be off, nfc or nfkc")
	}
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
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.H2C {
				v.errf("%s: a dns listener takes only address, dns and tls", p)
			}
			if ln.TLS != nil && len(ln.TLS.ACME) > 0 {
				v.errf("%s.tls.acme: not on a dns listener (no http-01 or tls-alpn-01 there); use certificates", p)
			}
			if ln.DNS != nil && (!strings.HasPrefix(ln.DNS.DoHPath, "/") || strings.ContainsAny(ln.DNS.DoHPath, "?# ")) {
				v.errf("%s.dns.doh_path: must be an absolute path", p)
			}
			if ln.DNS == nil {
				v.errf("%s.dns: required for kind dns", p)
			} else {
				v.dnsListener(p+".dns", ln.DNS)
				// An open resolver is somebody else's amplifier. The
				// 1232-byte cap bounds the gain but not the fact that
				// the answers are sent to whoever the source claims to
				// be, so a public listener needs at least one of the
				// two controls.
				if !loopbackListen(ln.Address) && len(ln.DNS.AllowClients) == 0 && ln.DNS.RateLimit == nil {
					v.warnf("%s: a dns listener on a non-loopback address with neither dns.allow_clients nor dns.rate_limit "+
						"answers anyone who can reach it, which makes this node an amplifier", p)
				}
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
	if o := t.OCSPStapling; o != nil {
		if o.Timeout < Duration(time.Second) || o.Timeout > Duration(time.Minute) {
			v.errf("%s.ocsp_stapling.timeout: must be between 1s and 1m", p)
		}
		if o.Refresh < Duration(5*time.Minute) || o.Refresh > Duration(24*time.Hour) {
			v.errf("%s.ocsp_stapling.refresh: must be between 5m and 24h", p)
		}
	}
	if c := t.CT; c != nil {
		if c.Require < 0 || c.Require > 10 {
			v.errf("%s.ct.require: must be between 0 and 10", p)
		}
		if c.LogListFile != "" {
			v.file(p+".ct.log_list_file", c.LogListFile)
		}
		if c.Enforce && c.Require == 0 {
			v.errf("%s.ct.enforce: needs require above 0", p)
		}
	}
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
	if m.HistoryDir != "" && !strings.HasPrefix(m.HistoryDir, "/") {
		v.errf("management.history_dir: must be an absolute path")
	}
	if m.HistoryKeep < 1 || m.HistoryKeep > 1000 {
		v.errf("management.history_keep: must be between 1 and 1000")
	}
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
			case "otlp":
				if l.OTLP == nil {
					v.errf("logging.%s.sinks[%d]: otlp requires a logging.otlp section", name, i)
				}
			case "siem":
				if l.SIEM == nil {
					v.errf("logging.%s.sinks[%d]: siem requires a logging.siem section", name, i)
				}
			default:
				v.errf("logging.%s.sinks[%d]: must be file, journald, syslog, otlp or siem", name, i)
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
	if l.OTLP != nil {
		v.otlpExport("logging.otlp", l.OTLP)
	}
	if l.SIEM != nil {
		v.siem(l.SIEM)
	}
	for name, s := range map[string]*LogStream{"access": &l.Access, "error": &l.Error, "security": &l.Security, "audit": &l.Audit} {
		switch s.Format {
		case "json":
			if s.Template != "" {
				v.errf("logging.%s.template: only for format custom", name)
			}
		case "common", "combined", "custom":
			if name != "access" {
				v.errf("logging.%s.format: only the access stream has text formats", name)
			}
			if s.Format == "custom" {
				if s.Template == "" || len(s.Template) > 1024 {
					v.errf("logging.%s.template: required for format custom, at most 1024 bytes", name)
				} else if err := templateOK(s.Template); err != nil {
					v.errf("logging.%s.template: %v", name, err)
				}
			} else if s.Template != "" {
				v.errf("logging.%s.template: only for format custom", name)
			}
		default:
			v.errf("logging.%s.format: must be json, common, combined or custom", name)
		}
		if name != "access" {
			if s.SamplePercent != nil || s.AlwaysLog != nil || len(s.Fields) > 0 {
				v.errf("logging.%s: sample_percent, always_log and fields are for the access stream only", name)
			}
			continue
		}
		if p := s.SamplePercent; p != nil && (*p < 0 || *p > 100) {
			v.errf("logging.access.sample_percent: must be between 0 and 100")
		}
		if len(s.Fields) > 64 {
			v.errf("logging.access.fields: at most 64")
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
		switch s.Format {
		case "rfc5424", "rfc3164", "cef", "leef":
		default:
			v.errf("logging.syslog.format: must be rfc5424, rfc3164, cef or leef")
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
	case r.Key == "client_ip", r.Key == "route", r.Key == "country", r.Key == "client_net", r.Key == "endpoint", r.Key == "ja4":
	case r.Key == "device":
		if !v.hasChallenge {
			v.errf("%s.key: device needs the challenge section (the identifier comes from the challenge cookie)", p)
		}
	case strings.HasPrefix(r.Key, "header:") && len(r.Key) > len("header:"):
		if !headerNameOK(r.Key[len("header:"):]) {
			v.errf("%s.key: %q is not a header name", p, r.Key[len("header:"):])
		}
	case strings.HasPrefix(r.Key, "cookie:") && len(r.Key) > len("cookie:"):
		if strings.ContainsAny(r.Key[len("cookie:"):], " ;=,") {
			v.errf("%s.key: %q is not a cookie name", p, r.Key[len("cookie:"):])
		}
	case strings.HasPrefix(r.Key, "jwt:") && len(r.Key) > len("jwt:"):
		if strings.ContainsAny(r.Key[len("jwt:"):], " \"") || len(r.Key) > 128 {
			v.errf("%s.key: %q is not a claim name", p, r.Key[len("jwt:"):])
		}
	case r.Key == "identity":
	case strings.HasPrefix(r.Key, "identity:") && len(r.Key) > len("identity:"):
		switch r.Key[len("identity:"):] {
		case "jwt", "oidc", "api_key", "basic", "ldap":
		default:
			v.errf("%s.key: identity kind must be jwt, oidc, api_key, basic or ldap", p)
		}
	default:
		v.errf("%s.key: must be client_ip, client_net, route, country, endpoint, ja4, device, identity, identity:<kind>, header:<name>, cookie:<name> or jwt:<claim>", p)
	}
	if r.NetV4 < 8 || r.NetV4 > 32 {
		v.errf("%s.net_v4: must be between 8 and 32", p)
	}
	if r.NetV6 < 16 || r.NetV6 > 128 {
		v.errf("%s.net_v6: must be between 16 and 128", p)
	}
	if r.Key != "client_net" && (r.NetV4 != DefaultRateLimitNetV4 || r.NetV6 != DefaultRateLimitNetV6) {
		v.errf("%s: net_v4 and net_v6 apply to key client_net", p)
	}
	switch r.Algorithm {
	case "token_bucket":
		if r.Rate <= 0 {
			v.errf("%s.rate: must be positive", p)
		}
		if r.Burst < 1 {
			v.errf("%s.burst: must be at least 1", p)
		}
		if r.Limit != 0 || r.Window != 0 {
			v.errf("%s: limit and window belong to algorithm sliding_window", p)
		}
	case "sliding_window":
		if r.Limit < 1 || r.Limit > 1_000_000_000 {
			v.errf("%s.limit: must be between 1 and 1000000000", p)
		}
		if r.Window < Duration(100*time.Millisecond) || r.Window > Duration(24*time.Hour) {
			v.errf("%s.window: must be between 100ms and 24h", p)
		}
		if r.Rate != 0 || r.Burst != 0 {
			v.errf("%s: rate and burst belong to algorithm token_bucket; use limit and window", p)
		}
	default:
		v.errf("%s.algorithm: must be token_bucket or sliding_window", p)
	}
	switch r.Distributed {
	case "approximate", "exact":
	default:
		v.errf("%s.distributed: must be approximate or exact", p)
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
	if os := u.OriginSignature; os != nil {
		if os.Header != "" && !headerNameOK(os.Header) {
			v.errf("%s.origin_signature.header: %q is not a header name", p, os.Header)
		}
		if os.SecretFile == "" {
			v.errf("%s.origin_signature.secret_file: required", p)
		} else if !strings.HasPrefix(os.SecretFile, "/") {
			v.errf("%s.origin_signature.secret_file: must be an absolute path", p)
		}
		if os.TTL < Duration(10*time.Second) || os.TTL > Duration(24*time.Hour) {
			v.errf("%s.origin_signature.ttl: must be between 10s and 24h", p)
		}
		for j, h := range os.Include {
			if !headerNameOK(h) {
				v.errf("%s.origin_signature.include[%d]: %q is not a header name", p, j, h)
			}
		}
	}
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
	if len(u.Endpoints) == 0 && u.Discovery == nil {
		v.errf("%s.endpoints: at least one endpoint or a discovery section is required", p)
	}
	if d := u.Discovery; d != nil {
		dp := p + ".discovery"
		switch d.Type {
		case "dns":
			if d.Port < 1 || d.Port > 65535 {
				v.errf("%s.port: required for type dns, 1 to 65535", dp)
			}
			v.discoveryDNSName(dp, d)
		case "srv":
			v.discoveryDNSName(dp, d)
		case "http":
			ru, err := url.Parse(d.Name)
			if err != nil || (ru.Scheme != "http" && ru.Scheme != "https") || ru.Host == "" {
				v.errf("%s.name: %q must be an http or https URL", dp, d.Name)
			}
			switch d.Format {
			case "", "list", "consul":
			default:
				v.errf("%s.format: must be list or consul", dp)
			}
			if d.Port != 0 && (d.Port < 1 || d.Port > 65535) {
				v.errf("%s.port: must be between 1 and 65535", dp)
			}
			if d.Resolver != "" {
				v.errf("%s.resolver: only for dns and srv discovery", dp)
			}
		default:
			v.errf("%s.type: must be dns, srv or http", dp)
		}
		if d.Interval < Duration(time.Second) || d.Interval > Duration(time.Hour) {
			v.errf("%s.interval: must be between 1s and 1h", dp)
		}
		if d.Timeout < Duration(100*time.Millisecond) || d.Timeout > Duration(time.Minute) {
			v.errf("%s.timeout: must be between 100ms and 1m", dp)
		}
		if d.Resolver != "" && (d.Type == "dns" || d.Type == "srv") {
			if _, _, err := net.SplitHostPort(d.Resolver); err != nil {
				v.errf("%s.resolver: %q must be host:port", dp, d.Resolver)
			}
		}
		if d.Weight < 1 || d.Weight > 1000 {
			v.errf("%s.weight: must be between 1 and 1000", dp)
		}
		if d.Canary && u.Canary == nil {
			v.errf("%s.canary: set without a canary section", dp)
		}
	}
	if u.SlowStart < 0 || u.SlowStart > Duration(time.Hour) {
		v.errf("%s.slow_start: must be between 0 and 1h", p)
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
	if c := u.Canary; c != nil {
		canaries := 0
		for _, e := range u.Endpoints {
			if e.Canary {
				canaries++
			}
		}
		if canaries == 0 {
			v.errf("%s.canary: no endpoint is marked canary: true", p)
		} else if canaries == len(u.Endpoints) {
			v.errf("%s.canary: every endpoint is a canary; mark the ordinary ones too", p)
		}
		if c.Header == "" && c.Cookie == "" && c.Percent <= 0 {
			v.errf("%s.canary: header, cookie or percent is required", p)
		}
		if c.Header != "" && !headerNameOK(c.Header) {
			v.errf("%s.canary.header: %q is not a header name", p, c.Header)
		}
		if c.Cookie != "" && strings.ContainsAny(c.Cookie, " \t;=,\r\n") {
			v.errf("%s.canary.cookie: %q is not a cookie name", p, c.Cookie)
		}
		if c.Percent < 0 || c.Percent > 100 {
			v.errf("%s.canary.percent: must be between 0 and 100", p)
		}
		if len(c.Values) > 32 {
			v.errf("%s.canary.values: at most 32", p)
		}
	} else {
		for j, e := range u.Endpoints {
			if e.Canary {
				v.errf("%s.endpoints[%d].canary: set without a canary section", p, j)
			}
		}
	}
	if cb := u.CircuitBreaker; cb != nil {
		if cb.ConsecutiveFailures < 1 || cb.ConsecutiveFailures > 10000 {
			v.errf("%s.circuit_breaker.consecutive_failures: must be between 1 and 10000", p)
		}
		if cb.OpenFor < Duration(100*time.Millisecond) || cb.OpenFor > Duration(time.Hour) {
			v.errf("%s.circuit_breaker.open_for: must be between 100ms and 1h", p)
		}
		if cb.HalfOpenRequests < 1 || cb.HalfOpenRequests > 1000 {
			v.errf("%s.circuit_breaker.half_open_requests: must be between 1 and 1000", p)
		}
	}
	if u.MaxConcurrent < 0 || u.MaxConcurrent > 1_000_000 {
		v.errf("%s.max_concurrent: must be between 0 and 1000000", p)
	}
	if q := u.Queue; q != nil {
		if u.MaxConcurrent == 0 {
			v.errf("%s.queue: needs max_concurrent", p)
		}
		if q.Size < 1 || q.Size > 1_000_000 {
			v.errf("%s.queue.size: must be between 1 and 1000000", p)
		}
		if q.Timeout < Duration(10*time.Millisecond) || q.Timeout > Duration(5*time.Minute) {
			v.errf("%s.queue.timeout: must be between 10ms and 5m", p)
		}
	}
	for j, on := range u.RetryOn {
		switch on {
		case "5xx", "500", "502", "503", "504", "429":
		default:
			v.errf("%s.retry_on[%d]: %q is not one of 5xx, 500, 502, 503, 504, 429", p, j, on)
		}
	}
	if len(u.RetryOn) > 0 && u.Retries != nil && *u.Retries == 0 {
		v.errf("%s.retry_on: set but retries is 0", p)
	}
	if b := u.RetryBudget; b != nil {
		if b.Percent < 1 || b.Percent > 1000 {
			v.errf("%s.retry_budget.percent: must be between 1 and 1000", p)
		}
		if b.MinConcurrency < 1 || b.MinConcurrency > 10000 {
			v.errf("%s.retry_budget.min_concurrency: must be between 1 and 10000", p)
		}
	}
	if h := u.Hedge; h != nil {
		if h.Delay < Duration(time.Millisecond) || h.Delay > Duration(time.Minute) {
			v.errf("%s.hedge.delay: must be between 1ms and 1m", p)
		}
		if h.Max < 1 || h.Max > 4 {
			v.errf("%s.hedge.max: must be between 1 and 4", p)
		}
	}
	if u.MaxIdleConnsPerHost < 0 {
		v.errf("%s.max_idle_conns_per_host: must not be negative", p)
	}
	if u.H3 {
		if u.Scheme != "https" {
			v.errf("%s.h3: needs scheme https", p)
		}
		if u.H2C {
			v.errf("%s.h3: exclusive with h2c", p)
		}
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
		if (hc.BodyContains != "" || hc.BodyRegex != "") && hc.Type != "http" {
			v.errf("%s.health_check: body_contains and body_regex need type http", p)
		}
		if len(hc.BodyContains) > 4096 || len(hc.BodyRegex) > 4096 {
			v.errf("%s.health_check: body_contains and body_regex are limited to 4096 bytes", p)
		}
		if hc.BodyRegex != "" {
			if _, err := regexp.Compile(hc.BodyRegex); err != nil {
				v.errf("%s.health_check.body_regex: %v", p, err)
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
		if o.LatencyThreshold < 0 {
			v.errf("%s.outlier_ejection.latency_threshold: must not be negative", p)
		}
		if o.LatencyFactor != 0 && (o.LatencyFactor < 1.5 || o.LatencyFactor > 100) {
			v.errf("%s.outlier_ejection.latency_factor: must be between 1.5 and 100, or 0", p)
		}
		if o.LatencyMinSamples < 1 || o.LatencyMinSamples > 100000 {
			v.errf("%s.outlier_ejection.latency_min_samples: must be between 1 and 100000", p)
		}
	}
}

// discoveryDNSName checks the Name of a dns or srv discovery is a DNS name.
func (v *validator) discoveryDNSName(dp string, d *Discovery) {
	if !hostPatternOK(strings.TrimSuffix(d.Name, ".")) || strings.HasPrefix(d.Name, "*") {
		v.errf("%s.name: %q is not a valid DNS name", dp, d.Name)
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
	if r.Tenant != "" && (len(r.Tenant) > 64 || !nameRE.MatchString(r.Tenant)) {
		v.errf("%s.tenant: %q is not a valid name", p, r.Tenant)
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
	if r.Policy != nil {
		v.routePolicy(p+".policy", r.Policy)
	}
	if r.CORS != nil {
		v.routeCORS(p+".cors", r.CORS)
	}
	if r.Timeouts != nil {
		if r.Timeout != 0 {
			v.errf("%s: set timeout or timeouts, not both", p)
		}
		if r.Timeouts.Total < 0 || r.Timeouts.Idle < 0 {
			v.errf("%s.timeouts: must not be negative", p)
		}
		if t, i := r.Timeouts.Total, r.Timeouts.Idle; t > 0 && i > 0 && i > t {
			v.errf("%s.timeouts.idle: must not exceed total", p)
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
		} else if u, err := url.Parse(placeholderRE.ReplaceAllString(r.Redirect.To, "x")); err != nil || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https") {
			v.errf("%s.redirect.to: %q is not a valid http(s) URL or path", p, r.Redirect.To)
		} else if !redirectTargetFixed(r.Redirect.To) {
			v.errf("%s.redirect.to: %q lets request data choose the destination host (open redirect); start with a literal path or scheme://host", p, r.Redirect.To)
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
		for j, o := range g.WebOrigins {
			if o != "*" && (!strings.HasPrefix(o, "https://") && !strings.HasPrefix(o, "http://") || strings.ContainsAny(o, " /\r\n\t") && strings.Count(o, "/") > 2) {
				v.errf("%s.grpc.web_origins[%d]: %q is not an origin (scheme://host[:port])", p, j, o)
			}
		}
		if len(g.WebOrigins) > 0 && !g.Web {
			v.errf("%s.grpc.web_origins: needs web: true", p)
		}
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
		if d := m.Diff; d != nil {
			if d.SamplePercent < 0 || d.SamplePercent > 100 {
				v.errf("%s.mirror.diff.sample_percent: must be between 0 and 100", p)
			}
			for j, h := range d.Headers {
				if !headerNameOK(h) {
					v.errf("%s.mirror.diff.headers[%d]: %q is not a header name", p, j, h)
				}
			}
			if d.MaxBodyBytes < 0 || d.MaxBodyBytes > 64<<20 {
				v.errf("%s.mirror.diff.max_body_bytes: must be between 0 and 64 MiB", p)
			}
		}
	}
	if r.StripPrefix != "" && !strings.HasPrefix(r.StripPrefix, "/") {
		v.errf("%s.strip_prefix: must start with /", p)
	}
	if rr := r.RewriteRegex; rr != nil {
		if r.RewritePath != "" {
			v.errf("%s.rewrite_regex: exclusive with rewrite_path", p)
		}
		re, err := regexp.Compile(rr.Pattern)
		if err != nil || rr.Pattern == "" || len(rr.Pattern) > 1024 {
			v.errf("%s.rewrite_regex.pattern: %q is not a valid RE2 pattern", p, rr.Pattern)
		} else if !strings.HasPrefix(rr.Replace, "/") {
			v.errf("%s.rewrite_regex.replace: must start with /", p)
		} else if _, err := tmpl.Parse(rr.Replace, re.SubexpNames()...); err != nil {
			v.errf("%s.rewrite_regex.replace: %v", p, err)
		}
	}
	v.headerTemplates(p+".request_headers", r.RequestHeaders, r)
	v.headerTemplates(p+".response_headers", r.ResponseHeaders, r)
	v.when(p+".when", r.When, r)
	if r.Redirect != nil {
		if _, err := tmpl.Parse(r.Redirect.To, CaptureNames(r)...); err != nil {
			v.errf("%s.redirect.to: %v", p, err)
		}
	}
	if r.ErrorPages != nil {
		v.errorPages(p+".error_pages", r.ErrorPages)
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
	"geo": true, "tcp_no_route": true, "forward_denied": true, "forward_auth": true, "honeypot": true, "dns_blocked": true, "dns_bogus": true,
	"account_abuse": true,
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
		switch t.Aggregate {
		case "address", "net", "ja4":
		default:
			v.errf("%s.aggregate: must be address, net or ja4", p)
		}
		if t.NetV4 < 8 || t.NetV4 > 32 {
			v.errf("%s.net_v4: must be between 8 and 32", p)
		}
		if t.NetV6 < 32 || t.NetV6 > 128 {
			v.errf("%s.net_v6: must be between 32 and 128", p)
		}
		if t.MinSources < 1 || t.MinSources > 100000 {
			v.errf("%s.min_sources: must be between 1 and 100000", p)
		}
		if t.MinSources > t.Threshold {
			v.errf("%s.min_sources: must not exceed threshold", p)
		}
	}
}

// loopbackListen reports an address bound to the loopback interface.
func loopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.IsLoopback()
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
	if len(c.TLS.AllowedNames) == 0 {
		v.warnf("cluster.tls.allowed_names is empty, so any certificate the cluster CA issued may join: " +
			"a cluster certificate is full trust inside the cluster, and the node id is all that distinguishes one holder from another")
	}
	if !c.TLS.BindsNodeID() {
		v.warnf("cluster.tls.bind_node_id is off: a peer's announced node_id is not checked against its certificate, " +
			"so it can choose which rate-limit keys it decides for every node")
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
	if c.ExactTimeout < Duration(5*time.Millisecond) || c.ExactTimeout > Duration(2*time.Second) {
		v.errf("cluster.exact_timeout: must be between 5ms and 2s")
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
	if ds := d.DNSSEC; ds != nil {
		for i, a := range ds.TrustAnchors {
			if _, err := dns.ParseTrustAnchor(a); err != nil {
				v.errf("%s.dnssec.trust_anchors[%d]: %v", p, i, err)
			}
		}
		if ds.TrustAnchorsFile != "" {
			v.file(p+".dnssec.trust_anchors_file", ds.TrustAnchorsFile)
		}
		if ds.MaxLookups < 4 || ds.MaxLookups > 1000 {
			v.errf("%s.dnssec.max_lookups: must be between 4 and 1000", p)
		}
	}
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
		if p.Introspection == nil && sources == 0 && p.HMACSecretFile == "" {
			v.errf("%s: jwks_file, jwks_url, hmac_secret_file or introspection is required", pp)
		}
		if in := p.Introspection; in != nil {
			if u, err := url.Parse(in.URL); err != nil || u.Scheme != "https" || u.Host == "" {
				v.errf("%s.introspection.url: must be an https URL", pp)
			}
			if in.ClientID == "" || !strings.HasPrefix(in.ClientSecretFile, "/") {
				v.errf("%s.introspection: client_id and an absolute client_secret_file are required", pp)
			} else {
				v.file(pp+".introspection.client_secret_file", in.ClientSecretFile)
			}
			if in.CAFile != "" {
				v.file(pp+".introspection.ca_file", in.CAFile)
			}
			if in.CacheTTL < 0 || in.CacheTTL > Duration(time.Hour) {
				v.errf("%s.introspection.cache_ttl: must be between 0 and 1h", pp)
			}
			if in.Timeout < Duration(100*time.Millisecond) || in.Timeout > Duration(30*time.Second) {
				v.errf("%s.introspection.timeout: must be between 100ms and 30s", pp)
			}
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

func (v *validator) maintenance(m *Maintenance) {
	if m.Status < 400 || m.Status > 599 {
		v.errf("maintenance.status: must be a 4xx or 5xx status")
	}
	if m.RetryAfter < 0 {
		v.errf("maintenance.retry_after: must not be negative")
	}
	for i, c := range m.AllowCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("maintenance.allow_cidrs[%d]: %q is not a CIDR", i, c)
		}
	}
	if h := m.AllowHeader; h != "" {
		name, val, ok := strings.Cut(h, ":")
		if !ok || !headerNameOK(strings.TrimSpace(name)) || strings.TrimSpace(val) == "" {
			v.errf("maintenance.allow_header: must be \"Name: value\"")
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
	switch c.CookieScope {
	case "", "shared", "host":
	default:
		v.errf("challenge.cookie_scope: must be shared or host")
	}
	for i, cidr := range c.ExemptCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			v.errf("challenge.exempt_cidrs[%d]: %q is not a CIDR", i, cidr)
		}
	}
	if len(c.Title) > 200 || strings.ContainsAny(c.Title, "<>&\"'") {
		v.errf("challenge.title: at most 200 characters, no HTML special characters")
	}
	if cp := c.Captcha; cp != nil && cp.ChecksHostname() && len(cp.Hostnames) == 0 && !v.anyRouteHosts {
		v.errf("challenge.captcha.hostnames: required when hostname_check is on and no route sets hosts: " +
			"the hostname the provider reports is otherwise compared against the request host, which the client chooses")
	}
	if cp := c.Captcha; cp != nil {
		switch cp.Provider {
		case "turnstile", "hcaptcha", "recaptcha":
		default:
			v.errf("challenge.captcha.provider: must be turnstile, hcaptcha or recaptcha")
		}
		if cp.SiteKey == "" || len(cp.SiteKey) > 200 || strings.ContainsAny(cp.SiteKey, "<>&\"' \r\n") {
			v.errf("challenge.captcha.site_key: required, at most 200 characters, no HTML or space characters")
		}
		if !strings.HasPrefix(cp.SecretFile, "/") {
			v.errf("challenge.captcha.secret_file: must be an absolute path")
		}
		if cp.VerifyURL != "" && !strings.HasPrefix(cp.VerifyURL, "https://") && !strings.HasPrefix(cp.VerifyURL, "http://127.0.0.1") && !strings.HasPrefix(cp.VerifyURL, "http://localhost") {
			v.errf("challenge.captcha.verify_url: must be an https URL (plain http only to localhost)")
		}
		if cp.Timeout < Duration(500_000_000) || cp.Timeout > Duration(30_000_000_000) {
			v.errf("challenge.captcha.timeout: must be between 500ms and 30s")
		}
		if cp.MinScore < 0 || cp.MinScore > 1 {
			v.errf("challenge.captcha.min_score: must be between 0 and 1")
		}
		if cp.Mode != "escalation" && cp.Mode != "always" {
			v.errf("challenge.captcha.mode: must be escalation or always")
		}
		for i, h := range cp.Hostnames {
			if h == "" || strings.ContainsAny(h, "/ :") || h != strings.ToLower(h) {
				v.errf("challenge.captcha.hostnames[%d]: %q is not a lower case host name", i, h)
			}
		}
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
	if l := w.Learning; l != nil {
		if l.MinHits < 1 || l.MinHits > 1_000_000 {
			v.errf("waf.learning.min_hits: must be between 1 and 1000000")
		}
		if l.MaxEntries < 100 || l.MaxEntries > 1_000_000 {
			v.errf("waf.learning.max_entries: must be between 100 and 1000000")
		}
	}
	if a := w.Anomaly; a != nil {
		if a.Window.D() < 10*time.Second || a.Window.D() > 24*time.Hour {
			v.errf("waf.anomaly.window: must be between 10s and 24h")
		}
		if a.MinRequests < 1 || a.MinRequests > 1_000_000 {
			v.errf("waf.anomaly.min_requests: must be between 1 and 1000000")
		}
		if a.Threshold < 1 || a.Threshold > 100 {
			v.errf("waf.anomaly.threshold: must be between 1 and 100")
		}
		switch a.Action {
		case "log", "challenge", "block":
		default:
			v.errf("waf.anomaly.action: must be log, challenge or block")
		}
		if a.MaxClients < 100 || a.MaxClients > 10_000_000 {
			v.errf("waf.anomaly.max_clients: must be between 100 and 10000000")
		}
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
			if crs.Dir != "" {
				v.dir(pp+".crs.dir", crs.Dir)
			}
			if crs.PluginsDir != "" {
				v.dir(pp+".crs.plugins_dir", crs.PluginsDir)
			} else if len(crs.Plugins) > 0 {
				v.errf("%s.crs.plugins: requires plugins_dir", pp)
			}
			for j, name := range crs.Plugins {
				if !nameRE.MatchString(name) {
					v.errf("%s.crs.plugins[%d]: %q is not a valid plugin name", pp, j, name)
				}
			}
		}
		for j, f := range p.DirectiveFiles {
			v.file(fmt.Sprintf("%s.directive_files[%d]", pp, j), f)
		}
		if len(p.Directives) > 1<<20 {
			v.errf("%s.directives: exceeds 1 MiB", pp)
		}
		schemas := map[string]bool{}
		for j := range p.JSONSchemas {
			js := &p.JSONSchemas[j]
			sp := fmt.Sprintf("%s.json_schemas[%d]", pp, j)
			if !nameRE.MatchString(js.Name) {
				v.errf("%s.name: %q is not a valid name", sp, js.Name)
			} else if schemas[js.Name] {
				v.errf("%s.name: duplicate %q", sp, js.Name)
			}
			schemas[js.Name] = true
			if len(js.Paths) == 0 {
				v.errf("%s.paths: at least one path prefix is required", sp)
			}
			for k, path := range js.Paths {
				if !strings.HasPrefix(path, "/") {
					v.errf("%s.paths[%d]: must start with /", sp, k)
				}
			}
			for k, m := range js.Methods {
				if m == "" || strings.ToUpper(m) != m {
					v.errf("%s.methods[%d]: %q must be an upper-case method", sp, k, m)
				}
			}
			if js.SchemaFile == "" {
				v.errf("%s.schema_file: required", sp)
			} else {
				v.file(sp+".schema_file", js.SchemaFile)
			}
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
	if rw.BlockPercent != nil && (*rw.BlockPercent < 0 || *rw.BlockPercent > 100) {
		v.errf("%s.block_percent: must be between 0 and 100", p)
	}
	for j, c := range rw.BlockCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.block_cidrs[%d]: %q is not a CIDR", p, j, c)
		}
	}
	if rw.Mode != "block" && (rw.BlockPercent != nil || len(rw.BlockCIDRs) > 0) {
		v.errf("%s: block_percent and block_cidrs apply to mode block", p)
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

// placeholderRE matches template placeholders, replaced by a token
// before shape checks that templates would otherwise fail.
var placeholderRE = regexp.MustCompile(`\$\{[^}]*\}`)

// publicSuffixes lists the common two-label registry suffixes under which
// anyone can register a name, so "https://*.co.uk" is refused like
// "https://*.com". It is a safety net, not the public suffix list:
// operators remain responsible for wildcards under rarer suffixes.
var publicSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true, "net.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "id.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "co.za": true, "org.za": true, "web.za": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true, "co.kr": true, "or.kr": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "com.hk": true, "com.tw": true, "com.sg": true, "com.my": true,
	"co.in": true, "net.in": true, "org.in": true, "co.id": true, "com.ph": true, "com.vn": true, "co.th": true,
	"com.br": true, "net.br": true, "org.br": true, "com.mx": true, "com.ar": true, "com.co": true, "com.pe": true,
	"com.tr": true, "com.ua": true, "com.pl": true, "com.ru": true, "co.il": true, "com.eg": true, "com.sa": true,
	"com.ng": true, "co.ke": true, "com.gh": true, "co.tz": true, "com.pk": true, "com.bd": true,
	"github.io": true, "gitlab.io": true, "herokuapp.com": true, "azurewebsites.net": true, "cloudfront.net": true,
	"appspot.com": true, "web.app": true, "firebaseapp.com": true, "vercel.app": true, "netlify.app": true, "pages.dev": true,
	"workers.dev": true, "amazonaws.com": true, "blogspot.com": true, "wordpress.com": true,
}

// redirectAuthorityRE matches the literal start a redirect target needs
// before any placeholder: a scheme (or ${scheme}) and a literal host (or
// ${host}, which routing has validated), followed by "/", "${path}" or
// the end.
var redirectAuthorityRE = regexp.MustCompile(`^(?:https?|\$\{scheme\})://(?:\$\{host\}|[A-Za-z0-9.\-]+(?::[0-9]+)?|\[[0-9A-Fa-f:.]+\](?::[0-9]+)?)(?:/|\$\{path\}|$)`)

// redirectTargetFixed reports whether the destination of a redirect is
// fixed by the configuration: request data may fill in the path or the
// query, never the host. "${query:next}" or "//${header:X-Host}" would
// be an open redirect; "/x${path}" and "https://a.example${path}" are
// fine, as is "https://${host}/new" since ${host} is the validated
// request host.
func redirectTargetFixed(to string) bool {
	if strings.HasPrefix(to, "/") {
		// A relative target: the literal part must reach past a first
		// character that is not another separator, so "/${x}" (which
		// could expand to "//evil") is refused while "/x${path}" passes.
		lit := to
		if i := strings.Index(to, "${"); i >= 0 {
			lit = to[:i]
		}
		return len(lit) >= 2 && lit[1] != '/' && lit[1] != '\\' || !strings.Contains(to, "${")
	}
	return redirectAuthorityRE.MatchString(to)
}

// CaptureNames lists the named groups of a route's regular expressions,
// which header templates may reference.
func CaptureNames(r *Route) []string {
	var names []string
	if rr := r.RewriteRegex; rr != nil {
		if re, err := regexp.Compile(rr.Pattern); err == nil {
			names = append(names, re.SubexpNames()...)
		}
	}
	for _, p := range r.PathRegex {
		if re, err := regexp.Compile(p); err == nil {
			names = append(names, re.SubexpNames()...)
		}
	}
	out := names[:0]
	for _, n := range names {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

// headerTemplates checks the placeholders of set and add values.
func (v *validator) headerTemplates(p string, h HeaderOps, r *Route) {
	names := CaptureNames(r)
	v.when(p+".when", h.When, r)
	for k, val := range h.Set {
		if _, err := tmpl.Parse(val, names...); err != nil {
			v.errf("%s.set.%s: %v", p, k, err)
		}
	}
	for k, val := range h.Add {
		if _, err := tmpl.Parse(val, names...); err != nil {
			v.errf("%s.add.%s: %v", p, k, err)
		}
	}
}

// errorPageKey matches "404", "4xx", "5xx" or "default".
var errorPageKey = regexp.MustCompile(`^([45][0-9][0-9]|4xx|5xx|default)$`)

// errorPages checks an error pages section.
func (v *validator) errorPages(p string, e *ErrorPages) {
	if e.Dir != "" {
		v.dir(p+".dir", e.Dir)
	}
	if len(e.Pages) == 0 {
		v.errf("%s.pages: at least one page is required", p)
	}
	for k, f := range e.Pages {
		if !errorPageKey.MatchString(k) {
			v.errf("%s.pages.%s: key must be a status 400 to 599, 4xx, 5xx or default", p, k)
		}
		if f == "" || strings.ContainsRune(f, 0) {
			v.errf("%s.pages.%s: file name is required", p, k)
			continue
		}
		path := f
		if !strings.HasPrefix(f, "/") {
			if e.Dir == "" {
				v.errf("%s.pages.%s: %q is relative but dir is not set", p, k, f)
				continue
			}
			path = filepath.Join(e.Dir, f)
		}
		v.file(p+".pages."+k, path)
	}
	for i, st := range e.InterceptUpstream {
		if st < 400 || st > 599 {
			v.errf("%s.intercept_upstream[%d]: must be 400 to 599", p, i)
		}
	}
	if strings.ContainsAny(e.ContentType, "\r\n") {
		v.errf("%s.content_type: control characters", p)
	}
}

// sandbox checks the extra Landlock paths.
func (v *validator) sandbox(s *Sandbox) {
	for i, p := range s.Landlock.ReadPaths {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "\x00") {
			v.errf("sandbox.landlock.read_paths[%d]: must be an absolute path", i)
		}
	}
	for i, p := range s.Landlock.WritePaths {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "\x00") {
			v.errf("sandbox.landlock.write_paths[%d]: must be an absolute path", i)
		}
	}
	if len(s.Landlock.ReadPaths)+len(s.Landlock.WritePaths) > 256 {
		v.errf("sandbox.landlock: at most 256 extra paths")
	}
}

// dir checks an absolute directory path.
func (v *validator) dir(p, path string) {
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
	if !st.IsDir() {
		v.errf("%s: %s is not a directory", p, path)
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

// templateOK checks a custom access log template: every { closes and
// names a field.
func templateOK(t string) error {
	for len(t) > 0 {
		i := strings.IndexByte(t, '{')
		if i < 0 {
			return nil
		}
		j := strings.IndexByte(t[i:], '}')
		if j < 0 {
			return fmt.Errorf("unclosed { at offset %d", i)
		}
		if name := t[i+1 : i+j]; name == "" || strings.ContainsAny(name, " {\"\\") {
			return fmt.Errorf("bad field name %q", name)
		}
		t = t[i+j+1:]
	}
	return nil
}

// otlpExport validates a trace or log collector endpoint.
// methodList checks a list of upper-case method tokens.
func (v *validator) methodList(p string, methods []string) {
	seen := map[string]bool{}
	for j, m := range methods {
		if m != strings.ToUpper(m) || m == "" || len(m) > 32 || strings.ContainsAny(m, " \t,") {
			v.errf("%s[%d]: %q must be an upper-case token", p, j, m)
		} else if seen[m] {
			v.errf("%s[%d]: duplicate %q", p, j, m)
		}
		seen[m] = true
	}
}

// mediaTypes checks a list of media types or type/* patterns.
func (v *validator) mediaTypes(p string, types []string) {
	for j, t := range types {
		main, sub, ok := strings.Cut(t, "/")
		if !ok || main == "" || sub == "" || t != strings.ToLower(t) || strings.ContainsAny(t, " ;,") || (main == "*" && sub != "*") {
			v.errf("%s[%d]: %q must be type/subtype or type/*", p, j, t)
		}
	}
}

func (v *validator) routeCORS(p string, c *RouteCORS) {
	if len(c.AllowOrigins) == 0 {
		v.errf("%s.allow_origins: at least one origin", p)
	}
	star := false
	for i, o := range c.AllowOrigins {
		if o == "*" {
			star = true
			continue
		}
		if !strings.HasPrefix(o, "http://") && !strings.HasPrefix(o, "https://") {
			v.errf("%s.allow_origins[%d]: %q must be a scheme://host origin or \"*\"", p, i, o)
		}
		// A wildcard stands for whole leading labels only: "https://*.example.com".
		// "https://*example.com" would also admit evilexample.com.
		if strings.Contains(o, "*") {
			host := o[strings.Index(o, "://")+3:]
			// At least two labels after the wildcard: "https://*.com" or
			// "https://*.co.uk" would admit every site under a public suffix.
			suffix := strings.TrimPrefix(host, "*.")
			labels := strings.Split(suffix, ".")
			if strings.Count(host, "*") != 1 || !strings.HasPrefix(host, "*.") || len(labels) < 2 || slices.Contains(labels, "") || strings.ContainsAny(host, "/?#@:\\") {
				v.errf("%s.allow_origins[%d]: %q wildcard must be scheme://*.domain.tld", p, i, o)
			} else if publicSuffixes[strings.ToLower(suffix)] {
				v.errf("%s.allow_origins[%d]: %q is a public suffix: every site under it would be allowed", p, i, o)
			}
		}
	}
	if star && c.AllowCredentials {
		v.errf("%s: allow_credentials cannot be combined with the \"*\" origin", p)
	}
	if star && len(c.AllowOrigins) > 1 {
		v.errf("%s.allow_origins: \"*\" must be the only entry", p)
	}
	for i, m := range c.AllowMethods {
		if m != strings.ToUpper(m) || strings.ContainsAny(m, " \r\n") {
			v.errf("%s.allow_methods[%d]: %q is not a method", p, i, m)
		}
	}
	for i, h := range c.AllowHeaders {
		if h != "*" && !headerNameOK(h) {
			v.errf("%s.allow_headers[%d]: %q is not a header name", p, i, h)
		}
	}
	for i, h := range c.ExposeHeaders {
		if !headerNameOK(h) {
			v.errf("%s.expose_headers[%d]: %q is not a header name", p, i, h)
		}
	}
	if c.MaxAge < 0 || c.MaxAge > Duration(24*3600*1e9) {
		v.errf("%s.max_age: must be between 0 and 24h", p)
	}
}

func (v *validator) routePolicy(p string, pol *RoutePolicy) {
	v.methodList(p+".methods", pol.Methods)
	v.mediaTypes(p+".content_types", pol.ContentTypes)
	if pol.MaxURILength < 0 || pol.MaxURILength > 1<<20 {
		v.errf("%s.max_uri_length: must be between 0 and 1048576", p)
	}
	if pol.MaxQueryBytes < 0 || pol.MaxQueryBytes > 1<<20 {
		v.errf("%s.max_query_bytes: must be between 0 and 1048576", p)
	}
	if pol.MaxQueryParams < 0 || pol.MaxQueryParams > 10000 {
		v.errf("%s.max_query_params: must be between 0 and 10000", p)
	}
	if pol.MaxHeaders < 0 || pol.MaxHeaders > 10000 {
		v.errf("%s.max_headers: must be between 0 and 10000", p)
	}
	if pol.MaxHeaderBytes < 0 || pol.MaxHeaderBytes > 1<<24 {
		v.errf("%s.max_header_bytes: must be between 0 and 16777216", p)
	}
	if len(pol.Query) > 256 {
		v.errf("%s.query: at most 256 parameters", p)
	}
	if pol.DenyUnknown && len(pol.Query) == 0 {
		v.errf("%s.deny_unknown_query: requires a query list", p)
	}
	names := map[string]bool{}
	for j, q := range pol.Query {
		qp := fmt.Sprintf("%s.query[%d]", p, j)
		if q.Name == "" || len(q.Name) > 128 {
			v.errf("%s.name: required, at most 128 bytes", qp)
		} else if names[q.Name] {
			v.errf("%s.name: duplicate %q", qp, q.Name)
		}
		names[q.Name] = true
		switch q.Type {
		case "string", "int", "number", "bool", "uuid":
			if len(q.Values) > 0 {
				v.errf("%s.values: only for type enum", qp)
			}
		case "enum":
			if len(q.Values) == 0 || len(q.Values) > 1024 {
				v.errf("%s.values: type enum needs 1 to 1024 values", qp)
			}
		default:
			v.errf("%s.type: must be string, int, number, bool, uuid or enum", qp)
		}
		if q.MaxLength < 0 || q.MaxLength > 1<<20 {
			v.errf("%s.max_length: must be between 0 and 1048576", qp)
		}
		if q.MaxRepeat < 1 || q.MaxRepeat > 1000 {
			v.errf("%s.max_repeat: must be between 1 and 1000", qp)
		}
		if q.Pattern != "" {
			if len(q.Pattern) > 512 {
				v.errf("%s.pattern: at most 512 bytes", qp)
			} else if _, err := regexp.Compile("^(?:" + q.Pattern + ")$"); err != nil {
				v.errf("%s.pattern: %v", qp, err)
			}
		}
	}
}

func (v *validator) patchMatches(p string, list []PatchMatch) {
	for j, m := range list {
		if m.Name == "" || len(m.Name) > 256 {
			v.errf("%s[%d].name: required, at most 256 bytes", p, j)
		}
		if m.Pattern != "" {
			if len(m.Pattern) > 512 {
				v.errf("%s[%d].pattern: at most 512 bytes", p, j)
			} else if _, err := regexp.Compile(m.Pattern); err != nil {
				v.errf("%s[%d].pattern: %v", p, j, err)
			}
		}
	}
}

// patchIDRE allows dots in patch identifiers (cve-2024-1234, app.export.1).
var patchIDRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62})$`)

func (v *validator) virtualPatches(patches []VirtualPatch, routes map[string]bool) {
	if len(patches) > 1024 {
		v.errf("virtual_patches: at most 1024 patches")
	}
	ids := map[string]bool{}
	for i := range patches {
		vp := &patches[i]
		p := fmt.Sprintf("virtual_patches[%d]", i)
		if !patchIDRE.MatchString(vp.ID) {
			v.errf("%s.id: %q is not a valid identifier (a-z, 0-9, . _ -)", p, vp.ID)
		} else if ids[vp.ID] {
			v.errf("%s.id: duplicate %q", p, vp.ID)
		}
		ids[vp.ID] = true
		if len(vp.Description) > 512 {
			v.errf("%s.description: at most 512 bytes", p)
		}
		for j, h := range vp.Hosts {
			if !hostPatternOK(h) {
				v.errf("%s.hosts[%d]: %q is not a valid host pattern", p, j, h)
			}
		}
		for j, r := range vp.Routes {
			if !routes[r] {
				v.errf("%s.routes[%d]: unknown route %q", p, j, r)
			}
		}
		for j, path := range vp.Paths {
			if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\ ") {
				v.errf("%s.paths[%d]: %q must be an absolute, normalised prefix", p, j, path)
			}
		}
		for j, re := range vp.PathRegex {
			if re == "" || len(re) > 512 {
				v.errf("%s.path_regex[%d]: must be 1 to 512 bytes", p, j)
			} else if _, err := regexp.Compile("^(?:" + re + ")$"); err != nil {
				v.errf("%s.path_regex[%d]: %v", p, j, err)
			}
		}
		v.methodList(p+".methods", vp.Methods)
		v.patchMatches(p+".query", vp.Query)
		v.patchMatches(p+".headers", vp.Headers)
		v.patchMatches(p+".cookies", vp.Cookies)
		if b := vp.Body; b != nil {
			if b.Pattern == "" || len(b.Pattern) > 512 {
				v.errf("%s.body.pattern: required, at most 512 bytes", p)
			} else if _, err := regexp.Compile(b.Pattern); err != nil {
				v.errf("%s.body.pattern: %v", p, err)
			}
			if b.MaxBytes < 1 || b.MaxBytes > 16<<20 {
				v.errf("%s.body.max_bytes: must be between 1 and 16 MiB", p)
			}
			v.mediaTypes(p+".body.content_types", b.ContentTypes)
			switch b.OverLimit {
			case "", "match", "skip":
			default:
				v.errf("%s.body.over_limit: must be match or skip", p)
			}
		}
		if len(vp.Paths)+len(vp.PathRegex)+len(vp.Query)+len(vp.Headers)+len(vp.Cookies) == 0 && vp.Body == nil {
			v.errf("%s: needs at least one of paths, path_regex, query, headers, cookies or body", p)
		}
		switch vp.Action {
		case "block", "log":
		default:
			v.errf("%s.action: must be block or log", p)
		}
		if vp.Status < 400 || vp.Status > 599 {
			v.errf("%s.status: must be a 4xx or 5xx status", p)
		}
		if vp.Expires != "" {
			if _, err := ParsePatchExpiry(vp.Expires); err != nil {
				v.errf("%s.expires: %v", p, err)
			}
		}
	}
}

// ParsePatchExpiry parses an expiry as RFC 3339 or a date, which
// expires at the end of that day in UTC.
func ParsePatchExpiry(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(24*time.Hour - time.Nanosecond), nil
	}
	return time.Time{}, fmt.Errorf("%q is not RFC 3339 or YYYY-MM-DD", s)
}

func (v *validator) fleet(f *Fleet) {
	u, err := url.Parse(f.Controller)
	switch {
	case f.Controller == "" || err != nil || u.Host == "":
		v.errf("fleet.controller: must be a URL")
	case u.Scheme != "https":
		v.errf("fleet.controller: must be an https URL")
	case u.Path != "" && u.Path != "/":
		v.errf("fleet.controller: must not carry a path")
	}
	if !nameRE.MatchString(f.NodeID) {
		v.errf("fleet.node_id: %q is not a valid name", f.NodeID)
	}
	if f.TLS.CertFile == "" || f.TLS.KeyFile == "" || f.TLS.CAFile == "" {
		v.errf("fleet.tls: cert_file, key_file and ca_file are all required (mutual TLS is mandatory)")
	} else {
		v.file("fleet.tls.cert_file", f.TLS.CertFile)
		v.file("fleet.tls.key_file", f.TLS.KeyFile)
		v.file("fleet.tls.ca_file", f.TLS.CAFile)
	}
	if f.Interval < Duration(5*time.Second) || f.Interval > Duration(time.Hour) {
		v.errf("fleet.interval: must be between 5s and 1h")
	}
	if f.Timeout < Duration(time.Second) || f.Timeout > Duration(time.Minute) {
		v.errf("fleet.timeout: must be between 1s and 1m")
	}
	if f.Dir != "" {
		v.dir("fleet.dir", f.Dir)
	}
	for i, t := range f.Tags {
		if !nameRE.MatchString(t) {
			v.errf("fleet.tags[%d]: %q is not a valid name", i, t)
		}
	}
}

func (v *validator) siem(s *SIEM) {
	const p = "logging.siem"
	u, err := url.Parse(s.Endpoint)
	switch {
	case s.Endpoint == "" || err != nil || u.Host == "":
		v.errf("%s.endpoint: must be a URL", p)
	case u.Scheme == "https":
	case u.Scheme == "http" && s.AllowHTTP:
	default:
		v.errf("%s.endpoint: must be an https URL (http only with allow_http)", p)
	}
	switch s.Format {
	case "json", "hec", "cef", "leef":
	default:
		v.errf("%s.format: must be json, hec, cef or leef", p)
	}
	if s.Timeout <= 0 || s.Timeout > Duration(time.Minute) {
		v.errf("%s.timeout: must be positive and at most 1m", p)
	}
	for k := range s.Headers {
		if !headerNameOK(k) {
			v.errf("%s.headers: %q is not a header", p, k)
		}
	}
	if s.AuthFile != "" {
		v.file(p+".auth_file", s.AuthFile)
	}
	if s.CAFile != "" {
		v.file(p+".ca_file", s.CAFile)
	}
	if (s.CertFile == "") != (s.KeyFile == "") {
		v.errf("%s: cert_file and key_file go together", p)
	} else if s.CertFile != "" {
		v.file(p+".cert_file", s.CertFile)
		v.file(p+".key_file", s.KeyFile)
	}
	if s.Batch < 1 || s.Batch > 10000 {
		v.errf("%s.batch: must be between 1 and 10000", p)
	}
	if s.Interval < Duration(100*time.Millisecond) || s.Interval > Duration(5*time.Minute) {
		v.errf("%s.interval: must be between 100ms and 5m", p)
	}
	if s.Queue < 1 || s.Queue > 1_000_000 {
		v.errf("%s.queue: must be between 1 and 1000000", p)
	}
	for _, f := range []struct{ k, v string }{{"vendor", s.Vendor}, {"product", s.Product}} {
		if f.v == "" || len(f.v) > 63 || strings.ContainsAny(f.v, "|\\\n") {
			v.errf("%s.%s: 1 to 63 characters without | or backslash", p, f.k)
		}
	}
	if len(s.Hostname) > 255 {
		v.errf("%s.hostname: at most 255 characters", p)
	}
}

func (v *validator) otlpExport(p string, o *OTLPExport) {
	u, err := url.Parse(o.Endpoint)
	switch {
	case o.Endpoint == "" || err != nil || u.Host == "":
		v.errf("%s.endpoint: must be a URL", p)
	case u.Scheme == "https":
	case u.Scheme == "http" && o.AllowHTTP:
	default:
		v.errf("%s.endpoint: must be an https URL (http only with allow_http)", p)
	}
	if o.Timeout <= 0 || o.Timeout > Duration(time.Minute) {
		v.errf("%s.timeout: must be positive and at most 1m", p)
	}
	for k := range o.Headers {
		if !headerNameOK(k) {
			v.errf("%s.headers: %q is not a header", p, k)
		}
	}
	if o.CAFile != "" {
		v.file(p+".ca_file", o.CAFile)
	}
	if len(o.ServiceName) > 255 {
		v.errf("%s.service_name: at most 255 characters", p)
	}
	for k := range o.Attributes {
		if k == "" || len(k) > 255 {
			v.errf("%s.attributes: empty or overlong key", p)
		}
	}
	if o.Batch < 1 || o.Batch > 10000 {
		v.errf("%s.batch: must be between 1 and 10000", p)
	}
	if o.Interval < Duration(100*time.Millisecond) || o.Interval > Duration(5*time.Minute) {
		v.errf("%s.interval: must be between 100ms and 5m", p)
	}
	if o.Queue < 1 || o.Queue > 1_000_000 {
		v.errf("%s.queue: must be between 1 and 1000000", p)
	}
}

// when checks an expression of the route: syntax, functions, variables
// and capture names.
func (v *validator) when(p, src string, r *Route) {
	if src == "" {
		return
	}
	if len(src) > 4096 {
		v.errf("%s: expression longer than 4096 bytes", p)
		return
	}
	if _, err := expr.Parse(src, ExprVars(), CaptureNames(r)...); err != nil {
		v.errf("%s: %v", p, err)
	}
}
