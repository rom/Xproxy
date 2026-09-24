package config

import (
	"encoding/hex"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/expr"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/ftp"
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/rdp"
	"github.com/rom/xproxy/internal/rfb"
	"github.com/rom/xproxy/internal/syslog"
	"github.com/rom/xproxy/internal/telnet"
	"github.com/rom/xproxy/internal/tmpl"
	"github.com/rom/xproxy/internal/yara"
	"mime"
	"path/filepath"
	"sort"
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
	// icapNames is every service icap.services defines, so a section
	// that names one is told at load rather than at the first file it
	// tries to scan.
	icapNames map[string]bool
}

// transferICAP checks a scanning section on a kind that moves files.
// downloads says whether this kind can scan them at all: sftp cannot,
// because a download there is a run of reads at offsets with no end to
// scan at.
func (v *validator) transferICAP(p string, c *TransferICAP, readOnly, downloads bool) {
	if c.Service == "" {
		v.errf("%s.service: required", p)
	} else {
		v.icapRef(p+".service", c.Service)
	}
	if !downloads && c.Downloads {
		v.errf("%s.downloads: not available here; a download is a run of reads at offsets with no end to scan at", p)
	}
	scansDown := downloads && c.ScansDownloads()
	if !c.ScansUploads() && !scansDown {
		v.errf("%s: nothing is scanned, so the service would never be asked", p)
	}
	if readOnly && c.ScansUploads() && !scansDown {
		v.warnf("%s: read_only is set, so there are no uploads to scan", p)
	}
}

// icapRef checks that a section names a service that exists. A name
// that does not is a scanner nobody notices is missing until a file
// goes past unscanned, or a session fails, depending on which way the
// service was told to fail.
func (v *validator) icapRef(p, name string) {
	if v.icapNames[name] {
		return
	}
	if len(v.icapNames) == 0 {
		v.errf("%s: %q, but no icap.services are configured", p, name)
		return
	}
	have := make([]string, 0, len(v.icapNames))
	for n := range v.icapNames {
		have = append(have, n)
	}
	sort.Strings(have)
	v.errf("%s: no icap service named %q; configured: %s", p, name, strings.Join(have, ", "))
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
	v := &validator{fileCheck: files, icapNames: map[string]bool{}}
	if c.ICAP != nil {
		for i := range c.ICAP.Services {
			v.icapNames[c.ICAP.Services[i].Name] = true
		}
	}
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
	v.securityTxt(c)
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
		if m := c.Server.Listeners[i].SMTP; m != nil && m.Upstream != "" && !upstreams[m.Upstream] {
			v.errf("server.listeners[%d].smtp.upstream: unknown upstream %q", i, m.Upstream)
		}
		if q := c.Server.Listeners[i].MQTT; q != nil && q.Upstream != "" && !upstreams[q.Upstream] {
			v.errf("server.listeners[%d].mqtt.upstream: unknown upstream %q", i, q.Upstream)
		}
		if h := c.Server.Listeners[i].SSH; h != nil && h.Upstream != "" && !upstreams[h.Upstream] {
			v.errf("server.listeners[%d].ssh.upstream: unknown upstream %q", i, h.Upstream)
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
	v.honeytokens(c.Honeytokens)
	v.handshake(c)
	v.degradation(c, routes)
	if c.Capture != nil {
		v.capture(c.Capture, routes)
	}
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
		} else if !v.hostPortOK(p+".address", ln.Address) { //nolint:revive // the helper reports
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
		case "udp":
			if ln.TLS != nil || len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.H2C {
				v.errf("%s: a udp listener takes only address and udp (there is no handshake on a datagram to secure or a protocol to negotiate)", p)
			}
			if ln.ProxyProtocol {
				v.errf("%s.proxy_protocol: a PROXY protocol header cannot be sent on a datagram flow", p)
			}
			if ln.UDP == nil {
				v.errf("%s.udp: required for kind udp", p)
			} else {
				v.udpListener(p+".udp", ln.UDP, ln.Address)
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
		case "smtp":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: an smtp listener takes only address, smtp and tls", p)
			}
			if ln.SMTP == nil {
				v.errf("%s.smtp: required for kind smtp", p)
			} else {
				v.smtpListener(p+".smtp", ln.SMTP, ln.TLS != nil)
			}
		case "mqtt":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: an mqtt listener takes only address, mqtt and tls", p)
			}
			if ln.MQTT == nil {
				v.errf("%s.mqtt: required for kind mqtt", p)
			} else {
				v.mqttListener(p+".mqtt", ln.MQTT, ln.TLS != nil)
			}
		case "ssh":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: an ssh listener takes only address and ssh (SSH carries its own transport security)", p)
			}
			if ln.SSH == nil {
				v.errf("%s.ssh: required for kind ssh", p)
			} else {
				v.sshListener(p+".ssh", ln.SSH)
			}
		case "vnc":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: a vnc listener takes only address, vnc and tls", p)
			}
			if ln.VNC == nil {
				v.errf("%s.vnc: required for kind vnc", p)
			} else {
				v.vncListener(p+".vnc", ln.VNC, ln.TLS != nil)
			}
		case "rdp":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: an rdp listener takes only address, rdp and tls", p)
			}
			if ln.RDP == nil {
				v.errf("%s.rdp: required for kind rdp", p)
			} else {
				v.rdpListener(p+".rdp", ln.RDP, ln.TLS != nil)
			}
		case "telnet":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: a telnet listener takes only address, telnet and tls", p)
			}
			if ln.Telnet == nil {
				v.errf("%s.telnet: required for kind telnet", p)
			} else {
				v.telnetListener(p+".telnet", ln.Telnet, ln.TLS != nil)
			}
		case "ftp":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: an ftp listener takes only address, ftp and tls", p)
			}
			if ln.FTP == nil {
				v.errf("%s.ftp: required for kind ftp", p)
			} else {
				v.ftpListener(p+".ftp", ln.FTP, ln.TLS != nil)
			}
		case "syslog":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: a syslog listener takes only address, syslog and tls", p)
			}
			if ln.Syslog == nil {
				v.errf("%s.syslog: required for kind syslog", p)
			} else {
				v.syslogListener(p+".syslog", ln.Syslog, ln.TLS != nil)
			}
		default:
			v.errf("%s.kind: must be one of %s", p, strings.Join(listener.Kinds(), ", "))
		}
		v.connectionRate(p, ln.ConnectionRate, ln.ConnectionRatePerSource)
		if ln.UDP != nil && ln.Kind != "udp" {
			v.errf("%s.udp: set on a %s listener (kind: udp)", p, ln.Kind)
		}
		if ln.Syslog != nil && ln.Kind != "syslog" {
			v.errf("%s.syslog: set on a %s listener (kind: syslog)", p, ln.Kind)
		}
		if ln.FTP != nil && ln.Kind != "ftp" {
			v.errf("%s.ftp: set on a %s listener (kind: ftp)", p, ln.Kind)
		}
		if ln.SSH != nil && ln.Kind != "ssh" {
			v.errf("%s.ssh: set on a %s listener (kind: ssh)", p, ln.Kind)
		}
		if ln.SMTP != nil && ln.Kind != "smtp" {
			v.errf("%s.smtp: set on a %s listener (kind: smtp)", p, ln.Kind)
		}
		if ln.MQTT != nil && ln.Kind != "mqtt" {
			v.errf("%s.mqtt: set on a %s listener (kind: mqtt)", p, ln.Kind)
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
	if b := l.MaxBufferedBodyBytes; b != 0 && (b < 1<<20 || b > 64<<30) {
		v.errf("server.limits.max_buffered_body_bytes: must be 0 (unbounded) or between 1 MiB and 64 GiB")
	}
	if b := l.MaxBufferedBodyBytes; b > 0 && b < l.MaxBodyBytes {
		v.warnf("server.limits.max_buffered_body_bytes (%d) is below max_body_bytes (%d): a single request on a route that inspects bodies cannot fit the budget and is refused", b, l.MaxBodyBytes)
	}
	v.connectionRate("server.limits", l.ConnectionRate, l.ConnectionRatePerSource)
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
	v.keyExchange(p, t.KeyExchange)
	v.ech(p, t)
}

// ech checks the Encrypted Client Hello section. The files are parsed
// here rather than only at listener build, so a broken key is a
// configuration error and not a listener that starts and quietly
// serves no ECH at all.
func (v *validator) ech(p string, t *TLS) {
	e := t.ECH
	if e == nil {
		return
	}
	if len(e.Keys) == 0 {
		v.errf("%s.ech.keys: at least one key is required", p)
		return
	}
	if len(e.Keys) > 8 {
		v.errf("%s.ech.keys: at most 8 keys (a rotation needs two, not eight)", p)
	}
	ids := map[uint8]bool{}
	names := map[string]bool{}
	retry := false
	for i := range e.Keys {
		k := &e.Keys[i]
		kp := fmt.Sprintf("%s.ech.keys[%d]", p, i)
		if k.ConfigFile == "" || k.KeyFile == "" {
			v.errf("%s: config_file and key_file are required", kp)
			continue
		}
		v.file(kp+".config_file", k.ConfigFile)
		v.file(kp+".key_file", k.KeyFile)
		if k.RetryOffered() {
			retry = true
		}
		if !v.fileCheck {
			continue
		}
		if st, err := os.Stat(k.KeyFile); err == nil && st.Mode().Perm()&0o004 != 0 {
			v.errf("%s.key_file: %s must not be world readable", kp, k.KeyFile)
		}
		cfg, _, err := LoadECHKey(k.ConfigFile, k.KeyFile)
		if err != nil {
			v.errf("%s: %v", kp, err)
			continue
		}
		if ids[cfg.ID] {
			v.errf("%s: config id %d is used by another key on this listener; a client echoes the id, so two keys sharing one means half the handshakes try the wrong key", kp, cfg.ID)
		}
		ids[cfg.ID] = true
		names[cfg.PublicName] = true
	}
	if len(names) > 1 {
		v.warnf("%s.ech: the keys carry %d different public names; a client falls back to the name in the config it used, so each of them needs a certificate on this listener", p, len(names))
	}
	// The fallback name has to be servable here, or a client whose key
	// is stale meets a certificate error instead of a working page.
	for name := range names {
		if !v.tlsServes(t, name) {
			v.warnf("%s.ech: no certificate on this listener covers the public name %q; a client whose key is stale falls back to it and will see a certificate error", p, name)
		}
	}
	if !retry && len(e.Keys) > 0 {
		v.warnf("%s.ech: no key has retry set, so a client with a stale config is never told the new one and keeps falling back", p)
	}
	if e.Require {
		v.warnf("%s.ech.require: every client that did not get the ECH key is refused, including one whose DNS answer was filtered; use it only on a listener that exists for ECH clients", p)
	}
}

// tlsServes reports whether a listener has a certificate for a name.
// It is a best-effort check on the configuration: ACME groups name
// their hosts, and file certificates are read for their SANs.
func (v *validator) tlsServes(t *TLS, name string) bool {
	for _, g := range t.ACME {
		for _, h := range g.Hosts {
			if strings.EqualFold(h, name) {
				return true
			}
		}
	}
	if !v.fileCheck {
		// Without file access the SANs cannot be read, so nothing is
		// claimed either way.
		return true
	}
	for _, c := range t.Certificates {
		if certCovers(c.CertFile, name) {
			return true
		}
	}
	return false
}

// websocketGuard checks the frame policy of a route.
func (v *validator) websocketGuard(p string, r *Route) {
	g := r.WebSocketGuard
	if g == nil {
		return
	}
	if !r.WebSocket {
		v.errf("%s.websocket_guard: needs websocket: true, or nothing upgrades on this route", p)
	}
	if g.MaxFrameBytes == 0 {
		g.MaxFrameBytes = 1 << 20
	}
	if g.MaxFrameBytes < 128 || g.MaxFrameBytes > 64<<20 {
		v.errf("%s.websocket_guard.max_frame_bytes: must be between 128 and 64 MiB", p)
	}
	if g.MaxMessageBytes == 0 {
		g.MaxMessageBytes = 8 << 20
	}
	if g.MaxMessageBytes < g.MaxFrameBytes {
		v.errf("%s.websocket_guard.max_message_bytes: must be at least max_frame_bytes", p)
	}
	if g.MaxMessageBytes > 256<<20 {
		v.errf("%s.websocket_guard.max_message_bytes: must be at most 256 MiB", p)
	}
	if g.MessagesPerSecond < 0 || g.MessagesPerSecond > 1_000_000 {
		v.errf("%s.websocket_guard.messages_per_second: must be between 0 and 1000000", p)
	}
	for i, op := range g.AllowOpcodes {
		switch strings.ToLower(op) {
		case "text", "binary", "close", "ping", "pong", "continuation":
		default:
			v.errf("%s.websocket_guard.allow_opcodes[%d]: %q is not a websocket opcode", p, i, op)
		}
	}
	for i, sp := range g.AllowSubprotocols {
		if sp == "" || strings.ContainsAny(sp, " \t\r\n,;") {
			v.errf("%s.websocket_guard.allow_subprotocols[%d]: %q is not a subprotocol token", p, i, sp)
		}
	}
	switch g.Inspect {
	case "", "text":
		g.Inspect = "text"
	case "none", "all":
	default:
		v.errf("%s.websocket_guard.inspect: must be none, text or all", p)
	}
	if g.MaxInspectBytes == 0 {
		g.MaxInspectBytes = 64 << 10
	}
	if g.MaxInspectBytes < 0 || g.MaxInspectBytes > 8<<20 {
		v.errf("%s.websocket_guard.max_inspect_bytes: must be between 0 and 8 MiB", p)
	}
	for i, pat := range g.DenyPatterns {
		if _, err := regexp.Compile(pat); err != nil {
			v.errf("%s.websocket_guard.deny_patterns[%d]: %v", p, i, err)
		}
	}
	if len(g.DenyPatterns) > 0 && g.Inspect == "none" {
		v.errf("%s.websocket_guard: deny_patterns with inspect: none matches nothing", p)
	}
	switch g.Action {
	case "", "close":
		g.Action = "close"
	case "log":
	default:
		v.errf("%s.websocket_guard.action: must be close or log", p)
	}
	if g.CloseCode != 0 && (g.CloseCode < 3000 || g.CloseCode > 4999) {
		// A code outside the private and registered ranges would be the
		// proxy claiming a protocol condition it did not observe.
		v.errf("%s.websocket_guard.close_code: must be between 3000 and 4999 (the ranges an application may use), or unset to use the protocol's own code", p)
	}
	if !g.Masked() {
		v.warnf("%s.websocket_guard.require_masked: false accepts unmasked client frames, which RFC 6455 forbids and which is how a request is smuggled past an intermediary", p)
	}
}

// keyExchange checks the named groups. An empty list is the default,
// which leads with the post-quantum hybrid; a list that names groups
// and leaves the hybrid out is allowed — a client fleet that cannot do
// it exists — but it is worth saying so, because the traffic it
// protects is recorded today and attacked later.
func (v *validator) keyExchange(p string, names []string) {
	seen := map[string]bool{}
	for i, n := range names {
		if _, ok := KeyExchangeID(n); !ok {
			v.errf("%s.key_exchange[%d]: unknown group %q (known: %s)", p, i, n, strings.Join(KeyExchangeNames(), ", "))
			continue
		}
		if seen[n] {
			v.errf("%s.key_exchange[%d]: duplicate %q", p, i, n)
		}
		seen[n] = true
	}
	if len(names) > 0 && !HasPostQuantum(names) {
		v.warnf("%s.key_exchange: no post-quantum group is offered, so a recording adversary can decrypt this traffic once it has a quantum computer; add X25519MLKEM768 unless a client cannot negotiate it", p)
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
	case "round_robin", "weighted", "least_conn", "hash", "p2c":
	case "ewma":
		// The latency it reads is the same smoothed time to first byte
		// outlier detection uses, and it is recorded per response. A
		// pool that never sees a response -- a layer 4 relay's -- has
		// nothing for this balancer to read, and p2c is the one that
		// reads what such a pool does have.
		if u.HealthCheck != nil && (u.HealthCheck.Type == "tcp" || u.HealthCheck.Type == "udp") {
			v.warnf("%s.balancer: ewma weighs endpoints by the time to first byte of a response, which a pool checked with "+
				"type %s has none of; p2c reads the in-flight count instead", p, u.HealthCheck.Type)
		}
	default:
		v.errf("%s.balancer: must be round_robin, weighted, least_conn, hash, p2c or ewma", p)
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
	switch u.AddressFamily {
	case "", "any", "ipv4", "ipv6":
	default:
		v.errf("%s.address_family: must be any, ipv4 or ipv6", p)
	}
	if u.FallbackDelay > Duration(10*time.Second) {
		v.errf("%s.fallback_delay: at most 10s; it is the pause before the second address family is tried, not a timeout", p)
	}
	if u.FallbackDelay != 0 && (u.AddressFamily == "ipv4" || u.AddressFamily == "ipv6") {
		v.warnf("%s.fallback_delay: address_family %s dials one family, so there is no second one to hold back", p, u.AddressFamily)
	}
	if u.MaxConnectionAge < 0 || u.MaxConnectionAge > Duration(24*time.Hour) {
		v.errf("%s.max_connection_age: must not be negative and at most 24h", p)
	}
	if u.MaxConnectionAge > 0 {
		if u.MaxConnectionAge < Duration(time.Second) {
			v.errf("%s.max_connection_age: must be at least 1s; below that a connection is retired before it is useful", p)
		}
		// An HTTP/2 or HTTP/3 connection carries many streams at once, so
		// it is never between exchanges and there is no safe moment to
		// retire it. Saying so beats a setting that quietly does nothing.
		switch {
		case u.H3:
			v.errf("%s.max_connection_age: not with h3; an HTTP/3 connection carries many streams and is never between exchanges", p)
		case u.H2C:
			v.errf("%s.max_connection_age: not with h2c; an HTTP/2 connection carries many streams and is never between exchanges", p)
		case u.Scheme == "https":
			v.warnf("%s.max_connection_age: an https pool may negotiate HTTP/2, and the age applies only to HTTP/1.1 connections, "+
				"which carry one exchange at a time; on a connection carrying many streams it is ignored", p)
		}
	}
	if l := u.Locality; l != nil {
		if l.MinLocal < 0 || l.MinLocal > 1000 {
			v.errf("%s.locality.min_local: must be 0..1000", p)
		}
		switch {
		case !l.PreferZone && l.MinLocal > 0:
			v.errf("%s.locality.min_local: set without prefer_zone, which is the thing it qualifies", p)
		case l.PreferZone && u.NodeZone == "":
			v.errf("%s.locality.prefer_zone: needs server.zone, or there is nothing for an endpoint's zone to be compared against", p)
		case l.PreferZone && !v.anyEndpointZone(u):
			v.warnf("%s.locality.prefer_zone: no endpoint of this pool names a zone, and an endpoint with no zone is local to every "+
				"zone, so this prefers nothing", p)
		}
	}
	if u.MaxConnectionsPerEndpoint < 0 {
		v.errf("%s.max_connections_per_endpoint: must not be negative", p)
	}
	if u.SlowStart < 0 || u.SlowStart > Duration(time.Hour) {
		v.errf("%s.slow_start: must be between 0 and 1h", p)
	}
	addrs := map[string]bool{}
	sockets := 0
	for j, e := range u.Endpoints {
		ep := fmt.Sprintf("%s.endpoints[%d]", p, j)
		if path, ok := UnixSocket(e.Address); ok {
			sockets++
			switch {
			case path == "":
				v.errf("%s.address: %q names no socket path", ep, e.Address)
			case !strings.HasPrefix(path, "/"):
				v.errf("%s.address: the socket path %q must be absolute", ep, path)
			case addrs[e.Address]:
				v.errf("%s.address: duplicate %q", ep, e.Address)
			}
			addrs[e.Address] = true
			if e.Weight < 1 || e.Weight > 1000 {
				v.errf("%s.weight: must be between 1 and 1000", ep)
			}
			continue
		}
		host, port, err := net.SplitHostPort(e.Address)
		pn, perr := strconv.Atoi(port)
		switch {
		case !v.hostPortOK(ep+".address", e.Address):
		case err != nil || host == "" || port == "":
			v.errf("%s.address: %q must be host:port, or unix:/path for a socket", ep, e.Address)
		case addrs[e.Address]:
			v.errf("%s.address: duplicate %q", ep, e.Address)
		case perr != nil || pn < 1 || pn > 65535:
			v.errf("%s.address: bad port in %q", ep, e.Address)
		}
		addrs[e.Address] = true
		if e.Weight < 1 || e.Weight > 1000 {
			v.errf("%s.weight: must be between 1 and 1000", ep)
		}
		if e.MaxConnections < 0 {
			v.errf("%s.max_connections: must not be negative", ep)
		}
		if e.Priority < 0 || e.Priority > 99 {
			v.errf("%s.priority: must be 0..99", ep)
		}
		if e.Zone != "" && !nameRE.MatchString(e.Zone) {
			v.errf("%s.zone: %q is not a name", ep, e.Zone)
		}
	}
	if sockets > 0 {
		// A socket endpoint's URL carries a synthetic authority, so
		// there is no name in it for TLS to verify and nothing sensible
		// for the handshake to ask for.
		if u.Scheme == "https" && (u.TLS == nil || u.TLS.ServerName == "") {
			v.errf("%s: a unix: endpoint with scheme https needs tls.server_name, because a socket has no name for the certificate to match", p)
		}
		if u.H3 {
			v.errf("%s.h3: HTTP/3 needs UDP to a host; a unix: endpoint has neither", p)
		}
		if u.Discovery != nil {
			v.errf("%s.discovery: discovery produces host:port endpoints and cannot produce a socket path", p)
		}
		if hc := u.HealthCheck; hc != nil && hc.Type == "grpc" {
			v.warnf("%s.health_check: a grpc check over a socket works, but the authority it sends is the synthetic one, "+
				"so a server that routes on :authority may not answer it", p)
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
		case "tcp":
			// A connect probe. Nothing is sent, so nothing about the
			// service behind the port is proved -- only that something
			// is listening, which for a relayed protocol this proxy does
			// not speak is often all there is to know.
			if hc.Send != "" || hc.SendHex != "" || hc.Expect != "" || hc.ExpectHex != "" {
				v.errf("%s.health_check: send and expect need type udp; a tcp check only connects", p)
			}
		case "udp":
			if (hc.Send == "") == (hc.SendHex == "") {
				v.errf("%s.health_check: type udp needs exactly one of send or send_hex; a probe that sends nothing is answered by nothing", p)
			}
			if hc.SendHex != "" {
				if _, err := hex.DecodeString(hc.SendHex); err != nil {
					v.errf("%s.health_check.send_hex: %v", p, err)
				}
			}
			if hc.Expect != "" && hc.ExpectHex != "" {
				v.errf("%s.health_check: expect and expect_hex are two spellings of one requirement; set one", p)
			}
			if hc.ExpectHex != "" {
				if _, err := hex.DecodeString(hc.ExpectHex); err != nil {
					v.errf("%s.health_check.expect_hex: %v", p, err)
				}
			}
		default:
			v.errf("%s.health_check.type: must be http, grpc, tcp or udp", p)
		}
		if hc.Type == "http" || hc.Type == "grpc" {
			if !strings.HasPrefix(hc.Path, "/") {
				v.errf("%s.health_check.path: must start with /", p)
			}
		} else if hc.Path != DefaultHealthCheckPath {
			v.errf("%s.health_check.path: not used by type %s", p, hc.Type)
		}
		if hc.Type != "udp" && (hc.Send != "" || hc.SendHex != "" || hc.Expect != "" || hc.ExpectHex != "") && hc.Type != "tcp" {
			v.errf("%s.health_check: send and expect need type udp", p)
		}
		if len(hc.Send) > 4096 || len(hc.SendHex) > 8192 || len(hc.Expect) > 4096 || len(hc.ExpectHex) > 8192 {
			v.errf("%s.health_check: send and expect are limited to 4096 bytes", p)
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
		if hc.GRPCService != "" && hc.Type != "grpc" && hc.Type != "http" {
			v.errf("%s.health_check.grpc_service: only for type grpc", p)
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
	v.keyExchange(p, t.KeyExchange)
}

func (v *validator) route(i int, r *Route, seen, upstreams, rateLimits map[string]bool) {
	p := fmt.Sprintf("routes[%d]", i)
	if !nameRE.MatchString(r.Name) {
		v.errf("%s.name: %q is not a valid name", p, r.Name)
	} else if seen[r.Name] {
		v.errf("%s.name: duplicate %q", p, r.Name)
	}
	seen[r.Name] = true
	v.websocketGuard(p, r)

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
		if hp.MarkFor() < 0 || hp.MarkFor() > 30*24*time.Hour {
			v.errf("%s.honeypot.mark: must be positive and at most 720h", p)
		}
	}
	if d := r.Deceive; d != nil {
		// Not an action: the route keeps whatever it does for everyone
		// else, and deceive only changes the answer for the clients it
		// admits.
		if r.Honeypot != nil {
			v.errf("%s.deceive: a honeypot route already answers with a decoy", p)
		}
		if !d.Marked && d.BotScoreAt == 0 && len(d.ClientCIDRs) == 0 {
			v.errf("%s.deceive: names no condition, so every client would be answered with a lie", p)
		}
		if d.BotScoreAt < 0 || d.BotScoreAt > 1000 {
			v.errf("%s.deceive.bot_score_at: must be between 0 and 1000", p)
		}
		for i, c := range d.ClientCIDRs {
			if _, err := netip.ParsePrefix(c); err != nil {
				v.errf("%s.deceive.client_cidrs[%d]: %q is not a CIDR", p, i, c)
			}
		}
		v.methodList(p+".deceive.methods", d.Methods)
		n := 0
		for _, set := range []bool{d.Decoy != "", d.Body != "", d.BodyFile != ""} {
			if set {
				n++
			}
		}
		if n != 1 {
			v.errf("%s.deceive: exactly one of decoy, body or body_file is required", p)
		}
		if d.Decoy != "" && !HoneypotDecoys[d.Decoy] {
			v.errf("%s.deceive.decoy: unknown decoy %q", p, d.Decoy)
		}
		if len(d.Body) > 64<<10 {
			v.errf("%s.deceive.body: exceeds 64 KiB", p)
		}
		if d.BodyFile != "" && !strings.HasPrefix(d.BodyFile, "/") {
			v.errf("%s.deceive.body_file: must be an absolute path", p)
		}
		if strings.ContainsAny(d.ContentType, "\r\n") {
			v.errf("%s.deceive.content_type: invalid", p)
		}
		if d.Status < 100 || d.Status > 599 {
			v.errf("%s.deceive.status: must be a valid status", p)
		}
		if d.Status >= 400 {
			v.warnf("%s.deceive.status is %d: an answer that looks like a refusal tells the client what a refusal tells it, "+
				"which is what deceiving was meant to avoid", p, d.Status)
		}
		if d.Mark < 0 || d.Mark > Duration(30*24*time.Hour) {
			v.errf("%s.deceive.mark: must be between 0 and 720h", p)
		}
		v.warnf("%s deceives: the clients it admits get a plausible answer instead of the origin's, and their writes "+
			"never reach it. Check the conditions against the access log before trusting it", p)
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
	"account_abuse": true, "honeytoken": true, "smtp_denied": true, "mqtt_denied": true, "ssh_denied": true, "ftp_denied": true, "syslog_denied": true, "yara": true,
	"forward_sni_mismatch": true, "dns_tunnel": true,
	"telnet_denied": true, "vnc_denied": true, "rdp_denied": true, "sftp_icap": true, "udp_denied": true,
}

// securityTxtFieldRE bounds an extra field name to the token RFC 9116
// inherits from RFC 5322: letters, digits and hyphens.
var securityTxtFieldRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

// securityTxtLangRE is a BCP 47 tag, loosely: a primary subtag and any
// number of hyphenated subtags.
var securityTxtLangRE = regexp.MustCompile(`^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$`)

// securityTxt validates the virtual security.txt entries. RFC 9116 is
// strict about two things and this follows it: there must be a way to
// report, and the document must say when it stops being valid.
func (v *validator) securityTxt(c *Config) {
	listeners := map[string]bool{}
	for _, l := range c.Server.Listeners {
		listeners[l.Name] = true
	}
	names := map[string]bool{}
	for i := range c.SecurityTxt {
		st := &c.SecurityTxt[i]
		p := fmt.Sprintf("security_txt[%d]", i)
		if st.Name != "" {
			if names[st.Name] {
				v.errf("%s.name: duplicate %q", p, st.Name)
			}
			names[st.Name] = true
		}
		for j, h := range st.Hosts {
			if !hostPatternOK(h) {
				v.errf("%s.hosts[%d]: %q is not a valid host pattern", p, j, h)
			}
		}
		if st.HostRegex != "" {
			if len(st.HostRegex) > 512 {
				v.errf("%s.host_regex: at most 512 bytes", p)
			} else if _, err := regexp.Compile(st.HostRegex); err != nil {
				v.errf("%s.host_regex: %v", p, err)
			}
		}
		for j, cidr := range st.HostCIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				v.errf("%s.host_cidrs[%d]: %q is not a CIDR", p, j, cidr)
			}
		}
		for j, cidr := range st.ClientCIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				v.errf("%s.client_cidrs[%d]: %q is not a CIDR", p, j, cidr)
			}
		}
		for j, l := range st.Listeners {
			if !listeners[l] {
				v.errf("%s.listeners[%d]: unknown listener %q", p, j, l)
			}
		}
		verbatim := st.Body != "" || st.BodyFile != ""
		if st.Body != "" && st.BodyFile != "" {
			v.errf("%s: body and body_file are exclusive", p)
		}
		if verbatim && (len(st.Contact) > 0 || st.Expires != "" || len(st.Encryption) > 0 ||
			len(st.Acknowledgments) > 0 || len(st.PreferredLanguages) > 0 || len(st.Canonical) > 0 ||
			len(st.Policy) > 0 || len(st.Hiring) > 0 || len(st.CSAF) > 0 || len(st.Extra) > 0 || st.Comment != "") {
			v.errf("%s: body and body_file replace the whole document, so the fields cannot be set with them", p)
		}
		switch {
		case verbatim:
		case len(st.Contact) == 0:
			v.errf("%s.contact: required (RFC 9116); a security.txt with no way to report is worse than none", p)
		}
		if st.BodyFile != "" {
			v.file(p+".body_file", st.BodyFile)
		}
		if len(st.Body) > 64<<10 {
			v.errf("%s.body: exceeds 64 KiB", p)
		}
		if st.Expires != "" {
			if st.ValidFor != 0 {
				v.errf("%s: expires and valid_for are exclusive", p)
			}
			t, err := time.Parse(time.RFC3339, st.Expires)
			switch {
			case err != nil:
				v.errf("%s.expires: %q is not an RFC 3339 instant (for example 2027-01-31T00:00:00Z)", p, st.Expires)
			case !t.After(time.Now()):
				v.errf("%s.expires: %s is in the past; a finder is told to ignore an expired document", p, st.Expires)
			case t.After(time.Now().Add(3 * 365 * 24 * time.Hour)):
				v.warnf("%s.expires: %s is more than three years out; RFC 9116 asks for less than a year", p, st.Expires)
			}
		}
		if st.ValidFor != 0 && (st.ValidFor < Duration(time.Hour) || st.ValidFor > Duration(3*365*24*time.Hour)) {
			v.errf("%s.valid_for: must be between 1h and three years", p)
		}
		if st.CacheFor < 0 || st.CacheFor > Duration(7*24*time.Hour) {
			v.errf("%s.cache_for: must be between 0 and 168h", p)
		}
		v.securityTxtValues(p+".contact", st.Contact)
		v.securityTxtValues(p+".encryption", st.Encryption)
		v.securityTxtValues(p+".acknowledgments", st.Acknowledgments)
		v.securityTxtValues(p+".canonical", st.Canonical)
		v.securityTxtValues(p+".policy", st.Policy)
		v.securityTxtValues(p+".hiring", st.Hiring)
		v.securityTxtValues(p+".csaf", st.CSAF)
		for j, l := range st.PreferredLanguages {
			if !securityTxtLangRE.MatchString(l) {
				v.errf("%s.preferred_languages[%d]: %q is not a language tag", p, j, l)
			}
		}
		for name, values := range st.Extra {
			if !securityTxtFieldRE.MatchString(name) {
				v.errf("%s.extra: %q is not a field name (letters, digits and hyphens)", p, name)
			}
			v.securityTxtValues(p+".extra."+name, values)
		}
		if strings.ContainsAny(st.Comment, "\r") {
			v.errf("%s.comment: carriage returns are not allowed", p)
		}
	}
}

// hostPortOK reports whether addr is a plausible host:port and, when
// it is not, records why. Whitespace is checked before the split
// because net.SplitHostPort is happy with " 127.0.0.1:8080 ": it
// separates on the last colon and never looks at the rest. A padded
// address passes validation and then fails to bind at start, which is
// the one place an operator cannot see it coming — on a reload the
// listener is built after the configuration is accepted.
func (v *validator) hostPortOK(path, addr string) bool {
	if strings.TrimSpace(addr) != addr {
		v.errf("%s: %q has leading or trailing whitespace", path, addr)
		return false
	}
	if strings.ContainsAny(addr, " \t") {
		v.errf("%s: %q contains a space", path, addr)
		return false
	}
	return true
}

// hasControlByte reports a C0 control or DEL anywhere in s.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// securityTxtValues checks the values of one field. A newline would end
// the field and start another, so a value carrying one could add a
// Contact of somebody else's choosing to the document this proxy
// serves.
func (v *validator) securityTxtValues(path string, values []string) {
	for i, val := range values {
		switch {
		case strings.TrimSpace(val) == "":
			v.errf("%s[%d]: empty", path, i)
		case len(val) > 2048:
			v.errf("%s[%d]: at most 2048 bytes", path, i)
		case strings.ContainsAny(val, "\r\n"):
			v.errf("%s[%d]: line breaks are not allowed in a field value", path, i)
		case hasControlByte(val):
			v.errf("%s[%d]: control characters are not allowed", path, i)
		}
	}
}

// capture checks the pcapng capture section. The bounds matter more
// than most: the files hold decrypted request and response bytes, and
// an unbounded capture is a disk filling with other people's cookies.
func (v *validator) capture(c *Capture, routes map[string]bool) {
	const p = "capture"
	if !c.Enabled {
		// A section that is present and off is a prepared capture, which
		// is the intended shape; nothing else in it needs to be usable
		// until somebody enables it.
		return
	}
	if !strings.HasPrefix(c.Directory, "/") {
		v.errf("%s.directory: must be an absolute path", p)
	} else {
		v.dir(p+".directory", c.Directory)
	}
	if c.FilePrefix == "" || strings.ContainsAny(c.FilePrefix, "/\\.\x00") || len(c.FilePrefix) > 64 {
		v.errf("%s.file_prefix: 1 to 64 characters without a separator or a dot", p)
	}
	if c.MaxFileBytes < 1<<20 || c.MaxFileBytes > 8<<30 {
		v.errf("%s.max_file_bytes: must be between 1 MiB and 8 GiB", p)
	}
	if c.MaxFiles < 1 || c.MaxFiles > 1000 {
		v.errf("%s.max_files: must be between 1 and 1000", p)
	}
	if c.MaxDuration < Duration(time.Second) || c.MaxDuration > Duration(24*time.Hour) {
		v.errf("%s.max_duration: must be between 1s and 24h", p)
	}
	if c.SnapLen < 128 || c.SnapLen > 1<<20 {
		v.errf("%s.snap_len: must be between 128 and 1048576", p)
	}
	if c.MaxBodyBytes < 0 || c.MaxBodyBytes > 16<<20 {
		v.errf("%s.max_body_bytes: must be between 0 and 16 MiB", p)
	}
	for i, h := range c.Redact {
		if !headerNameOK(h) {
			v.errf("%s.redact[%d]: %q is not a header name", p, i, h)
		}
	}
	if c.Bodies && len(c.Redact) == 0 {
		v.warnf("capture.bodies is on with an empty redact list: the files will hold request and response bodies in the clear, " +
			"including anything the application carries in them")
	}
	if c.StartActive {
		v.warnf("capture.start_active records from start-up; a capture is normally turned on for one reproduction " +
			"with xproxyctl capture start and off again")
	}
	names := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		if r.Name != "" {
			if names[r.Name] {
				v.errf("%s.name: duplicate %q", q, r.Name)
			}
			names[r.Name] = true
		}
		for j, h := range r.Hosts {
			if !hostPatternOK(h) {
				v.errf("%s.hosts[%d]: %q is not a valid host pattern", q, j, h)
			}
		}
		for j, n := range r.Routes {
			if !routes[n] {
				v.errf("%s.routes[%d]: unknown route %q", q, j, n)
			}
		}
		v.methodList(q+".methods", r.Methods)
		for j, path := range r.Paths {
			if !strings.HasPrefix(path, "/") {
				v.errf("%s.paths[%d]: %q must start with /", q, j, path)
			}
		}
		for j, cidr := range r.ClientCIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				v.errf("%s.client_cidrs[%d]: %q is not a CIDR", q, j, cidr)
			}
		}
		for j, st := range r.Statuses {
			if (st < 100 || st > 599) && (st < 1 || st > 5) {
				v.errf("%s.statuses[%d]: %d is neither a status nor a class (1 to 5)", q, j, st)
			}
		}
		for j, reason := range r.Reasons {
			base, _, _ := strings.Cut(reason, ":")
			if !denyReasons[base] && !allDenyReasons[base] {
				v.errf("%s.reasons[%d]: unknown reason %q", q, j, reason)
			}
		}
		if r.Percent < 1 || r.Percent > 100 {
			v.errf("%s.percent: must be between 1 and 100", q)
		}
		if r.MaxFlows < 0 || r.MaxFlows > 10_000_000 {
			v.errf("%s.max_flows: must be between 0 and 10000000", q)
		}
	}
}

// allDenyReasons are every reason the proxy raises, including the ones
// a ban trigger may not name: a capture rule is a diagnostic and may
// select on anything the access log can show.
var allDenyReasons = map[string]bool{
	"acl_deny": true, "acl_allow": true, "banned": true, "body_budget": true,
	"normalization": true, "grpc_web": true, "webtransport": true, "cors": true,
	"maintenance": true, "policy": true, "virtual_patch": true, "sensitive_data": true,
	"shed": true, "filter": true, "challenge": true, "waf": true, "jwt": true,
	"honeypot": true, "icap": true, "geo": true, "rate_limit": true, "no_route": true,
	"body_size": true, "uri_length": true, "bad_host": true, "concurrency": true,
	"websocket": true, "account_abuse": true, "tcp_no_route": true,
	"forward_denied": true, "forward_auth": true, "dns_blocked": true, "dns_bogus": true,
	"honeytoken": true,
}

// HoneypotDecoys are the built-in decoy names (bodies live in the proxy,
// which imports this package and so cannot be imported back). The two
// lists are kept in step by a test that fails when either side gains a
// name the other does not have.
var HoneypotDecoys = map[string]bool{
	// PHP and WordPress
	"wp-login": true, "wp-config": true, "wp-users": true, "phpmyadmin": true,
	"phpinfo": true, "adminer": true,
	// Generic and leaked files
	"admin-login": true, "robots": true, "env": true, "git-config": true,
	"htpasswd": true, "backup-sql": true, "s3-listing": true, "laravel-log": true,
	// Secrets and build files
	"aws-credentials": true, "ssh-key": true, "kubeconfig": true,
	"docker-compose": true, "npmrc": true, "pypirc": true, "gitlab-ci": true,
	"terraform-state": true, "vscode-sftp": true, "appsettings": true,
	"database-yml": true, "nginx-config": true,
	// Cloud and orchestration APIs (server side request forgery probes)
	"imds": true, "consul": true, "vault": true, "docker-api": true, "kubelet": true,
	// Data stores and dashboards
	"elasticsearch": true, "couchdb": true, "solr": true, "rabbitmq": true,
	"kibana": true, "grafana": true, "prometheus-config": true, "traefik": true,
	// Application servers and internals
	"tomcat-manager": true, "jenkins": true, "actuator": true, "swagger": true,
	"graphql": true, "debug-vars": true, "server-status": true, "webshell": true,
	// Enterprise front doors
	"confluence": true, "gitlab-login": true, "citrix": true, "fortinet": true,
	"esxi": true, "exchange-autodiscover": true, "idrac": true, "webmail": true,
	"cgi-bin": true, "ivanti": true, "nextcloud": true, "cpanel": true,
	// Cloud metadata other than AWS (more server side request forgery)
	"gcp-metadata": true, "azure-imds": true,
	// Platform consoles, registries and pipelines
	"registry-catalog": true, "argocd": true, "keycloak": true,
	// Application servers with their own exploit history
	"weblogic": true, "jboss": true, "coldfusion": true, "aspnet-trace": true,
	// Documents that are XML on the wire
	"web-config": true, "xmlrpc": true, "sitemap": true, "minio": true,
	"camera": true,
	// Notebooks, models and query front ends
	"jupyter": true, "ollama": true, "clickhouse": true,
	// Devices
	"printer": true,
	// Source control, build and artefact servers
	"gitea": true, "teamcity": true, "nexus": true, "svn-entries": true,
	"idea-workspace": true,
	// Container and cluster management
	"portainer": true, "rancher": true, "etcd": true, "nomad": true,
	"spark": true, "hadoop-yarn": true, "airflow": true,
	// Database consoles and analytics front ends
	"pgadmin": true, "mongo-express": true, "metabase": true, "superset": true,
	"zabbix": true,
	// Content management systems
	"joomla": true, "drupal": true, "magento": true, "moodle": true, "zimbra": true,
	// Firewalls and remote access gateways
	"pfsense": true, "sonicwall": true, "paloalto": true, "cisco-asa": true,
	"mikrotik": true,
	// Framework debug consoles and the probes that hunt them
	"werkzeug-console": true, "symfony-profiler": true, "laravel-telescope": true,
	"thinkphp": true, "phpunit-eval": true, "spring-gateway": true,
	// Files a traversal or a misconfigured server hands over
	"etc-passwd": true, "firebase-config": true, "wp-json-users": true,
	"dockerfile": true, "rails-secrets": true,
	// Mail, messaging and remote access
	"roundcube": true, "postfixadmin": true, "smtp-config": true,
	"dovecot-users": true, "mail-queue": true,
	"emqx-dashboard": true, "mosquitto-conf": true, "mqtt-clients": true, "mqtt-acl": true,
	"teleport": true, "guacamole": true, "authorized-keys": true, "known-hosts": true,
	"sshd-config": true, "sftp-audit": true,
	"openvpn-config": true, "wireguard-conf": true,
	"filezilla-sites": true, "winscp-ini": true, "vsftpd-conf": true, "rsync-modules": true,
	"webmin": true, "cockpit": true,
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
	local := c.IsLocal()
	if c.Listen == "" {
		v.errf("cluster.listen: required")
	} else if path, ok := UnixSocket(c.Listen); ok {
		v.clusterSocket("cluster.listen", path)
	} else if host, port, err := net.SplitHostPort(c.Listen); err != nil {
		v.errf("cluster.listen: %q: %v", c.Listen, err)
	} else if host == "" || host == "0.0.0.0" || host == "::" {
		if port != "0" {
			v.errf("cluster.listen: bind to an internal interface address, not all interfaces")
		}
	}
	seen := map[string]bool{}
	for i, p := range c.Peers {
		path, isUnix := UnixSocket(p)
		switch {
		case isUnix != local:
			// One cluster is one transport. A node that listened on a
			// socket and dialled a host would be reachable by its
			// siblings and not by the peers it dials, which is half a
			// cluster that looks like a whole one.
			v.errf("cluster.peers[%d]: %q and cluster.listen must both be Unix sockets or both be host:port", i, p)
		case isUnix:
			v.clusterSocket(fmt.Sprintf("cluster.peers[%d]", i), path)
		default:
			if _, _, err := net.SplitHostPort(p); err != nil {
				v.errf("cluster.peers[%d]: %q must be host:port", i, p)
			}
		}
		if seen[p] {
			v.errf("cluster.peers[%d]: duplicate %q", i, p)
		}
		seen[p] = true
	}
	if path, ok := UnixSocket(c.Listen); ok && seen[c.Listen] {
		v.errf("cluster.peers: %q is this node's own socket", path)
	}
	if local {
		v.clusterLocal(c)
	} else {
		if c.Local != nil {
			v.errf("cluster.local: only for a Unix socket cluster; a networked one is authenticated by cluster.tls")
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

// clusterSocket checks one Unix cluster address. The path is absolute
// because a relative one would depend on the working directory the
// daemon happens to have, and bounded because the kernel's sockaddr_un
// is.
func (v *validator) clusterSocket(field, path string) {
	switch {
	case path == "":
		v.errf("%s: %s needs a path", field, UnixSocketPrefix)
	case !strings.HasPrefix(path, "/"):
		v.errf("%s: %q must be an absolute path", field, path)
	case len(path) > 100:
		v.errf("%s: %q is longer than a Unix socket path may be", field, path)
	}
}

// clusterLocal checks the authentication of a Unix socket cluster: the
// permissions the socket is created with, and the user ids allowed to
// speak on it.
func (v *validator) clusterLocal(c *Cluster) {
	if c.TLS.CertFile != "" || c.TLS.KeyFile != "" || c.TLS.CAFile != "" || len(c.TLS.AllowedNames) > 0 {
		v.errf("cluster.tls: not used by a Unix socket cluster; the socket's permissions admit the peers")
	}
	if c.Local == nil {
		v.warnf("cluster.local.allow_uids is unset, so any process that can open the socket joins the cluster: " +
			"a peer places bans, decides rate limits and is named in the audit trail, so list the sibling daemons' user ids")
		return
	}
	if m := c.Local.SocketMode; m != "" {
		n, err := strconv.ParseUint(m, 8, 32)
		switch {
		case err != nil || len(m) > 4:
			v.errf("cluster.local.socket_mode: %q is not an octal mode", m)
		case n&0o007 != 0:
			v.errf("cluster.local.socket_mode: %q grants access to every user on the machine", m)
		}
	}
	for i, uid := range c.Local.AllowUIDs {
		if uid < 0 {
			v.errf("cluster.local.allow_uids[%d]: %d is not a user id", i, uid)
		}
		if uid == 0 {
			v.warnf("cluster.local.allow_uids lists root: the daemons run as their own users, and root needs no cluster to reach them")
		}
	}
	if len(c.Local.AllowUIDs) == 0 {
		v.warnf("cluster.local.allow_uids is empty, so any process that can open the socket joins the cluster: " +
			"a peer places bans, decides rate limits and is named in the audit trail, so list the sibling daemons' user ids")
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
	if t.SessionTimeout < 0 || t.SessionTimeout > Duration(7*24*time.Hour) {
		v.errf("%s.session_timeout: must not be negative and at most 168h", p)
	}
	if t.SessionTimeout > 0 && t.SessionTimeout < t.IdleTimeout {
		v.errf("%s.session_timeout: must not be shorter than idle_timeout, which would end every connection at the same moment", p)
	}
	if t.MaxBytesIn < 0 || t.MaxBytesOut < 0 {
		v.errf("%s: max_bytes_in and max_bytes_out must not be negative", p)
	}
	if t.QUICIdleTimeout <= 0 || t.QUICIdleTimeout > Duration(time.Hour) {
		v.errf("%s.quic_idle_timeout: must be positive and at most 1h", p)
	}
	if t.YARA != nil {
		v.yaraPolicy(p+".yara", t.YARA)
		if t.QUIC {
			v.warnf("%s.yara: QUIC flows are not scanned; they are encrypted, and a rule over ciphertext matches nothing", p)
		}
	}
	if t.QUIC && t.ProxyProtocol {
		v.errf("%s.quic: the PROXY protocol header cannot be sent on a datagram flow; disable proxy_protocol or quic", p)
	}
}

// anyEndpointZone reports whether any endpoint of a pool names a zone,
// including the ones discovery will produce (which cannot be known, so a
// discovery section counts as "maybe").
func (v *validator) anyEndpointZone(u *Upstream) bool {
	if u.Discovery != nil {
		return true
	}
	for _, e := range u.Endpoints {
		if e.Zone != "" {
			return true
		}
	}
	return false
}

// connectionRate validates an accept rate wherever one is set: on
// server.limits, or on one listener.
func (v *validator) connectionRate(p string, r *ConnectionRate, sr *SourceRate) {
	if r != nil {
		if r.PerSecond <= 0 {
			v.errf("%s.connection_rate.per_second: must be positive", p)
		}
		if r.Burst < 1 {
			v.errf("%s.connection_rate.burst: must be positive", p)
		}
	}
	if sr == nil {
		return
	}
	q := p + ".connection_rate_per_source"
	if sr.PerSecond <= 0 {
		v.errf("%s.per_second: must be positive", q)
	}
	if sr.Burst < 1 {
		v.errf("%s.burst: must be positive", q)
	}
	if sr.IPv4Prefix < 8 || sr.IPv4Prefix > 32 {
		v.errf("%s.ipv4_prefix: must be 8..32", q)
	}
	if sr.IPv6Prefix < 16 || sr.IPv6Prefix > 128 {
		v.errf("%s.ipv6_prefix: must be 16..128", q)
	}
	if sr.MaxSources < 1 || sr.MaxSources > 1<<22 {
		v.errf("%s.max_sources: must be 1..4194304", q)
	}
	// A /128 counts one address, and an attacker with a /64 has more of
	// those than any table can hold: the bound then costs memory and
	// stops nothing.
	if sr.IPv6Prefix > 96 {
		v.warnf("%s.ipv6_prefix: /%d counts single addresses, and a single attacker is normally given a /64 or more, "+
			"so this bounds nothing while filling the table", q, sr.IPv6Prefix)
	}
}

// udpListener validates a generic datagram relay.
func (v *validator) udpListener(p string, u *UDPListener, address string) {
	if u.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	if u.IdleTimeout <= 0 || u.IdleTimeout > Duration(time.Hour) {
		v.errf("%s.idle_timeout: must be positive and at most 1h", p)
	}
	if u.SessionTimeout < 0 || u.SessionTimeout > Duration(24*time.Hour) {
		v.errf("%s.session_timeout: must not be negative and at most 24h", p)
	}
	if u.SessionTimeout > 0 && u.SessionTimeout < u.IdleTimeout {
		v.errf("%s.session_timeout: must not be shorter than idle_timeout, which would end every session at the same moment", p)
	}
	if u.MaxSessions < 1 {
		v.errf("%s.max_sessions: must be positive", p)
	}
	if u.MaxSessionsPerIP < 0 {
		v.errf("%s.max_sessions_per_ip: must not be negative", p)
	}
	if u.MaxSessionsPerIP > u.MaxSessions {
		v.errf("%s.max_sessions_per_ip: %d is above max_sessions (%d), so it bounds nothing", p, u.MaxSessionsPerIP, u.MaxSessions)
	}
	if u.MaxDatagramBytes < 1 || u.MaxDatagramBytes > 65535 {
		v.errf("%s.max_datagram_bytes: must be 1..65535", p)
	}
	if u.MaxDatagrams < 0 {
		v.errf("%s.max_datagrams: must not be negative", p)
	}
	if u.MaxBytesIn < 0 || u.MaxBytesOut < 0 {
		v.errf("%s: max_bytes_in and max_bytes_out must not be negative", p)
	}
	if u.RateLimit != nil {
		if u.RateLimit.PPS <= 0 {
			v.errf("%s.rate_limit.pps: must be positive", p)
		}
		if u.RateLimit.Burst < 1 {
			v.errf("%s.rate_limit.burst: must be positive", p)
		}
	}
	for i, c := range u.AllowClients {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, c, err)
		}
	}
	// A datagram relay answers whatever address the datagram claimed to
	// come from, so an open one reflects traffic at a victim who never
	// asked for it, amplified by whatever is behind it. Neither control
	// removes spoofing; each bounds who can make this node do it.
	if !loopbackListen(address) && len(u.AllowClients) == 0 && u.RateLimit == nil {
		v.warnf("%s: a udp listener on a non-loopback address with neither allow_clients nor rate_limit relays for anyone "+
			"who can reach it, and a datagram's source can be forged, which makes this node an amplifier", p)
	}
}

// smtpListener validates an SMTP proxy listener. hasTLS says whether the
// listener carries a tls section, which decides whether the TLS modes
// are even reachable.
func (v *validator) smtpListener(p string, m *SMTPListener, hasTLS bool) {
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	switch m.TLSMode {
	case "starttls", "implicit":
		if !hasTLS {
			v.errf("%s.tls_mode: %s needs the listener's tls section (a certificate to answer with)", p, m.TLSMode)
		}
	case "none":
		if m.RequireTLS {
			v.errf("%s.require_tls: nothing can satisfy it with tls_mode: none", p)
		}
	default:
		v.errf("%s.tls_mode: must be starttls, implicit or none", p)
	}
	switch m.UpstreamTLSMode {
	case "none", "starttls", "implicit":
	default:
		v.errf("%s.upstream_tls_mode: must be none, starttls or implicit", p)
	}
	if m.UpstreamTLSMode == "none" && m.UpstreamTLS != nil {
		v.errf("%s.upstream_tls: set with upstream_tls_mode: none, which never uses it", p)
	}
	if m.UpstreamTLS != nil {
		v.upstreamTLS(p+".upstream_tls", m.UpstreamTLS)
	}
	switch m.BareNewlines {
	case "reject", "convert":
	default:
		v.errf("%s.bare_newlines: must be reject or convert", p)
	}
	if m.MaxCommandLine < 64 || m.MaxCommandLine > 4096 {
		v.errf("%s.max_command_line: must be 64..4096 (RFC 5321 asks for at least 512)", p)
	}
	if m.MaxTextLine < m.MaxCommandLine || m.MaxTextLine > 1<<20 {
		v.errf("%s.max_text_line: must be at least max_command_line and at most 1048576", p)
	}
	if m.MaxMessageSize < 0 {
		v.errf("%s.max_message_size: must not be negative", p)
	}
	if m.MaxRecipients < 1 || m.MaxRecipients > 100000 {
		v.errf("%s.max_recipients: must be 1..100000", p)
	}
	if m.MaxMessages < 1 {
		v.errf("%s.max_messages: must be positive", p)
	}
	if m.MaxErrors < 1 {
		v.errf("%s.max_errors: must be positive", p)
	}
	if m.MaxConnections < 1 {
		v.errf("%s.max_connections: must be positive", p)
	}
	if m.ReadTimeout <= 0 || m.ReadTimeout > Duration(time.Hour) {
		v.errf("%s.read_timeout: must be positive and at most 1h", p)
	}
	if m.SessionTimeout <= 0 || m.SessionTimeout > Duration(24*time.Hour) {
		v.errf("%s.session_timeout: must be positive and at most 24h", p)
	}
	if m.SessionTimeout < m.ReadTimeout {
		v.errf("%s.session_timeout: must not be shorter than read_timeout", p)
	}
	seen := map[string]bool{}
	for i, cmd := range m.Commands {
		u := strings.ToUpper(cmd)
		if !smtpVerbs[u] {
			v.errf("%s.commands[%d]: %q is not an SMTP verb this proxy relays", p, i, cmd)
		}
		if seen[u] {
			v.errf("%s.commands[%d]: %q listed twice", p, i, cmd)
		}
		seen[u] = true
	}
	if !seen["QUIT"] {
		v.errf("%s.commands: QUIT must be allowed; a client with no way to end the session waits for the timeout", p)
	}
	if !seen["EHLO"] && !seen["HELO"] {
		v.errf("%s.commands: EHLO or HELO must be allowed", p)
	}
	if m.TLSMode == "starttls" && !seen["STARTTLS"] {
		v.errf("%s.commands: tls_mode starttls needs STARTTLS in commands", p)
	}
	if m.RequireAuth && !seen["AUTH"] {
		v.errf("%s.require_auth: needs AUTH in commands", p)
	}
	if seen["VRFY"] || seen["EXPN"] {
		v.warnf("%s.commands: VRFY and EXPN let a prober test whether an address exists; leave them out unless something depends on them", p)
	}
	for i, kw := range m.HideCapabilities {
		if strings.TrimSpace(kw) == "" || strings.ContainsAny(kw, " \t") {
			v.errf("%s.hide_capabilities[%d]: must be one EHLO keyword", p, i)
		}
	}
	for i, c := range m.AllowClients {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, c, err)
		}
	}
	if m.TLSMode == "none" {
		v.warnf("%s.tls_mode: none carries every password and every message in clear; use starttls with require_tls, or implicit", p)
	} else if !m.RequireTLS {
		v.warnf("%s.require_tls: false lets a client skip STARTTLS and send its password in clear", p)
	}
}

// smtpVerbs is what commands may name. The list is the registered
// command set; whether a verb is wise is a separate question the
// defaults answer.
var smtpVerbs = map[string]bool{
	"EHLO": true, "HELO": true, "MAIL": true, "RCPT": true, "DATA": true,
	"RSET": true, "NOOP": true, "QUIT": true, "AUTH": true, "STARTTLS": true,
	"VRFY": true, "EXPN": true, "HELP": true,
}

// mqttListener validates an MQTT proxy listener.
func (v *validator) mqttListener(p string, m *MQTTListener, hasTLS bool) {
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	switch m.TLSMode {
	case "implicit":
		if !hasTLS {
			v.errf("%s.tls_mode: implicit needs the listener's tls section (a certificate to answer with)", p)
		}
	case "none":
		v.warnf("%s.tls_mode: none carries every credential and every message in clear; MQTT has no in-band upgrade, so use implicit on 8883", p)
	default:
		v.errf("%s.tls_mode: must be implicit or none", p)
	}
	switch m.UpstreamTLSMode {
	case "none", "implicit":
	default:
		v.errf("%s.upstream_tls_mode: must be none or implicit", p)
	}
	if m.UpstreamTLSMode == "none" && m.UpstreamTLS != nil {
		v.errf("%s.upstream_tls: set with upstream_tls_mode: none, which never uses it", p)
	}
	if m.UpstreamTLS != nil {
		v.upstreamTLS(p+".upstream_tls", m.UpstreamTLS)
	}
	seen := map[string]bool{}
	for i, ver := range m.Versions {
		switch ver {
		case "3.1.1", "5.0":
		default:
			v.errf("%s.versions[%d]: must be 3.1.1 or 5.0 (the versions this proxy parses; one it cannot parse it cannot check)", p, i)
		}
		if seen[ver] {
			v.errf("%s.versions[%d]: %q listed twice", p, i, ver)
		}
		seen[ver] = true
	}
	if len(m.Versions) == 0 {
		v.errf("%s.versions: at least one version is required", p)
	}
	switch m.Action {
	case "disconnect", "drop":
	default:
		v.errf("%s.action: must be disconnect or drop", p)
	}
	if m.MaxClientID < 1 || m.MaxClientID > 65535 {
		v.errf("%s.max_client_id: must be 1..65535", p)
	}
	if m.ClientIDPattern != "" {
		if _, err := regexp.Compile(m.ClientIDPattern); err != nil {
			v.errf("%s.client_id_pattern: %v", p, err)
		}
	}
	// The floor is the largest packet a session cannot do without: a
	// CONNECT carrying a client id, a username and a will.
	if m.MaxPacketSize < 1024 || m.MaxPacketSize > 268435460 {
		v.errf("%s.max_packet_size: must be 1024..268435460", p)
	}
	if m.MaxTopicLength < 1 || m.MaxTopicLength > 65535 {
		v.errf("%s.max_topic_length: must be 1..65535", p)
	}
	if m.MaxTopicLevels < 1 || m.MaxTopicLevels > 1000 {
		v.errf("%s.max_topic_levels: must be 1..1000", p)
	}
	if m.MaxSubscriptions < 1 {
		v.errf("%s.max_subscriptions: must be positive", p)
	}
	if m.MaxConnections < 1 {
		v.errf("%s.max_connections: must be positive", p)
	}
	if m.ConnectTimeout <= 0 || m.ConnectTimeout > Duration(10*time.Minute) {
		v.errf("%s.connect_timeout: must be positive and at most 10m", p)
	}
	if m.IdleTimeout <= 0 || m.IdleTimeout > Duration(24*time.Hour) {
		v.errf("%s.idle_timeout: must be positive and at most 24h", p)
	}
	// Keep alive is carried as seconds in a uint16.
	if m.KeepAliveMax < 0 || m.KeepAliveMax > Duration(65535*time.Second) {
		v.errf("%s.keep_alive_max: must be 0 (any) or at most 18h12m15s", p)
	}
	for _, l := range []struct {
		key  string
		list []string
		kind string
	}{
		{"publish_allow", m.PublishAllow, "filter"},
		{"publish_deny", m.PublishDeny, "filter"},
		{"subscribe_allow", m.SubscribeAllow, "filter"},
		{"subscribe_deny", m.SubscribeDeny, "filter"},
	} {
		for i, f := range l.list {
			if err := validTopicFilter(f); err != nil {
				v.errf("%s.%s[%d]: %q is not a topic filter: %v", p, l.key, i, f, err)
			}
		}
	}
	if m.AllowWildcardSubscribe != nil && !*m.AllowWildcardSubscribe {
		for i, f := range m.SubscribeAllow {
			if strings.ContainsAny(f, "+#") {
				v.errf("%s.subscribe_allow[%d]: %q has a wildcard, which allow_wildcard_subscribe: false refuses outright", p, i, f)
			}
		}
	}
	for i, c := range m.AllowClients {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, c, err)
		}
	}
	if len(m.PublishAllow) == 0 && len(m.PublishDeny) == 0 &&
		len(m.SubscribeAllow) == 0 && len(m.SubscribeDeny) == 0 {
		v.warnf("%s: no topic policy, so every client may publish and subscribe to everything the broker allows; "+
			"an mqtt listener without one is a layer 4 listener with extra parsing", p)
	}
}

// validTopicFilter is the MQTT 3.1.1 section 4.7 rule, repeated here
// because config must not import the mqtt package.
func validTopicFilter(f string) error {
	if f == "" {
		return errors.New("empty")
	}
	if len(f) > 65535 {
		return errors.New("longer than a topic can be")
	}
	if strings.ContainsRune(f, 0) {
		return errors.New("contains NUL")
	}
	levels := strings.Split(f, "/")
	for i, l := range levels {
		switch {
		case l == "#":
			if i != len(levels)-1 {
				return errors.New("# is only allowed as the last level")
			}
		case l == "+":
		case strings.ContainsAny(l, "+#"):
			return errors.New("a wildcard takes a whole level or none of it")
		}
	}
	return nil
}

// sshListener validates an SSH bastion listener.
func (v *validator) sshListener(p string, h *SSHListener) {
	if h.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	if len(h.HostKeys) == 0 {
		v.errf("%s.host_keys: at least one is required (clients pin it, so it is the bastion's identity)", p)
	}
	for i, f := range h.HostKeys {
		v.file(fmt.Sprintf("%s.host_keys[%d]", p, i), f)
	}
	if h.AuthorizedKeys == "" && h.UsersFile == "" {
		v.errf("%s: authorized_keys or users_file is required; a bastion that authenticates nobody forwards everybody", p)
	}
	if h.AuthorizedKeys != "" {
		v.file(p+".authorized_keys", h.AuthorizedKeys)
	}
	if h.UsersFile != "" {
		v.file(p+".users_file", h.UsersFile)
		if h.AuthorizedKeys == "" {
			v.warnf("%s.users_file: password authentication alone puts the whole estate behind one guessable secret; add authorized_keys", p)
		}
	}
	if h.UpstreamKeyFile == "" {
		v.errf("%s.upstream_key_file: required (the credential the proxy authenticates to the target with)", p)
	} else {
		v.file(p+".upstream_key_file", h.UpstreamKeyFile)
	}
	switch {
	case h.UpstreamKnownHosts != "":
		v.file(p+".upstream_known_hosts", h.UpstreamKnownHosts)
		if h.UpstreamInsecureHostKey {
			v.errf("%s.upstream_insecure_host_key: set together with upstream_known_hosts, which would never be read", p)
		}
	case h.UpstreamInsecureHostKey:
		if !h.AllowInsecure {
			v.errf("%s.upstream_insecure_host_key: refused unless allow_insecure is also true", p)
		} else {
			v.warnf("%s.upstream_insecure_host_key: every target's host key is accepted, so nothing would notice a machine in the middle "+
				"between the bastion and the target", p)
		}
	default:
		v.errf("%s.upstream_known_hosts: required unless upstream_insecure_host_key is set", p)
	}
	if !strings.HasPrefix(h.ServerVersion, "SSH-2.0-") {
		v.errf("%s.server_version: must begin with SSH-2.0-", p)
	}
	if strings.ContainsAny(h.ServerVersion, "\r\n") || len(h.ServerVersion) > 240 {
		v.errf("%s.server_version: must be one line of at most 240 characters", p)
	}
	if strings.Contains(h.Banner, "\x00") {
		v.errf("%s.banner: must not contain NUL", p)
	}
	if h.MaxAuthTries < 1 || h.MaxAuthTries > 100 {
		v.errf("%s.max_auth_tries: must be 1..100", p)
	}
	if h.MaxSessions < 1 {
		v.errf("%s.max_sessions: must be positive", p)
	}
	if h.MaxChannels < 1 || h.MaxChannels > 1000 {
		v.errf("%s.max_channels: must be 1..1000", p)
	}
	if h.HandshakeTimeout <= 0 || h.HandshakeTimeout > Duration(10*time.Minute) {
		v.errf("%s.handshake_timeout: must be positive and at most 10m", p)
	}
	if h.IdleTimeout <= 0 || h.IdleTimeout > Duration(24*time.Hour) {
		v.errf("%s.idle_timeout: must be positive and at most 24h", p)
	}
	if h.SessionTimeout < 0 || h.SessionTimeout > Duration(7*24*time.Hour) {
		v.errf("%s.session_timeout: must be 0 (no bound) or at most 168h", p)
	}
	chans := map[string]bool{}
	for i, ct := range h.AllowChannels {
		if !SSHChannelTypes[ct] {
			v.errf("%s.allow_channels[%d]: %q is not a channel type this proxy relays", p, i, ct)
		}
		chans[ct] = true
	}
	reqs := map[string]bool{}
	for i, rt := range h.AllowRequests {
		if !SSHRequestTypes[rt] {
			v.errf("%s.allow_requests[%d]: %q is not a session request this proxy relays", p, i, rt)
		}
		reqs[rt] = true
	}
	if reqs["x11-req"] {
		v.warnf("%s.allow_requests: x11-req lets the target open a channel back into the client's display", p)
	}
	if reqs["auth-agent-req@openssh.com"] {
		v.warnf("%s.allow_requests: agent forwarding lets anything on the target sign with the client's keys for as long as the session lasts", p)
	}
	if reqs["subsystem"] && len(h.AllowSubsystems) == 0 {
		v.errf("%s.allow_subsystems: subsystem is allowed but no subsystem is", p)
	}
	for i, sub := range h.AllowSubsystems {
		if sub == "" || strings.ContainsAny(sub, " \t\r\n") {
			v.errf("%s.allow_subsystems[%d]: must be one name", p, i)
		}
	}
	for i, re := range h.AllowCommands {
		if _, err := regexp.Compile(re); err != nil {
			v.errf("%s.allow_commands[%d]: %v", p, i, err)
		}
	}
	if len(h.AllowCommands) > 0 && !reqs["exec"] {
		v.errf("%s.allow_commands: set without exec in allow_requests, so nothing would ever match it", p)
	}
	for i, d := range h.Forward {
		if err := sshForwardOK(d); err != nil {
			v.errf("%s.forward[%d]: %q: %v", p, i, d, err)
		}
	}
	if len(h.Forward) > 0 && !chans["direct-tcpip"] {
		v.errf("%s.forward: set without direct-tcpip in allow_channels, so no forward can be opened", p)
	}
	if chans["direct-tcpip"] && len(h.Forward) == 0 {
		v.errf("%s.forward: direct-tcpip is allowed with no destinations, which would refuse every forward; list the destinations or drop the channel type", p)
	}
	if h.RemoteForward {
		v.warnf("%s.remote_forward: tcpip-forward asks the target to listen on the client's behalf, which turns the session into an inbound path", p)
	}
	if h.TrustedUserCAKeys != "" {
		v.file(p+".trusted_user_ca_keys", h.TrustedUserCAKeys)
	}
	if h.AuthorizedKeys == "" && h.UsersFile == "" && h.TrustedUserCAKeys == "" {
		// Stated again here because trusted_user_ca_keys is the third
		// way to authenticate and the earlier check knows only two.
		v.errf("%s: authorized_keys, users_file or trusted_user_ca_keys is required", p)
	}
	for i, e := range h.AllowEnv {
		if !envPatternOK(e) {
			v.errf("%s.allow_env[%d]: %q is not a variable name or a name ending in *", p, i, e)
		}
		if envDenied(e) {
			v.errf("%s.allow_env[%d]: %q is refused whatever an allow list says; it is a way to run code before the command", p, i, e)
		}
	}
	v.sshPrincipals(p, h)
	if h.AllowFileTransferCommands != nil && *h.AllowFileTransferCommands && h.SFTP != nil {
		v.warnf("%s.allow_file_transfer_commands: true with an sftp policy, so scp and rsync move files past every path and operation rule it sets", p)
	}
	if h.MFA != nil {
		v.mfaPolicy(p+".mfa", h.MFA)
	}
	if h.SFTP != nil {
		v.sftpPolicy(p+".sftp", h.SFTP, reqs["subsystem"], len(h.Principals) > 0)
	}
	if h.Recording != nil {
		v.sessionRecording(p+".recording", h.Recording, reqs)
	}
	for i, c := range h.AllowClients {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, c, err)
		}
	}
}

// sftpPolicy validates an SFTP policy. subsystemAllowed says whether a
// session could start one at all, because a policy on a subsystem
// nobody may request is a policy nobody reads.
func (v *validator) sftpPolicy(p string, s *SFTPPolicy, subsystemAllowed, hasPrincipals bool) {
	if !subsystemAllowed {
		v.errf("%s: set without subsystem in allow_requests, so no sftp session can start", p)
	}
	if s.MaxPacketSize < 4096 || s.MaxPacketSize > 1<<24 {
		v.errf("%s.max_packet_size: must be 4096..16777216", p)
	}
	for i, op := range s.DenyOperations {
		if !SFTPOperations[strings.ToLower(op)] {
			v.errf("%s.deny_operations[%d]: %q is not an SFTP operation", p, i, op)
		}
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"allow_paths", s.AllowPaths}, {"deny_paths", s.DenyPaths}} {
		for i, path := range l.list {
			if path == "" || strings.ContainsRune(path, 0) {
				v.errf("%s.%s[%d]: must be a path", p, l.key, i)
			}
			if err := sftpTemplateOK(path); err != nil {
				v.errf("%s.%s[%d]: %v", p, l.key, i, err)
			} else if !hasPrincipals && strings.Contains(path, "{principal}") {
				v.errf("%s.%s[%d]: {principal} with no principals list, so no session has a name to put here and every one would be refused", p, l.key, i)
			}
		}
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"allow_extensions", s.AllowExtensions}, {"deny_extensions", s.DenyExtensions}} {
		seen := map[string]bool{}
		for i, e := range l.list {
			switch {
			case e == "":
				v.errf("%s.%s[%d]: must be an extension", p, l.key, i)
			case strings.ContainsAny(e, "./\\*?"):
				v.errf("%s.%s[%d]: %q is an extension, without a dot and without a glob", p, l.key, i, e)
			}
			low := strings.ToLower(e)
			if seen[low] {
				v.errf("%s.%s[%d]: %q listed twice", p, l.key, i, e)
			}
			seen[low] = true
		}
	}
	for _, e := range s.AllowExtensions {
		for _, d := range s.DenyExtensions {
			if strings.EqualFold(e, d) {
				v.errf("%s: %q is in allow_extensions and deny_extensions; the deny list wins, so the allow entry says nothing", p, e)
			}
		}
	}
	if s.MaxFileBytes < 0 {
		v.errf("%s.max_file_bytes: must not be negative", p)
	}
	if s.MaxOpenFiles < 1 || s.MaxOpenFiles > 65536 {
		v.errf("%s.max_open_files: must be 1..65536", p)
	}
	if s.YARA != nil {
		v.yaraPolicy(p+".yara", s.YARA)
		if s.ReadOnly {
			v.warnf("%s.yara: read_only already refuses every write, so nothing reaches these rules", p)
		}
	}
	if s.ICAP != nil {
		v.transferICAP(p+".icap", s.ICAP, s.ReadOnly, false)
	}
}

// sftpTemplateOK checks the {user} and {principal} substitutions in a
// path pattern. An unknown one is an error rather than a literal:
// "{usr}" left as it stands is a pattern that matches nothing, which
// on an allow list refuses everybody and on a deny list refuses
// nobody, and neither is what was written.
func sftpTemplateOK(pattern string) error {
	rest := pattern
	for {
		i := strings.IndexByte(rest, '{')
		if i < 0 {
			if strings.ContainsRune(rest, '}') {
				return fmt.Errorf("%q has a closing brace with no substitution", pattern)
			}
			return nil
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return fmt.Errorf("%q has an unclosed substitution", pattern)
		}
		name := rest[i+1 : i+j]
		if !SFTPPathVars[name] {
			return fmt.Errorf("%q: {%s} is not a substitution here; {user} and {principal} are", pattern, name)
		}
		rest = rest[i+j+1:]
	}
}

// sessionRecording validates a session recording section. reqs is what the
// session may ask for, because a recording of requests nobody may make
// is a directory that stays empty.
func (v *validator) sessionRecording(p string, r *SessionRecording, reqs map[string]bool) {
	if r.Enabled != nil && !*r.Enabled {
		// Turned off here. Nothing is written, so nothing else in the
		// section has to make sense, and saying more would be telling
		// an operator to fill in a form they are opting out of.
		return
	}
	if r.Directory == "" {
		v.errf("%s.directory: required", p)
	} else {
		v.dir(p+".directory", r.Directory)
	}
	if r.FilePrefix == "" || strings.ContainsAny(r.FilePrefix, "/\\.\x00") {
		v.errf("%s.file_prefix: must be a name without a path or a dot", p)
	}
	if r.MaxFileBytes < 4096 || r.MaxFileBytes > 1<<32 {
		v.errf("%s.max_file_bytes: must be 4096..4294967296", p)
	}
	if r.MaxFiles < 1 || r.MaxFiles > 100000 {
		v.errf("%s.max_files: must be 1..100000", p)
	}
	if r.Input {
		v.warnf("%s.input: the input stream carries what the screen never showed, including every password typed into a sudo or su prompt", p)
	}
	// reqs is the ssh request policy, and nil for a kind whose sessions
	// are not made of ssh channel requests: an ftp control channel is
	// always recordable, so there is nothing here that could make the
	// section write nothing.
	if reqs == nil {
		return
	}
	recordsShell := reqs["shell"]
	recordsExec := reqs["exec"] && (r.Commands == nil || *r.Commands)
	if !recordsShell && !recordsExec {
		v.errf("%s: neither shell nor exec is recordable here, so nothing would ever be written", p)
	}
}

// sshPrincipals validates the per principal entries and their
// policies.
func (v *validator) sshPrincipals(p string, h *SSHListener) {
	names := map[string]bool{}
	for i := range h.Principals {
		e := &h.Principals[i]
		q := fmt.Sprintf("%s.principals[%d]", p, i)
		if e.Name == "" {
			v.errf("%s.name: required; it is what a refusal names in the log", q)
		} else if names[e.Name] {
			v.errf("%s.name: %q is used twice", q, e.Name)
		}
		names[e.Name] = true
		for j, f := range e.Fingerprints {
			if !strings.HasPrefix(f, "SHA256:") || len(f) != len("SHA256:")+43 {
				v.errf("%s.fingerprints[%d]: %q is not a SHA256 fingerprint as ssh-keygen prints it", q, j, f)
			}
		}
		if len(e.CertPrincipals) > 0 && h.TrustedUserCAKeys == "" {
			v.errf("%s.cert_principals: set without trusted_user_ca_keys, so no certificate can ever be accepted", q)
		}
		for j, u := range e.Users {
			if u == "" || strings.ContainsAny(u, " \t\r\n") {
				v.errf("%s.users[%d]: must be one login name", q, j)
			}
		}
		isDefault := len(e.Fingerprints) == 0 && len(e.CertPrincipals) == 0
		if isDefault && i != len(h.Principals)-1 {
			v.errf("%s: names neither a fingerprint nor a certificate principal, so it matches everything; a default entry must be last", q)
		}
		if e.Policy != nil {
			v.sshPolicy(q+".policy", e.Policy, h)
		}
	}
}

// sshPolicy validates a per principal policy. It is the listener's own
// vocabulary, so the checks are the listener's.
func (v *validator) sshPolicy(p string, s *SSHPolicy, h *SSHListener) {
	chans := map[string]bool{}
	for i, ct := range s.AllowChannels {
		if !SSHChannelTypes[ct] {
			v.errf("%s.allow_channels[%d]: %q is not a channel type this proxy relays", p, i, ct)
		}
		chans[ct] = true
	}
	reqs := map[string]bool{}
	for i, rt := range s.AllowRequests {
		if !SSHRequestTypes[rt] {
			v.errf("%s.allow_requests[%d]: %q is not a session request this proxy relays", p, i, rt)
		}
		reqs[rt] = true
	}
	for i, re := range s.AllowCommands {
		if _, err := regexp.Compile(re); err != nil {
			v.errf("%s.allow_commands[%d]: %v", p, i, err)
		}
	}
	for i, e := range s.AllowEnv {
		if !envPatternOK(e) {
			v.errf("%s.allow_env[%d]: %q is not a variable name or a name ending in *", p, i, e)
		}
		if envDenied(e) {
			v.errf("%s.allow_env[%d]: %q is refused whatever an allow list says", p, i, e)
		}
	}
	for i, d := range s.Forward {
		if err := sshForwardOK(d); err != nil {
			v.errf("%s.forward[%d]: %q: %v", p, i, d, err)
		}
	}
	// A principal that lists direct-tcpip and no destinations of its
	// own falls back to the listener's, which may be empty; say so here
	// rather than leaving every forward refused at runtime.
	if chans["direct-tcpip"] && len(s.Forward) == 0 && len(h.Forward) == 0 {
		v.errf("%s: direct-tcpip is allowed with no destinations here or on the listener, which refuses every forward", p)
	}
	if s.SFTP != nil {
		v.sftpPolicy(p+".sftp", s.SFTP, reqs["subsystem"] || sliceHas(h.AllowRequests, "subsystem"), len(h.Principals) > 0)
	}
	if s.Recording != nil {
		merged := map[string]bool{}
		for _, rt := range h.AllowRequests {
			merged[rt] = true
		}
		for rt := range reqs {
			merged[rt] = true
		}
		v.sessionRecording(p+".recording", s.Recording, merged)
	}
	if s.SFTP != nil && h.SFTP == nil && h.AllowFileTransferCommands != nil && *h.AllowFileTransferCommands {
		v.warnf("%s.sftp: the listener's allow_file_transfer_commands is true, so scp and rsync move files past every path and operation rule set here", p)
	}
	if s.Deny && (len(s.AllowChannels) > 0 || len(s.AllowRequests) > 0 || s.UpstreamUser != "") {
		v.warnf("%s.deny: the rest of this policy is never read", p)
	}
}

func sliceHas(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// envPatternOK accepts a variable name, or a prefix ending in "*".
func envPatternOK(s string) bool {
	name := strings.TrimSuffix(s, "*")
	if name == "" && s != "*" {
		return false
	}
	if s == "*" {
		// Every variable: that is not an allow list.
		return false
	}
	for _, c := range name {
		ok := c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// envDenied reports whether a pattern would admit a variable the proxy
// refuses outright. A prefix that covers a denied name counts.
func envDenied(pattern string) bool {
	for _, d := range SSHDeniedEnv {
		if envMatch(pattern, strings.TrimSuffix(d, "*")) || envMatch(d, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

// envMatch applies one pattern to one name.
func envMatch(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// sshForwardOK checks a direct-tcpip destination: host:port, where host
// is a name, a *.suffix pattern or a CIDR, and port is a number or "*".
func sshForwardOK(d string) error {
	host, port, err := net.SplitHostPort(d)
	if err != nil {
		return errors.New("must be host:port")
	}
	if port != "*" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("port must be 1..65535 or *")
		}
	}
	switch {
	case host == "":
		return errors.New("host is required")
	case strings.Contains(host, "/"):
		if _, err := netip.ParsePrefix(host); err != nil {
			return fmt.Errorf("not a CIDR: %w", err)
		}
	case strings.HasPrefix(host, "*."):
		if !hostPatternOK(host) {
			return errors.New("not a *.suffix pattern")
		}
	default:
		if _, err := netip.ParseAddr(host); err != nil && !hostPatternOK(host) {
			return errors.New("not a name, *.suffix pattern, address or CIDR")
		}
	}
	return nil
}

// mfaPolicy validates a second factor wherever it is configured.
func (v *validator) mfaPolicy(p string, m *MFAPolicy) {
	if m.File == "" {
		v.errf("%s.file: required", p)
	} else {
		v.file(p+".file", m.File)
		if st, err := os.Stat(m.File); err == nil && st.Mode().Perm()&0o004 != 0 {
			v.errf("%s.file: %s must not be world readable: it holds every second factor", p, m.File)
		}
	}
	if strings.ContainsAny(m.Issuer, ":\r\n") {
		v.errf("%s.issuer: must not contain a colon or a line break (it is a label in the enrolment URI)", p)
	}
	if strings.ContainsAny(m.Prompt, "\r\n") {
		v.errf("%s.prompt: must be one line", p)
	}
	if m.Skew < 0 || m.Skew > 10 {
		v.errf("%s.skew: must be 0..10", p)
	}
	if m.Skew > 2 {
		v.warnf("%s.skew: %d steps either side is a window of %d seconds in which an observed code can be replayed", p, m.Skew, (2*m.Skew+1)*30)
	}
	if m.MaxFailures < 1 || m.MaxFailures > 1000 {
		v.errf("%s.max_failures: must be 1..1000", p)
	}
	if m.Window <= 0 || m.Window > Duration(24*time.Hour) {
		v.errf("%s.window: must be positive and at most 24h", p)
	}
	if m.Duration <= 0 || m.Duration > Duration(7*24*time.Hour) {
		v.errf("%s.lockout: must be positive and at most 168h", p)
	}
	if m.MaxUsers < 1 {
		v.errf("%s.max_users: must be positive", p)
	}
	if m.RequireEnrolment != nil && !*m.RequireEnrolment {
		v.warnf("%s.require_enrolment: false lets a user who never enrolled past the second factor, which is the account an attacker will use", p)
	}
}

// yaraPolicy validates a YARA policy wherever it is configured.
func (v *validator) yaraPolicy(p string, y *YARAPolicy) {
	switch {
	case y.RulesFile != "" && y.RulesDir != "":
		v.errf("%s: set rules_file or rules_dir, not both", p)
	case y.RulesFile != "":
		v.file(p+".rules_file", y.RulesFile)
		if _, err := yara.LoadFile(y.RulesFile); err != nil {
			v.errf("%s.rules_file: %v", p, err)
		}
	case y.RulesDir != "":
		v.dir(p+".rules_dir", y.RulesDir)
		if _, err := yara.LoadDir(y.RulesDir); err != nil {
			v.errf("%s.rules_dir: %v", p, err)
		}
	default:
		v.errf("%s: rules_file or rules_dir is required", p)
	}
	switch y.Action {
	case "close", "log":
	default:
		v.errf("%s.action: must be close or log", p)
	}
	seen := map[string]bool{}
	for i, d := range y.Directions {
		switch d {
		case "client", "upstream":
		default:
			v.errf("%s.directions[%d]: must be client or upstream", p, i)
		}
		if seen[d] {
			v.errf("%s.directions[%d]: %q listed twice", p, i, d)
		}
		seen[d] = true
	}
	if len(y.Directions) == 0 {
		v.errf("%s.directions: at least one direction is required", p)
	}
	if y.MaxWindow < 4096 || y.MaxWindow > 1<<24 {
		v.errf("%s.max_window: must be 4096..16777216", p)
	}
	if y.MaxBytes < 0 {
		v.errf("%s.max_bytes: must not be negative", p)
	}
	if y.MaxBytes == 0 {
		v.warnf("%s.max_bytes: 0 scans every byte of every connection, which makes a long transfer arbitrarily expensive", p)
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
	v.dnsDiscovery(p, d)
	v.dnsRecords(p, d)
	v.dnsTunnel(p+".tunnel_detection", d.TunnelDetection)
}

// dnsTunnel checks the tunnelling detector. The bounds here are not
// taste: a detector that fires on one signal is a false positive
// generator, and a detector whose table has no ceiling is the denial of
// service it exists to catch.
func (v *validator) dnsTunnel(p string, t *DNSTunnel) {
	if t == nil {
		return
	}
	if t.Window < Duration(10*time.Second) || t.Window > Duration(time.Hour) {
		v.errf("%s.window: must be between 10s and 1h", p)
	}
	if t.MinQueries < 5 || t.MinQueries > 1_000_000 {
		v.errf("%s.min_queries: must be between 5 and 1000000", p)
	}
	if t.MinSignals < 1 || t.MinSignals > 5 {
		v.errf("%s.min_signals: must be between 1 and 5", p)
	}
	if t.MinSignals == 1 {
		v.warnf("%s.min_signals: 1 means any single signal is a detection, and each one has honest traffic behind it — a content delivery network's names are random, a reputation service answers TXT, a waking laptop produces NXDOMAIN; expect false positives and keep action: log", p)
	}
	if t.Entropy < 0 || t.Entropy > 8 {
		v.errf("%s.entropy: must be between 0 and 8 bits per character", p)
	}
	for name, share := range map[string]float64{
		"entropy_share": t.entropyShare(), "txt_share": t.txtShare(), "nxdomain_share": t.nxShare(),
	} {
		if share < 0 || share > 1 {
			v.errf("%s.%s: must be a share between 0 and 1", p, name)
		}
	}
	if t.MinLabelLength < 4 || t.MinLabelLength > 63 {
		v.errf("%s.min_label_length: must be between 4 and 63", p)
	}
	if t.distinct() < 0 || t.distinct() > 1_000_000 {
		v.errf("%s.distinct_subdomains: must be between 0 and 1000000", p)
	}
	if t.payloadBytes() < 0 {
		v.errf("%s.payload_bytes: must not be negative", p)
	}
	// A signal switched off is a signal that can never be one of the
	// min_signals, so a policy asking for more agreement than it has
	// signals left is one that can never fire at all.
	live := 0
	for _, on := range []bool{t.entropyShare() > 0 && t.Entropy > 0, t.distinct() > 0,
		t.txtShare() > 0, t.nxShare() > 0, t.payloadBytes() > 0} {
		if on {
			live++
		}
	}
	if t.MinSignals > live {
		v.errf("%s.min_signals: %d signals must agree but only %d are switched on, so nothing can ever be detected", p, t.MinSignals, live)
	}
	for _, dom := range t.AllowDomains {
		name := strings.TrimPrefix(strings.TrimPrefix(dom, "*."), "=")
		if !hostPatternOK(strings.ToLower(strings.TrimSuffix(name, "."))) {
			v.errf("%s.allow_domains: %q is not a name, *.suffix or =name", p, dom)
		}
	}
	switch t.Action {
	case "log":
	case "block":
		v.warnf("%s.action: block answers NXDOMAIN for a whole registered domain once a client trips the detector, so a false positive takes out every name under it for that client; run it as log until the detections read true", p)
	default:
		v.errf("%s.action: must be log or block", p)
	}
	if t.Cooldown < Duration(time.Second) || t.Cooldown > Duration(24*time.Hour) {
		v.errf("%s.cooldown: must be between 1s and 24h", p)
	}
	if t.MaxTracked < 64 || t.MaxTracked > 10_000_000 {
		v.errf("%s.max_tracked: must be between 64 and 10000000", p)
	}
}

// dnsDiscovery checks the designated resolver advertisement. Getting
// this wrong is worse than not having it: a client that believes the
// record upgrades itself to an endpoint that has to work, and verifies
// a certificate name that has to match.
func (v *validator) dnsDiscovery(p string, d *DNSListener) {
	seen := map[string]bool{}
	for i := range d.Discovery {
		e := &d.Discovery[i]
		ep := fmt.Sprintf("%s.discovery[%d]", p, i)
		switch e.Transport {
		case "dot", "doq":
			if e.Port == 0 {
				e.Port = 853
			}
		case "doh":
			if e.Port == 0 {
				e.Port = 443
			}
			if e.DoHPath == "" {
				e.DoHPath = dns.DefaultDoHPath + "{?dns}"
			}
			if !strings.HasPrefix(e.DoHPath, "/") {
				v.errf("%s.doh_path: must start with /", ep)
			}
		case "":
			v.errf("%s.transport: required (dot, doh or doq)", ep)
			continue
		default:
			v.errf("%s.transport: %q must be dot, doh or doq", ep, e.Transport)
			continue
		}
		if e.Name == "" || !hostPatternOK(strings.ToLower(e.Name)) || strings.HasPrefix(e.Name, "*.") {
			v.errf("%s.name: %q must be the fully qualified name the endpoint's certificate covers", ep, e.Name)
		}
		if e.Port < 1 || e.Port > 65535 {
			v.errf("%s.port: %d is not a port", ep, e.Port)
		}
		key := e.Transport + "/" + e.Name + "/" + strconv.Itoa(e.Port)
		if seen[key] {
			v.errf("%s: the same transport, name and port appears twice", ep)
		}
		seen[key] = true
		for j, a := range e.IPv4 {
			if addr, err := netip.ParseAddr(a); err != nil || !addr.Is4() {
				v.errf("%s.ipv4[%d]: %q is not an IPv4 address", ep, j, a)
			}
		}
		for j, a := range e.IPv6 {
			if addr, err := netip.ParseAddr(a); err != nil || !addr.Is6() || addr.Is4In6() {
				v.errf("%s.ipv6[%d]: %q is not an IPv6 address", ep, j, a)
			}
		}
		if e.TTL < 0 || e.TTL > 86400 {
			v.errf("%s.ttl: must be between 0 and 86400", ep)
		}
		if e.Transport == "doq" && !d.DoQ {
			v.warnf("%s: doq is advertised but this listener does not serve it (set dns.doq)", ep)
		}
	}
}

// dnsRecords checks the locally served SVCB and HTTPS records.
func (v *validator) dnsRecords(p string, d *DNSListener) {
	for i := range d.Records {
		r := &d.Records[i]
		rp := fmt.Sprintf("%s.records[%d]", p, i)
		if r.Name == "" || !hostPatternOK(strings.ToLower(strings.TrimSuffix(r.Name, "."))) {
			v.errf("%s.name: %q is not a name", rp, r.Name)
		}
		switch r.Type {
		case "", "https":
			r.Type = "https"
		case "svcb":
		default:
			v.errf("%s.type: must be https or svcb", rp)
		}
		if r.Priority < 0 || r.Priority > 65535 {
			v.errf("%s.priority: must be between 0 and 65535", rp)
		}
		if r.Priority == 0 && len(r.Params) > 0 {
			v.errf("%s: priority 0 is an alias record and takes no params", rp)
		}
		if r.TTL < 0 || r.TTL > 604800 {
			v.errf("%s.ttl: must be between 0 and 604800", rp)
		}
		if r.Target != "" && r.Target != "." && !hostPatternOK(strings.ToLower(strings.TrimSuffix(r.Target, "."))) {
			v.errf("%s.target: %q is not a name", rp, r.Target)
		}
		for name, value := range r.Params {
			if _, err := dns.ParseSVCBParam(name, value); err != nil {
				v.errf("%s.params.%s: %v", rp, name, err)
			}
		}
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
	case strings.HasPrefix(s, "quic://"):
		host, port, err := net.SplitHostPort(strings.TrimPrefix(s, "quic://"))
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("%q must be quic://host:port", s)
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
	if f.SOCKSUDP && !f.SOCKS5 {
		v.errf("%s.socks_udp: needs socks5", p)
	}
	if f.SOCKS5 && f.Auth == nil {
		// A SOCKS proxy without credentials is an open proxy to
		// everything the destination policy allows, and unlike the HTTP
		// side there is no header a middlebox will strip by accident.
		v.warnf("%s.socks5: no auth is configured, so anyone who can reach this port can use the proxy; restrict the listener address, the destinations, or add auth", p)
	}
	v.forwardIntercept(p+".intercept", f.Intercept)
	v.masque(p, f)
	if f.SOCKSUDP {
		v.warnf("%s.socks_udp: a UDP association relays datagrams for the client that opened it; it is bound to that client's address and dies with the control connection, but it is a wider exposure than a TCP tunnel", p)
	}
}

// forwardIntercept checks the TLS interception section. Every check here
// exists because the feature is the one that replaces a connection the
// client verified with two connections it cannot see past: what is
// refused is refused, and what is merely a decision is warned about so
// it appears in the log somebody reads after the fact.
func (v *validator) forwardIntercept(p string, ic *ForwardIntercept) {
	if ic == nil {
		return
	}
	if ic.CACertFile == "" {
		v.errf("%s.ca_cert_file: required", p)
	} else {
		v.file(p+".ca_cert_file", ic.CACertFile)
	}
	if ic.CAKeyFile == "" {
		v.errf("%s.ca_key_file: required", p)
	} else {
		v.file(p+".ca_key_file", ic.CAKeyFile)
		v.privateFile(p+".ca_key_file", ic.CAKeyFile)
	}
	for _, d := range ic.Hosts {
		if !destinationPatternOK(d) {
			v.errf("%s.hosts: %q is not a name, *.suffix, address or CIDR", p, d)
		}
	}
	for _, d := range ic.BypassHosts {
		if !destinationPatternOK(d) {
			v.errf("%s.bypass_hosts: %q is not a name, *.suffix, address or CIDR", p, d)
		}
	}
	if len(ic.Hosts) == 0 {
		v.warnf("%s.hosts: empty, so every destination this listener allows is decrypted; list the destinations the policy covers, and put what must not be read in bypass_hosts", p)
	}
	if ic.VerifyUpstream != nil && !*ic.VerifyUpstream {
		v.warnf("%s.verify_upstream: false means the proxy does not check the destination's certificate while still presenting a trusted one to the client, which turns every verified connection through this listener into an unverified one with the padlock left in place", p)
	}
	if ic.CAFile != "" {
		v.file(p+".ca_file", ic.CAFile)
	}
	switch ic.MinVersion {
	case "1.2", "1.3":
	default:
		v.errf("%s.min_version: must be 1.2 or 1.3", p)
	}
	if ic.LeafTTL <= 0 || ic.LeafTTL > Duration(30*24*time.Hour) {
		v.errf("%s.leaf_ttl: must be positive and at most 720h", p)
	}
	if ic.MaxCache < 1 || ic.MaxCache > 1_000_000 {
		v.errf("%s.max_cache: must be 1..1000000", p)
	}
	seen := map[string]bool{}
	for i, a := range ic.ALPN {
		switch a {
		case "http/1.1", "h2":
		default:
			v.errf("%s.alpn[%d]: must be http/1.1 or h2", p, i)
		}
		if seen[a] {
			v.errf("%s.alpn[%d]: %q listed twice", p, i, a)
		}
		seen[a] = true
	}
	if seen["h2"] {
		v.warnf("%s.alpn: h2 is offered, and the decrypted stream is relayed as a byte stream rather than parsed as HTTP/2; rules written for requests will not see framed messages", p)
	}
	if ic.YARA != nil {
		v.yaraPolicy(p+".yara", ic.YARA)
	}
}

// masque checks the MASQUE section of a forward listener.
func (v *validator) masque(p string, f *ForwardListener) {
	m := f.Masque
	if m == nil {
		return
	}
	if !m.UDP && !m.IP {
		v.errf("%s.masque: neither udp nor ip is enabled, so the section does nothing", p)
	}
	if m.MaxSessions < 0 || m.MaxSessions > 1_000_000 {
		v.errf("%s.masque.max_sessions: must be between 0 and 1000000", p)
	}
	if m.IP {
		if m.IPDevice == "" {
			v.errf("%s.masque.ip_device: required with ip: a userspace process cannot put an IP packet on the wire without a tunnel device", p)
		}
		if len(m.IPAssign) == 0 {
			v.errf("%s.masque.ip_assign: required with ip: a client cannot send until it has been told a source address", p)
		}
		if len(m.IPRoutes) == 0 {
			v.errf("%s.masque.ip_routes: required with ip: a client cannot send until it has been told where it may send", p)
		}
	}
	for i, a := range m.IPAssign {
		pfx, err := netip.ParsePrefix(a)
		if err != nil {
			v.errf("%s.masque.ip_assign[%d]: %q is not a CIDR", p, i, a)
			continue
		}
		if pfx.Addr().IsUnspecified() && pfx.Bits() == 0 {
			v.errf("%s.masque.ip_assign[%d]: %q would let a client claim any source address", p, i, a)
		}
	}
	for i, rt := range m.IPRoutes {
		pfx, err := netip.ParsePrefix(rt)
		if err != nil {
			v.errf("%s.masque.ip_routes[%d]: %q is not a CIDR", p, i, rt)
			continue
		}
		if pfx.Bits() == 0 {
			v.warnf("%s.masque.ip_routes[%d]: %q advertises the whole internet to clients of this tunnel; the tunnel device's own firewall is then the only thing narrowing it", p, i, rt)
		}
	}
	if m.IPDevice != "" && !m.IP {
		v.warnf("%s.masque.ip_device: set without ip: true, so nothing uses it", p)
	}
	if (m.UDP || m.IP) && f.Auth == nil {
		v.warnf("%s.masque: no auth is configured, so anyone who can reach this listener can send datagrams through it", p)
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

// privateFile refuses a key file anybody but its owner can read. A
// signing key that can impersonate every site to every client that
// trusts it is not a file to leave group- or world-readable, and the
// check belongs here as well as at load: the operator finds out from
// "xproxy check" rather than from a refused start.
func (v *validator) privateFile(p, path string) {
	if !v.fileCheck || !strings.HasPrefix(path, "/") {
		return
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return // already reported by file
	}
	if st.Mode().Perm()&0o077 != 0 {
		v.errf("%s: %s is readable by more than its owner (mode %04o); this key can impersonate every site to every client that trusts the CA", p, path, st.Mode().Perm())
	}
}

// placeholderRE matches template placeholders, replaced by a token
// before shape checks that templates would otherwise fail.
var placeholderRE = regexp.MustCompile(`\$\{[^}]*\}`)

// publicSuffixes is netutil's list, which DNS tunnel detection also
// reads: a suffix under which anyone can register is a suffix a
// wildcard origin must not cover, and a suffix a client's queries must
// not be grouped under.
var publicSuffixes = netutil.PublicSuffixes

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

// degradation validates the slow-lane levels.
func (v *validator) degradation(c *Config, routes map[string]bool) {
	d := c.Degradation
	if d == nil {
		return
	}
	const p = "degradation"
	if len(d.Levels) == 0 {
		v.errf("%s.levels: at least one level is required", p)
	}
	if len(d.Levels) > 64 {
		v.errf("%s.levels: at most 64 levels", p)
	}
	names := map[string]bool{}
	for i := range d.Levels {
		l := &d.Levels[i]
		q := fmt.Sprintf("%s.levels[%d]", p, i)
		if names[l.Name] {
			v.errf("%s.name: duplicate %q", q, l.Name)
		}
		names[l.Name] = true
		if l.BotScoreAt < 0 || l.BotScoreAt > 1000 {
			v.errf("%s.bot_score_at: must be between 0 and 1000", q)
		}
		for j, cidr := range l.ClientCIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				v.errf("%s.client_cidrs[%d]: %q is not a CIDR", q, j, cidr)
			}
		}
		for j, r := range l.Routes {
			if !routes[r] {
				v.errf("%s.routes[%d]: unknown route %q", q, j, r)
			}
		}
		v.methodList(q+".methods", l.Methods)
		if l.BytesPerSecond < 0 || (l.BytesPerSecond > 0 && l.BytesPerSecond < 256) {
			v.errf("%s.bytes_per_second: 0 to leave the body alone, or at least 256", q)
		}
		if l.BytesPerSecond > 1<<30 {
			v.errf("%s.bytes_per_second: at most 1 GiB/s", q)
		}
		if l.Delay < 0 || l.Delay > Duration(60*time.Second) {
			v.errf("%s.delay: must be between 0 and 60s", q)
		}
		if l.BytesPerSecond == 0 && l.Delay == 0 && !l.Close {
			v.errf("%s: a level that shapes nothing, delays nothing and closes nothing does nothing", q)
		}
		// A level with no condition at all applies to everything its
		// selectors admit, which is a choice; one with no selectors
		// either is almost certainly a mistake.
		if !l.Marked && l.BotScoreAt == 0 && len(l.ClientCIDRs) == 0 && len(l.Routes) == 0 && len(l.Methods) == 0 {
			v.errf("%s: names no condition and no selector, so it would degrade every request", q)
		}
		if l.BotScoreAt > 0 && !hasBotScoreFilter(c) {
			v.warnf("%s.bot_score_at is set and no bot_score filter is configured, so no request carries a score", q)
		}
	}
}

// hasBotScoreFilter reports whether any filter can produce a score.
func hasBotScoreFilter(c *Config) bool {
	for _, f := range c.Filters {
		if f.Kind == "bot_score" {
			return true
		}
	}
	return false
}

// fingerprintRE bounds a JA3 or JA4 entry: the character set both
// fingerprints use, and a trailing star for a JA4 prefix.
var fingerprintRE = regexp.MustCompile(`^[a-z0-9_]{4,128}\*?$`)

// handshake validates the pre-handshake refusal policy.
func (v *validator) handshake(c *Config) {
	h := c.Handshake
	if h == nil {
		return
	}
	const p = "handshake"
	if h.RefuseBanned && c.Bans == nil {
		v.errf("%s.refuse_banned: there is no bans section to refuse from", p)
	}
	seen := map[string]bool{}
	for i, f := range h.DenyFingerprints {
		q := fmt.Sprintf("%s.deny_fingerprints[%d]", p, i)
		value := f
		switch {
		case strings.HasPrefix(f, "ja4:"):
			value = strings.TrimPrefix(f, "ja4:")
		case strings.HasPrefix(f, "ja3:"):
			value = strings.TrimPrefix(f, "ja3:")
			if strings.HasSuffix(value, "*") {
				v.errf("%s: a JA3 fingerprint is a hash; only a JA4 entry may end in *", q)
			}
		}
		if !fingerprintRE.MatchString(value) {
			v.errf("%s: %q is not a JA3 or JA4 fingerprint", q, f)
		}
		if seen[f] {
			v.errf("%s: duplicate %q", q, f)
		}
		seen[f] = true
		if value == "*" || len(strings.TrimSuffix(value, "*")) < 4 {
			v.errf("%s: %q is too short to name a client", q, f)
		}
	}
	if len(h.DenyFingerprints) > 4096 {
		v.errf("%s.deny_fingerprints: at most 4096 entries", p)
	}
	tls := false
	for _, l := range c.Server.Listeners {
		if l.TLS != nil {
			tls = true
		}
	}
	if !tls && (h.RefuseBanned || len(h.DenyFingerprints) > 0) {
		v.warnf("handshake refuses clients before a TLS handshake, and no listener has a tls section: " +
			"what arrives on a plain listener is refused the ordinary way")
	}
	if h.RefuseBanned {
		v.warnf("handshake.refuse_banned makes a banned client's refusal invisible in the access log: " +
			"the connection never becomes a request. The security log records it as reason handshake when log is on")
	}
}

// honeytokenFields are the places a planted credential can be looked
// for. Bodies are deliberately absent: searching them means buffering
// every request, and a stolen credential is presented in the head.
var honeytokenFields = map[string]bool{"headers": true, "cookies": true, "query": true, "path": true}

// maxHoneytokenValues bounds the whole table. Every value is compared
// against a handful of fields of every request, so the table is a cost
// paid on the request path and not a list to grow without thinking.
const maxHoneytokenValues = 1024

// honeytokens validates the planted credentials. The rules exist to
// stop a token that would match ordinary traffic: a value short enough
// or common enough to appear in a real request turns a control with no
// false positives into one with nothing but.
func (v *validator) honeytokens(tokens []Honeytoken) {
	names := map[string]bool{}
	seen := map[string]string{}
	total := 0
	for i := range tokens {
		h := &tokens[i]
		p := fmt.Sprintf("honeytokens[%d]", i)
		if !patchIDRE.MatchString(h.Name) {
			v.errf("%s.name: %q must be 1 to 63 characters of a-z, 0-9, dot, underscore or hyphen", p, h.Name)
		} else if names[h.Name] {
			v.errf("%s.name: duplicate %q", p, h.Name)
		}
		names[h.Name] = true
		if len(h.Description) > 512 {
			v.errf("%s.description: at most 512 characters", p)
		}
		if len(h.Values) == 0 && h.ValuesFile == "" {
			v.errf("%s: values or values_file is required", p)
		}
		if h.ValuesFile != "" {
			v.file(p+".values_file", h.ValuesFile)
		}
		min := 8
		if h.Match == "contains" {
			// A short value found anywhere in a header is a false
			// positive waiting to happen; a token matched that way has
			// to be long enough to be nobody else's.
			min = 16
		}
		for j, val := range h.Values {
			q := fmt.Sprintf("%s.values[%d]", p, j)
			switch {
			case len(val) < min:
				v.errf("%s: a planted value must be at least %d characters, or it will match real traffic", q, min)
			case len(val) > 512:
				v.errf("%s: at most 512 characters", q)
			case strings.ContainsAny(val, " \t\r\n\x00"):
				v.errf("%s: must not contain whitespace or a NUL", q)
			}
			if other, dup := seen[val]; dup {
				v.errf("%s: the same value is planted as %q", q, other)
			}
			seen[val] = h.Name
			total++
		}
		if total > maxHoneytokenValues {
			v.errf("%s: more than %d planted values in total", p, maxHoneytokenValues)
		}
		for j, f := range h.In {
			if !honeytokenFields[f] {
				v.errf("%s.in[%d]: %q is not headers, cookies, query or path", p, j, f)
			}
		}
		for j, n := range h.Headers {
			if !headerNameOK(n) {
				v.errf("%s.headers[%d]: %q is not a header name", p, j, n)
			}
		}
		if len(h.Headers) > 0 && !slices.Contains(h.In, "headers") {
			v.errf("%s.headers: listed without \"headers\" in in", p)
		}
		switch h.Match {
		case "exact", "contains":
		default:
			v.errf("%s.match: must be exact or contains", p)
		}
		switch h.Action {
		case "block", "log":
		default:
			v.errf("%s.action: must be block or log", p)
		}
		if h.Status < 400 || h.Status > 599 {
			v.errf("%s.status: must be a 4xx or 5xx status", p)
		}
		if h.MarkFor() < 0 || h.MarkFor() > 720*time.Hour {
			v.errf("%s.mark: must be between 0 and 720h", p)
		}
		if h.Action == "log" && h.IsEnabled() {
			v.warnf("%s is in log mode: a request presenting a planted credential is recorded and served. "+
				"Nothing legitimate sends one, so this is a setting to leave once the token is proven quiet", p)
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

// ftpListener validates a kind: ftp listener.
// vncListener checks a VNC gateway.
func (v *validator) vncListener(p string, c *VNCListener, hasTLS bool) {
	if c.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	mediated, wantsTLS, wantsPassword := false, false, false
	namesUser, wantsRSA := false, false
	for _, name := range c.SecurityTypes {
		n := strings.ToLower(strings.TrimSpace(name))
		t, ok := rfb.SecurityByName(n)
		if !ok {
			v.errf("%s.security_types: %q is not a security type this proxy can name; see docs/CONFIG.md", p, name)
			continue
		}
		switch {
		case rfb.Mediated[t]:
			mediated = true
			if t == rfb.SecVeNCrypt || t == rfb.SecTLS {
				wantsTLS = true
			}
			if t == rfb.SecVNCAuth {
				wantsPassword = true
			}
		case rfb.Reimplemented[t]:
			mediated = true
			if rfb.RSAAESFamily[t] {
				wantsRSA = true
			}
			v.warnf("%s.security_types: %s is a vendor's own type, reimplemented here from published reverse engineering rather than from a specification, so interoperability with the vendor's own software is not guaranteed: %s. See docs/CONFIG.md", p, n, reimplementedNote[t])
		case rfb.Proprietary[t]:
			v.errf("%s.security_types: %q is a vendor's own type with no published specification and none reimplemented here, so this gateway cannot sit in the middle of it; see docs/CONFIG.md for what to do instead", p, n)
		default:
			v.errf("%s.security_types: %q is not mediated by this gateway", p, n)
		}
		if rfb.NamesAUser[t] {
			namesUser = true
		}
		if n == "tls" {
			v.warnf("%s.security_types: the tls type is anonymous Diffie-Hellman with no certificate to check, so it stops a reader and not an active attacker; vencrypt with an x509 subtype is the one to use", p)
		}
	}
	if !mediated {
		v.errf("%s.security_types: no type left that this gateway can complete, so no client could connect", p)
	}
	if wantsTLS && !hasTLS {
		v.errf("%s.security_types: vencrypt and tls need the listener's tls section, since there is no certificate to present without one", p)
	}
	switch c.TLSMode {
	case "negotiated":
		if hasTLS && !wantsTLS {
			v.warnf("%s.tls_mode: negotiated presents the certificate inside RFB, but no security type uses one; set tls_mode: wrap for a socket that is TLS from the first byte, or drop the tls section", p)
		}
	case "wrap":
		if !hasTLS {
			v.errf("%s.tls_mode: wrap needs the listener's tls section: there is no certificate to wrap the socket with", p)
		}
		if wantsTLS {
			v.errf("%s.tls_mode: wrap and the vencrypt or tls security type are two encryptions of the same leg, and a port can only be one of them: the first byte a client sends is either a TLS record or an RFB version string. Use one listener for each", p)
		}
	default:
		v.errf("%s.tls_mode: must be negotiated or wrap", p)
	}
	if wantsPassword && c.PasswordFile == "" {
		v.errf("%s.password_file: required with the vncauth security type; a challenge nobody can answer is not authentication", p)
	}
	if c.PasswordFile != "" {
		v.file(p+".password_file", c.PasswordFile)
	}
	if c.UpstreamPasswordFile != "" {
		v.file(p+".upstream_password_file", c.UpstreamPasswordFile)
	}
	for _, name := range c.VeNCryptSubtypes {
		n := strings.ToLower(strings.TrimSpace(name))
		if _, ok := rfb.SubtypeByName(n); !ok {
			v.errf("%s.vencrypt_subtypes: %q is not a VeNCrypt subtype", p, name)
			continue
		}
		if n == "plain" {
			v.errf("%s.vencrypt_subtypes: the bare plain subtype sends the credential with no TLS around it; use x509-plain", p)
		}
		if strings.HasPrefix(n, "tls-") {
			v.warnf("%s.vencrypt_subtypes: %s is anonymous TLS with no certificate to check; the x509 subtypes are the ones that authenticate the gateway", p, n)
		}
	}
	if c.UpstreamSecurity != "" {
		t, ok := rfb.SecurityByName(strings.ToLower(strings.TrimSpace(c.UpstreamSecurity)))
		if !ok || (!rfb.Mediated[t] && !rfb.Reimplemented[t]) {
			v.errf("%s.upstream_security: %q is not a type this gateway can use towards a target", p, c.UpstreamSecurity)
		}
	}
	switch c.UpstreamTLSMode {
	case "none", "vencrypt":
	default:
		v.errf("%s.upstream_tls_mode: must be none or vencrypt", p)
	}
	if c.MFA != nil {
		v.mfaPolicy(p+".mfa", c.MFA)
		// A factor needs a name to look an enrolment up by, and RFB
		// carries one in only two places.
		if !hasPlain(c.VeNCryptSubtypes) && !namesUser {
			v.errf("%s.mfa: needs a security type whose credential carries a user name -- a plain VeNCrypt subtype (x509-plain), or mslogon2 -- since a DES challenge proves a shared desktop password and says nothing about who holds it", p)
		}
	}
	if up, ok := rfb.SecurityByName(strings.ToLower(strings.TrimSpace(c.UpstreamSecurity))); ok && rfb.RSAAESFamily[up] {
		wantsRSA = true
		if c.UpstreamRSAFingerprint == "" {
			v.errf("%s.upstream_rsa_fingerprint: required to use rsa-aes towards a target: nothing else authenticates the far end of that exchange, and there is nobody at a proxy to show a fingerprint to. The key a target offers is printed in the log, which is where this comes from", p)
		}
	}
	if wantsRSA && c.RSAKeyFile == "" {
		v.errf("%s.rsa_key_file: required with the rsa-aes security types, which identify each end by an RSA key of its own", p)
	}
	if c.RSAKeyFile != "" {
		v.file(p+".rsa_key_file", c.RSAKeyFile)
	}
	// A named credential towards the target needs both halves of one.
	if wantsUpstreamName(c) {
		if c.UpstreamUser == "" {
			v.errf("%s.upstream_user: required to use %s towards a target, which sends a name as well as a password", p, c.UpstreamSecurity)
		}
		if c.UpstreamPasswordFile == "" {
			v.errf("%s.upstream_password_file: required to use %s towards a target", p, c.UpstreamSecurity)
		}
	}
	if c.SSH != nil {
		q := p + ".ssh"
		if c.SSH.User == "" {
			v.errf("%s.user: required", q)
		}
		if c.SSH.KeyFile == "" {
			v.errf("%s.key_file: required", q)
		} else {
			v.file(q+".key_file", c.SSH.KeyFile)
		}
		if c.SSH.KnownHosts == "" {
			v.errf("%s.known_hosts: required; an unpinned tunnel authenticates nothing, which is the whole reason for the tunnel", q)
		} else {
			v.file(q+".known_hosts", c.SSH.KnownHosts)
		}
	}
	if c.Recording != nil {
		v.sessionRecording(p+".recording", c.Recording, nil)
	}
	if c.MaxConnections < 1 {
		v.errf("%s.max_connections: must be positive", p)
	}
	for i, cidr := range c.AllowClients {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, cidr, err)
		}
	}
}

// telnetListener checks a telnet gateway.
func (v *validator) telnetListener(p string, c *TelnetListener, hasTLS bool) {
	if c.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	if !hasTLS {
		v.warnf("%s: telnet carries the session, every password typed into the target's own login, and the second factor if one is asked for, in clear; add a tls section (telnets) or keep this listener off any network a stranger can reach", p)
	}
	seen := map[string]bool{}
	for _, list := range [][]string{c.AllowOptions, c.DenyOptions} {
		for i, name := range list {
			n := strings.ToLower(strings.TrimSpace(name))
			if _, ok := telnet.OptionByName(n); !ok {
				v.errf("%s: %q is not an option this proxy can name, so no policy can be written about it; see docs/CONFIG.md for the list", p, name)
				continue
			}
			if seen[n] && i >= 0 {
				continue
			}
			seen[n] = true
		}
	}
	// The options that carry something to the target rather than
	// describing the terminal are worth saying out loud.
	for _, risky := range []struct{ name, why string }{
		{"environ", "carries variables of the client's choosing to the target, which is how a login shell is given a different PATH"},
		{"new-environ", "carries variables of the client's choosing to the target, which is how a login shell is given a different PATH"},
		{"x-display", "names an X display the target will try to reach, which is a connection back out of the estate"},
		{"authentication", "is negotiated differently by every implementation that has it, and this proxy relays it without understanding it"},
		{"encryption", "would encrypt the session end to end, which is a session this proxy can no longer record or hold to a policy"},
	} {
		for _, name := range c.AllowOptions {
			if strings.EqualFold(strings.TrimSpace(name), risky.name) && !hasDeny(c.DenyOptions, risky.name) {
				v.warnf("%s.allow_options: %s %s", p, risky.name, risky.why)
			}
		}
	}
	if c.MaxSubnegotiation < 64 || c.MaxSubnegotiation > 1<<20 {
		v.errf("%s.max_subnegotiation: must be 64..1048576", p)
	}
	if c.MaxConnections < 1 {
		v.errf("%s.max_connections: must be positive", p)
	}
	if c.Recording != nil {
		v.sessionRecording(p+".recording", c.Recording, nil)
	}
	if c.MFA != nil {
		v.mfaPolicy(p+".mfa", c.MFA)
	}
	for i, cidr := range c.AllowClients {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, cidr, err)
		}
	}
}

// hasDeny reports whether a name is in the deny list.
func hasDeny(deny []string, name string) bool {
	for _, d := range deny {
		if strings.EqualFold(strings.TrimSpace(d), name) {
			return true
		}
	}
	return false
}

func (v *validator) ftpListener(p string, f *FTPListener, hasTLS bool) {
	if f.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	switch f.TLSMode {
	case "none":
	case "starttls", "implicit":
		if !hasTLS {
			v.errf("%s.tls_mode: %q needs the listener's tls section", p, f.TLSMode)
		}
	default:
		v.errf("%s.tls_mode: must be none, starttls or implicit", p)
	}
	if f.TLSMode == "none" && hasTLS {
		v.warnf("%s.tls_mode: none with a tls section, so the certificate is never used", p)
	}
	if !f.RequireTLS && f.TLSMode != "none" {
		v.warnf("%s.require_tls: false where TLS is reachable, so a client can send the password in clear", p)
	}
	switch f.UpstreamTLSMode {
	case "none", "starttls", "implicit":
	default:
		v.errf("%s.upstream_tls_mode: must be none, starttls or implicit", p)
	}
	if f.UpstreamTLSMode != "none" {
		v.upstreamTLS(p+".upstream_tls", f.UpstreamTLS)
	}
	seen := map[string]bool{}
	for i, c := range f.Commands {
		verb := strings.ToUpper(strings.TrimSpace(c))
		if !ftp.Known[verb] {
			v.errf("%s.commands[%d]: %q is not a command this proxy can read the effect of", p, i, c)
		}
		if seen[verb] {
			v.errf("%s.commands[%d]: %q listed twice", p, i, c)
		}
		seen[verb] = true
	}
	if len(f.Commands) > 0 {
		for _, need := range []string{"USER", "QUIT"} {
			if !seen[need] {
				v.errf("%s.commands: %s is required; without it no session can %s", p, need,
					map[string]string{"USER": "log in", "QUIT": "end cleanly"}[need])
			}
		}
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"allow_paths", f.AllowPaths}, {"deny_paths", f.DenyPaths}} {
		for i, pattern := range l.list {
			if pattern == "" || strings.ContainsRune(pattern, 0) {
				v.errf("%s.%s[%d]: must be a path", p, l.key, i)
			}
			if strings.Contains(pattern, "{") && !strings.Contains(pattern, "{user}") {
				v.errf("%s.%s[%d]: {user} is the only substitution here", p, l.key, i)
			}
		}
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"allow_extensions", f.AllowExtensions}, {"deny_extensions", f.DenyExtensions}} {
		for i, e := range l.list {
			if e == "" || strings.ContainsAny(e, "./\\*?") {
				v.errf("%s.%s[%d]: %q is an extension, without a dot and without a glob", p, l.key, i, e)
			}
		}
	}
	if f.MaxFileBytes < 0 {
		v.errf("%s.max_file_bytes: must not be negative", p)
	}
	if f.YARA != nil {
		v.yaraPolicy(p+".yara", f.YARA)
	}
	if f.AllowActive {
		v.warnf("%s.allow_active: PORT and EPRT ask the proxy to connect to an address the client names; it is refused unless the address is the client's own, and that check is all that stands between this and the bounce attack", p)
	}
	if f.DataAddress != "" {
		if _, err := netip.ParseAddr(f.DataAddress); err != nil {
			v.errf("%s.data_address: %q is not an address", p, f.DataAddress)
		}
	}
	if f.DataPorts != "" && f.DataPorts != "0-0" {
		lo, hi, ok := strings.Cut(f.DataPorts, "-")
		l, errLo := strconv.Atoi(strings.TrimSpace(lo))
		h, errHi := strconv.Atoi(strings.TrimSpace(hi))
		switch {
		case !ok || errLo != nil || errHi != nil:
			v.errf(`%s.data_ports: must be written "low-high"`, p)
		case l < 1 || h > 65535 || l > h:
			v.errf("%s.data_ports: must be 1..65535 with low no higher than high", p)
		case h-l < 8:
			v.warnf("%s.data_ports: %d ports for concurrent transfers, which is a transfer refused as soon as they are all in use", p, h-l+1)
		}
	}
	if f.DataTimeout <= 0 {
		v.errf("%s.data_timeout: must be positive", p)
	}
	if f.MaxCommandLine < 512 || f.MaxCommandLine > 1<<20 {
		v.errf("%s.max_command_line: must be 512..1048576", p)
	}
	if f.MaxErrors < 1 {
		v.errf("%s.max_errors: must be at least 1", p)
	}
	if f.MaxConnections < 1 {
		v.errf("%s.max_connections: must be at least 1", p)
	}
	for i, c := range f.AllowClients {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, c, err)
		}
	}
	if f.Recording != nil {
		v.sessionRecording(p+".recording", f.Recording, nil)
	}
	if f.MFA != nil {
		v.mfaPolicy(p+".mfa", f.MFA)
		if f.TLSMode == "none" {
			v.warnf("%s.mfa: without tls_mode the code crosses the network in clear beside the password it is meant to back up", p)
		}
	}
	if f.ICAP != nil {
		v.transferICAP(p+".icap", f.ICAP, f.ReadOnly, true)
	}
}

// syslogListener validates a kind: syslog listener.
func (v *validator) syslogListener(p string, g *SyslogListener, hasTLS bool) {
	if g.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	switch g.Framing {
	case "octet_counting", "non_transparent", "auto":
	default:
		v.errf("%s.framing: must be octet_counting, non_transparent or auto", p)
	}
	switch g.UpstreamFraming {
	case "octet_counting":
	case "non_transparent":
		v.warnf("%s.upstream_framing: non_transparent delimits on line endings, which is the framing a message's own text can be mistaken for; octet_counting cannot be", p)
	default:
		v.errf("%s.upstream_framing: must be octet_counting or non_transparent", p)
	}
	switch g.TLSMode {
	case "none":
		if hasTLS {
			v.warnf("%s.tls_mode: none with a tls section, so the certificate is never used", p)
		}
	case "implicit":
		if !hasTLS {
			v.errf("%s.tls_mode: implicit needs the listener's tls section", p)
		}
	default:
		v.errf("%s.tls_mode: must be none or implicit", p)
	}
	switch g.UpstreamTLSMode {
	case "none", "implicit":
	default:
		v.errf("%s.upstream_tls_mode: must be none or implicit", p)
	}
	if g.UpstreamTLSMode != "none" {
		v.upstreamTLS(p+".upstream_tls", g.UpstreamTLS)
	}
	switch g.Hostname {
	case "keep":
		v.warnf("%s.hostname: keep takes the sender's word for which machine a record came from, which nothing checks", p)
	case "observed", "annotate":
	default:
		v.errf("%s.hostname: must be keep, observed or annotate", p)
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"allow_facilities", g.AllowFacilities}, {"deny_facilities", g.DenyFacilities}} {
		for i, f := range l.list {
			if _, ok := syslog.FacilityNumber(f); !ok {
				v.errf("%s.%s[%d]: %q is not a facility", p, l.key, i, f)
			}
		}
	}
	for _, a := range g.AllowFacilities {
		for _, d := range g.DenyFacilities {
			if strings.EqualFold(a, d) {
				v.errf("%s: %q is in allow_facilities and deny_facilities; the deny list wins, so the allow entry says nothing", p, a)
			}
		}
	}
	if g.MinSeverity != "" {
		if _, ok := syslog.SeverityNumber(g.MinSeverity); !ok {
			v.errf("%s.min_severity: %q is not a severity", p, g.MinSeverity)
		}
	}
	for i, c := range g.AllowSenders {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_senders[%d]: %q is not a CIDR: %v", p, i, c, err)
		}
	}
	udp := g.UDP == nil || *g.UDP
	if udp && len(g.AllowSenders) == 0 {
		v.warnf("%s.allow_senders: empty with udp on, so anything that can reach the port can write records; on UDP the sender's address is the only authentication there is", p)
	}
	for i, pat := range g.DenyPatterns {
		if _, err := regexp.Compile(pat); err != nil {
			v.errf("%s.deny_patterns[%d]: %v", p, i, err)
		}
	}
	names := map[string]bool{}
	for i := range g.Redact {
		r := &g.Redact[i]
		if r.Name == "" {
			v.errf("%s.redact[%d].name: required; it is what the added structured data names", p, i)
		} else if names[r.Name] {
			v.errf("%s.redact[%d].name: %q is used twice", p, i, r.Name)
		}
		names[r.Name] = true
		if r.Pattern == "" {
			v.errf("%s.redact[%d].pattern: required", p, i)
		} else if _, err := regexp.Compile(r.Pattern); err != nil {
			v.errf("%s.redact[%d].pattern: %v", p, i, err)
		}
	}
	if g.MaxMessageBytes < 480 || g.MaxMessageBytes > 1<<20 {
		// RFC 5426 section 3.2: every receiver must take 480 octets.
		v.errf("%s.max_message_bytes: must be 480..1048576", p)
	}
	if g.RateLimit < 0 || g.RateBurst < 0 {
		v.errf("%s.rate_limit: must not be negative", p)
	}
	if g.RateLimit == 0 && udp {
		v.warnf("%s.rate_limit: unset with udp on, so one sender can fill the collector and push older records out of whatever window it keeps", p)
	}
	if g.MaxSenders < 1 || g.MaxSenders > 1<<20 {
		v.errf("%s.max_senders: must be 1..1048576", p)
	}
	if g.MaxConnections < 1 {
		v.errf("%s.max_connections: must be at least 1", p)
	}
	if g.Queue < 1 || g.Queue > 1<<20 {
		v.errf("%s.queue: must be 1..1048576", p)
	}
}

// reimplementedNote says what one of the reimplemented types is
// actually worth, which is the part an operator needs and the name
// does not say.
var reimplementedNote = map[uint8]string{
	rfb.SecMSLogon2:  "the type is Diffie-Hellman over 64 bits with the shared secret used directly as a DES key, so the credential inside it is protected against nobody. Put a tls_mode: wrap or ssh leg around it",
	rfb.SecRSAAES:    "the cryptography is RSA with AES-128 in EAX and SHA-1, which is sound as far as it goes -- what is reconstructed here is the framing rather than the cipher",
	rfb.SecRSAAESne:  "the handshake is RSA with AES-128 in EAX, and the session after it is in clear. rsa-aes or rsa-aes-256 is the one to use unless something in the estate cannot",
	rfb.SecRSAAES256: "the cryptography is RSA with AES-256 in EAX and SHA-256 -- what is reconstructed here is the framing rather than the cipher",
	rfb.SecTight:     "the type is a negotiation rather than a cipher: it settles on one of the ordinary authentications, which is what actually protects anything, and this gateway refuses its tunnels and passes none of its extensions through",
	rfb.SecARD:       "Apple's own servers offer a 512 bit prime, the key is MD5 of the shared secret and the credential is encrypted in ECB, so the credential is protected against very little. Put a tls_mode: wrap or ssh leg around it",
}

// wantsUpstreamName says whether the target's leg may use a security
// type that sends a user name as well as a password, which is what
// makes upstream_user necessary.
func wantsUpstreamName(c *VNCListener) bool {
	n := strings.ToLower(strings.TrimSpace(c.UpstreamSecurity))
	if n == "" {
		return false
	}
	t, ok := rfb.SecurityByName(n)
	return ok && rfb.NamesAUser[t]
}

// rdpListener checks a Remote Desktop gateway.
func (v *validator) rdpListener(p string, c *RDPListener, hasTLS bool) {
	if c.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	wantsTLS, wantsLegacy := false, false
	for _, name := range c.Security {
		n := strings.ToLower(strings.TrimSpace(name))
		switch n {
		case "tls":
			wantsTLS = true
		case "rdp":
			// The protocol's own encryption, offered to clients that
			// speak nothing else. The certificate is signed with the
			// key Microsoft published in MS-RDPBCGR 5.3.3.1.1, which
			// is the only thing a client can check -- and since that
			// key is public, the check proves nothing. So a session
			// on this leg is protected by the network it runs over
			// and not by the protocol.
			wantsLegacy = true
			v.warnf("%s.security: rdp is the protocol's own encryption, which authenticates nothing to a client -- the key the certificate is signed with was published by Microsoft -- and is RC4 under MD5 and SHA-1. Offer tls to any client that can use it, and keep this listener on a network you trust", p)
		case "nla":
			v.errf("%s.security: nla cannot be offered to clients by this gateway: checking a client's network level authentication needs that person's own password, which is the one credential a gateway should not hold. A client that asks for it is answered with tls, which is the arrangement every remote desktop gateway uses; see docs/CONFIG.md", p)
		default:
			v.errf("%s.security: %q is not a security protocol this gateway offers; use tls or rdp", p, name)
		}
	}
	if !wantsTLS && !wantsLegacy {
		v.errf("%s.security: no protocol left that a client could use", p)
	}
	if wantsTLS && !hasTLS {
		v.errf("%s.security: tls needs the listener's tls section, since there is no certificate to present without one", p)
	}
	switch strings.ToLower(strings.TrimSpace(c.UpstreamSecurity)) {
	case "tls":
	case "nla":
		if c.UpstreamUser == "" || c.UpstreamPasswordFile == "" {
			// The exchange happens inside the tunnel before the
			// connection sequence starts, which is before the person
			// at the other end has sent anything: there is no
			// credential to pass through, only one to configure.
			v.errf("%s.upstream_security: nla towards a desktop needs upstream_user and upstream_password_file, since the credential is proved before the person's own has been sent", p)
		}
	case "rdp":
		// The protocol's own encryption: RC4 under keys from an
		// exchange this gateway performs itself. It protects the
		// session against very little -- see docs/CONFIG.md -- and it
		// is here for desktops that speak nothing else.
		v.warnf("%s.upstream_security: rdp is the protocol's own encryption, which is RC4 under MD5 and SHA-1 with a key from a certificate nothing can check. Use tls or nla where the desktop offers one; this is for equipment that does not", p)
	default:
		v.errf("%s.upstream_security: must be tls, nla or rdp", p)
	}
	if c.UpstreamPasswordFile != "" {
		v.file(p+".upstream_password_file", c.UpstreamPasswordFile)
	}
	if (c.UpstreamUser == "") != (c.UpstreamPasswordFile == "") {
		v.errf("%s.upstream_user: name it with upstream_password_file or with neither; half a credential opens nothing", p)
	}
	hasRDPDR := false
	if c.Channels != nil {
		for _, name := range c.Channels.Allow {
			n := strings.ToLower(strings.TrimSpace(name))
			if n == "" {
				v.errf("%s.channels.allow: an empty channel name", p)
				continue
			}
			if len(n) >= rdp.ChannelNameLen {
				v.errf("%s.channels.allow: %q is over %d characters, which is more than a channel name can be", p, name, rdp.ChannelNameLen-1)
			}
			if n == rdp.ChannelDeviceRedirection {
				hasRDPDR = true
			}
			if n == rdp.ChannelDynamic {
				v.warnf("%s.channels.allow: %s carries dynamic channels, whose contents this gateway does not decide -- audio, cameras, and on some clients redirection that the devices policy would otherwise have refused. Allow it only where something needs it", p, rdp.ChannelDynamic)
			}
		}
	}
	if c.Devices != nil {
		for _, name := range c.Devices.Allow {
			if _, ok := rdp.DeviceTypeByName(name); !ok {
				v.errf("%s.devices.allow: %q is not a device kind; use drive, printer, serial, parallel or smartcard", p, name)
			}
		}
		if len(c.Devices.Allow) > 0 && !hasRDPDR {
			v.errf("%s.devices.allow: names device kinds while the %s channel is not allowed, so nothing could announce one. Allow the channel or drop this section", p, rdp.ChannelDeviceRedirection)
		}
	}
	if c.Recording != nil {
		v.sessionRecording(p+".recording", c.Recording, nil)
	}
	if c.MFA != nil {
		v.mfaPolicy(p+".mfa", c.MFA)
	}
	if c.MaxConnections < 1 {
		v.errf("%s.max_connections: must be positive", p)
	}
	for i, cidr := range c.AllowClients {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, cidr, err)
		}
	}
}
