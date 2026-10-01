package config

import (
	"encoding/hex"
	amqpwire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/assets"
	bacnetwire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/correlate"
	dhcpwire "github.com/rom/xproxy/internal/dhcp"
	"github.com/rom/xproxy/internal/dhcp6"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/expr"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/fipsmode"
	"github.com/rom/xproxy/internal/ftp"
	"github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/keysource"
	ldapwire "github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/listener"
	mmswire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/modbus"
	mqttwire "github.com/rom/xproxy/internal/mqtt"
	mysqlwire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/numrange"
	opcuawire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/packs"
	pgwire "github.com/rom/xproxy/internal/pgwire"
	"github.com/rom/xproxy/internal/rdp"
	"github.com/rom/xproxy/internal/recenc"
	respwire "github.com/rom/xproxy/internal/respwire"
	"github.com/rom/xproxy/internal/rfb"
	s7wire "github.com/rom/xproxy/internal/s7"
	snmpwire "github.com/rom/xproxy/internal/snmp"
	"github.com/rom/xproxy/internal/syslog"
	tdswire "github.com/rom/xproxy/internal/tdswire"
	"github.com/rom/xproxy/internal/telnet"
	tftpwire "github.com/rom/xproxy/internal/tftp"
	"github.com/rom/xproxy/internal/tmpl"
	"github.com/rom/xproxy/internal/transparent"
	"github.com/rom/xproxy/internal/yara"
	"mime"
	"path"
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
	// clientCertAsked is set when any listener asks for a client
	// certificate, so a certificate binding that can never fire is
	// pointed out. Listeners are validated before the JWT providers.
	clientCertAsked bool
	// trustedProxies is set when trusted_proxies names anything, which is
	// what decides whether a forwarded client certificate is ever read.
	trustedProxies bool
	// hasVault is set when secrets.vault is configured, so that a vault
	// reference anywhere in the file is told at load rather than at the
	// first handshake that needs the key. It is set before any section
	// that may carry a reference is checked.
	hasVault bool
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
	// Key custody first: v.server below checks the certificates, and a
	// certificate whose key is a vault reference has to be able to see that
	// a vault is configured.
	v.hasVault = c.Secrets != nil && c.Secrets.Vault != nil
	v.secrets(c)
	v.fips(c)
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

	v.trustedProxies = len(c.TrustedProxies) > 0

	// Set once, before anything reads it: a configuration with a
	// challenge section and no rate limits used to leave this false, so
	// a later check would say there was nothing to challenge with.
	v.hasChallenge = c.Challenge != nil

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
	if p := c.Policy; p != nil {
		switch p.Mode {
		case "", "enforce":
		case "shadow":
			v.warnf("policy.mode is shadow, so every listener that does not say otherwise evaluates its policy and refuses nothing for it: read xproxyctl policy report, then turn enforcement on. Authentication, bans, rate limits, bounds and malformed input are still refused")
		default:
			v.errf("policy.mode: must be enforce or shadow")
		}
		if p.MaxReasons < 0 || p.MaxReasons > 65536 {
			v.errf("policy.max_reasons: must be between 0 and 65536")
		}
	}
	if c.ThreatIntel != nil {
		v.threatIntel(c.ThreatIntel, c)
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
	if c.AssetInventory != nil {
		v.assetInventory(c.AssetInventory)
	}
	if c.Correlation != nil {
		v.correlation(c)
	}
	if c.Packs != nil {
		v.packs(c.Packs)
	}
	if c.SCIM != nil {
		v.scim(c)
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
	v.access(c)
	v.authorization(c)
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
		if m := c.Server.Listeners[i].Modbus; m != nil {
			if m.Upstream != "" && !upstreams[m.Upstream] {
				v.errf("server.listeners[%d].modbus.upstream: unknown upstream %q", i, m.Upstream)
			}
			for j, r := range m.Routes {
				if r.Upstream != "" && !upstreams[r.Upstream] {
					v.errf("server.listeners[%d].modbus.routes[%d].upstream: unknown upstream %q", i, j, r.Upstream)
				}
			}
		}
		if n := c.Server.Listeners[i].NTP; n != nil && n.Upstream != "" {
			if !upstreams[n.Upstream] {
				v.errf("server.listeners[%d].ntp.upstream: unknown upstream %q", i, n.Upstream)
			} else if endpoints := endpointsOf(c, n.Upstream); endpoints > 0 && endpoints < 3 {
				// Two sources can disagree and neither can be shown to
				// be the wrong one. Three is where a relay can say which
				// clock to stop believing, which is the whole reason for
				// comparing them.
				v.warnf("server.listeners[%d].ntp.upstream %q has %d server(s): with fewer than three, a disagreement can be reported but the wrong clock cannot be identified",
					i, n.Upstream, endpoints)
			}
		}
		if k := c.Server.Listeners[i].NTSKE; k != nil && k.Upstream != "" && !upstreams[k.Upstream] {
			v.errf("server.listeners[%d].ntske.upstream: unknown upstream %q", i, k.Upstream)
		}
		if n := c.Server.Listeners[i].NTP; n != nil && n.NTS != nil && n.NTS.KeyListener != "" {
			// The two halves of NTS are two listeners, and termination only
			// works when the one spending the cookies names the one that issued
			// them. A name that is not a terminating ntske listener would be a
			// time listener that verified nothing and said it had.
			v.ntsKeyListener(fmt.Sprintf("server.listeners[%d].ntp.nts", i), c, n.NTS.KeyListener)
		}
		if m := c.Server.Listeners[i].DHCP6; m != nil && m.Upstream != "" && !upstreams[m.Upstream] {
			v.errf("server.listeners[%d].dhcp6.upstream: unknown upstream %q", i, m.Upstream)
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
		switch c.Routes[i].ClientPriority {
		case "", "ignore", "lower":
		default:
			v.errf("routes[%d].client_priority: must be ignore or lower", i)
		}
		switch c.Routes[i].EarlyHints {
		case "", "pass", "strip":
		default:
			v.errf("routes[%d].early_hints: must be pass or strip", i)
		}
		switch c.Routes[i].EarlyData {
		case "", "safe_methods", "allow", "reject":
		default:
			v.errf("routes[%d].early_data: must be safe_methods, allow or reject", i)
		}
		if c.Routes[i].EarlyData == "allow" && len(c.TrustedProxies) > 0 {
			v.warnf("routes[%d].early_data: allow accepts a request that can be replayed by whoever captured it; only the route knows whether that is safe", i)
		}
		if rg := c.Routes[i].Ranges; rg != nil {
			switch rg.Action {
			case "", "ignore", "refuse":
			default:
				v.errf("routes[%d].ranges.action: must be ignore or refuse", i)
			}
			if rg.MaxRanges < 0 || rg.MaxRanges > 1024 {
				v.errf("routes[%d].ranges.max_ranges: must be between 0 (the default of 4) and 1024", i)
			}
			if rg.Coalesce != nil && !*rg.Coalesce {
				v.warnf("routes[%d].ranges.coalesce: off, so a set of overlapping ranges is counted as it arrived rather than as the bytes it asks for; RFC 9110 section 14.2 allows the merge, and without it a client that overlaps its ranges is refused for asking twice for the same bytes", i)
			}
		}
		switch c.Routes[i].Trailers {
		case "", "pass", "strip":
		default:
			v.errf("routes[%d].trailers: must be pass or strip", i)
		}
		if c.Routes[i].Trailers == "strip" && c.Routes[i].GRPC != nil {
			v.errf("routes[%d].trailers: gRPC carries its status in the trailers, so they cannot be stripped", i)
		}
		if c.Routes[i].ClientPriority == "lower" && c.Shedding == nil {
			v.warnf("routes[%d].client_priority: nothing sheds without server.shedding, so a client's urgency changes nothing", i)
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
		case "modbus":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: a modbus listener takes only address, modbus and tls", p)
			}
			if ln.Modbus == nil {
				v.errf("%s.modbus: required for kind modbus", p)
			} else {
				v.modbusListener(p+".modbus", ln.Modbus, ln.TLS != nil)
			}
		case "snmp":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: an snmp listener takes only address, snmp and tls", p)
			}
			if ln.SNMP == nil {
				v.errf("%s.snmp: required for kind snmp", p)
			} else {
				v.snmpListener(p+".snmp", ln.SNMP, ln.TLS)
			}
		case "ldap":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: an ldap listener takes only address, ldap and tls", p)
			}
			if ln.LDAP == nil {
				v.errf("%s.ldap: required for kind ldap", p)
			} else {
				v.ldapListener(p+".ldap", ln.LDAP, ln.TLS != nil)
			}
		case "dhcp":
			// No tls section: DHCP is UDP and has no transport security of
			// any kind, so a listener carrying a certificate would be
			// promising something the protocol cannot do.
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: a dhcp listener takes only address and dhcp: the protocol is UDP and has no TLS", p)
			}
			if ln.DHCP == nil {
				v.errf("%s.dhcp: required for kind dhcp", p)
			} else {
				v.dhcpListener(p+".dhcp", ln.DHCP)
			}
		case "dhcp6":
			// No tls section, for the same reason as dhcp: the protocol is
			// UDP and has no transport security of any kind.
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: a dhcp6 listener takes only address and dhcp6: the protocol is UDP and has no TLS", p)
			}
			if ln.DHCP6 == nil {
				v.errf("%s.dhcp6: required for kind dhcp6", p)
			} else {
				v.dhcp6Listener(p+".dhcp6", ln.DHCP6, ln.Address)
			}
		case "coap":
			// A tls section is allowed and means DTLS: RFC 7252 s9 puts
			// CoAP inside DTLS on 5684, and a listener without one is
			// NoSec, which is what most of the field runs.
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: a coap listener takes only address, coap and tls", p)
			}
			if ln.CoAP == nil {
				v.errf("%s.coap: required for kind coap", p)
			} else {
				v.coapListener(p+".coap", ln.CoAP, ln.Address, ln.TLS)
			}
		case "bacnet":
			// No tls section: Annex J is BACnet over UDP and the protocol
			// has no transport security anywhere, so a listener carrying a
			// certificate would be promising something it cannot do.
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: a bacnet listener takes only address and bacnet: the protocol is UDP and has no TLS", p)
			}
			if ln.BACnet == nil {
				v.errf("%s.bacnet: required for kind bacnet", p)
			} else {
				v.bacnetListener(p+".bacnet", ln.BACnet)
			}
		case "s7":
			// No tls section: S7comm has no transport security of any
			// kind, and a listener carrying a certificate would be
			// promising something the protocol cannot do.
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: an s7 listener takes only address and s7: the protocol has no TLS", p)
			}
			if ln.S7 == nil {
				v.errf("%s.s7: required for kind s7", p)
			} else {
				v.s7Listener(p+".s7", ln.S7)
			}
		case "opcua":
			// No tls section: the opc.tcp transport has none. OPC UA's
			// security is inside the protocol, negotiated per connection in
			// the secure channel, so a certificate here would promise
			// something the transport cannot do -- and terminating the
			// channel would make this relay a man in the middle of the one
			// industrial protocol designed to notice.
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: an opcua listener takes only address and opcua: the transport has no TLS, the secure channel is inside the protocol", p)
			}
			if ln.OPCUA == nil {
				v.errf("%s.opcua: required for kind opcua", p)
			} else {
				v.opcuaListener(p+".opcua", ln.OPCUA, ln.Address)
			}
		case "mms":
			// No tls section: MMS on TCP 102 has none. IEC 62351-4 adds TLS
			// under the session layer, and a listener that terminated it would
			// be terminating the only end-to-end protection this protocol has
			// -- so a listener that wants it is a tcp listener with a tls
			// section in front of one of these, not this one.
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: an mms listener takes only address and mms: MMS on TCP 102 has no transport TLS", p)
			}
			if ln.MMS == nil {
				v.errf("%s.mms: required for kind mms", p)
			} else {
				v.mmsListener(p+".mms", ln.MMS, ln.Address)
			}
		case "amqp":
			if ln.AMQP == nil {
				v.errf("%s.amqp: required for kind amqp", p)
			} else {
				v.amqpListener(p+".amqp", ln.AMQP, ln.TLS != nil)
			}
		case "redis":
			if ln.Redis == nil {
				v.errf("%s.redis: required for kind redis", p)
			} else {
				v.redisListener(p+".redis", ln.Redis, ln.TLS != nil)
			}
		case "tds":
			if ln.TDS == nil {
				v.errf("%s.tds: required for kind tds", p)
			} else {
				v.tdsListener(p+".tds", ln.TDS, ln.TLS != nil)
			}
		case "mysql":
			if ln.MySQL == nil {
				v.errf("%s.mysql: required for kind mysql", p)
			} else {
				v.mysqlListener(p+".mysql", ln.MySQL, ln.TLS != nil)
			}
		case "postgres":
			if ln.Postgres == nil {
				v.errf("%s.postgres: required for kind postgres", p)
			} else {
				v.postgresListener(p+".postgres", ln.Postgres, ln.TLS != nil)
			}
		case "tftp":
			// No tls section: TFTP has no transport security and no
			// extension that adds one, so a listener carrying a
			// certificate would be a listener promising something the
			// protocol cannot do.
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: a tftp listener takes only address and tftp: the protocol is UDP and has no TLS", p)
			}
			if ln.TFTP == nil {
				v.errf("%s.tftp: required for kind tftp", p)
			} else {
				v.tftpListener(p+".tftp", ln.TFTP)
			}
		case "iec104":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: an iec104 listener takes only address, iec104 and tls", p)
			}
			if ln.IEC104 == nil {
				v.errf("%s.iec104: required for kind iec104", p)
			} else {
				v.iec104Listener(p+".iec104", ln.IEC104, ln.TLS != nil)
			}
		case "ntp":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C || ln.TLS != nil {
				v.errf("%s: an ntp listener takes only address and ntp: the time service is UDP, and its TLS is the ntske listener's", p)
			}
			if ln.NTP == nil {
				v.errf("%s.ntp: required for kind ntp", p)
			} else {
				v.ntpListener(p+".ntp", ln.NTP)
			}
		case "ntske":
			if len(ln.Protocols) > 0 || ln.H3 != nil || ln.RedirectToHTTPS || ln.TCP != nil || ln.Forward != nil || ln.DNS != nil || ln.H2C {
				v.errf("%s: an ntske listener takes only address and ntske", p)
			}
			if ln.NTSKE == nil {
				v.errf("%s.ntske: required for kind ntske", p)
			} else {
				v.ntskeListener(p+".ntske", ln.NTSKE, ln.Address, ln.TLS != nil)
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
		v.listenerDaemon(p, ln)
		v.connectionRate(p, ln.ConnectionRate, ln.ConnectionRatePerSource)
		if ln.UDP != nil && ln.Kind != "udp" {
			v.errf("%s.udp: set on a %s listener (kind: udp)", p, ln.Kind)
		}
		if ln.Syslog != nil && ln.Kind != "syslog" {
			v.errf("%s.syslog: set on a %s listener (kind: syslog)", p, ln.Kind)
		}
		if ln.Modbus != nil && ln.Kind != "modbus" {
			v.errf("%s.modbus: set on a %s listener (kind: modbus)", p, ln.Kind)
		}
		if ln.NTP != nil && ln.Kind != "ntp" {
			v.errf("%s.ntp: set on a %s listener (kind: ntp)", p, ln.Kind)
		}
		if ln.DHCP6 != nil && ln.Kind != "dhcp6" {
			v.errf("%s.dhcp6: set on a %s listener (kind: dhcp6)", p, kindOrHTTP(ln.Kind))
		}
		if ln.NTSKE != nil && ln.Kind != "ntske" {
			v.errf("%s.ntske: set on a %s listener (kind: ntske)", p, ln.Kind)
		}
		if lp := ln.Policy; lp != nil {
			switch lp.Mode {
			case "", "enforce":
			case "shadow":
				v.warnf("%s.policy.mode is shadow, so this listener evaluates its policy and refuses nothing for it: read xproxyctl policy report, then turn enforcement on. Authentication, bans, rate limits, bounds and malformed input are still refused", p)
			default:
				v.errf("%s.policy.mode: must be enforce or shadow", p)
			}
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
		// The three newest relay kinds. A section on the wrong kind is
		// silently ignored otherwise, which means a policy somebody wrote
		// and believes is in force.
		if ln.IEC104 != nil && ln.Kind != "iec104" {
			v.errf("%s.iec104: set on a %s listener (kind: iec104)", p, ln.Kind)
		}
		if ln.SNMP != nil && ln.Kind != "snmp" {
			v.errf("%s.snmp: set on a %s listener (kind: snmp)", p, ln.Kind)
		}
		if ln.LDAP != nil && ln.Kind != "ldap" {
			v.errf("%s.ldap: set on a %s listener (kind: ldap)", p, ln.Kind)
		}
		if ln.TLS == nil {
			for _, proto := range ln.Protocols {
				if proto == ProtocolH2 || proto == ProtocolH3 {
					v.errf("%s: protocol %s requires tls", p, proto)
				}
			}
		} else {
			v.tls(p+".tls", ln.TLS, pinsKeys(ln))
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

func (v *validator) tls(p string, t *TLS, pinsKeys bool) {
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
	if e := t.Expiry; e != nil {
		if e.Warn != 0 && (e.Warn < Duration(time.Hour) || e.Warn > Duration(365*24*time.Hour)) {
			v.errf("%s.expiry.warn: must be 0 (no warning) or between 1h and 8760h", p)
		}
		if !e.RefuseExpired && e.Warn == 0 {
			v.warnf("%s.expiry: neither refuse_expired nor warn is set, so the section does nothing", p)
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
		cp := fmt.Sprintf("%s.certificates[%d]", p, i)
		if c.CertFile == "" {
			v.errf("%s: cert_file is required", cp)
			continue
		}
		v.file(cp+".cert_file", c.CertFile)
		v.certificateKey(cp, c)
	}
	switch t.MinVersion {
	case "1.2", "1.3":
	default:
		v.errf("%s.min_version: must be \"1.2\" or \"1.3\" (TLS 1.0 and 1.1 are never allowed)", p)
	}
	if t.ClientAuth == "request" || t.ClientAuth == "require" {
		v.clientCertAsked = true
	}
	switch t.ClientAuth {
	case "none":
	case "request", "require":
		if t.ClientCAFile == "" {
			v.errf("%s.client_ca_file: required when client_auth is %s", p, t.ClientAuth)
		} else {
			v.file(p+".client_ca_file", t.ClientCAFile)
		}
	case "require_any":
		// A certificate demanded and checked against nothing. It is the shape
		// RFC 7252 s9.1.3.2's raw public key mode takes here -- the key inside
		// the certificate is pinned by the listener's public_keys table, and
		// there is no authority to check a chain against -- and it is refused
		// everywhere else, because a certificate nobody verified is not an
		// identity and a policy written on one would be a policy about
		// whatever a peer chose to send.
		if !pinsKeys {
			v.errf("%s.client_auth: require_any asks for a certificate and verifies it against nothing, which is only a credential where something else decides whether the peer is anybody. Write require with client_ca_file; require_any is for a coap listener whose public_keys table pins the key itself", p)
		}
		if t.ClientCAFile != "" {
			v.errf("%s.client_ca_file: set with client_auth: require_any, which verifies no chain. Write require to check certificates against that authority, or drop the file", p)
		}
	default:
		v.errf("%s.client_auth: must be none, request, require or require_any", p)
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
		case "jwt", "oidc", "saml", "api_key", "basic", "ldap":
		default:
			v.errf("%s.key: identity kind must be jwt, oidc, saml, api_key, basic or ldap", p)
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
		case "consul":
			if c := d.Consul; c == nil {
				v.errf("%s.consul: required for type consul", dp)
			} else {
				if c.Service == "" {
					v.errf("%s.consul.service: required", dp)
				}
				if _, _, err := net.SplitHostPort(c.Address); err != nil {
					v.errf("%s.consul.address: %q must be host:port", dp, c.Address)
				}
				if c.TokenFile != "" && !strings.HasPrefix(c.TokenFile, "/") {
					v.errf("%s.consul.token_file: must be an absolute path", dp)
				}
				if c.TokenFile != "" {
					v.file(dp+".consul.token_file", c.TokenFile)
					if st, err := os.Stat(c.TokenFile); err == nil && st.Mode().Perm()&0o077 != 0 {
						v.errf("%s.consul.token_file: %s is readable by more than its owner (mode %04o); "+
							"an ACL token is a credential", dp, c.TokenFile, st.Mode().Perm())
					}
				}
				if c.Wait < Duration(time.Second) || c.Wait > Duration(10*time.Minute) {
					v.errf("%s.consul.wait: must be between 1s and 10m", dp)
				}
				if c.TLS != nil {
					v.upstreamTLS(dp+".consul.tls", c.TLS)
				}
				if c.AllowStale {
					v.warnf("%s.consul.allow_stale: the agent answers from its own state, which may be a moment behind; "+
						"a balancer acting on stale membership sends traffic to an instance that has gone", dp)
				}
			}
			if d.Name != "" {
				v.errf("%s.name: not used by type consul; the service is consul.service", dp)
			}
			if d.Resolver != "" {
				v.errf("%s.resolver: only for dns and srv discovery", dp)
			}
		default:
			v.errf("%s.type: must be dns, srv, http or consul", dp)
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
		if d.MaxEndpoints < 1 || d.MaxEndpoints > 65536 {
			v.errf("%s.max_endpoints: must be between 1 and 65536", dp)
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
	switch r.ClientCertHeaders {
	case "", "none", "rfc9440", "xfcc":
	default:
		v.errf("%s.client_cert_headers: must be none, rfc9440 or xfcc", p)
	}

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
	"geo": true, "tcp_no_route": true, "forward_denied": true, "forward_auth": true, "honeypot": true, "dns_blocked": true, "dns_bogus": true, "dns_rpz": true,
	"account_abuse": true, "api_abuse": true, "flow": true, "honeytoken": true, "scim": true, "threat_intel": true, "smtp_denied": true, "mqtt_denied": true, "ssh_denied": true, "ftp_denied": true, "syslog_denied": true, "yara": true,
	"forward_sni_mismatch": true, "dns_tunnel": true, "dns_answer_denied": true,
	// The fabrications' own events (each kind's decoy.go).
	//
	// A tripwire reaches the ban ladder only where this proxy knows who sent
	// the frame that tripped it. On a TCP kind the handshake has completed
	// before any fabricated exchange, so the source address is the client's.
	// On a datagram kind it is whatever the sender wrote, so banning on it
	// would let one forged packet have somebody else's address banned -- which
	// is why dns attributes an unverified datagram to nobody, and why
	// snmp_tripwire is deliberately absent: the fabricated agent never answers
	// a version 3 message, so every exchange it does answer is unauthenticated
	// v1 or v2c. It stays in the security log, where it costs nobody anything.
	//
	// The tripwire is the one worth banning on. A client that asked a fabricated
	// resolver for a zone transfer has said something; one that was merely
	// answered has said that it resolved a name a feed named, and banning it ends
	// the deception that was about to tell you more.
	"dns_deceived": true, "dns_tripwire": true,
	// telnet_tripwire is the fabricated login's escalation: a client that typed
	// wget into a machine that is not there. The fabrication feeds the ban ladder
	// with that and nothing else -- an ordinary fabricated exchange is not a
	// finding, and banning on it would end the collection.
	"telnet_tripwire": true,
	// ssh_tripwire is the same on the bastion: a command reaching for a payload,
	// or a channel asking the fabrication to forward a connection somewhere.
	"ssh_tripwire": true,
	// And the same on the relays that front equipment and databases: an address
	// or a block nobody has a reason to touch, a command nothing legitimate
	// sends to a cache, a statement reaching for a file or a credential table.
	"modbus_tripwire": true, "iec104_tripwire": true, "s7_tripwire": true,
	"redis_tripwire": true, "mysql_tripwire": true, "postgres_tripwire": true,
	"telnet_denied": true, "vnc_denied": true, "rdp_denied": true, "sftp_icap": true, "udp_denied": true,
	// tcp_denied is the generic TCP relay's refusal by the imported lists or the
	// authorisation policy. It is separate from tcp_no_route, which is a client
	// asking for a name this listener has no route for: a scanner's SNI sweep and
	// a listed client are different findings and an estate may want to ban on one
	// and not the other.
	"tcp_denied": true,
	// dns_denied is the dns listener's refusal by the imported lists or the
	// authorisation policy, and dns_threat_intel is a name on a domain list. Both
	// are observations this listener already made; neither could be named by a ban
	// trigger until they were written here.
	"dns_denied": true, "dns_threat_intel": true,
	"modbus_denied": true, "iec104_denied": true, "ntp_denied": true, "ntske_denied": true,
	"snmp_denied": true, "ldap_denied": true, "tftp_denied": true, "dhcp_denied": true, "dhcp6_denied": true, "coap_denied": true, "opcua_denied": true, "mms_denied": true, "postgres_denied": true, "mysql_denied": true, "tds_denied": true, "redis_denied": true,
	"bacnet_denied": true, "amqp_denied": true, "s7_denied": true,
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
	// An intercepting listener takes its destination from the socket, so
	// it needs no route and may not have one; transparentTCP below says
	// so the other way round.
	if len(t.Routes) == 0 && t.Default == "" && !t.OriginalDestination {
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
	if t.ConnectTimeout <= 0 || t.ConnectTimeout > Duration(2*time.Minute) {
		v.errf("%s.connect_timeout: must be positive and at most 2m", p)
	}
	v.transparentTCP(p, t)
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

// listenerDaemon checks the program a listener names, for the kinds more
// than one of them serves.
//
// It is refused rather than ignored where the named daemon does not
// carry that kind's code, because the two ways to get it wrong are the
// two ways a listener silently stops being served: a daemon that does
// not exist, and one that exists and serves something else. Either
// leaves a port nobody binds and a policy nobody enforces, and neither
// shows up anywhere but in a log line saying the listener was left to a
// sibling that is never going to take it.
func (v *validator) listenerDaemon(p string, ln *Listener) {
	if ln.Daemon == "" {
		return
	}
	if _, ok := listener.RoleByDaemon(ln.Daemon); !ok {
		v.errf("%s.daemon: %q is not one of %s", p, ln.Daemon,
			strings.Join(daemonNames(), ", "))
		return
	}
	if _, ok := listener.RoleOf(ln.Kind); !ok {
		// The kind itself is already refused above; nothing to add.
		return
	}
	if _, ok := listener.Owner(ln.Kind, ln.Daemon); !ok {
		v.errf("%s.daemon: %s does not serve kind %s, which is served by %s",
			p, ln.Daemon, ln.Kind, strings.Join(listener.Daemons(ln.Kind), " and "))
		return
	}
	if !listener.Shared(ln.Kind) {
		v.warnf("%s.daemon: kind %s is served only by %s, so naming it says nothing",
			p, ln.Kind, ln.Daemon)
	}
}

// daemonNames are the programs a listener may name, for a message.
func daemonNames() []string {
	out := make([]string, 0, 4)
	for _, r := range listener.Roles() {
		out = append(out, r.Daemon())
	}
	return out
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

// transparentTCP validates the interception settings of a layer 4
// listener: the two socket tricks, and the destination policy without
// which the second is an open relay.
func (v *validator) transparentTCP(p string, t *TCPListener) {
	if (t.Transparent || t.OriginalDestination) && !transparent.Available() {
		v.errf("%s: transparent and original_destination need Linux (IP_TRANSPARENT and SO_ORIGINAL_DST)", p)
	}
	if t.OriginalDestination {
		if len(t.Routes) > 0 || t.Default != "" {
			v.errf("%s.original_destination: the destination comes from the socket, so routes and default would be ignored; remove them", p)
		}
		if len(t.AllowDestinations) == 0 {
			v.errf("%s.allow_destinations: required with original_destination, or the listener relays to anywhere "+
				"for anyone who can reach the port", p)
		}
		if t.QUIC {
			v.errf("%s.quic: a QUIC flow has no original destination to read; the option is for the stream half", p)
		}
	} else if len(t.AllowDestinations) > 0 || len(t.DestinationPorts) > 0 {
		v.errf("%s: allow_destinations and destination_ports are for original_destination, which is not set", p)
	}
	for i, c := range t.AllowDestinations {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow_destinations[%d]: %q is not a CIDR: %v", p, i, c, err)
		}
	}
	for i, port := range t.DestinationPorts {
		if port < 1 || port > 65535 {
			v.errf("%s.destination_ports[%d]: %d is not a port", p, i, port)
		}
	}
	if t.Transparent {
		// The capability is a property of the process, not of the file,
		// so this is the one check that has to be made at load: a
		// listener that cannot set the option would fail every dial
		// with something that looks like a dead upstream.
		if err := transparent.Check(); err != nil {
			v.errf("%s.transparent: this process cannot set IP_TRANSPARENT (%v); it needs CAP_NET_ADMIN", p, err)
		}
		v.warnf("%s.transparent: the upstream will see the client's address, so the return traffic must be routed back to "+
			"this host by the firewall; without that every connection fails in a way that looks like a dead upstream", p)
		if t.ProxyProtocol {
			v.errf("%s.transparent: with proxy_protocol as well, the upstream is told the client's address twice, "+
				"in the header and in the source; set one", p)
		}
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
	if l := m.Learn; l != nil && l.Enabled {
		if l.File == "" {
			v.errf("%s.learn.file: required when learning is enabled", p)
		} else if !strings.HasPrefix(l.File, "/") {
			v.errf("%s.learn.file: must be an absolute path", p)
		}
		if l.Interval != 0 && (l.Interval.D() < 10*time.Second || l.Interval.D() > 24*time.Hour) {
			v.errf("%s.learn.interval: must be between 10s and 24h", p)
		}
		if l.MaxSubjects != 0 && (l.MaxSubjects < 16 || l.MaxSubjects > 1_000_000) {
			v.errf("%s.learn.max_subjects: must be between 16 and 1000000", p)
		}
		if !l.Enforce {
			v.warnf("%s.learn is enabled without enforce, so this listener records and decides nothing: "+
				"turn enforce on, or take the learning section out, once the topic lists are written. "+
				"The packet, payload and subscription bounds stay in force either way", p)
		}
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
	if m.MaxPayloadBytes < 0 || m.MaxPayloadBytes > 268435455 {
		v.errf("%s.max_payload_bytes: must be between 0 and 268435455", p)
	}
	if m.MaxQoS != nil && (*m.MaxQoS < 0 || *m.MaxQoS > 2) {
		v.errf("%s.max_qos: must be 0, 1 or 2", p)
	}
	names := map[string]bool{}
	for i := range m.Topics {
		r := &m.Topics[i]
		q := fmt.Sprintf("%s.topics[%d]", p, i)
		switch {
		case r.Name == "":
			v.errf("%s.name: required", q)
		case names[r.Name]:
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		names[r.Name] = true
		if len(r.Filters) == 0 {
			v.errf("%s.filters: required", q)
		}
		for j, f := range r.Filters {
			if err := mqttwire.ValidFilter(f); err != nil {
				v.errf("%s.filters[%d]: %q is not a topic filter: %v", q, j, f, err)
			}
		}
		if r.MaxPayloadBytes < 0 || r.MaxPayloadBytes > 268435455 {
			v.errf("%s.max_payload_bytes: must be between 0 and 268435455", q)
		}
		for _, f := range []struct {
			key string
			val *int
		}{{"min_qos", r.MinQoS}, {"max_qos", r.MaxQoS}} {
			if f.val != nil && (*f.val < 0 || *f.val > 2) {
				v.errf("%s.%s: must be 0, 1 or 2", q, f.key)
			}
		}
		if r.MinQoS != nil && r.MaxQoS != nil && *r.MinQoS > *r.MaxQoS {
			v.errf("%s: min_qos %d is above max_qos %d", q, *r.MinQoS, *r.MaxQoS)
		}
		if r.MinQoS == nil && r.MaxQoS == nil && r.MaxPayloadBytes == 0 && r.AllowRetain == nil {
			v.errf("%s: sets no bound, so the rule decides nothing; drop it or give it one", q)
		}
	}
	if sp := m.Sparkplug; sp != nil && sp.Enabled {
		for i, name := range sp.AllowMessageTypes {
			if !mqttwire.SparkplugType(name) {
				v.errf("%s.sparkplug.allow_message_types[%d]: %q is not a Sparkplug B message type (NBIRTH, NDEATH, DBIRTH, DDEATH, NDATA, DDATA, NCMD, DCMD, STATE)", p, i, name)
			}
		}
		for i, c := range sp.CommandClients {
			if _, err := netip.ParsePrefix(c); err != nil {
				v.errf("%s.sparkplug.command_clients[%d]: %q is not a network in CIDR form", p, i, c)
			}
		}
		if sp.MaxNodes < 0 || sp.MaxNodes > 1<<20 {
			v.errf("%s.sparkplug.max_nodes: must be between 0 and 1048576", p)
		}
		if len(sp.CommandClients) == 0 {
			v.warnf("%s.sparkplug.command_clients is empty, so NCMD and DCMD -- the Sparkplug messages that command equipment -- are left to the ordinary publish policy: naming the publishers that may send one is what this section is for", p)
		}
		if !sp.RequireBirthBeforeData && !sp.CheckSequence && len(sp.CommandClients) == 0 &&
			len(sp.AllowMessageTypes) == 0 && !sp.RequireNamespace {
			v.warnf("%s.sparkplug is enabled and sets nothing, so it reads topics and decides nothing", p)
		}
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
// sshDecoyOnly says this listener is nothing but a fabricated bastion: there is no
// machine behind it, its own login accepts everybody by design, and there is
// nothing to authenticate to.
func sshDecoyOnly(h *SSHListener) bool {
	d := h.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// SSHDecoyProfiles are the machines a fabrication can impersonate.
var SSHDecoyProfiles = []string{"busybox", "linux"}

// sshDeception checks the fabricated bastion.
func (v *validator) sshDeception(p string, h *SSHListener) {
	d := h.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener fronts real machines, and a "+
				"section that would fabricate a shell for any client whose credential fails is not a "+
				"decision to arrive at by default", p)
		}
	case "decoy":
		if h.Upstream != "" {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream: use mode answer to "+
				"fabricate the refusals of a bastion that fronts real machines", p)
		}
		if h.RequireGrant {
			v.errf("%s.mode: decoy has nobody real to check a grant for; remove require_grant", p)
		}
		if h.MFA != nil {
			v.errf("%s.mode: decoy accepts every credential by design, so an mfa section would refuse "+
				"the visitors the trap exists to collect", p)
		}
		if len(d.Clients) == 0 {
			v.warnf("%s: no clients, so every client that connects reaches the fabricated bastion. "+
				"That is what a honeypot is for, and port 22 is the most scanned port there is", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	if d.Profile != "" && !slices.Contains(SSHDecoyProfiles, d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, d.Profile, strings.Join(SSHDecoyProfiles, ", "))
	}
	if d.Hostname == "" {
		v.warnf("%s.hostname: empty, so the profile's own name is used. Name it after something this "+
			"estate really has: a visitor who finds app01 on a site whose servers are named another "+
			"way has found the fabrication", p)
	}
	if n := d.Attempts; n < 0 || n > 16 {
		v.errf("%s.attempts: must be between 0 and 16", p)
	}
	if n := d.Attempts; n > 1 && h.MaxAuthTries > 0 && n > h.MaxAuthTries {
		// The protocol stops the client first: a trap waiting for a fifth
		// credential on a listener that allows three would never accept one.
		v.errf("%s.attempts: %d, but max_auth_tries is %d, so the client is refused before the "+
			"fabrication accepts anything", p, n, h.MaxAuthTries)
	}
	for i, c := range d.Tripwire {
		if strings.TrimSpace(c) == "" || strings.ContainsAny(c, " \t\r\n") {
			v.errf("%s.tripwire[%d]: %q is not a command name; one name per entry", p, i, c)
		}
	}
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
}

func (v *validator) sshListener(p string, h *SSHListener) {
	v.sshDeception(p+".deception", h)
	decoy := sshDecoyOnly(h)
	if h.Upstream == "" && !decoy {
		v.errf("%s.upstream: required", p)
	}
	if len(h.HostKeys) == 0 {
		v.errf("%s.host_keys: at least one is required (clients pin it, so it is the bastion's identity)", p)
	}
	for i, f := range h.HostKeys {
		v.file(fmt.Sprintf("%s.host_keys[%d]", p, i), f)
	}
	// Three ways to authenticate, not two: a fleet that has moved to
	// certificates has no authorized_keys to write, which is the point
	// of moving. The check below repeats this because it is the one an
	// operator reading the file finds first.
	if h.AuthorizedKeys == "" && h.UsersFile == "" && h.TrustedUserCAKeys == "" && !decoy {
		v.errf("%s: authorized_keys, users_file or trusted_user_ca_keys is required; a bastion that authenticates nobody forwards everybody", p)
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
	v.sshHardwareKeys(p, h)
	if h.UpstreamKeyFile == "" {
		if !decoy {
			v.errf("%s.upstream_key_file: required (the credential the proxy authenticates to the target with)", p)
		}
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
		if !decoy {
			v.errf("%s.upstream_known_hosts: required unless upstream_insecure_host_key is set", p)
		}
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
	v.sshCommandRules(p, h.CommandRules, h.SFTP != nil, reqs["exec"])
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
	v.sshCertPolicy(p, h)
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
	v.recordingIntegrity(p+".integrity", r.Integrity)
	v.recordingEncryption(p+".encryption", r.Encryption)
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
// sshHardwareKeys checks the security-token policy: what it is worth being
// refused for, and what it is worth being told about.
//
// The requirement is about a credential that cannot be copied, so the things
// that quietly restore a copyable one are what this looks for: a password, a
// principal exempted from the requirement, and the presence opt-out.
func (v *validator) sshHardwareKeys(p string, h *SSHListener) {
	if h.RequireHardwareKey {
		switch {
		case h.UsersFile != "" && h.MFA == nil:
			// A password is a second way in, and no token stands behind it:
			// the requirement would be a requirement on the door nobody uses.
			v.errf("%s.require_hardware_key: set with users_file and no mfa section, so a password is a way in that no token protects. Drop users_file, or add mfa, or drop the requirement", p)
		case h.UsersFile != "":
			v.warnf("%s.require_hardware_key: password authentication is still configured, so the hardware requirement covers public keys only -- a password with a one-time code is a different strength from a key in a token", p)
		}
		if h.AuthorizedKeys == "" && h.TrustedUserCAKeys == "" {
			v.errf("%s.require_hardware_key: set with neither authorized_keys nor trusted_user_ca_keys, so there is no key it could accept", p)
		}
	}
	if !h.Touch() {
		v.warnf("%s.require_touch: false honours no-touch-required, so a signature no longer proves somebody was there. The key still cannot be copied, but anything running on the machine it is plugged into can use it", p)
	}
	for i := range h.Principals {
		e := &h.Principals[i]
		if h.RequireHardwareKey && e.RequireHardwareKey != nil && !*e.RequireHardwareKey {
			v.warnf("%s.principals[%d] (%s): require_hardware_key: false exempts this principal from the listener's requirement, so its key is a file like any other", p, i, e.Name)
		}
	}
}

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
	v.sshCommandRules(p, s.CommandRules, s.SFTP != nil || h.SFTP != nil,
		reqs["exec"] || sliceHas(h.AllowRequests, "exec"))
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
	if m.File == "" && m.Push == nil {
		v.errf("%s: file or push is required; a second factor with neither asks for nothing", p)
	}
	if m.File == "" && m.Push != nil {
		// Every user is pushed, and the approval service decides whether a
		// user exists at all. The enrolment settings below then describe
		// nothing, which is worth saying rather than checking silently.
		if m.RequireEnrolment != nil {
			v.warnf("%s.require_enrolment: there is no enrolment file, so every user is pushed and the approval service is what decides whether they exist", p)
		}
	}
	if m.File != "" {
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
	if m.RequireEnrolment != nil && !*m.RequireEnrolment && m.Push == nil {
		v.warnf("%s.require_enrolment: false lets a user who never enrolled past the second factor, which is the account an attacker will use", p)
	}
	if m.Push != nil {
		v.mfaPush(p+".push", m.Push)
	}
}

// mfaPush validates the approval service: where it is, how long a person has,
// and the bounds that make the fatigue attack expensive rather than free.
func (v *validator) mfaPush(p string, s *MFAPush) {
	v.feedURL(p+".url", s.URL) // the same rules a threat feed's URL is held to
	if d := s.Timeout.D(); d != 0 && (d < 5*time.Second || d > 5*time.Minute) {
		v.errf("%s.timeout: must be between 5s and 5m, or 0 for the default; it is how long somebody has to find their phone, and how long a half-authenticated session is held open", p)
	}
	if d := s.Poll.D(); d != 0 && (d < time.Second || d > time.Minute) {
		v.errf("%s.poll: must be between 1s and 1m, or 0 for the default", p)
	}
	if s.Poll.D() > s.Timeout.D() && s.Timeout.D() > 0 {
		v.errf("%s.poll: longer than the timeout, so a pending request would never be asked about again", p)
	}
	if (s.Header == "") != (s.HeaderValue == "") {
		v.errf("%s: header and header_value go together", p)
	}
	if s.CAFile != "" {
		v.file(p+".ca_file", s.CAFile)
	}
	if s.PerWindow < 1 || s.PerWindow > 100 {
		v.errf("%s.per_window: must be 1..100", p)
	}
	if s.Window <= 0 || s.Window > Duration(24*time.Hour) {
		v.errf("%s.window: must be positive and at most 24h", p)
	}
	if s.PerWindow > 5 {
		v.warnf("%s.per_window: %d notifications per %s to one person is the push-fatigue attack most of the way done; the number exists to make it expensive", p, s.PerWindow, s.Window.D())
	}
	if !s.ShowsNumbers() {
		v.warnf("%s.numbers: false leaves an approval that says nothing about which sign-in it is for, so a person who did not cause it has nothing to compare", p)
	}
	switch {
	case s.Insecure && !s.AllowInsecure:
		v.errf("%s.insecure: needs allow_insecure as well, so skipping verification is two decisions rather than one", p)
	case s.Insecure:
		if u, err := url.Parse(s.URL); err == nil && !isLoopbackHost(u.Hostname()) {
			v.errf("%s.insecure: %s is not a loopback address, and whatever can answer for the approval service decides who gets in", p, u.Hostname())
		} else {
			v.warnf("%s.insecure: the approval service's certificate is not verified. Only a development instance on this machine", p)
		}
	}
	if s.Token == "" && s.Header == "" {
		v.warnf("%s: no token and no header, so the approval service is asked anonymously. A service that answers 401 for every request is a second factor that refuses everybody", p)
	}
}

// authorization validates the estate's authorisation policy, and refuses the
// one arrangement that would make it a lie: a listener whose kind does not
// consult it.
//
// That check is the reason this section can be delivered a few kinds at a time.
// A policy an operator believes covers the estate, with a listener quietly
// outside it, is worse than no policy at all -- so the load says which kinds
// consult it and which listener does not, and the operator decides whether to
// wait or to move that listener.
func (v *validator) authorization(c *Config) {
	a := c.Authorization
	if a == nil {
		return
	}
	switch a.Default {
	case "", "deny", "allow":
	default:
		v.errf("authorization.default: must be deny or allow")
	}
	if len(a.Rules) == 0 {
		v.errf("authorization.rules: at least one is required; a section with no rules and a deny default refuses the whole estate")
	}
	if a.Allows() {
		v.warnf("authorization.default: allow means anything no rule mentions is permitted, so the policy's gaps are invisible. deny is what makes a rule list a policy")
	}
	if a.Shadow {
		v.warnf("authorization: shadow evaluates the policy and enforces nothing, which is what a first reading wants and not what a policy is for. Take it out once the decisions read right")
	}
	// The listener names a rule may point at, and the kinds in use.
	names := map[string]bool{}
	for i := range c.Server.Listeners {
		names[c.Server.Listeners[i].Name] = true
	}
	seen := map[string]bool{}
	for i := range a.Rules {
		r := &a.Rules[i]
		q := fmt.Sprintf("authorization.rules[%d]", i)
		switch {
		case r.Name == "":
			v.errf("%s.name: required; a decision nobody can name is a decision nobody can find in a log", q)
		case !nameRE.MatchString(r.Name):
			v.errf("%s.name: %q is not a valid name", q, r.Name)
		case seen[r.Name]:
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		seen[r.Name] = true
		for j, act := range r.Actions {
			if !AuthzActions[act] {
				v.errf("%s.actions[%d]: %q is not an action; the vocabulary is connect, session, exec, forward, read, write and admin", q, j, act)
			}
		}
		v.authzNetworks(q+".networks", r.Networks)
		v.authzNetworks(q+".not_networks", r.NotNetworks)
		for j, l := range r.Listeners {
			if !names[l] {
				v.errf("%s.listeners[%d]: no listener is called %q", q, j, l)
			}
		}
		for j, k := range r.Kinds {
			if _, ok := listener.RoleOf(k); !ok {
				v.errf("%s.kinds[%d]: %q is not a listener kind", q, j, k)
			}
		}
		for j, t := range r.Targets {
			v.authzTarget(fmt.Sprintf("%s.targets[%d]", q, j), t)
		}
		for j, t := range r.NotTargets {
			v.authzTarget(fmt.Sprintf("%s.not_targets[%d]", q, j), t)
		}
		v.modbusSchedule(q+".schedule", r.Schedule)
		if r.Allow && len(r.Users) == 0 && len(r.Principals) == 0 && len(r.Groups) == 0 &&
			len(r.Networks) == 0 && len(r.Listeners) == 0 && len(r.Kinds) == 0 && len(r.Targets) == 0 &&
			len(r.Actions) == 0 && r.Schedule == nil {
			v.warnf("%s (%s): allows everything, because it names nothing to match on. Every rule after it is unreachable", q, r.Name)
		}
	}
	// The kinds that do not consult the policy. Named individually because an
	// operator has to know which listener to move or to wait for.
	for i := range c.Server.Listeners {
		l := &c.Server.Listeners[i]
		k := l.Kind
		if k == "" {
			k = "http"
		}
		if listener.Authorises(k) {
			continue
		}
		v.errf("authorization: listener %q is kind %q, which does not consult the authorization policy, so the section would not cover it. The kinds that do are %s; move the listener, or drop the section until this kind is one of them",
			l.Name, k, kindList())
	}
}

// kindList is the kinds that consult the policy, for a message that has to
// name them. "none yet" rather than an empty list, because a message ending in
// "the kinds that do are ." is a message nobody can act on.
func kindList() string {
	k := listener.AuthorisingKinds()
	if len(k) == 0 {
		return "none yet"
	}
	return strings.Join(k, ", ")
}

// authzNetworks checks an address list, where a bare address means that one
// address.
func (v *validator) authzNetworks(p string, list []string) {
	for i, n := range list {
		if _, err := netip.ParsePrefix(n); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(n); err != nil {
			v.errf("%s[%d]: %q is not an address or a CIDR", p, i, n)
		}
	}
}

// authzTarget checks a target pattern. The rule is narrow on purpose: * does
// not cross a colon or a slash, so a pattern cannot quietly widen past the host
// or the directory it looks like it names.
func (v *validator) authzTarget(p, pattern string) {
	switch {
	case pattern == "":
		v.errf("%s: empty", p)
	case strings.Contains(pattern, "**"):
		v.errf("%s: ** is not a target pattern here; * already matches a whole host or path element, and a pattern that crossed a colon or a slash would widen the rule past what it looks like", p)
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

// cookieModeName is the cookie mode as an operator sees it, with the default
// spelled out: a warning quoting "" tells nobody anything.
func cookieModeName(s string) string {
	if s == "" {
		return "respond"
	}
	return s
}

// dnsDecoyOnly says this listener is nothing but a fabricated resolver, which is
// the one shape that needs no upstreams: there is nothing behind it to ask.
func dnsDecoyOnly(d *DNSListener) bool {
	c := d.Deception
	return c != nil && (c.Enabled == nil || *c.Enabled) && c.Mode == "decoy"
}

// DNSDecoyProfiles are the fabricated resolver shapes the listener has built in.
var DNSDecoyProfiles = []string{"documentation", "loopback", "unroutable"}

// dnsDeception checks the fabricated resolver.
func (v *validator) dnsDeception(p string, d *DNSListener) {
	c := d.Deception
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return
	}
	switch c.Mode {
	case "", "answer":
		if len(c.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener resolves for real clients, and "+
				"a section that would fabricate an answer for any of them is not a decision to arrive "+
				"at by default", p)
		}
	case "decoy":
		if len(d.Upstreams) > 0 {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstreams: use mode answer to "+
				"fabricate the refusals of a listener that really resolves", p)
		}
		if len(c.Clients) == 0 {
			v.warnf("%s: no clients, so every client that connects is answered by the fabricated "+
				"resolver. That is what a honeypot is for, and on port 53 it will be found -- which "+
				"is why cookies: require is worth its compatibility cost here", p)
		}
		if d.Cookies != "require" {
			// A resolver is an amplifier, and a honeypot on port 53 is found in
			// hours. The fabrication bounds an unverified answer against the
			// query, which is what keeps it from being a reflector; cookies are
			// what make the *record* mean anything.
			v.warnf("%s: cookies is %q, so the address in this fabrication's record is the one the "+
				"datagram claimed. A fabricated answer is bounded against the query it answers, so "+
				"nothing here amplifies either way -- but cookies: require is what makes the record of "+
				"who visited worth reading", p, cookieModeName(d.Cookies))
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", c.Clients)
	if c.Profile != "" && !slices.Contains(DNSDecoyProfiles, c.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, c.Profile, strings.Join(DNSDecoyProfiles, ", "))
	}
	var seen4, seen6 bool
	for i, a := range c.Addresses {
		pfx, err := netip.ParsePrefix(a)
		if err != nil {
			v.errf("%s.addresses[%d]: %v", p, i, err)
			continue
		}
		switch {
		case pfx.Addr().Is4():
			if seen4 {
				v.errf("%s.addresses[%d]: a second IPv4 pool; one prefix per family", p, i)
			}
			seen4 = true
		default:
			if seen6 {
				v.errf("%s.addresses[%d]: a second IPv6 pool; one prefix per family", p, i)
			}
			seen6 = true
		}
		if pfx.Addr().Is4In6() {
			v.errf("%s.addresses[%d]: %s is an IPv4 address written as IPv6; write it as IPv4", p, i, a)
		}
		// A pool a visitor is sent into. Naming the estate's own network here is
		// a decision, and one worth saying out loud at load rather than
		// discovering from the traffic that arrives at a real host.
		if pfx.Addr().IsPrivate() || pfx.Addr().IsLinkLocalUnicast() {
			v.warnf("%s.addresses[%d]: %s is inside the estate, so every name this fabrication "+
				"answers sends the visitor there. That is worth doing on purpose -- a honeypot "+
				"listener of this proxy's own is a good answer -- and a mistake anywhere else", p, i, a)
		}
	}
	for i, n := range c.Tripwire {
		if strings.TrimSpace(n) == "" || strings.ContainsAny(n, " \t\r\n") {
			v.errf("%s.tripwire[%d]: %q is not a name; one name per entry", p, i, n)
		}
	}
	if ttl := c.TTL.D(); ttl != 0 && (ttl < time.Second || ttl > time.Hour) {
		v.errf("%s.ttl: must be between 1s and 1h", p)
	}
	if n := c.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := c.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
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
	v.dnsDeception(p+".deception", d)
	if len(d.Upstreams) == 0 && !dnsDecoyOnly(d) {
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
		// A stale window longer than a day stops being a resolver outage
		// this resolver rides out and starts being a resolver that
		// answers from last week.
		if c.ServeStale < 0 || c.ServeStale > Duration(24*time.Hour) {
			v.errf("%s.cache.serve_stale: must be between 0 and 24h", p)
		}
		if c.StaleTTL <= 0 || c.StaleTTL > Duration(5*time.Minute) {
			v.errf("%s.cache.stale_ttl: must be positive and at most 5m", p)
		}
		if c.PrefetchThreshold <= 0 || c.PrefetchThreshold > 0.5 {
			v.errf("%s.cache.prefetch_threshold: must be between 0 and 0.5", p)
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
	switch d.ECS {
	case "", "strip", "forward":
	default:
		v.errf("%s.ecs: must be strip or forward", p)
	}
	switch d.Cookies {
	case "", "off", "respond", "require":
	default:
		v.errf("%s.cookies: must be off, respond or require", p)
	}
	if d.CookieLifetime <= 0 || d.CookieLifetime > Duration(24*time.Hour) {
		v.errf("%s.cookie_lifetime: must be positive and at most 24h", p)
	}
	// require refuses every client that does not implement cookies,
	// which is most stub resolvers. On a listener open to the internet
	// that is a resolver nobody can use; on one with a client list it is
	// a deliberate choice about known clients.
	//
	// Not on a decoy listener, which is the one shape where refusing the
	// clients that do not implement cookies is the point: nothing on the
	// estate is configured to use it, so it has no clients to break, and
	// the section above asks for require by name.
	if d.Cookies == "require" && len(d.AllowClients) == 0 && !dnsDecoyOnly(d) {
		v.warnf("%s.cookies: require refuses any UDP client that does not implement DNS cookies (RFC 7873), "+
			"which most stub resolvers do not; name the clients in allow_clients, or use respond", p)
	}
	v.dnsAnswerPolicy(p+".answer_policy", d.AnswerPolicy)
	v.dnsDiscovery(p, d)
	v.dnsRecords(p, d)
	v.dnsTunnel(p+".tunnel_detection", d.TunnelDetection)
}

// tokenExchange checks an RFC 8693 exchange.
//
// The one shape worth refusing at load is an exchange that names neither
// an audience nor a resource: it asks the authorization server for a token
// as broad as the one it replaces, which is the point of the feature
// undone while the configuration reads as if it were on.
func (v *validator) tokenExchange(p string, t *TokenExchange) {
	if t == nil {
		return
	}
	if u, err := url.Parse(t.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		v.errf("%s.url: must be an https URL", p)
	}
	if t.ClientID == "" || !strings.HasPrefix(t.ClientSecretFile, "/") {
		v.errf("%s: client_id and an absolute client_secret_file are required", p)
	} else {
		v.file(p+".client_secret_file", t.ClientSecretFile)
	}
	if t.CAFile != "" {
		v.file(p+".ca_file", t.CAFile)
	}
	if t.Audience == "" && t.Resource == "" {
		v.errf("%s: audience or resource is required; an exchange that names neither asks for a token as broad as the one it replaces", p)
	}
	if t.Resource != "" {
		if u, err := url.Parse(t.Resource); err != nil || u.Scheme == "" || u.Host == "" {
			v.errf("%s.resource: must be an absolute URI (RFC 8707)", p)
		}
	}
	for i, sc := range t.Scopes {
		if sc == "" || strings.ContainsAny(sc, " \t\r\n\"") {
			v.errf("%s.scopes[%d]: a scope is a non-empty token without spaces", p, i)
		}
	}
	switch t.RequestedTokenType {
	case "", "urn:ietf:params:oauth:token-type:access_token", "urn:ietf:params:oauth:token-type:jwt":
	default:
		v.errf("%s.requested_token_type: must be the access_token or jwt URN; anything else would be forwarded as an access token", p)
	}
	if t.Header != "" && !headerNameOK(t.Header) {
		v.errf("%s.header: %q is not a valid header name", p, t.Header)
	}
	if strings.EqualFold(t.Header, "Cookie") || strings.EqualFold(t.Header, "Host") {
		v.errf("%s.header: %s cannot carry a token", p, t.Header)
	}
	if t.CacheTTL < 0 || t.CacheTTL > Duration(time.Hour) {
		v.errf("%s.cache_ttl: must be between 0 and 1h", p)
	}
	if t.Timeout != 0 && (t.Timeout < Duration(100*time.Millisecond) || t.Timeout > Duration(30*time.Second)) {
		v.errf("%s.timeout: must be between 100ms and 30s", p)
	}
	if !t.Requires() {
		v.warnf("%s.required: false lets a request through when the exchange fails, so the backend is reached with no token at all on exactly the requests where the control went wrong", p)
	}
}

// dpop checks a proof-of-possession policy.
//
// The algorithm list is the part worth refusing at load: a symmetric
// algorithm in it is a policy that verifies proofs the verifier could have
// written itself, which is proof of nothing and reads as if it were.
func (v *validator) dpop(p string, d *DPoP, source string) {
	if d == nil {
		return
	}
	switch d.Mode {
	case "", "off", "allow", "require":
	default:
		v.errf("%s.mode: must be off, allow or require", p)
	}
	for i, a := range d.Algorithms {
		switch a {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		default:
			v.errf("%s.algorithms[%d]: %q is not an asymmetric JWS algorithm", p, i, a)
		}
	}
	if d.MaxAge < 0 || d.MaxAge > Duration(10*time.Minute) {
		v.errf("%s.max_age: must be between 0 and 10m", p)
	}
	if d.ReplayEntries < 0 || d.ReplayEntries > 10_000_000 {
		v.errf("%s.replay_entries: must be between 0 and 10000000", p)
	}
	if d.ExternalURL != "" {
		if u, err := url.Parse(d.ExternalURL); err != nil || u.Scheme == "" || u.Host == "" {
			v.errf("%s.external_url: must be an absolute URL", p)
		}
	}
	// A proof binds the token in the Authorization header, and RFC 9449
	// puts it there under its own scheme. A provider reading the token
	// from a cookie or another header is a provider whose tokens no client
	// library will send a proof for.
	if d.Mode != "" && d.Mode != "off" && source != "" && source != "bearer" {
		v.warnf("%s: proof of possession is defined for the Authorization header (RFC 9449), and this provider reads its token from %q", p, source)
	}
}

// certificateBinding checks an RFC 8705 certificate binding. Both things
// it warns about are configurations that load and can never fire, which
// is worse than an error: the operator believes the control is on.
func (v *validator) certificateBinding(p string, c *CertificateBinding) {
	if c == nil {
		return
	}
	switch c.Mode {
	case "", "off":
		if c.TrustForwardedHeader {
			v.warnf("%s.trust_forwarded_header: set with mode off, so no certificate is ever compared", p)
		}
		return
	case "allow", "require":
	default:
		v.errf("%s.mode: must be off, allow or require", p)
		return
	}
	if c.TrustForwardedHeader && !v.trustedProxies {
		v.warnf("%s.trust_forwarded_header: needs trusted_proxies naming the peers that terminate TLS; without it the header is never read", p)
	}
	if !c.TrustForwardedHeader && !v.clientCertAsked {
		v.warnf("%s: no listener asks for a client certificate (tls.client_auth), so there is none to compare a bound token against", p)
	}
}

// dnsAnswerPolicy checks the answer screen. An answer policy that denies
// nothing is the one shape worth refusing at load: it reads like
// rebinding protection and is not, and an operator who wrote the section
// meant to get something for it.
func (v *validator) dnsAnswerPolicy(p string, a *DNSAnswerPolicy) {
	if a == nil {
		return
	}
	switch a.Action {
	case "", "nxdomain", "refuse", "servfail", "strip":
	default:
		v.errf("%s.action: must be nxdomain, refuse, servfail or strip", p)
	}
	for i, c := range a.Deny {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.deny[%d]: %q is not a CIDR", p, i, c)
		}
	}
	for i, c := range a.Allow {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s.allow[%d]: %q is not a CIDR", p, i, c)
		}
	}
	for i, n := range a.AllowNames {
		name := strings.TrimPrefix(strings.TrimPrefix(n, "*."), "=")
		if !hostPatternOK(strings.ToLower(strings.TrimSuffix(name, "."))) {
			v.errf("%s.allow_names[%d]: %q is not a name, *.suffix or =name", p, i, n)
		}
	}
	if len(a.Deny) == 0 && (a.DenyPrivate == nil || !*a.DenyPrivate) {
		v.errf("%s: denies nothing; set deny_private or name ranges in deny", p)
	}
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

// dnsRecords checks the records this resolver answers itself.
func (v *validator) dnsRecords(p string, d *DNSListener) {
	v.dnsRecordSet(p, d.Records)
	v.dnsViews(p, d)
	v.dns64(p+".dns64", d.DNS64)
	v.dnssecAggressive(p+".dnssec", d.DNSSEC)
	v.dnsRPZ(p+".rpz", d.RPZ)
}

// dnsRPZ checks the response policy zones. The file itself is read at
// load by the resolver, which is where a broken zone fails; what is
// checked here is what a file cannot say.
func (v *validator) dnsRPZ(p string, r *DNSRPZ) {
	if r == nil {
		return
	}
	if len(r.Zones) == 0 {
		v.errf("%s.zones: no zones, so the section does nothing; list them or drop it", p)
	}
	if r.Refresh != nil && *r.Refresh != 0 && r.Refresh.D() < 10*time.Second {
		v.errf("%s.refresh: must be at least 10s, or 0 for never; a feed nobody rewrites that often is a feed this would only stat", p)
	}
	seen := map[string]bool{}
	for i := range r.Zones {
		z := &r.Zones[i]
		q := fmt.Sprintf("%s.zones[%d]", p, i)
		if !nameRE.MatchString(z.Name) {
			v.errf("%s.name: %q is not a valid name", q, z.Name)
		} else if seen[z.Name] {
			v.errf("%s.name: duplicate %q", q, z.Name)
		}
		seen[z.Name] = true
		if z.File == "" {
			v.errf("%s.file: required", q)
		} else {
			v.file(q+".file", z.File)
		}
		switch z.Action {
		case "", dns.RPZZoneAction, dns.RPZNXDomain, dns.RPZNoData, dns.RPZPassthru, dns.RPZDrop, dns.RPZTCPOnly:
		default:
			v.errf("%s.action: must be zone, nxdomain, nodata, passthru, drop or tcp_only", q)
		}
		if z.Action == dns.RPZPassthru {
			v.warnf("%s.action is passthru, so every rule in this zone becomes an exception and the zone blocks nothing", q)
		}
		if z.IgnoreUnsupported {
			v.warnf("%s.ignore_unsupported is on, so the rules of this zone that use an address or name-server trigger are skipped: xproxyctl dns says how many", q)
		}
	}
}

func (v *validator) dnsRecordSet(p string, recs []DNSRecord) {
	for i := range recs {
		r := &recs[i]
		rp := fmt.Sprintf("%s.records[%d]", p, i)
		if r.Name == "" || !hostPatternOK(strings.ToLower(strings.TrimSuffix(r.Name, "."))) {
			v.errf("%s.name: %q is not a name", rp, r.Name)
		}
		if r.TTL < 0 || r.TTL > 604800 {
			v.errf("%s.ttl: must be between 0 and 604800", rp)
		}
		switch r.Type {
		case "", "https":
			r.Type = "https"
		case "svcb":
		case "a", "aaaa":
			// The address family has to match the type, or the record is
			// one no client can read.
			switch addr, err := netip.ParseAddr(r.Address); {
			case err != nil:
				v.errf("%s.address: %q is not an address", rp, r.Address)
			case r.Type == "a" && !addr.Unmap().Is4():
				v.errf("%s.address: %q is not an IPv4 address, which an a record needs", rp, r.Address)
			case r.Type == "aaaa" && addr.Unmap().Is4():
				v.errf("%s.address: %q is not an IPv6 address, which an aaaa record needs", rp, r.Address)
			}
			v.dnsRecordNoSVCB(rp, r)
			continue
		case "txt":
			if r.Text == "" || len(r.Text) > 255 {
				v.errf("%s.text: a txt record needs a string of 1 to 255 bytes", rp)
			}
			v.dnsRecordNoSVCB(rp, r)
			continue
		case "ptr":
			if r.Text == "" || !hostPatternOK(strings.ToLower(strings.TrimSuffix(r.Text, "."))) {
				v.errf("%s.text: a ptr record needs the name it points to", rp)
			}
			v.dnsRecordNoSVCB(rp, r)
			continue
		default:
			v.errf("%s.type: must be https, svcb, a, aaaa, txt or ptr", rp)
		}
		if r.Address != "" || r.Text != "" {
			v.errf("%s: address and text belong to a, aaaa, txt and ptr records", rp)
		}
		if r.Priority < 0 || r.Priority > 65535 {
			v.errf("%s.priority: must be between 0 and 65535", rp)
		}
		if r.Priority == 0 && len(r.Params) > 0 {
			v.errf("%s: priority 0 is an alias record and takes no params", rp)
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

// dnsRecordNoSVCB refuses the SVCB fields on a record type that has none,
// so a record that reads as if it carried parameters does not load
// ignoring them.
func (v *validator) dnsRecordNoSVCB(rp string, r *DNSRecord) {
	if r.Target != "" || len(r.Params) > 0 || r.Priority != 0 {
		v.errf("%s: target, params and priority belong to svcb and https records", rp)
	}
}

// dnssecAggressive checks the RFC 8198 settings, which only mean
// something with validation on.
func (v *validator) dnssecAggressive(p string, d *DNSSEC) {
	if d == nil {
		return
	}
	if d.AggressiveNSEC && !d.IsEnabled() {
		v.errf("%s.aggressive_nsec: needs validation; a proof this resolver has not validated is an attacker choosing which names do not exist", p)
	}
	if d.NSECEntries < 0 || d.NSECEntries > 1_000_000 {
		v.errf("%s.nsec_entries: must be between 0 and 1000000", p)
	}
	if d.NSECEntries > 0 && !d.AggressiveNSEC {
		v.warnf("%s.nsec_entries: set without aggressive_nsec, so nothing is remembered", p)
	}
}

// dns64 checks the address synthesis section.
func (v *validator) dns64(p string, d *DNS64) {
	if d == nil {
		return
	}
	prefix := d.Prefix
	if prefix == "" {
		prefix = dns.WellKnownPrefix
	}
	switch pfx, err := netip.ParsePrefix(prefix); {
	case err != nil:
		v.errf("%s.prefix: %q is not a CIDR", p, d.Prefix)
	case !pfx.Addr().Is6() || pfx.Addr().Is4In6():
		v.errf("%s.prefix: %q is not an IPv6 prefix", p, prefix)
	case !dns.PrefixLengthOK(pfx.Bits()):
		v.errf("%s.prefix: /%d has no defined place for the address; RFC 6052 defines /32, /40, /48, /56, /64 and /96", p, pfx.Bits())
	case pfx.Masked().Addr() != pfx.Addr():
		v.errf("%s.prefix: %q has bits set past its length", p, prefix)
	}
	for i, c := range d.Clients {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			v.errf("%s.clients[%d]: %q is not a CIDR", p, i, c)
			continue
		}
		// A synthesised answer is for a client that has no IPv4 at all;
		// handing one to an IPv4 client would send it through a
		// translator to reach an address it could have dialled directly.
		if pfx.Addr().Unmap().Is4() {
			v.errf("%s.clients[%d]: %q is an IPv4 network, and DNS64 answers clients that have no IPv4", p, i, c)
		}
	}
	if d.TTL < 0 || d.TTL > 604800 {
		v.errf("%s.ttl: must be between 0 and 604800", p)
	}
}

// dnsViews checks the split-horizon views.
func (v *validator) dnsViews(p string, d *DNSListener) {
	seen := map[string]bool{}
	for i := range d.Views {
		w := &d.Views[i]
		vp := fmt.Sprintf("%s.views[%d]", p, i)
		if !nameRE.MatchString(w.Name) {
			v.errf("%s.name: %q is not a name", vp, w.Name)
		}
		if seen[w.Name] {
			v.errf("%s.name: %q is used twice", vp, w.Name)
		}
		seen[w.Name] = true
		if len(w.Clients) == 0 {
			v.errf("%s.clients: at least one network is required; a view that matched everybody is this listener's own policy under another name", vp)
		}
		for j, c := range w.Clients {
			if _, err := netip.ParsePrefix(c); err != nil {
				v.errf("%s.clients[%d]: %q is not a CIDR", vp, j, c)
			}
		}
		switch w.BlockAction {
		case "", "nxdomain", "refuse", "sinkhole":
		default:
			v.errf("%s.block_action: must be nxdomain, refuse or sinkhole", vp)
		}
		for _, pair := range [][2]string{{"sinkhole_ipv4", w.SinkholeIPv4}, {"sinkhole_ipv6", w.SinkholeIPv6}} {
			if pair[1] == "" {
				continue
			}
			if _, err := netip.ParseAddr(pair[1]); err != nil {
				v.errf("%s.%s: %q is not an address", vp, pair[0], pair[1])
			}
		}
		if w.BlockFile != "" {
			v.file(vp+".block_file", w.BlockFile)
		}
		// A view that changes nothing is a section an operator wrote
		// expecting something for it.
		if len(w.Records) == 0 && len(w.Block) == 0 && w.BlockFile == "" && w.BlockAction == "" {
			v.errf("%s: a view must change something: records, block, block_file or block_action", vp)
		}
		v.dnsRecordSet(vp, w.Records)
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
		if len(f.Auth.Groups) > maxForwardGroups {
			v.errf("%s.auth.groups: %d is more than the %d this bounds a listener to",
				p, len(f.Auth.Groups), maxForwardGroups)
		}
		for name, members := range f.Auth.Groups {
			if name == "" {
				v.errf("%s.auth.groups: a group with no name", p)
			}
			if len(members) == 0 {
				v.errf("%s.auth.groups.%s: names no members, so every rule about it is a rule about nobody", p, name)
			}
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
	v.forwardEgress(p, f)
	v.forwardIntercept(p+".intercept", f.Intercept)
	v.masque(p, f)
	if f.SOCKSUDP {
		v.warnf("%s.socks_udp: a UDP association relays datagrams for the client that opened it; it is bound to that client's address and dies with the control connection, but it is a wider exposure than a TCP tunnel", p)
	}
}

// forwardEgress checks the categories and the egress rules.
//
// The checks that matter most here are the two that would otherwise leave an
// operator believing a rule decides something it does not: a category name a
// rule misspells is a rule about nothing, and a rule about a method on a
// destination this listener never sees inside is a rule that cannot run.
func (v *validator) forwardEgress(p string, f *ForwardListener) {
	if !ForwardSNIModes[fwSNIMode(f.SNI)] {
		v.errf("%s.sni: %q is not off, observe or enforce", p, f.SNI)
	}
	if len(f.Categories) > maxForwardCategories {
		v.errf("%s.categories: %d is more than the %d this bounds a listener to",
			p, len(f.Categories), maxForwardCategories)
	}
	cats := map[string]bool{}
	for i := range f.Categories {
		c := &f.Categories[i]
		q := fmt.Sprintf("%s.categories[%d]", p, i)
		switch {
		case c.Name == "":
			v.errf("%s.name: required", q)
		case cats[strings.ToLower(c.Name)]:
			v.errf("%s.name: %q is used twice", q, c.Name)
		default:
			cats[strings.ToLower(c.Name)] = true
		}
		for _, d := range c.Hosts {
			if !destinationPatternOK(d) {
				v.errf("%s.hosts: %q is not a name, *.suffix, address or CIDR", q, d)
			}
		}
		if c.File != "" {
			if !filepath.IsAbs(c.File) {
				v.errf("%s.file: must be an absolute path", q)
			} else {
				v.file(q+".file", c.File)
			}
		}
		if len(c.Hosts) == 0 && c.File == "" {
			v.errf("%s: names no hosts and no file, so every rule about it is a rule about nothing", q)
		}
	}
	if len(f.Rules) > maxForwardRules {
		v.errf("%s.rules: %d is more than the %d this bounds a listener to",
			p, len(f.Rules), maxForwardRules)
	}
	names := map[string]bool{}
	requestLevel := 0
	for i := range f.Rules {
		r := &f.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		switch {
		case r.Name == "":
			v.errf("%s.name: required", q)
		case names[r.Name]:
			v.errf("%s.name: %q is used twice", q, r.Name)
		default:
			names[r.Name] = true
		}
		if r.Action != "" && !ForwardActions[r.Action] {
			v.errf("%s.action: %q is not allow, deny or observe", q, r.Action)
		}
		for _, d := range r.Hosts {
			if !destinationPatternOK(d) {
				v.errf("%s.hosts: %q is not a name, *.suffix, address or CIDR", q, d)
			}
		}
		for _, d := range r.NotHosts {
			if !destinationPatternOK(d) {
				v.errf("%s.not_hosts: %q is not a name, *.suffix, address or CIDR", q, d)
			}
		}
		for _, name := range append(append([]string{}, r.Categories...), r.NotCategories...) {
			if !cats[strings.ToLower(name)] {
				v.errf("%s: names category %q, which this listener does not define", q, name)
			}
		}
		for _, port := range r.Ports {
			if port < 1 || port > 65535 {
				v.errf("%s.ports: %d is not a port", q, port)
			}
		}
		for _, n := range append(append([]string{}, r.Networks...), r.NotNetworks...) {
			if !cidrOrAddr(n) {
				v.errf("%s.networks: %q is not an address or CIDR", q, n)
			}
		}
		for _, m := range r.Methods {
			if m == "" || m != strings.ToUpper(m) || strings.ContainsAny(m, " \t\r\n") {
				v.errf("%s.methods: %q is not an HTTP method in upper case", q, m)
			}
		}
		for _, t := range append(append([]string{}, r.RequestTypes...), r.ResponseTypes...) {
			if !mediaPatternOK(t) {
				v.errf("%s: %q is not a media type or a type/* tree", q, t)
			}
		}
		if r.RequestBytesOver < 0 || r.ResponseBytesOver < 0 {
			v.errf("%s: a byte bound must not be negative", q)
		}
		v.modbusSchedule(q+".schedule", r.Schedule)
		if (len(r.Users) > 0 || len(r.Groups) > 0) && f.Auth == nil {
			v.warnf("%s: names users or groups on a listener with no auth, so the name is always "+
				"empty and this rule matches nobody; add auth, or write the rule about networks", q)
		}
		if fwRequestLevel(r) {
			requestLevel++
		}
	}
	// A rule about a request cannot be decided inside a tunnel nobody opens,
	// which is the one way this policy can look stronger than it is.
	if requestLevel > 0 && f.Intercept == nil {
		v.warnf("%s.rules: %d rule(s) name a method, path, content type or body size, which are "+
			"only visible on a plain request through the proxy -- inside a CONNECT tunnel they "+
			"decide nothing. Add intercept for the destinations they are about, or read them as "+
			"a policy for the plain path only", p, requestLevel)
	}
}

// fwSNIMode fills in the default for the sni setting.
func fwSNIMode(s string) string {
	if s == "" {
		return "observe"
	}
	return s
}

// fwRequestLevel reports whether a rule names something only a visible request
// can answer.
func fwRequestLevel(r *ForwardRule) bool {
	return len(r.Methods) > 0 || len(r.Paths) > 0 || len(r.RequestTypes) > 0 ||
		len(r.ResponseTypes) > 0 || r.RequestBytesOver > 0 || r.ResponseBytesOver > 0
}

// mediaPatternOK accepts "type/subtype" and "type/*", which is as much shape as
// a media type selector needs and no more than can be matched exactly.
func mediaPatternOK(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\r\n;\"") {
		return false
	}
	t, sub, ok := strings.Cut(s, "/")
	if !ok || t == "" || sub == "" || strings.Contains(t, "*") {
		return false
	}
	return sub == "*" || !strings.Contains(sub, "*")
}

// cidrOrAddr accepts a bare address or a CIDR.
func cidrOrAddr(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// Bounds on an egress policy. A listener with a thousand rules is a mistake
// rather than a policy, and both are checked so the table a reload builds
// cannot be unbounded.
const (
	maxForwardCategories = 256
	maxForwardRules      = 512
	maxForwardGroups     = 256
)

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
		v.dpop(pp+".dpop", p.DPoP, p.Source)
		v.tokenExchange(pp+".token_exchange", p.TokenExchange)
		v.certificateBinding(pp+".certificate_binding", p.CertificateBinding)
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
	mediated, wantsTLS, wantsPassword, wantsVeNCrypt := false, false, false, false
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
			if t == rfb.SecVeNCrypt {
				wantsVeNCrypt = true
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
	if c.PasswordFile != "" {
		v.file(p+".password_file", c.PasswordFile)
	}
	if c.UpstreamPasswordFile != "" {
		v.file(p+".upstream_password_file", c.UpstreamPasswordFile)
	}
	for _, name := range c.VeNCryptSubtypes {
		n := strings.ToLower(strings.TrimSpace(name))
		subtype, ok := rfb.SubtypeByName(n)
		if !ok {
			v.errf("%s.vencrypt_subtypes: %q is not a VeNCrypt subtype", p, name)
			continue
		}
		if wantsVeNCrypt && rfb.AuthAfterTLS(subtype) == rfb.SecVNCAuth {
			wantsPassword = true
		}
		if n == "plain" {
			v.errf("%s.vencrypt_subtypes: the bare plain subtype sends the credential with no TLS around it; use x509-plain", p)
		}
		if strings.HasPrefix(n, "tls-") {
			v.warnf("%s.vencrypt_subtypes: %s is anonymous TLS with no certificate to check; the x509 subtypes are the ones that authenticate the gateway", p, n)
		}
	}
	if wantsPassword && c.PasswordFile == "" {
		v.errf("%s.password_file: required with VNC authentication; a challenge with no password is not authentication", p)
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
	// A grant names a person, so this listener has to learn one. RFB carries
	// a name in the same two places the factor needs, and without either the
	// subject would be empty -- which fails closed, refusing every session,
	// and is better said here than discovered in a change window.
	if c.RequireGrant && c.MFA == nil && !hasPlain(c.VeNCryptSubtypes) && !namesUser {
		v.errf("%s.require_grant: needs a security type whose credential carries a user name -- a plain VeNCrypt subtype (x509-plain), or mslogon2 -- or an mfa section, because a grant names a person and there would be nobody to match it against", p)
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
	v.vncPixels(p, c)
	for i, cidr := range c.AllowClients {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			v.errf("%s.allow_clients[%d]: %q is not a CIDR: %v", p, i, cidr, err)
		}
	}
}

// vncPixels checks the pixel stream mode, the clipboard direction and
// the bounds on what a desktop may declare.
func (v *validator) vncPixels(p string, c *VNCListener) {
	switch c.PixelStream {
	case VNCPixelsFramed:
	case VNCPixelsOpaque:
		v.warnf("%s.pixel_stream: opaque forwards the desktop's picture without reading it, so only max_framebuffer_pixels applies and a rectangle that declares more than it carries is not refused. It is the setting for a desktop that must use the tight encoding; framed is the one that bounds what a viewer is asked to allocate", p)
	default:
		v.errf("%s.pixel_stream: must be framed or opaque", p)
	}
	switch c.Clipboard {
	case VNCClipboardBoth, VNCClipboardToClient, VNCClipboardToTarget, VNCClipboardNone:
	default:
		v.errf("%s.clipboard: must be both, to_client, to_target or none", p)
	}
	b := c.Bounds
	if b == nil {
		return
	}
	q := p + ".bounds"
	// 640x480 is the smallest desktop anything serves; a bound under it
	// is a listener where nothing can connect, which is worth saying at
	// load rather than discovering per session.
	if b.MaxFramebufferPixels < 0 {
		v.errf("%s.max_framebuffer_pixels: must not be negative", q)
	} else if b.MaxFramebufferPixels > 0 && b.MaxFramebufferPixels < 640*480 {
		v.errf("%s.max_framebuffer_pixels: %d is smaller than a 640x480 desktop, so no session could start", q, b.MaxFramebufferPixels)
	}
	if b.MaxRectanglesPerUpdate < 0 {
		v.errf("%s.max_rectangles_per_update: must not be negative", q)
	} else if b.MaxRectanglesPerUpdate > 0 && b.MaxRectanglesPerUpdate < 16 {
		v.errf("%s.max_rectangles_per_update: %d is fewer than an ordinary screen redraw, which is tens", q, b.MaxRectanglesPerUpdate)
	}
	if b.MaxEncodedRectangle < 0 {
		v.errf("%s.max_encoded_rectangle: must not be negative", q)
	} else if b.MaxEncodedRectangle > 0 && b.MaxEncodedRectangle < 64<<10 {
		v.errf("%s.max_encoded_rectangle: %d is smaller than one tile of a raw update", q, b.MaxEncodedRectangle)
	}
	if b.MaxDecodeRatio < 0 {
		v.errf("%s.max_decode_ratio: must not be negative", q)
	} else if b.MaxDecodeRatio > 0 && b.MaxDecodeRatio < 4 {
		v.errf("%s.max_decode_ratio: %d would refuse ordinary compression; a screen of flat colour compresses far better than fourfold", q, b.MaxDecodeRatio)
	}
	if b.MaxCutText < 0 {
		v.errf("%s.max_cut_text: must not be negative", q)
	}
	if c.PixelStream == VNCPixelsOpaque && (b.MaxRectanglesPerUpdate > 0 || b.MaxEncodedRectangle > 0 || b.MaxDecodeRatio > 0) {
		v.warnf("%s: max_rectangles_per_update, max_encoded_rectangle and max_decode_ratio need the pixel stream read, and pixel_stream is opaque, so they do nothing here. max_framebuffer_pixels and max_cut_text still apply", q)
	}
}

// sshCertPolicy checks what the listener says about certificates, the
// bounds on what one session may hold, and the two knobs that make a
// command policy weaker than it looks.
func (v *validator) sshCertPolicy(p string, h *SSHListener) {
	if h.RevokedKeys != "" {
		v.file(p+".revoked_keys", h.RevokedKeys)
	}
	switch life := h.MaxCertificateLifetime.D(); {
	case life < 0:
		v.errf("%s.max_certificate_lifetime: must not be negative", p)
	case life > 0 && h.TrustedUserCAKeys == "":
		v.warnf("%s.max_certificate_lifetime: set with no trusted_user_ca_keys, so no certificate ever reaches it", p)
	case life > 0 && life < time.Minute:
		v.errf("%s.max_certificate_lifetime: %s is shorter than any certificate is issued for", p, life)
	}
	if h.MaxForwards < 0 {
		v.errf("%s.max_forwards: must not be negative", p)
	}
	if h.MaxSessionsPerPrincipal < 0 {
		v.errf("%s.max_sessions_per_principal: must not be negative", p)
	}
	if h.MaxSessionsPerPrincipal > 0 && h.MaxSessions > 0 && h.MaxSessionsPerPrincipal > h.MaxSessions {
		v.errf("%s.max_sessions_per_principal: %d is more than max_sessions (%d), so it can never apply",
			p, h.MaxSessionsPerPrincipal, h.MaxSessions)
	}
	switch {
	case h.RekeyBytes < 0:
		v.errf("%s.rekey_bytes: must not be negative", p)
	case h.RekeyBytes > 0 && h.RekeyBytes < 1<<20:
		v.errf("%s.rekey_bytes: %d would rekey every few packets; a megabyte is the smallest useful threshold", p, h.RekeyBytes)
	}
	if h.AllowShellSyntax && len(h.AllowCommands) > 0 {
		v.warnf("%s.allow_shell_syntax: allow_commands is a list of regular expressions over the command line, and with shell syntax allowed one of them can match a line the shell will read as two commands (\"^journalctl .*$\" matches \"journalctl -u x; rm -rf /\"). Write the patterns knowing that, or leave the operators refused", p)
	}
}

// telnetListener checks a telnet gateway.
// telnetDecoyOnly says this listener is nothing but a fabricated device, which is
// the one shape that needs no upstream: there is no equipment behind it.
func telnetDecoyOnly(c *TelnetListener) bool {
	d := c.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// TelnetDecoyProfiles are the machines a fabrication can impersonate.
var TelnetDecoyProfiles = []string{"busybox", "linux"}

// telnetDeception checks the fabricated device.
func (v *validator) telnetDeception(p string, c *TelnetListener) {
	d := c.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener fronts real equipment, and a "+
				"section that would fabricate a device for any client that fails the factor is not a "+
				"decision to arrive at by default", p)
		}
	case "decoy":
		if c.Upstream != "" {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream: use mode answer to "+
				"fabricate the refusals of a listener that fronts real equipment", p)
		}
		// A decoy's own login prompt *is* the trap, and it accepts everybody by
		// design. A second factor in front of it would refuse the visitors the
		// trap exists to collect, and a grant would be checked against a name
		// nobody real typed.
		if c.MFA != nil {
			v.errf("%s.mode: decoy has its own login prompt and accepts every credential, so an mfa "+
				"section would refuse the visitors the trap exists to collect", p)
		}
		if c.RequireGrant {
			v.errf("%s.mode: decoy has nobody real to check a grant for; remove require_grant", p)
		}
		if len(d.Clients) == 0 {
			v.warnf("%s: no clients, so every client that connects reaches the fabricated device. "+
				"That is what a honeypot is for, and on port 23 it will be found within the hour", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	if d.Profile != "" && !slices.Contains(TelnetDecoyProfiles, d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, d.Profile, strings.Join(TelnetDecoyProfiles, ", "))
	}
	if d.Hostname == "" {
		v.warnf("%s.hostname: empty, so the profile's own name is used. Name it after something this "+
			"estate really has: a visitor who finds a recorder called dvr on a site whose recorders are "+
			"called something else has found the fabrication", p)
	}
	if n := d.Attempts; n < 0 || n > 16 {
		v.errf("%s.attempts: must be between 0 and 16", p)
	}
	for i, c := range d.Tripwire {
		if strings.TrimSpace(c) == "" || strings.ContainsAny(c, " \t\r\n") {
			v.errf("%s.tripwire[%d]: %q is not a command name; one name per entry", p, i, c)
		}
	}
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
}

func (v *validator) telnetListener(p string, c *TelnetListener, hasTLS bool) {
	// Telnet carries no identity of its own for a proxy to read: the login
	// the target asks for is between the client and the target, and this
	// gateway never sees it. The name a grant is matched against is the one
	// the factor prompt asks for, so require_grant needs that prompt --
	// without it the subject would be empty, every session would be refused,
	// and the operator would find out in a change window.
	if c.RequireGrant && c.MFA == nil {
		v.errf("%s.require_grant: needs an mfa section on this kind: telnet has no identity of its own, and the login the "+
			"factor prompt asks for is the name a grant is matched against", p)
	}
	v.telnetDeception(p+".deception", c)
	if c.Upstream == "" && !telnetDecoyOnly(c) {
		v.errf("%s.upstream: required", p)
	}
	if !hasTLS && !telnetDecoyOnly(c) {
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
// modbusListener checks the Modbus relay. Every check here is about the
// same thing: this listener sits in front of equipment that does what it
// is told, so a rule that does not do what its author thought is a rule
// that lets somebody write a setpoint.
// oidRE is a dotted-decimal object identifier, which is how LDAP names an
// extended operation and a control.
var oidRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)

// DefaultLDAPDenyAttributes is the password and key material of the
// directories people actually run. It is the built-in deny list an ldap
// listener uses when it names none of its own, because the useful default on
// this protocol is "a relay does not carry password hashes" -- and an
// operator who needs one of these carried can say so.
var DefaultLDAPDenyAttributes = []string{
	"userpassword", "unicodepwd", "dbcspwd", "ntpwdhistory", "lmpwdhistory",
	"pwdhistory", "supplementalcredentials", "msds-managedpassword",
	"ms-mcs-admpwd", "ms-mcs-admpwdexpirationtime", "krbprincipalkey",
	"sambantpassword", "sambalmpassword", "sambapasswordhistory", "userpkcs12",
}

func (v *validator) ldapListener(p string, m *LDAPListener, hasTLS bool) {
	switch m.Mode {
	case "", "reverse", "forward":
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	switch m.TLSMode {
	case "", "implicit", "starttls", "none":
	default:
		v.errf("%s.tls_mode: must be implicit, starttls or none", p)
	}
	if (m.TLSMode == "implicit" || m.TLSMode == "starttls") && !hasTLS {
		v.errf("%s.tls_mode: %s needs the listener's tls section", p, m.TLSMode)
	}
	switch m.UpstreamTLSMode {
	case "", "none", "implicit", "starttls":
	default:
		v.errf("%s.upstream_tls_mode: must be none, implicit or starttls", p)
	}
	if m.UpstreamTLS != nil {
		v.upstreamTLS(p+".upstream_tls", m.UpstreamTLS)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	if len(m.AllowClients) == 0 {
		v.warnf("%s.allow_clients: empty, so any address may reach the directory behind this relay", p)
	}
	requireTLS := m.RequireTLS == nil || *m.RequireTLS
	if !requireTLS && m.TLSMode != "implicit" {
		v.warnf("%s.require_tls: false on a listener that is not TLS throughout, so a simple bind may put a directory password in the clear on the wire", p)
	}
	if m.MinVersion != 0 && (m.MinVersion < 2 || m.MinVersion > 3) {
		v.errf("%s.min_version: must be 2 or 3", p)
	}
	if m.MinVersion == 2 {
		v.warnf("%s.min_version: 2 accepts LDAPv2, which is a different protocol wearing the same tags and has no SASL bind", p)
	}
	methods := v.ldapMethods(p+".methods", m.Methods)
	if methods[ldapwire.MethodUnauthenticated] {
		// This is the one warning on this kind worth reading twice.
		v.warnf("%s.methods: unauthenticated is a simple bind with a name and an *empty* password, which RFC 4513 calls an anonymous bind and most directories answer with success -- the application behind it then reads that success as a correct password", p)
	}
	for i, mech := range m.SASLMechanisms {
		switch {
		case mech == "":
			v.errf("%s.sasl_mechanisms[%d]: empty", p, i)
		case len(mech) > 20:
			v.errf("%s.sasl_mechanisms[%d]: longer than 20 characters", p, i)
		case mech == "PLAIN" && !requireTLS:
			v.warnf("%s.sasl_mechanisms[%d]: PLAIN carries a password exactly as a simple bind does", p, i)
		}
	}
	v.ldapDNs(p+".base_dns", m.BaseDNs)
	if len(m.BaseDNs) == 0 {
		v.warnf("%s.base_dns: empty, so a request may name any object in the directory, including the naming contexts this listener is not for", p)
	}
	if len(m.DenyAttributes) > 0 {
		named := map[string]bool{}
		for i, a := range m.DenyAttributes {
			if a == "" {
				v.errf("%s.deny_attributes[%d]: empty", p, i)
				continue
			}
			named[strings.ToLower(a)] = true
		}
		if !named["userpassword"] {
			v.warnf("%s.deny_attributes: set without userPassword, which replaces the built-in list and lets password hashes through", p)
		}
	}
	switch m.OnDeniedAttribute {
	case "", "strip", "deny":
	default:
		v.errf("%s.on_denied_attribute: must be strip or deny", p)
	}
	if m.MaxEntries < 0 || m.MaxEntries > 1<<20 {
		v.errf("%s.max_entries: must be between 0 and 1048576", p)
	}
	if m.MaxEntries == 0 {
		v.warnf("%s.max_entries: 0 leaves the entries one search may return unbounded, and an unbounded subtree search is how a directory is copied", p)
	}
	if m.MaxFilterTerms < 0 || m.MaxFilterTerms > ldapwire.MaxFilterTerms {
		v.errf("%s.max_filter_terms: must be between 0 and %d", p, ldapwire.MaxFilterTerms)
	}
	if m.MaxFilterDepth < 0 || m.MaxFilterDepth > ldapwire.MaxFilterDepth {
		v.errf("%s.max_filter_depth: must be between 0 and %d", p, ldapwire.MaxFilterDepth)
	}
	for i, oid := range m.ExtendedOperations {
		if !oidRE.MatchString(oid) {
			v.errf("%s.extended_operations[%d]: %q is not an object identifier", p, i, oid)
		}
	}
	for i, oid := range m.DenyControls {
		if !oidRE.MatchString(oid) {
			v.errf("%s.deny_controls[%d]: %q is not an object identifier", p, i, oid)
		}
	}
	switch m.DefaultAction {
	case "", "deny", "allow":
	default:
		v.errf("%s.default_action: must be deny or allow", p)
	}
	if m.DefaultAction == "allow" && len(m.Rules) == 0 && !m.ReadOnly {
		v.warnf("%s: default_action allow with no rules and without read_only relays every modification to the directory", p)
	}
	switch m.DenyResponse {
	case "", "insufficient", "unwilling", "drop", "close":
	default:
		v.errf("%s.deny_response: must be insufficient, unwilling, drop or close", p)
	}
	if m.MaxOutstanding < 0 || m.MaxOutstanding > 1<<16 {
		v.errf("%s.max_outstanding: must be between 0 and 65536", p)
	}
	if m.MaxConnections < 0 || m.MaxConnections > 65536 {
		v.errf("%s.max_connections: must be between 0 and 65536", p)
	}
	for _, d := range []struct {
		key    string
		val    Duration
		lo, hi time.Duration
	}{
		{"idle_timeout", m.IdleTimeout, time.Second, 24 * time.Hour},
		{"request_timeout", m.RequestTimeout, time.Second, 10 * time.Minute},
		{"connect_timeout", m.ConnectTimeout, 100 * time.Millisecond, time.Minute},
	} {
		if d.val != 0 && (d.val.D() < d.lo || d.val.D() > d.hi) {
			v.errf("%s.%s: must be between %s and %s", p, d.key, d.lo, d.hi)
		}
	}
	if m.MaxMessageBytes != 0 && (m.MaxMessageBytes < 1024 || m.MaxMessageBytes > ldapwire.MaxMessage) {
		v.errf("%s.max_message_bytes: must be between 1024 and %d", p, ldapwire.MaxMessage)
	}
	for _, r := range []struct {
		key         string
		rate, burst int
	}{
		{"rate", m.RateLimit, m.RateBurst},
		{"bind_rate", m.BindRateLimit, m.BindRateBurst},
	} {
		if r.rate < 0 || r.rate > 1<<20 {
			v.errf("%s.%s_limit: must be between 0 and 1048576", p, r.key)
		}
		if r.burst < 0 || r.burst > 1<<20 {
			v.errf("%s.%s_burst: must be between 0 and 1048576", p, r.key)
		}
		if r.rate == 0 && r.burst > 0 {
			v.warnf("%s.%s_burst: a burst without a %s_limit bounds nothing", p, r.key, r.key)
		}
	}
	if m.BindRateLimit == 0 {
		v.warnf("%s.bind_rate_limit: 0 leaves binds unbounded, and a bind rate is the one signal that says somebody is trying passwords against the directory", p)
	}
	names := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		if !nameRE.MatchString(r.Name) {
			v.errf("%s.name: %q is not a valid name", q, r.Name)
		} else if names[r.Name] {
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		names[r.Name] = true
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", q)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		v.ldapMethods(q+".methods", r.Methods)
		v.ldapDNs(q+".base_dns", r.BaseDNs)
		v.ldapDNs(q+".deny_dns", r.DenyDNs)
		for j, dn := range r.BindDNs {
			if dn == "" {
				// The empty name is the unbound connection, which is a
				// thing a rule may legitimately be about.
				continue
			}
			if _, err := ldapwire.ParseDN(dn); err != nil {
				v.errf("%s.bind_dns[%d]: %v", q, j, err)
			}
		}
		for j, name := range r.Operations {
			if _, ok := ldapwire.OpOf(name); !ok {
				v.errf("%s.operations[%d]: %q is not an operation (bind, search, compare, modify, add, delete, modify_dn, extended, abandon, unbind)", q, j, name)
			}
		}
		for j, a := range r.Access {
			switch a {
			case "read", "write", "bind":
			default:
				v.errf("%s.access[%d]: %q must be read, write or bind", q, j, a)
			}
		}
		for j, sc := range r.Scopes {
			switch sc {
			case "base", "one", "sub":
			default:
				v.errf("%s.scopes[%d]: %q must be base, one or sub", q, j, sc)
			}
		}
		if r.MaxEntries < 0 || r.MaxEntries > 1<<20 {
			v.errf("%s.max_entries: must be between 0 and 1048576", q)
		}
		if r.MaxFilterTerms < 0 || r.MaxFilterTerms > ldapwire.MaxFilterTerms {
			v.errf("%s.max_filter_terms: must be between 0 and %d", q, ldapwire.MaxFilterTerms)
		}
		if r.MaxFilterDepth < 0 || r.MaxFilterDepth > ldapwire.MaxFilterDepth {
			v.errf("%s.max_filter_depth: must be between 0 and %d", q, ldapwire.MaxFilterDepth)
		}
		v.modbusSchedule(q+".schedule", r.Schedule)
	}
}

// ldapMethods checks a bind-method list and returns it as a set.
func (v *validator) ldapMethods(p string, in []string) map[ldapwire.Method]bool {
	out := map[ldapwire.Method]bool{}
	for i, name := range in {
		m, ok := ldapwire.MethodOf(name)
		if !ok {
			v.errf("%s[%d]: %q must be anonymous, unauthenticated, simple or sasl", p, i, name)
			continue
		}
		out[m] = true
	}
	return out
}

// ldapDNs checks a list of distinguished names.
func (v *validator) ldapDNs(p string, in []string) {
	for i, dn := range in {
		if dn == "" {
			v.errf("%s[%d]: empty; the root is not a suffix worth naming, because it is every suffix", p, i)
			continue
		}
		if _, err := ldapwire.ParseDN(dn); err != nil {
			v.errf("%s[%d]: %v", p, i, err)
		}
	}
}

// opcuaListener checks the OPC UA relay.
//
// Three checks here are worth more than the rest and none of them is a bound. The
// deprecated security policies have to be named twice before they are carried, so
// that switching on SHA-1 is a decision somebody wrote down. The service-level lists
// are warned about when the security modes make them inert, because a rule that
// never runs is worse than no rule at all. And a namespace list of indices is warned
// about, because an index only means something against the server's own namespace
// table and that table's order is not guaranteed across a firmware update.
func (v *validator) opcuaListener(p string, m *OPCUAListener, address string) {
	v.anomaly(p+".anomaly", m.Anomaly)
	v.engineering(p+".engineering", m.Engineering)
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.opcuaPolicies(p, m)
	v.opcuaIdentity(p, m)
	v.opcuaServices(p, m)
	v.opcuaNodes(p, m)
	v.opcuaBounds(p, m)
	v.opcuaLearn(p, m)
	v.opcuaRules(p, m)
	v.opcuaWarnings(p, m, address)
}

// opcuaLearn checks the learning section.
//
// The last warning here is the one worth having: a learning run over a channel whose
// bodies are encrypted records an identity and no address space at all, and an
// operator who does not hear that reads a report with few nodes and concludes the
// plant reads few nodes.
func (v *validator) opcuaLearn(p string, m *OPCUAListener) {
	l := m.Learn
	if l == nil || !l.Enabled {
		return
	}
	switch {
	case l.File == "":
		v.errf("%s.learn.file: required when learning is enabled", p)
	case !strings.HasPrefix(l.File, "/"):
		v.errf("%s.learn.file: must be an absolute path", p)
	}
	if l.Interval != 0 && (l.Interval.D() < 10*time.Second || l.Interval.D() > 24*time.Hour) {
		v.errf("%s.learn.interval: must be between 10s and 24h", p)
	}
	if l.MaxSubjects != 0 && (l.MaxSubjects < 16 || l.MaxSubjects > 1_000_000) {
		v.errf("%s.learn.max_subjects: must be between 16 and 1000000", p)
	}
	if !l.Enforce {
		v.warnf("%s.learn is enabled without enforce, so this listener records and decides nothing: turn enforce on, or take the learning section out, once the rules are written",
			p)
	}
	if v.opcuaAllowsOpaque(m) && !m.RequireReadableBodies {
		v.warnf("%s.learn is enabled and sign_and_encrypt is allowed, so any channel that uses it will teach this run nothing about nodes -- the body is ciphertext. A run meant to learn an address space wants security_modes: [sign] or require_readable_bodies: true for its duration; mode sign still authenticates every message and still detects modification",
			p)
	}
}

// opcuaPolicies checks the security policies and modes.
func (v *validator) opcuaPolicies(p string, m *OPCUAListener) {
	for i, s := range m.SecurityPolicies {
		pol, ok := opcuawire.PolicyOf(s)
		if !ok {
			v.errf("%s.security_policies[%d]: %q is not an OPC UA security policy", p, i, s)
			continue
		}
		if pol.Deprecated() && !m.AllowDeprecatedPolicies {
			// Named in the list and not allowed by the knob. Refusing rather than
			// warning is the point: the list is where somebody added the policy
			// for one old client, and the knob is where the deprecation gets
			// read.
			v.errf("%s.security_policies[%d]: %s was withdrawn in IEC 62541 1.04 (it is SHA-1 based); set allow_deprecated_policies to carry it anyway",
				p, i, pol.Short())
		}
	}
	for i, s := range m.DenySecurityPolicies {
		if _, ok := opcuawire.PolicyOf(s); !ok {
			v.errf("%s.deny_security_policies[%d]: %q is not an OPC UA security policy", p, i, s)
		}
	}
	for i, s := range m.SecurityModes {
		if _, ok := opcuawire.ModeOf(s); !ok {
			v.errf("%s.security_modes[%d]: %q is not a message security mode (none, sign, sign_and_encrypt)",
				p, i, s)
		}
	}
	if d := m.MaxTokenLifetime.D(); d < 0 {
		v.errf("%s.max_token_lifetime: must not be negative", p)
	}
}

// opcuaIdentity checks the token kinds and the user lists.
func (v *validator) opcuaIdentity(p string, m *OPCUAListener) {
	for i, s := range m.TokenKinds {
		if _, ok := opcuawire.TokenOf(s); !ok {
			v.errf("%s.token_kinds[%d]: %q is not an identity token kind (anonymous, username, x509, issued)",
				p, i, s)
		}
	}
	v.opcuaPatterns(p+".application_uris", m.ApplicationURIs)
	v.opcuaPatterns(p+".users", m.Users)
	v.opcuaPatterns(p+".deny_users", m.DenyUsers)
}

// opcuaServices checks the service names and the attributes.
func (v *validator) opcuaServices(p string, m *OPCUAListener) {
	for i, s := range m.Services {
		if _, ok := opcuawire.ServiceOf(s); !ok {
			v.errf("%s.services[%d]: %q is not an OPC UA service", p, i, s)
		}
	}
	for i, s := range m.DenyServices {
		if _, ok := opcuawire.ServiceOf(s); !ok {
			v.errf("%s.deny_services[%d]: %q is not an OPC UA service", p, i, s)
		}
	}
	for i, s := range m.Attributes {
		if _, ok := opcuawire.AttributeOf(s); !ok {
			v.errf("%s.attributes[%d]: %q is not a node attribute", p, i, s)
		}
	}
	for i, s := range m.WriteAttributes {
		if _, ok := opcuawire.AttributeOf(s); !ok {
			v.errf("%s.write_attributes[%d]: %q is not a node attribute", p, i, s)
		}
	}
}

// opcuaNodes checks the namespaces and the node patterns.
func (v *validator) opcuaNodes(p string, m *OPCUAListener) {
	v.opcuaNamespaces(p+".namespaces", m.Namespaces)
	v.opcuaNodePatterns(p+".nodes", m.Nodes)
	v.opcuaNodePatterns(p+".write_nodes", m.WriteNodes)
	v.opcuaNodePatterns(p+".deny_nodes", m.DenyNodes)
	v.opcuaNodePatterns(p+".methods", m.Methods)
	v.opcuaNodePatterns(p+".deny_methods", m.DenyMethods)
}

// opcuaNamespaces checks a namespace list, whose entries are indices and ranges.
//
// A URI is refused with the reason, because it is the form an operator will reach
// for and it cannot work: a namespace URI appears only in an ExpandedNodeId, and the
// node a Read, a Write, a Browse or a Call names is a plain NodeId. A rule written
// with URIs would match nothing while looking exactly as though it should.
func (v *validator) opcuaNamespaces(p string, in []string) {
	for i, s := range in {
		if s == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if strings.ContainsAny(s, ":/") {
			v.errf("%s[%d]: %q looks like a namespace URI, and a namespace can only be named by index here: a URI appears only in an ExpandedNodeId, and the node a Read, a Write, a Browse or a Call names is a plain NodeId",
				p, i, s)
			continue
		}
		if _, err := numrange.Parse("namespace", []string{s}, opcuawire.MaxNamespaces-1); err != nil {
			v.errf("%s[%d]: %v", p, i, err)
		}
	}
}

// opcuaNodePatterns checks node-identifier patterns.
//
// A pattern with no wildcard has to parse as a node identifier, because one that
// does not would match nothing and look like it should match something:
// "ns=3,i=1001" with a comma is the mistake this catches, and it is a mistake an
// operator makes once per configuration file.
func (v *validator) opcuaNodePatterns(p string, in []string) {
	for i, s := range in {
		if s == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if strings.ContainsAny(s, "*?[") {
			if _, err := path.Match(s, ""); err != nil {
				v.errf("%s[%d]: %v", p, i, err)
			}
			continue
		}
		if _, err := opcuawire.ParseNodeId(s); err != nil {
			v.errf("%s[%d]: %v (a node identifier is written ns=3;i=1001, ns=4;s=Motor/Speed or nsu=urn:plant;i=7)",
				p, i, err)
		}
	}
}

// opcuaPatterns checks glob patterns over names.
func (v *validator) opcuaPatterns(p string, in []string) {
	for i, s := range in {
		if s == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if _, err := path.Match(s, ""); err != nil {
			v.errf("%s[%d]: %v", p, i, err)
		}
	}
}

// opcuaBounds checks the numbers.
func (v *validator) opcuaBounds(p string, m *OPCUAListener) {
	for _, b := range []struct {
		name string
		n    int
	}{
		{"max_operations", m.MaxOperations},
		{"max_write_operations", m.MaxWriteOperations},
		{"max_monitored_items", m.MaxMonitoredItems},
		{"max_subscriptions", m.MaxSubscriptions},
		{"max_requests", m.MaxRequests},
		{"max_sessions", m.MaxSessions},
		{"max_sessions_per_client", m.MaxSessionsPerClient},
		{"rate_limit", m.RateLimit},
		{"rate_burst", m.RateBurst},
	} {
		if b.n < 0 {
			v.errf("%s.%s: must not be negative", p, b.name)
		}
	}
	if m.RateBurst > 0 && m.RateLimit == 0 {
		v.errf("%s.rate_burst: set without rate_limit, so nothing is limited", p)
	}
	if m.MaxChunkSize != 0 && (m.MaxChunkSize < opcuawire.MinBuffer || m.MaxChunkSize > opcuawire.MaxMessageSize) {
		v.errf("%s.max_chunk_size: must be between %d and %d; IEC 62541-6 s7.1.2.3 makes %d the smallest buffer a conforming peer may be asked to work with",
			p, opcuawire.MinBuffer, opcuawire.MaxMessageSize, opcuawire.MinBuffer)
	}
	if m.MaxMessageSize != 0 && m.MaxMessageSize < m.MaxChunkSize {
		v.errf("%s.max_message_size: %d is smaller than max_chunk_size %d, so no message could be assembled",
			p, m.MaxMessageSize, m.MaxChunkSize)
	}
	if m.MaxChunks < 0 {
		v.errf("%s.max_chunks: must not be negative", p)
	}
	if m.MaxMessageSize < 0 {
		v.errf("%s.max_message_size: must not be negative", p)
	}
	switch m.DefaultAction {
	case "", "deny", "allow":
	default:
		v.errf("%s.default_action: must be allow or deny", p)
	}
	switch m.DenyResponse {
	case "", "fault", "error", "close", "drop":
	default:
		v.errf("%s.deny_response: must be fault, error, close or drop", p)
	}
	for _, d := range []struct {
		name string
		d    Duration
	}{
		{"idle_timeout", m.IdleTimeout},
		{"session_duration", m.SessionDuration},
		{"handshake_timeout", m.HandshakeTimeout},
		{"min_publishing_interval", m.MinPublishingInterval},
		{"min_sampling_interval", m.MinSamplingInterval},
	} {
		if d.d.D() < 0 {
			v.errf("%s.%s: must not be negative", p, d.name)
		}
	}
}

// opcuaRules checks the rules.
func (v *validator) opcuaRules(p string, m *OPCUAListener) {
	seen := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		switch {
		case r.Name == "":
			v.errf("%s.name: required", q)
		case seen[r.Name]:
			v.errf("%s.name: %q is used twice; a rule's name is how a refusal is attributed", q, r.Name)
		default:
			seen[r.Name] = true
		}
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", q)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		v.opcuaPatterns(q+".application_uris", r.ApplicationURIs)
		v.opcuaPatterns(q+".users", r.Users)
		for j, s := range r.TokenKinds {
			if _, ok := opcuawire.TokenOf(s); !ok {
				v.errf("%s.token_kinds[%d]: %q is not an identity token kind", q, j, s)
			}
		}
		for j, s := range r.SecurityPolicies {
			if _, ok := opcuawire.PolicyOf(s); !ok {
				v.errf("%s.security_policies[%d]: %q is not an OPC UA security policy", q, j, s)
			}
		}
		for j, s := range r.SecurityModes {
			if _, ok := opcuawire.ModeOf(s); !ok {
				v.errf("%s.security_modes[%d]: %q is not a message security mode", q, j, s)
			}
		}
		for j, s := range r.Services {
			if _, ok := opcuawire.ServiceOf(s); !ok {
				v.errf("%s.services[%d]: %q is not an OPC UA service", q, j, s)
			}
		}
		for j, s := range r.DenyServices {
			if _, ok := opcuawire.ServiceOf(s); !ok {
				v.errf("%s.deny_services[%d]: %q is not an OPC UA service", q, j, s)
			}
		}
		for j, s := range r.Attributes {
			if _, ok := opcuawire.AttributeOf(s); !ok {
				v.errf("%s.attributes[%d]: %q is not a node attribute", q, j, s)
			}
		}
		for j, s := range r.WriteAttributes {
			if _, ok := opcuawire.AttributeOf(s); !ok {
				v.errf("%s.write_attributes[%d]: %q is not a node attribute", q, j, s)
			}
		}
		v.opcuaNamespaces(q+".namespaces", r.Namespaces)
		v.opcuaNodePatterns(q+".nodes", r.Nodes)
		v.opcuaNodePatterns(q+".write_nodes", r.WriteNodes)
		v.opcuaNodePatterns(q+".deny_nodes", r.DenyNodes)
		v.opcuaNodePatterns(q+".methods", r.Methods)
		v.opcuaNodePatterns(q+".deny_methods", r.DenyMethods)
		if r.MaxOperations < 0 {
			v.errf("%s.max_operations: must not be negative", q)
		}
		if r.Schedule != nil {
			v.modbusSchedule(q+".schedule", r.Schedule)
		}
	}
}

// opcuaWarnings is what loads and is worth saying out loud.
func (v *validator) opcuaWarnings(p string, m *OPCUAListener, address string) {
	if len(m.AllowClients) == 0 {
		v.warnf("%s.allow_clients: empty, so every client the deny list does not refuse may reach a plant; an OPC UA server usually has four or five clients and they do not move",
			p)
	}
	if m.AllowDeprecatedPolicies {
		v.warnf("%s.allow_deprecated_policies: Basic128Rsa15 and Basic256 are SHA-1 based and were withdrawn in IEC 62541 1.04; they are usually switched on for one old client, and that client is the exposure",
			p)
	}
	// The mode and the service rules. This is the warning that matters most,
	// because the configuration reads as though it is enforcing something it is
	// not: a listener with rules about nodes over a sign_and_encrypt channel is a
	// listener whose rules never see a body.
	if v.opcuaHasServiceRules(m) && v.opcuaAllowsOpaque(m) && !m.RequireReadableBodies {
		v.warnf("%s: there are rules about nodes, attributes or methods and sign_and_encrypt is allowed, so those rules will not apply to any channel that uses it -- the body is ciphertext. Set require_readable_bodies to refuse that mode, or accept that the service rules apply only to none and sign channels",
			p)
	}
	if m.RequireReadableBodies {
		v.warnf("%s.require_readable_bodies: sign_and_encrypt will be refused, so nothing on this hop is confidential; mode sign still authenticates every message and still detects modification, which is the trade this knob makes",
			p)
	}
	if len(m.Namespaces) > 0 {
		// An index is meaningful only against the table it came from, and there
		// is no portable form available here: the wire names a namespace by index
		// in every request a policy decides about. So the caveat is a review
		// item rather than a thing to configure around.
		v.warnf("%s.namespaces: a namespace index only means something against the server's own namespace table, whose order is not guaranteed across a firmware update; this list is one to review after one, because the same indices can then name different nodes",
			p)
	}
	if m.ReadOnly && len(m.WriteNodes) > 0 {
		v.warnf("%s.write_nodes: set on a read_only listener, where no writing service is carried at all, so the list decides nothing", p)
	}
	if m.MinPublishingInterval.D() == 0 {
		v.warnf("%s.min_publishing_interval: unset, so a client may ask for a publishing interval of zero -- which over a thousand monitored items is a server asked to send a thousand values a millisecond, from one session, in valid protocol",
			p)
	}
	if m.MaxOperations == 0 {
		v.warnf("%s.max_operations: unset, so one Read may name as many nodes as a message holds; a request naming ten thousand nodes is one request and ten thousand operations",
			p)
	}
	if _, port, err := net.SplitHostPort(address); err == nil &&
		port != "4840" && port != "0" {
		v.warnf("%s: port %s, where an OPC UA client sends to 4840 by convention; a client that discovered this endpoint from a discovery server will not find it here",
			p, port)
	}
}

// opcuaHasServiceRules says the listener names anything the service level decides.
func (v *validator) opcuaHasServiceRules(m *OPCUAListener) bool {
	if len(m.Nodes) > 0 || len(m.WriteNodes) > 0 || len(m.DenyNodes) > 0 ||
		len(m.Methods) > 0 || len(m.DenyMethods) > 0 ||
		len(m.Attributes) > 0 || len(m.WriteAttributes) > 0 || len(m.Namespaces) > 0 {
		return true
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		if len(r.Nodes) > 0 || len(r.WriteNodes) > 0 || len(r.DenyNodes) > 0 ||
			len(r.Methods) > 0 || len(r.DenyMethods) > 0 ||
			len(r.Attributes) > 0 || len(r.WriteAttributes) > 0 || len(r.Namespaces) > 0 {
			return true
		}
	}
	return false
}

// opcuaAllowsOpaque says a channel that encrypts its bodies would be carried.
func (v *validator) opcuaAllowsOpaque(m *OPCUAListener) bool {
	if len(m.SecurityModes) == 0 {
		// The default allows sign and sign_and_encrypt.
		return true
	}
	for _, s := range m.SecurityModes {
		if mode, ok := opcuawire.ModeOf(s); ok && !mode.Readable() {
			return true
		}
	}
	return false
}

// coapListener checks the CoAP relay.
func (v *validator) coapListener(p string, m *CoAPListener, address string, tc *TLS) {
	v.anomaly(p+".anomaly", m.Anomaly)
	v.engineering(p+".engineering", m.Engineering)
	dtls := tc != nil
	switch m.Mode {
	case "", "reverse", "forward":
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.modbusCIDRs(p+".allow_servers", m.AllowServers)
	for i, s := range m.MessageTypes {
		if _, ok := coapTypeNames[s]; !ok {
			v.errf("%s.message_types[%d]: %q is not a CoAP message type", p, i, s)
		}
	}
	for i, s := range m.Methods {
		if !coapMethod(s) {
			v.errf("%s.methods[%d]: %q is not a CoAP method", p, i, s)
		}
	}
	v.coapPatterns(p+".allow_paths", m.AllowPaths)
	v.coapPatterns(p+".deny_paths", m.DenyPaths)
	v.coapFormats(p+".content_formats", m.ContentFormats)
	switch {
	case m.MaxPayloadBytes < 0:
		v.errf("%s.max_payload_bytes: must not be negative", p)
	case m.MaxPayloadBytes > 65535:
		v.errf("%s.max_payload_bytes: %d is past a datagram", p, m.MaxPayloadBytes)
	}
	if m.MaxBlockBytes != 0 && !coapBlockSize(m.MaxBlockBytes) {
		v.errf("%s.max_block_bytes: must be a power of two from 16 to 1024 (RFC 7959 s2.2)",
			p)
	}
	if m.MaxTransferBytes < 0 {
		v.errf("%s.max_transfer_bytes: must not be negative", p)
	}
	if m.MaxMessageBytes != 0 && (m.MaxMessageBytes < 16 || m.MaxMessageBytes > 8192) {
		v.errf("%s.max_message_bytes: must be between 16 and 8192", p)
	}
	if m.MaxResponseBytes < 0 {
		v.errf("%s.max_response_bytes: must not be negative", p)
	}
	if m.AmplificationFactor < 0 {
		v.errf("%s.amplification_factor: must not be negative", p)
	}
	switch m.DefaultAction {
	case "", "deny", "allow":
	default:
		v.errf("%s.default_action: must be allow or deny", p)
	}
	if d := m.RequestTimeout.D(); d != 0 && (d < time.Second || d > time.Minute) {
		v.errf("%s.request_timeout: must be between 1s and 1m", p)
	}
	v.coapBounds(p, m)
	v.coapIdentities(p, m, dtls)
	v.coapRules(p, m)
	v.coapWarnings(p, m, address, tc)
}

// coapIdentities checks the two tables that turn a DTLS peer into a name: the
// pre-shared keys and the pinned public keys.
//
// Everything here is checked at load because the alternative is a listener
// that refuses every handshake, or worse accepts one and maps it to nothing:
// on this protocol the identity *is* the identity, and a table with a typo in
// it is a policy about a device that will never connect.
func (v *validator) coapIdentities(p string, m *CoAPListener, dtls bool) {
	names := map[string]bool{}
	if m.PSK != nil {
		q := p + ".psk"
		// A table with no tls section is not an error: it is a PSK-only
		// listener, which is the ordinary shape on a segment whose devices
		// have no certificate machinery -- and whose estate therefore usually
		// has no authority of its own. RFC 7252 s9.1.3.1's mode needs no
		// certificate at either end.
		if len(m.PSK.Identities) == 0 {
			v.errf("%s.identities: required: a psk section with no identities offers the mode and holds no key, so every handshake in it fails", q)
		}
		if len(m.PSK.Hint) > dtlsx.MaxPSKIdentity {
			v.errf("%s.hint: %d octets, past the %d-octet bound", q, len(m.PSK.Hint), dtlsx.MaxPSKIdentity)
		}
		if len(m.PSK.Identities) > dtlsx.MaxPSKEntries {
			v.errf("%s.identities: %d entries, past the bound of %d", q, len(m.PSK.Identities), dtlsx.MaxPSKEntries)
		}
		seen := map[string]bool{}
		for i := range m.PSK.Identities {
			id := &m.PSK.Identities[i]
			r := fmt.Sprintf("%s.identities[%d]", q, i)
			switch {
			case id.Identity == "":
				v.errf("%s.identity: required: an empty identity is the row every client that names nothing would reach", r)
			case len(id.Identity) > dtlsx.MaxPSKIdentity:
				v.errf("%s.identity: %d octets, past the %d-octet bound", r, len(id.Identity), dtlsx.MaxPSKIdentity)
			case seen[id.Identity]:
				v.errf("%s.identity: %q appears twice, and two keys for one identity is a table nobody can read", r, id.Identity)
			default:
				seen[id.Identity] = true
			}
			if id.Key == "" {
				v.errf("%s.key: required", r)
			} else {
				v.secretRef(r+".key", id.Key)
			}
			if id.Name != "" {
				names[id.Name] = true
			} else if id.Identity != "" {
				names[id.Identity] = true
			}
		}
	}
	prints := map[string]bool{}
	for i := range m.PublicKeys {
		k := &m.PublicKeys[i]
		r := fmt.Sprintf("%s.public_keys[%d]", p, i)
		if !dtls {
			// Unlike a pre-shared key, a pinned key is read out of the
			// certificate a peer presents -- so the listener has to be doing a
			// certificate handshake, which is what the tls section is.
			v.errf("%s: a pinned public key is read from the certificate a peer presents, and this listener has no tls section to ask for one", r)
		}
		sum, err := dtlsx.ParseKeyFingerprint(k.Fingerprint)
		switch {
		case err != nil:
			v.errf("%s.fingerprint: %v", r, err)
		case prints[sum]:
			v.errf("%s.fingerprint: the same key appears twice", r)
		default:
			prints[sum] = true
		}
		if k.Name == "" {
			v.errf("%s.name: required: a pinned key with no name authenticates a peer and tells the policy nothing", r)
		} else {
			names[k.Name] = true
		}
	}
	// A rule naming a security name that no table produces is a rule that
	// never matches, which reads in a file as a control and is not one.
	for i := range m.Rules {
		for j, want := range m.Rules[i].SecurityNames {
			if names[want] {
				continue
			}
			v.errf("%s.rules[%d].security_names[%d]: %q is not a name any psk identity or public key maps to, so this rule can never match",
				p, i, j, want)
		}
	}
	if m.RequireSecurityName != nil && *m.RequireSecurityName && len(names) == 0 {
		v.errf("%s.require_security_name: true with no psk identities and no public keys, so every message would be refused: there is nothing for a peer to map to", p)
	}
}

// coapBounds checks the table sizes and the rate.
func (v *validator) coapBounds(p string, m *CoAPListener) {
	if m.MaxPending < 0 {
		v.errf("%s.max_pending: must not be negative", p)
	}
	if m.MaxClients < 0 {
		v.errf("%s.max_clients: must not be negative", p)
	}
	if m.MaxObservers < 0 {
		v.errf("%s.max_observers: must not be negative", p)
	}
	if m.RateLimit < 0 || m.RateBurst < 0 {
		v.errf("%s.rate_limit: must not be negative", p)
	}
	if m.RateBurst > 0 && m.RateLimit == 0 {
		v.errf("%s.rate_burst: set without rate_limit, so nothing is limited", p)
	}
}

func (v *validator) coapRules(p string, m *CoAPListener) {
	seen := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		if r.Name == "" {
			v.errf("%s.name: required", q)
		}
		if seen[r.Name] {
			v.errf("%s.name: %q is used twice, so the logs cannot tell them apart", q, r.Name)
		}
		seen[r.Name] = true
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", q)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		for j, s := range r.Methods {
			if !coapMethod(s) {
				v.errf("%s.methods[%d]: %q is not a CoAP method", q, j, s)
			}
		}
		v.coapPatterns(q+".paths", r.Paths)
		v.coapFormats(q+".content_formats", r.ContentFormats)
		if r.MaxPayloadBytes < 0 {
			v.errf("%s.max_payload_bytes: must not be negative", q)
		}
		if r.Schedule != nil {
			v.modbusSchedule(q+".schedule", r.Schedule)
		}
	}
}

// coapWarnings are the configurations that load and are probably not what the
// operator meant.
func (v *validator) coapWarnings(p string, m *CoAPListener, address string, tc *TLS) {
	if tc == nil && (m.PSK == nil || len(m.PSK.Identities) == 0) {
		v.warnf("%s: no tls section and no psk identities, so this listener is CoAP NoSec: there is no identity of any kind, and a rule can name only the source address. RFC 7252 s9 puts CoAP inside DTLS on 5684, and most of the field does not -- which is why this warns rather than refuses", p)
	}
	if _, port, err := net.SplitHostPort(address); err == nil &&
		port != "5683" && port != "5684" && port != "0" {
		v.warnf("%s: port %s, where a CoAP client sends to 5683 in the clear and 5684 inside DTLS", p, port)
	}
	if m.DefaultAction != "allow" && len(m.Rules) == 0 {
		v.warnf("%s: default_action is deny and no rules are written, so this listener refuses every request. The paths are the device's object model, so a rule naming them is how an estate says what may be done", p)
	}
	if m.AllowProxying {
		v.warnf("%s.allow_proxying: true, so a client may send Proxy-Uri or Proxy-Scheme and have the device fetch a URI of the client's choosing. On a constrained network that is an open forward proxy, an amplification stage and a way to reach what the segment was built to protect", p)
	}
	if m.AmplificationFactor == 0 && m.MaxResponseBytes == 0 {
		v.warnf("%s: neither amplification_factor nor max_response_bytes is set, so a four-octet request may return whatever a device will send -- which is what makes CoAP over UDP a reflection amplifier", p)
	}
	if coapOn(m.AllowObserve) && m.MaxObservers == 0 {
		// Not a warning worth making: the default bound applies. Left as a note
		// so the next reader does not add one.
		_ = m
	}
	if !coapOn(m.RefuseUnknownOptions) {
		v.warnf("%s.refuse_unknown_options: false, so an option this relay cannot name is forwarded. RFC 7252 s5.7.1 says a proxy must not forward an UnSafe option it does not recognise, because forwarding an option whose meaning is unknown is forwarding a request whose meaning is unknown", p)
	}
	if !coapOn(m.RefuseSuspiciousPaths) {
		v.warnf("%s.refuse_suspicious_paths: false, so a path segment containing a separator is carried -- and then one segment renders as two, which is how a rule about /sensors/* is satisfied by a request to /config", p)
	}
	if !coapOn(m.AnswerRefusals) {
		v.warnf("%s.answer_refusals: false, so a refused request is dropped. A Confirmable request is retransmitted until something answers, so each refusal becomes four or five more requests and the device's own logs show a timeout rather than a refusal", p)
	}
	if m.PSK != nil && len(m.PSK.Identities) > 0 && !m.RequiresSecurityName() {
		v.warnf("%s.require_security_name: false with a psk table, so a session that authenticated some other way -- a certificate this listener also accepts -- carries no name, and every rule naming security_names is silently not about it", p)
	}
	if len(m.PublicKeys) > 0 && !coapAsksForAKey(tc) {
		// The pin is on the key inside the certificate the peer sent, and a
		// listener that does not ask for one gets no key to pin.
		v.warnf("%s.public_keys: a pinned key is read from the certificate the peer presents, and this listener's tls section does not ask for one. Set tls.client_auth: require_any, which is the shape a raw public key takes here -- the key is pinned by this table rather than vouched for by an authority, so there is nothing for require (with client_ca_file) to verify it against", p)
	}
	if coapOn(m.AllowDiscovery) && len(m.AllowPaths) == 0 && len(m.Rules) == 0 {
		v.warnf("%s: /.well-known/core is carried and no path policy is written, so a client may ask any device for a list of every resource it has -- the largest answer on the device for the smallest question (RFC 6690)", p)
	}
}

func (v *validator) coapPatterns(p string, pats []string) {
	for i, s := range pats {
		if s == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if !strings.HasPrefix(s, "/") {
			v.errf("%s[%d]: %q must start with a slash: a CoAP path policy is matched against the whole path", p, i, s)
		}
		if _, err := path.Match(strings.TrimSuffix(s, "/..."), "/x"); err != nil {
			v.errf("%s[%d]: %q is not a valid pattern: %v", p, i, s, err)
		}
	}
}

func (v *validator) coapFormats(p string, in []string) {
	for i, s := range in {
		if _, ok := coapFormatNames[s]; ok {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 65535 {
			v.errf("%s[%d]: %q is not a media type this relay names or a number from 0 to 65535", p, i, s)
		}
	}
}

// The names the CoAP validator accepts, kept here rather than imported so that
// internal/config depends on no kind.
var coapTypeNames = map[string]bool{
	"con": true, "confirmable": true, "non": true, "non_confirmable": true,
	"ack": true, "acknowledgement": true, "rst": true, "reset": true,
}

// coapOn reads a switch whose default is on, so that a warning about it being
// turned off fires only when it was turned off.
func coapOn(p *bool) bool { return p == nil || *p }

func coapMethod(s string) bool {
	switch s {
	case "get", "GET", "post", "POST", "put", "PUT", "delete", "DELETE",
		"fetch", "FETCH", "patch", "PATCH", "ipatch", "iPATCH", "IPATCH":
		return true
	}
	return false
}

// coapBlockSize says the value is one of the block sizes RFC 7959 s2.2 defines:
// a power of two from sixteen to a kilobyte, because the option carries the
// exponent rather than the size.
func coapBlockSize(n int) bool {
	for s := 16; s <= 1024; s *= 2 {
		if n == s {
			return true
		}
	}
	return false
}

var coapFormatNames = map[string]bool{
	"text/plain": true, "application/link-format": true, "application/xml": true,
	"application/octet-stream": true, "application/exi": true,
	"application/json": true, "application/json-patch+json": true,
	"application/merge-patch+json": true, "application/cbor": true,
	"application/cwt": true, "application/multipart-core": true,
	"application/cbor-seq": true, "application/senml+json": true,
	"application/sensml+json": true, "application/senml+cbor": true,
	"application/sensml+cbor": true, "application/coap-group+json": true,
	"application/dots+cbor": true, "application/missing-blocks+cbor-seq": true,
	"application/vnd.oma.lwm2m+tlv": true, "application/vnd.oma.lwm2m+json": true,
	"application/cose; cose-type=cose-encrypt0": true,
	"application/cose; cose-type=cose-mac0":     true,
	"application/cose; cose-type=cose-sign1":    true,
}

// dhcp6Listener checks the DHCPv6 relay.
func (v *validator) dhcp6Listener(p string, m *DHCP6Listener, address string) {
	switch m.Mode {
	case "", "reverse", "forward":
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.modbusCIDRs(p+".allow_servers", m.AllowServers)
	v.dhcp6Addrs(p+".allow_resolvers", m.AllowResolvers)
	v.dhcp6Types(p+".message_types", m.MessageTypes)
	v.dhcp6Options(p+".deny_options", m.DenyOptions)
	v.dhcp6Options(p+".allow_options", m.AllowOptions)
	v.dhcp6Options(p+".deny_requested_options", m.DenyRequestedOptions)
	v.dhcpPatterns(p+".allow_domains", m.AllowDomains)
	v.dhcpPatterns(p+".allow_boot_urls", m.AllowBootURLs)
	if len(m.DenyOptions) > 0 && len(m.AllowOptions) > 0 {
		v.errf("%s: deny_options and allow_options are two ways of writing the same policy; set one", p)
	}
	if len(m.DenyOptions) > 0 {
		// The list replaces the built-in one, so an operator who wrote a
		// shorter one has turned protections off without meaning to.
		missing := make([]string, 0, 4)
		named := map[uint16]bool{}
		for _, s := range m.DenyOptions {
			if c, ok := dhcp6.OptionOf(s); ok {
				named[c] = true
			}
		}
		for _, c := range dhcp6.DangerousOptions {
			if !named[c] {
				missing = append(missing, dhcp6.OptionName(c))
			}
		}
		if len(missing) > 0 {
			v.warnf("%s.deny_options replaces the built-in list, and leaves out %s: each of those carries a configuration rather than a value, and a server that sends one is configuring the client",
				p, strings.Join(missing, ", "))
		}
	}
	switch m.OnDeniedOption {
	case "", "strip", "deny":
	default:
		v.errf("%s.on_denied_option: must be strip or deny", p)
	}
	switch m.OnClientRelayOption {
	case "", "strip", "deny":
	default:
		v.errf("%s.on_client_relay_option: must be strip or deny", p)
	}
	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: must be allow or deny", p)
	}
	if m.MaxRelayHops != 0 && (m.MaxRelayHops < 1 || m.MaxRelayHops > dhcp6.MaxHopCount) {
		v.errf("%s.max_relay_hops: must be between 1 and %d", p, dhcp6.MaxHopCount)
	}
	if m.MaxMessageBytes != 0 && (m.MaxMessageBytes < 128 || m.MaxMessageBytes > dhcp6.MaxMessage) {
		v.errf("%s.max_message_bytes: must be between 128 and %d", p, dhcp6.MaxMessage)
	}
	if m.MaxPending != 0 && (m.MaxPending < 1 || m.MaxPending > 1<<20) {
		v.errf("%s.max_pending: must be between 1 and 1048576", p)
	}
	if m.MaxClients != 0 && (m.MaxClients < 1 || m.MaxClients > 1<<20) {
		v.errf("%s.max_clients: must be between 1 and 1048576", p)
	}
	if d := m.RequestTimeout; d != 0 && (d.D() < time.Second || d.D() > time.Minute) {
		v.errf("%s.request_timeout: must be between 1s and 1m", p)
	}
	if m.RateLimit < 0 || m.RateBurst < 0 {
		v.errf("%s.rate_limit and rate_burst cannot be negative", p)
	}
	if m.MinLeaseTime != 0 && m.MaxLeaseTime != 0 && m.MinLeaseTime.D() > m.MaxLeaseTime.D() {
		v.errf("%s: min_lease_time is longer than max_lease_time", p)
	}
	if m.RemoteIDEnterprise < 0 || m.RemoteIDEnterprise > 0xffffffff {
		v.errf("%s.remote_id_enterprise: must be a 32-bit enterprise number", p)
	}
	if m.RemoteID != "" && m.RemoteIDEnterprise == 0 {
		v.warnf("%s.remote_id has no remote_id_enterprise, so it goes out under enterprise number 0: RFC 4649 s3 puts the number first, and a server that indexes on it will not find this relay where it expects", p)
	}
	v.dhcp6Prefixes(p+".prefix_delegation", m.PrefixDelegation)
	if m.Mode != "forward" && m.LinkAddress == "" {
		v.errf("%s.link_address: required in reverse mode: a relay agent that left it unspecified would be asking the server to guess which segment to allocate from", p)
	}
	if m.LinkAddress != "" {
		a, err := netip.ParseAddr(m.LinkAddress)
		switch {
		case err != nil:
			v.errf("%s.link_address: %q is not an address", p, m.LinkAddress)
		case !a.Is6() || a.Is4In6():
			v.errf("%s.link_address: %q is not an IPv6 address", p, m.LinkAddress)
		case a.IsLinkLocalUnicast():
			v.errf("%s.link_address: %q is link-local, which tells a server nothing about which segment to allocate from", p, m.LinkAddress)
		}
	}
	if m.AllowReconfigure {
		v.warnf("%s.allow_reconfigure carries a RECONFIGURE from a server: it is a message to a client that answers nothing, RFC 8415 s18.3.11 requires it to be authenticated with a key almost nobody deploys, and a client that accepts one can be made to re-ask a server of the sender's choosing", p)
	}
	if len(m.AllowResolvers) == 0 {
		v.warnf("%s.allow_resolvers: empty, so any resolver a server names is carried. An estate knows its own resolvers, and a reply naming anything else is wrong whoever sent it -- which is the check that catches a compromised real server as well as a rogue one", p)
	}
	if _, port, err := net.SplitHostPort(address); err == nil && port != "547" && port != "0" {
		v.warnf("%s is on port %s rather than 547: a DHCPv6 client sends to 547 and nothing else will reach this listener", p, port)
	}
	names := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		rp := fmt.Sprintf("%s.rules[%d]", p, i)
		if r.Name == "" {
			v.errf("%s.name: required", rp)
		} else if names[r.Name] {
			v.errf("%s.name: %q is used twice", rp, r.Name)
		}
		names[r.Name] = true
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", rp)
		}
		v.modbusCIDRs(rp+".clients", r.Clients)
		v.dhcp6Types(rp+".message_types", r.MessageTypes)
		v.dhcp6Options(rp+".deny_options", r.DenyOptions)
		v.dhcp6Addrs(rp+".allow_resolvers", r.AllowResolvers)
		v.dhcpPatterns(rp+".duids", r.DUIDs)
		v.dhcpPatterns(rp+".vendor_classes", r.VendorClasses)
		v.dhcpPatterns(rp+".user_classes", r.UserClasses)
		v.dhcpPatterns(rp+".allow_domains", r.AllowDomains)
		v.dhcpPatterns(rp+".allow_boot_urls", r.AllowBootURLs)
		v.modbusSchedule(rp+".schedule", r.Schedule)
	}
}

// dhcp6Prefixes checks the prefix delegation policy.
func (v *validator) dhcp6Prefixes(p string, pd *DHCP6PrefixPolicy) {
	if pd == nil {
		return
	}
	for i, s := range pd.Prefixes {
		pfx, err := netip.ParsePrefix(s)
		switch {
		case err != nil:
			v.errf("%s.prefixes[%d]: %q is not a network", p, i, s)
		case !pfx.Addr().Is6() || pfx.Addr().Is4In6():
			v.errf("%s.prefixes[%d]: %q is not an IPv6 network", p, i, s)
		case pfx.Bits() == 0:
			v.errf("%s.prefixes[%d]: ::/0 is every prefix there is, which is not a bound", p, i)
		}
	}
	for _, b := range []struct {
		key string
		val int
	}{{"min_length", pd.MinLength}, {"max_length", pd.MaxLength}} {
		if b.val != 0 && (b.val < 1 || b.val > 128) {
			v.errf("%s.%s: must be between 1 and 128", p, b.key)
		}
	}
	if pd.MinLength != 0 && pd.MaxLength != 0 && pd.MinLength > pd.MaxLength {
		v.errf("%s: min_length is longer than max_length", p)
	}
	if pd.Delegating() && len(pd.Prefixes) == 0 && pd.MaxLength == 0 {
		v.warnf("%s: prefix delegation is carried with no prefixes and no length bound, so a reply delegating ::/0 is forwarded -- which hands a host the whole of IPv6 to route", p)
	}
}

// dhcp6Types checks a list of DHCPv6 message type names.
func (v *validator) dhcp6Types(p string, in []string) {
	for i, s := range in {
		t, ok := dhcp6.TypeOf(s)
		if !ok {
			v.errf("%s[%d]: %q is not a DHCPv6 message type", p, i, s)
			continue
		}
		if t.IsRelay() {
			v.errf("%s[%d]: %q is a relay agent's own message, not one a client sends", p, i, s)
		}
	}
}

// dhcp6Options checks a list of DHCPv6 option names or numbers.
func (v *validator) dhcp6Options(p string, in []string) {
	for i, s := range in {
		if _, ok := dhcp6.OptionOf(s); !ok {
			v.errf("%s[%d]: %q is not a DHCPv6 option name or number", p, i, s)
		}
	}
}

// dhcp6Addrs checks a list of IPv6 addresses.
func (v *validator) dhcp6Addrs(p string, in []string) {
	for i, s := range in {
		a, err := netip.ParseAddr(s)
		switch {
		case err != nil:
			v.errf("%s[%d]: %q is not an address", p, i, s)
		case !a.Is6() || a.Is4In6():
			v.errf("%s[%d]: %q is not an IPv6 address", p, i, s)
		}
	}
}

func (v *validator) dhcpListener(p string, m *DHCPListener) {
	switch m.Mode {
	case "", "reverse", "forward":
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.modbusCIDRs(p+".allow_servers", m.AllowServers)
	v.modbusCIDRs(p+".allow_routes", m.AllowRoutes)
	v.dhcpAddrs(p+".allow_gateways", m.AllowGateways)
	v.dhcpAddrs(p+".allow_resolvers", m.AllowResolvers)
	v.dhcpAddrs(p+".allow_boot_servers", m.AllowBootServers)
	v.dhcpTypes(p+".message_types", m.MessageTypes)
	denied := v.dhcpOptions(p+".deny_options", m.DenyOptions)
	allowed := v.dhcpOptions(p+".allow_options", m.AllowOptions)
	v.dhcpOptions(p+".deny_requested_options", m.DenyRequestedOptions)
	v.dhcpPatterns(p+".boot_files", m.BootFiles)
	if len(m.DenyOptions) > 0 {
		// The list replaces the built-in one, so an operator who wrote a
		// shorter list has quietly allowed what they left out. The two worth
		// naming are the ones that are a route and a proxy.
		for _, c := range []uint8{dhcpwire.OptClasslessRoute, dhcpwire.OptWPAD} {
			if !denied[c] {
				v.warnf("%s.deny_options: set without %s, which replaces the built-in list and lets it through",
					p, dhcpwire.OptionName(c))
			}
		}
	}
	if len(m.AllowOptions) > 0 {
		// A positive list that leaves out the address's own terms is a list
		// that hands out an address nothing can use.
		for _, c := range []uint8{dhcpwire.OptSubnetMask, dhcpwire.OptLeaseTime} {
			if !allowed[c] {
				v.warnf("%s.allow_options: does not include %s, so a client would be given an address it cannot use",
					p, dhcpwire.OptionName(c))
			}
		}
		for _, c := range m.DenyOptions {
			if code, ok := dhcpwire.OptionOf(c); ok && allowed[code] {
				v.errf("%s: %s is in both allow_options and deny_options", p, dhcpwire.OptionName(code))
			}
		}
	}
	switch m.OnDeniedOption {
	case "", "strip", "deny":
	default:
		v.errf("%s.on_denied_option: must be strip or deny", p)
	}
	switch m.OnClientAgentOption {
	case "", "strip", "deny":
	default:
		v.errf("%s.on_client_agent_option: must be strip or deny", p)
	}
	reverse := m.Mode == "" || m.Mode == "reverse"
	if m.RelayAddress == "" {
		if reverse {
			v.errf("%s.relay_address: required in reverse mode: a relay agent that left giaddr empty would be asking the server to answer a broadcast it never saw", p)
		}
	} else if a, err := netip.ParseAddr(m.RelayAddress); err != nil || !a.Is4() {
		v.errf("%s.relay_address: %q is not an IPv4 address", p, m.RelayAddress)
	} else if a.IsUnspecified() {
		v.errf("%s.relay_address: 0.0.0.0 is what an unrelayed message carries, so it is not an address a relay can claim", p)
	}
	for _, s := range []struct {
		key, val string
	}{{"circuit_id", m.CircuitID}, {"remote_id", m.RemoteID}} {
		if len(s.val) > 255 {
			v.errf("%s.%s: longer than the 255 octets a suboption holds", p, s.key)
		}
	}
	if m.MaxHops < 0 || m.MaxHops > 16 {
		v.errf("%s.max_hops: must be between 0 and 16", p)
	}
	for _, d := range []struct {
		key    string
		val    Duration
		lo, hi time.Duration
	}{
		{"min_lease_time", m.MinLeaseTime, time.Minute, 365 * 24 * time.Hour},
		{"max_lease_time", m.MaxLeaseTime, time.Minute, 365 * 24 * time.Hour},
		{"request_timeout", m.RequestTimeout, time.Second, time.Minute},
	} {
		if d.val != 0 && (d.val.D() < d.lo || d.val.D() > d.hi) {
			v.errf("%s.%s: must be between %s and %s", p, d.key, d.lo, d.hi)
		}
	}
	if m.MinLeaseTime != 0 && m.MaxLeaseTime != 0 && m.MinLeaseTime.D() > m.MaxLeaseTime.D() {
		v.errf("%s.min_lease_time: longer than max_lease_time", p)
	}
	if m.MaxLeaseTime == 0 {
		v.warnf("%s.max_lease_time: 0 leaves the lease a server may hand out unbounded, and a lease of a year is an address pool exhausted by every device that ever visited", p)
	}
	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: must be allow or deny", p)
	}
	switch m.DenyResponse {
	case "", "drop", "nak":
	default:
		v.errf("%s.deny_response: must be drop or nak", p)
	}
	if m.MaxPending < 0 || m.MaxPending > 1<<20 {
		v.errf("%s.max_pending: must be between 0 and 1048576", p)
	}
	if m.MaxClients < 0 || m.MaxClients > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if m.MaxMessageBytes != 0 && (m.MaxMessageBytes < dhcpwire.MinPacket || m.MaxMessageBytes > dhcpwire.MaxPacket) {
		v.errf("%s.max_message_bytes: must be between %d and %d", p, dhcpwire.MinPacket, dhcpwire.MaxPacket)
	}
	if m.RateLimit < 0 || m.RateLimit > 1<<20 {
		v.errf("%s.rate_limit: must be between 0 and 1048576", p)
	}
	if m.RateBurst < 0 || m.RateBurst > 1<<20 {
		v.errf("%s.rate_burst: must be between 0 and 1048576", p)
	}
	if m.RateLimit == 0 && m.RateBurst > 0 {
		v.warnf("%s.rate_burst: a burst without a rate_limit bounds nothing", p)
	}
	if m.RateLimit == 0 {
		v.warnf("%s.rate_limit: 0 leaves messages per hardware address unbounded, and address pool exhaustion is one client sending thousands of discovers with a made-up address in each", p)
	}
	if len(m.AllowGateways) == 0 && len(m.AllowResolvers) == 0 {
		v.warnf("%s: neither allow_gateways nor allow_resolvers is set, so a reply this listener admits may name any router and any resolver -- which is what a rogue server sends", p)
	}
	names := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		if !nameRE.MatchString(r.Name) {
			v.errf("%s.name: %q is not a valid name", q, r.Name)
		} else if names[r.Name] {
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		names[r.Name] = true
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", q)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		v.modbusCIDRs(q+".allow_routes", r.AllowRoutes)
		v.dhcpTypes(q+".message_types", r.MessageTypes)
		v.dhcpOptions(q+".deny_options", r.DenyOptions)
		v.dhcpAddrs(q+".allow_gateways", r.AllowGateways)
		v.dhcpAddrs(q+".allow_resolvers", r.AllowResolvers)
		v.dhcpAddrs(q+".allow_boot_servers", r.AllowBootServers)
		v.dhcpPatterns(q+".boot_files", r.BootFiles)
		v.dhcpPatterns(q+".vendor_classes", r.VendorClasses)
		v.dhcpPatterns(q+".user_classes", r.UserClasses)
		for j, h := range r.HardwareAddresses {
			if _, err := dhcpwire.ParseHardwareAddr(h); err != nil {
				v.errf("%s.hardware_addresses[%d]: %q is not a hardware address or a vendor prefix", q, j, h)
			}
		}
		if r.MaxLeaseTime != 0 && (r.MaxLeaseTime.D() < time.Minute || r.MaxLeaseTime.D() > 365*24*time.Hour) {
			v.errf("%s.max_lease_time: must be between 1m0s and 8760h0m0s", q)
		}
		if len(r.CircuitID) > 255 {
			v.errf("%s.circuit_id: longer than the 255 octets a suboption holds", q)
		}
		v.modbusSchedule(q+".schedule", r.Schedule)
	}
}

// dhcpTypes checks a message-type list.
func (v *validator) dhcpTypes(p string, in []string) {
	for i, name := range in {
		if _, ok := dhcpwire.TypeOf(name); !ok {
			v.errf("%s[%d]: %q is not a message type (discover, offer, request, decline, ack, nak, release, inform, force_renew, lease_query)", p, i, name)
		}
	}
}

// dhcpOptions checks an option list and returns it as a set. An option may be
// named or numbered: an estate's own vendor option has no name here, and
// refusing to let an operator name it would make the policy incomplete.
func (v *validator) dhcpOptions(p string, in []string) map[uint8]bool {
	out := map[uint8]bool{}
	for i, name := range in {
		code, ok := dhcpwire.OptionOf(name)
		if !ok {
			v.errf("%s[%d]: %q is not an option name or a number from 0 to 255", p, i, name)
			continue
		}
		switch code {
		case dhcpwire.OptPad, dhcpwire.OptEnd:
			v.errf("%s[%d]: %q is the option field's framing, not an option", p, i, name)
			continue
		case dhcpwire.OptMessageType:
			v.errf("%s[%d]: the message type is what every rule is written about, so it cannot be stripped; use message_types", p, i)
			continue
		}
		out[code] = true
	}
	return out
}

// dhcpAddrs checks a list of IPv4 addresses.
func (v *validator) dhcpAddrs(p string, in []string) {
	for i, s := range in {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			v.errf("%s[%d]: %q is not an IPv4 address", p, i, s)
		}
	}
}

// dhcpPatterns checks a shell pattern list.
func (v *validator) dhcpPatterns(p string, in []string) {
	for i, pat := range in {
		if pat == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if _, err := path.Match(pat, "x"); err != nil {
			v.errf("%s[%d]: %q is not a pattern: %v", p, i, pat, err)
		}
	}
}

// mysqlListener validates a kind: mysql section.
// mysqlDecoyOnly says this listener is nothing but a fabricated server, which is
// the one shape that needs no upstream: there is nothing behind it to reach.
func mysqlDecoyOnly(m *MySQLListener) bool {
	d := m.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// MySQLDecoyProfiles are the fabricated server shapes the listener has built in.
var MySQLDecoyProfiles = []string{"generic-mysql", "mariadb", "wordpress"}

// mysqlDeception checks the fabricated server.
func (v *validator) mysqlDeception(p string, m *MySQLListener) {
	d := m.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener reaches a real server, and a "+
				"section that would fabricate an answer for any client that connects is not a decision "+
				"to arrive at by default", p)
		}
	case "decoy":
		if m.Upstream != "" {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream: use mode answer to "+
				"fabricate refusals on a listener that fronts a real server", p)
		}
		if len(d.Clients) == 0 {
			v.warnf("%s: no clients, so every client that connects is answered by the fabricated "+
				"server. That is what a honeypot is for, and on port 3306 it will be found", p)
		}
		if m.RequireTLS == nil || *m.RequireTLS {
			// The greeting does not offer CLIENT_SSL, so a listener that requires
			// it refuses every client before the fabrication says a word.
			v.errf("%s.mode: decoy needs require_tls: false. The fabricated greeting does not offer "+
				"CLIENT_SSL -- the negotiation is mid-handshake on this protocol and a server that "+
				"offered it and could not complete it is a tell -- so a listener requiring TLS would "+
				"refuse every client before the fabrication answered", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	if d.Mode != "decoy" && m.DenyResponse == "drop" {
		v.warnf("%s: deny_response drop does not apply to the clients this section covers -- their "+
			"refused statements are answered by the fabricated server rather than ignored", p)
	}
	if d.Profile != "" && !slices.Contains(MySQLDecoyProfiles, d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, d.Profile, strings.Join(MySQLDecoyProfiles, ", "))
	}
	if len(d.Version) > 64 {
		v.errf("%s.version: %d characters, and a server version string is a few", p, len(d.Version))
	}
	if d.Version == "" {
		v.warnf("%s.version: empty, so the profile's version is reported. A decoy should say what the "+
			"estate's own servers say: a version nobody on the site runs is the tell that ends the "+
			"pretence, and only you know what that is", p)
	}
	for i, db := range d.Databases {
		if db == "" || len(db) > 64 {
			v.errf("%s.databases[%d]: must be 1 to 64 characters, which is what MySQL allows", p, i)
		}
	}
	for i, t := range d.Tables {
		schema, name, ok := strings.Cut(t, ".")
		if !ok || schema == "" || name == "" {
			v.errf("%s.tables[%d]: %q must be written database.table, because SHOW TABLES answers "+
				"per database and a bare name belongs to none", p, i, t)
			continue
		}
		if len(d.Databases) > 0 && !slices.Contains(d.Databases, schema) {
			v.warnf("%s.tables[%d]: %q names a database that is not in databases, so SHOW DATABASES "+
				"will not list it and SHOW TABLES will never be asked for it", p, i, t)
		}
	}
	for i, t := range d.Tripwire {
		if strings.TrimSpace(t) == "" || strings.ContainsAny(t, " \t\r\n") {
			v.errf("%s.tripwire[%d]: %q is not an object name; one name per entry, and a qualified "+
				"one is written schema.name", p, i, t)
		}
	}
	if d.RequireAuth {
		v.warnf("%s.require_auth: the fabrication will refuse every login, so nothing past the "+
			"greeting is ever collected. On this protocol the reconnaissance is the message, and it "+
			"happens after the login", p)
	}
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
}

func (v *validator) mysqlListener(p string, m *MySQLListener, hasTLS bool) {
	if m.Upstream == "" && !mysqlDecoyOnly(m) {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.mysqlDeception(p+".deception", m)

	requireTLS := m.RequireTLS == nil || *m.RequireTLS
	if requireTLS && !hasTLS {
		v.errf("%s.require_tls: set (it defaults on) but the listener has no tls section; "+
			"a mysql client upgrades an existing connection, so the listener needs a certificate", p)
	}
	if !requireTLS {
		v.warnf("%s.require_tls: false lets a client connect without setting CLIENT_SSL, "+
			"and nothing signs the server greeting that advertises it", p)
	}
	switch m.UpstreamTLSMode {
	case "", "require", "prefer", "disable":
	default:
		v.errf("%s.upstream_tls_mode: %q is not require, prefer or disable", p, m.UpstreamTLSMode)
	}

	for i, name := range m.AllowAuth {
		if !mysqlPlugin(name) {
			v.errf("%s.allow_auth[%d]: %q is not an authentication plugin (%s)",
				p, i, name, strings.Join(mysqlwire.AuthPlugins(), ", "))
		}
	}
	if m.AllowWeakAuth {
		v.warnf("%s.allow_weak_auth: true permits mysql_clear_password (the password itself) "+
			"and mysql_old_password (the pre-4.1 scramble, removed from the server in 5.7)", p)
	}

	v.mysqlCommands(p+".allow_commands", m.AllowCommands)
	v.mysqlCommands(p+".deny_commands", m.DenyCommands)
	v.mysqlCaps(p+".deny_capabilities", m.DenyCapabilities)
	v.postgresStatements(p+".allow_statements", m.AllowStatements)
	v.postgresStatements(p+".deny_statements", m.DenyStatements)
	v.mysqlLoad(p+".allow_load", m.AllowLoad)

	for name, val := range map[string]int{
		"max_statements": m.MaxStatements, "max_statement_bytes": m.MaxStatementBytes,
		"max_message_bytes": m.MaxMessageBytes, "max_sessions": m.MaxSessions,
		"max_sessions_per_client": m.MaxSessionsPerClient,
	} {
		if val < 0 {
			v.errf("%s.%s: must not be negative", p, name)
		}
	}
	if m.MaxMessageBytes > mysqlwire.MaxMessage {
		v.errf("%s.max_message_bytes: %d is past the bound of %d", p, m.MaxMessageBytes, mysqlwire.MaxMessage)
	}

	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: %q is not allow or deny", p, m.DefaultAction)
	}
	switch m.DenyResponse {
	case "", "error", "drop":
	default:
		v.errf("%s.deny_response: %q is not error or drop", p, m.DenyResponse)
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		rp := fmt.Sprintf("%s.rules[%d]", p, i)
		v.modbusCIDRs(rp+".clients", r.Clients)
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: %q is not allow, deny or observe", rp, r.Action)
		}
		v.mysqlCommands(rp+".allow_commands", r.AllowCommands)
		v.mysqlCommands(rp+".deny_commands", r.DenyCommands)
		v.postgresStatements(rp+".allow_statements", r.AllowStatements)
		v.postgresStatements(rp+".deny_statements", r.DenyStatements)
		v.mysqlLoad(rp+".allow_load", r.AllowLoad)
		if r.MaxStatements < 0 {
			v.errf("%s.max_statements: must not be negative", rp)
		}
		if r.Schedule != nil {
			v.modbusSchedule(rp+".schedule", r.Schedule)
		}
	}
}

func mysqlPlugin(name string) bool {
	for _, p := range mysqlwire.AuthPlugins() {
		if p == strings.TrimSpace(name) {
			return true
		}
	}
	return false
}

func (v *validator) mysqlCommands(p string, in []string) {
	for i, n := range in {
		if _, ok := mysqlwire.CommandOf(n); !ok {
			v.errf("%s[%d]: %q is not a command (%s)", p, i, n,
				strings.Join(mysqlwire.CommandNames(), ", "))
		}
	}
}

// mysqlCaps checks the capabilities to strip. `ssl` cannot be named: stripping it
// would perform the downgrade the kind exists to prevent, because a client that
// never sees CLIENT_SSL offered never asks for TLS.
func (v *validator) mysqlCaps(p string, in []string) {
	for i, n := range in {
		bit, ok := mysqlwire.CapOf(n)
		if !ok {
			v.errf("%s[%d]: %q is not a capability (%s)", p, i, n,
				strings.Join(mysqlwire.CapNames(), ", "))
			continue
		}
		if bit == mysqlwire.CapSSL {
			v.errf("%s[%d]: ssl cannot be stripped; a client that never sees it offered "+
				"never asks for TLS, which is the downgrade this kind exists to prevent", p, i)
		}
	}
}

// mysqlLoad checks which LOAD DATA forms may cross.
func (v *validator) mysqlLoad(p string, in []string) {
	for i, n := range in {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "file":
			v.warnf("%s[%d]: file lets LOAD DATA read a path on the server, "+
				"which needs the FILE privilege", p, i)
		case "local":
			v.warnf("%s[%d]: local lets the server ask the *client* to open a path and send it, "+
				"which is how a hostile server reads the filesystem of whatever connected to it", p, i)
		default:
			v.errf("%s[%d]: %q is not file or local", p, i, n)
		}
	}
}

// redisListener validates a kind: redis section.
// s7CommPlus checks the S7comm-plus section.
//
// Two of these checks exist because of something the reference cannot make an
// operator read: a policy written in a mode that never reads it, and the fact
// that there is no way to say no in this protocol, so the error response an
// operator configured degrades to a timeout.
func (v *validator) s7CommPlus(p string, m *S7CommPlus, l *S7Listener) {
	if m == nil {
		return
	}
	switch m.Mode {
	case "", "refuse", "policy", "passthrough":
	default:
		v.errf("%s.mode: %q is not refuse, policy or passthrough", p, m.Mode)
	}
	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: %q is not allow or deny", p, m.DefaultAction)
	}
	v.s7PlusFunctions(p+".functions", m.Functions)
	v.s7PlusFunctions(p+".deny_functions", m.DenyFunctions)
	v.s7PlusClasses(p+".classes", m.Classes)
	v.s7PlusClasses(p+".deny_classes", m.DenyClasses)
	lists := len(m.Functions) + len(m.DenyFunctions) + len(m.Classes) + len(m.DenyClasses)
	if m.Mode != "policy" && lists > 0 {
		mode := m.Mode
		if mode == "" {
			mode = "refuse"
		}
		v.errf("%s: functions and classes are read only in mode: policy, and this listener is "+
			"mode: %s, so the policy written here would decide nothing", p, mode)
	}
	if m.Mode == "policy" && lists == 0 && m.DefaultAction != "allow" {
		v.warnf("%s: mode: policy with no functions or classes named and default_action deny "+
			"refuses every S7comm-plus request, which is what mode: refuse says more plainly", p)
	}
	if m.Mode == "passthrough" {
		v.warnf("%s.mode: passthrough forwards every S7comm-plus request unexamined -- the "+
			"frame bounds, the rate limits and the rack and slot still hold, and nothing else "+
			"does. read_only and the operations list do not apply to what goes through here", p)
	}
	if m.Mode == "policy" && (l.DenyResponse == "" || l.DenyResponse == "error") {
		v.warnf("%s: there is no refusal to write in S7comm-plus, so deny_response error "+
			"degrades to drop for it: a refused request is swallowed and the engineering "+
			"station reads a timeout for that one request. Set deny_response close if a "+
			"refusal should end the session instead", p)
	}
	if m.Mode == "policy" && m.DefaultAction == "allow" {
		v.warnf("%s.default_action: allow carries an S7comm-plus function this relay could not "+
			"name. The function table is read from the wire rather than from a specification "+
			"Siemens publishes, so it is incomplete by construction -- deny is what makes that "+
			"safe", p)
	}
}

// s7PlusFunctions checks a list of S7comm-plus function codes.
func (v *validator) s7PlusFunctions(p string, in []string) {
	for i, f := range in {
		name := strings.TrimSpace(f)
		if _, ok := s7wire.PlusFunctionOf(name); ok {
			continue
		}
		hex := strings.TrimPrefix(strings.TrimPrefix(name, "0x"), "0X")
		if _, err := strconv.ParseUint(hex, 16, 16); err != nil {
			v.errf("%s[%d]: %q is not an S7comm-plus function name (explore, get_link, "+
				"get_multi_variables, get_var_sub_streamed, set_variable, set_multi_variables, "+
				"create_object, delete_object, invoke, begin_sequence, end_sequence) or a "+
				"16-bit hex code such as 0x054c", p, i, f)
		}
	}
}

// s7PlusClasses checks a list of S7comm-plus classes.
func (v *validator) s7PlusClasses(p string, in []string) {
	for i, c := range in {
		if _, ok := s7wire.PlusClassNamed(strings.TrimSpace(c)); !ok {
			v.errf("%s[%d]: %q is not read, write, admin or unknown", p, i, c)
		}
	}
}

// s7Listener validates a kind: s7 section.
// s7DecoyOnly says whether this listener is nothing but a fabricated
// controller, which is the one shape that needs no upstream: there is no CPU
// behind it to reach.
func s7DecoyOnly(m *S7Listener) bool {
	d := m.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// S7DecoyProfiles are the fabricated controller shapes the listener has built
// in. The list lives here so the error can name them, and a test in the kind
// keeps the two in step.
var S7DecoyProfiles = []string{"generic-s7-300", "generic-s7-400"}

// S7DecoyShapes are the shapes a band of bytes inside a block may take.
var S7DecoyShapes = []string{"analogue", "discrete", "counter"}

// s7PDULengths are the lengths a classic S7 CPU negotiates. A fabrication
// that offered something else would be answering with a number no controller
// sends, which is the kind of detail a client library prints.
var s7PDULengths = []int{240, 480, 960}

func (v *validator) s7Deception(p string, m *S7Listener) {
	d := m.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener reaches a real controller, and a "+
				"section that would fabricate an answer for any client that connects is not a decision to "+
				"arrive at by default", p)
		}
	case "decoy":
		if m.Upstream != "" {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream: "+
				"use mode answer to fabricate refusals on a listener that fronts a controller", p)
		}
		if len(d.Clients) == 0 {
			// Not an error: a honeypot with nothing behind it is exactly the
			// case where answering every client is the point.
			v.warnf("%s: no clients, so every client that connects is answered by the fabricated "+
				"controller. That is what a honeypot is for; it is worth being sure this listener is one", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	if d.Mode != "decoy" && (m.DenyResponse == "close" || m.DenyResponse == "drop") {
		v.warnf("%s: deny_response %s does not apply to the clients this section covers -- their refused "+
			"requests are answered by the fabricated controller rather than closed or ignored", p, m.DenyResponse)
	}
	if d.Profile != "" && !slices.Contains(S7DecoyProfiles, d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s. Both are classic S7comm "+
			"families on purpose: an S7-1200 or S7-1500 speaks S7comm-plus, so a decoy answering classic "+
			"S7comm while claiming to be one is a contradiction a scanner sees in one exchange",
			p, d.Profile, strings.Join(S7DecoyProfiles, ", "))
	}
	if n := d.PDULength; n != 0 && !slices.Contains(s7PDULengths, n) {
		v.errf("%s.pdu_length: %d is not a length a classic CPU negotiates; they are 240, 480 and 960", p, n)
	}
	if d.Version != "" && !s7Version(d.Version) {
		v.errf("%s.version: %q is not a firmware version; it is three numbers below 256, as 3.2.7", p, d.Version)
	}
	if n := len(d.OrderNumber); n > 20 {
		v.errf("%s.order_number: %d characters, and the module identification list carries 20", p, n)
	}
	for _, f := range []struct{ name, text string }{
		{"module_type", d.ModuleType}, {"plant", d.Plant}, {"serial", d.Serial},
	} {
		if len(f.text) > 32 {
			v.errf("%s.%s: %d characters, and the component identification list carries 32",
				p, f.name, len(f.text))
		}
	}
	v.modbusRanges(p+".tripwire", d.Tripwire, 65535)
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
	for i := range d.Blocks {
		q := fmt.Sprintf("%s.blocks[%d]", p, i)
		b := &d.Blocks[i]
		if b.DBs == "" {
			v.errf("%s.dbs: required", q)
		} else {
			v.modbusRanges(q+".dbs", []string{b.DBs}, 65535)
		}
		if b.Bytes < 0 || b.Bytes > 1<<20 {
			v.errf("%s.bytes: must be between 0 and 1048576", q)
		}
	}
	for i := range d.Bands {
		q := fmt.Sprintf("%s.bands[%d]", p, i)
		b := &d.Bands[i]
		if b.Addresses == "" {
			v.errf("%s.addresses: required", q)
		} else {
			v.modbusRanges(q+".addresses", []string{b.Addresses}, 1<<24-1)
		}
		if b.Shape != "" && !slices.Contains(S7DecoyShapes, b.Shape) {
			v.errf("%s.shape: must be analogue, discrete or counter", q)
		}
		if b.Max != 0 && b.Max <= b.Min {
			v.errf("%s: max must be above min", q)
		}
		if b.Rate < 0 {
			v.errf("%s.rate: must not be negative; a totaliser that went backwards is the one thing a "+
				"fabricated controller cannot do and be believed", q)
		}
	}
}

// s7Version says whether a firmware version reads as three numbers below 256.
func s7Version(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return false
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func (v *validator) s7Listener(p string, m *S7Listener) {
	v.anomaly(p+".anomaly", m.Anomaly)
	v.engineering(p+".engineering", m.Engineering)
	if m.Upstream == "" && !s7DecoyOnly(m) {
		v.errf("%s.upstream: required", p)
	}
	v.s7Deception(p+".deception", m)
	if l := m.Learn; l != nil && l.Enabled {
		if l.File == "" {
			v.errf("%s.learn.file: required when learning is enabled", p)
		} else if !strings.HasPrefix(l.File, "/") {
			v.errf("%s.learn.file: must be an absolute path", p)
		}
		if l.Interval != 0 && (l.Interval.D() < 10*time.Second || l.Interval.D() > 24*time.Hour) {
			v.errf("%s.learn.interval: must be between 10s and 24h", p)
		}
		if l.MaxSubjects != 0 && (l.MaxSubjects < 16 || l.MaxSubjects > 1_000_000) {
			v.errf("%s.learn.max_subjects: must be between 16 and 1000000", p)
		}
		if !l.Enforce {
			v.warnf("%s.learn is enabled without enforce, so this listener records and decides nothing: "+
				"turn enforce on, or take the learning section out, once the rules are written", p)
		}
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	if len(m.AllowClients) == 0 {
		v.warnf("%s.allow_clients: empty, so every client the deny list does not refuse may "+
			"reach a controller. On a plant network that is the whole segment", p)
	}
	// A rack is three bits and a slot five, which is what the one octet
	// holds: a number outside them is a policy line nothing can match.
	v.modbusRanges(p+".racks", m.Racks, 7)
	v.modbusRanges(p+".slots", m.Slots, 31)
	v.s7Resources(p+".resources", m.Resources)
	v.s7Operations(p+".operations", m.Operations)
	v.s7Operations(p+".deny_operations", m.DenyOperations)
	v.s7Areas(p+".areas", m.Areas)
	v.s7Areas(p+".deny_areas", m.DenyAreas)
	v.modbusRanges(p+".dbs", m.DBs, 65535)
	// A byte address is the protocol's bit address divided by eight, so the
	// top of the range is a little over two million.
	v.modbusRanges(p+".addresses", m.Addresses, 1<<21-1)
	v.modbusRanges(p+".write_addresses", m.WriteAddresses, 1<<21-1)
	v.s7BlockTypes(p+".block_types", m.BlockTypes)
	v.s7CommPlus(p+".s7comm_plus", m.CommPlus, m)

	for name, val := range map[string]int{
		"max_items": m.MaxItems, "max_read_bytes": m.MaxReadBytes,
		"max_write_bytes": m.MaxWriteBytes, "max_pdu_length": m.MaxPDULength,
		"max_frame_bytes": m.MaxFrameBytes, "max_requests": m.MaxRequests,
		"rate_limit": m.RateLimit, "rate_burst": m.RateBurst,
		"max_sessions": m.MaxSessions, "max_sessions_per_client": m.MaxSessionsPerClient,
	} {
		if val < 0 {
			v.errf("%s.%s: must not be negative", p, name)
		}
	}
	if m.MaxFrameBytes != 0 && m.MaxFrameBytes < s7wire.MinFrame {
		v.errf("%s.max_frame_bytes: %d is below the %d a COTP header needs",
			p, m.MaxFrameBytes, s7wire.MinFrame)
	}
	if m.MaxPDULength > 0 && m.MaxFrameBytes > 0 && m.MaxPDULength > m.MaxFrameBytes {
		v.warnf("%s.max_pdu_length: %d is above max_frame_bytes (%d), so the frame bound "+
			"decides and this value never applies", p, m.MaxPDULength, m.MaxFrameBytes)
	}

	// The operations that change a controller, named where an operator can
	// see what they have just allowed.
	if !m.ReadOnly {
		for i, o := range m.Operations {
			op, ok := s7wire.OpOf(strings.TrimSpace(o))
			if !ok || !s7wire.Writes(op) {
				continue
			}
			switch op {
			case s7wire.OpStop:
				v.warnf("%s.operations[%d]: stop lets a client stop the CPU, which stops the "+
					"machine", p, i)
			case s7wire.OpDownload:
				v.warnf("%s.operations[%d]: download lets a client change the program the "+
					"machine runs", p, i)
			case s7wire.OpProgrammer:
				v.warnf("%s.operations[%d]: programmer is the debugger -- forcing a variable, "+
					"setting a breakpoint -- which no application needs", p, i)
			case s7wire.OpSecurity:
				v.warnf("%s.operations[%d]: security is the password functions, so a client "+
					"may unlock a protected CPU through this listener", p, i)
			default:
				v.warnf("%s.operations[%d]: %s changes the controller", p, i, op)
			}
		}
	}
	if len(m.Operations) > 0 && m.ReadOnly {
		for _, o := range m.Operations {
			if op, ok := s7wire.OpOf(strings.TrimSpace(o)); ok && s7wire.Writes(op) {
				v.warnf("%s.operations: %s is named and read_only is set, so it is refused "+
					"anyway -- read_only is not overridden by a list", p, op)
			}
		}
	}

	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: %q is not allow or deny", p, m.DefaultAction)
	}
	if m.DefaultAction == "allow" && len(m.Rules) == 0 && !m.MonitorOnly && !m.ReadOnly {
		v.warnf("%s: default_action allow with no rules, without monitor_only and without "+
			"read_only relays every request to the controller", p)
	}
	switch m.DenyResponse {
	case "", "error", "drop", "close":
	default:
		v.errf("%s.deny_response: %q is not error, drop or close", p, m.DenyResponse)
	}

	for i := range m.Rules {
		r := &m.Rules[i]
		rp := fmt.Sprintf("%s.rules[%d]", p, i)
		if r.Name == "" {
			v.errf("%s.name: required, because it is what a refusal names", rp)
		}
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: %q is not allow, deny or observe", rp, r.Action)
		}
		v.modbusCIDRs(rp+".clients", r.Clients)
		v.modbusRanges(rp+".racks", r.Racks, 7)
		v.modbusRanges(rp+".slots", r.Slots, 31)
		v.s7Resources(rp+".resources", r.Resources)
		v.s7Operations(rp+".operations", r.Operations)
		v.s7Operations(rp+".deny_operations", r.DenyOperations)
		v.s7Areas(rp+".areas", r.Areas)
		v.s7Areas(rp+".deny_areas", r.DenyAreas)
		v.modbusRanges(rp+".dbs", r.DBs, 65535)
		v.modbusRanges(rp+".addresses", r.Addresses, 1<<21-1)
		v.modbusRanges(rp+".write_addresses", r.WriteAddresses, 1<<21-1)
		v.s7BlockTypes(rp+".block_types", r.BlockTypes)
		if r.MaxItems < 0 {
			v.errf("%s.max_items: must not be negative", rp)
		}
		if r.Schedule != nil {
			v.modbusSchedule(rp+".schedule", r.Schedule)
		}
	}
}

// s7Operations checks the operation names.
func (v *validator) s7Operations(p string, in []string) {
	for i, o := range in {
		if _, ok := s7wire.OpOf(strings.TrimSpace(o)); !ok {
			v.errf("%s[%d]: %q is not an S7 operation (read, write, setup, upload, download, "+
				"control, stop, cpu_services, szl, diagnostics, blocks, cyclic, time_read, "+
				"time_write, security, programmer, mode, pbc, nc)", p, i, o)
		}
	}
}

// s7Areas checks the memory area names.
func (v *validator) s7Areas(p string, in []string) {
	for i, a := range in {
		if _, ok := s7wire.AreaOf(strings.TrimSpace(a)); !ok {
			v.errf("%s[%d]: %q is not a memory area (db, inputs, outputs, flags, timer, "+
				"counter, instance_db, local, previous_local, peripheral and the 200-family "+
				"areas)", p, i, a)
		}
	}
}

// s7Resources checks the connection resource names.
func (v *validator) s7Resources(p string, in []string) {
	for i, r := range in {
		if _, ok := s7wire.ResourceOf(strings.TrimSpace(r)); !ok {
			v.errf("%s[%d]: %q is not a connection resource (pg, op, basic)", p, i, r)
		}
	}
}

// s7BlockTypes checks the block type names.
func (v *validator) s7BlockTypes(p string, in []string) {
	for i, b := range in {
		switch strings.TrimSpace(b) {
		case "db", "fb", "fc", "sdb", "sfb", "sfc":
		default:
			v.errf("%s[%d]: %q is not a block type (db, fb, fc, sdb, sfb, sfc)", p, i, b)
		}
	}
}

// amqpListener validates a kind: amqp section.
func (v *validator) amqpListener(p string, m *AMQPListener, hasTLS bool) {
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)

	requireTLS := m.RequireTLS == nil || *m.RequireTLS
	if requireTLS && !hasTLS {
		v.errf("%s.require_tls: set (it defaults on) but the listener has no tls section; "+
			"AMQP has no in-protocol upgrade, so the port is either TLS or it is not", p)
	}
	if !requireTLS {
		v.warnf("%s.require_tls: false lets a client authenticate in the clear, and AMQP's "+
			"PLAIN mechanism is the username and the password in one field", p)
	}
	switch m.UpstreamTLSMode {
	case "", "require", "prefer", "disable":
	default:
		v.errf("%s.upstream_tls_mode: %q is not require, prefer or disable", p, m.UpstreamTLSMode)
	}
	if m.RequireAuth != nil && !*m.RequireAuth {
		v.warnf("%s.require_auth: false lets an operation through before the broker has "+
			"accepted a credential", p)
	}

	for i, ver := range m.Versions {
		switch ver {
		case "0-9-1", "1.0":
		case "0-8", "0-9":
			v.errf("%s.versions[%d]: %q is not a version this relay reads; a broker answers it "+
				"for compatibility, and a policy on a revision from 2006 is not one worth "+
				"writing", p, i, ver)
		default:
			v.errf("%s.versions[%d]: %q is not 0-9-1 or 1.0", p, i, ver)
		}
	}
	v.amqpMechanisms(p+".allow_mechanisms", m.AllowMechanisms)
	v.amqpMechanisms(p+".deny_mechanisms", m.DenyMechanisms)

	v.amqpMethods(p+".allow_methods", m.AllowMethods)
	v.amqpMethods(p+".deny_methods", m.DenyMethods)
	v.amqpPerformatives(p+".allow_performatives", m.AllowPerformatives)
	v.amqpPerformatives(p+".deny_performatives", m.DenyPerformatives)

	for name, list := range map[string][]string{
		"allow_exchanges": m.AllowExchanges, "deny_exchanges": m.DenyExchanges,
		"allow_queues": m.AllowQueues, "deny_queues": m.DenyQueues,
		"allow_routing_keys": m.AllowRoutingKeys, "deny_routing_keys": m.DenyRoutingKeys,
		"allow_addresses": m.AllowAddresses, "deny_addresses": m.DenyAddresses,
		"allow_vhosts": m.AllowVhosts, "deny_vhosts": m.DenyVhosts,
	} {
		v.amqpPatterns(p+"."+name, list)
	}

	if m.AllowTopology {
		v.warnf("%s.allow_topology: true lets a client declare and delete exchanges and "+
			"queues, and purge them; almost no application needs to", p)
	}
	if m.MaxPriority < 0 || m.MaxPriority > 255 {
		v.errf("%s.max_priority: %d is not a message priority", p, m.MaxPriority)
	}
	if m.MaxFrameBytes != 0 && m.MaxFrameBytes < amqpwire.MinFrameMax091 {
		v.errf("%s.max_frame_bytes: %d is below the %d the protocol requires a peer to accept",
			p, m.MaxFrameBytes, amqpwire.MinFrameMax091)
	}
	for name, val := range map[string]int{
		"max_frame_bytes": m.MaxFrameBytes, "max_channels": m.MaxChannels,
		"max_links": m.MaxLinks, "max_message_bytes": m.MaxMessageBytes,
		"max_methods": m.MaxMethods, "rate_limit": m.RateLimit, "rate_burst": m.RateBurst,
		"max_sessions": m.MaxSessions, "max_sessions_per_client": m.MaxSessionsPerClient,
	} {
		if val < 0 {
			v.errf("%s.%s: must not be negative", p, name)
		}
	}
	// A message bound below the frame bound never applies on 0-9-1: the
	// content header declares the message size, and a message that fits in
	// one frame is refused by neither.
	if m.MaxMessageBytes > 0 && m.MaxFrameBytes > 0 && m.MaxMessageBytes < m.MaxFrameBytes {
		v.warnf("%s.max_message_bytes: %d is below max_frame_bytes (%d), so a single frame may "+
			"carry a message this bound would refuse", p, m.MaxMessageBytes, m.MaxFrameBytes)
	}
	if m.RequireUserID && m.MatchUserID != nil && !*m.MatchUserID {
		v.warnf("%s.require_user_id: set with match_user_id false, so every message must "+
			"carry a user identifier and none of them has to be this connection's", p)
	}

	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: %q is not allow or deny", p, m.DefaultAction)
	}
	switch m.DenyResponse {
	case "", "close", "drop":
	default:
		v.errf("%s.deny_response: %q is not close or drop", p, m.DenyResponse)
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		rp := fmt.Sprintf("%s.rules[%d]", p, i)
		v.modbusCIDRs(rp+".clients", r.Clients)
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: %q is not allow, deny or observe", rp, r.Action)
		}
		v.amqpMethods(rp+".allow_methods", r.AllowMethods)
		v.amqpMethods(rp+".deny_methods", r.DenyMethods)
		v.amqpPerformatives(rp+".allow_performatives", r.AllowPerformatives)
		v.amqpPerformatives(rp+".deny_performatives", r.DenyPerformatives)
		for name, list := range map[string][]string{
			"allow_exchanges": r.AllowExchanges, "deny_exchanges": r.DenyExchanges,
			"allow_queues": r.AllowQueues, "deny_queues": r.DenyQueues,
			"allow_routing_keys": r.AllowRoutingKeys, "deny_routing_keys": r.DenyRoutingKeys,
			"allow_addresses": r.AllowAddresses, "deny_addresses": r.DenyAddresses,
			"vhosts": r.Vhosts,
		} {
			v.amqpPatterns(rp+"."+name, list)
		}
		if r.MaxMessageBytes < 0 || r.MaxMethods < 0 {
			v.errf("%s: max_message_bytes and max_methods must not be negative", rp)
		}
		if r.Schedule != nil {
			v.modbusSchedule(rp+".schedule", r.Schedule)
		}
	}
}

// amqpMethods checks 0-9-1 method names, and says what an operator has just
// allowed when the name is one that changes the broker rather than using it.
func (v *validator) amqpMethods(p string, in []string) {
	allowing := strings.HasSuffix(p, ".allow_methods")
	for i, n := range in {
		name := strings.ToLower(strings.TrimSpace(n))
		if name == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if _, _, ok := amqpwire.MethodID(name); !ok {
			// An error rather than a warning: unlike a redis command,
			// this catalogue is fixed by the specification, so a name
			// outside it is a typo and a policy line that matches
			// nothing.
			v.errf("%s[%d]: %q is not an AMQP 0-9-1 method (they are spelled "+
				"`basic.publish`, `queue.declare`)", p, i, n)
			continue
		}
		if !allowing {
			continue
		}
		switch {
		case amqpwire.Destructive(name):
			v.warnf("%s[%d]: %s deletes or empties something, and no rule below can take it "+
				"back", p, i, name)
		case amqpwire.Topology(name):
			v.warnf("%s[%d]: %s changes the broker's own configuration", p, i, name)
		case amqpwire.Administrative(name):
			v.warnf("%s[%d]: %s reaches past this connection", p, i, name)
		}
	}
}

// amqpPerformatives checks AMQP 1.0 performative names.
func (v *validator) amqpPerformatives(p string, in []string) {
	for i, n := range in {
		name := strings.ToLower(strings.TrimSpace(n))
		if name == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if _, ok := amqpwire.PerformativeCode(name); !ok {
			v.errf("%s[%d]: %q is not an AMQP 1.0 performative (they are spelled `attach`, "+
				"`transfer`, `sasl-init`)", p, i, n)
		}
	}
}

// amqpMechanisms checks SASL mechanism names.
func (v *validator) amqpMechanisms(p string, in []string) {
	allowing := strings.HasSuffix(p, ".allow_mechanisms")
	for i, n := range in {
		name := strings.ToUpper(strings.TrimSpace(n))
		if name == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if allowing && name == "ANONYMOUS" {
			v.warnf("%s[%d]: ANONYMOUS is a login with no identity, so nothing this listener "+
				"logs or bans can be attributed to an account", p, i)
		}
	}
}

// amqpPatterns checks a name pattern list.
func (v *validator) amqpPatterns(p string, in []string) {
	for i, pat := range in {
		if pat == "" {
			// An empty pattern is not nothing on this protocol: the
			// default exchange is named by the empty string, and a
			// publish to it with a routing key is how every client
			// library sends to a queue by name. So it has to be written
			// deliberately, as `""`, and an accidental blank line in a
			// list is an error.
			v.errf("%s[%d]: empty; the default exchange is matched by the pattern \"\" "+
				"written deliberately, not by a blank entry", p, i)
			continue
		}
		if _, err := path.Match(pat, "x"); err != nil {
			v.errf("%s[%d]: %q is not a pattern: %v", p, i, pat, err)
		}
	}
}

// redisDecoyOnly says this listener is nothing but a fabricated server, which is
// the one shape that needs no upstream: there is nothing behind it to reach.
func redisDecoyOnly(m *RedisListener) bool {
	d := m.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// RedisDecoyProfiles are the fabricated server shapes the listener has built in.
var RedisDecoyProfiles = []string{"generic-cache", "queue", "session-store"}

// redisDeception checks the fabricated server.
func (v *validator) redisDeception(p string, m *RedisListener) {
	d := m.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener reaches a real server, and a "+
				"section that would fabricate an answer for any client that connects is not a decision "+
				"to arrive at by default", p)
		}
	case "decoy":
		if m.Upstream != "" {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream: use mode answer to "+
				"fabricate refusals on a listener that fronts a real server", p)
		}
		if len(d.Clients) == 0 {
			v.warnf("%s: no clients, so every client that connects is answered by the fabricated "+
				"server. That is what a honeypot is for; on this protocol it is also the thing the "+
				"scanning is looking for, so expect it to be found", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	if d.Mode != "decoy" && m.DenyResponse == "drop" {
		v.warnf("%s: deny_response drop does not apply to the clients this section covers -- their "+
			"refused commands are answered by the fabricated server rather than ignored", p)
	}
	if d.Profile != "" && !slices.Contains(RedisDecoyProfiles, d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, d.Profile, strings.Join(RedisDecoyProfiles, ", "))
	}
	if len(d.Version) > 64 {
		v.errf("%s.version: %d characters, and a redis_version is a few", p, len(d.Version))
	}
	if d.Version == "" {
		v.warnf("%s.version: empty, so the profile's version is reported. A decoy should say what the "+
			"estate's own servers say: a version nobody on the site runs is the tell that ends the "+
			"pretence, and only you know what that is", p)
	}
	if n := d.KeyCount; n < 0 || n > 4096 {
		v.errf("%s.key_count: must be between 0 and 4096", p)
	}
	for i, k := range d.Keys {
		switch {
		case k == "":
			v.errf("%s.keys[%d]: empty", p, i)
		case len(k) > 512:
			v.errf("%s.keys[%d]: longer than 512 octets", p, i)
		}
	}
	for i, c := range d.Tripwire {
		if redisCommandName(c) == "" {
			v.errf("%s.tripwire[%d]: %q is not a command name, or a name and a subcommand", p, i, c)
		}
	}
	if d.RequireAuth {
		v.warnf("%s.require_auth: the fabrication will ask for a password and then accept any of "+
			"them, because refusing would make it a credential oracle. It also makes the decoy less "+
			"interesting to the scripts this protocol attracts, which look for an instance with no "+
			"password at all", p)
	}
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
}

// redisCommandName reads a configured command name, or a name and a subcommand,
// and returns it normalised or "" when it is not one.
func redisCommandName(s string) string {
	fields := strings.Fields(strings.ToUpper(s))
	if len(fields) == 0 || len(fields) > 2 {
		return ""
	}
	for _, f := range fields {
		for i := 0; i < len(f); i++ {
			if !redisNameChar(f[i]) {
				return ""
			}
		}
	}
	return strings.Join(fields, " ")
}

func (v *validator) redisListener(p string, m *RedisListener, hasTLS bool) {
	if m.Upstream == "" && !redisDecoyOnly(m) {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.redisDeception(p+".deception", m)

	requireTLS := m.RequireTLS == nil || *m.RequireTLS
	if requireTLS && !hasTLS {
		v.errf("%s.require_tls: set (it defaults on) but the listener has no tls section; "+
			"redis has no in-protocol upgrade, so the port is either TLS or it is not", p)
	}
	if !requireTLS {
		v.warnf("%s.require_tls: false lets a client send AUTH in the clear, and a redis "+
			"password is an ordinary command argument", p)
	}
	switch m.UpstreamTLSMode {
	case "", "require", "prefer", "disable":
	default:
		v.errf("%s.upstream_tls_mode: %q is not require, prefer or disable", p, m.UpstreamTLSMode)
	}
	if m.RequireAuth != nil && !*m.RequireAuth {
		v.warnf("%s.require_auth: false lets a command through before the connection has "+
			"authenticated, and redis's own default is no password at all", p)
	}

	v.redisCommands(p+".allow_commands", m.AllowCommands)
	v.redisCommands(p+".deny_commands", m.DenyCommands)
	v.redisSubcommands(p+".allow_subcommands", m.AllowSubcommands)
	v.redisSubcommands(p+".deny_subcommands", m.DenySubcommands)
	v.redisPrefixes(p+".allow_key_prefixes", m.AllowKeyPrefixes)
	v.redisPrefixes(p+".deny_key_prefixes", m.DenyKeyPrefixes)

	for _, db := range m.AllowDatabases {
		if db < 0 || db > 255 {
			v.errf("%s.allow_databases: %d is not a database number", p, db)
		}
	}
	if m.AllowInline {
		v.warnf("%s.allow_inline: true permits the space-separated command form, which no "+
			"client library sends and which most exploitation scripts use", p)
	}

	for name, val := range map[string]int{
		"max_message_bytes": m.MaxMessageBytes, "max_bulk_bytes": m.MaxBulkBytes,
		"max_elements": m.MaxElements, "max_commands": m.MaxCommands,
		"max_sessions": m.MaxSessions, "max_sessions_per_client": m.MaxSessionsPerClient,
	} {
		if val < 0 {
			v.errf("%s.%s: must not be negative", p, name)
		}
	}
	if m.MaxMessageBytes > respwire.MaxMessage {
		v.errf("%s.max_message_bytes: %d is past the bound of %d",
			p, m.MaxMessageBytes, respwire.MaxMessage)
	}
	if m.MaxBulkBytes > respwire.MaxBulk {
		v.errf("%s.max_bulk_bytes: %d is past the bound of %d",
			p, m.MaxBulkBytes, respwire.MaxBulk)
	}
	if m.MaxElements > respwire.MaxElements {
		v.errf("%s.max_elements: %d is past the bound of %d",
			p, m.MaxElements, respwire.MaxElements)
	}
	// A bulk bound above the message bound never applies: the message check
	// fires first, and the log then names a limit the operator did not set.
	if m.MaxBulkBytes > 0 && m.MaxMessageBytes > 0 && m.MaxBulkBytes > m.MaxMessageBytes {
		v.warnf("%s.max_bulk_bytes: %d is above max_message_bytes (%d), so the message bound "+
			"decides and this value never applies", p, m.MaxBulkBytes, m.MaxMessageBytes)
	}

	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: %q is not allow or deny", p, m.DefaultAction)
	}
	switch m.DenyResponse {
	case "", "error", "drop":
	default:
		v.errf("%s.deny_response: %q is not error or drop", p, m.DenyResponse)
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		rp := fmt.Sprintf("%s.rules[%d]", p, i)
		v.modbusCIDRs(rp+".clients", r.Clients)
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: %q is not allow, deny or observe", rp, r.Action)
		}
		v.redisCommands(rp+".allow_commands", r.AllowCommands)
		v.redisCommands(rp+".deny_commands", r.DenyCommands)
		v.redisSubcommands(rp+".allow_subcommands", r.AllowSubcommands)
		v.redisSubcommands(rp+".deny_subcommands", r.DenySubcommands)
		v.redisPrefixes(rp+".allow_key_prefixes", r.AllowKeyPrefixes)
		v.redisPrefixes(rp+".deny_key_prefixes", r.DenyKeyPrefixes)
		if r.MaxCommands < 0 {
			v.errf("%s.max_commands: must not be negative", rp)
		}
		if r.Schedule != nil {
			v.modbusSchedule(rp+".schedule", r.Schedule)
		}
	}
}

// redisCommands checks the command names, and says what an operator has just
// allowed when the name is one of the ways out of the database.
func (v *validator) redisCommands(p string, in []string) {
	allowing := strings.HasSuffix(p, ".allow_commands")
	for i, n := range in {
		name := strings.ToUpper(strings.TrimSpace(n))
		if name == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if !respwire.Known(name) {
			// Not an error: redis gains commands every release and a module adds
			// its own, so a name this build does not know may still be one the
			// server has. But the relay cannot locate its keys or say whether it
			// writes, so naming it has consequences worth stating.
			v.warnf("%s[%d]: %s is not a command this build knows, so the relay cannot say "+
				"where its keys are (a key prefix policy will refuse it) and counts it as a write",
				p, i, name)
			continue
		}
		if allowing && respwire.Dangerous(name) {
			v.warnf("%s[%d]: %s is a way out of the database, a way to lose all of it, or a "+
				"way to stop the thread that serves every client", p, i, name)
		}
	}
}

// redisSubcommands checks the "CONTAINER SUB" spellings.
func (v *validator) redisSubcommands(p string, in []string) {
	for i, n := range in {
		fields := strings.Fields(strings.ToUpper(n))
		if len(fields) != 2 {
			v.errf("%s[%d]: %q is not a container command and a subcommand, as in "+
				"\"CONFIG GET\"", p, i, n)
			continue
		}
		if !respwire.Known(fields[0]) {
			v.warnf("%s[%d]: %s is not a command this build knows", p, i, fields[0])
		}
	}
}

// redisPrefixes checks the key prefixes. An empty one matches every key, which
// makes the list it is in decorative -- and on an allow list that reads as a
// policy where there is none.
func (v *validator) redisPrefixes(p string, in []string) {
	for i, n := range in {
		if n == "" {
			v.errf("%s[%d]: an empty prefix matches every key", p, i)
		}
	}
}

// tdsListener validates a kind: tds section.
func (v *validator) tdsListener(p string, m *TDSListener, hasTLS bool) {
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)

	requireTLS := m.RequireTLS == nil || *m.RequireTLS
	if requireTLS && !hasTLS {
		v.errf("%s.require_tls: set (it defaults on) but the listener has no tls section; "+
			"a tds client upgrades an existing connection, so the listener needs a certificate", p)
	}
	if !requireTLS {
		v.warnf("%s.require_tls: false lets the PRELOGIN negotiation settle on cleartext, "+
			"and a TDS password is XOR 0xa5 with the nibbles swapped -- an encoding, not encryption", p)
	}
	if m.AllowCleartextPassword {
		v.warnf("%s.allow_cleartext_password: true lets a LOGIN7 carry a recoverable "+
			"password over an unencrypted connection", p)
	}
	switch m.UpstreamTLSMode {
	case "", "require", "prefer", "disable":
	default:
		v.errf("%s.upstream_tls_mode: %q is not require, prefer or disable", p, m.UpstreamTLSMode)
	}

	// A user list and integrated security cannot both be in force: an SSPI login
	// carries no user name for a list to match. Saying so at validation is much
	// better than a policy that silently does not apply.
	if (len(m.AllowUsers) > 0 || len(m.DenyUsers) > 0) && m.AllowIntegrated == nil {
		v.warnf("%s: allow_users or deny_users is set, so a login using integrated security "+
			"-- which carries no user name -- is refused; set allow_integrated explicitly to say "+
			"which you meant", p)
	}
	if m.AllowIntegrated != nil && *m.AllowIntegrated && len(m.AllowUsers) > 0 {
		v.warnf("%s.allow_integrated: true with allow_users set means the user list does not "+
			"apply to a login using integrated security, because it carries no user name", p)
	}

	v.tdsTypes(p+".allow_types", m.AllowTypes)
	v.tdsTypes(p+".deny_types", m.DenyTypes)
	v.tdsProcedures(p+".allow_procedures", m.AllowProcedures)
	v.tdsProcedures(p+".deny_procedures", m.DenyProcedures)
	v.postgresStatements(p+".allow_statements", m.AllowStatements)
	v.postgresStatements(p+".deny_statements", m.DenyStatements)

	for name, val := range map[string]int{
		"max_statements": m.MaxStatements, "max_statement_bytes": m.MaxStatementBytes,
		"max_message_bytes": m.MaxMessageBytes, "max_sessions": m.MaxSessions,
		"max_sessions_per_client": m.MaxSessionsPerClient,
	} {
		if val < 0 {
			v.errf("%s.%s: must not be negative", p, name)
		}
	}
	if m.MaxMessageBytes > tdswire.MaxMessage {
		v.errf("%s.max_message_bytes: %d is past the bound of %d", p, m.MaxMessageBytes, tdswire.MaxMessage)
	}

	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: %q is not allow or deny", p, m.DefaultAction)
	}
	switch m.DenyResponse {
	case "", "error", "drop":
	default:
		v.errf("%s.deny_response: %q is not error or drop", p, m.DenyResponse)
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		rp := fmt.Sprintf("%s.rules[%d]", p, i)
		v.modbusCIDRs(rp+".clients", r.Clients)
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: %q is not allow, deny or observe", rp, r.Action)
		}
		v.tdsTypes(rp+".allow_types", r.AllowTypes)
		v.tdsTypes(rp+".deny_types", r.DenyTypes)
		v.tdsProcedures(rp+".allow_procedures", r.AllowProcedures)
		v.tdsProcedures(rp+".deny_procedures", r.DenyProcedures)
		v.postgresStatements(rp+".allow_statements", r.AllowStatements)
		v.postgresStatements(rp+".deny_statements", r.DenyStatements)
		if r.MaxStatements < 0 {
			v.errf("%s.max_statements: must not be negative", rp)
		}
		if r.Schedule != nil {
			v.modbusSchedule(rp+".schedule", r.Schedule)
		}
	}
}

func (v *validator) tdsTypes(p string, in []string) {
	for i, n := range in {
		if _, ok := tdswire.TypeOf(n); !ok {
			v.errf("%s[%d]: %q is not a message type (%s)", p, i, n,
				strings.Join(tdswire.TypeNames(), ", "))
		}
	}
}

// tdsProcedures checks the procedure names, and says what an operator has just
// allowed when the name is one of the ways out of the database.
//
// A procedure name is any identifier, so there is nothing to spell-check. What
// there is to do is notice: a configuration that allows xp_cmdshell is a
// configuration somebody should have to defend, and an empty spelling is a typo
// that would otherwise sit in an allow list matching nothing.
func (v *validator) tdsProcedures(p string, in []string) {
	allowing := strings.HasSuffix(p, ".allow_procedures")
	for i, n := range in {
		name := strings.ToLower(strings.TrimSpace(n))
		if name == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if allowing && tdswire.Dangerous(name) {
			v.warnf("%s[%d]: %s is a way out of the database -- a shell command, a COM object, "+
				"the host registry, a linked server or the switch that turns one of those back on",
				p, i, name)
		}
	}
}

// postgresListener validates a kind: postgres section.
// postgresDecoyOnly says this listener is nothing but a fabricated server, which
// is the one shape that needs no upstream: there is nothing behind it to reach.
func postgresDecoyOnly(m *PostgresListener) bool {
	d := m.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// PostgresDecoyProfiles are the fabricated server shapes the listener has built
// in.
var PostgresDecoyProfiles = []string{"django", "generic-postgres", "rails"}

// postgresDeception checks the fabricated server.
func (v *validator) postgresDeception(p string, m *PostgresListener) {
	d := m.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener reaches a real server, and a "+
				"section that would fabricate an answer for any client that connects is not a decision "+
				"to arrive at by default", p)
		}
	case "decoy":
		if m.Upstream != "" {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream: use mode answer to "+
				"fabricate refusals on a listener that fronts a real server", p)
		}
		if len(d.Clients) == 0 {
			v.warnf("%s: no clients, so every client that connects is answered by the fabricated "+
				"server. That is what a honeypot is for, and on port 5432 it will be found", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	if d.Profile != "" && !slices.Contains(PostgresDecoyProfiles, d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, d.Profile, strings.Join(PostgresDecoyProfiles, ", "))
	}
	if len(d.Version) > 128 {
		v.errf("%s.version: %d characters, and a server_version is a few", p, len(d.Version))
	}
	if d.Version == "" {
		v.warnf("%s.version: empty, so the profile's version is reported. A decoy should say what the "+
			"estate's own servers say: a version nobody on the site runs is the tell that ends the "+
			"pretence, and only you know what that is", p)
	}
	for i, db := range d.Databases {
		if db == "" || len(db) > 63 {
			v.errf("%s.databases[%d]: must be 1 to 63 characters, which is what PostgreSQL allows", p, i)
		}
	}
	for i, t := range d.Tables {
		schema, name, ok := strings.Cut(t, ".")
		if !ok || schema == "" || name == "" {
			v.errf("%s.tables[%d]: %q must be written schema.table, because a catalogue query answers "+
				"per schema and a bare name belongs to none", p, i, t)
		}
	}
	for i, t := range d.Tripwire {
		if strings.TrimSpace(t) == "" || strings.ContainsAny(t, " \t\r\n") {
			v.errf("%s.tripwire[%d]: %q is not an object name; one name per entry", p, i, t)
		}
	}
	if d.Superuser {
		// The most consequential field of the section: a superuser can COPY FROM
		// PROGRAM, which is a shell command, so a decoy that says yes is
		// impersonating the account every scanner is hoping to find.
		v.warnf("%s.superuser: the fabrication will report a superuser role, which is the account a "+
			"scanner is hoping for: COPY FROM PROGRAM is a shell command and the visitor will try it. "+
			"The fabrication still runs nothing -- it answers the error a failed program gives -- but "+
			"saying no is both safer to impersonate and the more common truth on an application "+
			"account", p)
	}
	switch {
	case d.RequireAuth && d.Mode != "decoy":
		// There is no login for the fabrication to refuse in mode answer: the
		// real server accepts or refuses it, and this section only ever answers a
		// statement the policy has already stopped.
		v.warnf("%s.require_auth: does nothing in mode answer, where the login is the real server's "+
			"to accept or refuse; it applies to a decoy listener", p)
	case d.RequireAuth:
		v.warnf("%s.require_auth: the fabrication will refuse every login, so nothing past the "+
			"startup packet is ever collected. On this protocol the reconnaissance is the message, and "+
			"it happens after the login", p)
	}
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
}

func (v *validator) postgresListener(p string, m *PostgresListener, hasTLS bool) {
	if m.Upstream == "" && !postgresDecoyOnly(m) {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.postgresDeception(p+".deception", m)

	// require_tls defaults on, and a listener that requires it without a
	// certificate cannot serve anybody. Saying so here is better than every
	// connection failing at handshake with a message in a log nobody is
	// reading yet.
	requireTLS := m.RequireTLS == nil || *m.RequireTLS
	if requireTLS && !hasTLS {
		v.errf("%s.require_tls: set (it defaults on) but the listener has no tls section; "+
			"a postgres client upgrades an existing connection, so the listener needs a certificate", p)
	}
	if !requireTLS {
		v.warnf("%s.require_tls: false lets a client connect in the clear; libpq's default "+
			"sslmode=prefer then carries on unencrypted without telling anybody", p)
	}
	switch m.UpstreamTLSMode {
	case "", "require", "prefer", "disable":
	default:
		v.errf("%s.upstream_tls_mode: %q is not require, prefer or disable", p, m.UpstreamTLSMode)
	}
	if m.UpstreamTLSMode == "disable" {
		v.warnf("%s.upstream_tls_mode: disable means the leg to the server is in the clear, "+
			"which moves the exposure rather than removing it", p)
	}

	for i, name := range m.AllowAuth {
		if !postgresAuthNames[strings.ToLower(strings.TrimSpace(name))] {
			v.errf("%s.allow_auth[%d]: %q is not an authentication method (password, md5, scram, gss, sspi, kerberos, scm)", p, i, name)
		}
	}
	if m.AllowWeakAuth {
		v.warnf("%s.allow_weak_auth: true permits password (the password in cleartext) and md5 "+
			"(whose stored verifier is a password-equivalent); PostgreSQL has shipped SCRAM since version 10", p)
	}
	if m.AllowReplication {
		v.warnf("%s.allow_replication: true lets a connection open a replication stream, which is a "+
			"byte-for-byte copy of every database on the server including the role passwords", p)
	}
	if m.AllowFunctionCall {
		v.warnf("%s.allow_function_call: true permits the legacy fast-path interface, which names a "+
			"function by object identifier and bypasses the parser; nothing written this century sends it", p)
	}

	v.postgresStatements(p+".allow_statements", m.AllowStatements)
	v.postgresStatements(p+".deny_statements", m.DenyStatements)
	v.postgresCopy(p+".allow_copy", m.AllowCopy)

	for name, val := range map[string]int{
		"max_statements": m.MaxStatements, "max_statement_bytes": m.MaxStatementBytes,
		"max_message_bytes": m.MaxMessageBytes, "max_sessions": m.MaxSessions,
		"max_sessions_per_client": m.MaxSessionsPerClient,
	} {
		if val < 0 {
			v.errf("%s.%s: must not be negative", p, name)
		}
	}
	if m.MaxMessageBytes > pgwire.MaxMessage {
		v.errf("%s.max_message_bytes: %d is past the bound of %d", p, m.MaxMessageBytes, pgwire.MaxMessage)
	}

	switch m.DefaultAction {
	case "", "allow", "deny":
	default:
		v.errf("%s.default_action: %q is not allow or deny", p, m.DefaultAction)
	}
	switch m.DenyResponse {
	case "", "error", "drop":
	default:
		v.errf("%s.deny_response: %q is not error or drop", p, m.DenyResponse)
	}
	if m.DefaultAction == "allow" && len(m.AllowStatements) == 0 && !m.ReadOnly {
		v.warnf("%s: default_action allow with no allow_statements and read_only false lets every "+
			"statement kind the classifier can name through, including ddl and grant", p)
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		rp := fmt.Sprintf("%s.rules[%d]", p, i)
		v.modbusCIDRs(rp+".clients", r.Clients)
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: %q is not allow, deny or observe", rp, r.Action)
		}
		v.postgresStatements(rp+".allow_statements", r.AllowStatements)
		v.postgresStatements(rp+".deny_statements", r.DenyStatements)
		v.postgresCopy(rp+".allow_copy", r.AllowCopy)
		if r.MaxStatements < 0 {
			v.errf("%s.max_statements: must not be negative", rp)
		}
		if r.Schedule != nil {
			v.modbusSchedule(rp+".schedule", r.Schedule)
		}
	}
}

// postgresAuthNames are the methods a configuration may name, spelled as
// pg_hba.conf spells them.
var postgresAuthNames = map[string]bool{
	"password": true, "md5": true, "scram": true, "gss": true,
	"sspi": true, "kerberos": true, "scm": true,
}

// postgresStatements checks a list of statement kinds.
func (v *validator) postgresStatements(p string, in []string) {
	for i, name := range in {
		if _, ok := pgwire.KindOf(name); !ok {
			v.errf("%s[%d]: %q is not a statement kind (%s)", p, i, name,
				strings.Join(pgwire.KindNames(), ", "))
		}
	}
}

// postgresCopy checks a list of COPY targets. `program` is deliberately not
// nameable: COPY ... FROM PROGRAM runs a shell command as the server's
// operating-system user, and a setting that could switch it on through a relay
// is one somebody switches on by accident.
func (v *validator) postgresCopy(p string, in []string) {
	for i, name := range in {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "in", "out":
		case "file":
			v.warnf("%s[%d]: file lets COPY read and write the server's own filesystem, "+
				"which needs a privileged role", p, i)
		case "program":
			v.errf("%s[%d]: program cannot be allowed through this relay; COPY ... FROM PROGRAM "+
				"runs a command as the server's operating-system user", p, i)
		default:
			v.errf("%s[%d]: %q is not in, out or file", p, i, name)
		}
	}
}

func (v *validator) tftpListener(p string, m *TFTPListener) {
	v.engineering(p+".engineering", m.Engineering)
	switch m.Mode {
	case "", "reverse", "forward":
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	if l := m.Learn; l != nil && l.Enabled {
		if l.File == "" {
			v.errf("%s.learn.file: required when learning is enabled", p)
		} else if !strings.HasPrefix(l.File, "/") {
			v.errf("%s.learn.file: must be an absolute path", p)
		}
		if l.Interval != 0 && (l.Interval.D() < 10*time.Second || l.Interval.D() > 24*time.Hour) {
			v.errf("%s.learn.interval: must be between 10s and 24h", p)
		}
		if l.MaxSubjects != 0 && (l.MaxSubjects < 16 || l.MaxSubjects > 1_000_000) {
			v.errf("%s.learn.max_subjects: must be between 16 and 1000000", p)
		}
		if !l.Enforce {
			v.warnf("%s.learn is enabled without enforce, so this listener records and decides nothing: "+
				"turn enforce on, or take the learning section out, once the rules are written. "+
				"The block, window and transfer-size bounds stay in force either way", p)
		}
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	if len(m.AllowClients) == 0 {
		// On a protocol with no credential at all, this list is the whole
		// of the identity.
		v.warnf("%s.allow_clients: empty, so any address may transfer through this relay -- and TFTP has no other identity to check", p)
	}
	ops := v.tftpOperations(p+".operations", m.Operations)
	if ops[tftpwire.OpWrite] {
		v.warnf("%s.operations: write allows a client to put files onto the server, which is how a configuration leaves an estate and how firmware arrives in it", p)
	}
	modes := v.tftpModes(p+".modes", m.Modes)
	if modes[tftpwire.ModeMail] {
		v.warnf("%s.modes: mail is obsolete -- RFC 1350 removed it -- and asked the server to deliver the file as mail to the address in the filename field", p)
	}
	v.tftpClasses(p+".allow_path_classes", m.AllowPathClasses)
	v.tftpDirs(p+".directories", m.Directories)
	v.tftpDirs(p+".deny_directories", m.DenyDirectories)
	if len(m.Directories) == 0 {
		v.warnf("%s.directories: empty, so a transfer may name any path the server serves", p)
	}
	v.tftpPatterns(p+".filenames", m.Filenames)
	v.tftpPatterns(p+".deny_filenames", m.DenyFilenames)
	if m.MaxDepth < 0 || m.MaxDepth > 64 {
		v.errf("%s.max_depth: must be between 0 and 64", p)
	}
	if m.MaxFilenameBytes < 0 || m.MaxFilenameBytes > tftpwire.MaxFilename {
		v.errf("%s.max_filename_bytes: must be between 0 and %d", p, tftpwire.MaxFilename)
	}
	if m.MaxTransferBytes < 0 || m.MaxTransferBytes > 1<<40 {
		v.errf("%s.max_transfer_bytes: must be between 0 and %d", p, int64(1)<<40)
	}
	if m.MaxTransferBytes == 0 {
		v.warnf("%s.max_transfer_bytes: 0 leaves a transfer unbounded, and a write with no bound is a disk somebody else fills", p)
	}
	if m.MaxBlockSize != 0 && (m.MaxBlockSize < tftpwire.MinBlockSize || m.MaxBlockSize > tftpwire.MaxBlockSize) {
		v.errf("%s.max_block_size: must be between %d and %d", p, tftpwire.MinBlockSize, tftpwire.MaxBlockSize)
	}
	if m.MaxWindowSize < 0 || m.MaxWindowSize > tftpwire.MaxWindowSize {
		v.errf("%s.max_window_size: must be between 0 and %d", p, tftpwire.MaxWindowSize)
	}
	if m.MaxWindowSize == 0 {
		v.warnf("%s.max_window_size: 0 leaves RFC 7440's window unbounded, which is this protocol's amplification factor: a twenty-octet request answered by a window of packets", p)
	}
	if m.MaxTransfers < 0 || m.MaxTransfers > 1<<16 {
		v.errf("%s.max_transfers: must be between 0 and 65536", p)
	}
	if m.MaxTransfersPerClient < 0 || m.MaxTransfersPerClient > 1<<16 {
		v.errf("%s.max_transfers_per_client: must be between 0 and 65536", p)
	}
	switch m.DefaultAction {
	case "", "deny", "allow":
	default:
		v.errf("%s.default_action: must be deny or allow", p)
	}
	if m.DefaultAction == "allow" && len(m.Rules) == 0 {
		v.warnf("%s: default_action allow with no rules relays every transfer this listener can reach, from any address the client list admits", p)
	}
	switch m.DenyResponse {
	case "", "error", "drop":
	default:
		v.errf("%s.deny_response: must be error or drop", p)
	}
	if m.DenyResponse == "drop" {
		v.warnf("%s.deny_response: drop makes a refused client retransmit until it times out, where error makes it stop", p)
	}
	for _, d := range []struct {
		key    string
		val    Duration
		lo, hi time.Duration
	}{
		{"transfer_timeout", m.TransferTimeout, time.Second, 24 * time.Hour},
		{"idle_timeout", m.IdleTimeout, time.Second, time.Hour},
	} {
		if d.val != 0 && (d.val.D() < d.lo || d.val.D() > d.hi) {
			v.errf("%s.%s: must be between %s and %s", p, d.key, d.lo, d.hi)
		}
	}
	if m.TransferTimeout != 0 && m.IdleTimeout != 0 && m.IdleTimeout.D() > m.TransferTimeout.D() {
		v.errf("%s.idle_timeout: longer than transfer_timeout, so it would never end a transfer", p)
	}
	if m.RateLimit < 0 || m.RateLimit > 1<<20 {
		v.errf("%s.rate_limit: must be between 0 and 1048576", p)
	}
	if m.RateBurst < 0 || m.RateBurst > 1<<20 {
		v.errf("%s.rate_burst: must be between 0 and 1048576", p)
	}
	if m.RateLimit == 0 && m.RateBurst > 0 {
		v.warnf("%s.rate_burst: a burst without a rate_limit bounds nothing", p)
	}
	names := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		if !nameRE.MatchString(r.Name) {
			v.errf("%s.name: %q is not a valid name", q, r.Name)
		} else if names[r.Name] {
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		names[r.Name] = true
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", q)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		v.tftpOperations(q+".operations", r.Operations)
		v.tftpModes(q+".modes", r.Modes)
		v.tftpClasses(q+".allow_path_classes", r.AllowPathClasses)
		v.tftpDirs(q+".directories", r.Directories)
		v.tftpDirs(q+".deny_directories", r.DenyDirectories)
		v.tftpPatterns(q+".filenames", r.Filenames)
		v.tftpPatterns(q+".deny_filenames", r.DenyFilenames)
		if r.MaxTransferBytes < 0 || r.MaxTransferBytes > 1<<40 {
			v.errf("%s.max_transfer_bytes: must be between 0 and %d", q, int64(1)<<40)
		}
		if r.MaxBlockSize != 0 && (r.MaxBlockSize < tftpwire.MinBlockSize || r.MaxBlockSize > tftpwire.MaxBlockSize) {
			v.errf("%s.max_block_size: must be between %d and %d", q, tftpwire.MinBlockSize, tftpwire.MaxBlockSize)
		}
		if r.MaxWindowSize < 0 || r.MaxWindowSize > tftpwire.MaxWindowSize {
			v.errf("%s.max_window_size: must be between 0 and %d", q, tftpwire.MaxWindowSize)
		}
		v.modbusSchedule(q+".schedule", r.Schedule)
	}
}

// tftpOperations checks a transfer-direction list and returns it as a set.
func (v *validator) tftpOperations(p string, in []string) map[tftpwire.Op]bool {
	out := map[tftpwire.Op]bool{}
	for i, name := range in {
		op, ok := tftpwire.OpOf(name)
		if !ok || !op.Request() {
			v.errf("%s[%d]: %q must be read or write", p, i, name)
			continue
		}
		out[op] = true
	}
	return out
}

// tftpModes checks a transfer-mode list and returns it as a set.
func (v *validator) tftpModes(p string, in []string) map[string]bool {
	out := map[string]bool{}
	for i, name := range in {
		switch m := strings.ToLower(name); m {
		case tftpwire.ModeOctet, tftpwire.ModeNetASCII, tftpwire.ModeMail:
			out[m] = true
		default:
			v.errf("%s[%d]: %q must be octet, netascii or mail", p, i, name)
		}
	}
	return out
}

// tftpClasses checks a path-class list.
//
// The three classes a configuration may not name are refused here rather
// than ignored at run time, because an operator who wrote one asked for
// something this relay will not do and is owed the answer at load: a name
// whose end two parsers disagree about cannot be decided at all, so
// "allowed" is not a thing it can be.
func (v *validator) tftpClasses(p string, in []string) {
	for i, name := range in {
		c, ok := tftpwire.ClassOf(name)
		switch {
		case !ok:
			v.errf("%s[%d]: %q must be absolute, backslash, drive, traversal, trailing or non_ascii", p, i, name)
		case c == tftpwire.ClassPlain:
			v.errf("%s[%d]: plain is every ordinary path and is always allowed, so naming it says nothing", p, i)
		case c.Hard():
			v.errf("%s[%d]: %q can never be allowed: it means this relay and the server read different filenames", p, i, name)
		case c == tftpwire.ClassTraversal:
			v.warnf("%s[%d]: traversal allows a .. element, which is how every path escape in this protocol's history was written", p, i)
		}
	}
}

// tftpDirs checks a directory list. A directory is compared element by
// element, so what is checked here is that there is an element to compare.
func (v *validator) tftpDirs(p string, in []string) {
	for i, d := range in {
		if strings.TrimSpace(d) == "" {
			v.errf("%s[%d]: empty; the server's own directory is not one worth naming, because it is every directory", p, i)
			continue
		}
		if c := tftpwire.Classify(d); c.Class.Hard() {
			v.errf("%s[%d]: %q is not a directory a filename can be under: %s", p, i, d, c.Detail)
		}
	}
}

// tftpPatterns checks a filename pattern list.
func (v *validator) tftpPatterns(p string, in []string) {
	for i, pat := range in {
		if pat == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		if _, err := path.Match(pat, "x"); err != nil {
			v.errf("%s[%d]: %q is not a pattern: %v", p, i, pat, err)
		}
	}
}

// snmpDecoyOnly says whether this listener is nothing but a fabricated
// agent, which is the one shape that needs no upstream: there is no agent
// behind it to reach.
func snmpDecoyOnly(m *SNMPListener) bool {
	d := m.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// SNMPDecoyProfiles are the fabricated device shapes the listener has built
// in. The list lives here so the error can name them, and a test in the kind
// keeps the two in step.
var SNMPDecoyProfiles = []string{"generic-switch", "generic-router"}

func (v *validator) snmpDeception(p string, m *SNMPListener) {
	d := m.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener reaches a real agent, and a section "+
				"that would fabricate an answer for any client that connects is not a decision to arrive at "+
				"by default", p)
		}
	case "decoy":
		if m.Upstream != "" {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream: "+
				"use mode answer to fabricate refusals on a listener that fronts an agent", p)
		}
		if len(d.Clients) == 0 {
			// Not an error, but worth saying out loud on this protocol in
			// particular: an SNMP listener answering every client is a UDP
			// service answering strangers, and the amplification bounds are
			// what keep that from being an amplifier.
			v.warnf("%s: no clients, so every client that sends a datagram is answered by the fabricated "+
				"agent. That is what a honeypot is for, and on a datagram protocol it is also what an "+
				"amplifier is: max_repetitions, max_var_binds and max_response_bytes are the bounds that "+
				"make the difference, and they apply to the fabrication too", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	if d.Mode != "decoy" && m.DenyResponse == "drop" {
		v.warnf("%s: deny_response drop does not apply to the clients this section covers -- their refused "+
			"requests are answered by the fabricated agent rather than ignored", p)
	}
	if d.Profile != "" && !slices.Contains(SNMPDecoyProfiles, d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, d.Profile, strings.Join(SNMPDecoyProfiles, ", "))
	}
	if d.SysObjectID != "" {
		if _, err := snmpwire.ParseOID(d.SysObjectID); err != nil {
			v.errf("%s.sys_object_id: %v", p, err)
		}
	}
	for i, o := range d.Tripwire {
		if _, err := snmpwire.ParseOID(o); err != nil {
			v.errf("%s.tripwire[%d]: %v", p, i, err)
		}
	}
	for _, f := range []struct{ name, text string }{
		{"sys_descr", d.SysDescr}, {"sys_name", d.SysName},
		{"sys_contact", d.SysContact}, {"sys_location", d.SysLocation},
	} {
		if len(f.text) > 255 {
			v.errf("%s.%s: %d characters, and one of these objects carries 255", p, f.name, len(f.text))
		}
	}
	if n := d.Interfaces; n < 0 || n > 256 {
		v.errf("%s.interfaces: must be between 0 and 256", p)
	}
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
}

// SNMPAuthAlgos and SNMPPrivAlgos are the version 3 protocol names
// usm_users accepts, which are the wire package's own lists so that a name
// validation accepts is a name the reader can use.
var (
	SNMPAuthAlgos = snmpAlgoNames()
	SNMPPrivAlgos = snmpPrivNames()
)

func snmpAlgoNames() []string {
	out := make([]string, 0, len(snmpwire.AuthAlgos))
	for _, a := range snmpwire.AuthAlgos {
		out = append(out, string(a))
	}
	return out
}

func snmpPrivNames() []string {
	out := make([]string, 0, len(snmpwire.PrivAlgos))
	for _, p := range snmpwire.PrivAlgos {
		out = append(out, string(p))
	}
	return out
}

// snmpUpstreamUSM checks the identity this relay presents to the agent.
//
// It is held to the same rules as a user this listener reads, plus the ones that
// are only about originating: a level needs the keys it uses, and terminating
// the manager's security is a thing an operator should be told they have done.
func (v *validator) snmpUpstreamUSM(p string, m *SNMPListener) {
	u := m.UpstreamUSM
	if u == nil {
		if m.UpstreamSecurityLevel != "" {
			v.errf("%s.upstream_security_level: set without upstream_usm, so there is no identity to originate as", p)
		}
		return
	}
	q := p + ".upstream_usm"
	v.snmpUser(q, u, m)
	level := snmpwire.AuthPriv
	if u.Privacy == "" {
		level = snmpwire.AuthNoPriv
	}
	if m.UpstreamSecurityLevel != "" {
		lvl, ok := snmpwire.LevelOf(m.UpstreamSecurityLevel)
		if !ok {
			v.errf("%s.upstream_security_level: must be noAuthNoPriv, authNoPriv or authPriv", p)
		} else {
			level = lvl
		}
	}
	switch {
	case level == snmpwire.AuthPriv && u.Privacy == "":
		v.errf("%s.upstream_security_level: authPriv needs upstream_usm.privacy and a privacy pass phrase", p)
	case level == snmpwire.NoAuthNoPriv:
		// Allowed, because an agent that only speaks v3 and trusts the
		// network is a real deployment. Said out loud, because originating at
		// noAuthNoPriv with a pass phrase configured is almost always a
		// mistake in the level rather than a decision about it.
		v.warnf("%s.upstream_security_level: noAuthNoPriv originates unauthenticated v3, so the pass phrases "+
			"in upstream_usm are not used and anything that can reach the agent can forge this relay's "+
			"messages to it", p)
	case u.Privacy != "" && level == snmpwire.AuthNoPriv:
		v.warnf("%s.upstream_security_level: authNoPriv with a privacy pass phrase configured, so the requests "+
			"to the agent are signed and readable on the wire. The reason to configure privacy is to use it", p)
	}
	if up, ok := snmpwire.VersionOf(m.UpgradeVersion); m.UpgradeVersion == "" || !ok || up != snmpwire.V3 {
		v.warnf("%s.upstream_usm: configured without upgrade_version: v3, so nothing originates as it and the "+
			"pass phrases are unused", p)
	}
	// The consequence, once, where an operator reading the file will see it.
	v.warnf("%s.upstream_usm: this relay now terminates the manager's security and originates its own, so "+
		"there is no end-to-end authentication between the manager and the agent: the manager authenticates "+
		"to this relay and this relay authenticates to the agent. That is the point of it and it is also what "+
		"an estate has to decide it wants", p)
}

// snmpUser checks one version 3 user, whether it is a user this listener reads
// or the identity it presents to the agent. One function so that both are held
// to one set of rules: an upstream identity validated more loosely than a
// downstream one would be the weaker half of a configuration whose whole point
// is that the upstream half is stronger.
func (v *validator) snmpUser(q string, u *SNMPUser, m *SNMPListener) {
	switch {
	case u.Name == "":
		v.errf("%s.name: required", q)
	case len(u.Name) > 255:
		v.errf("%s.name: longer than 255 octets", q)
	}
	auth, ok := snmpwire.AuthAlgoOf(u.Auth)
	if !ok {
		v.errf("%s.auth: %q is not an authentication protocol; the ones USM defines are %s",
			q, u.Auth, strings.Join(SNMPAuthAlgos, ", "))
	} else if auth == snmpwire.AuthMD5 || auth == snmpwire.AuthSHA1 {
		v.warnf("%s.auth: %s is RFC 3414's original and is weak by any current measure. It is here "+
			"because it is what the installed base speaks; where the equipment can do better, "+
			"RFC 7860's sha256 is the same configuration with a different word", q, auth)
	}
	if u.AuthSecret == "" {
		v.errf("%s.auth_secret: required", q)
	} else {
		v.secretRef(q+".auth_secret", u.AuthSecret)
	}
	if u.Privacy == "" {
		if u.PrivacySecret != "" {
			v.errf("%s.privacy: required with privacy_secret", q)
		}
		// A user with no privacy key cannot be read at authPriv, and this
		// relay refuses what it cannot read rather than forwarding it
		// around the rules. Whether that matters depends on the listener's
		// own floor.
		if m.MinSecurityLevel != "" {
			if lvl, ok := snmpwire.LevelOf(m.MinSecurityLevel); ok && lvl == snmpwire.AuthPriv {
				v.errf("%s.privacy: required, because min_security_level authPriv means every message "+
					"from %q arrives encrypted and without a privacy key none of them can be read -- "+
					"so all of them would be refused", q, u.Name)
			}
		}
		return
	}
	priv, ok := snmpwire.PrivAlgoOf(u.Privacy)
	if !ok {
		v.errf("%s.privacy: %q is not a privacy protocol; the ones USM defines are %s",
			q, u.Privacy, strings.Join(SNMPPrivAlgos, ", "))
	} else {
		if priv == snmpwire.PrivDES {
			v.warnf("%s.privacy: des is a fifty-six bit cipher, which is RFC 3414's own and is "+
				"breakable. RFC 3826's aes128 is the same configuration with a different word", q)
		}
		// One derivation, truncated by the cipher: a sixteen-octet MD5 key
		// cannot key AES-256.
		if have, need := auth.KeyLen(), priv.KeyLen(); ok && have > 0 && have < need {
			v.errf("%s.privacy: %s needs %d key octets and %s derives %d; USM has one key derivation "+
				"and the cipher truncates it, so pair a wider authentication protocol with this one",
				q, priv, need, auth, have)
		}
	}
	if u.PrivacySecret == "" {
		v.errf("%s.privacy_secret: required with privacy", q)
	} else {
		v.secretRef(q+".privacy_secret", u.PrivacySecret)
		if u.PrivacySecret == u.AuthSecret {
			v.warnf("%s.privacy_secret: the same reference as auth_secret, so one pass phrase keys both "+
				"the digest and the cipher. USM allows it and every tool does it; it means one guess "+
				"gets both", q)
		}
	}
}

// snmpUSMUsers checks the version 3 users whose keys this listener holds.
//
// Everything here is about a configuration that would load and then refuse the
// traffic it was written to read: a protocol name that is not one, a pass
// phrase that resolves to nothing, an engine identifier that is not
// hexadecimal, or a hash too narrow to key the cipher named beside it.
func (v *validator) snmpUSMUsers(p string, m *SNMPListener) {
	seen := map[string]bool{}
	for i := range m.USMUsers {
		u := &m.USMUsers[i]
		q := fmt.Sprintf("%s[%d]", p, i)
		if u.Name != "" && seen[u.Name] {
			v.errf("%s.name: %q appears twice; one user has one set of keys", q, u.Name)
		}
		seen[u.Name] = true
		v.snmpUser(q, u, m)
	}
	for i, u := range m.USMUsers {
		if u.EngineID == "" {
			continue
		}
		if _, err := parseSNMPEngineID(u.EngineID); err != nil {
			v.errf("%s[%d].engine_id: %v", p, i, err)
		}
	}
	// Named in usm_users but not in users: the keys are held and the allow
	// list does not let the user through, which is a configuration that reads
	// as working and refuses everything.
	if len(m.Users) > 0 {
		for _, u := range m.USMUsers {
			if u.Name != "" && !slices.Contains(m.Users, u.Name) {
				v.warnf("%s: %q has keys here and is not in users, so every message from it is refused by "+
					"the allow list before the keys are reached", p, u.Name)
			}
		}
	}
	if len(m.USMUsers) > 0 && len(m.Versions) > 0 && !slices.Contains(m.Versions, "v3") {
		v.warnf("%s: this listener does not accept v3, so these keys are never used", p)
	}
}

// parseSNMPEngineID reads a configured engine identifier, which is the same
// hexadecimal the tools print. It is duplicated from the listener kind rather
// than imported because internal/config must not depend on a kind.
func parseSNMPEngineID(s string) ([]byte, error) {
	t := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	t = strings.NewReplacer(":", "", "-", "", " ", "").Replace(t)
	b, err := hex.DecodeString(t)
	if err != nil {
		return nil, fmt.Errorf("%q is not hexadecimal: %w", s, err)
	}
	if len(b) == 0 || len(b) > 32 {
		return nil, fmt.Errorf("an engine identifier is 1 to 32 octets and this is %d", len(b))
	}
	return b, nil
}

// snmpHasDTLS says whether this listener puts its datagrams inside DTLS.
func snmpHasDTLS(m *SNMPListener) bool {
	return m.DTLSMode != "" && m.DTLSMode != "none"
}

// snmpDTLS checks RFC 6353's transport model on the datagram half: the mode,
// its bounds, and the table that turns a certificate into a name.
//
// The warnings here are the ones worth writing down, because each names a
// configuration that looks like a control and is not one. A `detect` listener
// whose rules do not name a transport lets the client choose whether to present
// a certificate. A `cert_to_name` row matching any certificate on a listener
// that does not require one is a row matching anybody. And a listener that
// takes the transport model without mapping any certificate to a name refuses
// every such message, which is a working listener that nothing can get through.
func (v *validator) snmpDTLS(p string, m *SNMPListener, tc *TLS, udp bool) {
	switch m.DTLSMode {
	case "", "none", "implicit", "detect":
	default:
		v.errf("%s.dtls_mode: must be none, implicit or detect", p)
	}
	if !snmpHasDTLS(m) {
		if len(m.CertToName) > 0 {
			v.warnf("%s.cert_to_name: nothing here speaks a transport that carries a certificate, so no name is ever derived; dtls_mode on the datagram half or tls_mode on the stream half is what makes it apply", p)
		}
		v.snmpCertToName(p, m, tc)
		return
	}
	if !udp {
		v.errf("%s.dtls_mode: needs a datagram socket, and transport: tcp opens none. Use transport: udp (the default), or tls_mode for the stream half", p)
	}
	if tc == nil {
		v.errf("%s.dtls_mode: %s needs the listener's tls section, for the certificate this relay presents", p, m.DTLSMode)
	} else if tc.MinVersion == "1.3" {
		v.errf("%s.dtls_mode: the tls section requires TLS 1.3 and this transport is DTLS 1.2, so no handshake would ever complete", p)
	}
	if m.DTLSMode == "detect" {
		v.snmpDetect(p, m)
	}
	for _, d := range []struct {
		key    string
		val    Duration
		lo, hi time.Duration
	}{
		{"dtls_handshake_timeout", m.DTLSHandshakeTimeout, time.Second, time.Minute},
		{"dtls_idle_timeout", m.DTLSIdleTimeout, time.Second, time.Hour},
	} {
		if d.val != 0 && (d.val.D() < d.lo || d.val.D() > d.hi) {
			v.errf("%s.%s: must be between %s and %s", p, d.key, d.lo, d.hi)
		}
	}
	if m.MaxDTLSPeers < 0 || m.MaxDTLSPeers > 1<<16 {
		v.errf("%s.max_dtls_peers: must be between 0 and 65536", p)
	}
	v.snmpCertToName(p, m, tc)
	if len(m.CertToName) == 0 {
		if m.RequireSecurityName == nil || *m.RequireSecurityName {
			v.warnf("%s.cert_to_name: empty, so a message under the transport security model maps to no name and is refused (require_security_name). Add a row, or set require_security_name: false for a listener that wants DTLS for confidentiality and decides on the address alone", p)
		} else {
			v.warnf("%s.require_security_name: false with no cert_to_name means the certificate identifies nobody here: the session is confidential and the policy decides on the address and the objects alone", p)
		}
	}
}

// snmpDetect is the warning that keeps detect mode honest.
//
// In detect mode a client chooses whether to speak DTLS, because both are
// accepted on the one port. That is the point -- it is what an estate part-way
// through a migration needs -- and it means the *policy* has to be what requires
// the certificate. A listener that allows by default, or whose rules never name
// a transport, has a DTLS mode and no DTLS requirement.
func (v *validator) snmpDetect(p string, m *SNMPListener) {
	named := false
	for i := range m.Rules {
		if len(m.Rules[i].Transports) > 0 || len(m.Rules[i].SecurityNames) > 0 {
			named = true
			break
		}
	}
	if m.DefaultAction == "allow" {
		v.warnf("%s.dtls_mode: detect accepts plain datagrams on the same port, so with default_action: allow a client reaches the agents by simply not offering a certificate", p)
	}
	if !named {
		v.warnf("%s.dtls_mode: detect accepts plain datagrams on the same port and no rule names transports or security_names, so nothing here requires the DTLS half; a client chooses which to speak", p)
	}
}

// snmpCertToName checks RFC 6353 s5.3's mapping table.
func (v *validator) snmpCertToName(p string, m *SNMPListener, tc *TLS) {
	anyRow := false
	for i := range m.CertToName {
		r := &m.CertToName[i]
		q := fmt.Sprintf("%s.cert_to_name[%d]", p, i)
		how := r.Map
		if how == "" {
			how = snmpwire.CertMapSANAny
		}
		switch {
		case !snmpwire.CertMapKnown(how):
			v.errf("%s.map: %q must be one of %s", q, r.Map,
				strings.Join(snmpwire.CertMaps(), ", "))
		case !snmpwire.CertMapDerives(how) && r.Name == "":
			v.errf("%s.name: required with map: %s, which takes the name from here rather than from the certificate", q, how)
		case snmpwire.CertMapDerives(how) && r.Name != "":
			// A name beside a mapping that derives one looks like it applies
			// and does not, which is the kind of configuration an operator
			// reads as a control and tests as a hole.
			v.errf("%s.name: map: %s derives the name from the certificate, so name must be empty", q, how)
		}
		if how == snmpwire.CertMapCommonName {
			v.warnf("%s.map: common_name is RFC 6353's last resort and it advises against it: a common name is free text that has meant several things, and two authorities can issue the same one. A subject alternative name is what a certificate issued this decade puts the subject in", q)
		}
		algo, _, err := snmpwire.ParseFingerprint(r.Fingerprint)
		switch {
		case err != nil:
			v.errf("%s.fingerprint: %v", q, err)
		case algo == "":
			anyRow = true
		case algo == "sha1":
			v.warnf("%s.fingerprint: sha1 is in RFC 6353 for the equipment that shipped with it; sha256 is what to write for anything issued since", q)
		}
	}
	if anyRow && !snmpVerifiesClients(tc) {
		// The row means "any certificate this listener accepted", and a
		// listener that does not require and verify one accepts every peer
		// including the ones that offered nothing.
		v.warnf("%s.cert_to_name: a row matching any fingerprint names whichever certificate the handshake accepted, and this listener's tls section does not require and verify one -- so the name is derived from whatever a peer chose to send. Set tls.client_auth: require with tls.client_ca_file", p)
	}
}

// snmpVerifiesClients says whether the listener's TLS section makes a client
// certificate mandatory and checks it against an authority.
func snmpVerifiesClients(tc *TLS) bool {
	return tc != nil && tc.ClientAuth == "require" && tc.ClientCAFile != ""
}

func (v *validator) snmpListener(p string, m *SNMPListener, tc *TLS) {
	v.anomaly(p+".anomaly", m.Anomaly)
	v.engineering(p+".engineering", m.Engineering)
	hasTLS := tc != nil
	switch m.Mode {
	case "", "reverse", "forward":
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	if m.Upstream == "" && !snmpDecoyOnly(m) {
		v.errf("%s.upstream: required", p)
	}
	v.snmpDeception(p+".deception", m)
	switch m.Transport {
	case "", "udp", "tcp":
	default:
		v.errf("%s.transport: must be udp or tcp", p)
	}
	udp := m.Transport == "" || m.Transport == "udp"
	switch m.TLSMode {
	case "", "implicit", "none":
	default:
		v.errf("%s.tls_mode: must be implicit or none", p)
	}
	if m.TLSMode == "implicit" {
		if !hasTLS {
			v.errf("%s.tls_mode: implicit needs the listener's tls section", p)
		}
		if udp && !snmpHasDTLS(m) {
			// RFC 6353 puts TLS on TCP 10161 and DTLS on UDP 10161. tls_mode
			// is the stream half, so with transport udp the datagram half of
			// this listener is unprotected unless dtls_mode covers it. Saying
			// so is better than implying a whole listener is encrypted when
			// half of it is plaintext.
			v.warnf("%s.tls_mode: implicit protects the stream half only; the datagram socket transport udp adds stays plaintext. Add dtls_mode: implicit for RFC 6353 on the datagram half too, or transport: tcp for a listener that is TLS throughout", p)
		}
	}
	v.snmpDTLS(p, m, tc, udp)
	switch m.UpstreamTLSMode {
	case "", "none", "implicit":
	default:
		v.errf("%s.upstream_tls_mode: must be none or implicit", p)
	}
	if m.UpstreamTLSMode == "implicit" && udp {
		v.warnf("%s.upstream_tls_mode: implicit applies to the stream half only; datagrams go to the agent as plain UDP", p)
	}
	if m.UpstreamTLS != nil {
		v.upstreamTLS(p+".upstream_tls", m.UpstreamTLS)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	if len(m.AllowClients) == 0 {
		v.warnf("%s.allow_clients: empty, so any address may poll the agents behind this relay; a community string is not a secret in any useful sense", p)
	}
	// Which versions this listener takes, which the upgrade rules below are
	// written against: a v3 message carries no community string to forward,
	// and its answer cannot be authenticated by a relay with no keys.
	v3only, takesV3 := len(m.Versions) > 0, len(m.Versions) == 0
	for i, name := range m.Versions {
		ver, ok := snmpwire.VersionOf(name)
		if !ok {
			v.errf("%s.versions[%d]: %q must be v1, v2c or v3", p, i, name)
			continue
		}
		if ver == snmpwire.V3 {
			takesV3 = true
		} else {
			v3only = false
		}
	}
	if len(m.Versions) == 0 {
		v.warnf("%s.versions: empty, so v1 and v2c are accepted; their credential is a cleartext community string in every datagram", p)
	}
	for i, c := range m.Communities {
		switch {
		case c == "":
			v.errf("%s.communities[%d]: empty", p, i)
		case len(c) > 255:
			v.errf("%s.communities[%d]: longer than 255 octets", p, i)
		case c == "public" || c == "private":
			v.warnf("%s.communities[%d]: %q is a default that is scanned for constantly", p, i, c)
		}
	}
	for i, u := range m.Users {
		if u == "" || len(u) > 255 {
			v.errf("%s.users[%d]: must be 1 to 255 octets", p, i)
		}
	}
	if m.MinSecurityLevel != "" {
		lvl, ok := snmpwire.LevelOf(m.MinSecurityLevel)
		if !ok {
			v.errf("%s.min_security_level: must be noAuthNoPriv, authNoPriv or authPriv", p)
		} else if lvl == snmpwire.NoAuthNoPriv {
			v.warnf("%s.min_security_level: noAuthNoPriv refuses nothing; it is version 2c with more fields", p)
		}
	}
	v.snmpUSMUsers(p+".usm_users", m)
	if w := m.ReplayWindow.D(); w != 0 && (w < time.Second || w > time.Hour) {
		v.errf("%s.replay_window: must be between 1s and 1h", p)
	}
	if len(m.USMUsers) == 0 && m.ReplayWindow != 0 {
		v.warnf("%s.replay_window: a replay is recognised by the clock inside an authenticated message, so "+
			"this does nothing without usm_users to verify one with", p)
	}
	if n := m.MaxUSMEngines; n < 0 || n > 1024 {
		v.errf("%s.max_usm_engines: must be between 0 and 1024", p)
	}
	if takesV3 && len(m.USMUsers) == 0 {
		// The gap this is about: every rule an operator wrote about
		// operations and object identifiers applies to v1 and v2c and does
		// not apply to v3, because a v3 payload cannot be read without the
		// user's keys.
		v.warnf("%s.usm_users: empty, so a v3 message is a header and an opaque payload here: the user, the "+
			"engine and the security level are checked and no rule about an operation or an object can be. "+
			"The keys are needed for reading only -- nothing is re-signed or re-encrypted", p)
	}
	if m.UpgradeVersion != "" {
		up, ok := snmpwire.VersionOf(m.UpgradeVersion)
		if !ok {
			v.errf("%s.upgrade_version: must be v1, v2c or v3", p)
		} else if up != snmpwire.V3 && m.UpstreamCommunity == "" && !v3only {
			// Upgrading down to v1 or v2c needs a community string to send,
			// and a v3 message has none to carry over. Refusing here is the
			// difference between a misconfiguration and every request being
			// forwarded with an empty credential.
			v.errf("%s.upstream_community: required with upgrade_version %s, because a v3 message carries no community string to forward", p, m.UpgradeVersion)
		}
		if up == snmpwire.V3 && m.UpstreamUSM == nil {
			// Without an identity of its own there is no pass phrase to
			// authenticate with, and this relay will not forge an
			// authentication that did not happen.
			v.errf("%s.upgrade_version: v3 needs upstream_usm, the identity this relay presents to the agent: "+
				"without a user and a pass phrase of its own there is nothing to authenticate the message with", p)
		}
		if up != snmpwire.V3 && takesV3 && !m.Traps {
			// A v3 request downgraded to v2c gets a v2c answer, and giving
			// that to a v3 manager would mean authenticating it with a key
			// this relay does not hold. The relay refuses such a request
			// rather than half-translating it, and saying so here is the
			// difference between a design decision and a surprise.
			v.warnf("%s.upgrade_version: a v3 *request* cannot be downgraded -- its answer would have to be authenticated, and this relay reads USM messages but never writes one -- so v3 requests on this listener are refused. The downgrade that works end to end is a v3 notification to a legacy collector: traps: true", p)
		}
	}
	if m.UpstreamCommunity != "" && len(m.UpstreamCommunity) > 255 {
		v.errf("%s.upstream_community: longer than 255 octets", p)
	}
	v.snmpUpstreamUSM(p, m)
	if m.Traps && m.ReadOnly {
		v.warnf("%s.read_only: a trap listener carries no SetRequest, so read_only refuses nothing here", p)
	}
	switch m.DefaultAction {
	case "", "deny", "allow":
	default:
		v.errf("%s.default_action: must be deny or allow", p)
	}
	if m.DefaultAction == "allow" && len(m.Rules) == 0 && !m.ReadOnly {
		v.warnf("%s: default_action allow with no rules and without read_only relays every SetRequest to the equipment", p)
	}
	switch m.DenyResponse {
	case "", "error", "drop", "close":
	default:
		v.errf("%s.deny_response: must be error, drop or close", p)
	}
	if m.DenyResponse == "close" && udp {
		v.warnf("%s.deny_response: close ends a stream session; on the datagram half there is no connection to end, so it reads as drop and the manager sees a timeout", p)
	}
	if m.MaxRepetitions < 0 || m.MaxRepetitions > 1<<20 {
		v.errf("%s.max_repetitions: must be between 0 and 1048576", p)
	}
	if m.MaxRepetitions == 0 && !m.Traps {
		v.warnf("%s.max_repetitions: 0 leaves a GETBULK's repetition count unbounded, which is the amplification factor of the best-known SNMP reflection attack", p)
	}
	if m.MaxVarBinds < 0 || m.MaxVarBinds > snmpwire.MaxVarBinds {
		v.errf("%s.max_var_binds: must be between 0 and %d", p, snmpwire.MaxVarBinds)
	}
	if m.MaxResponseBytes < 0 || m.MaxResponseBytes > snmpwire.MaxMessage {
		v.errf("%s.max_response_bytes: must be between 0 and %d", p, snmpwire.MaxMessage)
	}
	if m.MaxResponseRatio < 0 || m.MaxResponseRatio > 1<<16 {
		v.errf("%s.max_response_ratio: must be between 0 and 65536", p)
	}
	if m.MaxPending < 0 || m.MaxPending > 1<<16 {
		v.errf("%s.max_pending: must be between 0 and 65536", p)
	}
	if m.MaxConnections < 0 || m.MaxConnections > 4096 {
		v.errf("%s.max_connections: must be between 0 and 4096", p)
	}
	for _, d := range []struct {
		key    string
		val    Duration
		lo, hi time.Duration
	}{
		{"idle_timeout", m.IdleTimeout, time.Second, time.Hour},
		{"request_timeout", m.RequestTimeout, 100 * time.Millisecond, time.Minute},
		{"connect_timeout", m.ConnectTimeout, 100 * time.Millisecond, time.Minute},
	} {
		if d.val != 0 && (d.val.D() < d.lo || d.val.D() > d.hi) {
			v.errf("%s.%s: must be between %s and %s", p, d.key, d.lo, d.hi)
		}
	}
	if m.MaxMessageBytes != 0 && (m.MaxMessageBytes < 484 || m.MaxMessageBytes > snmpwire.MaxMessage) {
		v.errf("%s.max_message_bytes: must be between 484 (the protocol's own floor) and %d", p, snmpwire.MaxMessage)
	}
	if m.RateLimit < 0 || m.RateLimit > 1<<20 {
		v.errf("%s.rate_limit: must be between 0 and 1048576", p)
	}
	if m.RateBurst < 0 || m.RateBurst > 1<<20 {
		v.errf("%s.rate_burst: must be between 0 and 1048576", p)
	}
	if m.RateLimit == 0 && m.RateBurst > 0 {
		v.warnf("%s.rate_burst: a burst without a rate_limit bounds nothing", p)
	}
	names := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		if !nameRE.MatchString(r.Name) {
			v.errf("%s.name: %q is not a valid name", q, r.Name)
		} else if names[r.Name] {
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		names[r.Name] = true
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", q)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		for j, name := range r.Versions {
			if _, ok := snmpwire.VersionOf(name); !ok {
				v.errf("%s.versions[%d]: %q must be v1, v2c or v3", q, j, name)
			}
		}
		for j, name := range r.PDUs {
			if _, ok := snmpwire.PDUTypeOf(name); !ok {
				v.errf("%s.pdus[%d]: %q is not an operation (get, get_next, get_bulk, set, trap, trap_v1, inform, response, report)", q, j, name)
			}
		}
		for j, a := range r.Access {
			switch a {
			case "read", "write", "notify":
			default:
				v.errf("%s.access[%d]: %q must be read, write or notify", q, j, a)
			}
		}
		for _, set := range []struct {
			key  string
			oids []string
		}{{"oids", r.OIDs}, {"deny_oids", r.DenyOIDs}, {"write_oids", r.WriteOIDs}} {
			for j, o := range set.oids {
				if _, err := snmpwire.ParseOID(o); err != nil {
					v.errf("%s.%s[%d]: %v", q, set.key, j, err)
				}
			}
		}
		if r.MinSecurityLevel != "" {
			if _, ok := snmpwire.LevelOf(r.MinSecurityLevel); !ok {
				v.errf("%s.min_security_level: must be noAuthNoPriv, authNoPriv or authPriv", q)
			}
		}
		for j, name := range r.Transports {
			switch name {
			case "udp", "tcp", "tls", "dtls":
			default:
				v.errf("%s.transports[%d]: %q must be udp, tcp, tls or dtls", q, j, name)
			}
		}
		for j, name := range r.SecurityNames {
			if name == "" || len(name) > 255 {
				v.errf("%s.security_names[%d]: must be 1 to 255 octets", q, j)
			}
		}
		if len(r.SecurityNames) > 0 && len(m.CertToName) == 0 {
			// A rule naming a name nothing can derive matches nothing, which
			// on a deny rule is a control that is not there and on an allow
			// rule is traffic that falls through to the default.
			v.errf("%s.security_names: nothing derives a security name here; cert_to_name is what maps a certificate to one (RFC 6353 s5.3)", q)
		}
		if len(r.SecurityNames) > 0 && len(r.Users) > 0 {
			v.errf("%s: users names USM users and security_names names transport security model names, and one message is never both, so a rule naming each matches nothing", q)
		}
		if r.MaxRepetitions < 0 || r.MaxRepetitions > 1<<20 {
			v.errf("%s.max_repetitions: must be between 0 and 1048576", q)
		}
		if r.Schedule != nil {
			v.modbusSchedule(q+".schedule", r.Schedule)
		}
		if r.Action == "allow" && len(r.Clients) == 0 && len(r.OIDs) == 0 && len(r.PDUs) == 0 &&
			len(r.Access) == 0 && len(r.Communities) == 0 && len(r.Users) == 0 && len(r.Versions) == 0 &&
			len(r.SecurityNames) == 0 && len(r.Transports) == 0 {
			v.warnf("%s: an allow rule that names no client, version, credential, operation or object identifier allows everything", q)
		}
		if r.Action == "observe" && len(r.WriteOIDs) > 0 {
			v.warnf("%s: an observe rule records the message and decides nothing, so write_oids are not applied", q)
		}
	}
}

// iec104Setpoints checks the value bounds on setpoint commands.
//
// Every error here is a bound that would not do what its author meant, which on
// this protocol is worse than no bound: an operator who has written one stops
// looking at the point.
func (v *validator) iec104Setpoints(p string, in []IEC104Setpoint) {
	seen := map[string]bool{}
	for i, sp := range in {
		q := fmt.Sprintf("%s[%d]", p, i)
		switch {
		case sp.Name == "":
			v.errf("%s.name: required; a bound nobody can name is one nobody can find in a log", q)
		case seen[sp.Name]:
			v.errf("%s.name: duplicate %q", q, sp.Name)
		default:
			seen[sp.Name] = true
		}
		if len(sp.Points) == 0 {
			v.errf("%s.points: required; a value bound over every point on a substation is one somebody wrote without looking", q)
		}
		v.modbusRanges(q+".points", sp.Points, 1<<24-1)
		v.modbusRanges(q+".common_addresses", sp.CommonAddresses, 65535)
		// Only the setpoint types, and only by name: a bound naming a single
		// command has no value to bound and would silently cover nothing.
		for j, ty := range sp.Types {
			t, ok := iec104.TypeOf(ty)
			if !ok {
				v.errf("%s.types[%d]: %q is not a type identification", q, j, ty)
				continue
			}
			if kind, _ := iec104.SetpointEncoding(t); kind == iec104.NotASetpoint {
				v.errf("%s.types[%d]: %s carries no setpoint value, so a value bound on it covers nothing (the setpoint types are C_SE_NA_1, C_SE_NB_1, C_SE_NC_1 and their timed forms)", q, j, ty)
			}
		}
		switch {
		case sp.Min == nil || sp.Max == nil:
			v.errf("%s: min and max are both required; a bound with one end open is a bound in one direction, and a setpoint driven to the other end is what this exists to stop", q)
		case *sp.Min > *sp.Max:
			v.errf("%s: min %v is above max %v", q, *sp.Min, *sp.Max)
		}
		if sp.MaxDelta < 0 {
			v.errf("%s.max_delta: must not be negative", q)
		}
		switch sp.OnUnknown {
		case "", "allow", "refuse":
		default:
			v.errf("%s.on_unknown: must be allow or refuse", q)
		}
		if sp.MaxDelta == 0 && sp.OnUnknown != "" {
			v.warnf("%s.on_unknown: set without max_delta, which is the only check that needs a previous value, so it decides nothing", q)
		}
		// The normalised trap: a fraction of full scale, not an engineering
		// value. A bound outside -1..+1 on a listener whose setpoints are
		// normalised is a bound nothing can exceed.
		if normalisedOnly(sp.Types) && sp.Min != nil && sp.Max != nil &&
			(*sp.Max > 1 || *sp.Min < -1) {
			v.warnf("%s: min %v / max %v on C_SE_NA_1, whose value is a *fraction of full scale* from -1 to nearly +1 rather than an engineering value -- the full scale lives in the device, where this relay cannot see it, so a bound outside that range can never be exceeded", q, *sp.Min, *sp.Max)
		}
	}
}

// normalisedOnly says whether every type named is a normalised setpoint, which
// is when the fraction-of-full-scale warning above is worth making.
func normalisedOnly(types []string) bool {
	if len(types) == 0 {
		return false
	}
	for _, ty := range types {
		t, ok := iec104.TypeOf(ty)
		if !ok {
			return false
		}
		if kind, _ := iec104.SetpointEncoding(t); kind != iec104.Normalised {
			return false
		}
	}
	return true
}

// iec104DecoyOnly says whether this listener is nothing but a fabricated
// station, which is the one shape that needs no upstream: there is no
// station behind it to reach.
func iec104DecoyOnly(m *IEC104Listener) bool {
	d := m.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// IEC104DecoyProfiles are the fabricated station shapes the listener has
// built in. The list lives here so the error can name them.
var IEC104DecoyProfiles = []string{"generic-substation", "generic-rtu"}

// IEC104DecoyTypes are the type identifications a point run may be
// reported as: the ones a value can be fabricated for.
var IEC104DecoyTypes = []string{"M_SP_NA_1", "M_DP_NA_1", "M_ME_NB_1", "M_ME_NC_1", "M_IT_NA_1"}

func (v *validator) iec104Deception(p string, m *IEC104Listener) {
	d := m.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener reaches a real station, and a section that "+
				"would fabricate a confirmation for any client that connects is not a decision to arrive at by default", p)
		}
	case "decoy":
		if m.Upstream != "" {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream: "+
				"use mode answer to fabricate refusals on a listener that fronts a station", p)
		}
		if len(d.Clients) == 0 {
			// Not an error: a honeypot with nothing behind it is exactly
			// the case where answering every client is the point.
			v.warnf("%s: no clients, so every client that connects is answered by the fabricated station. "+
				"That is what a honeypot is for; it is worth being sure this listener is one", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	// deny_response is what a refused client is told, and a deceived client
	// is told something else instead. Saying so at load is cheaper than an
	// engineer wondering why the connection they expected to be closed
	// stayed open.
	if d.Mode != "decoy" && (m.DenyResponse == "close" || m.DenyResponse == "drop") {
		v.warnf("%s: deny_response %s does not apply to the clients this section covers -- their refused "+
			"activations are confirmed by the fabricated station rather than closed or ignored", p, m.DenyResponse)
	}
	if d.Profile != "" && !slices.Contains(IEC104DecoyProfiles, d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, d.Profile, strings.Join(IEC104DecoyProfiles, ", "))
	}
	v.modbusRanges(p+".common_addresses", d.CommonAddresses, 65535)
	v.modbusRanges(p+".tripwire", d.Tripwire, 1<<24-1)
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
	for i := range d.Points {
		q := fmt.Sprintf("%s.points[%d]", p, i)
		pt := &d.Points[i]
		if pt.Addresses == "" {
			v.errf("%s.addresses: required", q)
		} else {
			v.modbusRanges(q+".addresses", []string{pt.Addresses}, 1<<24-1)
		}
		if pt.Type == "" {
			v.errf("%s.type: required; a point run with no type identification is not something a value can be "+
				"fabricated for", q)
		} else if !slices.Contains(IEC104DecoyTypes, pt.Type) {
			v.errf("%s.type: %q is not a type this can fabricate a value for; the list is %s",
				q, pt.Type, strings.Join(IEC104DecoyTypes, ", "))
		}
		if pt.Min < -1<<31 || pt.Max > 1<<31-1 {
			v.errf("%s: min and max must fit a 32-bit integer", q)
		}
		if pt.Max != 0 && pt.Max <= pt.Min {
			v.errf("%s: max must be above min", q)
		}
		if pt.Rate < 0 {
			v.errf("%s.rate: must not be negative; a totaliser that went backwards is the one thing a "+
				"fabricated station cannot do and be believed", q)
		}
	}
}

// iec104Redundancy checks the redundancy groups of edition 2.
//
// A group is an assertion that a set of addresses is one controlling
// station, and every check here is about the ways that assertion can be
// wrong in a way an operator would not notice: a group that claims a client
// another group also claims, a group whose client list is so wide that it
// is not an assertion at all, and a group that carries selections across
// connections nothing else distinguishes.
func (v *validator) iec104Redundancy(p string, m *IEC104Listener) {
	r := m.Redundancy
	if r == nil {
		return
	}
	if len(r.Groups) == 0 {
		v.warnf("%s: no groups, so nothing about redundancy is enforced: take the section out or name the connection groups", p)
		return
	}
	names := map[string]bool{}
	type claimed struct {
		group  string
		prefix netip.Prefix
	}
	var seen []claimed
	for i := range r.Groups {
		g := &r.Groups[i]
		q := fmt.Sprintf("%s.groups[%d]", p, i)
		if !nameRE.MatchString(g.Name) {
			v.errf("%s.name: %q is not a valid name", q, g.Name)
		} else if names[g.Name] {
			v.errf("%s.name: duplicate %q", q, g.Name)
		}
		names[g.Name] = true
		if len(g.Clients) == 0 {
			v.errf("%s.clients: required; the client list is what says which connections are one controlling station", q)
		}
		v.modbusCIDRs(q+".clients", g.Clients)
		if g.MaxConnections != 0 && (g.MaxConnections < 1 || g.MaxConnections > 8) {
			v.errf("%s.max_connections: must be between 1 and 8", q)
		}
		switch g.Takeover {
		case "", "switch", "refuse":
		default:
			v.errf("%s.takeover: must be switch or refuse", q)
		}
		carries := g.CarrySelects == nil || *g.CarrySelects
		for _, c := range g.Clients {
			pre, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				continue // already reported by modbusCIDRs
			}
			for _, was := range seen {
				if was.prefix.Overlaps(pre) {
					v.errf("%s.clients: %s overlaps %s in group %q: a connection in two groups would be two controlling stations at once",
						q, pre, was.prefix, was.group)
				}
			}
			seen = append(seen, claimed{group: g.Name, prefix: pre})
			// A group carries a selection across its connections on the
			// strength of this list, so how wide it is *is* the bound. A
			// /16 of a control centre's network is fourteen thousand
			// addresses that can consume each other's selections.
			if carries && m.RequireSelect && pre.Bits() < carryPrefixAdvice(pre) {
				v.warnf("%s.clients: %s is wider than the two or three paths a redundancy group has, carry_selects is on and require_select is on, so any address in it can execute a command another selected. The group's own rule -- only the connection holding data transfer may send anything -- is what bounds that, so pair a list this wide with takeover: refuse, or narrow it to the paths that exist",
					q, pre)
			}
		}
	}
}

// carryPrefixAdvice is the prefix length below which a group's client list
// stops being an assertion about a few paths. A redundancy group is two or
// three addresses; /29 leaves room for eight, which is the group's own
// bound on connections.
func carryPrefixAdvice(pre netip.Prefix) int {
	if pre.Addr().Is4() {
		return 29
	}
	return 125
}

func (v *validator) iec104Listener(p string, m *IEC104Listener, hasTLS bool) {
	v.anomaly(p+".anomaly", m.Anomaly)
	v.engineering(p+".engineering", m.Engineering)
	switch m.Mode {
	case "", "reverse", "forward":
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	if m.Upstream == "" && !iec104DecoyOnly(m) {
		v.errf("%s.upstream: required; an IEC 104 connection is one association with one controlled station, so this listener relays to one pool", p)
	}
	switch m.TLSMode {
	case "", "implicit", "none":
	default:
		v.errf("%s.tls_mode: must be implicit or none", p)
	}
	if m.TLSMode == "implicit" && !hasTLS {
		v.errf("%s.tls_mode: implicit needs the listener's tls section", p)
	}
	switch m.UpstreamTLSMode {
	case "", "none", "implicit":
	default:
		v.errf("%s.upstream_tls_mode: must be none or implicit", p)
	}
	if m.UpstreamTLS != nil {
		v.upstreamTLS(p+".upstream_tls", m.UpstreamTLS)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.modbusRanges(p+".common_addresses", m.CommonAddresses, 65535)
	switch m.DefaultAction {
	case "", "deny", "allow":
	default:
		v.errf("%s.default_action: must be deny or allow", p)
	}
	if m.DefaultAction == "allow" && len(m.Rules) == 0 && !m.MonitorOnly {
		v.warnf("%s: default_action allow with no rules and without monitor_only relays every command to the substation", p)
	}
	switch m.DenyResponse {
	case "", "negative", "drop", "close":
	default:
		v.errf("%s.deny_response: must be negative, drop or close", p)
	}
	for i, c := range m.AllowControls {
		if _, ok := iec104ControlName(c); !ok {
			v.errf("%s.allow_controls[%d]: %q is not a control function (STARTDT_act, STARTDT_con, STOPDT_act, STOPDT_con, TESTFR_act, TESTFR_con)", p, i, c)
		}
	}
	v.iec104Setpoints(p+".setpoints", m.Setpoints)
	v.iec104Deception(p+".deception", m)
	if l := m.Learn; l != nil && l.Enabled {
		if l.File == "" {
			v.errf("%s.learn.file: required when learning is enabled", p)
		} else if !strings.HasPrefix(l.File, "/") {
			v.errf("%s.learn.file: must be an absolute path", p)
		}
		if l.Interval != 0 && (l.Interval.D() < 10*time.Second || l.Interval.D() > 24*time.Hour) {
			v.errf("%s.learn.interval: must be between 10s and 24h", p)
		}
		if l.MaxSubjects != 0 && (l.MaxSubjects < 16 || l.MaxSubjects > 1_000_000) {
			v.errf("%s.learn.max_subjects: must be between 16 and 1000000", p)
		}
		if !l.Enforce {
			v.warnf("%s.learn is enabled without enforce, so this listener records and decides nothing: "+
				"turn enforce on, or take the learning section out, once the rules are written", p)
		}
	}
	if m.MonitorOnly && m.RequireSelect {
		v.warnf("%s.require_select: monitor_only already refuses every command, so there is nothing left to select", p)
	}
	if m.SelectTimeout != 0 && (m.SelectTimeout < Duration(time.Second) || m.SelectTimeout > Duration(10*time.Minute)) {
		v.errf("%s.select_timeout: must be between 1s and 10m", p)
	}
	if m.MaxSelections < 0 || m.MaxSelections > 1<<20 {
		v.errf("%s.max_selections: must be between 0 and 1048576", p)
	}
	v.iec104Redundancy(p+".redundancy", m)
	if m.K != 0 && (m.K < 1 || m.K > 32767) {
		v.errf("%s.k: must be between 1 and 32767", p)
	}
	if m.W != 0 && (m.W < 1 || m.W > 32767) {
		v.errf("%s.w: must be between 1 and 32767", p)
	}
	if m.K != 0 && m.W != 0 && m.W > m.K {
		// The standard's own rule: acknowledging later than the sending
		// window closes stalls the link.
		v.errf("%s.w: %d is above k (%d): a station that acknowledges later than its peer's window closes stops the link", p, m.W, m.K)
	}
	if m.MaxConnections < 0 || m.MaxConnections > 4096 {
		v.errf("%s.max_connections: must be between 0 and 4096", p)
	}
	if m.IdleTimeout != 0 && (m.IdleTimeout < Duration(time.Second) || m.IdleTimeout > Duration(time.Hour)) {
		v.errf("%s.idle_timeout: must be between 1s and 1h", p)
	}
	if m.ConnectTimeout != 0 && (m.ConnectTimeout < Duration(100*time.Millisecond) || m.ConnectTimeout > Duration(time.Minute)) {
		v.errf("%s.connect_timeout: must be between 100ms and 1m", p)
	}
	if m.MaxFrameBytes != 0 && (m.MaxFrameBytes < 6 || m.MaxFrameBytes > 255) {
		v.errf("%s.max_frame_bytes: must be between 6 and 255 (the length field is one octet)", p)
	}
	for _, r := range []struct {
		key         string
		rate, burst int
	}{{"rate", m.RateLimit, m.RateBurst}, {"command_rate", m.CommandRateLimit, m.CommandRateBurst}} {
		if r.rate < 0 || r.rate > 1<<20 {
			v.errf("%s.%s_limit: must be between 0 and 1048576", p, r.key)
		}
		if r.burst < 0 || r.burst > 1<<20 {
			v.errf("%s.%s_burst: must be between 0 and 1048576", p, r.key)
		}
		if r.rate == 0 && r.burst > 0 {
			v.warnf("%s.%s_burst: a burst without a %s_limit bounds nothing", p, r.key, r.key)
		}
	}
	ruleNames := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		if !nameRE.MatchString(r.Name) {
			v.errf("%s.name: %q is not a valid name", q, r.Name)
		} else if ruleNames[r.Name] {
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		ruleNames[r.Name] = true
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", q)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		v.modbusRanges(q+".common_addresses", r.CommonAddresses, 65535)
		v.modbusRanges(q+".originators", r.Originators, 255)
		v.modbusRanges(q+".addresses", r.Addresses, 1<<24-1)
		for j, t := range r.Types {
			if _, ok := iec104TypeName(t); !ok {
				v.errf("%s.types[%d]: %q is not a type identification name or a number 1 to 255", q, j, t)
			}
		}
		for j, c := range r.Class {
			switch c {
			case "monitoring", "command", "system", "parameter", "file", "security":
			default:
				v.errf("%s.class[%d]: %q must be monitoring, command, system, parameter, file or security",
					q, j, c)
			}
		}
		for j, c := range r.Causes {
			if _, ok := iec104CauseName(c); !ok {
				v.errf("%s.causes[%d]: %q is not a cause of transmission name or a number 1 to 63", q, j, c)
			}
		}
		if r.MaxObjects < 0 || r.MaxObjects > 127 {
			v.errf("%s.max_objects: must be between 0 and 127", q)
		}
		switch r.Select {
		case "", "select", "execute":
		default:
			v.errf("%s.select: must be select or execute", q)
		}
		if r.Schedule != nil {
			v.modbusSchedule(q+".schedule", r.Schedule)
		}
		if r.Action == "allow" && len(r.Clients) == 0 && len(r.Types) == 0 && len(r.Class) == 0 &&
			len(r.CommonAddresses) == 0 && len(r.Causes) == 0 && len(r.Originators) == 0 {
			v.warnf("%s: an allow rule that names no client, station, type, class, cause or originator allows everything", q)
		}
	}
}

// iec104TypeName says whether a string names a type identification, by the
// standard's name or by number. The number is allowed because a vendor's
// private range is still a thing an operator has to be able to write.
func iec104TypeName(s string) (byte, bool) {
	if t, ok := iec104.TypeOf(s); ok {
		return byte(t), true
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 1 && n <= 255 {
		return byte(n), true
	}
	return 0, false
}

// iec104CauseName says whether a string names a cause of transmission.
func iec104CauseName(s string) (byte, bool) {
	if c, ok := iec104.CauseOf(s); ok {
		return byte(c), true
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 1 && n <= 63 {
		return byte(n), true
	}
	return 0, false
}

// iec104ControlName says whether a string names a U-format control function.
func iec104ControlName(s string) (byte, bool) {
	c, ok := iec104.ControlOf(strings.TrimSpace(s))
	return byte(c), ok
}

// modbusSubFunctions checks a rule's three sub-function selectors, and
// the one way they can be written so as to select nothing: a rule that
// names a diagnostic sub-function and a function list without function
// code 8 in it can never match, which is a rule that looks like a control
// and is not one.
func (v *validator) modbusSubFunctions(q string, r *ModbusRule) {
	for _, sel := range []struct {
		fc    byte
		in    []string
		field string
	}{
		{modbus.FCDiagnostic, r.Diagnostics, "diagnostics"},
		{modbus.FCUMAS, r.UMASCommands, "umas_commands"},
	} {
		// A name, a number, or a range of numbers -- the same three forms
		// as every other numeric list in a Modbus rule, so that the
		// counters can be written as 11-18.
		for j, s := range sel.in {
			if _, ok := modbus.SubCode(sel.fc, s); ok {
				continue
			}
			if _, err := numrange.Parse("sub", []string{s}, modbus.SubMax(sel.fc)); err == nil {
				continue
			}
			v.errf("%s.%s[%d]: %q is not a %s sub-function name (%s), a number from 0 to %d, or a range of them",
				q, sel.field, j, s, modbus.FunctionName(sel.fc),
				strings.Join(modbus.SubNames(sel.fc), ", "), modbus.SubMax(sel.fc))
		}
		if len(sel.in) == 0 || len(r.Functions) == 0 {
			continue
		}
		named := false
		for _, f := range r.Functions {
			if fc, ok := modbus.FunctionCode(f); ok && fc == sel.fc {
				named = true
			} else if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && n == int(sel.fc) {
				named = true
			}
		}
		if !named {
			v.warnf("%s.%s names a sub-function of function code %d, and %s.functions does not name that function code, so this rule can never match",
				q, sel.field, sel.fc, q)
		}
	}
	for j, e := range r.Effects {
		if _, ok := modbus.ParseSubEffect(e); !ok {
			v.errf("%s.effects[%d]: %q must be read, write, control, program, clear, session or unknown", q, j, e)
		}
	}
}

func (v *validator) modbusListener(p string, m *ModbusListener, hasTLS bool) {
	if m.MaxValuePoints < 0 || m.MaxValuePoints > 1<<20 {
		v.errf("%s.max_value_points: must be between 0 and 1048576", p)
	}
	switch m.Mode {
	case "", "reverse":
	case "forward":
		if len(m.Routes) == 0 && m.Upstream == "" {
			v.errf("%s: a forward listener needs routes or an upstream: an egress with no destination has nowhere to send a frame", p)
		}
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	// A listener that is nothing but a decoy has nowhere to send a frame
	// and is not supposed to: that is the one shape where an upstream is
	// not a missing field.
	if m.Upstream == "" && len(m.Routes) == 0 && !modbusDecoyOnly(m) {
		v.errf("%s.upstream: required unless routes name every destination", p)
	}
	v.modbusDeception(p+".deception", m)
	for _, f := range []struct{ key, val string }{{"framing", m.Framing}, {"upstream_framing", m.UpstreamFraming}} {
		switch f.val {
		case "", "tcp", "rtu", "ascii":
		default:
			v.errf("%s.%s: must be tcp, rtu or ascii", p, f.key)
		}
	}
	names := map[string]bool{}
	for i := range m.Routes {
		r := &m.Routes[i]
		q := fmt.Sprintf("%s.routes[%d]", p, i)
		if !nameRE.MatchString(r.Name) {
			v.errf("%s.name: %q is not a valid name", q, r.Name)
		} else if names[r.Name] {
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		names[r.Name] = true
		if len(r.Units) == 0 {
			v.errf("%s.units: required; a route that claims no unit identifier claims nothing", q)
		}
		v.modbusRanges(q+".units", r.Units, 255)
		if r.Upstream == "" {
			v.errf("%s.upstream: required", q)
		}
		switch r.Framing {
		case "", "tcp", "rtu", "ascii":
		default:
			v.errf("%s.framing: must be tcp, rtu or ascii", q)
		}
		if r.UnitOverride != nil && (*r.UnitOverride < 0 || *r.UnitOverride > 255) {
			v.errf("%s.unit_override: must be between 0 and 255", q)
		}
	}
	switch m.TLSMode {
	case "", "implicit", "none":
	default:
		v.errf("%s.tls_mode: must be implicit or none", p)
	}
	if m.TLSMode == "implicit" && !hasTLS {
		v.errf("%s.tls_mode: implicit needs the listener's tls section", p)
	}
	switch m.UpstreamTLSMode {
	case "", "none", "implicit":
	default:
		v.errf("%s.upstream_tls_mode: must be none or implicit", p)
	}
	if m.UpstreamTLS != nil {
		v.upstreamTLS(p+".upstream_tls", m.UpstreamTLS)
	}
	if s := m.Security; s != nil {
		switch s.Mode {
		case "", "off", "allow", "require":
		default:
			v.errf("%s.security.mode: must be off, allow or require", p)
		}
		switch s.RoleSource {
		case "", "extension", "cn", "ou":
		default:
			v.errf("%s.security.role_source: must be extension, cn or ou", p)
		}
		if s.Mode == "require" && !hasTLS {
			v.errf("%s.security.mode: require needs the listener's tls section: a role comes from a client certificate", p)
		}
		if s.RoleSource == "cn" || s.RoleSource == "ou" {
			v.warnf("%s.security.role_source is %s, which reads a role out of the certificate subject rather than the Modbus role extension: that trusts whoever issues certificates to keep to a naming convention", p, s.RoleSource)
		}
		for i, r := range s.Roles {
			if r == "" || len(r) > 64 || strings.ContainsAny(r, " \t") {
				v.errf("%s.security.roles[%d]: %q is not a role name", p, i, r)
			}
		}
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.modbusRanges(p+".units", m.Units, 255)
	switch m.DefaultAction {
	case "", "deny", "allow":
	default:
		v.errf("%s.default_action: must be deny or allow", p)
	}
	switch m.DenyResponse {
	case "", "exception", "drop", "close":
	default:
		v.errf("%s.deny_response: must be exception, drop or close", p)
	}
	if m.RefuseUnsafeSubFunctions != nil && !*m.RefuseUnsafeSubFunctions {
		v.warnf("%s.refuse_unsafe_sub_functions is off, so a rule allowing function code 8 allows sub-function 4, Force Listen Only Mode, which is one frame that takes a device off the bus until something restarts it -- and a rule allowing function code 90 allows stop_plc. Leave it on and name the sub-functions a rule means, with diagnostics, umas_commands or effects", p)
	}
	ruleNames := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		if !nameRE.MatchString(r.Name) {
			v.errf("%s.name: %q is not a valid name", q, r.Name)
		} else if ruleNames[r.Name] {
			v.errf("%s.name: duplicate %q", q, r.Name)
		}
		ruleNames[r.Name] = true
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", q)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		v.modbusRanges(q+".units", r.Units, 255)
		v.modbusRanges(q+".addresses", r.Addresses, 0xFFFF)
		v.modbusRanges(q+".write_addresses", r.WriteAddresses, 0xFFFF)
		for j, f := range r.Functions {
			if !modbusFunction(f) {
				v.errf("%s.functions[%d]: %q is not a function code name or a number from 1 to 127", q, j, f)
			}
		}
		for j, a := range r.Access {
			switch a {
			case "read", "write", "diagnostic", "identify", "vendor":
			default:
				v.errf("%s.access[%d]: must be read, write, diagnostic, identify or vendor", q, j)
			}
		}
		v.modbusSubFunctions(q, r)
		if r.MaxQuantity < 0 || r.MaxQuantity > 2000 {
			v.errf("%s.max_quantity: must be between 0 and 2000", q)
		}
		for j := range r.Values {
			val := &r.Values[j]
			vq := fmt.Sprintf("%s.values[%d]", q, j)
			if val.Registers != "" {
				v.modbusRanges(vq+".registers", []string{val.Registers}, 0xFFFF)
			}
			if val.Coils == nil && (val.Min == nil || val.Max == nil) {
				v.errf("%s: min and max are both required unless coils is set", vq)
			}
			if val.Min != nil && val.Max != nil && *val.Min > *val.Max {
				v.errf("%s: min %d is above max %d", vq, *val.Min, *val.Max)
			}
			lo, hi := 0, 65535
			if val.Signed {
				lo, hi = -32768, 32767
			}
			if val.Min != nil && (*val.Min < lo || *val.Min > hi) {
				v.errf("%s.min: outside %d to %d", vq, lo, hi)
			}
			if val.Max != nil && (*val.Max < lo || *val.Max > hi) {
				v.errf("%s.max: outside %d to %d", vq, lo, hi)
			}
			// The three bounds that are about a change rather than a
			// value, and the rate.
			if val.MaxDelta < 0 || val.MaxDelta > 0xFFFF {
				v.errf("%s.max_delta: must be between 0 and 65535", vq)
			}
			for k, tr := range val.Transitions {
				if !modbusTransition(tr) {
					v.errf("%s.transitions[%d]: %q is not a transition: \"from->to\" with values or *", vq, k, tr)
				}
			}
			switch val.OnUnknown {
			case "", "allow", "refuse":
			default:
				v.errf("%s.on_unknown: must be allow or refuse", vq)
			}
			if (val.MaxDelta > 0 || len(val.Transitions) > 0) && val.OnUnknown != "refuse" {
				v.warnf("%s: max_delta and transitions need the address's current value, and on_unknown is allow, so a write to an address this relay has not seen a value for is bounded by min and max alone: set on_unknown: refuse where that is not enough, knowing it refuses until something reads the register", vq)
			}
			if r := val.Rate; r != nil {
				if r.Max < 1 {
					v.errf("%s.rate.max: must be at least 1", vq)
				}
				if d := r.Period.D(); d < time.Second || d > 24*time.Hour {
					v.errf("%s.rate.period: must be between 1s and 24h", vq)
				}
			}
			if b := val.RequireBefore; b != nil {
				if b.Registers == "" {
					v.errf("%s.require_before.registers: required", vq)
				} else {
					v.modbusRanges(vq+".require_before.registers", []string{b.Registers}, 0xFFFF)
				}
				if d := b.Within; d != 0 && (d < Duration(time.Second) || d > Duration(time.Hour)) {
					v.errf("%s.require_before.within: must be between 1s and 1h", vq)
				}
				if b.Unit != nil && (*b.Unit < 0 || *b.Unit > 255) {
					v.errf("%s.require_before.unit: must be between 0 and 255", vq)
				}
				if b.Equals < -32768 || b.Equals > 65535 {
					v.errf("%s.require_before.equals: outside -32768 to 65535", vq)
				}
			}
		}
		if s := r.Schedule; s != nil {
			v.modbusSchedule(q+".schedule", s)
		}
		if r.Action == "observe" && len(r.Values) > 0 {
			v.warnf("%s: an observe rule with value bounds records the frame and decides nothing, so the bounds are not applied", q)
		}
	}
	if l := m.Learn; l != nil && l.Enabled {
		if l.File == "" {
			v.errf("%s.learn.file: required when learning is enabled", p)
		} else if !strings.HasPrefix(l.File, "/") {
			v.errf("%s.learn.file: must be an absolute path", p)
		}
		if l.Interval != 0 && (l.Interval.D() < 10*time.Second || l.Interval.D() > 24*time.Hour) {
			v.errf("%s.learn.interval: must be between 10s and 24h", p)
		}
		if l.MaxSubjects != 0 && (l.MaxSubjects < 16 || l.MaxSubjects > 1_000_000) {
			v.errf("%s.learn.max_subjects: must be between 16 and 1000000", p)
		}
		if !l.Enforce {
			v.warnf("%s.learn is enabled without enforce, so this listener records and decides nothing: turn enforce on, or take the learning section out, once the rules are written", p)
		}
	}
	v.anomaly(p+".anomaly", m.Anomaly)
	v.engineering(p+".engineering", m.Engineering)
	if tr := m.Trace; tr != nil {
		if tr.File == "" {
			v.errf("%s.trace.file: required", p)
		} else if !strings.HasPrefix(tr.File, "/") {
			v.errf("%s.trace.file: must be an absolute path", p)
		}
		if tr.MaxBytes != 0 && (tr.MaxBytes < 1<<20 || tr.MaxBytes > 64<<30) {
			v.errf("%s.trace.max_bytes: must be between 1MiB and 64GiB", p)
		}
		if tr.IncludeData {
			v.warnf("%s.trace.include_data writes the frames' data bytes, which is process data, into the trace file", p)
		}
	}
	if m.MaxConnections < 0 || m.MaxConnections > 65536 {
		v.errf("%s.max_connections: must be between 0 and 65536", p)
	}
	if m.MaxPending < 0 || m.MaxPending > 256 {
		v.errf("%s.max_pending: must be between 0 and 256", p)
	}
	if m.MaxFrameBytes != 0 && (m.MaxFrameBytes < 8 || m.MaxFrameBytes > 260) {
		v.errf("%s.max_frame_bytes: must be between 8 and 260, the longest ADU the specification has", p)
	}
	if m.RateLimit < 0 || m.RateLimit > 1_000_000 {
		v.errf("%s.rate_limit: must be between 0 and 1000000", p)
	}
	if m.RateBurst < 0 || m.RateBurst > 1_000_000 {
		v.errf("%s.rate_burst: must be between 0 and 1000000", p)
	}
	for _, d := range []struct {
		key string
		val Duration
	}{{"idle_timeout", m.IdleTimeout}, {"request_timeout", m.RequestTimeout}, {"connect_timeout", m.ConnectTimeout}} {
		if d.val < 0 || d.val > Duration(10*time.Minute) {
			v.errf("%s.%s: must be between 0 and 10m", p, d.key)
		}
	}
	// The advice. Each of these loads, and each is a relay in front of
	// equipment with one fewer lock on it than it should have.
	if len(m.AllowClients) == 0 && len(m.DenyClients) == 0 {
		v.warnf("%s.allow_clients is empty, so any client that can reach this listener can reach the equipment behind it: name the masters' networks", p)
	}
	if len(m.Rules) == 0 && m.DefaultAction == "allow" && !m.ReadOnly {
		v.warnf("%s has no rules and default_action allow, so every frame is forwarded: that is a relay that watches, which is what learning mode is for", p)
	}
	if m.ReadOnly {
		for i := range m.Rules {
			for _, a := range m.Rules[i].Access {
				if a == "write" {
					v.warnf("%s.rules[%d] allows write access on a read_only listener, where read_only wins: a read-only listener a rule could write through would not be one", p, i)
				}
			}
		}
	}
	if !m.LogFrames {
		v.warnf("%s.log_frames is off, so the audit trail is one line per session rather than per frame: a plant asked to show who wrote what needs the frames", p)
	}
}

// modbusCIDRs checks a network list.
// modbusTransition says whether a string is a "from->to" pair.
func modbusTransition(s string) bool {
	parts := strings.SplitN(s, "->", 2)
	if len(parts) != 2 {
		return false
	}
	stars := 0
	for _, half := range parts {
		text := strings.TrimSpace(half)
		if text == "*" {
			stars++
			continue
		}
		n, err := strconv.Atoi(text)
		if err != nil || n < -32768 || n > 65535 {
			return false
		}
	}
	// Two stars permit every change, which is the same as no list at all
	// and reads as a rule that does something.
	return stars < 2
}

// modbusDecoyOnly reports whether this listener is a honeypot: the whole
// of it is a device that is not there.
func modbusDecoyOnly(m *ModbusListener) bool {
	d := m.Deception
	return d != nil && (d.Enabled == nil || *d.Enabled) && d.Mode == "decoy"
}

// modbusDeception checks the deception section.
//
// The one rule worth being strict about is the client list. On a web
// gateway a deceptive answer goes to a scanner; on a plant floor the same
// answer can put a fabricated tank level in front of an operator. The
// relay never deceives a frame that was going to reach a device -- that is
// the code's invariant and it is tested -- but a policy refusing something
// legitimate by mistake is exactly how a real master ends up being lied
// to, and a section that would lie to anybody who connects is not
// something to arrive at by leaving a field out.
func (v *validator) modbusDeception(p string, m *ModbusListener) {
	d := m.Deception
	if d == nil || (d.Enabled != nil && !*d.Enabled) {
		return
	}
	switch d.Mode {
	case "", "answer":
		if len(d.Clients) == 0 {
			v.errf("%s.clients: required in mode answer; this listener reaches real devices, and a section that "+
				"would fabricate an answer for any client that connects is not a decision to arrive at by default", p)
		}
	case "decoy":
		if m.Upstream != "" || len(m.Routes) > 0 {
			v.errf("%s.mode: decoy is the whole listener, so it has no upstream and no routes: "+
				"use mode answer to fabricate refusals on a listener that fronts devices", p)
		}
		if len(d.Clients) == 0 {
			// Not an error: a honeypot with nothing behind it is exactly
			// the case where lying to every client is the point.
			v.warnf("%s: no clients, so every client that connects is answered by the fabricated device. "+
				"That is what a honeypot is for; it is worth being sure this listener is one", p)
		}
	default:
		v.errf("%s.mode: must be answer or decoy", p)
	}
	v.modbusCIDRs(p+".clients", d.Clients)
	// deny_response is what a refused client is told, and a deceived
	// client is told something else instead. Saying so at load is cheaper
	// than an engineer wondering why the connection they expected to be
	// closed stayed open.
	if d.Mode != "decoy" && (m.DenyResponse == "close" || m.DenyResponse == "drop") {
		v.warnf("%s: deny_response %s does not apply to the clients this section covers -- they are answered by the "+
			"fabricated device rather than closed or ignored", p, m.DenyResponse)
	}
	if d.Profile != "" && !modbusDecoyProfile(d.Profile) {
		v.errf("%s.profile: %q is not a profile; the built-in ones are %s",
			p, d.Profile, strings.Join(ModbusDecoyProfiles, ", "))
	}
	v.modbusRanges(p+".units", d.Units, 255)
	v.modbusRanges(p+".tripwire", d.Tripwire, 65535)
	if n := d.MaxClients; n < 0 || n > 1<<20 {
		v.errf("%s.max_clients: must be between 0 and 1048576", p)
	}
	if period := d.Period.D(); period != 0 && (period < time.Second || period > time.Hour) {
		v.errf("%s.period: must be between 1s and 1h", p)
	}
	for i := range d.Bands {
		b := &d.Bands[i]
		q := fmt.Sprintf("%s.bands[%d]", p, i)
		if b.Addresses == "" {
			v.errf("%s.addresses: required", q)
		} else {
			v.modbusRanges(q+".addresses", []string{b.Addresses}, 65535)
		}
		switch b.Shape {
		case "", "analogue", "discrete", "counter":
		default:
			v.errf("%s.shape: must be analogue, discrete or counter", q)
		}
		if b.Min < 0 || b.Min > 65535 || b.Max < 0 || b.Max > 65535 {
			v.errf("%s: min and max must be between 0 and 65535", q)
		}
		if b.Shape == "analogue" && b.Max != 0 && b.Max <= b.Min {
			v.errf("%s: max must be above min", q)
		}
		if b.Rate < 0 || b.Rate > 65535 {
			v.errf("%s.rate: must be between 0 and 65535", q)
		}
	}
	for i, fc := range d.Functions {
		if !modbusFunction(fc) {
			v.errf("%s.functions[%d]: %q is not a function code", p, i, fc)
		}
	}
}

// ModbusDecoyProfiles are the fabricated device shapes a deception
// section may name.
//
// The list is here because the validator has to refuse a name the kind
// would not know, and the shapes themselves are in internal/kinds/modbus
// because they are made of function codes and address bands. A test there
// keeps the two exactly in step, which is the arrangement that stops a
// profile existing in one and not the other.
var ModbusDecoyProfiles = []string{"generic-plc", "generic-rtu", "generic-meter"}

func modbusDecoyProfile(name string) bool {
	for _, p := range ModbusDecoyProfiles {
		if p == name {
			return true
		}
	}
	return false
}

func (v *validator) modbusCIDRs(p string, in []string) {
	for i, c := range in {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s[%d]: %q is not a CIDR: %v", p, i, c, err)
		}
	}
}

// modbusRanges checks the "5" and "1-16" range lists the Modbus policy is
// written with.
// modbusSchedule validates a rule's time window. It is shared with the
// IEC 104 rules, because "during the day shift" does not change with the
// protocol.
// engineering validates the engineering block. It is shared by every OT
// listener kind, because the block is.
//
// The fail-closed check -- require_grant with no access section -- is in
// access() with the gate kinds', because it is the same mistake and the message
// naming every listener that made it is more use than one per listener.
func (v *validator) engineering(p string, e *Engineering) {
	if e == nil {
		return
	}
	off := e.Enabled != nil && !*e.Enabled
	switch e.Action {
	case "", "alert", "deny":
	default:
		v.errf("%s.action: must be alert or deny", p)
	}
	for i, c := range e.Classes {
		switch c {
		case "program_download", "program_upload", "mode_change", "restart",
			"configuration", "firmware", "method_call", "file_transfer":
		default:
			v.errf("%s.classes[%d]: %q is not an engineering class", p, i, c)
		}
	}
	if len(e.Classes) > 0 && !e.RequireGrant {
		v.errf("%s.classes are named without require_grant, so nothing would be asked of them", p)
	}
	if off && e.RequireGrant {
		v.errf("%s: enabled is false and require_grant is true, which cannot both be meant", p)
	}
	if e.RequireGrant && e.Action == "alert" {
		v.warnf("%s.action is alert, so an engineering operation outside every approved "+
			"work order is reported and carried. That is the right first step; an estate "+
			"that has been filing its windows for a month should move it to deny", p)
	}
}

// anomaly validates the behavioural detector. It is shared by every OT
// listener kind, because the block is: the models are about the shape of
// traffic rather than about a protocol.
func (v *validator) anomaly(p string, a *Anomaly) {
	if a == nil || !a.Enabled {
		return
	}
	if s := a.Settle; s != nil {
		switch {
		case s.D() < 0:
			v.errf("%s.settle: must not be negative", p)
		case s.D() == 0:
			v.warnf("%s.settle is 0, so the first thing every client does is reported as novel. "+
				"After a restart that is every client's whole scan cycle at once", p)
		case s.D() < time.Minute || s.D() > 7*24*time.Hour:
			v.errf("%s.settle: must be 0 or between 1m and 168h", p)
		}
	}
	if a.MaxClients != 0 && (a.MaxClients < 8 || a.MaxClients > 1_000_000) {
		v.errf("%s.max_clients: must be between 8 and 1000000", p)
	}
	switch a.Action {
	case "", "alert", "deny":
	default:
		v.errf("%s.action: must be alert or deny", p)
	}
	burst := DefaultAnomalyBurst
	if n := a.Novelty; n != nil {
		if n.Burst != nil {
			burst = *n.Burst
			switch {
			case burst < 0:
				v.errf("%s.novelty.burst: must not be negative", p)
			case burst > 1_000_000:
				v.errf("%s.novelty.burst: must be at most 1000000", p)
			}
		}
		if n.BurstPeriod != 0 && (n.BurstPeriod.D() < time.Second || n.BurstPeriod.D() > time.Hour) {
			v.errf("%s.novelty.burst_period: must be between 1s and 1h", p)
		}
	}
	on := func(b *bool) bool { return b == nil || *b }
	off := func(b *bool) bool { return b != nil && !*b }
	if c := a.Cycle; c != nil {
		if c.MinSamples != 0 && (c.MinSamples < 4 || c.MinSamples > 100_000) {
			v.errf("%s.cycle.min_samples: must be between 4 and 100000", p)
		}
		if c.Tolerance != 0 && (c.Tolerance < 1 || c.Tolerance > 1000) {
			v.errf("%s.cycle.tolerance: must be between 1 and 1000", p)
		}
		if c.ReportEvery != 0 && (c.ReportEvery.D() < time.Second || c.ReportEvery.D() > 24*time.Hour) {
			v.errf("%s.cycle.report_every: must be between 1s and 24h", p)
		}
		if on(c.Enabled) && c.MinSamples != 0 && c.MinSamples < 20 {
			v.warnf("%s.cycle.min_samples is %d, so a rhythm is called learned from %d intervals. "+
				"A mean that short is the last few seconds rather than this poller's cycle", p, c.MinSamples, c.MinSamples)
		}
	}
	if q := a.Sequence; q != nil && q.MinSamples != 0 &&
		(q.MinSamples < 10 || q.MinSamples > 1_000_000) {
		v.errf("%s.sequence.min_samples: must be between 10 and 1000000", p)
	}
	if t := a.Talkers; t != nil && t.ReadyAfter != 0 &&
		(t.ReadyAfter.D() < time.Second || t.ReadyAfter.D() > 7*24*time.Hour) {
		v.errf("%s.talkers.ready_after: must be between 1s and 168h", p)
	}
	if t := a.Telemetry; t != nil {
		if t.FrozenSamples != 0 && (t.FrozenSamples < 3 || t.FrozenSamples > 32) {
			v.errf("%s.telemetry.frozen_samples: must be between 3 and 32", p)
		}
		if t.ReplayWindow != 0 && (t.ReplayWindow < 4 || t.ReplayWindow > 32) {
			v.errf("%s.telemetry.replay_window: must be between 4 and 32", p)
		}
	}
	for i, c := range a.Correlations {
		q := fmt.Sprintf("%s.correlations[%d]", p, i)
		if c.A == "" || c.B == "" {
			v.errf("%s: a and b are both required", q)
		}
		if c.A == c.B && c.A != "" {
			v.errf("%s: a and b are the same point, which tracks itself", q)
		}
		if c.Ratio == 0 && c.Difference == 0 {
			v.errf("%s: one of ratio or difference is required, or the pair says nothing", q)
		}
		if c.Ratio < 0 {
			v.errf("%s.ratio: must not be negative", q)
		}
		if c.Difference < 0 {
			v.errf("%s.difference: must not be negative", q)
		}
		if c.Tolerance < 0 || c.Tolerance > 1 {
			v.errf("%s.tolerance: must be between 0 and 1", q)
		}
		if c.MaxAge != 0 && (c.MaxAge.D() < time.Second || c.MaxAge.D() > time.Hour) {
			v.errf("%s.max_age: must be between 1s and 1h", q)
		}
	}
	// A detector that is on with every model off is a mistake somebody
	// spends an afternoon on, because nothing is wrong and nothing is
	// reported.
	novelty := a.Novelty == nil || on(a.Novelty.Symbols) || on(a.Novelty.WritePoints) || burst != 0
	if a.Novelty != nil && off(a.Novelty.Symbols) && off(a.Novelty.WritePoints) && burst == 0 {
		novelty = false
	}
	anything := novelty ||
		(a.Cycle != nil && on(a.Cycle.Enabled)) ||
		(a.Sequence != nil && on(a.Sequence.Enabled)) ||
		(a.Talkers != nil && on(a.Talkers.Enabled)) ||
		(a.Telemetry != nil && on(a.Telemetry.Enabled)) ||
		len(a.Correlations) > 0
	if !anything {
		v.errf("%s: enabled with nothing to detect: every model is off", p)
	}
	if a.Action == "deny" {
		v.warnf("%s.action is deny, so a client doing something this relay has not seen it do is refused. "+
			"The signal is novelty, which the first legitimate maintenance write of the year also is: "+
			"run it as alert first and read what it would have refused", p)
	}
}

func (v *validator) modbusSchedule(p string, s *ModbusSchedule) {
	if s == nil {
		// A rule with no window is in force always, which is the common
		// case; every caller used to have to remember to check.
		return
	}
	for j, d := range s.Days {
		if !modbusDay(d) {
			v.errf("%s.days[%d]: %q is not a day (mon to sun)", p, j, d)
		}
	}
	v.modbusClock(p+".from", s.From)
	v.modbusClock(p+".to", s.To)
	if s.Timezone != "" {
		if _, err := time.LoadLocation(s.Timezone); err != nil {
			v.errf("%s.timezone: %v", p, err)
		}
	}
	if s.From == "" && s.To == "" && len(s.Days) == 0 {
		v.errf("%s: sets nothing, so the rule is always in force; drop the section", p)
	}
}

func (v *validator) modbusRanges(p string, in []string, max int) {
	for i, s := range in {
		text := strings.TrimSpace(s)
		if text == "" {
			v.errf("%s[%d]: empty", p, i)
			continue
		}
		lo, hi := text, text
		if j := strings.IndexByte(text, '-'); j > 0 {
			lo, hi = strings.TrimSpace(text[:j]), strings.TrimSpace(text[j+1:])
		}
		l, okLo := modbusNum(lo)
		h, okHi := modbusNum(hi)
		switch {
		case !okLo || !okHi:
			v.errf("%s[%d]: %q is not a number or a range", p, i, s)
		case l > h:
			v.errf("%s[%d]: %q starts after it ends", p, i, s)
		case l < 0 || h > max:
			v.errf("%s[%d]: %q is outside 0 to %d", p, i, s, max)
		}
	}
}

func modbusNum(s string) (int, bool) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err := strconv.ParseInt(s[2:], 16, 32)
		return int(n), err == nil
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// modbusFunction says whether a function code is written as a name this
// build knows or as a number the protocol has.
func modbusFunction(s string) bool {
	if _, ok := modbus.FunctionCode(s); ok {
		return true
	}
	n, ok := modbusNum(strings.TrimSpace(s))
	return ok && n >= 1 && n <= 127
}

func modbusDay(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "mon", "monday", "tue", "tuesday", "wed", "wednesday", "thu", "thursday",
		"fri", "friday", "sat", "saturday", "sun", "sunday":
		return true
	}
	return false
}

func (v *validator) modbusClock(p, s string) {
	if s == "" {
		return
	}
	h, m, ok := strings.Cut(s, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		v.errf("%s: %q is not a time of day as HH:MM", p, s)
	}
}

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
// rdpDynamicChannels checks the policy for the channels opened inside drdynvc,
// and warns when drdynvc is allowed with no such policy.
//
// That warning is the whole point of the block being optional. drdynvc is a
// multiplexer, not a channel: the graphics pipeline, display control, geometry,
// camera, audio and -- on a current client -- device and clipboard redirection
// are all opened by name inside it, so allowing drdynvc without a dynamic
// policy allows all of them, including ones channels.allow refused by name.
// Refusing them by default would break every session that works today, so the
// traffic is carried and this says so at load.
func (v *validator) rdpDynamicChannels(p string, c *RDPDynamicChannelPolicy, allowed bool) {
	if c == nil {
		if allowed {
			v.warnf("%s: the %s channel is allowed and nothing here decides what is opened "+
				"inside it. It is a multiplexer rather than a channel: the graphics pipeline, "+
				"display control, cameras, audio and on a current client device and clipboard "+
				"redirection are all opened by name within it, so a channel refused in "+
				"channels.allow can be opened again in here. Those channels are carried and "+
				"counted as rdp_dynamic_channels_seen; name the ones a session needs in "+
				"%s.allow to decide about them", p, rdp.ChannelDynamic, p)
		}
		return
	}
	if !allowed {
		v.errf("%s: names dynamic channels while the %s channel is not in channels.allow, so "+
			"nothing could open one. Allow the channel or drop this section", p, rdp.ChannelDynamic)
	}
	for what, list := range map[string][]string{"allow": c.Allow, "deny": c.Deny} {
		for _, name := range list {
			n := strings.TrimSpace(name)
			if n == "" {
				v.errf("%s.%s: an empty dynamic channel name", p, what)
				continue
			}
			if len(n) > rdp.MaxDVCName {
				v.errf("%s.%s: %q is over %d characters, which is longer than any listener name",
					p, what, name, rdp.MaxDVCName)
			}
			for _, ch := range []byte(n) {
				if ch < 0x20 || ch == 0x7f {
					v.errf("%s.%s: %q has a control character in it, and no listener name does",
						p, what, name)
					break
				}
			}
		}
	}
	if len(c.Allow) == 0 && len(c.Deny) == 0 {
		v.warnf("%s: written with no names, which refuses every dynamic channel. On a current "+
			"client that includes the graphics pipeline a session draws through, so this is "+
			"usually a block somebody meant to fill in", p)
	}
}

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
	hasRDPDR, hasDynamic := false, false
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
				hasDynamic = true
			}
		}
		v.rdpDynamicChannels(p+".channels.dynamic", c.Channels.Dynamic, hasDynamic)
	}
	if c.Channels == nil && hasDynamic {
		// Unreachable as written, and here so that a later change cannot
		// silently take the warning away.
		v.warnf("%s.channels: %s is allowed with no policy for what it carries", p, rdp.ChannelDynamic)
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

// sshCommandRules checks the structured command rules of one policy.
// hasSFTP says whether an sftp section applies here (the policy's own
// or the listener's), and execAllowed whether exec can happen at all.
func (v *validator) sshCommandRules(p string, rules []SSHCommandRule, hasSFTP, execAllowed bool) {
	if len(rules) == 0 {
		return
	}
	if !execAllowed {
		v.errf("%s.command_rules: set without exec in allow_requests, so no command ever reaches them", p)
	}
	seen := map[string]bool{}
	for i, r := range rules {
		q := fmt.Sprintf("%s.command_rules[%d]", p, i)
		if !SSHCommandFamilies[r.Command] {
			v.errf("%s.command: %q is not a family this proxy can read; one of scp, rsync, sftp_server, git", q, r.Command)
			continue
		}
		if seen[r.Command] {
			v.errf("%s.command: %q has a rule already; one rule decides a family, and two would leave which one silent", q, r.Command)
		}
		seen[r.Command] = true
		dirs := map[string]bool{}
		for j, d := range r.Directions {
			switch strings.ToLower(d) {
			case "upload", "download":
				if dirs[strings.ToLower(d)] {
					v.errf("%s.directions[%d]: %q listed twice", q, j, d)
				}
				dirs[strings.ToLower(d)] = true
			default:
				v.errf("%s.directions[%d]: %q is not a direction; upload puts files on the target, download takes them off it", q, j, d)
			}
		}
		if r.Command == "sftp_server" {
			if len(r.Directions) > 0 {
				v.errf("%s.directions: an sftp_server rule takes none; which way files may move is the sftp policy's decision (read_only), and saying it twice is two answers", q)
			}
			if !r.EnforceSFTPPolicy {
				v.errf("%s.enforce_sftp_policy: an sftp_server rule needs it. An exec of the sftp server binary is the sftp subsystem under another name, so allowing it without inspecting it hands this session every path rule the subsystem is held to", q)
			}
			if !hasSFTP {
				v.errf("%s: enforce_sftp_policy with no sftp section to enforce", q)
			}
		} else {
			if len(dirs) == 0 {
				v.errf("%s.directions: required, or the rule allows nothing and the family is simply refused", q)
			}
			if r.EnforceSFTPPolicy {
				v.errf("%s.enforce_sftp_policy: only an sftp_server rule can be relayed through the sftp policy; %s speaks its own protocol", q, r.Command)
			}
		}
		if r.Recursive && r.Command != "scp" {
			v.errf("%s.recursive: only scp takes -r; %s recurses by what it transfers, not by a flag this can read", q, r.Command)
		}
		if r.Delete && r.Command != "rsync" {
			v.errf("%s.delete: only rsync has options that remove files at the far end", q)
		}
		for _, l := range []struct {
			key  string
			list []string
		}{{"paths", r.Paths}, {"deny_paths", r.DenyPaths}} {
			for j, path := range l.list {
				switch {
				case path == "" || strings.ContainsRune(path, 0):
					v.errf("%s.%s[%d]: must be a path", q, l.key, j)
				case !strings.HasPrefix(path, "/"):
					v.errf("%s.%s[%d]: %q must be absolute; a relative pattern is matched against a path this gateway resolves from the root, so it would never match", q, l.key, j, path)
				}
			}
		}
		if len(r.Paths) == 0 && r.Command != "sftp_server" && len(dirs) > 0 {
			v.warnf("%s.paths: empty, so every path on the target is in reach of this %s rule", q, r.Command)
		}
	}
}

// threatIntel checks the imported lists. Every file is read at load by
// the server itself, so what is checked here is what a file cannot say:
// the name, the kind, the action and the refresh interval.
// scimFile checks a path the provisioning endpoint writes: absolute, and
// noted rather than refused when it is not there yet.
func (v *validator) scimFile(p, path string) {
	if path == "" {
		return
	}
	if !strings.HasPrefix(path, "/") {
		v.errf("%s: must be an absolute path", p)
		return
	}
	if !v.fileCheck {
		return
	}
	st, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		v.warnf("%s: %s does not exist yet; the first provisioning creates it, so check the path is the one the rest of this file reads", p, path)
	case err != nil:
		v.errf("%s: %v", p, errors.Unwrap(err))
	case st.IsDir():
		v.errf("%s: %s is a directory", p, path)
	}
}

// scim checks the provisioning endpoint. Every check here is about the
// same thing: this endpoint creates and destroys credentials, so a
// mistake in its configuration is not a feature that does not work but a
// door somebody else can open.
func (v *validator) scim(c *Config) {
	t := c.SCIM
	base := t.Base()
	switch {
	case !strings.HasPrefix(base, "/"):
		v.errf("scim.path: %q must start with /", base)
	case base == "/":
		v.errf("scim.path: cannot be the root; the endpoint would answer every request")
	case strings.HasSuffix(base, "/") && base != "/":
		v.errf("scim.path: %q must not end with /", base)
	case len(base) > 128:
		v.errf("scim.path: at most 128 characters")
	case strings.ContainsAny(base, "?# "):
		v.errf("scim.path: %q is a path, not a URL", base)
	}
	if t.TokenFile == "" {
		v.errf("scim.token_file: required; this endpoint is never open")
	} else {
		v.file("scim.token_file", t.TokenFile)
	}
	if t.StateFile == "" {
		v.errf("scim.state_file: required; it holds the provisioned users")
	} else if !strings.HasPrefix(t.StateFile, "/") {
		// Unlike the others this file is written, and need not exist yet:
		// the first provisioning creates it.
		v.errf("scim.state_file: must be an absolute path")
	}
	if t.MFAUsersFile == "" && t.KeysFile == "" {
		v.errf("scim.mfa_users_file, scim.keys_file: name at least one; with neither there is nothing to provision")
	}
	// The two credential files are written by this endpoint, so unlike
	// every other file in the configuration they need not exist yet: a
	// provisioned estate starts with no enrolments and no keys, and the
	// first joiner is what creates them. A path that does not exist is
	// still worth saying out loud, because the other way to get one is a
	// typo, and then the credentials the rest of the proxy reads are in
	// the other file.
	v.scimFile("scim.mfa_users_file", t.MFAUsersFile)
	v.scimFile("scim.keys_file", t.KeysFile)
	listeners := map[string]bool{}
	for _, l := range c.Server.Listeners {
		listeners[l.Name] = true
	}
	for i, l := range t.Listeners {
		if !listeners[l] {
			v.errf("scim.listeners[%d]: unknown listener %q", i, l)
		}
	}
	for i, h := range t.Hosts {
		if !hostPatternOK(h) {
			v.errf("scim.hosts[%d]: %q is not a valid host pattern", i, h)
		}
	}
	for i, cidr := range t.ClientCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			v.errf("scim.client_cidrs[%d]: %q is not a CIDR", i, cidr)
		}
	}
	if t.MaxResults != 0 && (t.MaxResults < 1 || t.MaxResults > 1000) {
		v.errf("scim.max_results: must be between 1 and 1000")
	}
	if t.KeyTTL != nil && (t.KeyTTL.D() < time.Hour || t.KeyTTL.D() > Duration(10*365*24*time.Hour).D()) {
		v.errf("scim.key_ttl: must be between 1h and 10 years")
	}
	if t.Issuer != "" && (len(t.Issuer) > 64 || strings.ContainsAny(t.Issuer, ":?&= ")) {
		v.errf("scim.issuer: at most 64 characters and none of \":?&= \", which the enrolment URI is made of")
	}
	for i, sc := range t.KeyScopes {
		if sc == "" || len(sc) > 64 || strings.ContainsAny(sc, ", ") {
			v.errf("scim.key_scopes[%d]: %q is not a scope name", i, sc)
		}
	}
	if u := t.ExternalURL; u != "" {
		switch {
		case !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://"):
			v.errf("scim.external_url: must begin with https:// or http://")
		case strings.ContainsAny(u, "?# "):
			v.errf("scim.external_url: %q must be a base URL with no query or fragment", u)
		case strings.HasPrefix(u, "http://"):
			v.warnf("scim.external_url is http://, so the provider is told to send its token in the clear")
		}
	}
	// The advice. Each of these loads, and each of them is a
	// provisioning endpoint with one fewer lock on it than it should
	// have.
	if len(t.ClientCIDRs) == 0 && len(t.Hosts) == 0 && len(t.Listeners) == 0 {
		v.warnf("scim has no hosts, listeners or client_cidrs, so the provisioning endpoint answers on every listener and every host: name at least the provider's networks")
	}
	if t.Secrets() {
		v.warnf("scim.return_secrets is on, so the enrolment secret, the recovery codes and the key plaintext are in the provider's responses and wherever it logs them")
	}
	if t.KeysFile != "" && len(t.KeyScopes) == 0 {
		v.warnf("scim.key_scopes is empty, so a provisioned key carries no scopes: it passes an api_key filter that requires none and fails every one that requires any")
	}
}

func (v *validator) threatIntel(t *ThreatIntel, c *Config) {
	if len(t.Lists) == 0 {
		v.errf("threat_intel: no lists, so the section does nothing; list them or drop it")
	}
	if t.Refresh != nil && *t.Refresh != 0 && t.Refresh.D() < 10*time.Second {
		v.errf("threat_intel.refresh: must be at least 10s, or 0 for never; a feed nobody rewrites that often is a feed this would only stat")
	}
	seen := map[string]bool{}
	challenges, hashes := false, false
	for i := range t.Lists {
		l := &t.Lists[i]
		q := fmt.Sprintf("threat_intel.lists[%d]", i)
		if !nameRE.MatchString(l.Name) {
			v.errf("%s.name: %q is not a valid name; it is what the security event and the counters call this list", q, l.Name)
		} else if seen[l.Name] {
			v.errf("%s.name: duplicate %q", q, l.Name)
		}
		seen[l.Name] = true
		if l.Kind == "hash" {
			hashes = true
		}
		switch l.Kind {
		case "", "cidr", "ja4", "domain", "url", "hash":
		default:
			v.errf("%s.kind: must be cidr (addresses and networks), ja4 (TLS client fingerprints), domain (host names and the names under them), url (a host and path at a path boundary) or hash (MD5, SHA-1 or SHA-256 digests)", q)
		}
		switch l.Action {
		case "", "log", "block":
		case "challenge":
			challenges = true
			// A challenge answers a browser. A digest is computed from a
			// payload the client sent, and a name is asked for by a resolver
			// or a machine; neither has anybody to show a page to, so the
			// action would silently become nothing.
			if l.Kind == "hash" {
				v.errf("%s.action: challenge on a hash list has nobody to challenge -- the match is on a payload, not on a browser asking for a page. Use log or block", q)
			}
		default:
			v.errf("%s.action: must be log, challenge or block", q)
		}
		v.threatSource(q, l)
		if l.Action == "block" {
			switch l.Kind {
			case "domain", "url":
				v.warnf("%s.action: block refuses every request for a name this feed covers, and a domain entry covers the names under it -- so one wrong line takes a whole zone. challenge lets a browser through and stops everything else", q)
			case "hash":
				v.warnf("%s.action: block refuses every payload whose digest this feed names. That is the one kind where a wrong line is cheap, because a digest names one exact payload -- but it is still somebody else's list deciding", q)
			default:
				v.warnf("%s.action: block refuses every request from an address this feed names, and a feed with one wrong line in it is an outage nobody can explain from the logs. challenge lets a browser through and stops everything else", q)
			}
		}
	}
	if challenges && !v.hasChallenge {
		v.errf("threat_intel: a list asks for a challenge and there is no challenge section, so there is nothing to challenge with")
	}
	// A hash list is matched where a payload is assembled, which today is the
	// upload guard. Without one it is a list that loads, refreshes, reports
	// its entry count and never matches anything -- which is worse than no
	// list, because the operator believes it works.
	if hashes {
		guard := false
		for i := range c.Filters {
			if c.Filters[i].Kind == "upload_guard" {
				guard = true
				break
			}
		}
		if !guard {
			v.warnf("threat_intel: a hash list only matches where a payload is assembled, which is the upload_guard filter on a route. With no upload_guard filter configured, the digests are loaded and never asked about")
		}
	}
}

// threatSource checks where one list's entries come from: exactly one source,
// and whatever that source needs.
func (v *validator) threatSource(q string, l *ThreatList) {
	var set []string
	if l.File != "" {
		set = append(set, "file")
	}
	if l.URL != "" {
		set = append(set, "url")
	}
	if l.TAXII != nil {
		set = append(set, "taxii")
	}
	if l.MISP != nil {
		set = append(set, "misp")
	}
	switch len(set) {
	case 0:
		v.errf("%s: one of file, url, taxii or misp is required to say where the entries come from", q)
		return
	case 1:
	default:
		v.errf("%s: %s are all set; exactly one says where the entries come from, because a list whose source is ambiguous is a list nobody can say the contents of",
			q, strings.Join(set, ", "))
		return
	}
	switch l.Format {
	case "", "auto", "lines", "stix", "misp":
	default:
		v.errf("%s.format: must be lines, stix, misp or auto", q)
	}
	switch {
	case l.File != "":
		v.file(q+".file", l.File)
		if l.HTTP != nil {
			v.warnf("%s.http: the source is a file, so nothing here is used", q)
		}
	case l.URL != "":
		v.feedURL(q+".url", l.URL)
	case l.TAXII != nil:
		t := l.TAXII
		v.feedURL(q+".taxii.api_root", t.APIRoot)
		if t.Collection == "" {
			v.errf("%s.taxii.collection: required; it is the collection's id in the server's discovery document", q)
		}
		if t.AddedAfter != "" {
			if _, err := time.Parse(time.RFC3339, t.AddedAfter); err != nil {
				v.errf("%s.taxii.added_after: %q is not an RFC 3339 timestamp", q, t.AddedAfter)
			}
		}
		// A TAXII collection answers STIX. Saying otherwise would be a list
		// that fetches correctly and then reads the answer with the wrong
		// parser, which yields nothing and fails the load -- confusingly.
		if l.Format != "" && l.Format != "auto" && l.Format != "stix" {
			v.errf("%s.format: a taxii source answers STIX; %q cannot read it", q, l.Format)
		}
	case l.MISP != nil:
		m := l.MISP
		v.feedURL(q+".misp.url", m.URL)
		if m.Limit < 0 || m.Limit > 1000000 {
			v.errf("%s.misp.limit: must be between 0 (the instance decides) and 1000000", q)
		}
		if l.Format != "" && l.Format != "auto" && l.Format != "misp" {
			v.errf("%s.format: a misp source answers MISP JSON; %q cannot read it", q, l.Format)
		}
		if m.Published != nil && !*m.Published {
			v.warnf("%s.misp.published: false includes attributes of unpublished events, which is MISP's own boundary between somebody's draft and intelligence. This proxy would then act on a report its author has not finished", q)
		}
	}
	if l.HTTP != nil && l.File == "" {
		v.feedHTTP(q+".http", l.HTTP, l)
	}
	// A TAXII server or a MISP instance with no credential is either open to
	// the world or about to answer 401 for ever. Neither is what an operator
	// wrote, and the second one leaves a list that never updates and still
	// matches -- which looks exactly like a list that is working.
	//
	// Checked here rather than in feedHTTP, because the case that needs saying
	// is the one with no http section at all.
	if l.TAXII != nil || l.MISP != nil {
		if l.HTTP == nil || (l.HTTP.Token == "" && l.HTTP.Header == "") {
			v.warnf("%s: no http.token and no http.header, so this feed is fetched anonymously. A TAXII server or a MISP instance that answers 401 every time leaves a list that never updates and still matches", q)
		}
	}
}

// feedURL checks a feed's URL: absolute, http or https, with a host.
func (v *validator) feedURL(p, raw string) {
	if raw == "" {
		v.errf("%s: required", p)
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		v.errf("%s: %v", p, err)
		return
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Not refused: a feed on a loopback address or inside an estate's own
		// network is a real arrangement. But the whole content of the list
		// arrives over it, so anything on the path chooses what this proxy
		// blocks.
		v.warnf("%s: http:// means anything on the path between this proxy and the feed chooses what the proxy blocks, and the credential is in clear. Use https", p)
	default:
		v.errf("%s: must be an http:// or https:// URL", p)
		return
	}
	if u.Host == "" {
		v.errf("%s: no host", p)
	}
	if u.Fragment != "" {
		v.errf("%s: a fragment is not sent, so it cannot be part of a feed's address", p)
	}
}

// feedHTTP checks how a network feed is reached.
func (v *validator) feedHTTP(p string, h *FeedHTTP, l *ThreatList) {
	if d := h.Timeout.D(); d != 0 && (d < time.Second || d > 10*time.Minute) {
		v.errf("%s.timeout: must be between 1s and 10m, or 0 for the default", p)
	}
	if (h.Header == "") != (h.HeaderValue == "") {
		v.errf("%s: header and header_value go together", p)
	}
	if h.Token != "" {
		v.secretRef(p+".token", h.Token)
	}
	if h.CAFile != "" {
		v.file(p+".ca_file", h.CAFile)
	}
	switch {
	case !h.Insecure:
	case !h.AllowInsecure:
		v.errf("%s.insecure: set without allow_insecure; skipping verification takes two decisions rather than one", p)
	default:
		// The package refuses this for anything but a loopback address, and
		// says so at load. Checking here as well means an operator finds out
		// from -validate rather than from a daemon that will not start.
		host := feedHost(l)
		if !isLoopbackHost(host) {
			v.errf("%s.insecure: %s is not a loopback address. A feed nobody authenticated becomes this proxy's block list, so verification may only be skipped for a development instance on this machine", p, host)
		} else {
			v.warnf("%s.insecure: the feed's certificate is not verified. Only defensible because %s is on this machine", p, host)
		}
	}
}

// feedHost is the host of whichever source a list has.
func feedHost(l *ThreatList) string {
	raw := l.URL
	switch {
	case l.TAXII != nil:
		raw = l.TAXII.APIRoot
	case l.MISP != nil:
		raw = l.MISP.URL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
}

// isLoopbackHost reports whether a host is this machine.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// ntpListener checks the NTP and NTS gateway.
//
// Two things shape the checks. Every bound here is one a device on the
// other side will not check for itself -- a clock is believed absolutely
// -- and several of the settings are ones that turn a control off, so
// those are warnings rather than silence: an estate should be able to
// find out from validation that its time gateway is not comparing its
// sources.
func (v *validator) ntpListener(p string, n *NTPListener) {
	switch n.Mode {
	case "", "reverse", "forward":
	default:
		v.errf("%s.mode: must be reverse or forward", p)
	}
	if n.Upstream == "" {
		v.errf("%s.upstream: required: a time gateway with no server has nothing to forward to", p)
	}
	for i, ver := range n.Versions {
		switch {
		case ver == 5:
			v.errf("%s.versions[%d]: version 5 is not a version this parser reads; allow_version5 forwards it as opaque bytes", p, i)
		case ver < 1 || ver > 4:
			v.errf("%s.versions[%d]: %d is not an NTP version", p, i, ver)
		case ver <= 2:
			v.warnf("%s.versions[%d] is %d, which has no mode field of its own: accept it only where a device is known to need it", p, i, ver)
		}
	}
	symmetric := false
	for i, m := range n.Modes {
		switch m {
		case "client", "server":
		case "symmetric_active", "symmetric_passive", "broadcast":
			symmetric = true
		case "control", "private":
			v.errf("%s.modes[%d]: %q is not a time service mode and is always refused: mode 6 is the control protocol and mode 7 the private one monlist belongs to", p, i, m)
		default:
			v.errf("%s.modes[%d]: %q is not a mode", p, i, m)
		}
	}
	if symmetric && len(n.Peers) == 0 {
		v.errf("%s.peers: required when a symmetric or broadcast mode is accepted: those modes are relationships between named peers, not requests from whoever asks", p)
	}
	v.ntpCIDRs(p+".allow_clients", n.AllowClients)
	v.ntpCIDRs(p+".deny_clients", n.DenyClients)
	v.ntpCIDRs(p+".allow_servers", n.AllowServers)
	v.ntpCIDRs(p+".peers", n.Peers)
	v.ntpCIDRs(p+".manycast_responders", n.ManycastResponders)
	if n.AllowManycast && len(n.ManycastResponders) == 0 {
		v.errf("%s.manycast_responders: required with allow_manycast: manycast without a list of responders is an answer from whoever replies first", p)
	}
	if n.AllowVersion5 {
		v.warnf("%s.allow_version5 forwards version 5 packets as opaque bytes: they are not parsed, so no rule here applies to them", p)
	}
	if a := n.Auth; a != nil {
		ids := map[int]bool{}
		for i := range a.Keys {
			k := &a.Keys[i]
			q := fmt.Sprintf("%s.auth.keys[%d]", p, i)
			if k.ID < 1 || k.ID > 65535 {
				v.errf("%s.id: must be between 1 and 65535", q)
			} else if ids[k.ID] {
				v.errf("%s.id: duplicate %d", q, k.ID)
			}
			ids[k.ID] = true
			switch k.Algorithm {
			case "", "aes-cmac":
			case "md5", "sha1":
				if !a.AllowLegacyAlgorithms {
					v.errf("%s.algorithm: %s needs auth.allow_legacy_algorithms: RFC 8573 replaced it because the construction is a broken hash with a length extension", q, k.Algorithm)
				} else {
					v.warnf("%s.algorithm is %s, which RFC 8573 replaced with AES-CMAC: keep it only for a device that cannot be taught another", q, k.Algorithm)
				}
			default:
				v.errf("%s.algorithm: must be aes-cmac, md5 or sha1", q)
			}
			switch {
			case k.KeyFile == "":
				v.errf("%s.key_file: required", q)
			case !strings.HasPrefix(k.KeyFile, "/"):
				v.errf("%s.key_file: must be an absolute path", q)
			default:
				v.file(q+".key_file", k.KeyFile)
			}
		}
		if a.Require && len(a.Keys) == 0 && (n.NTS == nil || !n.NTS.Require) {
			v.errf("%s.auth.require: needs keys, or nts.require: a listener that demands authentication it cannot check refuses every packet", p)
		}
		if a.ProbeKeyID != 0 && !ids[a.ProbeKeyID] {
			v.errf("%s.auth.probe_key_id: %d is not one of the keys", p, a.ProbeKeyID)
		}
	}
	if s := n.NTS; s != nil {
		switch s.Mode {
		case "", "passthrough", "off", "terminate":
		default:
			v.errf("%s.nts.mode: must be passthrough, terminate or off", p)
		}
		if s.Require && s.Mode == "off" {
			v.errf("%s.nts: require with mode off refuses every packet: NTS cannot be required by a listener that is not passing it", p)
		}
		if s.Mode == "terminate" && s.KeyListener == "" {
			v.errf("%s.nts.key_listener: required with mode terminate: the cookies this listener opens were issued by an ntske listener, and it has to be named", p)
		}
		if s.Mode != "terminate" && s.KeyListener != "" {
			v.errf("%s.nts.key_listener: set with mode %q, which does not open cookies", p, s.Mode)
		}
		if s.Source != nil {
			if s.Mode != "terminate" {
				v.errf("%s.nts.source: needs mode terminate: the relay can only hold its own association with the source once the client's authentication ends here", p)
			}
			v.ntsSource(p+".nts.source", s.Source)
		}
	}
	if e := n.Extensions; e != nil {
		if e.Max != 0 && (e.Max < 1 || e.Max > 32) {
			v.errf("%s.extensions.max: must be between 1 and 32", p)
		}
		if e.AllowUnknown {
			v.warnf("%s.extensions.allow_unknown forwards fields this relay cannot read, which is every field Autokey defined and anything else a sender invents", p)
		}
		if e.RefuseAmbiguousMAC != nil && !*e.RefuseAmbiguousMAC {
			v.warnf("%s.extensions.refuse_ambiguous_mac is off, so a packet whose tail is both a MAC and an extension field is forwarded on this relay's reading of it (RFC 7822 cannot tell them apart)", p)
		}
	}
	if q := n.Quality; q != nil {
		if q.CompareSources != nil && !*q.CompareSources {
			v.warnf("%s.quality.compare_sources is off, so nothing here notices a server that is reachable, synchronised and wrong -- which is the failure a relay can catch and a client cannot", p)
		}
		if d := q.ProbeInterval.D(); q.ProbeInterval != 0 && (d < time.Second || d > time.Hour) {
			v.errf("%s.quality.probe_interval: must be between 1s and 1h", p)
		}
		for _, f := range []struct {
			key string
			val Duration
		}{{"max_disagreement", q.MaxDisagreement}, {"max_offset", q.MaxOffset}, {"max_delay", q.MaxDelay},
			{"max_root_delay", q.MaxRootDelay}, {"max_root_dispersion", q.MaxRootDispersion}} {
			if f.val < 0 || f.val > Duration(time.Hour) {
				v.errf("%s.quality.%s: must be between 0 and 1h", p, f.key)
			}
		}
		if q.MaxStratum < 0 || q.MaxStratum > 16 {
			v.errf("%s.quality.max_stratum: must be between 0 and 16", p)
		}
		if q.MaxRootDistance < 0 || q.MaxRootDistance > Duration(time.Hour) {
			v.errf("%s.quality.max_root_distance: must be between 0 and 1h", p)
		}
		for i, st := range q.AllowStrata {
			switch {
			case st < 1 || st > 15:
				v.errf("%s.quality.allow_strata[%d]: %d is not a stratum a server answers with: 1 to 15, since stratum 0 is a kiss-o'-death rather than a time and 16 is the protocol's own unsynchronised", p, i, st)
			case q.MaxStratum > 0 && st > q.MaxStratum:
				v.errf("%s.quality.allow_strata[%d]: stratum %d is past max_stratum %d, so naming it here cannot admit it", p, i, st, q.MaxStratum)
			}
		}
		for i, id := range q.ExpectRefID {
			switch {
			case id == "":
				v.errf("%s.quality.expect_refid[%d]: empty", p, i)
			case len(id) > 15:
				v.errf("%s.quality.expect_refid[%d]: %q is neither a four-character reference clock name nor a dotted quad", p, i, id)
			}
		}
		switch q.LeapPolicy {
		case "", "alert", "allow", "window", "refuse":
		default:
			v.errf("%s.quality.leap_policy: must be alert, allow, window or refuse", p)
		}
		if q.LeapPolicy == "allow" {
			v.warnf("%s.quality.leap_policy is allow, so a leap second announced in a month the IERS never uses is forwarded to every client without a word: an announcement makes each of them plan to move its clock", p)
		}
		if d := q.LeapWindow; d != 0 && (d < Duration(time.Hour) || d > Duration(90*24*time.Hour)) {
			v.errf("%s.quality.leap_window: must be between 1h and 2160h", p)
		}
		if q.RefuseBogusTimestamps != nil && !*q.RefuseBogusTimestamps {
			v.warnf("%s.quality.refuse_bogus_timestamps is off, so an answer whose own timestamps cannot describe an exchange is forwarded, and the client computes an offset from it", p)
		}
		if q.RefuseBogusRefID != nil && !*q.RefuseBogusRefID {
			v.warnf("%s.quality.refuse_bogus_refid is off, so a stratum 1 answer that names no reference clock is forwarded as if it came from one", p)
		}
		for _, f := range []struct {
			key string
			val int
		}{{"healthy_after", q.HealthyAfter}, {"unhealthy_after", q.UnhealthyAfter}} {
			if f.val < 0 || f.val > 100 {
				v.errf("%s.quality.%s: must be between 0 and 100", p, f.key)
			}
		}
		switch q.OnAllSuspect {
		case "", "pass":
		case "refuse":
			v.warnf("%s.quality.on_all_suspect is refuse, so this listener stops answering when no server can be trusted: that is a deliberate outage rather than a wrong clock, and it has to be the estate's choice", p)
		default:
			v.errf("%s.quality.on_all_suspect: must be pass or refuse", p)
		}
		if q.RefuseUnsynchronised != nil && !*q.RefuseUnsynchronised {
			v.warnf("%s.quality.refuse_unsynchronised is off, so an answer from a server that says its own clock is not synchronised is passed to the clients", p)
		}
	}
	if h := n.Holdover; h != nil && (h.MaxDuration < 0 || h.MaxDuration > Duration(24*time.Hour)) {
		v.errf("%s.holdover.max_duration: must be between 0 and 24h", p)
	}
	if c := n.ChangeDetection; c != nil {
		if d := c.MaxStep; d < 0 || d > Duration(time.Hour) {
			v.errf("%s.change_detection.max_step: must be between 0 and 1h", p)
		}
		if c.MaxStratumJump < 0 || c.MaxStratumJump > 15 {
			v.errf("%s.change_detection.max_stratum_jump: must be between 0 and 15", p)
		}
		if c.DispersionGrowth < 0 || c.DispersionGrowth > 1_000_000 {
			v.errf("%s.change_detection.dispersion_growth: must be between 0 and 1000000", p)
		}
		switch c.Action {
		case "", "alert":
		case "refuse":
			v.warnf("%s.change_detection.action is refuse, so a source that changed stops reaching the clients until an operator looks: that stops corrections rather than merely reporting them, and it has to be the estate's choice", p)
		default:
			v.errf("%s.change_detection.action: must be alert or refuse", p)
		}
		if c.Enabled != nil && !*c.Enabled {
			v.warnf("%s.change_detection is off, so nothing here notices a time source being replaced, re-pointed or stood in front of: every check that is left asks whether one answer was good, not whether this is still the same server", p)
		}
	}
	if l := n.Learn; l != nil && l.Enabled {
		if l.File == "" {
			v.errf("%s.learn.file: required when learning is enabled", p)
		} else if !strings.HasPrefix(l.File, "/") {
			v.errf("%s.learn.file: must be an absolute path", p)
		}
		if l.Interval != 0 && (l.Interval.D() < 10*time.Second || l.Interval.D() > 24*time.Hour) {
			v.errf("%s.learn.interval: must be between 10s and 24h", p)
		}
		if l.MaxSubjects != 0 && (l.MaxSubjects < 16 || l.MaxSubjects > 1_000_000) {
			v.errf("%s.learn.max_subjects: must be between 16 and 1000000", p)
		}
		if !l.Enforce {
			v.warnf("%s.learn is enabled without enforce, so this listener records and decides nothing: turn enforce on, or take the learning section out, once the lists are written", p)
		}
	}
	if tr := n.Trace; tr != nil {
		if tr.File == "" {
			v.errf("%s.trace.file: required", p)
		} else if !strings.HasPrefix(tr.File, "/") {
			v.errf("%s.trace.file: must be an absolute path", p)
		}
		if tr.MaxBytes != 0 && (tr.MaxBytes < 1<<20 || tr.MaxBytes > 64<<30) {
			v.errf("%s.trace.max_bytes: must be between 1MiB and 64GiB", p)
		}
	}
	if n.MaxPacketBytes != 0 && (n.MaxPacketBytes < 48 || n.MaxPacketBytes > 9000) {
		v.errf("%s.max_packet_bytes: must be between 48, the header, and 9000", p)
	}
	if n.MaxExtensions != 0 && (n.MaxExtensions < 1 || n.MaxExtensions > 32) {
		v.errf("%s.max_extensions: must be between 1 and 32", p)
	}
	for _, f := range []struct {
		key string
		val int
	}{{"max_associations", n.MaxAssociations}, {"max_outstanding", n.MaxOutstanding}} {
		if f.val != 0 && (f.val < 16 || f.val > 1_000_000) {
			v.errf("%s.%s: must be between 16 and 1000000", p, f.key)
		}
	}
	if d := n.IdleTimeout; d != 0 && (d < Duration(time.Second) || d > Duration(24*time.Hour)) {
		v.errf("%s.idle_timeout: must be between 1s and 24h", p)
	}
	if d := n.RequestTimeout; d != 0 && (d < Duration(100*time.Millisecond) || d > Duration(time.Minute)) {
		v.errf("%s.request_timeout: must be between 100ms and 1m", p)
	}
	for _, f := range []struct {
		key string
		val int
	}{{"rate_limit", n.RateLimit}, {"rate_burst", n.RateBurst},
		{"prefix_rate_limit", n.PrefixRateLimit}, {"prefix_rate_burst", n.PrefixRateBurst}} {
		if f.val < 0 || f.val > 1_000_000 {
			v.errf("%s.%s: must be between 0 and 1000000", p, f.key)
		}
	}
	if n.RatePrefixLength < 0 || n.RatePrefixLength > 128 {
		v.errf("%s.rate_prefix_length: must be between 0 and 128", p)
	}
	// The advice.
	if len(n.AllowClients) == 0 && len(n.DenyClients) == 0 {
		v.warnf("%s.allow_clients is empty, so any client that can reach this listener gets the time from it: an open NTP port is also an amplifier, and the modes that amplify are refused here but the traffic still arrives", p)
	}
	if n.RateLimit == 0 && n.PrefixRateLimit == 0 {
		v.warnf("%s has no rate limit, so one client can spend the servers' whole answer budget: a poll is once a minute and a flood is thousands a second", p)
	}
}

// ntpCIDRs checks a list of networks.
func (v *validator) ntpCIDRs(what string, list []string) {
	for i, s := range list {
		if _, err := netip.ParsePrefix(s); err != nil {
			v.errf("%s[%d]: %q is not a network in CIDR form", what, i, s)
		}
	}
}

// ntsSource checks the relay's own association with the time source.
func (v *validator) ntsSource(p string, n *NTPSourceNTS) {
	if n.KEAddress == "" {
		v.errf("%s.ke_address: required", p)
	} else {
		host := n.KEAddress
		if h, _, err := net.SplitHostPort(n.KEAddress); err == nil {
			host = h
		}
		if !hostPatternOK(host) {
			v.errf("%s.ke_address: %q is not a host or host:port", p, n.KEAddress)
		}
	}
	if n.ServerName != "" && !hostPatternOK(n.ServerName) {
		v.errf("%s.server_name: %q is not a valid host name", p, n.ServerName)
	}
	if n.CAFile != "" {
		v.file(p+".ca_file", n.CAFile)
	} else {
		v.warnf("%s.ca_file: empty, so the source's certificate is checked against the system trust store -- on a plant network that admits any public authority, which is not usually what an estate means by \"this is our time server\"", p)
	}
	if (n.CertFile == "") != (n.KeyFile == "") {
		v.errf("%s: cert_file and key_file are both needed, or neither", p)
	}
	if n.CertFile != "" {
		v.file(p+".cert_file", n.CertFile)
		v.file(p+".key_file", n.KeyFile)
	}
	if n.RefreshBelow != 0 && (n.RefreshBelow < 1 || n.RefreshBelow > 8) {
		v.errf("%s.refresh_below: must be between 1 and 8", p)
	}
	if d := n.Timeout; d != 0 && (d.D() < time.Second || d.D() > time.Minute) {
		v.errf("%s.timeout: must be between 1s and 1m", p)
	}
	v.warnf("%s: there is no end-to-end authentication between a client and the time source any more. The client authenticates to this relay and this relay authenticates to the source, so the process is a party to the security rather than a reader of it -- which is the point, and is worth being written down", p)
}

// ntsKeyListener checks that a named listener is one that issues cookies.
func (v *validator) ntsKeyListener(p string, c *Config, name string) {
	for i := range c.Server.Listeners {
		ln := &c.Server.Listeners[i]
		if ln.Name != name {
			continue
		}
		switch {
		case ln.Kind != "ntske":
			v.errf("%s.key_listener: %q is a %s listener, not an ntske one", p, name, kindOrHTTP(ln.Kind))
		case !ln.NTSKE.Terminating():
			v.errf("%s.key_listener: %q relays key establishment rather than terminating it, so it holds no cookie keys", p, name)
		}
		return
	}
	v.errf("%s.key_listener: no listener named %q", p, name)
}

// kindOrHTTP names a listener's kind, including the default.
func kindOrHTTP(kind string) string {
	if kind == "" {
		return "http"
	}
	return kind
}

// ntskeListener checks the NTS key establishment relay.
func (v *validator) ntskeListener(p string, k *NTSKEListener, address string, hasTLS bool) {
	switch {
	case k.Terminating():
		if k.Upstream != "" {
			v.errf("%s.upstream: set with terminate: this listener answers key establishment itself, so there is nothing to relay it to", p)
		}
		v.ntskeTerminate(p+".terminate", k.Terminate, hasTLS)
	case k.Upstream == "":
		v.errf("%s.upstream: required, or terminate to answer key establishment here", p)
	}
	v.ntpCIDRs(p+".allow_clients", k.AllowClients)
	v.ntpCIDRs(p+".deny_clients", k.DenyClients)
	for i, n := range k.ServerNames {
		if !hostPatternOK(n) {
			v.errf("%s.server_names[%d]: %q is not a valid host pattern", p, i, n)
		}
	}
	if k.MaxConnections != 0 && (k.MaxConnections < 1 || k.MaxConnections > 65536) {
		v.errf("%s.max_connections: must be between 1 and 65536", p)
	}
	if k.MaxConcurrentHandshakes != 0 && (k.MaxConcurrentHandshakes < 1 || k.MaxConcurrentHandshakes > 4096) {
		v.errf("%s.max_concurrent_handshakes: must be between 1 and 4096", p)
	}
	if d := k.HandshakeTimeout; d != 0 && (d < Duration(time.Second) || d > Duration(time.Minute)) {
		v.errf("%s.handshake_timeout: must be between 1s and 1m", p)
	}
	if d := k.IdleTimeout; d != 0 && (d < Duration(time.Second) || d > Duration(10*time.Minute)) {
		v.errf("%s.idle_timeout: must be between 1s and 10m", p)
	}
	if k.MaxBytes != 0 && (k.MaxBytes < 1024 || k.MaxBytes > 1<<30) {
		v.errf("%s.max_bytes: must be between 1024 and 1GiB", p)
	}
	if !k.ALPNRequired() {
		v.warnf("%s.require_alpn is off, so a connection to this port that is not an NTS client is relayed anyway: the application protocol is the only thing the handshake shows that says what a connection is for", p)
	}
	if _, port, err := net.SplitHostPort(address); err == nil && port != "4460" && port != "0" {
		v.warnf("%s is on port %s rather than 4460: a client that found this service through a server's own key establishment record will look for 4460", p, port)
	}
}

// ntskeTerminate checks the terminating side.
func (v *validator) ntskeTerminate(p string, t *NTSKETerminate, hasTLS bool) {
	if !hasTLS {
		// The certificate is the whole of what a client authenticates in NTS:
		// there is nothing else in the exchange that names the server. A
		// terminating listener without one could not answer at all.
		v.errf("%s: needs a tls section on the listener: the certificate is the only thing an NTS client authenticates", p)
	}
	if t.Server != "" && !hostPatternOK(t.Server) {
		v.errf("%s.server: %q is not a valid host name", p, t.Server)
	}
	if t.Port != 0 && (t.Port < 1 || t.Port > 65535) {
		v.errf("%s.port: must be between 1 and 65535", p)
	}
	if t.Cookies != 0 && (t.Cookies < 1 || t.Cookies > 8) {
		// Eight is the bound because it is also the bound on how many cookies
		// one time exchange may ask for: a listener that issued more would be
		// answering a request with a response larger than the client asked for.
		v.errf("%s.cookies: must be between 1 and 8", p)
	}
	if d := t.RotateEvery; d != 0 && (d.D() < time.Minute || d.D() > 30*24*time.Hour) {
		v.errf("%s.rotate_every: must be between 1m and 720h", p)
	}
	if n := t.KeepKeys; n != nil && (*n < 0 || *n > 64) {
		v.errf("%s.keep_keys: must be between 0 and 64", p)
	}
	if t.KeepKeys != nil && *t.KeepKeys == 0 {
		v.warnf("%s.keep_keys: 0, so a rotation refuses every cookie already issued at once and every client has to establish keys again -- a TLS handshake each, all at the same moment", p)
	}
	if t.State == "" {
		v.warnf("%s.state: empty, so the cookie keys live only in memory and a restart refuses every cookie in the estate -- every client then re-establishes at once, which is the load a restart should not create", p)
	} else if !filepath.IsAbs(t.State) {
		v.errf("%s.state: must be an absolute path", p)
	}
}

// endpointsOf is how many endpoints a named pool has, for the advice that
// depends on it.
func endpointsOf(c *Config, name string) int {
	for i := range c.Upstreams {
		if c.Upstreams[i].Name == name {
			return len(c.Upstreams[i].Endpoints)
		}
	}
	return 0
}

// assetInventory validates the device inventory.
// correlation checks the cross-listener window's bounds.
//
// The bounds are the whole of it: this is a table keyed by an address a
// stranger picks, so a window nobody bounded is a window an address flood
// fills. The package clamps to its own ceilings whatever this says, and
// validation says so here rather than letting an operator believe a
// 72-hour window is in force.
func (v *validator) correlation(c *Config) {
	a := c.Correlation
	const p = "correlation"
	if d := time.Duration(a.Window); d < 0 {
		v.errf("%s.window: must not be negative", p)
	} else if d > correlate.MaxWindow {
		v.errf("%s.window: %s is above the %s ceiling; a longer window is a bigger table keyed by an address a stranger picks",
			p, d, correlate.MaxWindow)
	} else if d > 0 && d < time.Minute {
		v.warnf("%s.window: %s is shorter than a scan cycle on most of these protocols, so a chain of two events will rarely be inside it", p, d)
	}
	if a.MaxActors < 0 {
		v.errf("%s.max_actors: must not be negative", p)
	} else if a.MaxActors > correlate.MaxActorsCeil {
		v.errf("%s.max_actors: %d is above the %d ceiling", p, a.MaxActors, correlate.MaxActorsCeil)
	}
	if a.MaxFacts < 0 {
		v.errf("%s.max_facts: must not be negative", p)
	} else if a.MaxFacts > correlate.MaxFactsCeil {
		v.errf("%s.max_facts: %d is above the %d ceiling", p, a.MaxFacts, correlate.MaxFactsCeil)
	}
	if a.Share != nil && *a.Share && c.Cluster == nil {
		v.warnf("%s.share is on with no cluster section, so there is nobody to share with: a pivot from a bastion into a control protocol crosses two daemons, and seeing it needs both of them in one cluster", p)
	}
	if !c.CorrelationEnabled() {
		v.warnf("%s.enabled is false, so nothing is remembered between listeners: the detections that need two listeners -- one host on several control protocols, an OT session after a bastion session, a clock step before a time-tagged command -- report nothing rather than reporting less", p)
	}
}

// packs validates the behaviour-pack directory. The files themselves are not
// read here: a pack is loaded and verified at start by internal/packs, which
// names the file and the reason when one does not pass. What this checks is the
// arrangement -- that there is a directory, that something can vouch for what is
// in it, and that a signature is asked for.
func (v *validator) packs(a *Packs) {
	const p = "packs"
	if a.Directory == "" {
		v.errf("%s.directory: required, and the packs do nothing without it", p)
	} else if !filepath.IsAbs(a.Directory) {
		v.errf("%s.directory: must be an absolute path", p)
	}
	names := map[string]bool{}
	for i, k := range a.Keys {
		q := fmt.Sprintf("%s.keys[%d]", p, i)
		if strings.TrimSpace(k.Name) == "" {
			v.errf("%s.name: required, because a signature names a key", q)
		} else if names[k.Name] {
			v.errf("%s.name: %q twice, so a signature naming it would be ambiguous", q, k.Name)
		}
		names[k.Name] = true
		switch {
		case k.Key != "" && k.File != "":
			v.errf("%s: key and file both given; one of the two", q)
		case k.Key == "" && k.File == "":
			v.errf("%s: one of key or file", q)
		case k.File != "" && !filepath.IsAbs(k.File):
			v.errf("%s.file: must be an absolute path", q)
		case k.Key != "":
			if _, err := packs.ParseKey(k.Name, k.Key); err != nil {
				v.errf("%s.key: %v", q, err)
			}
		}
	}
	if len(a.Keys) == 0 && !a.AllowUnsigned {
		v.errf("%s: no keys and allow_unsigned is off, so every pack in the directory would be refused. "+
			"Name the key that signs them, or say allow_unsigned for a directory this estate writes itself", p)
	}
	if a.AllowUnsigned {
		v.warnf("%s.allow_unsigned is on, so a pack with no signature is loaded: anybody who can write a file in %s "+
			"can change what this daemon alerts on, and -- where enforce is on -- what it refuses", p, a.Directory)
	}
	if a.Enforce {
		v.warnf("%s.enforce is on, so a pack that declares `enforcement: deny` may hold an address out of the "+
			"plant listeners for the length of its own window. That is not the ban ladder and it expires by itself, "+
			"but it is still a control room losing a master: read the reports for a month first", p)
	}
	if a.MaxActors < 0 || a.MaxActors > 1<<20 {
		v.errf("%s.max_actors: must be between 0 and 1048576", p)
	}
	if a.MaxQuarantined < 0 || a.MaxQuarantined > 65536 {
		v.errf("%s.max_quarantined: must be between 0 and 65536", p)
	}
	for i, id := range a.Disabled {
		if strings.TrimSpace(id) == "" {
			v.errf("%s.disabled[%d]: empty", p, i)
		}
	}
}

func (v *validator) assetInventory(a *AssetInventory) {
	const p = "asset_inventory"
	if a.MaxAssets < 0 || a.MaxAssets > 1<<20 {
		v.errf("%s.max_assets: must be between 0 and 1048576", p)
	}
	for _, d := range []struct {
		key    string
		val    Duration
		lo, hi time.Duration
	}{
		{"save_interval", a.SaveInterval, 10 * time.Second, 24 * time.Hour},
		{"ttl", a.TTL, time.Hour, 365 * 24 * time.Hour},
	} {
		if d.val != 0 && (d.val.D() < d.lo || d.val.D() > d.hi) {
			v.errf("%s.%s: must be between %s and %s", p, d.key, d.lo, d.hi)
		}
	}
	for i, name := range a.Roles {
		if _, ok := assets.RoleOf(name); !ok {
			v.errf("%s.roles[%d]: %q is not a role (%s)", p, i, name, roleNames())
		}
	}
	if a.StateFile != "" && !filepath.IsAbs(a.StateFile) {
		v.errf("%s.state_file: must be an absolute path", p)
	}
	if a.VendorFile != "" && !filepath.IsAbs(a.VendorFile) {
		v.errf("%s.vendor_file: must be an absolute path", p)
	}
	if a.Enabled && a.StateFile == "" {
		v.warnf("%s.state_file: empty, so the inventory starts from nothing after every restart and reports the whole estate as new -- which is the fastest way to teach an operator to ignore it", p)
	}
	if a.Advisories != nil {
		v.advisories(p+".advisories", a, a.Advisories)
	}
}

// advisories checks the CSAF matching.
//
// Everything here is checked at load rather than at the first read, for the
// reason the package itself gives: a source that cannot be read is a set that
// silently matches nothing, and a proxy reporting no advisories against an
// estate is the one wrong answer this feature must not give.
func (v *validator) advisories(p string, inv *AssetInventory, a *Advisories) {
	if a.Enabled && !inv.Enabled {
		v.errf("%s.enabled: the advisory matching needs the inventory it matches, so asset_inventory.enabled must be true as well", p)
	}
	if a.Enabled && len(a.Sources) == 0 {
		v.errf("%s.sources: required when the advisory matching is enabled", p)
	}
	seen := map[string]bool{}
	for i := range a.Sources {
		src := &a.Sources[i]
		where := fmt.Sprintf("%s.sources[%d]", p, i)
		switch {
		case src.Name == "":
			v.errf("%s.name: required; it is what names the source in the status view", where)
		case seen[src.Name]:
			v.errf("%s.name: duplicate name %q", where, src.Name)
		default:
			seen[src.Name] = true
			where = p + ".sources." + src.Name
		}
		switch {
		case src.File == "" && src.Directory == "":
			v.errf("%s: one of file or directory is required", where)
		case src.File != "" && src.Directory != "":
			v.errf("%s: file and directory are alternatives, not both", where)
		}
		for key, path := range map[string]string{"file": src.File, "directory": src.Directory} {
			if path != "" && !filepath.IsAbs(path) {
				v.errf("%s.%s: must be an absolute path", where, key)
			}
		}
	}
	if d := a.Refresh; d != nil && *d != 0 && (d.D() < time.Minute || d.D() > 7*24*time.Hour) {
		v.errf("%s.refresh: must be between 1m and 168h, or 0 for never", p)
	}
	if a.MinSeverity != "" {
		switch strings.ToLower(a.MinSeverity) {
		case "critical", "high", "medium", "low":
		default:
			v.errf("%s.min_severity: must be critical, high, medium or low", p)
		}
	}
	if a.Enabled && inv.StateFile == "" {
		v.warnf("%s: the inventory is not written to a file, so every restart re-assesses an estate it has forgotten and the findings arrive again as if they were new", p)
	}
}

// roleNames lists the roles for a validation message.
func roleNames() string {
	return strings.Join(assets.RoleNames(), ", ")
}

// bacnetListener checks a kind: bacnet section.
//
// Every name is resolved here rather than at the first datagram, because a
// service, object type or property this file spells wrong would otherwise be
// a rule that quietly matches nothing -- which on this protocol is a policy
// with a hole in it that nothing reports.
func (v *validator) bacnetListener(p string, m *BACnetListener) {
	v.anomaly(p+".anomaly", m.Anomaly)
	v.engineering(p+".engineering", m.Engineering)
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	if len(m.AllowClients) == 0 {
		v.warnf("%s.allow_clients: empty, so any address may send: BACnet has no "+
			"authentication, and this list is the only identity a request has", p)
	}
	v.bacnetServices(p+".services", m.Services)
	v.bacnetServices(p+".deny_services", m.DenyServices)
	v.bacnetObjects(p+".objects", m.Objects)
	v.bacnetObjects(p+".deny_objects", m.DenyObjects)
	v.bacnetProperties(p+".properties", m.Properties)
	v.bacnetProperties(p+".deny_properties", m.DenyProperties)
	v.bacnetPriority(p+".max_command_priority", m.MaxCommandPriority)
	v.bacnetNetworks(p+".networks", m.Networks)
	if m.MaxPriority != "" {
		switch strings.ToLower(m.MaxPriority) {
		case "normal", "urgent", "critical-equipment", "life-safety":
		default:
			v.errf("%s.max_priority: must be normal, urgent, critical-equipment or life-safety", p)
		}
	}
	if m.MaxHopCount < 0 || m.MaxHopCount > 255 {
		v.errf("%s.max_hop_count: must be between 1 and 255", p)
	}
	if m.MaxMessageBytes < 0 || m.MaxMessageBytes > bacnetwire.MaxMessage {
		v.errf("%s.max_message_bytes: must be between 1 and %d, which is Annex J's own maximum",
			p, bacnetwire.MaxMessage)
	}
	if m.MaxBroadcastReplies < 0 {
		v.errf("%s.max_broadcast_replies: must not be negative", p)
	}
	if m.MaxWhoIsRange < 0 {
		v.errf("%s.max_whois_range: must not be negative", p)
	}
	if m.MaxPending < 0 || m.MaxPending > 256 {
		// There are two hundred and fifty-six invoke identifiers, and the
		// relay allocates one per outstanding request. A larger table
		// cannot hold more than that, and asking for one says the
		// configuration expects something the protocol cannot do.
		v.errf("%s.max_pending: must be between 1 and 256, which is how many invoke "+
			"identifiers the protocol has", p)
	}
	switch m.DenyResponse {
	case "", "reject", "error", "drop":
	default:
		v.errf("%s.deny_response: must be reject, error or drop", p)
	}
	switch m.DefaultAction {
	case "", "deny", "allow":
	default:
		v.errf("%s.default_action: must be deny or allow", p)
	}
	if m.DefaultAction == "allow" {
		v.warnf("%s.default_action: allow carries every request no rule refuses, on a "+
			"protocol with no authentication", p)
	}
	if bacnetOn(m.AllowBBMD) {
		v.warnf("%s.allow_bbmd: register-foreign-device asks a BBMD to send the "+
			"registering address every broadcast on a network it is not on, from one "+
			"unauthenticated datagram", p)
	}
	if bacnetOn(m.AllowRouting) && !bacnetOn(m.AllowNetworkMessages) {
		v.errf("%s.allow_routing: needs allow_network_messages, because a routing "+
			"message is a network layer message", p)
	}
	if bacnetOn(m.AllowForwarded) && !bacnetOn(m.AllowBroadcast) {
		v.warnf("%s.allow_forwarded: a forwarded-npdu is a broadcast somebody else "+
			"relayed, and it carries the originating address inside the payload", p)
	}
	names := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		rp := fmt.Sprintf("%s.rules[%d]", p, i)
		if r.Name == "" {
			v.errf("%s.name: required", rp)
		} else if names[r.Name] {
			v.errf("%s.name: %q is used twice", rp, r.Name)
		}
		names[r.Name] = true
		switch r.Action {
		case "allow", "deny", "observe":
		default:
			v.errf("%s.action: must be allow, deny or observe", rp)
		}
		v.modbusCIDRs(rp+".clients", r.Clients)
		v.bacnetServices(rp+".services", r.Services)
		v.bacnetObjects(rp+".objects", r.Objects)
		v.bacnetObjects(rp+".deny_objects", r.DenyObjects)
		v.bacnetProperties(rp+".properties", r.Properties)
		v.bacnetProperties(rp+".deny_properties", r.DenyProperties)
		v.bacnetRanges(rp+".instances", r.Instances)
		v.bacnetNetworks(rp+".networks", r.Networks)
		v.bacnetPriority(rp+".max_command_priority", r.MaxCommandPriority)
		v.modbusSchedule(rp+".schedule", r.Schedule)
	}
}

// bacnetOn reads an optional boolean the way the kind does, so a warning
// about a setting says what the listener will actually do with it.
//
// Every setting it is asked about defaults to off. The ones that default to
// on are refusals -- deny_sensitive_writes, refuse_unlocated_objects -- and a
// warning about those would fire on every well-configured file.
func bacnetOn(p *bool) bool { return p != nil && *p }

func (v *validator) bacnetServices(p string, names []string) {
	for _, n := range names {
		if _, ok := bacnetwire.ParseService(n); !ok {
			v.errf("%s: %q is not a BACnet service", p, n)
		}
	}
}

func (v *validator) bacnetObjects(p string, names []string) {
	for _, n := range names {
		if _, ok := bacnetwire.ParseObjectType(n); !ok {
			v.errf("%s: %q is not a BACnet object type", p, n)
		}
	}
}

func (v *validator) bacnetProperties(p string, names []string) {
	for _, n := range names {
		if _, ok := bacnetwire.ParseProperty(n); !ok {
			v.errf("%s: %q is not a BACnet property", p, n)
		}
	}
}

// bacnetPriority checks a command priority. Zero means "not set", which is
// how a rule says it takes the listener's bound.
func (v *validator) bacnetPriority(p string, n int) {
	if n < 0 || n > 16 {
		v.errf("%s: must be between 1 and 16, which are the command priorities of clause 19.2", p)
	}
	if n > 0 && n <= 2 {
		v.warnf("%s: priority 1 and 2 are life safety and cannot be overridden by the "+
			"management system, a schedule or an operator", p)
	}
}

func (v *validator) bacnetNetworks(p string, ns []int) {
	for _, n := range ns {
		if n < 0 || n > 65535 {
			v.errf("%s: %d is not a BACnet network number", p, n)
		}
		if n == 65535 {
			v.errf("%s: 65535 is the global broadcast network, which this relay will not route to", p)
		}
	}
}

// bacnetRanges checks instance ranges written as 1-100 or as one number.
func (v *validator) bacnetRanges(p string, specs []string) {
	for _, s := range specs {
		lo, hi, found := strings.Cut(strings.TrimSpace(s), "-")
		low, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 22)
		if err != nil {
			v.errf("%s: %q is not an instance or a range of them", p, s)
			continue
		}
		if !found {
			continue
		}
		high, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 22)
		if err != nil {
			v.errf("%s: %q is not a range of instances", p, s)
			continue
		}
		if high < low {
			v.errf("%s: %q runs backwards", p, s)
		}
	}
}

// grantRequired says whether an engineering block asks the ledger for
// anything, which is what makes a listener one the access section has to exist
// for.
func grantRequired(e *Engineering) bool { return e != nil && e.RequireGrant }

// access checks the access section and the listeners that require a grant.
//
// The two halves are checked together on purpose: a listener that requires a
// grant with no ledger to ask would refuse every session, and a ledger no
// listener asks is a queue of approvals nobody's access depends on. Each is a
// configuration that reads as if it did something.
func (v *validator) access(c *Config) {
	const p = "access"
	var need []string
	for i := range c.Server.Listeners {
		l := &c.Server.Listeners[i]
		for _, g := range []struct {
			kind string
			on   bool
		}{
			{"ssh", l.SSH != nil && l.SSH.RequireGrant},
			{"telnet", l.Telnet != nil && l.Telnet.RequireGrant},
			{"vnc", l.VNC != nil && l.VNC.RequireGrant},
			{"rdp", l.RDP != nil && l.RDP.RequireGrant},
			{"ftp", l.FTP != nil && l.FTP.RequireGrant},
			// The OT kinds ask for a grant per engineering operation rather
			// than per session, and the mistake is the same one: a listener
			// told to check a ledger that does not exist refuses every
			// download.
			{"modbus engineering", l.Modbus != nil && grantRequired(l.Modbus.Engineering)},
			{"iec104 engineering", l.IEC104 != nil && grantRequired(l.IEC104.Engineering)},
			{"s7 engineering", l.S7 != nil && grantRequired(l.S7.Engineering)},
			{"mms engineering", l.MMS != nil && grantRequired(l.MMS.Engineering)},
			{"bacnet engineering", l.BACnet != nil && grantRequired(l.BACnet.Engineering)},
			{"opcua engineering", l.OPCUA != nil && grantRequired(l.OPCUA.Engineering)},
			{"coap engineering", l.CoAP != nil && grantRequired(l.CoAP.Engineering)},
			{"snmp engineering", l.SNMP != nil && grantRequired(l.SNMP.Engineering)},
			{"tftp engineering", l.TFTP != nil && grantRequired(l.TFTP.Engineering)},
		} {
			if g.on {
				need = append(need, l.Name+" ("+g.kind+")")
			}
		}
	}
	a := c.Access
	if a == nil {
		if len(need) > 0 {
			v.errf("access: %s require a grant, and there is no access section for the grants to come from; "+
				"without one every session on them would be refused", strings.Join(need, ", "))
		}
		return
	}
	if len(need) == 0 {
		v.warnf("%s: no listener sets require_grant, so nothing consults these grants: requests would be approved and "+
			"never used", p)
	}
	if a.Ledger == "" {
		v.warnf("%s.ledger: empty, so the grants live only in this process -- gone at the next restart, with no trail "+
			"of who approved what, which is the record this arrangement exists to produce", p)
	} else if !filepath.IsAbs(a.Ledger) {
		v.errf("%s.ledger: must be an absolute path", p)
	}
	if n := a.Approvals; n != nil {
		switch {
		case *n < 0:
			v.errf("%s.approvals: must not be negative", p)
		case *n > 8:
			v.errf("%s.approvals: at most 8; a grant needing more approvals than an estate has operators is a grant "+
				"nobody can use", p)
		case *n == 0:
			v.warnf("%s.approvals: 0, so a request is in force the moment it is made. Access is still just-in-time and "+
				"time-boxed, but nobody else has to agree -- which is not four eyes", p)
		}
	}
	if d := a.MaxDuration.D(); d < time.Minute || d > 24*time.Hour {
		v.errf("%s.max_duration: must be between 1m and 24h", p)
	}
	if d := a.MaxLead.D(); d < 0 || d > 30*24*time.Hour {
		v.errf("%s.max_lead: must be between 0 and 720h", p)
	}
	if d := a.MaxWorkOrder.D(); d < time.Minute || d > 90*24*time.Hour {
		v.errf("%s.max_work_order: must be between 1m and 2160h", p)
	}
	if a.MaxUses < 0 || a.MaxUses > 1000 {
		v.errf("%s.max_uses: must be between 0 and 1000", p)
	}
	if a.MaxOpen < 1 || a.MaxOpen > 4096 {
		v.errf("%s.max_open: must be between 1 and 4096", p)
	}
	if a.SelfApproval {
		v.warnf("%s.self_approval: the person who asks may approve their own access, so four eyes is off. It is here for "+
			"the estate with one operator; where there are two, this is the setting an attacker who reaches one "+
			"account most wants", p)
	}
}

// certificateKey checks where one certificate's private key comes from.
//
// There are three custody arrangements and they are mutually exclusive, because
// a certificate with two keys configured is a certificate whose key nobody can
// name from the file:
//
//   - key_file: the key is a file on this machine, as it has always been.
//   - key: a reference, so the key may come from a vault or the environment.
//   - signer: the key never enters this process; a helper holds it and answers
//     signature requests over a Unix socket.
func (v *validator) certificateKey(p string, c Certificate) {
	var set []string
	if c.KeyFile != "" {
		set = append(set, "key_file")
	}
	if c.Key != "" {
		set = append(set, "key")
	}
	if c.Signer != nil {
		set = append(set, "signer")
	}
	switch len(set) {
	case 0:
		v.errf("%s: one of key_file, key or signer is required to say where the private key comes from", p)
		return
	case 1:
	default:
		v.errf("%s: %s are all set; exactly one says where the private key comes from", p, strings.Join(set, ", "))
		return
	}
	switch {
	case c.KeyFile != "":
		v.file(p+".key_file", c.KeyFile)
	case c.Key != "":
		v.secretRef(p+".key", c.Key)
	case c.Signer != nil:
		v.signer(p+".signer", c.Signer)
	}
}

// recordingIntegrity checks the manifest section: the key reference resolves to
// something, and one record covers a sensible run of the file.
func (v *validator) recordingIntegrity(p string, i *RecordingIntegrity) {
	if i == nil || (i.Enabled != nil && !*i.Enabled) {
		return
	}
	if i.Key == "" {
		// Worth saying rather than refusing. A chain with no key is useful
		// -- it catches corruption, a shortened file and a partial edit --
		// and it is not what an operator who asked for evidence thinks
		// they configured, because whoever can write the recording can
		// write the manifest too.
		v.warnf("%s.key: no key, so the manifest detects corruption and truncation but anybody who can write the "+
			"recording can recompute the chain; name a key to make the records unforgeable without it", p)
	} else {
		v.secretRef(p+".key", i.Key)
	}
	if i.SegmentBytes < 4096 || i.SegmentBytes > 1<<30 {
		v.errf("%s.segment_bytes: must be 4096..1073741824", p)
	}
}

// recordingEncryption checks the encryption section: a key, because
// there is no encryption without one, and a frame size that is worth
// having.
func (v *validator) recordingEncryption(p string, e *RecordingEncryption) {
	if e == nil || (e.Enabled != nil && !*e.Enabled) {
		return
	}
	if e.Key == "" {
		v.errf("%s.key: required; there is no encryption without a key", p)
	} else {
		v.secretRef(p+".key", e.Key)
	}
	if e.ChunkBytes < recenc.MinChunk || e.ChunkBytes > recenc.MaxChunk {
		v.errf("%s.chunk_bytes: must be %d..%d", p, recenc.MinChunk, recenc.MaxChunk)
	}
	// The thing that goes wrong with encryption at rest is not the
	// cryptography. It is a key nobody kept: the recordings are then as
	// good as deleted, and nobody finds out until an incident.
	v.warnf("%s: a recording encrypted at rest cannot be read without its key, and rotating the key does not "+
		"re-encrypt what is already written -- keep every key for as long as the recordings it wrote are kept", p)
}

// secretRef checks one secret reference: that it parses, that a vault reference
// has a vault to come from, and that a plain path exists.
func (v *validator) secretRef(p, ref string) {
	r, err := keysource.Parse(ref)
	if err != nil {
		v.errf("%s: %v", p, err)
		return
	}
	switch r.Scheme {
	case keysource.SchemeFile:
		if !filepath.IsAbs(r.Target) {
			v.errf("%s: %q must be an absolute path", p, r.Target)
			return
		}
		v.file(p, r.Target)
	case keysource.SchemeEnv:
		// An environment variable is read at resolve time, so there is
		// nothing to check here beyond the name. It is worth a word,
		// though: the environment of a process is readable by anything
		// that can read /proc for the same user, and it is inherited by
		// anything the proxy execs.
		if r.Target != strings.ToUpper(r.Target) {
			v.warnf("%s: env:%s is lower case; environment variables are conventionally upper case, and a name that "+
				"does not match the one the unit sets resolves to nothing", p, r.Target)
		}
	case keysource.SchemeVault:
		if !v.hasVault {
			v.errf("%s: %s is a vault reference and there is no secrets.vault section for it to come from", p, ref)
		}
	}
}

// signer checks an external signer: a socket to reach it on, and the bounds on
// how long one signature may take and how many connections are held.
func (v *validator) signer(p string, s *CertSigner) {
	if s.Socket == "" {
		v.errf("%s.socket: required; it is the Unix socket the signer listens on", p)
	} else if !filepath.IsAbs(s.Socket) {
		v.errf("%s.socket: must be an absolute path", p)
	}
	if s.Key == "" {
		v.errf("%s.key: required; it names which key of the signer's to use", p)
	}
	if d := s.Timeout.D(); d < 100*time.Millisecond || d > time.Minute {
		v.errf("%s.timeout: must be between 100ms and 1m; it bounds one signature, which is on the handshake path", p)
	}
	if s.MaxConns < 1 || s.MaxConns > 256 {
		v.errf("%s.max_conns: must be between 1 and 256", p)
	}
}

// secrets checks the secrets section: where secret references are resolved from.
func (v *validator) secrets(c *Config) {
	const p = "secrets"
	s := c.Secrets
	if s == nil {
		return
	}
	if d := s.RefreshInterval.D(); d < time.Minute || d > 24*time.Hour {
		v.errf("%s.refresh_interval: must be between 1m and 24h; below a minute a vault becomes this proxy's hot path, "+
			"and above a day a rotation does not reach a running process", p)
	}
	vs := s.Vault
	if vs == nil {
		v.warnf("%s: a secrets section with no vault, so only file: and env: references resolve. That is a valid "+
			"arrangement, but this section then only sets the refresh interval", p)
		return
	}
	vp := p + ".vault"
	switch {
	case vs.Address == "":
		v.errf("%s.address: required", vp)
	case strings.HasPrefix(vs.Address, "https://"):
	case strings.HasPrefix(vs.Address, "http://"):
		// Plain HTTP to a vault puts every secret this proxy holds on the
		// wire in clear, including the token that reads them. It is here
		// for a development vault on the loopback and it takes two
		// settings to say so, because one typo must not do it.
		switch {
		case !vs.Insecure:
			v.errf("%s.address: http:// sends the token and every secret in clear; use https://, or set insecure: true "+
				"and allow_insecure: true if this is a development vault", vp)
		case !vs.AllowInsecure:
			v.errf("%s.allow_insecure: insecure is set for an http:// address; allow_insecure must also be true, so "+
				"that serving secrets in clear is two decisions rather than one", vp)
		default:
			v.warnf("%s.address: %s is plain HTTP, so the token and every secret it reads are in clear on the wire. "+
				"This is a development arrangement", vp, vs.Address)
		}
	default:
		v.errf("%s.address: must be an http:// or https:// URL", vp)
	}
	if vs.KVVersion != 1 && vs.KVVersion != 2 {
		v.errf("%s.kv_version: must be 1 or 2", vp)
	}
	switch {
	case vs.TokenFile != "" && vs.TokenEnv != "":
		v.errf("%s: token_file and token_env are both set; exactly one says where the token comes from", vp)
	case vs.TokenFile != "":
		if !filepath.IsAbs(vs.TokenFile) {
			v.errf("%s.token_file: must be an absolute path", vp)
		} else {
			v.file(vp+".token_file", vs.TokenFile)
		}
	case vs.TokenEnv != "":
		v.warnf("%s.token_env: the token is in this process's environment, which anything that can read /proc for this "+
			"user can read, and which every child process inherits. A file with mode 0400 is the tighter "+
			"arrangement", vp)
	default:
		v.errf("%s: one of token_file or token_env is required; there is no anonymous read of a vault", vp)
	}
	if vs.CAFile != "" {
		v.file(vp+".ca_file", vs.CAFile)
	}
	if vs.Insecure && !strings.HasPrefix(vs.Address, "http://") {
		v.errf("%s.insecure: set for an https:// address, which would skip verifying the vault's certificate -- and then "+
			"anything on the path can hand this proxy its secrets. Set ca_file instead", vp)
	}
}

// fips checks the fips section.
//
// The interesting case is required: true on a binary that was not built for it,
// which this section exists to turn from a silent non-event into a refusal at
// start. Validation cannot decide it -- whether the module is active is a
// property of this process, not of the file -- so it says what will be checked
// and where.
func (v *validator) fips(c *Config) {
	const p = "fips"
	f := c.FIPS
	if f == nil {
		return
	}
	if !f.Required {
		if f.Probe != nil && *f.Probe {
			v.warnf("%s.probe: set with required: false, so the algorithms are probed and reported but nothing refuses "+
				"to start. That is a useful reporting arrangement; it is not an enforced one", p)
		}
		if f.ProbeFails {
			v.errf("%s.probe_fails: refusing to start on a probe that fails only makes sense with required: true", p)
		}
		return
	}
	if f.Probe != nil && !*f.Probe && f.ProbeFails {
		v.errf("%s.probe_fails: set with probe: false, so there is no probe to fail", p)
	}
	if !fipsmode.Enabled() {
		// Not an error: the same configuration is loaded by xproxyctl and
		// by a check on a build host, where the module is not active and
		// the answer would be a false alarm. The daemon refuses at start.
		v.warnf("%s.required: this build does not have the FIPS 140-3 module active, so a daemon reading this "+
			"configuration would refuse to start. Build with GOFIPS140=v1.0.0 and run with GODEBUG=fips140=on", p)
	}
}

// redisNameChar is the alphabet a Redis command name is made of: the upper-case
// letters, the digits, and the two separators a few names use.
func redisNameChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		return true
	}
	return false
}

// mmsListener checks an mms listener's section.
func (v *validator) mmsListener(p string, m *MMSListener, address string) {
	v.anomaly(p+".anomaly", m.Anomaly)
	v.engineering(p+".engineering", m.Engineering)
	if m.Upstream == "" {
		v.errf("%s.upstream: required", p)
	}
	v.modbusCIDRs(p+".allow_clients", m.AllowClients)
	v.modbusCIDRs(p+".deny_clients", m.DenyClients)
	v.mmsIdentity(p, m)
	v.mmsServices(p, m)
	v.mmsNames(p, m)
	v.mmsBounds(p, m)
	v.mmsLearn(p, m)
	v.mmsRules(p, m)
	v.mmsWarnings(p, m, address)
}

// mmsIdentity checks the AP-titles and the qualifiers.
func (v *validator) mmsIdentity(p string, m *MMSListener) {
	for _, f := range []struct {
		name string
		list []string
	}{
		{"ap_titles", m.APTitles},
		{"deny_ap_titles", m.DenyAPTitles},
	} {
		for i, t := range f.list {
			if err := mmsCheckAPTitle(t); err != nil {
				v.errf("%s.%s[%d]: %v", p, f.name, i, err)
			}
		}
	}
	if _, err := numrange.Parse("ae_qualifier", m.AEQualifiers, 65535); err != nil {
		v.errf("%s.ae_qualifiers: %v", p, err)
	}
}

// mmsCheckAPTitle checks an AP-title pattern: dotted arcs, with `*` and `?`
// allowed so that an estate's own numbering can be named by prefix.
//
// It is checked rather than taken as an opaque string because an AP-title that is
// not an object identifier is a rule that can never match, and a rule that can
// never match in an allow list is a listener that refuses everything.
func mmsCheckAPTitle(t string) error {
	if t == "" {
		return errors.New("empty")
	}
	if len(t) > 128 {
		return fmt.Errorf("%d characters, which is longer than any object identifier", len(t))
	}
	for _, arc := range strings.Split(t, ".") {
		if arc == "" {
			return fmt.Errorf("%q has an empty arc", t)
		}
		for _, c := range arc {
			if (c < '0' || c > '9') && c != '*' && c != '?' {
				return fmt.Errorf("%q is not an object identifier or a pattern over one", t)
			}
		}
	}
	return nil
}

// mmsServices checks the service and class lists.
func (v *validator) mmsServices(p string, m *MMSListener) {
	v.mmsServiceList(p+".services", m.Services)
	v.mmsServiceList(p+".deny_services", m.DenyServices)
	v.mmsClassList(p+".service_classes", m.ServiceClasses)
	v.mmsClassList(p+".deny_service_classes", m.DenyServiceClasses)
}

func (v *validator) mmsServiceList(p string, names []string) {
	for i, n := range names {
		if _, ok := mmswire.ServiceOf(n); !ok {
			v.errf("%s[%d]: %q is not an MMS service; the names are in docs/CONFIG.md", p, i, n)
		}
	}
}

// mmsClasses is what a service_classes list may name.
var mmsClasses = map[string]bool{
	"browse": true, "read": true, "write": true, "report": true,
	"dataset": true, "control": true, "domain": true, "file": true,
	"session": true,
}

func (v *validator) mmsClassList(p string, names []string) {
	for i, n := range names {
		if !mmsClasses[n] {
			v.errf("%s[%d]: %q is not a service class; they are browse, read, write, report, dataset, control, domain, file and session",
				p, i, n)
		}
	}
}

// mmsNames checks the domain, object, constraint and file patterns.
func (v *validator) mmsNames(p string, m *MMSListener) {
	for _, f := range []struct {
		name string
		list []string
	}{
		{"domains", m.Domains}, {"deny_domains", m.DenyDomains},
		{"objects", m.Objects}, {"deny_objects", m.DenyObjects},
		{"write_objects", m.WriteObjects},
		{"files", m.Files}, {"deny_files", m.DenyFiles},
	} {
		v.mmsPatterns(p+"."+f.name, f.list)
	}
	v.mmsConstraints(p+".functional_constraints", m.FunctionalConstraints)
	v.mmsConstraints(p+".write_constraints", m.WriteConstraints)
	v.mmsConstraints(p+".deny_constraints", m.DenyConstraints)
}

// mmsPatterns checks a glob list: non-empty, bounded, and not a bare `*`, which
// is the pattern somebody writes meaning "for now" and then leaves.
func (v *validator) mmsPatterns(p string, list []string) {
	for i, g := range list {
		switch {
		case g == "":
			v.errf("%s[%d]: empty", p, i)
		case len(g) > 512:
			v.errf("%s[%d]: %d characters, which is longer than any IEC 61850 name", p, i, len(g))
		case g == "*":
			v.warnf("%s[%d] is `*`, which allows everything and reads as though it did not: leave the list empty instead, which says the same thing where a reviewer will see it",
				p, i)
		}
	}
}

// mmsConstraints checks a functional-constraint list.
func (v *validator) mmsConstraints(p string, list []string) {
	for i, c := range list {
		if !mmswire.FC(c).Known() {
			v.errf("%s[%d]: %q is not an IEC 61850 functional constraint; they are %s",
				p, i, c, strings.Join(sortedStrings(mmswire.FCs()), ", "))
		}
	}
}

// mmsBounds checks the numeric bounds.
func (v *validator) mmsBounds(p string, m *MMSListener) {
	for _, f := range []struct {
		name string
		v    int
		lo   int
		hi   int
	}{
		{"max_names", m.MaxNames, 1, 65536},
		{"max_write_names", m.MaxWriteNames, 1, 65536},
		{"max_frame", m.MaxFrame, 1024, 16 << 20},
		{"max_requests", m.MaxRequests, 1, 1 << 30},
		{"max_pending_requests", m.MaxPendingRequests, 1, 4096},
		{"rate_limit", m.RateLimit, 1, 1 << 20},
		{"rate_burst", m.RateBurst, 1, 1 << 20},
		{"max_sessions", m.MaxSessions, 1, 1 << 20},
		{"max_sessions_per_client", m.MaxSessionsPerClient, 1, 1 << 20},
	} {
		if f.v != 0 && (f.v < f.lo || f.v > f.hi) {
			v.errf("%s.%s: must be between %d and %d", p, f.name, f.lo, f.hi)
		}
	}
	if m.RateBurst != 0 && m.RateLimit == 0 {
		v.errf("%s.rate_burst: set without rate_limit, so nothing is limited", p)
	}
	for _, f := range []struct {
		name string
		d    Duration
	}{
		{"idle_timeout", m.IdleTimeout},
		{"session_duration", m.SessionDuration},
		{"handshake_timeout", m.HandshakeTimeout},
		{"select_timeout", m.SelectTimeout},
	} {
		if f.d < 0 {
			v.errf("%s.%s: must not be negative", p, f.name)
		}
	}
	if m.DefaultAction != "" && m.DefaultAction != "allow" && m.DefaultAction != "deny" {
		v.errf("%s.default_action: %q is not allow or deny", p, m.DefaultAction)
	}
	switch m.DenyResponse {
	case "", "error", "reject", "drop", "close":
	default:
		v.errf("%s.deny_response: %q is not error, reject, drop or close", p, m.DenyResponse)
	}
}

// mmsLearn checks the learning section.
func (v *validator) mmsLearn(p string, m *MMSListener) {
	l := m.Learn
	if l == nil || !l.Enabled {
		return
	}
	switch {
	case l.File == "":
		v.errf("%s.learn.file: required when learning is enabled", p)
	case !strings.HasPrefix(l.File, "/"):
		v.errf("%s.learn.file: must be an absolute path", p)
	}
	if l.Interval != 0 && (l.Interval.D() < 10*time.Second || l.Interval.D() > 24*time.Hour) {
		v.errf("%s.learn.interval: must be between 10s and 24h", p)
	}
	if l.MaxSubjects != 0 && (l.MaxSubjects < 16 || l.MaxSubjects > 1_000_000) {
		v.errf("%s.learn.max_subjects: must be between 16 and 1000000", p)
	}
	if !l.Enforce {
		v.warnf("%s.learn is enabled without enforce, so this listener records and decides nothing: turn enforce on, or take the learning section out, once the rules are written",
			p)
	}
}

// mmsRules checks the rules.
func (v *validator) mmsRules(p string, m *MMSListener) {
	seen := map[string]bool{}
	for i, r := range m.Rules {
		q := fmt.Sprintf("%s.rules[%d]", p, i)
		switch {
		case r.Name == "":
			v.errf("%s.name: required", q)
		case seen[r.Name]:
			v.errf("%s.name: %q is used twice; a rule's name is what a log line and a counter carry", q, r.Name)
		default:
			seen[r.Name] = true
		}
		switch r.Action {
		case "", "allow", "deny", "observe":
		default:
			v.errf("%s.action: %q is not allow, deny or observe", q, r.Action)
		}
		v.modbusCIDRs(q+".clients", r.Clients)
		for j, t := range r.APTitles {
			if err := mmsCheckAPTitle(t); err != nil {
				v.errf("%s.ap_titles[%d]: %v", q, j, err)
			}
		}
		if _, err := numrange.Parse("ae_qualifier", r.AEQualifiers, 65535); err != nil {
			v.errf("%s.ae_qualifiers: %v", q, err)
		}
		v.mmsServiceList(q+".services", r.Services)
		v.mmsServiceList(q+".deny_services", r.DenyServices)
		v.mmsClassList(q+".service_classes", r.ServiceClasses)
		v.mmsClassList(q+".deny_service_classes", r.DenyServiceClasses)
		for _, f := range []struct {
			name string
			list []string
		}{
			{"domains", r.Domains}, {"deny_domains", r.DenyDomains},
			{"objects", r.Objects}, {"deny_objects", r.DenyObjects},
			{"write_objects", r.WriteObjects},
			{"files", r.Files}, {"deny_files", r.DenyFiles},
		} {
			v.mmsPatterns(q+"."+f.name, f.list)
		}
		v.mmsConstraints(q+".functional_constraints", r.FunctionalConstraints)
		v.mmsConstraints(q+".write_constraints", r.WriteConstraints)
		v.mmsConstraints(q+".deny_constraints", r.DenyConstraints)
		if r.MaxNames != 0 && (r.MaxNames < 1 || r.MaxNames > 65536) {
			v.errf("%s.max_names: must be between 1 and 65536", q)
		}
		if r.Schedule != nil {
			v.modbusSchedule(q+".schedule", r.Schedule)
		}
	}
}

// mmsWarnings are the things worth saying about a configuration that is valid.
func (v *validator) mmsWarnings(p string, m *MMSListener, address string) {
	if len(m.AllowClients) == 0 {
		v.warnf("%s.allow_clients is empty, so any address that reaches this listener reaches the substation: name the control centre's and the engineering network's prefixes",
			p)
	}
	if _, port, err := net.SplitHostPort(address); err == nil &&
		port != "102" && port != "0" {
		v.warnf("%s: port %s, where an IEC 61850 client sends to 102 by convention; a client configured from an SCL file will not find it here",
			p, port)
	}
	// The one about the protocol's own authentication, which is the finding an
	// estate most often does not know it has.
	if m.RefusePlaintextPasswords {
		v.warnf("%s.refuse_plaintext_passwords is on, so every association whose ACSE authentication value is a password will be refused. On most of the installed base that password is the only authentication the IED has, and IEC 62351-4 is what replaces it: turn this on once the clients have moved, not before",
			p)
	}
	// Writing to the constraints that decide what the device does in a fault.
	if writes := mmsWriteConstraints(m); len(writes) > 0 {
		var protecting []string
		for _, c := range writes {
			if mmswire.FC(c).Protects() {
				protecting = append(protecting, c)
			}
		}
		if len(protecting) > 0 {
			v.warnf("%s.write_constraints names %s, so a client may change what the device does in a fault rather than what it is doing now -- a setting group is a protection relay's trip characteristic and nothing moves until the fault it was meant to clear. Put those behind a rule with a schedule if they are needed at all",
				p, strings.Join(sortedStrings(protecting), ", "))
		}
	}
	// Operating without the interlock, where the configuration could remove it.
	//
	// Not warned on a listener that is only learning: it decides nothing, and the
	// warning about that is the one worth reading.
	learning := m.Learn != nil && m.Learn.Enabled && !m.Learn.Enforce
	if !learning && mmsAllowsOperate(m) && !m.RequireSelectBeforeOperate {
		v.warnf("%s allows a control operate and require_select_before_operate is off, so an Oper is carried whether or not the client selected first. IEC 61850 leaves that to the IED's ctlModel, and ctlModel lives in $CF$ where a client with configuration access can change it -- requiring the select here puts the interlock somewhere the configuration cannot reach",
			p)
	}
	// The domain services, unless every rule that admits them already has a window
	// on it -- which is what the warning is asking for, so firing it then would be
	// firing it at somebody who did the thing.
	if m.AllowDomainServices && !m.ReadOnly && !mmsDomainScheduled(m) {
		v.warnf("%s.allow_domain_services is on, so a client may download into an IED and replace what is inside it. That is the operation this listener most exists to refuse: put it behind a rule naming the engineering station and a schedule",
			p)
	}
	if len(m.Domains) == 0 && len(m.Objects) == 0 && !m.ReadOnly {
		v.warnf("%s names neither domains nor objects, so every logical device behind this listener is reachable by every client it admits. A learning run writes the lists: see the learn section",
			p)
	}
}

// mmsWriteConstraints is the effective write-constraint list: the listener's own,
// or the default an HMI needs.
func mmsWriteConstraints(m *MMSListener) []string {
	if len(m.WriteConstraints) > 0 {
		return m.WriteConstraints
	}
	return nil
}

// mmsAllowsOperate says the configuration carries a control operate.
//
// It has to read the rules and the default action as well as the lists, because a
// listener whose default is deny and whose rules never admit a write to a control
// constraint does not carry one -- and warning about the interlock there would be
// warning about something that cannot happen.
func mmsAllowsOperate(m *MMSListener) bool {
	if m.ReadOnly {
		return false
	}
	if m.AllowOperate != nil && !*m.AllowOperate {
		return false
	}
	for _, c := range m.DenyConstraints {
		if c == string(mmswire.FCControl) {
			return false
		}
	}
	if m.DefaultAction != "allow" && !mmsRuleWritesControl(m) {
		return false
	}
	if len(m.WriteConstraints) == 0 {
		// The default includes CO.
		return true
	}
	for _, c := range m.WriteConstraints {
		if c == string(mmswire.FCControl) {
			return true
		}
	}
	return false
}

// mmsRuleWritesControl says some allowing rule admits a write to a control
// constraint.
func mmsRuleWritesControl(m *MMSListener) bool {
	for _, r := range m.Rules {
		if r.Action == "deny" || r.Action == "observe" {
			continue
		}
		if r.AllowOperate != nil && !*r.AllowOperate {
			continue
		}
		if mmsHasConstraint(r.DenyConstraints, mmswire.FCControl) {
			continue
		}
		if !mmsRuleCarriesWrite(r) {
			// The rule narrowed to services that cannot address a control object.
			// A control operate is a Write; a rule admitting only the file or
			// domain services carries none, whatever its constraint list says.
			continue
		}
		// A rule with no write-constraint list of its own inherits the listener's,
		// which is where the caller's own check then applies.
		list := r.WriteConstraints
		if len(list) == 0 {
			list = m.WriteConstraints
		}
		if len(list) == 0 || mmsHasConstraint(list, mmswire.FCControl) {
			return true
		}
	}
	return false
}

// mmsRuleCarriesWrite says a rule's own service narrowing lets through a service
// that can address a control object.
//
// That is the Write class and nothing else: a control operate is `XCBR1$CO$Pos$Oper`
// arriving as an MMS Write, so a rule admitting only the file or domain services
// cannot carry one however wide its constraint list is.
func mmsRuleCarriesWrite(r MMSRule) bool {
	if len(r.Services) > 0 {
		for _, n := range r.Services {
			if s, ok := mmswire.ServiceOf(n); ok && s.Class() == mmswire.ClassWrite {
				return true
			}
		}
		return false
	}
	if len(r.ServiceClasses) > 0 {
		for _, c := range r.ServiceClasses {
			if c == "write" {
				return true
			}
		}
		return false
	}
	// No narrowing: the rule inherits the listener's lists.
	return true
}

func mmsHasConstraint(list []string, want mmswire.FC) bool {
	for _, c := range list {
		if c == string(want) {
			return true
		}
	}
	return false
}

// mmsDomainScheduled says every rule that admits the domain services has a time
// window on it, which is what the warning about them asks for.
func mmsDomainScheduled(m *MMSListener) bool {
	found := false
	for _, r := range m.Rules {
		if r.Action == "deny" || r.Action == "observe" {
			continue
		}
		if !mmsRuleAdmitsDomain(r, m) {
			continue
		}
		found = true
		if r.Schedule == nil {
			return false
		}
	}
	return found
}

// mmsRuleAdmitsDomain says a rule's own service narrowing lets a domain service
// through.
func mmsRuleAdmitsDomain(r MMSRule, m *MMSListener) bool {
	for _, c := range r.DenyServiceClasses {
		if c == "domain" {
			return false
		}
	}
	for _, c := range r.ServiceClasses {
		if c == "domain" {
			return true
		}
	}
	for _, n := range r.Services {
		if s, ok := mmswire.ServiceOf(n); ok && s.Class() == mmswire.ClassDomain {
			return true
		}
	}
	if len(r.ServiceClasses) > 0 || len(r.Services) > 0 {
		// The rule narrowed to something else.
		return false
	}
	// A rule that names no services at all inherits the listener's lists, which
	// allow_domain_services has already opened.
	_ = m
	return true
}

// sortedStrings is a sorted copy, so that a validation message reads the same way
// twice.
func sortedStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// coapAsksForAKey says whether the listener's TLS section makes a peer present
// a certificate at all, which is what a pinned public key is read out of.
//
// Any of the three modes that ask for one will do, and require_any is the one
// to write: a raw public key is pinned by the table rather than vouched for by
// an authority, so there is no chain for require-with-client_ca_file to check
// and a self-signed certificate is what a device will send.
func coapAsksForAKey(tc *TLS) bool {
	if tc == nil {
		return false
	}
	switch tc.ClientAuth {
	case "require", "require_any", "verify_if_given":
		return true
	}
	return false
}

// pinsKeys says whether this listener pins peer public keys of its own, which
// is the one place a certificate verified against no authority is a credential
// rather than a hole.
func pinsKeys(ln *Listener) bool {
	return ln != nil && ln.Kind == "coap" && ln.CoAP != nil && len(ln.CoAP.PublicKeys) > 0
}
