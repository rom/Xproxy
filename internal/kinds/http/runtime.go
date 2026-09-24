package http

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/geoip"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/jwt"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/metrics"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/originsig"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/router"
	"github.com/rom/xproxy/internal/secret"
	"github.com/rom/xproxy/internal/securitytxt"
	"github.com/rom/xproxy/internal/shed"
	"github.com/rom/xproxy/internal/tmpl"
	"github.com/rom/xproxy/internal/upstream"
	"github.com/rom/xproxy/internal/waf"
)

// runtime is everything derived from one configuration generation. The
// handler reads the current runtime through an atomic pointer, so a reload
// is a single pointer swap and in-flight requests keep the generation they
// started with.
type runtime struct {
	cfg        *config.Config
	generation uint64
	patches    []*compiledPatch
	// patchBuffersBody is set when any virtual patch matches on a body,
	// which every request on every route then pays for.
	patchBuffersBody bool
	// inFlight counts requests being served by this generation, so a
	// reload can tear it down when the last one ends rather than after
	// a fixed wait.
	inFlight atomic.Int64
	// securityTxt answers /.well-known/security.txt before routing, or
	// is nil when the configuration has no entry.
	securityTxt *securitytxt.Set
	// honeytokens are the planted credentials, checked before routing
	// because a stolen one can be presented anywhere; nil when none are
	// configured.
	honeytokens *honeytokens
	router      *router.Router
	pools       map[string]*upstream.Pool
	rateLimits  map[string]*rateLimit
	trusted     []netip.Prefix
	routes      []*compiledRoute
	waf         *waf.Engine
	// signers sign forwarded requests per upstream (origin_signature).
	signers     map[string]*originsig.Signer
	jwt         map[string]*jwt.Provider
	maintenance *compiledMaintenance
	accessLog   accessLogPolicy
	icap        map[string]*icap.Service
	filters     map[string]*customFilter
	geo         *geoip.DB
	// geoNeeded is set when any route or rate limit consults the country.
	geoNeeded bool
	// events is the generation's event bus (nil in unit tests that build
	// a runtime without a server).
	events *eventBus
	// errorPages are the server level pages, nil when not configured.
	errorPages *errorPages
}

// customFilter wraps a configured middleware instance with its deny
// counter and defaults the deny reason to the instance name.
type customFilter struct {
	cfg *config.FilterConfig
	f   filter.Filter
	// buffersBody is the kind's declaration that it may hold a whole
	// request body; see bodybudget.
	buffersBody bool
	denied      atomic.Uint64
}

func (c *customFilter) Name() string { return c.cfg.Name }

func (c *customFilter) Begin(ctx context.Context, info *filter.Info) filter.Instance {
	in := c.f.Begin(ctx, info)
	if in == nil {
		return nil
	}
	return &customInstance{c: c, in: in}
}

type customInstance struct {
	c  *customFilter
	in filter.Instance
}

func (ci *customInstance) fix(v filter.Verdict) filter.Verdict {
	if v.Deny {
		ci.c.denied.Add(1)
		if v.Reason == "" {
			v.Reason = ci.c.cfg.Name
		}
		if v.Status < 400 || v.Status > 599 {
			v.Status = 403
		}
	}
	return v
}

func (ci *customInstance) Request(r *http.Request) filter.Verdict   { return ci.fix(ci.in.Request(r)) }
func (ci *customInstance) Response(r *http.Response) filter.Verdict { return ci.fix(ci.in.Response(r)) }
func (ci *customInstance) End() []any                               { return ci.in.End() }

type rateLimit struct {
	cfg *config.RateLimit
	lim *limits.KeyedLimiter
	// allowed and denied count decisions for quota reporting.
	allowed, denied atomic.Uint64
}

// compiledRoute caches per-route derived data.
type compiledRoute struct {
	cfg          *config.Route
	pool         *upstream.Pool
	honeypotBody []byte
	honeypotType string
	// deceive answers clients this route no longer trusts with
	// something plausible instead of the origin's answer.
	deceive *deceivePolicy
	// wsGuard inspects the frames of an upgraded connection on this
	// route; nil leaves the upgrade an opaque tunnel.
	wsGuard  *wsGuard
	static   *staticSite
	compress *compressPolicy
	// compressAuth allows compressing a response to a request that
	// carried Authorization or Cookie; see BREACH in the configuration
	// reference.
	compressAuth bool
	// buffersBody is set when anything on this route may hold the whole
	// request body in memory: a filter that declares it, the WAF's body
	// inspection, ICAP, a virtual patch or policy body pattern, or a
	// mirror. Such a request charges the process-wide body budget for
	// its life.
	buffersBody bool
	cors        *compiledCORS
	idleTimeout time.Duration
	mirror      *mirror
	rateLimits  []*rateLimit
	// identityLimits key on the verified identity and so run after the
	// filter chain; the others run before it.
	identityLimits []*rateLimit
	allow          []netip.Prefix
	deny           []netip.Prefix
	filters        filter.Chain
	wafMode        string
	// Templated header operations, regex rewrite, redirect target and
	// error pages (nil without a route section).
	reqOps, respOps compiledOps
	rewriteRE       *regexp.Regexp
	pathREs         []*regexp.Regexp
	rewriteTo       *tmpl.Template
	redirectTo      *tmpl.Template
	errPages        *errorPages
	class           shed.Class
	// lowerByClient honours a client's RFC 9218 urgency, downwards only.
	lowerByClient bool
	// stripEarlyHints drops the upstream's 1xx informational responses
	// instead of relaying them.
	stripEarlyHints bool
	// earlyData is what to do with a request that arrived as unconfirmed
	// TLS early data.
	earlyData string
	// stripTrailers drops the response's trailers instead of relaying
	// them.
	stripTrailers bool
	// ranges is the byte range policy, nil when the route has none.
	ranges *rangePolicy
	// intel is false on a route exempted from the imported threat
	// intelligence lists.
	intel        bool
	challenge    *config.RouteChallenge // nil or mode off means no gate
	counts       [5]atomic.Uint64       // 2xx, 3xx, 4xx, 5xx, denied
	hist         *metrics.Histogram     // request duration per route
	bytesIn      atomic.Uint64
	bytesOut     atomic.Uint64
	rateLimited  atomic.Uint64
	geoAllow     map[string]bool
	geoDeny      map[string]bool
	geoUnknown   string
	policy       *compiledPolicy
	policyDenied atomic.Uint64
	// inventory marks a route whose requests feed the API inventory;
	// describers are its OpenAPI filters.
	inventory  bool
	describers []apiinv.Describer
}

// inventoryRoute reports whether the inventory's host and route
// selectors admit a route.
func inventoryRoute(inv *config.APIInventory, r *config.Route) bool {
	if len(inv.Routes) > 0 {
		found := false
		for _, n := range inv.Routes {
			if n == r.Name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(inv.Hosts) > 0 {
		if len(r.Hosts) == 0 {
			return false
		}
		for _, h := range r.Hosts {
			for _, p := range inv.Hosts {
				if hostMatches(p, h) || p == h {
					return true
				}
			}
		}
		return false
	}
	return true
}

// geoAllowed applies the route's country policy.
func (cr *compiledRoute) geoAllowed(country string) bool {
	if cr.geoAllow == nil && cr.geoDeny == nil {
		return true
	}
	if country == "" {
		return cr.geoUnknown != "deny"
	}
	if cr.geoDeny[country] {
		return false
	}
	if len(cr.geoAllow) > 0 && !cr.geoAllow[country] {
		return false
	}
	return true
}

// wafSelection returns the WAF profile and mode for a route.
func wafSelection(cfg *config.Config, r *config.Route) (profile string, mode waf.Mode) {
	if cfg.WAF == nil {
		return "", waf.ModeOff
	}
	if r.WAF != nil {
		return r.WAF.Profile, waf.Mode(r.WAF.Mode)
	}
	return cfg.WAF.DefaultProfile, waf.Mode(cfg.WAF.DefaultMode)
}

func newRuntime(cfg *config.Config, generation uint64, pools map[string]*upstream.Pool, trusted []netip.Prefix,
	services map[string]*icap.Service,
	log *slog.Logger, events *eventBus, wafStats *waf.Stats,
	patches *patchCounters, tokens *honeytokenCounters) (*runtime, error) {
	rt := &runtime{
		cfg:        cfg,
		generation: generation,
		icap:       services,
		patches:    compilePatches(cfg.VirtualPatches, patches),
		router:     router.New(cfg.Routes),
		pools:      pools,
		rateLimits: make(map[string]*rateLimit, len(cfg.RateLimits)),
		trusted:    trusted,
		routes:     make([]*compiledRoute, len(cfg.Routes)),
		events:     events,
	}

	for _, vp := range rt.patches {
		if vp.bodyRE != nil {
			rt.patchBuffersBody = true
			break
		}
	}
	if len(cfg.SecurityTxt) > 0 {
		set, err := securityTxtSet(cfg)
		if err != nil {
			rt.stop()
			return nil, err
		}
		rt.securityTxt = set
	}
	if len(cfg.Honeytokens) > 0 {
		ht, err := newHoneytokens(cfg.Honeytokens, tokens)
		if err != nil {
			rt.stop()
			return nil, err
		}
		rt.honeytokens = ht
	}
	if cfg.Maintenance != nil {
		rt.maintenance = newMaintenance(cfg.Maintenance)
	}
	rt.accessLog = newAccessLogPolicy(cfg.Logging.Access)
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		if os := u.OriginSignature; os != nil {
			ring, err := secret.LoadOrCreate(os.SecretFile)
			if err != nil {
				rt.stop()
				return nil, fmt.Errorf("upstream %s: origin signature secret: %w", u.Name, err)
			}
			signer, err := originsig.New(os.Header, os.Include, ring.All())
			if err != nil {
				rt.stop()
				return nil, fmt.Errorf("upstream %s: %w", u.Name, err)
			}
			signer.Digest = os.BodyDigest
			if rt.signers == nil {
				rt.signers = map[string]*originsig.Signer{}
			}
			rt.signers[u.Name] = signer
		}
	}
	for i := range cfg.RateLimits {
		rl := &cfg.RateLimits[i]
		// Bound tracked keys so that a distributed source cannot grow memory
		// without limit: 64 shards * 8192 keys * ~64 bytes ≈ 32 MiB worst case
		// per policy.
		var lim *limits.KeyedLimiter
		if rl.Algorithm == "sliding_window" {
			lim = limits.NewWindowLimiter(float64(rl.Limit), rl.Window.D(), 8192)
		} else {
			lim = limits.NewKeyedLimiter(rl.Rate, rl.Burst, 8192)
		}
		if cfg.Cluster != nil && cfg.Cluster.SharesRateLimits() {
			lim.SetPeerStale(cfg.Cluster.PeerStale.D())
		}
		rt.rateLimits[rl.Name] = &rateLimit{cfg: rl, lim: lim}
	}
	if cfg.JWT != nil {
		rt.jwt = make(map[string]*jwt.Provider, len(cfg.JWT.Providers))
		for i := range cfg.JWT.Providers {
			pc := cfg.JWT.Providers[i]
			p, err := jwt.NewProvider(pc, log)
			if err != nil {
				rt.stop()
				return nil, err
			}
			rt.jwt[pc.Name] = p
		}
	}
	if cfg.GeoIP != nil {
		db, err := geoip.Open(cfg.GeoIP)
		if err != nil {
			rt.stop()
			return nil, fmt.Errorf("geoip: %w", err)
		}
		rt.geo = db
		for i := range cfg.Routes {
			if cfg.Routes[i].Geo != nil {
				rt.geoNeeded = true
			}
		}
		for i := range cfg.RateLimits {
			if cfg.RateLimits[i].Key == "country" {
				rt.geoNeeded = true
			}
		}
	}
	if len(cfg.Filters) > 0 {
		rt.filters = make(map[string]*customFilter, len(cfg.Filters))
		for i := range cfg.Filters {
			fc := &cfg.Filters[i]
			k, ok := filter.Lookup(fc.Kind)
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("filter %s: %w %q", fc.Name, filter.ErrUnknownKind, fc.Kind)
			}
			env := filter.Env{Log: log.With("filter", fc.Name, "kind", fc.Kind)}
			if events != nil {
				env.Events = events
			}
			f, err := k.New(fc.Name, filter.Options(fc.Options), env)
			if err != nil {
				rt.stop()
				return nil, fmt.Errorf("filter %s: %w", fc.Name, err)
			}
			rt.filters[fc.Name] = &customFilter{cfg: fc, f: f, buffersBody: k.BuffersBody}
		}
	}
	if cfg.WAF != nil {
		need := waf.Need{}
		for i := range cfg.Routes {
			p, m := wafSelection(cfg, &cfg.Routes[i])
			if m == waf.ModeOff {
				continue
			}
			if need[p] == nil {
				need[p] = map[waf.Mode]bool{}
			}
			need[p][m] = true
			if cfg.Routes[i].WAF.Gradual() {
				need[p][waf.ModeDetect] = true
			}
		}
		engine, err := waf.New(cfg.WAF, need, wafStats, log)
		if err != nil {
			rt.stop()
			return nil, err
		}
		rt.waf = engine
	}
	var compressPol *compressPolicy
	if cfg.Compression.Enable() {
		compressPol = newCompressPolicy(cfg.Compression)
	}
	if ep, err := loadErrorPages(cfg.Server.ErrorPages); err != nil {
		rt.stop()
		return nil, fmt.Errorf("server.%w", err)
	} else {
		rt.errorPages = ep
	}
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		cr := &compiledRoute{
			cfg:   r,
			hist:  metrics.NewHistogram(metrics.DurationBuckets),
			allow: netutil.ParsePrefixes(r.AllowCIDRs),
			deny:  netutil.ParsePrefixes(r.DenyCIDRs),
			class: shed.ParseClass(r.PriorityClass), lowerByClient: r.ClientPriority == "lower",
			stripEarlyHints: r.EarlyHints == "strip", earlyData: r.EarlyData, stripTrailers: r.Trailers == "strip",
			ranges: compileRangePolicy(r.Ranges),
			intel:  r.ThreatIntel == nil || *r.ThreatIntel,
		}
		cr.policy = compilePolicy(r.Policy)

		if r.Challenge != nil && r.Challenge.Mode != "off" && cfg.Challenge != nil {
			cr.challenge = r.Challenge
		}
		if g := r.Geo; g != nil {
			cr.geoUnknown = g.Unknown
			if len(g.Allow) > 0 {
				cr.geoAllow = make(map[string]bool, len(g.Allow))
				for _, cc := range g.Allow {
					cr.geoAllow[cc] = true
				}
			}
			if len(g.Deny) > 0 {
				cr.geoDeny = make(map[string]bool, len(g.Deny))
				for _, cc := range g.Deny {
					cr.geoDeny[cc] = true
				}
			}
		}
		if d := r.Deceive; d != nil {
			pol, err := newDeceivePolicy(d)
			if err != nil {
				rt.stop()
				return nil, fmt.Errorf("route %s: deceive: %w", r.Name, err)
			}
			cr.deceive = pol
		}
		if wg := r.WebSocketGuard; wg != nil {
			g, err := newWSGuard(wg)
			if err != nil {
				rt.stop()
				return nil, fmt.Errorf("route %s: websocket_guard: %w", r.Name, err)
			}
			cr.wsGuard = g
		}
		if hp := r.Honeypot; hp != nil {
			cr.honeypotType = hp.ContentType
			switch {
			case hp.Decoy != "":
				d := decoys[hp.Decoy]
				cr.honeypotBody, cr.honeypotType = []byte(d.body), d.contentType
			case hp.BodyFile != "":
				b, err := readBounded(hp.BodyFile, 1<<20)
				if err != nil {
					rt.stop()
					return nil, fmt.Errorf("route %s: honeypot body_file: %w", r.Name, err)
				}
				cr.honeypotBody = b
			default:
				cr.honeypotBody = []byte(hp.Body)
			}
		}
		if on := cfg.Compression.Enable(); on && (r.Compress == nil || *r.Compress) {
			cr.compress = compressPol
			cr.compressAuth = cfg.Compression.CompressesAuthenticated()
			if r.CompressAuthenticated != nil {
				cr.compressAuth = *r.CompressAuthenticated
			}
		}
		if r.CORS != nil {
			cr.cors = newCORS(r.CORS)
		}
		cr.idleTimeout = r.IdleTimeout().D()
		if r.Static != nil {
			ss, err := openStatic(r.Static)
			if err != nil {
				rt.stop()
				return nil, fmt.Errorf("route %s: static root: %w", r.Name, err)
			}
			cr.static = ss
		}
		if r.Upstream != "" {
			p, ok := rt.pools[r.Upstream]
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("route %s: unknown upstream %s", r.Name, r.Upstream)
			}
			cr.pool = p
			if mc := r.Mirror; mc != nil {
				mp, ok := rt.pools[mc.Upstream]
				if !ok {
					rt.stop()
					return nil, fmt.Errorf("route %s: unknown mirror upstream %s", r.Name, mc.Upstream)
				}
				cr.mirror = newMirror(mc, mp)
				cr.buffersBody = true
			}
		}
		for _, name := range r.RateLimits {
			rl, ok := rt.rateLimits[name]
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("route %s: unknown rate limit %s", r.Name, name)
			}
			if rl.cfg.IdentityKeyed() {
				cr.identityLimits = append(cr.identityLimits, rl)
			} else {
				cr.rateLimits = append(cr.rateLimits, rl)
			}
		}
		// Chain order: before_auth, JWT, after_auth, WAF, after_waf, ICAP,
		// after_scan; custom filters keep their listed order within a stage.
		stage := func(name string) error {
			for _, fname := range r.Filters {
				cf, ok := rt.filters[fname]
				if !ok {
					return fmt.Errorf("route %s: unknown filter %s", r.Name, fname)
				}
				if cf.cfg.Stage == name {
					cr.filters = append(cr.filters, cf)
					cr.buffersBody = cr.buffersBody || cf.buffersBody
				}
			}
			return nil
		}
		if err := stage(config.StageBeforeAuth); err != nil {
			rt.stop()
			return nil, err
		}
		if r.JWT != nil {
			p, ok := rt.jwt[r.JWT.Provider]
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("route %s: unknown jwt provider %s", r.Name, r.JWT.Provider)
			}
			cr.filters = append(cr.filters, p.Filter(r.JWT.IsRequired()))
		}
		if err := stage(config.StageAfterAuth); err != nil {
			rt.stop()
			return nil, err
		}
		if p, m := wafSelection(cfg, r); m != waf.ModeOff {
			f, err := rt.waf.Filter(p, m)
			if err != nil {
				rt.stop()
				return nil, fmt.Errorf("route %s: %w", r.Name, err)
			}
			if r.WAF.Gradual() {
				detect, err := rt.waf.Filter(p, waf.ModeDetect)
				if err != nil {
					rt.stop()
					return nil, fmt.Errorf("route %s: %w", r.Name, err)
				}
				f = newSplitWAF(f, detect, r.WAF)
			}
			cr.filters = append(cr.filters, f)
			cr.buffersBody = true
			cr.wafMode = string(m)
		}
		if err := stage(config.StageAfterWAF); err != nil {
			rt.stop()
			return nil, err
		}
		if r.ICAP != nil {
			svc, ok := rt.icap[r.ICAP.Service]
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("route %s: unknown icap service %s", r.Name, r.ICAP.Service)
			}
			cr.filters = append(cr.filters, svc.Filter(r.ICAP))
			cr.buffersBody = true
		}
		if err := stage(config.StageAfterScan); err != nil {
			rt.stop()
			return nil, err
		}
		if inv := cfg.APIInventory; inv.IsEnabled() && r.Upstream != "" && inventoryRoute(inv, r) {
			cr.inventory = true
			for _, f := range cr.filters {
				if c, ok := f.(*customFilter); ok {
					if d, ok := c.f.(apiinv.Describer); ok {
						cr.describers = append(cr.describers, d)
					}
				}
			}
		}
		if err := cr.compileTemplates(); err != nil {
			rt.stop()
			return nil, fmt.Errorf("route %s: %w", r.Name, err)
		}
		rt.routes[i] = cr
	}
	return rt, nil
}

// captureFrom records the groups of the first path_regex that matches
// the request path, for templates; rewrite_regex captures replace them
// when the outbound path is built.
func (cr *compiledRoute) captureFrom(st *reqState) {
	for _, re := range cr.pathREs {
		if m := re.FindStringSubmatch(st.path); m != nil {
			st.captures, st.captureNames = m, re.SubexpNames()
			return
		}
	}
}

// compileTemplates parses the route's header templates, regex rewrite,
// redirect target and error pages.
func (cr *compiledRoute) compileTemplates() error {
	r := cr.cfg
	var captures []string
	if rr := r.RewriteRegex; rr != nil {
		re, err := regexp.Compile(rr.Pattern)
		if err != nil {
			return fmt.Errorf("rewrite_regex: %w", err)
		}
		cr.rewriteRE = re
		captures = append(captures, re.SubexpNames()...)
		t, err := tmpl.Parse(rr.Replace, re.SubexpNames()...)
		if err != nil {
			return fmt.Errorf("rewrite_regex.replace: %w", err)
		}
		cr.rewriteTo = t
	}
	for _, p := range r.PathRegex {
		if re, err := regexp.Compile(p); err == nil {
			captures = append(captures, re.SubexpNames()...)
			cr.pathREs = append(cr.pathREs, re)
		}
	}
	var err error
	if cr.reqOps, err = compileOps(r.RequestHeaders, captures); err != nil {
		return fmt.Errorf("request_headers: %w", err)
	}
	if cr.respOps, err = compileOps(r.ResponseHeaders, captures); err != nil {
		return fmt.Errorf("response_headers: %w", err)
	}
	if r.Redirect != nil {
		if cr.redirectTo, err = tmpl.Parse(r.Redirect.To, captures...); err != nil {
			return fmt.Errorf("redirect.to: %w", err)
		}
	}
	if cr.errPages, err = loadErrorPages(r.ErrorPages); err != nil {
		return err
	}
	return nil
}

func (rt *runtime) start() {
	for _, p := range rt.jwt {
		p.Start()
	}
}

// stopChecks ends background probing of a superseded generation; its
// transports keep serving in-flight requests until stop.
func (rt *runtime) stopChecks() {
	for _, p := range rt.jwt {
		p.Stop()
	}
}

// stop releases the generation once its requests have drained (or the
// hard cap passed).
func (rt *runtime) stop() {
	for _, p := range rt.jwt {
		p.Stop()
	}
	for _, cf := range rt.filters {
		if c, ok := cf.f.(filter.Closer); ok {
			_ = c.Close()
		}
	}
	for _, cr := range rt.routes {
		if cr != nil { // a failed build leaves later slots empty
			cr.static.close()
		}
	}
}

// filterStatus lists the configured middleware instances.
func (rt *runtime) filterStatus() []proxy.FilterStatus {
	out := make([]proxy.FilterStatus, 0, len(rt.filters))
	for _, cf := range rt.filters {
		routes := 0
		for _, cr := range rt.routes {
			for _, name := range cr.cfg.Filters {
				if name == cf.cfg.Name {
					routes++
				}
			}
		}
		out = append(out, proxy.FilterStatus{Name: cf.cfg.Name, Kind: cf.cfg.Kind, Stage: cf.cfg.Stage, Routes: routes, Denied: cf.denied.Load()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// securityTxtSet compiles the virtual security.txt entries, reading a
// body_file so a reload picks up an edited or re-signed document.
func securityTxtSet(cfg *config.Config) (*securitytxt.Set, error) {
	entries := make([]config.SecurityTxt, len(cfg.SecurityTxt))
	copy(entries, cfg.SecurityTxt)
	for i := range entries {
		if entries[i].BodyFile == "" {
			continue
		}
		b, err := readBounded(entries[i].BodyFile, 64<<10)
		if err != nil {
			return nil, fmt.Errorf("security_txt[%d] body_file: %w", i, err)
		}
		entries[i].Body, entries[i].BodyFile = string(b), ""
	}
	return securitytxt.New(entries, time.Now())
}
