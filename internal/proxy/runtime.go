package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"sync/atomic"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/geoip"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/jwt"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/router"
	"github.com/rom/xproxy/internal/shed"
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
	router     *router.Router
	pools      map[string]*upstream.Pool
	rateLimits map[string]*rateLimit
	trusted    []netip.Prefix
	routes     []*compiledRoute
	waf        *waf.Engine
	jwt        map[string]*jwt.Provider
	icap       map[string]*icap.Service
	filters    map[string]*customFilter
	geo        *geoip.DB
	// geoNeeded is set when any route or rate limit consults the country.
	geoNeeded bool
	// events is the generation's event bus (nil in unit tests that build
	// a runtime without a server).
	events *eventBus
}

// customFilter wraps a configured middleware instance with its deny
// counter and defaults the deny reason to the instance name.
type customFilter struct {
	cfg    *config.FilterConfig
	f      filter.Filter
	denied atomic.Uint64
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

// FilterStatus is the management view of one middleware instance.
type FilterStatus struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Stage  string `json:"stage"`
	Routes int    `json:"routes"`
	Denied uint64 `json:"denied"`
}

type rateLimit struct {
	cfg *config.RateLimit
	lim *limits.KeyedLimiter
}

// compiledRoute caches per-route derived data.
type compiledRoute struct {
	cfg          *config.Route
	pool         *upstream.Pool
	honeypotBody []byte
	honeypotType string
	mirror       *mirror
	rateLimits   []*rateLimit
	allow        []netip.Prefix
	deny         []netip.Prefix
	filters      filter.Chain
	wafMode      string
	class        shed.Class
	challenge    *config.RouteChallenge // nil or mode off means no gate
	counts       [5]atomic.Uint64       // 2xx, 3xx, 4xx, 5xx, denied
	geoAllow     map[string]bool
	geoDeny      map[string]bool
	geoUnknown   string
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

func newRuntime(cfg *config.Config, generation uint64, log *slog.Logger, events *eventBus) (*runtime, error) {
	rt := &runtime{
		cfg:        cfg,
		generation: generation,
		router:     router.New(cfg.Routes),
		pools:      make(map[string]*upstream.Pool, len(cfg.Upstreams)),
		rateLimits: make(map[string]*rateLimit, len(cfg.RateLimits)),
		trusted:    netutil.ParsePrefixes(cfg.TrustedProxies),
		routes:     make([]*compiledRoute, len(cfg.Routes)),
		events:     events,
	}
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		p, err := upstream.NewPool(u, log)
		if err != nil {
			rt.stop()
			return nil, err
		}
		rt.pools[u.Name] = p
	}
	for i := range cfg.RateLimits {
		rl := &cfg.RateLimits[i]
		// Bound tracked keys so that a distributed source cannot grow memory
		// without limit: 64 shards * 8192 keys * ~64 bytes ≈ 32 MiB worst case
		// per policy.
		lim := limits.NewKeyedLimiter(rl.Rate, rl.Burst, 8192)
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
	if cfg.ICAP != nil {
		rt.icap = make(map[string]*icap.Service, len(cfg.ICAP.Services))
		for i := range cfg.ICAP.Services {
			sc := cfg.ICAP.Services[i]
			svc, err := icap.NewService(sc)
			if err != nil {
				rt.stop()
				return nil, err
			}
			if !svc.Status().Reachable {
				log.Warn("icap service unreachable at load", "service", sc.Name, "url", sc.URL, "fail", sc.Fail)
			}
			rt.icap[sc.Name] = svc
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
			rt.filters[fc.Name] = &customFilter{cfg: fc, f: f}
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
		}
		engine, err := waf.New(cfg.WAF, need, log)
		if err != nil {
			rt.stop()
			return nil, err
		}
		rt.waf = engine
	}
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		cr := &compiledRoute{
			cfg:   r,
			allow: netutil.ParsePrefixes(r.AllowCIDRs),
			deny:  netutil.ParsePrefixes(r.DenyCIDRs),
			class: shed.ParseClass(r.PriorityClass),
		}
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
			}
		}
		for _, name := range r.RateLimits {
			rl, ok := rt.rateLimits[name]
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("route %s: unknown rate limit %s", r.Name, name)
			}
			cr.rateLimits = append(cr.rateLimits, rl)
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
			cr.filters = append(cr.filters, f)
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
		}
		if err := stage(config.StageAfterScan); err != nil {
			rt.stop()
			return nil, err
		}
		rt.routes[i] = cr
	}
	return rt, nil
}

func (rt *runtime) start() {
	for _, p := range rt.pools {
		p.Start()
	}
	for _, p := range rt.jwt {
		p.Start()
	}
}

// stopChecks ends background probing of a superseded generation; its
// transports keep serving in-flight requests until stop.
func (rt *runtime) stopChecks() {
	for _, p := range rt.pools {
		p.StopChecks()
	}
	for _, p := range rt.jwt {
		p.Stop()
	}
}

func (rt *runtime) stop() {
	for _, p := range rt.pools {
		p.Stop()
	}
	for _, p := range rt.jwt {
		p.Stop()
	}
	for _, s := range rt.icap {
		s.Close()
	}
	for _, cf := range rt.filters {
		if c, ok := cf.f.(filter.Closer); ok {
			_ = c.Close()
		}
	}
}

// filterStatus lists the configured middleware instances.
func (rt *runtime) filterStatus() []FilterStatus {
	out := make([]FilterStatus, 0, len(rt.filters))
	for _, cf := range rt.filters {
		routes := 0
		for _, cr := range rt.routes {
			for _, name := range cr.cfg.Filters {
				if name == cf.cfg.Name {
					routes++
				}
			}
		}
		out = append(out, FilterStatus{Name: cf.cfg.Name, Kind: cf.cfg.Kind, Stage: cf.cfg.Stage, Routes: routes, Denied: cf.denied.Load()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
