package proxy

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
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
}

type rateLimit struct {
	cfg *config.RateLimit
	lim *limits.KeyedLimiter
}

// compiledRoute caches per-route derived data.
type compiledRoute struct {
	cfg        *config.Route
	pool       *upstream.Pool
	rateLimits []*rateLimit
	allow      []netip.Prefix
	deny       []netip.Prefix
	filters    filter.Chain
	wafMode    string
	class      shed.Class
	challenge  *config.RouteChallenge // nil or mode off means no gate
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

func newRuntime(cfg *config.Config, generation uint64, log *slog.Logger) (*runtime, error) {
	rt := &runtime{
		cfg:        cfg,
		generation: generation,
		router:     router.New(cfg.Routes),
		pools:      make(map[string]*upstream.Pool, len(cfg.Upstreams)),
		rateLimits: make(map[string]*rateLimit, len(cfg.RateLimits)),
		trusted:    netutil.ParsePrefixes(cfg.TrustedProxies),
		routes:     make([]*compiledRoute, len(cfg.Routes)),
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
		if r.Upstream != "" {
			p, ok := rt.pools[r.Upstream]
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("route %s: unknown upstream %s", r.Name, r.Upstream)
			}
			cr.pool = p
		}
		for _, name := range r.RateLimits {
			rl, ok := rt.rateLimits[name]
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("route %s: unknown rate limit %s", r.Name, name)
			}
			cr.rateLimits = append(cr.rateLimits, rl)
		}
		if r.JWT != nil {
			p, ok := rt.jwt[r.JWT.Provider]
			if !ok {
				rt.stop()
				return nil, fmt.Errorf("route %s: unknown jwt provider %s", r.Name, r.JWT.Provider)
			}
			cr.filters = append(cr.filters, p.Filter(r.JWT.IsRequired()))
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

func (rt *runtime) stop() {
	for _, p := range rt.pools {
		p.Stop()
	}
	for _, p := range rt.jwt {
		p.Stop()
	}
}
