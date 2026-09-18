package proxy

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/router"
	"github.com/rom/xproxy/internal/upstream"
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
		rt.rateLimits[rl.Name] = &rateLimit{cfg: rl, lim: limits.NewKeyedLimiter(rl.Rate, rl.Burst, 8192)}
	}
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		cr := &compiledRoute{
			cfg:   r,
			allow: netutil.ParsePrefixes(r.AllowCIDRs),
			deny:  netutil.ParsePrefixes(r.DenyCIDRs),
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
		rt.routes[i] = cr
	}
	return rt, nil
}

func (rt *runtime) start() {
	for _, p := range rt.pools {
		p.Start()
	}
}

func (rt *runtime) stop() {
	for _, p := range rt.pools {
		p.Stop()
	}
}
