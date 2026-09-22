package proxy

import (
	"log/slog"
	"net/netip"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/upstream"
)

// runtime is what the engine derives from one configuration generation
// and shares with every listener kind: the upstream pools and the
// prefixes whose forwarding headers are believed.
//
// It is deliberately small. Everything else a generation holds — the
// routes, the filters, the rule sets — belongs to the data plane that
// compiles it, and a reload swaps both under one lock (see Plane).
type runtime struct {
	cfg        *config.Config
	generation uint64
	pools      map[string]*upstream.Pool
	trusted    []netip.Prefix
}

// newRuntime opens this generation's pools. A pool that cannot be built
// fails the generation, so a bad upstream never reaches the swap.
func newRuntime(cfg *config.Config, generation uint64, log *slog.Logger) (*runtime, error) {
	rt := &runtime{
		cfg:        cfg,
		generation: generation,
		pools:      make(map[string]*upstream.Pool, len(cfg.Upstreams)),
		trusted:    netutil.ParsePrefixes(cfg.TrustedProxies),
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
	return rt, nil
}

// start begins health checking.
func (rt *runtime) start() {
	for _, p := range rt.pools {
		p.Start()
	}
}

// stopChecks ends background probing of a superseded generation; its
// transports keep serving in-flight requests until stop.
func (rt *runtime) stopChecks() {
	for _, p := range rt.pools {
		p.StopChecks()
	}
}

// stop releases the generation once its requests have drained.
func (rt *runtime) stop() {
	for _, p := range rt.pools {
		p.Close()
	}
}
