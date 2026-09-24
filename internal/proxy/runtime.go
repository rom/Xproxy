package proxy

import (
	"log/slog"
	"net/netip"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/upstream"
)

// runtime is what the engine derives from one configuration generation
// and shares with every listener kind: the upstream pools, the prefixes
// whose forwarding headers are believed, and the scanning services.
//
// The ICAP services are here rather than in the data plane because the
// kinds that hand files to a scanner are not all in the same daemon as
// the plane: ftp is in xrelay and sftp in xgate, and neither links an
// http data plane at all. One list in the configuration, one service
// per name, whichever daemon reads it.
//
// It is deliberately small. Everything else a generation holds — the
// routes, the filters, the rule sets — belongs to the data plane that
// compiles it, and a reload swaps both under one lock (see Plane).
type runtime struct {
	cfg        *config.Config
	generation uint64
	pools      map[string]*upstream.Pool
	trusted    []netip.Prefix
	icap       map[string]*icap.Service
}

// newRuntime opens this generation's pools. A pool that cannot be built
// fails the generation, so a bad upstream never reaches the swap.
func newRuntime(cfg *config.Config, generation uint64, log *slog.Logger, drains *upstream.Drains) (*runtime, error) {
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
		// The pool follows the operator decisions this process holds,
		// which outlive a configuration generation: somebody who drained
		// a machine to patch it did not mean "until the next reload".
		if drains != nil {
			p.UseDrains(drains)
		}
		rt.pools[u.Name] = p
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
	for _, s := range rt.icap {
		s.Close()
	}
}
