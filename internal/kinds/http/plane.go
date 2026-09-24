package http

import (
	"context"
	"fmt"
	"time"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/challenge"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/shed"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/waf"
)

func init() { proxy.RegisterPlane(newEngine) }

// newEngine builds the process's HTTP data plane. The engine calls it
// once, before the first listener is bound and after the first
// generation's pools exist, so host already answers Limits.
func newEngine(host proxy.Host) (proxy.Plane, error) {
	lim := host.Limits()
	s := &engine{
		host:         host,
		logs:         host.Logs(),
		stats:        host.Counters(),
		fingerprints: host.Fingerprints(),
		concurrency:  limits.NewConcurrency(lim.MaxConcurrentRequests),
		h3Headers:    limits.NewConcurrency(lim.MaxConcurrentRequests),
		tarpits:      limits.NewConcurrency(lim.MaxTarpits),
		marks:        newMarks(),
		wafStats:     waf.NewStats(),
		inventory:    apiinv.New(),
	}
	return s, nil
}

// Prepare compiles a generation. Everything that can fail is done here:
// the routes, the filters and the rule sets, a challenge secret that has
// to be readable before a route in mode always is served, and a tracing
// exporter that moved. Nothing the running data plane reads is touched
// until commit.
func (s *engine) Prepare(g proxy.Generation) (commit, discard func(), err error) {
	cfg := g.Config
	old := s.rt.Load()
	rt, err := newRuntime(cfg, g.Number, g.Pools, g.Trusted, g.ICAP, s.logs.Error,
		newEventBus(s), s.wafStats, &s.patches, &s.honeytokenHits)
	if err != nil {
		return nil, nil, err
	}
	s.inventory.Configure(inventoryConfig(cfg), s.logs.Error)
	// A challenge section that appears on this reload needs its key
	// before the swap: routes in mode always would otherwise serve
	// unchallenged until the next reload if the secret file were
	// unreadable (fail open).
	var fresh *challenge.Challenger
	if cfg.Challenge != nil && s.challenger.Load() == nil {
		nc, err := challenge.New(cfg.Challenge)
		if err != nil {
			rt.stop()
			return nil, nil, fmt.Errorf("challenge: %w", err)
		}
		fresh = nc
	}
	// Tracing is rebuilt when its section changed, so a reload can move
	// the collector or the sampling share. A first generation has no
	// previous section to compare with.
	var tracer *tracing.Tracer
	retrace := old == nil || !sameTracing(old.cfg.Tracing, cfg.Tracing)
	if retrace && cfg.Tracing.IsEnabled() {
		tr, err := newTracer(cfg.Tracing, s.logs.Error)
		switch {
		case err == nil:
			tracer = tr
		case old == nil:
			// At start a tracing section that cannot be built is a
			// configuration error, and the operator is watching.
			rt.stop()
			return nil, nil, fmt.Errorf("tracing: %w", err)
		default:
			// On a reload it is not worth refusing the configuration
			// over: the spans stop, the proxying does not.
			s.logs.Error.Error("tracing exporter unavailable", "err", err.Error())
		}
	}
	commit = func() {
		rt.start()
		s.degradation.Store(newDegradation(cfg.Degradation))
		switch ch := s.challenger.Load(); {
		case cfg.Challenge != nil && ch != nil:
			ch.Reconfigure(cfg.Challenge)
			ch.SetRouteHosts(routeHosts(cfg))
		case cfg.Challenge != nil:
			fresh.SetRouteHosts(routeHosts(cfg)) // built above; nil never reaches here
			s.challenger.Store(fresh)
		case ch != nil:
			s.challenger.Store(nil)
		}
		switch sh := s.shedder.Load(); {
		case cfg.Shedding != nil && sh != nil:
			sh.Reconfigure(cfg.Shedding, cfg.Server.Limits.MaxConcurrentRequests)
		case cfg.Shedding != nil:
			s.shedder.Store(shed.New(cfg.Shedding, s.concurrency.InFlight, cfg.Server.Limits.MaxConcurrentRequests))
		case sh != nil:
			s.shedder.Store(nil)
		}
		switch c := s.cache.Load(); {
		case cfg.Cache != nil && c != nil:
			c.Resize(cfg.Cache.MaxBytes, cfg.Cache.MaxObjectBytes)
		case cfg.Cache != nil:
			s.cache.Store(cache.New(cfg.Cache.MaxBytes, cfg.Cache.MaxObjectBytes))
		case c != nil:
			s.cache.Store(nil)
		}
		if retrace {
			if prev := s.tracer.Swap(tracer); prev != nil {
				go prev.Stop()
			}
		}
		s.traceRedactIP.Store(cfg.Tracing.RedactsClientAddress())
		s.bodyBudget.SetLimit(cfg.Server.Limits.MaxBufferedBodyBytes)
		// The concurrency and tarpit gates are sized here rather than at
		// start, so a reload that changed either setting takes effect
		// without a restart.
		s.concurrency.Resize(cfg.Server.Limits.MaxConcurrentRequests)
		s.h3Headers.Resize(cfg.Server.Limits.MaxConcurrentRequests)
		s.tarpits.Resize(cfg.Server.Limits.MaxTarpits)
		if old == nil && cfg.Maintenance != nil {
			s.maintenance.Store(cfg.Maintenance.Enabled)
		}
		s.rt.Store(rt)
		if old != nil {
			go s.retire(old, cfg.Server.ShutdownTimeout.D(), g.Retire)
		}
	}
	discard = func() {
		rt.stop()
		if tracer != nil {
			go tracer.Stop()
		}
	}
	return commit, discard, nil
}

// retire tears a superseded generation down when its last request ends,
// not after a fixed wait: an exchange older than shutdown_timeout — a
// long upload, a gRPC or SSE stream — was otherwise cut or answered
// 500 although it was still making progress. The hard cap bounds one
// that never ends. release hands the generation's upstream pools back
// to the engine, which cannot see the requests still on them.
func (s *engine) retire(old *runtime, drain time.Duration, release func()) {
	old.stopChecks()
	time.Sleep(drain)
	hard := max(10*drain, 5*time.Minute)
	deadline := time.Now().Add(hard - drain)
	for old.inFlight.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if n := old.inFlight.Load(); n > 0 {
		s.logs.Error.Warn("previous configuration generation torn down with requests still in flight",
			"generation", old.generation, "in_flight", n, "after", hard.String())
	}
	old.stop()
	if release != nil {
		release()
	}
}

// Start is where a plane would begin serving. This one has nothing to
// do: the generation's background work — the health checks, the JWT key
// refresh — started with commit, because a listener bound before Start
// must already have a generation to serve from.
func (s *engine) Start() {}

// Stop releases the live generation. The listeners are already drained
// by the time the engine calls it, so what is left is the state that
// outlives them.
func (s *engine) Stop(_ context.Context) {
	if rt := s.rt.Load(); rt != nil {
		rt.stopChecks()
		rt.stop()
	}
	s.inventory.Stop()
	if tr := s.tracer.Load(); tr != nil {
		tr.Stop()
	}
}

// inventoryConfig maps the configuration section to the table's setting.
func inventoryConfig(cfg *config.Config) apiinv.Config {
	a := cfg.APIInventory
	if !a.IsEnabled() {
		return apiinv.Config{}
	}
	return apiinv.Config{Enabled: true, MaxEndpoints: a.MaxEndpoints, ZombieAfter: a.ZombieAfter.D(), StateFile: a.StateFile, SaveInterval: a.SaveInterval.D()}
}

// routeHosts collects the host names the configuration's routes are
// written for. The CAPTCHA hostname check uses them as its allowlist
// when challenge.captcha.hostnames is not set.
func routeHosts(cfg *config.Config) []string {
	var out []string
	for _, r := range cfg.Routes {
		out = append(out, r.Hosts...)
	}
	return out
}
