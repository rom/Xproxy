package upstream

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/config"
)

// endpointSpec is one discovered endpoint before it becomes an Endpoint.
type endpointSpec struct {
	address string
	weight  int
	canary  bool
}

// Lookup is the DNS interface discovery uses; tests replace it.
type Lookup interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// discoverer resolves a pool's endpoints from DNS on an interval.
type discoverer struct {
	cfg    config.Discovery
	lookup Lookup
	pool   *Pool

	// consul is the client for type consul, whose blocking queries make
	// the loop below wait on the agent rather than on a ticker.
	consul *consulClient

	mu          sync.Mutex
	last        time.Time
	lastErr     string
	resolutions atomic.Uint64
	changes     atomic.Uint64
	errors      atomic.Uint64
	count       atomic.Int64
	truncations atomic.Uint64
	errNotice   bound.Notice
	// bigNotice warns about a resolution larger than max_endpoints. It is
	// throttled because a registry that answers with ten thousand entries
	// answers that way on every interval, and a log line per resolution
	// would be the second denial of service.
	bigNotice bound.Notice
	// httpClient polls the registry for type http.
	httpClient *http.Client
	// refresh wakes the loop early (tests, reload).
	refresh chan struct{}
}

// DiscoveryStatus is the management view of a pool's discovery.
type DiscoveryStatus struct {
	Type         string    `json:"type"`
	Name         string    `json:"name"`
	Interval     string    `json:"interval"`
	Endpoints    int       `json:"endpoints"`
	LastResolved time.Time `json:"last_resolved,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	Resolutions  uint64    `json:"resolutions"`
	Changes      uint64    `json:"changes"`
	Errors       uint64    `json:"errors"`
	// Truncations counts resolutions that exceeded max_endpoints. Not
	// zero means the pool is serving a subset of what the registry
	// announced, which an operator has to see.
	Truncations uint64 `json:"truncations,omitempty"`
}

func newDiscoverer(cfg *config.Discovery, p *Pool) (*discoverer, error) {
	d := &discoverer{cfg: *cfg, pool: p, refresh: make(chan struct{}, 1)}
	if cfg.Type == "consul" {
		c, err := newConsulClient(*cfg)
		if err != nil {
			return nil, err
		}
		d.consul = c
		return d, nil
	}
	if cfg.Type == "http" {
		// A dedicated client: no environment proxy, a bounded per-request
		// timeout applied in resolve, connections not pooled across the long
		// resolution interval.
		d.httpClient = &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
		return d, nil
	}
	if cfg.Resolver != "" {
		addr := cfg.Resolver
		dialer := &net.Dialer{Timeout: cfg.Timeout.D()}
		d.lookup = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}}
	} else {
		d.lookup = net.DefaultResolver
	}
	return d, nil
}

func (d *discoverer) status() *DiscoveryStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return &DiscoveryStatus{Type: d.cfg.Type, Name: d.cfg.Name, Interval: d.cfg.Interval.D().String(), Endpoints: int(d.count.Load()),
		LastResolved: d.last, LastError: d.lastErr, Resolutions: d.resolutions.Load(), Changes: d.changes.Load(), Errors: d.errors.Load(),
		Truncations: d.truncations.Load()}
}

// resolve performs one resolution and returns the endpoint specs sorted
// by address.
func (d *discoverer) resolve(ctx context.Context) ([]endpointSpec, error) {
	if d.consul != nil {
		// A blocking query is meant to hang, so the bound is the wait
		// plus a margin for the round trip rather than the resolution
		// timeout, which is about a request that should answer at once.
		ctx, cancel := context.WithTimeout(ctx, d.consul.wait+d.cfg.Timeout.D())
		defer cancel()
		specs, err := d.consul.resolve(ctx, d.cfg.Port, d.cfg.Weight, d.cfg.Canary)
		if err != nil {
			return nil, err
		}
		return finalizeSpecs(specs, "consul service "+d.consul.service)
	}
	ctx, cancel := context.WithTimeout(ctx, d.cfg.Timeout.D())
	defer cancel()
	if d.cfg.Type == "http" {
		specs, err := d.resolveHTTP(ctx)
		if err != nil {
			return nil, err
		}
		return finalizeSpecs(specs, d.cfg.Name)
	}
	var specs []endpointSpec
	switch d.cfg.Type {
	case "srv":
		_, recs, err := d.lookup.LookupSRV(ctx, "", "", d.cfg.Name)
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return nil, fmt.Errorf("no SRV records for %s", d.cfg.Name)
		}
		// Lowest priority group only; targets resolve to addresses.
		minPrio := recs[0].Priority
		for _, r := range recs {
			minPrio = min(minPrio, r.Priority)
		}
		for _, r := range recs {
			if r.Priority != minPrio || r.Target == "." || r.Port == 0 {
				continue
			}
			ips, err := d.lookup.LookupIPAddr(ctx, r.Target)
			if err != nil {
				return nil, fmt.Errorf("srv target %s: %w", r.Target, err)
			}
			w := int(r.Weight)
			if w < 1 {
				w = 1
			}
			if w > 1000 {
				w = 1000
			}
			for _, ip := range ips {
				specs = append(specs, endpointSpec{address: net.JoinHostPort(ip.IP.String(), strconv.Itoa(int(r.Port))), weight: w, canary: d.cfg.Canary})
			}
		}
	default:
		ips, err := d.lookup.LookupIPAddr(ctx, d.cfg.Name)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			specs = append(specs, endpointSpec{address: net.JoinHostPort(ip.IP.String(), strconv.Itoa(d.cfg.Port)), weight: d.cfg.Weight, canary: d.cfg.Canary})
		}
	}
	return finalizeSpecs(specs, d.cfg.Name)
}

// finalizeSpecs sorts specs by address, drops duplicates and errors when the
// set is empty, so a resolution never installs zero endpoints.
func finalizeSpecs(specs []endpointSpec, name string) ([]endpointSpec, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("%s resolved to no addresses", name)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].address < specs[j].address })
	// Duplicates (the same address from two SRV targets or registry
	// entries) keep the first.
	out := specs[:0]
	for i, s := range specs {
		if i > 0 && s.address == specs[i-1].address {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// bound truncates a resolution to max_endpoints, warning and counting when it
// does.
//
// A registry is a remote input, and the answer it gives decides how many
// health check goroutines this process runs, how large the hash ring is and how
// much the pool holds. A DNS answer over TCP carries thousands of A records and
// a four megabyte registry response tens of thousands of entries, so without a
// bound one answer -- from a registry that is confused, compromised or answering
// somebody else's question -- sizes the proxy.
//
// It truncates rather than refusing the resolution. Refusing would keep the
// previous set, which for a pool whose backends have all moved is a pool that
// serves nothing; a bounded subset of what was announced still carries traffic.
// The specs are sorted by address by this point, so the subset is the same one
// on every resolution: an unstable subset would churn the pool and the ring
// on every interval, which is worse than serving fewer endpoints.
func (d *discoverer) bound(specs []endpointSpec) []endpointSpec {
	// Validation fills max_endpoints, so an unset one means a caller that
	// built the configuration itself rather than loading it. That falls back
	// to the documented default rather than to no bound: a bound that any
	// path can arrive at unset is not a bound.
	maxEP := d.cfg.MaxEndpoints
	if maxEP <= 0 {
		maxEP = config.DefaultDiscoveryMaxEndpoints
	}
	if len(specs) <= maxEP {
		return specs
	}
	d.truncations.Add(1)
	d.bigNotice.Hit(d.pool.log, "endpoint discovery returned more endpoints than max_endpoints; using the first by address",
		"name", d.cfg.Name, "returned", len(specs), "max_endpoints", maxEP)
	return specs[:maxEP]
}

// once resolves and applies the result; a failure keeps the previous set.
func (d *discoverer) once(ctx context.Context) {
	specs, err := d.resolve(ctx)
	d.resolutions.Add(1)
	d.mu.Lock()
	if err != nil {
		d.errors.Add(1)
		d.lastErr = err.Error()
		d.mu.Unlock()
		d.errNotice.Hit(d.pool.log, "endpoint discovery failed; keeping the previous endpoints", "name", d.cfg.Name, "err", err.Error())
		return
	}
	d.last = time.Now()
	d.lastErr = ""
	d.mu.Unlock()
	specs = d.bound(specs)
	added, removed := d.pool.setDiscovered(specs)
	d.count.Store(int64(len(specs)))
	if added+removed > 0 {
		d.changes.Add(1)
		d.pool.log.Info("endpoints discovered", "name", d.cfg.Name, "endpoints", len(specs), "added", added, "removed", removed)
	}
}

// run re-resolves on the interval until ctx ends.
func (d *discoverer) run(ctx context.Context) {
	defer d.pool.wg.Done()
	if d.consul != nil {
		d.runBlocking(ctx)
		return
	}
	t := time.NewTicker(d.cfg.Interval.D())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.refresh:
		}
		d.once(ctx)
	}
}

// runBlocking is the loop for a discovery whose resolution waits on the
// registry instead of on a ticker: it asks again as soon as an answer
// arrives, because the answer only arrives when something changed.
//
// The interval becomes the pause after a failure. Without one, an agent
// that is down or answering 403 would be asked again immediately and for
// ever, which is a loop against somebody else's machine.
func (d *discoverer) runBlocking(ctx context.Context) {
	for {
		before := d.errors.Load()
		d.once(ctx)
		if ctx.Err() != nil {
			return
		}
		if d.errors.Load() == before {
			// The query answered. Ask again at once: the next answer is
			// the next change.
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.cfg.Interval.D()):
		case <-d.refresh:
		}
	}
}

// Refresh triggers a resolution now (tests and operators).
func (p *Pool) Refresh() {
	if p.disc == nil {
		return
	}
	select {
	case p.disc.refresh <- struct{}{}:
	default:
	}
}

// SetLookupForTest replaces the DNS interface of the pool's discovery.
func (p *Pool) SetLookupForTest(l Lookup) {
	if p.disc != nil {
		p.disc.lookup = l
	}
}

// ResolveNowForTest runs one synchronous resolution.
func (p *Pool) ResolveNowForTest() {
	if p.disc != nil {
		p.disc.once(context.Background())
	}
}
