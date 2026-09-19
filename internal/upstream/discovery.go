package upstream

import (
	"context"
	"fmt"
	"net"
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

	mu          sync.Mutex
	last        time.Time
	lastErr     string
	resolutions atomic.Uint64
	changes     atomic.Uint64
	errors      atomic.Uint64
	count       atomic.Int64
	errNotice   bound.Notice
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
}

func newDiscoverer(cfg *config.Discovery, p *Pool) *discoverer {
	d := &discoverer{cfg: *cfg, pool: p, refresh: make(chan struct{}, 1)}
	if cfg.Resolver != "" {
		addr := cfg.Resolver
		dialer := &net.Dialer{Timeout: cfg.Timeout.D()}
		d.lookup = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}}
	} else {
		d.lookup = net.DefaultResolver
	}
	return d
}

func (d *discoverer) status() *DiscoveryStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return &DiscoveryStatus{Type: d.cfg.Type, Name: d.cfg.Name, Interval: d.cfg.Interval.D().String(), Endpoints: int(d.count.Load()),
		LastResolved: d.last, LastError: d.lastErr, Resolutions: d.resolutions.Load(), Changes: d.changes.Load(), Errors: d.errors.Load()}
}

// resolve performs one resolution and returns the endpoint specs sorted
// by address.
func (d *discoverer) resolve(ctx context.Context) ([]endpointSpec, error) {
	ctx, cancel := context.WithTimeout(ctx, d.cfg.Timeout.D())
	defer cancel()
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
	if len(specs) == 0 {
		return nil, fmt.Errorf("%s resolved to no addresses", d.cfg.Name)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].address < specs[j].address })
	// Duplicates (the same address from two SRV targets) keep the first.
	out := specs[:0]
	for i, s := range specs {
		if i > 0 && s.address == specs[i-1].address {
			continue
		}
		out = append(out, s)
	}
	return out, nil
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
