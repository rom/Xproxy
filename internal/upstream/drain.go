package upstream

import (
	"sort"
	"sync"
)

// Drains records which endpoints and which pools an operator has taken
// out of rotation, and applies that to the pools of whatever
// configuration generation is live.
//
// Draining is not the same as unhealthy, and the difference is the whole
// point: an unhealthy endpoint is one the proxy found broken, and a
// drained one is one a person decided to stop sending work to. So it is
// set from outside -- the management API, the CLI, the GUI -- and it has
// to survive a reload, because a reload builds new pools and an operator
// who drained a machine to patch it did not mean "until the next
// configuration change". The registry holds that intent and the pools
// subscribe to it.
//
// What it does not do is end anything. New work stops; sessions and
// connections already on the endpoint run to their own end. That is what
// makes it usable for a rolling restart, and it is why draining is a
// separate idea from the connection bounds, which do end things.
type Drains struct {
	mu sync.Mutex
	// endpoints and pools hold explicit decisions only. An endpoint with
	// no entry follows its configuration; an entry overrides it until the
	// daemon restarts, because an operator's decision outranks the file
	// that was current when they made it.
	endpoints map[drainKey]bool
	pools     map[string]bool
	// live are the pools of the current generation, so a decision
	// applies at once rather than at the next reload.
	live map[*Pool]struct{}
}

type drainKey struct{ pool, address string }

// NewDrains creates an empty registry.
func NewDrains() *Drains {
	return &Drains{endpoints: map[drainKey]bool{}, pools: map[string]bool{}, live: map[*Pool]struct{}{}}
}

// Attach registers a pool and applies whatever is already recorded for
// it. A pool calls this once, when its generation is built.
func (d *Drains) Attach(p *Pool) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.live[p] = struct{}{}
	d.mu.Unlock()
	d.apply(p)
}

// Detach forgets a pool whose generation has been retired. The recorded
// decisions stay: the next generation's pool of the same name takes them
// on.
func (d *Drains) Detach(p *Pool) {
	if d == nil {
		return
	}
	d.mu.Lock()
	delete(d.live, p)
	d.mu.Unlock()
}

// SetEndpoint drains or restores one endpoint of one pool. It reports
// whether any live pool has an endpoint of that address, so a caller can
// tell an operator that they have named something that is not there --
// while still recording the decision, because an endpoint may be about
// to arrive from discovery.
func (d *Drains) SetEndpoint(pool, address string, draining bool) bool {
	d.mu.Lock()
	d.endpoints[drainKey{pool, address}] = draining
	pools := d.livePools(pool)
	d.mu.Unlock()
	found := false
	for _, p := range pools {
		for _, e := range p.endpoints() {
			if e.Address == address {
				e.draining.Store(draining)
				found = true
			}
		}
	}
	return found
}

// SetPool puts a whole pool into maintenance, or takes it out. A pool in
// maintenance offers no endpoint at all, so a route over it answers as
// it does when everything is unhealthy.
func (d *Drains) SetPool(pool string, on bool) bool {
	d.mu.Lock()
	d.pools[pool] = on
	pools := d.livePools(pool)
	d.mu.Unlock()
	for _, p := range pools {
		p.maintenance.Store(on)
	}
	return len(pools) > 0
}

// livePools are the live pools with a name. Caller holds the lock.
func (d *Drains) livePools(name string) []*Pool {
	var out []*Pool
	for p := range d.live {
		if p.Cfg.Name == name {
			out = append(out, p)
		}
	}
	return out
}

// apply pushes the recorded decisions into one pool, including the
// configuration's own drain flags where nothing overrides them. It runs
// when a pool is attached and whenever discovery changes its endpoints.
func (d *Drains) apply(p *Pool) {
	if d == nil {
		return
	}
	d.mu.Lock()
	maintenance, hasM := d.pools[p.Cfg.Name]
	over := make(map[string]bool, len(d.endpoints))
	for k, v := range d.endpoints {
		if k.pool == p.Cfg.Name {
			over[k.address] = v
		}
	}
	d.mu.Unlock()
	if hasM {
		p.maintenance.Store(maintenance)
	} else {
		p.maintenance.Store(p.Cfg.Maintenance)
	}
	declared := map[string]bool{}
	for _, e := range p.Cfg.Endpoints {
		declared[e.Address] = e.Drain
	}
	for _, e := range p.endpoints() {
		if v, ok := over[e.Address]; ok {
			e.draining.Store(v)
			continue
		}
		e.draining.Store(declared[e.Address])
	}
}

// Decisions is the recorded state, for the management API: every pool in
// maintenance and every endpoint explicitly drained or restored.
type Decisions struct {
	Pools     map[string]bool            `json:"pools,omitempty"`
	Endpoints map[string]map[string]bool `json:"endpoints,omitempty"`
}

// Decisions returns a copy of what has been recorded.
func (d *Drains) Decisions() Decisions {
	out := Decisions{Pools: map[string]bool{}, Endpoints: map[string]map[string]bool{}}
	if d == nil {
		return out
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for name, on := range d.pools {
		out.Pools[name] = on
	}
	for k, v := range d.endpoints {
		if out.Endpoints[k.pool] == nil {
			out.Endpoints[k.pool] = map[string]bool{}
		}
		out.Endpoints[k.pool][k.address] = v
	}
	return out
}

// Names are the pools with a recorded decision, sorted, for logs.
func (d *Drains) Names() []string {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	seen := map[string]bool{}
	for name := range d.pools {
		seen[name] = true
	}
	for k := range d.endpoints {
		seen[k.pool] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
