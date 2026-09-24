package upstream

import "time"

// Tiering: which endpoints of a pool are candidates at all, before the
// balancer chooses among them.
//
// Two policies produce a tier, and they compose:
//
//   - Priority. The endpoints of the lowest priority number that has an
//     available member carry the traffic; the rest are ignored until that
//     tier has nothing left. This is how a failover pool is written, and
//     a backup endpoint is simply one in a later tier.
//   - Locality. Where the node knows which zone it is in and the pool
//     asks for it, the endpoints of that zone are preferred over the
//     ones elsewhere -- which keeps traffic off the links between sites.
//     It is a preference, not a restriction: an estate that pinned
//     traffic to one zone would lose the service when the zone lost it,
//     which is the opposite of what zones are for. min_local is what
//     keeps one surviving local endpoint from taking the whole load.
//
// Tiering is applied by excluding the endpoints outside the chosen tier
// rather than by handing the balancer a shorter list, because the
// consistent hash ring is built over every endpoint: shortening the list
// would move every key, while excluding moves only the keys of the
// endpoints left out -- which is the whole property the ring exists for.

// tierExclude returns the exclusion set to pick within: the caller's own
// exclusions plus every endpoint outside the active tier. It returns the
// caller's set unchanged when no tiering applies.
func (p *Pool) tierExclude(eps []*Endpoint, exclude map[*Endpoint]bool, now time.Time) map[*Endpoint]bool {
	tiered := p.tiered
	if !tiered {
		return exclude
	}
	// The active priority is the lowest one with an available endpoint
	// outside the caller's exclusions, so a retry that has used up a
	// tier falls to the next.
	best := 0
	found := false
	for _, e := range eps {
		if !available(e, exclude, now) {
			continue
		}
		if !found || e.priority < best {
			best, found = e.priority, true
		}
	}
	if !found {
		return exclude
	}
	out := make(map[*Endpoint]bool, len(exclude)+len(eps))
	for e, v := range exclude {
		out[e] = v
	}
	for _, e := range eps {
		if e.priority != best {
			out[e] = true
		}
	}
	if !p.preferZone || p.zone == "" {
		return out
	}
	// Locality within the tier: count what is available locally, and
	// leave the rest out only when there is enough of it.
	local := 0
	for _, e := range eps {
		if available(e, out, now) && e.localTo(p.zone) {
			local++
		}
	}
	if local < p.minLocal {
		return out
	}
	for _, e := range eps {
		if !e.localTo(p.zone) {
			out[e] = true
		}
	}
	return out
}

// localTo reports whether the endpoint counts as being in zone. An
// endpoint with no zone is local to every zone: "somewhere unknown" is
// not a reason to send traffic across a site.
func (e *Endpoint) localTo(zone string) bool {
	return e.zone == "" || e.zone == zone
}
