// Package sesslimit bounds the sessions a listener will hold: how many
// altogether, and how many from one client address.
//
// Six kinds had their own copy of this, identical but for which struct field
// held the configured numbers. The copies shared a defect, and it is the reason
// this package exists rather than a tidier version of the same code.
//
// Each one read the counter and then incremented it:
//
//	if n.Load() >= int64(per) {   // check
//	    return false
//	}
//	n.Add(1)                      // act
//
// Nothing holds the counter between those two lines, so concurrent accepts all
// see room and all take it. Driven with 512 goroutines against a bound of two,
// three sessions get admitted. The global bound has the same shape and fails the
// same way, by as many as the number of accepts in flight.
//
// The per-client map had a second problem. Leave deletes a client's entry when
// its count reaches zero, while another goroutine may already be holding the
// counter it fetched and be about to increment it -- so that increment lands on
// an orphan and the session goes uncounted for the rest of its life.
//
// Both are bound evasion by an attacker who opens connections in parallel, which
// is not a sophisticated thing to do. On the s7 kind it matters most concretely:
// the bound there exists because an S7-300 has sixteen connection resources
// altogether, and a client that takes more than its share denies the plant its
// own HMI.
//
// So this is a mutex, not a pair of atomics. A lock is the cheap and obviously
// correct answer here because the contended operation is an *accept* -- one per
// connection, not one per frame -- and a bound that is only approximately
// enforced is not a bound. Atomics would need a compare-and-swap loop per
// counter and a way to keep Leave from deleting an entry somebody holds; that is
// more code to get right for no measurable gain on a path that already does a
// syscall.
package sesslimit

import (
	"net/netip"
	"sync"
)

// Reasons a gate refuses. They are the strings the kinds already counted and
// logged, so a refusal keeps its name in the metrics across this change.
const (
	ReasonTooMany          = "too_many_sessions"
	ReasonTooManyPerClient = "too_many_sessions_per_client"
)

// A Gate admits and releases sessions. The zero Gate is unbounded, so a
// listener that configures neither bound needs no special case.
type Gate struct {
	// max and perClient are 0 for no bound, which is what the
	// configuration's own default means.
	max, perClient int

	mu   sync.Mutex
	live int
	byIP map[netip.Addr]int
}

// New builds a gate. Either bound may be zero, meaning no bound.
func New(max, perClient int) *Gate {
	return &Gate{max: max, perClient: perClient}
}

// Enter admits a session from an address, and says why not when it does not.
//
// The count is taken under the same lock that checked it, which is the whole
// point of the package: a caller that is admitted has already been counted, and
// the bound cannot be passed by two accepts arriving together.
//
// A caller that is admitted must call Leave exactly once, and the ordinary way
// to guarantee that is a deferred Leave immediately after the check.
func (g *Gate) Enter(ip netip.Addr) (ok bool, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.max > 0 && g.live >= g.max {
		return false, ReasonTooMany
	}
	if g.perClient > 0 && g.byIP[ip] >= g.perClient {
		return false, ReasonTooManyPerClient
	}
	g.live++
	if g.perClient > 0 {
		if g.byIP == nil {
			g.byIP = make(map[netip.Addr]int)
		}
		g.byIP[ip]++
	}
	return true, ""
}

// Leave releases a session.
//
// The entry is deleted when its count reaches zero, which is what keeps the map
// from growing once per address that has ever connected -- a table that an
// attacker cycling through spoofed or real addresses would otherwise fill. Under
// the lock there is no orphan to lose an increment to: a concurrent Enter either
// ran before this and is counted, or runs after and creates the entry again.
func (g *Gate) Leave(ip netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.live > 0 {
		g.live--
	}
	if g.byIP == nil {
		return
	}
	if n := g.byIP[ip] - 1; n > 0 {
		g.byIP[ip] = n
	} else {
		delete(g.byIP, ip)
	}
}

// Live is how many sessions the gate is holding, for a status page.
func (g *Gate) Live() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.live
}

// Clients is how many addresses the gate is tracking, which is the size of the
// table the per-client bound needs. It is zero when no per-client bound is set,
// because then no table exists to grow.
func (g *Gate) Clients() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.byIP)
}
