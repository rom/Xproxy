package proxy

import (
	"sort"
	"sync"
	"sync/atomic"

	"github.com/rom/xproxy/internal/attack"
	"github.com/rom/xproxy/internal/listener"
)

// maxRefusalReasons bounds one kind's reason set.
//
// Every reason is a string literal in the kind that reports it, so the
// set is fixed at compile time and a client cannot grow it. The bound is
// here for the case the literals outgrow it, which is a mistake in this
// repository rather than anything a client did: the refusal is still
// counted, under RefusalsUntracked, and the metric that says so is
// exported. A bounded table that dropped what it could not hold would
// lose exactly the refusals an operator is looking for.
const maxRefusalReasons = 96

// refusals counts refusals per listener kind and reason.
//
// The pointers are stable once inserted, so the counting path takes a
// read lock, finds the counter and adds to it; only a reason seen for
// the first time takes the write lock. A refusal is by definition not
// the hot path — the request that was served is — but a flood is made of
// refusals, so the lock is not held while anything is allocated except
// on that first sighting.
type refusals struct {
	mu sync.RWMutex
	m  map[string]map[string]*atomic.Uint64
}

// The two tables: what was refused, and what a listener in shadow mode
// would have refused. Kept apart so a status view cannot add them up.

// Refuse counts one refusal: kind is the listener kind that refused
// (the same name a "kind:" in the configuration says), reason the fine
// grained reason it logged.
//
// A reason spelled with the kind's own prefix — vnc's "vnc_version",
// rdp's "rdp_negotiate" — is counted without it, because the kind label
// already carries it. The kinds spell the prefix differently in their
// security log, where the field it lands in differs too, and this is
// the one place that has to agree with itself.
func (s *Stats) Refuse(kind, reason string) {
	if _, known := listener.RoleOf(kind); !known {
		// Not a kind this project implements: nothing is counted
		// under a name the roster does not have, because that is how
		// the outer map stays bounded whatever a caller passes.
		s.RefusalsUntracked.Add(1)
		return
	}
	reason = refusalReason(kind, reason)
	// What the refusal means in ATT&CK for ICS terms, counted beside it.
	// It is the same lookup the security log does, from the same table,
	// so a graph by technique and a search by technique cannot disagree
	// -- and it is counted only on the enforced path, because a listener
	// in shadow mode did not detect a technique, it decided not to act on
	// one. The shadow ledger is where that reading belongs.
	s.techniques.observe(kind, reason)
	r := &s.refusals
	r.mu.RLock()
	c := r.m[kind][reason]
	r.mu.RUnlock()
	if c != nil {
		c.Add(1)
		return
	}
	r.mu.Lock()
	if r.m == nil {
		r.m = make(map[string]map[string]*atomic.Uint64, 4)
	}
	byReason := r.m[kind]
	if byReason == nil {
		byReason = make(map[string]*atomic.Uint64, 16)
		r.m[kind] = byReason
	}
	c = byReason[reason]
	if c == nil {
		if len(byReason) >= maxRefusalReasons {
			r.mu.Unlock()
			s.RefusalsUntracked.Add(1)
			return
		}
		c = new(atomic.Uint64)
		byReason[reason] = c
	}
	r.mu.Unlock()
	c.Add(1)
}

// refusalReason is the label form of a reason: the kind's own prefix
// removed, and an empty reason named rather than left blank, because a
// counter with an empty label reads as a broken exporter.
func refusalReason(kind, reason string) string {
	if reason == "" {
		return "unspecified"
	}
	if n := len(kind) + 1; len(reason) > n && reason[:n] == kind+"_" {
		return reason[n:]
	}
	return reason
}

// WouldRefuse counts one refusal a listener in shadow mode recorded
// instead of enforcing. It is a separate table from the refusals on
// purpose: an operator reading a status view has to be able to tell what
// was refused from what merely would have been, and one table with a
// label for the difference is one label away from a graph that adds them
// together.
//
// The detail -- which rule, an example of what was asked for -- is in the
// shadow ledger (xproxyctl policy report); this is the number.
func (s *Stats) WouldRefuse(kind, reason string) {
	if _, known := listener.RoleOf(kind); !known {
		s.RefusalsUntracked.Add(1)
		return
	}
	reason = refusalReason(kind, reason)
	r := &s.wouldRefusals
	r.mu.RLock()
	c := r.m[kind][reason]
	r.mu.RUnlock()
	if c != nil {
		c.Add(1)
		return
	}
	r.mu.Lock()
	if r.m == nil {
		r.m = make(map[string]map[string]*atomic.Uint64, 4)
	}
	byReason := r.m[kind]
	if byReason == nil {
		byReason = make(map[string]*atomic.Uint64, 16)
		r.m[kind] = byReason
	}
	c = byReason[reason]
	if c == nil {
		if len(byReason) >= maxRefusalReasons {
			r.mu.Unlock()
			s.RefusalsUntracked.Add(1)
			return
		}
		c = new(atomic.Uint64)
		byReason[reason] = c
	}
	r.mu.Unlock()
	c.Add(1)
}

// WouldRefusalCounts copies the shadow counters, kind to reason to count.
func (s *Stats) WouldRefusalCounts() map[string]map[string]uint64 {
	return s.wouldRefusals.counts()
}

// RefusalCounts copies the counters, kind to reason to count.
func (s *Stats) RefusalCounts() map[string]map[string]uint64 { return s.refusals.counts() }

// counts copies one table.
func (r *refusals) counts() map[string]map[string]uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.m) == 0 {
		return nil
	}
	out := make(map[string]map[string]uint64, len(r.m))
	for kind, byReason := range r.m {
		m := make(map[string]uint64, len(byReason))
		for reason, c := range byReason {
			m[reason] = c.Load()
		}
		out[kind] = m
	}
	return out
}

// techniqueCounts is the refusals seen per ATT&CK for ICS technique.
//
// It is a table of its own rather than a label on the refusal counter for
// two reasons. One reason carries more than one technique, so a label
// would have to hold a list and nothing could then sum a technique's
// total. And the set is bounded by the catalogue in internal/attack
// rather than by anything a client does, so this table needs no bound of
// its own: a technique that is not in the catalogue is not counted at
// all.
type techniqueCounts struct {
	mu sync.RWMutex
	m  map[string]*atomic.Uint64
}

// observe counts the techniques one refusal carries.
func (t *techniqueCounts) observe(kind, reason string) {
	ts := attack.Of(kind, reason)
	if len(ts) == 0 {
		return
	}
	for _, tech := range ts {
		t.mu.RLock()
		c := t.m[tech.ID]
		t.mu.RUnlock()
		if c == nil {
			t.mu.Lock()
			if t.m == nil {
				t.m = make(map[string]*atomic.Uint64, 16)
			}
			if c = t.m[tech.ID]; c == nil {
				c = new(atomic.Uint64)
				t.m[tech.ID] = c
			}
			t.mu.Unlock()
		}
		c.Add(1)
	}
}

// TechniqueCounts copies the table, identifier to count.
func (s *Stats) TechniqueCounts() map[string]uint64 {
	t := &s.techniques
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.m) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(t.m))
	for id, c := range t.m {
		out[id] = c.Load()
	}
	return out
}

// TechniqueIDs are the identifiers seen, sorted, for a view that lists
// them in a stable order.
func (s *Stats) TechniqueIDs() []string {
	counts := s.TechniqueCounts()
	out := make([]string, 0, len(counts))
	for id := range counts {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
