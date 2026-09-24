package proxy

import (
	"sync"
	"sync/atomic"

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

// RefusalCounts copies the counters, kind to reason to count.
func (s *Stats) RefusalCounts() map[string]map[string]uint64 {
	r := &s.refusals
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
