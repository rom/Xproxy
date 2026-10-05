package kkdcp

import (
	"net/netip"
	"sync"
	"time"
)

// A counting window, per client, used for the two behavioural bounds this
// kind has of its own.
//
// The first counts *distinct* values -- the service principals one client
// asked for -- because that is what service ticket enumeration looks like:
// forty different names in a minute, where ordinary traffic asks for the
// handful of services a workstation uses. The second counts occurrences --
// pre-authentication failures -- because that is what password spraying
// looks like.
//
// Both are deliberately per client and not per principal. A sprayer tries
// one password against a thousand accounts, so a per-account bound sees one
// failure each and never fires; the KDC's own lockout policy is the
// per-account bound, and locking the account is the outcome the sprayer
// wanted. The address is the thing the two have in common.
//
// The table is bounded and the eviction is the oldest-first sweep a map of
// this size can afford: it is swept on every record, which costs a walk of
// at most maxClients entries and saves a goroutine.

// maxClients bounds the addresses tracked. An estate's own clients are
// few; an internet-facing listener's are not, and the bound is what stops a
// sweep from becoming the listener's workload.
const maxClients = 4096

type entry struct {
	// seen is the distinct values, for a window counting those.
	seen map[string]time.Time
	// hits are the timestamps, for a window counting occurrences.
	hits  []time.Time
	touch time.Time
}

type window struct {
	mu    sync.Mutex
	by    map[netip.Addr]*entry
	bound int
	span  time.Duration
}

func newWindow(bound int, span time.Duration) *window {
	return &window{by: map[netip.Addr]*entry{}, bound: bound, span: span}
}

// distinct records a value for a client and reports how many different ones
// it has asked for inside the window, and whether that is past the bound.
func (w *window) distinct(ip netip.Addr, value string, now time.Time) (int, bool) {
	if w == nil {
		return 0, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sweep(now)
	e := w.by[ip]
	if e == nil {
		if len(w.by) >= maxClients {
			// The table is full and the sweep found nothing to drop, which
			// means every tracked client is active. A new client is not
			// tracked rather than evicting one that is: the alternative is a
			// flood of new addresses pushing the real ones out, which is the
			// shape of an attack on the detector rather than on the KDC.
			return 0, false
		}
		e = &entry{seen: map[string]time.Time{}}
		w.by[ip] = e
	}
	e.touch = now
	if e.seen == nil {
		e.seen = map[string]time.Time{}
	}
	for k, at := range e.seen {
		if now.Sub(at) > w.span {
			delete(e.seen, k)
		}
	}
	// The bound is also the table's bound per client: a client that asks for
	// more names than the bound allows has already tripped it, so there is
	// no reason to keep counting past it.
	if len(e.seen) > w.bound*4 {
		return len(e.seen), true
	}
	e.seen[value] = now
	return len(e.seen), len(e.seen) > w.bound
}

// hit records an occurrence and reports the count inside the window and
// whether it is past the bound.
func (w *window) hit(ip netip.Addr, now time.Time) (int, bool) {
	if w == nil {
		return 0, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sweep(now)
	e := w.by[ip]
	if e == nil {
		if len(w.by) >= maxClients {
			return 0, false
		}
		e = &entry{}
		w.by[ip] = e
	}
	e.touch = now
	keep := e.hits[:0]
	for _, at := range e.hits {
		if now.Sub(at) <= w.span {
			keep = append(keep, at)
		}
	}
	e.hits = keep
	if len(e.hits) <= w.bound*4 {
		e.hits = append(e.hits, now)
	}
	return len(e.hits), len(e.hits) > w.bound
}

// count reports a client's current count without recording anything, which
// is what a log line about a refusal needs.
func (w *window) count(ip netip.Addr) int {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.by[ip]
	if e == nil {
		return 0
	}
	if e.seen != nil {
		return len(e.seen)
	}
	return len(e.hits)
}

// sweep drops the clients nothing has been heard from for twice the window,
// which is long enough that a client inside its own window is never dropped
// and short enough that the table does not grow without bound.
func (w *window) sweep(now time.Time) {
	for ip, e := range w.by {
		if now.Sub(e.touch) > 2*w.span {
			delete(w.by, ip)
		}
	}
}
