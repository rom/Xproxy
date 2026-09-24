package dns

import (
	"container/list"
	"sync"
	"time"
)

// Aggressive use of DNSSEC-validated denial of existence, RFC 8198.
//
// An NSEC record is a signed statement that nothing exists between two
// names. Having validated one, a resolver knows the answer to every query
// for a name in that gap -- and an ordinary resolver throws that away and
// asks the upstream again for each one. Random-subdomain floods
// (`<random>.example.com`, thousands a second) and junk top-level queries
// are exactly the traffic that produces, and RFC 8198 is the answer:
// synthesise the NXDOMAIN from the proof already in hand.
//
// Two deliberate narrowings, because a wrong answer here is worse than no
// feature: it is this resolver inventing an NXDOMAIN for a name that
// exists.
//
// The first is the wildcard. A full NXDOMAIN proof is two statements -- the
// name is in a gap, *and* no wildcard at its closest encloser would have
// answered -- and the second is what an implementation forgets. Rather
// than reconstruct which NSEC proved what, a proof is only reused for a
// name that is a **sibling** of the one it was collected for: same parent,
// therefore the same ancestors, therefore the same closest encloser and
// the same wildcard denial that the validator already checked. That still
// covers the case the feature exists for, since a flood's random labels
// are all siblings, and so are junk top-level names under the root.
//
// The second is the client. A synthesised NXDOMAIN carries no signatures,
// so a client that set DO asked for something this cannot give and gets
// the upstream lookup it asked for. The saving applies to the ordinary
// stub traffic, which is nearly all of it.

// maxGapsPerParent bounds the gaps remembered for one parent name. An
// NXDOMAIN proof carries one or two NSEC records; more than a few is a
// zone this is not helping with.
const maxGapsPerParent = 8

// Denials is a bounded store of validated non-existence, keyed by the
// parent of the name each proof was collected for.
type Denials struct {
	mu       sync.Mutex
	max      int
	byParent map[string]*denial
	lru      *list.List
	// Hits counts answers synthesised, Stored the proofs learned.
	Hits, Stored uint64
}

type denial struct {
	parent   string
	gaps     []gap
	deadline time.Time
	elem     *list.Element
}

// gap is one NSEC's statement: nothing exists between owner and next.
type gap struct{ owner, next string }

// NewDenials returns a store holding at most max parents.
func NewDenials(max int) *Denials {
	if max < 1 {
		max = 1
	}
	return &Denials{max: max, byParent: map[string]*denial{}, lru: list.New()}
}

// Len is the number of proofs held.
func (d *Denials) Len() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lru.Len()
}

// Purge drops every proof and returns how many there were. An operator
// who empties the cache means every answer, and a held gap denies names
// the cache no longer has anything to say about -- a name added to the
// zone a moment ago among them.
func (d *Denials) Purge() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.lru.Len()
	d.byParent = map[string]*denial{}
	d.lru.Init()
	return n
}

// Learn records the NSEC gaps of a validated NXDOMAIN response. The
// caller must have validated it: nothing here checks a signature, and a
// proof learned from an unvalidated answer would be an attacker choosing
// which names this resolver says do not exist.
func (d *Denials) Learn(q Question, m *Message, now time.Time, maxTTL time.Duration) {
	if d == nil || m == nil || q.Class != ClassIN || m.Header.Rcode() != RcodeNXDomain {
		return
	}
	gaps := make([]gap, 0, maxGapsPerParent)
	ttl := uint32(0)
	for _, rr := range m.Authority {
		if rr.Type != TypeNSEC || rr.Class != ClassIN || len(rr.Data) == 0 {
			continue
		}
		next, _, err := readName(rr.Data, 0)
		if err != nil {
			return // a proof this resolver cannot read whole is not one it uses
		}
		owner := canonicalName(rr.Name)
		gaps = append(gaps, gap{owner: owner, next: canonicalName(next)})
		if ttl == 0 || rr.TTL < ttl {
			ttl = rr.TTL
		}
		if len(gaps) >= maxGapsPerParent {
			break
		}
	}
	if len(gaps) == 0 || ttl == 0 {
		return
	}
	life := time.Duration(ttl) * time.Second
	if maxTTL > 0 && life > maxTTL {
		life = maxTTL
	}
	parent := parentName(canonicalName(q.Name))
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.byParent[parent]; ok {
		e.gaps, e.deadline = gaps, now.Add(life)
		d.lru.MoveToFront(e.elem)
		d.Stored++
		return
	}
	for d.lru.Len() >= d.max {
		if el := d.lru.Back(); el != nil {
			old := el.Value.(*denial)
			delete(d.byParent, old.parent)
			d.lru.Remove(el)
		}
	}
	e := &denial{parent: parent, gaps: gaps, deadline: now.Add(life)}
	e.elem = d.lru.PushFront(e)
	d.byParent[parent] = e
	d.Stored++
}

// Covers reports whether a validated proof already says this name does
// not exist: a sibling of the name the proof was collected for, inside one
// of its gaps.
func (d *Denials) Covers(q Question, now time.Time) bool {
	if d == nil || q.Class != ClassIN {
		return false
	}
	name := canonicalName(q.Name)
	parent := parentName(name)
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.byParent[parent]
	if !ok {
		return false
	}
	if !now.Before(e.deadline) {
		delete(d.byParent, parent)
		d.lru.Remove(e.elem)
		return false
	}
	for _, g := range e.gaps {
		if inGap(name, g) {
			d.lru.MoveToFront(e.elem)
			d.Hits++
			return true
		}
	}
	return false
}

// inGap reports whether name falls strictly inside an NSEC's gap. The last
// NSEC of a zone wraps -- its next name is the apex, which sorts before
// its owner -- and a name after the owner is then covered.
// Both comparisons are strict, which is what excludes the gap's own
// endpoints: an NSEC says those two names exist and nothing between them
// does.
func inGap(name string, g gap) bool {
	if canonicalCompare(g.owner, g.next) < 0 {
		return canonicalCompare(name, g.owner) > 0 && canonicalCompare(name, g.next) < 0
	}
	// Wrapped, or a single-NSEC zone: everything after the owner and
	// everything before the next name is in the gap.
	return canonicalCompare(name, g.owner) > 0 || canonicalCompare(name, g.next) < 0
}
