// Package correlate is the short memory a listener does not have: what
// each address has been doing across every listener of this daemon, for
// the last window, bounded.
//
// # The questions it exists to answer
//
// Every policy in this project decides about one message on one listener,
// which is the right shape for a policy and the wrong shape for several
// real detections:
//
//	one host touching Modbus, then DNP3, then S7      three listeners, one actor
//	an OT session right after a bastion session       two daemons, one machine
//	an NTP step, then time-tagged 104 commands        two protocols, one clock
//	a device that has never published, publishing     one listener, two epochs
//
// None of those is visible to the listener that sees half of it. This is
// the half-sentence store: a listener writes down what it saw about an
// actor, and a detector asks what else that actor has been doing.
//
// # What it is not
//
// It is not the asset inventory. The inventory answers "what is on this
// network", keeps a record per device for as long as the estate runs, and
// is written to disk. This answers "what has this address done in the last
// half hour", holds a few dozen facts per actor, and is gone on a restart
// -- which is the right trade for a detection window and the wrong one for
// an inventory.
//
// It is not the ban list or a rate limiter. Nothing here decides anything:
// it records, and a caller that reads it decides. In particular nothing
// here reaches the ban ladder, for the reason OT detections never do.
//
// It is not per message. A frame every few milliseconds for years is what
// a control network is, and a store that took a lock per frame would be a
// latency tax on the scan cycle. Callers write a fact when something
// *changes*: a session opened, a first write, an engineering operation, a
// refusal, a clock step. Identical facts inside a short interval bump a
// count rather than appending, so a burst of refusals is one fact with a
// count of forty rather than forty facts.
//
// # Bounds
//
// Everything is bounded and the bounds are the interesting part, because
// this is a table keyed by something a stranger chooses. The actors are
// bounded and the oldest is evicted; each actor's facts are bounded and
// the oldest is dropped; a fact's detail is clipped; and every drop is
// counted, so a status view can say the window is not complete rather than
// quietly answering from a table that lost half of what it was told.
package correlate

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/textsafe"
)

// Class is what happened, from a closed vocabulary.
//
// It is closed on purpose. A detector asks "has this actor opened a
// session on another kind" or "did an engineering operation happen here in
// the last ten minutes", and a free-form string would make that a question
// about spelling. What the protocol called it goes in Detail.
type Class string

const (
	// ClassSession is a session, connection or association established.
	// The one every kind writes, because "this actor spoke to this
	// listener at all" is what the cross-kind questions are about.
	ClassSession Class = "session"
	// ClassRefused is a refusal by the listener's own policy.
	ClassRefused Class = "refused"
	// ClassRead is a read of process data: values, objects, points.
	ClassRead Class = "read"
	// ClassWrite is a write that changes the process or a setting.
	ClassWrite Class = "write"
	// ClassEngineering is an operation from the engineering workflow: a
	// program or firmware transfer, a mode change, a restart. The class
	// a work order is about.
	ClassEngineering Class = "engineering"
	// ClassDiscovery is enumeration: sweeps, browse storms, who-is with
	// no range, identification requests.
	ClassDiscovery Class = "discovery"
	// ClassCredential is a credential event: a failure, a default
	// community string, an identity nobody enrolled.
	ClassCredential Class = "credential"
	// ClassTimeStep is the clock moving other than by drift -- an offset
	// step this relay carried or refused. The left half of a
	// time-manipulation chain.
	ClassTimeStep Class = "time_step"
	// ClassGateSession is an interactive session on a gate listener:
	// somebody logged in. Written about both ends, the person's address
	// and the machine they reached, because the pivot question is about
	// the machine.
	ClassGateSession Class = "gate_session"
)

// Classes are the classes, for validation and for a status view.
func Classes() []Class {
	return []Class{ClassSession, ClassRefused, ClassRead, ClassWrite,
		ClassEngineering, ClassDiscovery, ClassCredential, ClassTimeStep,
		ClassGateSession}
}

// Fact is one thing a listener saw.
type Fact struct {
	// Class is what happened.
	Class Class
	// Kind is the listener kind that saw it, as the roster spells it.
	Kind string
	// Listener is the listener's own name, so a report can say where.
	Listener string
	// Identity is who the protocol said it was, where it has an identity
	// at all: a security name, a user, an AP-title, a PSK identity.
	Identity string
	// Detail is what the protocol called it -- a function code, a
	// service, an object name -- clipped, and from a peer, so it is
	// never used as a key.
	Detail string
	// At is when, and Count how many of the same fact were collapsed
	// into this one.
	At    time.Time
	Count int
	// Remote says the fact came from a cluster peer rather than from this
	// process. A detector that must not act on a sibling's word can tell.
	Remote bool
}

// Bounds are the table's limits.
type Bounds struct {
	// Window is how long a fact is worth remembering. Default 30m.
	Window time.Duration
	// MaxActors bounds the addresses remembered; the least recently
	// active is evicted. Default 4096.
	MaxActors int
	// MaxFacts bounds one actor's facts; the oldest is dropped. Default
	// 64.
	MaxFacts int
	// Collapse is the interval inside which an identical fact bumps a
	// count rather than appending. Default 1s.
	Collapse time.Duration
}

// The defaults, and the ceilings validation holds a configuration to.
const (
	DefaultWindow   = 30 * time.Minute
	MaxWindow       = 24 * time.Hour
	DefaultActors   = 4096
	MaxActorsCeil   = 262144
	DefaultFacts    = 64
	MaxFactsCeil    = 1024
	DefaultCollapse = time.Second
)

func (b Bounds) withDefaults() Bounds {
	if b.Window <= 0 {
		b.Window = DefaultWindow
	}
	if b.Window > MaxWindow {
		b.Window = MaxWindow
	}
	if b.MaxActors <= 0 {
		b.MaxActors = DefaultActors
	}
	if b.MaxActors > MaxActorsCeil {
		b.MaxActors = MaxActorsCeil
	}
	if b.MaxFacts <= 0 {
		b.MaxFacts = DefaultFacts
	}
	if b.MaxFacts > MaxFactsCeil {
		b.MaxFacts = MaxFactsCeil
	}
	if b.Collapse < 0 {
		b.Collapse = 0
	}
	if b.Collapse == 0 {
		b.Collapse = DefaultCollapse
	}
	return b
}

// actor is one address's recent facts, oldest first.
type actor struct {
	facts []Fact
	last  time.Time
	// dropped counts this actor's facts the bound pushed out, so a
	// detector reading a truncated window can tell.
	dropped uint64
}

// Store is the table. A nil *Store answers every question with nothing
// and records nothing, so a kind need not check whether correlation is
// configured.
type Store struct {
	b  Bounds
	mu sync.Mutex
	m  map[netip.Addr]*actor
	// now is the clock, injectable for the tests -- a window store whose
	// tests slept would be a test suite that took half an hour.
	now func() time.Time

	observed, collapsed, dropped, evicted uint64
}

// New makes a store with the bounds, filling in the defaults.
func New(b Bounds) *Store {
	return &Store{b: b.withDefaults(), m: map[netip.Addr]*actor{}, now: time.Now}
}

// SetClock replaces the clock. For tests.
func (s *Store) SetClock(f func() time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.now = f
	s.mu.Unlock()
}

// Window is the window this store keeps, so a caller asking for "the
// window" does not have to know the configuration.
func (s *Store) Window() time.Duration {
	if s == nil {
		return 0
	}
	return s.b.Window
}

// estate is the key facts about the daemon rather than about one address
// are filed under: the invalid address, which no peer can have.
var estate = netip.Addr{}

// Observe records one fact about an address.
//
// The caller decides who the fact is about, which is the whole of the
// design: a gate kind writes its session fact twice, once about the
// person's address and once about the machine they reached, because the
// pivot question is about the machine.
func (s *Store) Observe(addr netip.Addr, f Fact) {
	if s == nil || f.Class == "" {
		return
	}
	s.record(addr, f)
}

// ObserveEstate records a fact about the daemon rather than about an
// address: a clock step, a reload, anything whose subject is the process.
func (s *Store) ObserveEstate(f Fact) {
	if s == nil || f.Class == "" {
		return
	}
	s.record(estate, f)
}

// Merge records a fact a cluster peer reported. It is marked Remote, and
// is otherwise an ordinary fact: the whole point of sharing them is that
// the daemon in front of the plant can see the bastion session that
// preceded an OT session, and those are two processes.
func (s *Store) Merge(addr netip.Addr, f Fact) {
	if s == nil || f.Class == "" {
		return
	}
	f.Remote = true
	s.record(addr, f)
}

func (s *Store) record(key netip.Addr, f Fact) {
	if f.Count <= 0 {
		f.Count = 1
	}
	f.Detail = textsafe.Clip256(f.Detail)
	f.Identity = textsafe.Clip64(f.Identity)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if f.At.IsZero() {
		f.At = now
	}
	s.observed++
	a := s.m[key]
	if a == nil {
		if len(s.m) >= s.b.MaxActors {
			s.evictOldestLocked()
		}
		a = &actor{}
		s.m[key] = a
	}
	a.last = now
	a.expireLocked(now.Add(-s.b.Window))

	// Collapse an identical fact seen a moment ago. A burst of refusals
	// is one fact with a count, which is what a report wants to print and
	// what stops a flood from filling one actor's whole window with the
	// same line.
	if n := len(a.facts); n > 0 {
		last := &a.facts[n-1]
		if last.Class == f.Class && last.Kind == f.Kind && last.Listener == f.Listener &&
			last.Detail == f.Detail && last.Identity == f.Identity && last.Remote == f.Remote &&
			now.Sub(last.At) <= s.b.Collapse {
			last.Count += f.Count
			last.At = f.At
			s.collapsed++
			return
		}
	}
	if len(a.facts) >= s.b.MaxFacts {
		// The oldest goes, and is counted. A window that silently lost
		// its first half would answer "no gate session preceded this"
		// when there was one.
		a.facts = append(a.facts[:0], a.facts[1:]...)
		a.dropped++
		s.dropped++
	}
	a.facts = append(a.facts, f)
}

// expireLocked drops the facts older than the cutoff.
func (a *actor) expireLocked(cutoff time.Time) {
	i := 0
	for i < len(a.facts) && a.facts[i].At.Before(cutoff) {
		i++
	}
	if i > 0 {
		a.facts = append(a.facts[:0], a.facts[i:]...)
	}
}

// evictOldestLocked removes the least recently active actor.
func (s *Store) evictOldestLocked() {
	var oldest netip.Addr
	first := true
	var when time.Time
	for k, a := range s.m {
		if k == estate {
			// The estate's own facts are not an actor a stranger can
			// create, and evicting them would lose the left half of every
			// chain that starts with a clock step.
			continue
		}
		if first || a.last.Before(when) {
			oldest, when, first = k, a.last, false
		}
	}
	if first {
		return
	}
	delete(s.m, oldest)
	s.evicted++
}

// Recent are an actor's facts inside the window, oldest first.
func (s *Store) Recent(addr netip.Addr, within time.Duration) []Fact {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recentLocked(addr, within)
}

// RecentEstate are the daemon's own facts inside the window.
func (s *Store) RecentEstate(within time.Duration) []Fact {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recentLocked(estate, within)
}

func (s *Store) recentLocked(key netip.Addr, within time.Duration) []Fact {
	a := s.m[key]
	if a == nil {
		return nil
	}
	now := s.now()
	if within <= 0 || within > s.b.Window {
		within = s.b.Window
	}
	cutoff := now.Add(-within)
	out := make([]Fact, 0, len(a.facts))
	for _, f := range a.facts {
		if f.At.Before(cutoff) {
			continue
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Count is how many facts of a class an actor has inside the window,
// counting the collapsed ones. An empty kind counts every kind.
func (s *Store) Count(addr netip.Addr, class Class, kind string, within time.Duration) int {
	n := 0
	for _, f := range s.Recent(addr, within) {
		if f.Class != class {
			continue
		}
		if kind != "" && f.Kind != kind {
			continue
		}
		n += f.Count
	}
	return n
}

// Seen reports whether an actor has a fact of this class, optionally on
// one kind, inside the window.
func (s *Store) Seen(addr netip.Addr, class Class, kind string, within time.Duration) bool {
	return s.Count(addr, class, kind, within) > 0
}

// KindsTouched are the distinct listener kinds an actor has been seen on
// inside the window, sorted. It is the answer to the sequential-probing
// question: one host on Modbus, then S7, then DNP3 is three kinds and one
// actor, which no listener can see by itself.
func (s *Store) KindsTouched(addr netip.Addr, within time.Duration) []string {
	seen := map[string]bool{}
	for _, f := range s.Recent(addr, within) {
		if f.Kind != "" {
			seen[f.Kind] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// First is when an actor's oldest remembered fact was, and whether it has
// any. It is not "first ever seen" -- the window is the window -- and a
// caller that needs the difference has the asset inventory for it.
func (s *Store) First(addr netip.Addr, within time.Duration) (time.Time, bool) {
	fs := s.Recent(addr, within)
	if len(fs) == 0 {
		return time.Time{}, false
	}
	return fs[0].At, true
}

// Truncated reports whether this actor's window lost facts to the bound,
// so a detector can say "as far as this relay remembers" rather than
// answering from half a window as if it were whole.
func (s *Store) Truncated(addr netip.Addr) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.m[addr]
	return a != nil && a.dropped > 0
}

// Status is the table's own numbers, for a management view.
type Status struct {
	Actors    int    `json:"actors"`
	Facts     int    `json:"facts"`
	Window    string `json:"window"`
	Observed  uint64 `json:"observed"`
	Collapsed uint64 `json:"collapsed"`
	Dropped   uint64 `json:"dropped"`
	Evicted   uint64 `json:"evicted"`
	MaxActors int    `json:"max_actors"`
	MaxFacts  int    `json:"max_facts"`
}

// Status reports the table's numbers. The drops and evictions are the
// ones worth an alert: a window that is being pushed out is a window
// whose answers are becoming "no" for the wrong reason.
func (s *Store) Status() Status {
	if s == nil {
		return Status{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	facts := 0
	cutoff := s.now().Add(-s.b.Window)
	for _, a := range s.m {
		a.expireLocked(cutoff)
		facts += len(a.facts)
	}
	return Status{
		Actors: len(s.m), Facts: facts, Window: s.b.Window.String(),
		Observed: s.observed, Collapsed: s.collapsed,
		Dropped: s.dropped, Evicted: s.evicted,
		MaxActors: s.b.MaxActors, MaxFacts: s.b.MaxFacts,
	}
}
