package packs

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// The engine: the packs, the per-actor state they need, and the bounds on it.
//
// # Where the events come from
//
// One place: logging.SecurityEvent, which every refusal, behavioural finding
// and engineering operation in this project already passes through. The engine
// is a sink on it rather than a call in each kind, for the reason the ATT&CK
// tagging is done there too -- a kind that had to remember to feed the packs
// would be a kind whose next detection silently applied to nothing.
//
// # The state, and why it is this small
//
// Per actor, per pack: how many events have satisfied each signal, when the
// first one arrived, and which kinds they came from. That is a handful of
// integers, and it is all the pack language can ask about, which is the point:
// a language that could ask about a value or a name would need the values and
// the names kept, and a table of peer-chosen strings keyed by a peer-chosen
// address is the shape of an out-of-memory.
//
// Everything is bounded. The actors are bounded and the least recently seen is
// evicted; the state expires with the pack's own window; and an eviction is
// counted, so a status view can say the window is not complete rather than
// answering from a table that lost half of what it was told. That is the same
// arrangement internal/correlate makes, for the same reason.
//
// # Quarantine, which is not the ban ladder
//
// A pack that declares `deny`, on a daemon whose operator turned enforcement
// on, quarantines the actor: the OT listeners refuse it at admission for the
// rest of the pack's window, and then it is over. Nothing is written to the
// ban list, no ladder escalates, no prefix or fingerprint is banned, and a
// restart clears it. That is a deliberate ceiling: an engineer whose laptop
// tripped a pack should lose a quarter of an hour, not their access to the
// plant while somebody finds the ban list.

// Bounds are the engine's limits.
type Bounds struct {
	// MaxActors is how many addresses have pack state at once; the least
	// recently seen is evicted. Default 4096.
	MaxActors int
	// MaxQuarantined is how many actors may be quarantined at once. Default
	// 256. Past it nothing new is quarantined and the drops are counted: a
	// detection that could quarantine an unbounded number of addresses is a
	// detection somebody can use to take a plant off the air.
	MaxQuarantined int
}

func (b Bounds) withDefaults() Bounds {
	if b.MaxActors <= 0 {
		b.MaxActors = 4096
	}
	if b.MaxQuarantined <= 0 {
		b.MaxQuarantined = 256
	}
	return b
}

// Options is how the engine is configured, beyond the packs themselves.
type Options struct {
	// Enforce lets the packs that declare `deny` actually quarantine. Off by
	// default: a detection an estate has not read the report for should not
	// be refusing anything.
	Enforce bool
	// Disabled are pack identifiers this estate does not want, by name. It is
	// how an operator drops one pack that is noisy on their plant without
	// giving up the directory.
	Disabled []string
	// Bounds are the table's limits.
	Bounds Bounds
}

// state is one actor's progress through one pack.
type state struct {
	// counts is how many events have matched each signal.
	counts []int
	// stage is the next signal an ordered pack is looking for. An ordered
	// pack looks for its signals one at a time, so an event that would
	// satisfy a later signal before its turn is not counted at all -- which
	// is what makes "read the program, then write one" a different statement
	// from "did both this morning".
	stage int
	// order is the signal indices in the order they were satisfied, which is
	// what the finding reports.
	order []int
	// kinds are the listener kinds the matching events came from.
	kinds map[string]bool
	// first is when the first matching event arrived, which starts the
	// window, and last when the most recent did.
	first, last time.Time
	// fired is when this pack last reported about this actor, for refire.
	fired time.Time
}

// actor is one address's state across the packs, keyed by pack identifier.
type actor struct {
	byPack map[string]*state
	seen   time.Time
}

// Engine evaluates the packs. A nil Engine is usable and does nothing, so a
// caller holds one without checking.
type Engine struct {
	mu      sync.Mutex
	packs   []*Pack
	opts    Options
	bounds  Bounds
	actors  map[netip.Addr]*actor
	quar    map[netip.Addr]quarantine
	now     func() time.Time
	evicted uint64
	refused uint64
	matches map[string]uint64
}

// quarantine is one actor held out, and by which pack.
type quarantine struct {
	pack  string
	until time.Time
}

// New builds an engine from loaded packs. The packs an operator disabled are
// dropped here rather than filtered at every event.
func New(ps []*Pack, o Options) *Engine {
	keep := make([]*Pack, 0, len(ps))
	for _, p := range ps {
		if contains(o.Disabled, p.ID) {
			continue
		}
		keep = append(keep, p)
	}
	return &Engine{
		packs:   keep,
		opts:    o,
		bounds:  o.Bounds.withDefaults(),
		actors:  make(map[netip.Addr]*actor),
		quar:    make(map[netip.Addr]quarantine),
		matches: make(map[string]uint64),
		now:     time.Now,
	}
}

// SetClock replaces the clock, for the tests.
func (e *Engine) SetClock(f func() time.Time) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.now = f
	e.mu.Unlock()
}

// Packs are the packs in force, sorted by identifier.
func (e *Engine) Packs() []*Pack {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Pack, len(e.packs))
	copy(out, e.packs)
	return out
}

// On reports whether there is anything to evaluate.
func (e *Engine) On() bool { return e != nil && len(e.packs) > 0 }

// Observe feeds one security event to the packs and returns what matched.
//
// It returns rather than reporting itself: the caller owns the log, the
// counters and the correlation window, and an engine that wrote to those would
// be an engine the tests could not drive.
func (e *Engine) Observe(ev Event) []Finding {
	if !e.On() || !ev.Actor.IsValid() || ev.Reason == "" {
		return nil
	}
	if ev.At.IsZero() {
		ev.At = e.now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	a := e.actors[ev.Actor]
	if a == nil {
		if len(e.actors) >= e.bounds.MaxActors {
			if !e.evictOldestLocked() {
				e.evicted++
				return nil
			}
		}
		a = &actor{byPack: make(map[string]*state)}
		e.actors[ev.Actor] = a
	}
	a.seen = ev.At

	var out []Finding
	for _, p := range e.packs {
		if !p.Covers(ev.Kind) {
			continue
		}
		if f, ok := e.step(p, a, ev); ok {
			out = append(out, f)
		}
	}
	if len(e.actors) > 0 && len(a.byPack) == 0 {
		// Nothing this actor did interests any pack; do not hold a row for
		// it, so a plant's ordinary traffic does not fill the table.
		delete(e.actors, ev.Actor)
	}
	return out
}

// step advances one pack for one actor and reports a match.
func (e *Engine) step(p *Pack, a *actor, ev Event) (Finding, bool) {
	sig := p.Detect.Signals
	st := a.byPack[p.ID]
	// The window is anchored on the first matching event, and once it has
	// passed this is the start of a new attempt rather than the tail of an old
	// one. Without that, a pack with a fifteen-minute window would eventually
	// match a plant's ordinary traffic given a long enough day.
	stale := st != nil && ev.At.Sub(st.first) > p.Detect.Window
	stage := 0
	if st != nil && !stale {
		stage = st.stage
	}
	idx := -1
	if p.Detect.Ordered {
		if stage < len(sig) && sig[stage].matches(ev) {
			idx = stage
		}
	} else {
		for i := range sig {
			if sig[i].matches(ev) {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		return Finding{}, false
	}
	switch {
	case st == nil:
		st = newState(len(sig), ev.At)
		a.byPack[p.ID] = st
	case stale:
		fired := st.fired
		*st = *newState(len(sig), ev.At)
		st.fired = fired
	}
	st.last = ev.At
	st.kinds[ev.Kind] = true
	st.counts[idx]++
	if st.counts[idx] == sig[idx].Count {
		st.order = append(st.order, idx)
		if p.Detect.Ordered {
			st.stage++
		}
	}

	if !e.satisfied(p, st) {
		return Finding{}, false
	}
	if !st.fired.IsZero() && ev.At.Sub(st.fired) < p.Detect.Refire {
		return Finding{}, false
	}
	st.fired = ev.At

	f := Finding{
		Pack: p.ID, Name: p.Name, Technique: p.Technique,
		Severity: p.Severity, Actor: ev.Actor, At: ev.At,
	}
	for _, i := range st.order {
		f.Signals = append(f.Signals, sig[i].Name)
	}
	for k := range st.kinds {
		f.Kinds = append(f.Kinds, k)
	}
	sort.Strings(f.Kinds)
	f.Denied = e.quarantineLocked(p, ev)
	e.matches[p.ID]++
	return f, true
}

// newState is one actor's progress through one pack, from the first event that
// matched a signal of it.
func newState(signals int, at time.Time) *state {
	return &state{counts: make([]int, signals), kinds: map[string]bool{}, first: at}
}

// satisfied reports whether every signal has its count, and the pack's
// across_kinds its protocols. The order, where the pack asked for one, is
// already guaranteed by the staging in step.
func (e *Engine) satisfied(p *Pack, st *state) bool {
	for i := range p.Detect.Signals {
		if st.counts[i] < p.Detect.Signals[i].Count {
			return false
		}
	}
	if p.Detect.AcrossKinds > 0 && len(st.kinds) < p.Detect.AcrossKinds {
		return false
	}
	return true
}

// quarantineLocked holds the actor out where the pack and the operator both
// allow it. It reports whether the actor was held.
func (e *Engine) quarantineLocked(p *Pack, ev Event) bool {
	if !e.opts.Enforce || !p.MayDeny() {
		return false
	}
	if q, ok := e.quar[ev.Actor]; ok && q.until.After(ev.At) {
		// Already held; extend it to this pack's window rather than
		// stacking, so two packs cannot multiply one actor's quarantine.
		if until := ev.At.Add(p.Detect.Window); until.After(q.until) {
			e.quar[ev.Actor] = quarantine{pack: p.ID, until: until}
		}
		return true
	}
	if len(e.quar) >= e.bounds.MaxQuarantined {
		e.expireQuarantineLocked(ev.At)
	}
	if len(e.quar) >= e.bounds.MaxQuarantined {
		e.refused++
		return false
	}
	e.quar[ev.Actor] = quarantine{pack: p.ID, until: ev.At.Add(p.Detect.Window)}
	return true
}

func (e *Engine) expireQuarantineLocked(now time.Time) {
	for addr, q := range e.quar {
		if !q.until.After(now) {
			delete(e.quar, addr)
		}
	}
}

// Quarantined reports whether an actor is held out, and by which pack. It is
// what a listener's admission path asks, and it answers false on a nil engine
// and whenever enforcement is off.
func (e *Engine) Quarantined(addr netip.Addr) (string, bool) {
	if e == nil || !e.opts.Enforce || !addr.IsValid() {
		return "", false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	q, ok := e.quar[addr]
	if !ok {
		return "", false
	}
	if !q.until.After(e.now()) {
		delete(e.quar, addr)
		return "", false
	}
	return q.pack, true
}

// Release lifts a quarantine, which is what an operator does when the laptop
// that tripped a pack turns out to be the commissioning engineer's. It reports
// whether there was one.
func (e *Engine) Release(addr netip.Addr) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.quar[addr]; !ok {
		return false
	}
	delete(e.quar, addr)
	return true
}

// evictOldestLocked drops the least recently seen actor. It reports whether it
// found one, which it always does with a non-empty table.
func (e *Engine) evictOldestLocked() bool {
	var oldest netip.Addr
	var at time.Time
	for addr, a := range e.actors {
		if at.IsZero() || a.seen.Before(at) {
			oldest, at = addr, a.seen
		}
	}
	if !oldest.IsValid() {
		return false
	}
	delete(e.actors, oldest)
	e.evicted++
	return true
}

// Status is what a view shows.
type Status struct {
	// Packs is how many are in force, and Actors how many have state.
	Packs  int `json:"packs"`
	Actors int `json:"actors"`
	// Enforcing says the packs that declare deny may quarantine.
	Enforcing bool `json:"enforcing"`
	// Quarantined is how many actors are held out now.
	Quarantined int `json:"quarantined"`
	// Evicted is actors dropped for the bound, and Refused quarantines not
	// taken for theirs. Both mean the picture is incomplete, which is worth
	// saying rather than leaving somebody to trust a table that lost rows.
	Evicted uint64 `json:"evicted,omitempty"`
	Refused uint64 `json:"quarantines_refused,omitempty"`
	// Matches is per pack identifier.
	Matches map[string]uint64 `json:"matches,omitempty"`
}

// Status reads the engine's own numbers.
func (e *Engine) Status() Status {
	if e == nil {
		return Status{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Packs: len(e.packs), Actors: len(e.actors), Enforcing: e.opts.Enforce,
		Evicted: e.evicted, Refused: e.refused}
	now := e.now()
	for _, q := range e.quar {
		if q.until.After(now) {
			st.Quarantined++
		}
	}
	if len(e.matches) > 0 {
		st.Matches = make(map[string]uint64, len(e.matches))
		for k, v := range e.matches {
			st.Matches[k] = v
		}
	}
	return st
}
