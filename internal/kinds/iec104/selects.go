package iec104

import (
	"sync"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
)

// Select-before-operate is the one safety property this protocol describes
// and the equipment mostly does not enforce.
//
// The standard's two-step command is: the controlling station sends an
// activation with the select bit set, naming a point; the station answers;
// then the same command arrives again *without* the bit, and only then does
// the equipment act. It exists so that an operator's intention is confirmed
// before a breaker moves, and so that a single corrupted or injected frame
// cannot operate anything.
//
// In practice a great many RTUs accept a bare execute. So a relay that
// remembers the selections is the only thing in the path that can require
// the two steps -- and requiring them turns a single injected frame from an
// operation into a refusal.
//
// What is remembered is deliberately narrow: a selection belongs to the
// *connection* that made it, to one common address and one information
// object address, and to the type identification, and it expires. A
// selection that outlived its connection would let a later client ride on
// an earlier one's intention; a selection that never expired would let an
// execute sent hours later operate a breaker somebody selected and thought
// better of.
//
// The one case where a selection does outlive its connection is a declared
// redundancy group, where the operator has said which connections are one
// controlling station and a failover between the select and the execute
// would otherwise refuse a legitimate command. See redundancy.go for what
// keeps that from being a hole: the group's selection can only be consumed
// by whichever of its connections currently holds data transfer.
type selects struct {
	mu    sync.Mutex
	held  map[selectKey]time.Time
	max   int
	ttl   time.Duration
	now   func() time.Time
	drops uint64
}

// selectOwner is who a selection belongs to: one connection, or -- where a
// redundancy group has said its connections are one controlling station and
// carries selections across them -- the group.
//
// The group name is carried even when the session owns the selection,
// because it is what lets a refusal say *which* refusal it is: an execute
// with no selection anywhere is somebody sending a bare command, and an
// execute whose selection was made on another connection in the same group
// is a failover that dropped it. Those are different things and an operator
// needs to be told which one happened.
type selectOwner struct {
	group   string
	session uint64
}

// selectKey is what makes two commands the same command: the station, the
// point, the type, and whoever asked.
type selectKey struct {
	owner  selectOwner
	common uint16
	addr   uint32
	typ    wire.Type
}

func newSelects(max int, ttl time.Duration, now func() time.Time) *selects {
	if max <= 0 {
		max = 4096
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &selects{held: map[selectKey]time.Time{}, max: max, ttl: ttl, now: now}
}

// key builds the identity of a command from a frame, for one owner.
// A command with no address names no point and cannot be selected.
func key(owner selectOwner, a *wire.ASDU) (selectKey, bool) {
	if a == nil || len(a.Addresses) == 0 {
		return selectKey{}, false
	}
	return selectKey{owner: owner, common: a.Common, addr: a.Addresses[0], typ: a.Type}, true
}

// Select records a selection. It returns false when the table is full,
// which the caller treats as a refusal rather than as permission: a bound
// that let a command through would be a bound that disabled the check.
func (s *selects) Select(owner selectOwner, a *wire.ASDU) bool {
	k, ok := key(owner, a)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if _, held := s.held[k]; !held && len(s.held) >= s.max {
		// Sweep what has expired before giving up: a full table is
		// usually a table full of selections nobody executed.
		s.expireLocked(now)
		if len(s.held) >= s.max {
			s.drops++
			return false
		}
	}
	s.held[k] = now.Add(s.ttl)
	return true
}

// Taken is what a Take found, because the three ways an execute can fail
// to be selected are three different things to tell an operator.
type Taken int

const (
	// TakeNone is no selection for this point at all: somebody sent a bare
	// execute.
	TakeNone Taken = iota
	// TakeOK is a live selection, now consumed.
	TakeOK
	// TakeExpired is a selection that was made and whose window has passed:
	// an operator who selected a point, was interrupted, and came back to
	// it. The command is refused and the reason is not "you never selected
	// it".
	TakeExpired
	// TakeOther is a selection held for this point by another connection in
	// the same redundancy group, on a group that does not carry them across
	// a failover. This is the diagnosis that is otherwise impossible to
	// make from the outside, and the one a control room needs: the two-step
	// command was done properly and the failover in the middle dropped it.
	TakeOther
)

// Take consumes a selection: it says what it found, and removes the
// selection if it was this owner's, because a selection authorises one
// execution and not a stream of them.
func (s *selects) Take(owner selectOwner, a *wire.ASDU) Taken {
	k, ok := key(owner, a)
	if !ok {
		return TakeNone
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until, held := s.held[k]
	if !held {
		if owner.group != "" && s.elsewhereLocked(k) {
			return TakeOther
		}
		return TakeNone
	}
	delete(s.held, k)
	if s.now().Before(until) {
		return TakeOK
	}
	return TakeExpired
}

// elsewhereLocked says whether the same point is selected by another
// connection in the same redundancy group. It is only asked when this
// owner holds no selection of its own, so the answer is about a different
// connection by construction.
func (s *selects) elsewhereLocked(k selectKey) bool {
	for held := range s.held {
		if held.owner.group == k.owner.group && held.owner.session != k.owner.session &&
			held.common == k.common && held.addr == k.addr && held.typ == k.typ {
			return true
		}
	}
	return false
}

// Release drops a selection without executing it, which is what a
// deactivation is: the controlling station thinking better of it.
func (s *selects) Release(owner selectOwner, a *wire.ASDU) {
	if k, ok := key(owner, a); ok {
		s.mu.Lock()
		delete(s.held, k)
		s.mu.Unlock()
	}
}

// Close drops every selection a connection held. A selection that outlived
// its connection would let a later client execute on an earlier one's
// intention, which is precisely the injection this check exists to stop.
//
// group is the redundancy group whose carried selections go too, which is
// the empty string unless this was the group's last connection: while
// another path is still up, the selection surviving is the whole point of
// having declared the group.
func (s *selects) Close(session uint64, group string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.held {
		switch {
		case k.owner.session == session:
			delete(s.held, k)
		case group != "" && k.owner.group == group:
			delete(s.held, k)
		}
	}
}

// expireLocked removes selections whose window has passed.
func (s *selects) expireLocked(now time.Time) {
	for k, until := range s.held {
		if now.After(until) {
			delete(s.held, k)
		}
	}
}

// Status is how many selections are held and how many the bound refused.
func (s *selects) Status() (int, uint64) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.held), s.drops
}
