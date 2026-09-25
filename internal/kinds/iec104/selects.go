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
type selects struct {
	mu    sync.Mutex
	held  map[selectKey]time.Time
	max   int
	ttl   time.Duration
	now   func() time.Time
	drops uint64
}

// selectKey is what makes two commands the same command: the station, the
// point, the type, and the connection that asked.
type selectKey struct {
	session uint64
	common  uint16
	addr    uint32
	typ     wire.Type
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

// key builds the identity of a command from a frame, for one session.
// A command with no address names no point and cannot be selected.
func key(session uint64, a *wire.ASDU) (selectKey, bool) {
	if a == nil || len(a.Addresses) == 0 {
		return selectKey{}, false
	}
	return selectKey{session: session, common: a.Common, addr: a.Addresses[0], typ: a.Type}, true
}

// Select records a selection. It returns false when the table is full,
// which the caller treats as a refusal rather than as permission: a bound
// that let a command through would be a bound that disabled the check.
func (s *selects) Select(session uint64, a *wire.ASDU) bool {
	k, ok := key(session, a)
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

// Take consumes a selection: it says whether this execute was selected,
// and removes the selection either way, because a selection authorises one
// execution and not a stream of them.
func (s *selects) Take(session uint64, a *wire.ASDU) bool {
	k, ok := key(session, a)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until, held := s.held[k]
	if !held {
		return false
	}
	delete(s.held, k)
	return s.now().Before(until)
}

// Release drops a selection without executing it, which is what a
// deactivation is: the controlling station thinking better of it.
func (s *selects) Release(session uint64, a *wire.ASDU) {
	if k, ok := key(session, a); ok {
		s.mu.Lock()
		delete(s.held, k)
		s.mu.Unlock()
	}
}

// Close drops every selection a session held. A selection that outlived its
// connection would let a later client execute on an earlier one's
// intention, which is precisely the injection this check exists to stop.
func (s *selects) Close(session uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.held {
		if k.session == session {
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

// seqState follows one direction's sequence numbers.
//
// This protocol numbers every I frame in both directions, and the numbering
// is the only thing in it that can detect a lost, duplicated or replayed
// frame. A station's send sequence number must be the next one after the
// last; its receive sequence number must not acknowledge a frame that was
// never sent; and the number of frames it has outstanding must not exceed
// k, the sending window the two ends agreed on.
//
// A relay can check all three because it sees both directions, and none of
// the three is something a substation gateway reliably enforces.
type seqState struct {
	// send is the next send sequence number expected from this side,
	// and known says whether anything has arrived yet.
	send  uint16
	known bool
	// acked is the highest send sequence number the *peer* has
	// acknowledged, which is what bounds the outstanding window.
	acked uint16
	// sent counts the frames this side has sent, for the window check.
	sent uint64
	// ackedCount is how many of them the peer has acknowledged.
	ackedCount uint64
}

// next is the sequence number that may follow one, wrapping at the
// protocol's 15-bit space.
func nextSeq(v uint16) uint16 { return (v + 1) % wire.MaxSeq }

// observe records an I frame arriving from this side and says what, if
// anything, is wrong with its numbering.
//
// A gap moves the state to what arrived, so one gap is one refusal rather
// than every frame after it: a relay that refused for ever after a single
// lost frame would take a substation off the air until somebody restarted
// the link.
func (s *seqState) observe(send uint16, k int) string {
	defer func() {
		s.send = nextSeq(send)
		s.known = true
		s.sent++
	}()
	if !s.known {
		// The first frame on a connection sets the expectation. A station
		// that starts at a number other than zero is unusual and not
		// wrong: the numbering survives a STOPDT and a STARTDT.
		return ""
	}
	if send != s.send {
		return "iec104_sequence"
	}
	if k > 0 && s.sent-s.ackedCount >= uint64(k) {
		// The sending window is full and this frame is one too many. It
		// is what a station does when it has stopped listening to the
		// acknowledgements, and what a flood looks like on this protocol.
		return "iec104_window"
	}
	return ""
}

// acknowledge records the receive sequence number a frame from the *other*
// side carried, which is what releases the window.
func (s *seqState) acknowledge(recv uint16, peerSent uint64) string {
	// A receive sequence number ahead of what the peer has actually sent
	// acknowledges a frame that does not exist, which is either a
	// confused implementation or an attempt to open the window.
	ahead := int64(recv) - int64(s.acked)
	if ahead < 0 {
		ahead += wire.MaxSeq
	}
	if uint64(ahead) > peerSent-s.ackedCount {
		return "iec104_ack_ahead"
	}
	s.acked = recv
	s.ackedCount += uint64(ahead)
	return ""
}
