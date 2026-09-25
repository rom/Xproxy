package modbus

import (
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/numrange"
)

// The value state is what makes a Modbus policy about the process rather
// than about the frame.
//
// A range bound answers "may this value be written at all". The three
// checks here answer the questions a plant actually asks, and each of
// them needs to know what the value is now:
//
//	max_delta       may this value move this far in one step
//	transitions     may this value go from what it is to what is asked
//	require_before  was the confirming register set first, recently
//
// Plus a rate, which needs to know when the address was last written.
//
// What "what the value is now" means here is the honest limit of all
// four: it is the last value *this relay saw*, from a write it forwarded
// or a read it relayed back. A value changed by another master, by a
// local panel or by the process itself was never on this path, so the
// relay does not know it -- which is why a rule that needs one says what
// to do when there is none (on_unknown), and why the range bound, which
// needs nothing, is the one that always holds.

// MaxValuePoints bounds the addresses whose value is remembered.
const MaxValuePoints = 65536

// point is one address on one device.
type point struct {
	unit byte
	addr int
}

// observed is the last value seen at a point.
type observed struct {
	value int
	at    time.Time
	// writtenAt is when a master last wrote it through this relay, which
	// is what a rate bound counts; a read does not move it.
	writtenAt time.Time
	// writes are the times of the recent writes, oldest first, bounded by
	// the largest rate a rule asks for. A sliding window rather than a
	// token bucket, because "once a minute" in a plant means once in the
	// last minute and not a bucket that refills at a sixtieth a second.
	writes []time.Time
	// byClient is the same window per master, kept only when a rule asks
	// for per_client.
	byClient map[netip.Addr][]time.Time
}

// valueState remembers what the relay has seen. It is per listener.
type valueState struct {
	mu     sync.Mutex
	points map[point]*observed
	max    int
	// Unknown counts the checks that needed a value the relay did not
	// have, so an operator can see how often a policy is running on less
	// than it asks for.
	Unknown, Dropped uint64
}

func newValueState(max int) *valueState {
	if max <= 0 || max > MaxValuePoints {
		max = MaxValuePoints
	}
	return &valueState{points: map[point]*observed{}, max: max}
}

// Observe records values seen at consecutive addresses. write says the
// values were written by a master rather than read from the device.
func (v *valueState) Observe(unit byte, base int, vals []uint16, write bool, client netip.Addr, now time.Time) {
	if v == nil || len(vals) == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for i, raw := range vals {
		p := point{unit: unit, addr: base + i}
		o := v.points[p]
		if o == nil {
			if len(v.points) >= v.max {
				v.Dropped++
				continue
			}
			o = &observed{}
			v.points[p] = o
		}
		o.value, o.at = int(raw), now
		if write {
			o.writtenAt = now
			o.writes = append(o.writes, now)
			if len(o.writes) > 64 {
				o.writes = append([]time.Time(nil), o.writes[len(o.writes)-64:]...)
			}
			if client.IsValid() {
				if o.byClient == nil {
					o.byClient = map[netip.Addr][]time.Time{}
				}
				// A master already counted keeps being counted; a new one
				// is only added while there is room, because the masters
				// come off the network like everything else here.
				w, counted := o.byClient[client]
				if counted || len(o.byClient) < 64 {
					w = append(w, now)
					if len(w) > 64 {
						w = append([]time.Time(nil), w[len(w)-64:]...)
					}
					o.byClient[client] = w
				}
			}
		}
	}
}

// ObserveCoils records coil states as 0 and 1, so the same delta,
// transition and rate machinery covers them.
func (v *valueState) ObserveCoils(unit byte, base int, on []bool, write bool, client netip.Addr, now time.Time) {
	if v == nil || len(on) == 0 {
		return
	}
	vals := make([]uint16, len(on))
	for i, b := range on {
		if b {
			vals[i] = 1
		}
	}
	v.Observe(unit, base, vals, write, client, now)
}

// Forget drops what is known about an address, for a write whose effect
// on the value this relay cannot compute -- a masked write, where the
// result depends on what the register held inside the device.
func (v *valueState) Forget(unit byte, addr int) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if o := v.points[point{unit: unit, addr: addr}]; o != nil {
		o.at = time.Time{}
	}
}

// Last is the value last seen at an address, and whether one was.
func (v *valueState) Last(unit byte, addr int) (int, time.Time, bool) {
	if v == nil {
		return 0, time.Time{}, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	o := v.points[point{unit: unit, addr: addr}]
	if o == nil || o.at.IsZero() {
		return 0, time.Time{}, false
	}
	return o.value, o.at, true
}

// WritesIn is how many writes this relay has forwarded to an address
// within the window, optionally counting only one master's.
func (v *valueState) WritesIn(unit byte, addr int, window time.Duration, client netip.Addr, perClient bool, now time.Time) int {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	o := v.points[point{unit: unit, addr: addr}]
	if o == nil {
		return 0
	}
	times := o.writes
	if perClient {
		times = o.byClient[client]
	}
	cut := now.Add(-window)
	n := 0
	for _, t := range times {
		if t.After(cut) {
			n++
		}
	}
	return n
}

// Selected reports whether a select register holds the value a
// precondition asks for, written recently enough.
func (v *valueState) Selected(unit byte, addrs numrange.Set, equals int, within time.Duration, now time.Time) bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for p, o := range v.points {
		if p.unit != unit || !addrs.Has(p.addr) {
			continue
		}
		// The select has to have been *written*, not merely read back:
		// a register a poll happens to find at 1 is not somebody
		// confirming an operation.
		if o.value == equals && !o.writtenAt.IsZero() && now.Sub(o.writtenAt) <= within {
			return true
		}
	}
	return false
}

// Len is how many addresses are remembered, for the status view.
func (v *valueState) Len() int {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.points)
}
