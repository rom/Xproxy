package modbus

import (
	"fmt"
	"sort"
	"strings"
	"time"

	wire "github.com/rom/xproxy/internal/modbus"
)

// The process baseline: what a value normally is, and how fast it normally
// moves.
//
// A learning run used to produce allow-lists -- which client, which unit, which
// function, which addresses -- and one value span per *subject*. That span is at
// the wrong grain to be a bound, and the proposal built from it was looser than
// the traffic it claimed to come from: a master writing a 0..40 bar setpoint at
// register 100 and a 0..3 mode at register 200 produced `values: [{min: 0, max:
// 40}]`, which permits setting the mode to 40. An engineer who pasted that got a
// value policy that was wrong in a way that looked derived from evidence, which
// is worse than having none.
//
// So the envelope is recorded per address, and with it the two things a
// rate-of-change policy is written from:
//
//	max_delta   the largest jump between consecutive writes this relay saw
//	rate        the most writes seen in any one minute
//
// **A baseline is where a conversation starts and not a control.** It is derived
// from traffic, and traffic is what an attacker who was already there has been
// shaping. A run on a plant that has been quietly driven out of its envelope for
// a month learns the wider envelope. That is why this is a report an engineer
// reads against the drawings rather than a policy that installs itself, and why
// the report says so in as many words.

const (
	// maxBaselinePoints bounds the addresses whose baseline is remembered, over
	// the whole listener. A master sweeping the address space would otherwise
	// make the report as large as the space.
	maxBaselinePoints = 4096
	// baselineWindow is the period a write rate is counted over. A minute,
	// because "twice a minute" is how a plant engineer says it, and because a
	// shorter window would call a pair of writes a burst.
	baselineWindow = time.Minute
)

// baselineKey is one address on one device. The client is deliberately not in
// it: a value's envelope is a property of the *point*, and splitting it per
// master would propose a different bound for the same register depending on who
// wrote it -- which is not how a process works.
type baselineKey struct {
	unit  byte
	addr  int
	coils bool
}

// baselinePoint is what was seen at one address.
type baselinePoint struct {
	// min and max are the envelope of the register values written. For coils,
	// set and cleared say which ways it was driven.
	min, max     int
	haveValue    bool
	set, cleared bool
	writes       uint64
	// maxDelta is the largest step between consecutive writes. It is what
	// `max_delta` is written from, and it is only meaningful between writes
	// this relay saw: a value moved by another master or by the process is not
	// on this path, which is the same honest limit the runtime check has.
	maxDelta int
	last     int
	haveLast bool
	// window is the sliding minute of write times, and peak the most writes
	// ever inside one. A sliding window rather than a counter per minute,
	// because a burst that straddles a minute boundary is still a burst.
	window []time.Time
	peak   int
}

// baselines is the per-listener table of points.
//
// It is separate from the learner's subject table because the two are keyed
// differently and bounded differently: a subject is a client doing a thing, and
// a point is a place in a device.
type baselines struct {
	points  map[baselineKey]*baselinePoint
	order   []baselineKey
	dropped uint64
}

func newBaselines() *baselines {
	return &baselines{points: map[baselineKey]*baselinePoint{}}
}

// observe records the writes one request carried.
//
// Only writes. A read tells this relay what the value *is*, which is useful to
// the runtime delta check and useless to a baseline of what a master may write:
// a bound proposed from values the process produced would permit a master to
// write anything the plant ever reached on its own.
func (b *baselines) observe(unit byte, p *wire.PDU, now time.Time) {
	if b == nil || p == nil {
		return
	}
	lo, hi, ok := writeSpan(p)
	if !ok || hi < 0 {
		return
	}
	// The coils are recorded whatever the code: code 5 is excluded below, and
	// what it says about the coil is still true.
	var regs []uint16
	if carriesValues(p.Function) {
		regs = p.Registers
	}
	for i, v := range regs {
		b.at(baselineKey{unit: unit, addr: lo + i}, now, func(pt *baselinePoint) {
			val := int(v)
			if !pt.haveValue {
				pt.min, pt.max, pt.haveValue = val, val, true
			}
			if val < pt.min {
				pt.min = val
			}
			if val > pt.max {
				pt.max = val
			}
			if pt.haveLast {
				if d := abs(val - pt.last); d > pt.maxDelta {
					pt.maxDelta = d
				}
			}
			pt.last, pt.haveLast = val, true
		})
	}
	for i, on := range p.Coils {
		b.at(baselineKey{unit: unit, addr: lo + i, coils: true}, now, func(pt *baselinePoint) {
			if on {
				pt.set = true
			} else {
				pt.cleared = true
			}
		})
	}
}

// carriesValues says whether a function code's Registers are values at
// consecutive addresses, which is the only thing a value envelope can be built
// from.
//
// Three function codes populate Registers with something that is not that, and
// a baseline that read them as values would propose bounds derived from
// nonsense:
//
//   - code 5 writes a coil, and Registers carries the wire encoding of the bit
//     (0xFF00 or 0x0000, section 6.5). An envelope of 65280..65280 at the coil's
//     address is not a bound anybody wants, and the coil itself is recorded on
//     the coil side below.
//   - code 22 writes an AND mask and an OR mask. They are not values at the
//     address and at the address after it -- the runtime check refuses to apply
//     a value bound to them for the same reason.
//   - code 8 is a diagnostic, whose data word is a sub-function argument. It
//     reaches here at all only because writeSpan reports "writes nothing" as
//     hi == -1, which observe now checks.
//
// That leaves the three codes that really do write values: 6, 16 and the write
// half of 23.
func carriesValues(fn byte) bool {
	switch fn {
	case wire.FCWriteSingleRegister, wire.FCWriteMultipleRegisters, wire.FCReadWriteMultiple:
		return true
	}
	return false
}

// at finds or makes a point, counts the write against its window, and applies
// the caller's update.
func (b *baselines) at(k baselineKey, now time.Time, fn func(*baselinePoint)) {
	pt := b.points[k]
	if pt == nil {
		if len(b.points) >= maxBaselinePoints {
			// The bound is reached, and the drop is counted rather than
			// silent: a report that held the first four thousand addresses
			// and none after them would be a report nobody could trust.
			b.dropped++
			return
		}
		pt = &baselinePoint{}
		b.points[k] = pt
		b.order = append(b.order, k)
	}
	pt.writes++
	pt.window = append(pt.window, now)
	cut := now.Add(-baselineWindow)
	drop := 0
	for drop < len(pt.window) && pt.window[drop].Before(cut) {
		drop++
	}
	pt.window = pt.window[drop:]
	if n := len(pt.window); n > pt.peak {
		pt.peak = n
	}
	fn(pt)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// snapshot copies the table for rendering outside the lock the learner holds.
func (b *baselines) snapshot() ([]baselineKey, []baselinePoint, uint64) {
	keys := make([]baselineKey, 0, len(b.points))
	keys = append(keys, b.order...)
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		if a.unit != c.unit {
			return a.unit < c.unit
		}
		if a.coils != c.coils {
			return !a.coils
		}
		return a.addr < c.addr
	})
	out := make([]baselinePoint, 0, len(keys))
	for _, k := range keys {
		pt := *b.points[k]
		pt.window = nil // the instants are not rendered; the peak is
		out = append(out, pt)
	}
	return keys, out, b.dropped
}

// run is a contiguous stretch of addresses on one device whose baseline is the
// same, which is what one `values` entry covers.
type run struct {
	unit   byte
	coils  bool
	lo, hi int
	pt     baselinePoint
}

// runs folds the points into the fewest entries that say the same thing.
//
// Adjacent addresses with the same envelope, the same step and the same peak are
// one entry: a report with a line per register of a forty-register block is a
// report nobody reads. Adjacent addresses that differ stay separate, which is the
// whole point of recording per address.
func runs(keys []baselineKey, pts []baselinePoint) []run {
	var out []run
	for i, k := range keys {
		pt := pts[i]
		if n := len(out); n > 0 {
			prev := &out[n-1]
			// prev.coils == k.coils is redundant against same(), which compares
			// haveValue and so never matches a coil against a register; it stays
			// because folding a coil into a register run would be wrong for a
			// reason that has nothing to do with envelopes.
			if prev.unit == k.unit && prev.coils == k.coils && prev.hi+1 == k.addr && same(prev.pt, pt) {
				prev.hi = k.addr
				continue
			}
		}
		out = append(out, run{unit: k.unit, coils: k.coils, lo: k.addr, hi: k.addr, pt: pt})
	}
	return out
}

// same is every field the entry prints. Folding on anything less prints one
// address's number for another's: two addresses with the same envelope and
// different write counts folded into one line that claims a count only one of
// them had.
func same(a, b baselinePoint) bool {
	return a.haveValue == b.haveValue && a.min == b.min && a.max == b.max &&
		a.maxDelta == b.maxDelta && a.peak == b.peak && a.writes == b.writes &&
		a.set == b.set && a.cleared == b.cleared
}

// renderBaselines writes the observed section and the proposed `values` block.
func renderBaselines(b *strings.Builder, keys []baselineKey, pts []baselinePoint, dropped uint64) {
	if len(keys) == 0 {
		return
	}
	rs := runs(keys, pts)
	b.WriteString("\n# What the values themselves were, per address. This is the part a value\n")
	b.WriteString("# policy is written from, and the part the old per-subject span got wrong:\n")
	b.WriteString("# one span for every register a master touched permits the narrow ones to be\n")
	b.WriteString("# set to the widest one's limit.\n")
	b.WriteString("#\n")
	b.WriteString("# A BASELINE IS WHERE A CONVERSATION STARTS AND NOT A CONTROL. It is derived\n")
	b.WriteString("# from traffic, and traffic is what somebody who was already inside has been\n")
	b.WriteString("# shaping: a run on a plant that has been quietly driven out of its envelope\n")
	b.WriteString("# for a month learns the wider envelope. Read every line below against the\n")
	b.WriteString("# drawings and the instrument ranges before pasting any of it.\n")
	if dropped > 0 {
		fmt.Fprintf(b, "#\n# %d addresses were dropped at the bound of %d, so this is not every\n"+
			"# address that was written.\n", dropped, maxBaselinePoints)
	}
	b.WriteString("\nobserved_values:\n")
	for _, r := range rs {
		fmt.Fprintf(b, "  - unit: %d\n", r.unit)
		fmt.Fprintf(b, "    %s: %s\n", addrKey(r.coils), rangeText(r.lo, r.hi))
		fmt.Fprintf(b, "    writes: %d\n", r.pt.writes)
		if r.coils {
			fmt.Fprintf(b, "    driven: {set: %t, cleared: %t}\n", r.pt.set, r.pt.cleared)
		}
		if r.pt.haveValue {
			fmt.Fprintf(b, "    value_seen: {min: %d, max: %d}\n", r.pt.min, r.pt.max)
			fmt.Fprintf(b, "    largest_step: %d\n", r.pt.maxDelta)
		}
		fmt.Fprintf(b, "    peak_writes_per_minute: %d\n", r.pt.peak)
	}

	b.WriteString("\n# The same, as the value policy would be written. A value policy belongs to a\n")
	b.WriteString("# rule, not to the listener, so this block is pasted as the `values:` of the\n")
	b.WriteString("# rule that allows the writes -- under modbus.rules[].values -- and only once\n")
	b.WriteString("# the numbers have been checked against the plant.\n")
	b.WriteString("values:\n")
	n := 0
	for _, r := range rs {
		if r.coils {
			// A coil has no envelope and no step -- redundant against the
			// haveValue check below, and kept because it carries the reason.
			// What is worth saying about one
			// is which ways it was driven, and `transitions` is the key for
			// that -- but a transition list learned from traffic is a list of
			// the transitions that happened, and proposing "this coil may only
			// be set" from a run where nobody cleared it would refuse the reset
			// somebody needs at three in the morning. So the observation above
			// stands on its own and no rule is proposed.
			continue
		}
		if !r.pt.haveValue {
			continue
		}
		n++
		fmt.Fprintf(b, "  - registers: %s\n", rangeText(r.lo, r.hi))
		fmt.Fprintf(b, "    min: %d\n", r.pt.min)
		fmt.Fprintf(b, "    max: %d\n", r.pt.max)
		if r.pt.maxDelta > 0 {
			fmt.Fprintf(b, "    max_delta: %d\n", r.pt.maxDelta)
		} else {
			b.WriteString("    # Every write carried the same value, so no step was observed and\n")
			b.WriteString("    # max_delta is left out: a max_delta of 0 would refuse every change.\n")
		}
		if r.pt.peak > 0 {
			fmt.Fprintf(b, "    rate: {max: %d, period: 1m}\n", r.pt.peak)
		}
	}
	if n == 0 {
		b.WriteString("  []\n")
	}
}

func addrKey(coils bool) string {
	if coils {
		return "coils"
	}
	return "registers"
}

func rangeText(lo, hi int) string {
	if lo == hi {
		return fmt.Sprintf("%q", fmt.Sprintf("%d", lo))
	}
	return fmt.Sprintf("%q", fmt.Sprintf("%d-%d", lo, hi))
}
