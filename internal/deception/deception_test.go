package deception

import (
	"net/netip"
	"testing"
	"time"
)

// A fabricated value has to survive a second look. These are the
// properties that make it look like a process rather than a random number
// generator, and each one is a way a decoy gets found out.
func TestAValueIsStableAndThenMoves(t *testing.T) {
	v := NewValues(SeedFor("plant"), time.Minute, []Band{
		{Lo: 0, Hi: 99, Shape: ShapeAnalogue, Min: 1000, Max: 2000},
	})
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	v.SetClockForTest(func() time.Time { return at })

	first := v.Register(1, 42)
	if got := v.Register(1, 42); got != first {
		t.Errorf("two reads in the same period disagreed: %d then %d", first, got)
	}
	if first < 1000 || first > 2000 {
		t.Errorf("%d is outside the band", first)
	}
	// A different address is a different point, and the spread across the
	// band is the assertion: if the address only moved the value inside
	// the drift window, every register on the device would read within a
	// per cent or two of every other, which no plant looks like.
	lo, hi := first, first
	for addr := range 100 {
		v := v.Register(1, addr)
		lo, hi = min(lo, v), max(hi, v)
	}
	if int(hi)-int(lo) < 500 {
		t.Errorf("100 addresses span %d of a 1000-wide band, so the address barely decides the value",
			int(hi)-int(lo))
	}
	// And every one of them is inside the band, over several periods: a
	// value that leaves its range is a reading an engineer would query.
	for p := range 5 {
		at = at.Add(time.Minute)
		for addr := range 100 {
			if got := v.Register(1, addr); got < 1000 || got > 2000 {
				t.Fatalf("period %d address %d answered %d, outside the band", p, addr, got)
			}
		}
	}
	at = at.Add(-5 * time.Minute)
	// A period later it has moved, and not by much: a measurement that
	// swings across its range every minute is not a measurement.
	at = at.Add(time.Minute)
	later := v.Register(1, 42)
	if later == first {
		t.Error("nothing moved in a whole period")
	}
	if d := int(later) - int(first); d > 40 || d < -40 {
		t.Errorf("it moved %d in one period, which is not a process", d)
	}
	// And the same unit is not the same device: two units answering
	// identically is a gateway with one PLC behind it pretending to be
	// eight. Nor do they drift together, which is the same tell one step
	// further in.
	if v.Register(2, 42) == first {
		t.Error("two units answered the same value at the same address")
	}
	before := make([]uint16, 8)
	for u := range before {
		before[u] = v.Register(byte(u+1), 7)
	}
	at = at.Add(time.Minute)
	up, down := 0, 0
	for u := range before {
		switch after := v.Register(byte(u+1), 7); {
		case after > before[u]:
			up++
		case after < before[u]:
			down++
		}
	}
	if up == 0 || down == 0 {
		t.Errorf("eight units drifted the same way (%d up, %d down), so one process is driving all of them",
			up, down)
	}
	// Nor do the addresses of one unit drift together. Every register on a
	// device moving by the same amount at the same instant is the same
	// tell one level down.
	was := make([]uint16, 32)
	for addr := range was {
		was[addr] = v.Register(1, addr+200)
	}
	at = at.Add(time.Minute)
	deltas := map[int]bool{}
	for addr := range was {
		deltas[int(v.Register(1, addr+200))-int(was[addr])] = true
	}
	if len(deltas) < 4 {
		t.Errorf("32 addresses moved by %d distinct amounts, so one offset is moving all of them", len(deltas))
	}
}

// A totaliser that goes backwards is the tell that ends the pretence.
func TestACounterOnlyIncreases(t *testing.T) {
	v := NewValues(1, time.Second, []Band{{Lo: 0, Hi: 10, Shape: ShapeCounter, Rate: 5}})
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	v.SetClockForTest(func() time.Time { return at })
	last := v.Register(1, 3)
	wrapped := false
	for range 50 {
		at = at.Add(time.Second)
		next := v.Register(1, 3)
		switch {
		case next == last:
			t.Fatal("a counter stood still for a whole period")
		case next < last:
			// One wrap is what a 16-bit totaliser does; a second would
			// mean it is not counting.
			if wrapped {
				t.Fatalf("the counter went backwards twice: %d then %d", last, next)
			}
			wrapped = true
		case next-last != 5:
			t.Fatalf("the counter moved %d, want the rate of 5", next-last)
		}
		last = next
	}
}

// A bit that changes every time it is read is a bit nothing drives.
func TestADiscreteBitHolds(t *testing.T) {
	v := NewValues(2, time.Second, []Band{{Lo: 0, Hi: 999, Shape: ShapeDiscrete}})
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	v.SetClockForTest(func() time.Time { return at })
	before := make([]bool, 200)
	for i := range before {
		before[i] = v.Bit(1, i)
	}
	at = at.Add(time.Second)
	changed := 0
	for i := range before {
		if v.Bit(1, i) != before[i] {
			changed++
		}
	}
	if changed > 40 {
		t.Errorf("%d of 200 bits changed in one second", changed)
	}
	// Over a long enough run some of them do move, or the plant is off.
	at = at.Add(time.Hour)
	moved := 0
	for i := range before {
		if v.Bit(1, i) != before[i] {
			moved++
		}
	}
	if moved == 0 {
		t.Error("no bit moved in an hour")
	}
	// A discrete register is the bit as 0 or 1, and it is *the* bit: a
	// register that answers zero while the coil at the same address
	// answers one is a device contradicting itself.
	ones := 0
	for addr := range 200 {
		got := v.Register(1, addr)
		if got > 1 {
			t.Fatalf("a discrete register answered %d", got)
		}
		if (got == 1) != v.Bit(1, addr) {
			t.Fatalf("address %d: register %d, bit %v", addr, got, v.Bit(1, addr))
		}
		if got == 1 {
			ones++
		}
	}
	if ones == 0 || ones == 200 {
		t.Errorf("%d of 200 discrete registers are set, so they are not bits", ones)
	}
}

// The same seed is the same device: a fabricated PLC whose serial number
// changes when the proxy restarts is one somebody has noticed.
func TestTheSameSeedIsTheSameDevice(t *testing.T) {
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	mk := func(seed uint64) *Values {
		v := NewValues(seed, time.Minute, nil)
		v.SetClockForTest(func() time.Time { return at })
		return v
	}
	a, b, other := mk(7), mk(7), mk(8)
	for addr := range 20 {
		if a.Register(1, addr) != b.Register(1, addr) {
			t.Fatalf("two devices on one seed disagreed at %d", addr)
		}
	}
	same := 0
	for addr := range 20 {
		if a.Register(1, addr) == other.Register(1, addr) {
			same++
		}
	}
	if same > 4 {
		t.Errorf("%d of 20 addresses agree across seeds, so the seed decides little", same)
	}
	if SeedFor("plant") == SeedFor("other") {
		t.Error("two listener names derive the same seed")
	}
}

// Each address is in the band that covers it. A device whose second band
// behaved like its first would be a device whose totalisers are
// measurements, which is a shape no plant has.
func TestEachAddressIsInItsOwnBand(t *testing.T) {
	v := NewValues(11, time.Second, []Band{
		{Lo: 0, Hi: 99, Shape: ShapeAnalogue, Min: 100, Max: 200},
		{Lo: 100, Hi: 199, Shape: ShapeCounter, Rate: 4},
		{Lo: 200, Hi: 299, Shape: ShapeDiscrete},
	})
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	v.SetClockForTest(func() time.Time { return at })

	analogue, counter, discrete := v.Register(1, 50), v.Register(1, 150), v.Register(1, 250)
	if analogue < 100 || analogue > 200 {
		t.Errorf("the analogue band answered %d, outside 100..200", analogue)
	}
	if discrete > 1 {
		t.Errorf("the discrete band answered %d", discrete)
	}
	// The counter is the one that says the band was chosen by coverage
	// rather than by order: it adds its rate every period, and the
	// analogue address beside it does not.
	at = at.Add(time.Second)
	if got := v.Register(1, 150); got-counter != 4 {
		t.Errorf("the counter band moved %d in one period, want its rate of 4", got-counter)
	}
	if got := v.Register(1, 50); got < 100 || got > 200 {
		t.Errorf("the analogue band answered %d after a period, outside 100..200", got)
	}
}

// The guards at the edges of the derivation are here because the numbers
// come from a configuration: a band written the wrong way round is the
// sort of mistake that happens exactly once.
func TestTheDerivationHoldsAtItsEdges(t *testing.T) {
	// A negative index would otherwise convert to a number near 2^64 and
	// answer from somewhere unrelated in the address space.
	if got := nonneg(-1); got != 0 {
		t.Errorf("nonneg(-1) = %d", got)
	}
	if got := nonneg(7); got != 7 {
		t.Errorf("nonneg(7) = %d", got)
	}
	// And a modulus of zero is a division by zero rather than a value.
	if got := reduce(12345, 0); got != 0 {
		t.Errorf("reduce(_, 0) = %d", got)
	}
	if got := reduce(12345, -5); got != 0 {
		t.Errorf("reduce(_, -5) = %d", got)
	}
	if got := reduce(12345, 10); got < 0 || got > 9 {
		t.Errorf("reduce(_, 10) = %d", got)
	}
}

// An address outside every band still answers: refusing one address in the
// middle of a range is how a scanner finds the edges of the fabrication.
func TestAnAddressOutsideEveryBandStillAnswers(t *testing.T) {
	v := NewValues(3, time.Minute, []Band{
		{Lo: 0, Hi: 9, Shape: ShapeAnalogue, Min: 5, Max: 9},
		{Lo: 10, Hi: 19, Shape: ShapeCounter, Rate: 1},
	})
	if got := v.Register(1, 5); got < 5 || got > 9 {
		t.Errorf("inside the first band: %d", got)
	}
	// Past the last band it is answered as the device's last kind of
	// register rather than refused.
	if got := v.Register(1, 5000); got == 0 {
		t.Log("a counter can legitimately be zero here")
	}
	// A band whose range is the wrong way round is read as no range at
	// all rather than as an empty one: a device whose every register
	// answers the same number is not a device.
	bad := NewValues(4, time.Minute, []Band{{Lo: 0, Hi: 9, Shape: ShapeAnalogue, Min: 900, Max: 100}})
	seen := map[uint16]bool{}
	for addr := range 10 {
		got := bad.Register(1, addr)
		if got > 27648 {
			t.Errorf("a reversed band answered %d", got)
		}
		seen[got] = true
	}
	if len(seen) < 5 {
		t.Errorf("a reversed band answered %d distinct values across ten addresses", len(seen))
	}
	// And no bands at all is a device rather than an error.
	if got := NewValues(5, 0, nil).Register(1, 1); got > 27648 {
		t.Errorf("the default band answered %d", got)
	}
}

// The client list decides who is lied to, and an empty one is everybody --
// which only a caller that has checked it is safe may ask for.
func TestTheClientListDecides(t *testing.T) {
	p := NewPolicy([]netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}, 0)
	if !p.Admits(netip.MustParseAddr("10.9.0.7")) {
		t.Error("a client inside the list was not admitted")
	}
	if p.Admits(netip.MustParseAddr("10.8.0.7")) {
		t.Error("a client outside the list was admitted")
	}
	if p.Anyone() {
		t.Error("a policy with a list says it admits anybody")
	}
	open := NewPolicy(nil, 0)
	if !open.Admits(netip.MustParseAddr("192.0.2.1")) || !open.Anyone() {
		t.Error("an empty list is not everybody")
	}
	var nilP *Policy
	if nilP.Admits(netip.MustParseAddr("192.0.2.1")) || nilP.Anyone() {
		t.Error("a nil policy admits somebody")
	}
	nilP.Record(netip.MustParseAddr("192.0.2.1"), true, time.Now())
	if nilP.Clients(0) != nil {
		t.Error("a nil policy has visitors")
	}
}

// The visitor record is what an operator reads, and it is bounded,
// because the addresses in it come off the network: a scan from a whole
// subnet is the case that would otherwise grow it without limit.
func TestTheVisitorRecordIsBoundedAndKeepsTheRecent(t *testing.T) {
	p := NewPolicy(nil, 4)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	for i := range 20 {
		p.Record(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), i%5 == 0, at.Add(time.Duration(i)*time.Second))
	}
	got := p.Clients(0)
	if len(got) != 4 {
		t.Fatalf("%d visitors kept, want the bound of 4", len(got))
	}
	// The ones kept are the most recent four, not any four: the question
	// the record answers is who is probing now.
	want := map[string]bool{"10.0.0.16": true, "10.0.0.17": true, "10.0.0.18": true, "10.0.0.19": true}
	for _, c := range got {
		if !want[c.Addr.String()] {
			t.Errorf("%s was kept over a more recent visitor", c.Addr)
		}
	}
	// And the list is newest first.
	if got[0].Addr.String() != "10.0.0.19" {
		t.Errorf("the newest visitor is %s", got[0].Addr)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Last.After(got[i-1].Last) {
			t.Error("the list is not newest first")
		}
	}
	if p.Served() != 20 {
		t.Errorf("served %d, want 20", p.Served())
	}
	if p.Tripped() != 4 {
		t.Errorf("tripped %d, want 4", p.Tripped())
	}
	// A client seen twice is one visitor with two frames.
	one := netip.MustParseAddr("10.1.0.1")
	p.Record(one, false, at)
	p.Record(one, true, at.Add(time.Second))
	for _, c := range p.Clients(0) {
		if c.Addr != one {
			continue
		}
		if c.Frames != 2 || c.Tripped != 1 {
			t.Errorf("the repeat visitor is %+v", c)
		}
		if c.FirstSeen == "" || c.LastSeen == "" {
			t.Error("the visitor has no timestamps in the view")
		}
	}
	if n := len(p.Clients(2)); n != 2 {
		t.Errorf("a limit of 2 returned %d", n)
	}
}

// The values are taken modulo a small range, which is the low bits of the
// hash, so the hash's low bits have to be good. Before the finaliser they
// were not: a band a thousand wide answered only between 1443 and 1889
// across a hundred addresses, and every register reading inside the middle
// half of its range is the statistical tell that ends a pretence.
func TestTheValuesFillTheirBand(t *testing.T) {
	v := NewValues(SeedFor("plant"), time.Minute, []Band{
		{Lo: 0, Hi: 999, Shape: ShapeAnalogue, Min: 1000, Max: 2000},
	})
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	v.SetClockForTest(func() time.Time { return at })

	// Ten buckets across the band, and every one of them holds something:
	// a generator that leaves a tenth of the range empty is one a
	// histogram finds.
	buckets := make([]int, 10)
	for addr := range 1000 {
		got := int(v.Register(1, addr))
		i := (got - 1000) * 10 / 1001
		if i < 0 || i > 9 {
			t.Fatalf("address %d answered %d, outside the band", addr, got)
		}
		buckets[i]++
	}
	for i, n := range buckets {
		// A uniform thousand over ten buckets is a hundred each. Anything
		// under a third of that is a hole rather than noise.
		if n < 33 {
			t.Errorf("bucket %d of the band holds %d of 1000 values: %v", i, n, buckets)
		}
	}
}
