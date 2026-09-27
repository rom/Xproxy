package iec104

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
)

// The value bound is the half of an IEC 104 policy that is about the
// process. Every test here is one way a bound could silently cover nothing,
// because a bound an operator has written and that decides nothing is worse
// than no bound: they stop watching the point.

func f64(v float64) *float64 { return &v }

// scaled builds a C_SE_NB_1 setpoint the way it arrives on the wire, and
// parses it, so these tests exercise the same path a frame takes.
func scaled(t *testing.T, common uint16, ioa uint32, val int16, sel bool) *wire.ASDU {
	t.Helper()
	q := byte(0)
	if sel {
		q |= 0x80
	}
	var v [2]byte
	binary.LittleEndian.PutUint16(v[:], uint16(val))
	return parseSetpoint(t, wire.CSeNB1, wire.CauseActivation, common, ioa, []byte{v[0], v[1], q})
}

// shortFloat builds a C_SE_NC_1, which is the encoding that can carry NaN
// and the infinities.
func shortFloat(t *testing.T, common uint16, ioa uint32, val float32) *wire.ASDU {
	t.Helper()
	var v [4]byte
	binary.LittleEndian.PutUint32(v[:], math.Float32bits(val))
	return parseSetpoint(t, wire.CSeNC1, wire.CauseActivation, common, ioa,
		[]byte{v[0], v[1], v[2], v[3], 0})
}

// normalised builds a C_SE_NA_1, whose value is a fraction of a full scale
// this relay cannot see.
func normalised(t *testing.T, common uint16, ioa uint32, raw int16) *wire.ASDU {
	t.Helper()
	var v [2]byte
	binary.LittleEndian.PutUint16(v[:], uint16(raw))
	return parseSetpoint(t, wire.CSeNA1, wire.CauseActivation, common, ioa, []byte{v[0], v[1], 0})
}

func parseSetpoint(t *testing.T, ty wire.Type, cause wire.Cause, common uint16, ioa uint32, elem []byte) *wire.ASDU {
	t.Helper()
	b := []byte{byte(ty), 1, byte(cause), 0}
	b = binary.LittleEndian.AppendUint16(b, common)
	b = append(b, byte(ioa), byte(ioa>>8), byte(ioa>>16))
	b = append(b, elem...)
	a, err := wire.ParseASDU(b)
	if err != nil {
		t.Fatalf("ParseASDU: %v", err)
	}
	return a
}

func boundedPolicy(t *testing.T, sp ...config.IEC104Setpoint) *Policy {
	t.Helper()
	return policyOf(t, &config.IEC104Listener{DefaultAction: "allow", Setpoints: sp})
}

// The range is the half that needs nothing, so it is the half that always
// holds: a value outside it is refused whether or not the relay knows where
// the point was.
func TestTheValueRangeHolds(t *testing.T) {
	t.Parallel()
	p := boundedPolicy(t, config.IEC104Setpoint{
		Name: "pressure", Points: []string{"4711"}, Min: f64(0), Max: f64(40),
	})
	for _, c := range []struct {
		val   int16
		allow bool
	}{{0, true}, {40, true}, {20, true}, {41, false}, {-1, false}, {900, false}, {-32768, false}} {
		d := p.Setpoint(scaled(t, 1, 4711, c.val, false))
		if d.Allow != c.allow {
			t.Errorf("value %d: allow=%v, want %v (%s)", c.val, d.Allow, c.allow, d.Reason)
		}
		if !c.allow && d.Reason != "iec104_setpoint_range" {
			t.Errorf("value %d: reason %q", c.val, d.Reason)
		}
		if d.Rule != "pressure" {
			t.Errorf("value %d: the bound did not name itself: %q", c.val, d.Rule)
		}
	}
}

// A short float can carry NaN and the infinities, and every comparison with
// NaN is false -- so a bound that only asked "below min or above max" would
// pass NaN straight through to a governor.
func TestANotANumberIsOutsideEveryBound(t *testing.T) {
	t.Parallel()
	p := boundedPolicy(t, config.IEC104Setpoint{
		Name: "governor", Points: []string{"100"}, Min: f64(-1000), Max: f64(1000),
	})
	for what, val := range map[string]float32{
		"NaN":               float32(math.NaN()),
		"+Inf":              float32(math.Inf(1)),
		"-Inf":              float32(math.Inf(-1)),
		"a number in range": 12.5,
	} {
		d := p.Setpoint(shortFloat(t, 1, 100, val))
		want := what == "a number in range"
		if d.Allow != want {
			t.Errorf("%s: allow=%v, want %v", what, d.Allow, want)
		}
	}
}

// The delta is the half that needs to know where the point was, and what
// that means here is the last value this relay saw.
func TestTheDeltaIsMeasuredFromTheLastValueSeen(t *testing.T) {
	t.Parallel()
	p := boundedPolicy(t, config.IEC104Setpoint{
		Name: "tap", Points: []string{"4711"}, Min: f64(0), Max: f64(40), MaxDelta: 5,
	})
	// Nothing is known yet, so on_unknown decides -- and its default is
	// allow with the range still in force.
	if d := p.Setpoint(scaled(t, 1, 4711, 20, false)); !d.Allow {
		t.Fatalf("the first command was refused: %+v", d)
	}
	p.state.Observe(scaled(t, 1, 4711, 20, false), 20)
	for _, c := range []struct {
		val   int16
		allow bool
	}{{20, true}, {25, true}, {15, true}, {26, false}, {14, false}, {40, false}} {
		d := p.Setpoint(scaled(t, 1, 4711, c.val, false))
		if d.Allow != c.allow {
			t.Errorf("20 -> %d: allow=%v, want %v (%s)", c.val, d.Allow, c.allow, d.Reason)
		}
		if !c.allow && d.Reason != "iec104_setpoint_delta" {
			t.Errorf("20 -> %d: reason %q", c.val, d.Reason)
		}
	}
}

// on_unknown is a real choice rather than a default to accept, so both
// answers have to be reachable.
func TestOnUnknownDecidesTheFirstCommand(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		on    string
		allow bool
	}{{"", true}, {"allow", true}, {"refuse", false}} {
		p := boundedPolicy(t, config.IEC104Setpoint{
			Name: "tap", Points: []string{"4711"}, Min: f64(0), Max: f64(40),
			MaxDelta: 5, OnUnknown: c.on,
		})
		d := p.Setpoint(scaled(t, 1, 4711, 20, false))
		if d.Allow != c.allow {
			t.Errorf("on_unknown %q: allow=%v, want %v (%s)", c.on, d.Allow, c.allow, d.Reason)
		}
		if !c.allow && d.Reason != "iec104_setpoint_unknown" {
			t.Errorf("on_unknown %q: reason %q", c.on, d.Reason)
		}
		// Either way the check that ran without a value is counted: a
		// policy running on less than it asks for should be visible.
		if _, unknowns, _ := p.state.Status(); unknowns != 1 {
			t.Errorf("on_unknown %q: %d unknown checks counted", c.on, unknowns)
		}
		// And the range still holds when the delta could not be checked,
		// which is the point of checking it first.
		if d := p.Setpoint(scaled(t, 1, 4711, 900, false)); d.Allow {
			t.Errorf("on_unknown %q: an out-of-range value rode on an unknown previous value", c.on)
		}
	}
}

// A bound narrows by every field it names. Each of these is a way an
// operator writes "this bound is about that point on that station in that
// encoding", and a matcher that quietly matched everything would turn a
// narrow bound into a wide one.
func TestABoundNarrowsByEveryFieldItNames(t *testing.T) {
	t.Parallel()
	p := boundedPolicy(t, config.IEC104Setpoint{
		Name: "pressure", Points: []string{"4700-4799"}, CommonAddresses: []string{"1-2"},
		Types: []string{"C_SE_NB_1"}, Min: f64(0), Max: f64(40),
	})
	if d := p.Setpoint(scaled(t, 1, 4711, 900, false)); d.Allow {
		t.Fatalf("the bound did not hold on its own traffic: %+v", d)
	}
	// The same out-of-range value outside each of the three: no bound is
	// about it, so this check says nothing and the rules decide.
	for what, a := range map[string]*wire.ASDU{
		"another station":  scaled(t, 9, 4711, 900, false),
		"another point":    scaled(t, 1, 9999, 900, false),
		"another encoding": shortFloat(t, 1, 4711, 900),
	} {
		if d := p.Setpoint(a); !d.Allow || d.Rule != "" {
			t.Errorf("%s was decided by a bound that does not cover it: %+v", what, d)
		}
	}
}

// The first bound that covers a point decides, so a narrow bound written
// above a wide one is the way to make an exception.
func TestTheFirstBoundThatCoversThePointDecides(t *testing.T) {
	t.Parallel()
	p := boundedPolicy(t,
		config.IEC104Setpoint{Name: "one point", Points: []string{"4711"}, Min: f64(0), Max: f64(100)},
		config.IEC104Setpoint{Name: "the rest", Points: []string{"4000-4999"}, Min: f64(0), Max: f64(40)},
	)
	if d := p.Setpoint(scaled(t, 1, 4711, 90, false)); !d.Allow || d.Rule != "one point" {
		t.Fatalf("the narrower bound did not decide: %+v", d)
	}
	if d := p.Setpoint(scaled(t, 1, 4712, 90, false)); d.Allow || d.Rule != "the rest" {
		t.Fatalf("the wider bound did not decide the other point: %+v", d)
	}
}

// A selection carries the value too, so it is bounded: refusing the select
// refuses the value before the station is asked to hold it.
func TestASelectionIsBoundedLikeAnExecute(t *testing.T) {
	t.Parallel()
	p := boundedPolicy(t, config.IEC104Setpoint{
		Name: "pressure", Points: []string{"4711"}, Min: f64(0), Max: f64(40),
	})
	if d := p.Setpoint(scaled(t, 1, 4711, 900, true)); d.Allow {
		t.Fatalf("a selection carried a value no execute could: %+v", d)
	}
}

// The encoding is part of a point's identity, because the values are not
// comparable across it: a normalised fraction and a scaled integer are two
// different quantities, and a delta computed between them would be
// arithmetic on nothing.
func TestTheEncodingIsPartOfAPointsIdentity(t *testing.T) {
	t.Parallel()
	p := boundedPolicy(t,
		config.IEC104Setpoint{Name: "fraction", Points: []string{"4711"},
			Types: []string{"C_SE_NA_1"}, Min: f64(-1), Max: f64(1), MaxDelta: 0.1},
		config.IEC104Setpoint{Name: "engineering", Points: []string{"4711"},
			Types: []string{"C_SE_NB_1"}, Min: f64(0), Max: f64(40), MaxDelta: 5},
	)
	// A scaled 20 is remembered for the scaled point and says nothing
	// about the normalised one, whose command is decided by on_unknown.
	p.state.Observe(scaled(t, 1, 4711, 20, false), 20)
	if _, known := p.state.Last(normalised(t, 1, 4711, 16384)); known {
		t.Fatal("a scaled value was read back as a normalised one")
	}
	if d := p.Setpoint(normalised(t, 1, 4711, 16384)); !d.Allow || d.Rule != "fraction" {
		t.Fatalf("the normalised bound did not decide: %+v", d)
	}
	// The timed form of the same encoding *is* the same point: a station
	// commanded with a timestamp is not a different setpoint.
	timed := parseSetpoint(t, wire.CSeTB1, wire.CauseActivation, 1, 4711,
		[]byte{22, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if v, known := p.state.Last(timed); !known || v != 20 {
		t.Fatalf("the timed form did not share the point's memory: %v %v", v, known)
	}
}

// The relay's idea of a value comes from what it forwarded and from what the
// station confirmed. Both matter, and a negative confirmation has to undo
// the first: the command did not take effect, so a delta measured from it
// would be measured from a value the equipment refused.
func TestWhatTheRelayLearnsAboutAPoint(t *testing.T) {
	t.Parallel()
	st := newSetpointState(0)
	a := scaled(t, 1, 4711, 20, false)
	st.Observe(a, 20)
	if v, known := st.Last(a); !known || v != 20 {
		t.Fatalf("a forwarded setpoint was not remembered: %v %v", v, known)
	}
	st.Forget(a)
	if _, known := st.Last(a); known {
		t.Fatal("a contradicted value was still remembered")
	}
	// NaN is never remembered: a delta measured from it is NaN, and NaN
	// compares false against every bound.
	st.Observe(shortFloat(t, 1, 100, float32(math.NaN())), math.NaN())
	if _, known := st.Last(shortFloat(t, 1, 100, 0)); known {
		t.Fatal("a NaN was remembered as a value")
	}
	// A setpoint naming no point cannot be remembered, and asking about one
	// is not an answer.
	if _, known := st.Last(&wire.ASDU{Type: wire.CSeNB1}); known {
		t.Fatal("a command with no address had a remembered value")
	}
}

// What a frame teaches the relay, frame by frame. The selection is the
// important row: a relay that learned from selections could be walked
// anywhere, each step measured from the last selection and none of them ever
// executed.
func TestWhichFramesTeachTheRelayAValue(t *testing.T) {
	t.Parallel()
	exec := scaled(t, 1, 4711, 20, false)
	sel := scaled(t, 1, 4711, 20, true)
	con := parseSetpoint(t, wire.CSeNB1, wire.CauseActCon, 1, 4711, []byte{20, 0, 0})
	neg := parseSetpoint(t, wire.CSeNB1, wire.CauseActCon, 1, 4711, []byte{20, 0, 0})
	neg.Negative = true
	negTerm := parseSetpoint(t, wire.CSeNB1, wire.CauseActTerm, 1, 4711, []byte{20, 0, 0})
	negTerm.Negative = true
	deact := parseSetpoint(t, wire.CSeNB1, wire.CauseDeactivation, 1, 4711, []byte{20, 0, 0})
	for _, c := range []struct {
		what       string
		a          *wire.ASDU
		fromClient bool
		want       setpointEffect
	}{
		{"an execute from the centre", exec, true, learnValue},
		{"a selection from the centre", sel, true, learnNothing},
		{"a deactivation", deact, true, learnNothing},
		{"the station's confirmation", con, false, learnValue},
		{"a negative confirmation", neg, false, learnForget},
		{"a negative termination", negTerm, false, learnForget},
		{"a command echoed back as an activation", exec, false, learnNothing},
		{"not a setpoint at all", sc(1, 4321, wire.CauseActivation, false), true, learnNothing},
		{"nothing", nil, true, learnNothing},
	} {
		if got := setpointLearned(c.a, c.fromClient); got != c.want {
			t.Errorf("%s: effect %v, want %v", c.what, got, c.want)
		}
	}
}

// The table of remembered points is bounded, and a full table drops rather
// than grows. A point it could not remember is a delta check that runs
// without a previous value, which on_unknown decides -- the bound is never
// the thing that lets a command through unchecked.
func TestTheRememberedPointsAreBounded(t *testing.T) {
	t.Parallel()
	st := newSetpointState(2)
	for ioa := uint32(1); ioa <= 5; ioa++ {
		st.Observe(scaled(t, 1, ioa, 10, false), 10)
	}
	held, _, dropped := st.Status()
	if held != 2 || dropped != 3 {
		t.Fatalf("held %d, dropped %d: the bound did not hold", held, dropped)
	}
	// A point already remembered keeps being remembered, so a full table
	// does not freeze the points that are in it.
	st.Observe(scaled(t, 1, 1, 11, false), 11)
	if v, known := st.Last(scaled(t, 1, 1, 0, false)); !known || v != 11 {
		t.Fatalf("a remembered point stopped being updated: %v %v", v, known)
	}
}

// A listener with no bounds decides nothing here, which is what an estate
// that has not written any gets: the rules still decide who may command
// what.
func TestNoBoundsDecideNothing(t *testing.T) {
	t.Parallel()
	p := boundedPolicy(t)
	if d := p.Setpoint(shortFloat(t, 1, 100, float32(math.NaN()))); !d.Allow {
		t.Fatalf("a listener with no value bounds refused a setpoint: %+v", d)
	}
}

// Everything that can be wrong with a bound is wrong at load. A bound that
// would not do what its author meant must not start.
func TestABoundThatWouldNotWorkIsRefusedAtLoad(t *testing.T) {
	t.Parallel()
	for what, sp := range map[string]config.IEC104Setpoint{
		"no name":            {Points: []string{"1"}, Min: f64(0), Max: f64(1)},
		"no points":          {Name: "a", Min: f64(0), Max: f64(1)},
		"no min":             {Name: "a", Points: []string{"1"}, Max: f64(1)},
		"no max":             {Name: "a", Points: []string{"1"}, Min: f64(0)},
		"min above max":      {Name: "a", Points: []string{"1"}, Min: f64(10), Max: f64(1)},
		"a negative delta":   {Name: "a", Points: []string{"1"}, Min: f64(0), Max: f64(1), MaxDelta: -1},
		"an unknown answer":  {Name: "a", Points: []string{"1"}, Min: f64(0), Max: f64(1), OnUnknown: "maybe"},
		"not a type":         {Name: "a", Points: []string{"1"}, Types: []string{"C_XX_NA_1"}, Min: f64(0), Max: f64(1)},
		"a valueless type":   {Name: "a", Points: []string{"1"}, Types: []string{"C_SC_NA_1"}, Min: f64(0), Max: f64(1)},
		"a point too high":   {Name: "a", Points: []string{"16777216"}, Min: f64(0), Max: f64(1)},
		"a station too high": {Name: "a", Points: []string{"1"}, CommonAddresses: []string{"65536"}, Min: f64(0), Max: f64(1)},
		"a min that is not a number": {Name: "a", Points: []string{"1"},
			Min: f64(math.NaN()), Max: f64(math.NaN())},
	} {
		if _, err := compileSetpoints([]config.IEC104Setpoint{sp}); err == nil {
			t.Errorf("%s: compiled", what)
		}
	}
	// And two bounds cannot share a name, because a refusal nobody can
	// name is one nobody can find in a log.
	_, err := compileSetpoints([]config.IEC104Setpoint{
		{Name: "a", Points: []string{"1"}, Min: f64(0), Max: f64(1)},
		{Name: "a", Points: []string{"2"}, Min: f64(0), Max: f64(1)},
	})
	if err == nil {
		t.Error("two bounds shared a name")
	}
}

// The detail line is what an incident report is written from: a refusal that
// does not say which value, at which point, against which bound is not an
// audit trail.
func TestTheRefusalSaysWhatWasAsked(t *testing.T) {
	t.Parallel()
	a := scaled(t, 1, 4711, 900, false)
	got := setpointDetail(a, "pressure", 900)
	for _, want := range []string{"C_SE_NB_1", "ca=1", "ioa=4711", "value=900", "bound=pressure"} {
		if !contains(got, want) {
			t.Errorf("the detail %q does not say %q", got, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A bound and the policy share a clock only in so far as neither is about
// time: this is here to hold the compile path with the listener's own
// fields, so a bound cannot be added to the config and left uncompiled.
func TestTheListenerCompilesItsBounds(t *testing.T) {
	t.Parallel()
	p, err := compile(&config.IEC104Listener{
		Setpoints: []config.IEC104Setpoint{{
			Name: "pressure", Points: []string{"4711"}, Min: f64(0), Max: f64(40),
		}},
	}, time.Now)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(p.setpoints) != 1 || p.state == nil {
		t.Fatalf("the listener's bounds were not compiled: %+v", p.setpoints)
	}
}
