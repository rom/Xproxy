package anomaly

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	master  = netip.MustParseAddr("10.30.1.20")
	scanner = netip.MustParseAddr("10.90.0.7")
	epoch   = time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
)

// reasons are the findings' reasons, for a compact assertion.
func reasons(fs []Finding) string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Reason)
	}
	return strings.Join(out, ",")
}

func newSet(t *testing.T, p Policy) *Set {
	t.Helper()
	s, err := New(p, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("no detector was built from a policy with a model enabled")
	}
	return s
}

// A policy with nothing enabled builds no detector, and one that enabled
// the detector and every model off is refused rather than defaulted -- it
// is the mistake somebody spends an afternoon on.
func TestAPolicyWithNothingToDetect(t *testing.T) {
	s, err := New(Policy{}, epoch)
	if err != nil {
		t.Fatalf("an empty policy should be no detector, not an error: %v", err)
	}
	if s != nil {
		t.Error("an empty policy built a detector")
	}
	// A nil detector answers nothing and records nothing.
	if got := s.Observe(Event{Actor: master, Symbol: "read"}); got != nil {
		t.Errorf("a nil detector reported %v", got)
	}
	if st := s.Status(); st.Actors != 0 || len(st.Models) != 0 {
		t.Errorf("a nil detector's status is %+v", st)
	}
}

func TestSettlingIsQuietAndThenIsNot(t *testing.T) {
	s := newSet(t, Policy{Settle: 10 * time.Minute,
		Novelty: Novelty{Symbols: true, WritePoints: true}})
	// During the settling window everything is learned and nothing said.
	for i, sym := range []string{"read_holding", "read_input", "write_single"} {
		at := epoch.Add(time.Duration(i) * time.Minute)
		if fs := s.Observe(Event{Actor: master, Symbol: sym, Write: sym == "write_single",
			Point: "40001", At: at}); len(fs) != 0 {
			t.Errorf("%s during settling reported %s", sym, reasons(fs))
		}
	}
	// After it, a symbol this peer has not used is reported once.
	after := epoch.Add(20 * time.Minute)
	fs := s.Observe(Event{Actor: master, Symbol: "write_multiple", Write: true,
		Point: "40010", At: after})
	if got := reasons(fs); got != ReasonNewSymbol+","+ReasonNewWritePoint {
		t.Fatalf("findings %q", got)
	}
	// And only once: it has been seen now.
	if fs := s.Observe(Event{Actor: master, Symbol: "write_multiple", Write: true,
		Point: "40010", At: after.Add(time.Second)}); len(fs) != 0 {
		t.Errorf("the second sighting reported %s", reasons(fs))
	}
}

func TestTheWriteBurstIsNotSuppressedWhileSettling(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Hour,
		Novelty: Novelty{Burst: 5, Period: 10 * time.Second}})
	var got []Finding
	for i := range 6 {
		got = s.Observe(Event{Actor: scanner, Symbol: "write_single", Write: true,
			Point: "4000" + string(rune('0'+i)), At: epoch.Add(time.Duration(i) * time.Second)})
	}
	if reasons(got) != ReasonWriteBurst {
		t.Fatalf("a burst inside the settling window reported %q: the bound is a number an operator set, not something learned", reasons(got))
	}
	// One burst is one finding rather than one per request for as long as
	// it lasts.
	if fs := s.Observe(Event{Actor: scanner, Symbol: "write_single", Write: true,
		Point: "40099", At: epoch.Add(7 * time.Second)}); len(fs) != 0 {
		t.Errorf("the next write in the same burst reported %s", reasons(fs))
	}
}

// The cycle model: a rhythm learned, then a rhythm that changed.
func TestTheCycleModelLearnsAndReportsAChange(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Cycle: Cycle{Enabled: true, MinSamples: 20, Tolerance: 6}})
	at := epoch
	// A poller with a two-second cycle and a little jitter.
	for i := range 40 {
		step := 2 * time.Second
		if i%3 == 0 {
			step += 30 * time.Millisecond
		}
		at = at.Add(step)
		if fs := s.Observe(Event{Actor: master, Symbol: "read_holding", At: at}); len(fs) != 0 {
			t.Fatalf("a steady cycle reported %s at sample %d", reasons(fs), i)
		}
	}
	// Then it starts asking twenty times a second.
	at = at.Add(50 * time.Millisecond)
	fs := s.Observe(Event{Actor: master, Symbol: "read_holding", At: at})
	if reasons(fs) != ReasonCycleChanged {
		t.Fatalf("a cycle that changed reported %q", reasons(fs))
	}
	if !strings.Contains(fs[0].Detail, "learned") {
		t.Errorf("the finding does not say what was learned: %q", fs[0].Detail)
	}
	// Rate limited: not one finding per request until the new rhythm is
	// learned.
	at = at.Add(50 * time.Millisecond)
	if fs := s.Observe(Event{Actor: master, Symbol: "read_holding", At: at}); len(fs) != 0 {
		t.Errorf("the next request in the changed cycle reported %s", reasons(fs))
	}
}

func TestTheCycleModelIsQuietUntilItHasARhythm(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Cycle: Cycle{Enabled: true, MinSamples: 20}})
	at := epoch
	// Ten wildly irregular requests, which is not a rhythm and must not
	// be reported as a broken one.
	for i, step := range []time.Duration{time.Second, 30 * time.Millisecond, 4 * time.Second,
		200 * time.Millisecond, 9 * time.Second, time.Second, 50 * time.Millisecond,
		3 * time.Second, 700 * time.Millisecond, 2 * time.Second} {
		at = at.Add(step)
		if fs := s.Observe(Event{Actor: master, Symbol: "read", At: at}); len(fs) != 0 {
			t.Errorf("sample %d reported %s before a rhythm was learned", i, reasons(fs))
		}
	}
}

// The sequence model: a transition nobody has made.
func TestTheSequenceModelReportsAnUnseenTransition(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Sequence: Sequence{Enabled: true, MinSamples: 20}})
	at := epoch
	// A panel that reads, reads, writes, reads, for ever.
	for range 10 {
		for _, sym := range []string{"read", "read", "write", "read"} {
			at = at.Add(time.Second)
			if fs := s.Observe(Event{Actor: master, Symbol: sym, At: at}); len(fs) != 0 {
				t.Fatalf("the learned round reported %s", reasons(fs))
			}
		}
	}
	// A write straight after a write has never happened here.
	at = at.Add(time.Second)
	if fs := s.Observe(Event{Actor: master, Symbol: "write", At: at}); len(fs) != 0 {
		t.Fatalf("read->write is known, so this should be quiet: %s", reasons(fs))
	}
	at = at.Add(time.Second)
	fs := s.Observe(Event{Actor: master, Symbol: "write", At: at})
	if reasons(fs) != ReasonSequenceUnseen {
		t.Fatalf("write following write reported %q", reasons(fs))
	}
	if !strings.Contains(fs[0].Detail, "never followed") {
		t.Errorf("detail %q", fs[0].Detail)
	}
}

// The talkers model: a peer nobody has seen, and a peer on a device it has
// never touched.
func TestTheTalkersModel(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Talkers: Talkers{Enabled: true, ReadyAfter: 15 * time.Minute}})
	// In the first minutes of a process every peer is new, and reporting
	// that is how an operator learns to ignore the alerts.
	if fs := s.Observe(Event{Actor: master, Symbol: "read", Device: "unit 1",
		At: epoch.Add(time.Minute)}); len(fs) != 0 {
		t.Errorf("a peer in the first minute reported %s", reasons(fs))
	}
	// After the listener has settled, a new peer is worth saying.
	late := epoch.Add(30 * time.Minute)
	fs := s.Observe(Event{Actor: scanner, Symbol: "read", Device: "unit 1", At: late})
	if reasons(fs) != ReasonNewTalker {
		t.Fatalf("a new peer reported %q", reasons(fs))
	}
	// Its first device is the pair, not a new pair.
	if fs := s.Observe(Event{Actor: scanner, Symbol: "read", Device: "unit 1",
		At: late.Add(time.Second)}); len(fs) != 0 {
		t.Errorf("the same device reported %s", reasons(fs))
	}
	// A second device is.
	fs = s.Observe(Event{Actor: scanner, Symbol: "read", Device: "unit 7", At: late.Add(2 * time.Second)})
	if reasons(fs) != ReasonNewPair {
		t.Fatalf("a device this peer has never touched reported %q", reasons(fs))
	}
}

// The telemetry model: a point that stopped moving, and a run of readings
// that repeats. Both are what a plant looks like when the control room is
// being shown a recording.
func TestTheTelemetryModelReportsAFrozenPoint(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Telemetry: Telemetry{Enabled: true, FrozenSamples: 6}})
	at := epoch
	// A moving temperature.
	for i, v := range []float64{20.1, 20.3, 20.2, 20.4, 20.5} {
		at = at.Add(time.Second)
		if fs := s.Observe(Event{Actor: master, Symbol: "read", Point: "30001",
			Value: v, HasValue: true, At: at}); len(fs) != 0 {
			t.Fatalf("reading %d reported %s", i, reasons(fs))
		}
	}
	// Then it stops. The finding comes when the run reaches the bound, not
	// on the last reading, so every round's findings are collected.
	var got []Finding
	for range 6 {
		at = at.Add(time.Second)
		got = append(got, s.Observe(Event{Actor: master, Symbol: "read", Point: "30001",
			Value: 20.5, HasValue: true, At: at})...)
	}
	if reasons(got) != ReasonTelemetryFrozen {
		t.Fatalf("a frozen point reported %q", reasons(got))
	}
	// One stuck point is one finding.
	at = at.Add(time.Second)
	if fs := s.Observe(Event{Actor: master, Symbol: "read", Point: "30001",
		Value: 20.5, HasValue: true, At: at}); len(fs) != 0 {
		t.Errorf("the next identical reading reported %s", reasons(fs))
	}
	// And a point that never moved is not reported: a constant is not
	// necessarily a lie, and a relay that alerted on every constant would
	// alert on every status bit.
	s2 := newSet(t, Policy{Settle: time.Nanosecond, Telemetry: Telemetry{Enabled: true, FrozenSamples: 4}})
	for i := range 10 {
		if fs := s2.Observe(Event{Actor: master, Symbol: "read", Point: "30002",
			Value: 1, HasValue: true, At: epoch.Add(time.Duration(i) * time.Second)}); len(fs) != 0 {
			t.Fatalf("a point that never moved reported %s", reasons(fs))
		}
	}
}

func TestTheTelemetryModelReportsAReplayedRun(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Telemetry: Telemetry{Enabled: true, ReplayWindow: 4}})
	run := []float64{10, 11, 12, 13}
	at := epoch
	var got []Finding
	for range 2 {
		for _, v := range run {
			at = at.Add(time.Second)
			got = append(got, s.Observe(Event{Actor: master, Symbol: "read", Point: "30003",
				Value: v, HasValue: true, At: at})...)
		}
	}
	if reasons(got) != ReasonTelemetryReplayed {
		t.Fatalf("a repeated run reported %q", reasons(got))
	}
	// A constant run is frozen rather than replayed, and reporting it as
	// both would be one fact twice.
	s2 := newSet(t, Policy{Settle: time.Nanosecond, Telemetry: Telemetry{Enabled: true,
		ReplayWindow: 4, FrozenSamples: 60}})
	for i := range 12 {
		if fs := s2.Observe(Event{Actor: master, Symbol: "read", Point: "30004",
			Value: 7, HasValue: true, At: epoch.Add(time.Duration(i) * time.Second)}); len(fs) != 0 {
			t.Fatalf("a constant reported %s as a replay", reasons(fs))
		}
	}
}

// The correlation model: two points that are supposed to track each other.
func TestTheCorrelationModel(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Correlations: []Correlation{{
		Name: "pump-and-flow", A: "flow", B: "speed", Ratio: 2, Tolerance: 0.1,
		MaxAge: time.Minute}}})
	at := epoch
	// Speed 100, flow 200: as expected.
	s.Observe(Event{Actor: master, Point: "speed", Value: 100, HasValue: true, At: at})
	at = at.Add(time.Second)
	if fs := s.Observe(Event{Actor: master, Point: "flow", Value: 200, HasValue: true, At: at}); len(fs) != 0 {
		t.Fatalf("a pair that tracks reported %s", reasons(fs))
	}
	// The pump is told to run at 100 and the flow meter says 20: either
	// the plant is broken or somebody is writing a number.
	at = at.Add(time.Second)
	fs := s.Observe(Event{Actor: master, Point: "flow", Value: 20, HasValue: true, At: at})
	if reasons(fs) != ReasonCorrelationBroken {
		t.Fatalf("a broken pair reported %q", reasons(fs))
	}
	if !strings.Contains(fs[0].Detail, "pump-and-flow") {
		t.Errorf("the finding does not name the pair: %q", fs[0].Detail)
	}
	// A reading with nothing recent to compare against says nothing: a
	// relay only has the values that crossed it.
	old := at.Add(10 * time.Minute)
	if fs := s.Observe(Event{Actor: master, Point: "flow", Value: 0, HasValue: true, At: old}); len(fs) != 0 {
		t.Errorf("a stale pair was compared anyway: %s", reasons(fs))
	}
}

func TestTheCorrelationModelChecksADifference(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Correlations: []Correlation{{
		Name: "two-thermocouples", A: "t1", B: "t2", Difference: 5, MaxAge: time.Minute}}})
	at := epoch
	s.Observe(Event{Actor: master, Point: "t1", Value: 300, HasValue: true, At: at})
	at = at.Add(time.Second)
	if fs := s.Observe(Event{Actor: master, Point: "t2", Value: 302, HasValue: true, At: at}); len(fs) != 0 {
		t.Fatalf("two degrees apart reported %s", reasons(fs))
	}
	at = at.Add(time.Second)
	if fs := s.Observe(Event{Actor: master, Point: "t2", Value: 340, HasValue: true, At: at}); reasons(fs) != ReasonCorrelationBroken {
		t.Fatalf("forty degrees apart reported %q", reasons(fs))
	}
}

// A refused policy is better than a policy that silently checks nothing.
func TestTheCorrelationConfigurationIsChecked(t *testing.T) {
	for _, c := range []struct {
		what string
		corr Correlation
	}{
		{"no name", Correlation{A: "a", B: "b", Ratio: 1}},
		{"one point", Correlation{Name: "x", A: "a", Ratio: 1}},
		{"a point with itself", Correlation{Name: "x", A: "a", B: "a", Ratio: 1}},
		{"nothing to check", Correlation{Name: "x", A: "a", B: "b"}},
		{"a negative ratio", Correlation{Name: "x", A: "a", B: "b", Ratio: -1}},
	} {
		p := Policy{Correlations: []Correlation{c.corr}}
		if _, err := New(p, epoch); err == nil {
			t.Errorf("%s was accepted", c.what)
		}
	}
	// Two pairs with one name is a report nobody can read.
	p := Policy{Correlations: []Correlation{
		{Name: "x", A: "a", B: "b", Ratio: 1},
		{Name: "x", A: "c", B: "d", Ratio: 1},
	}}
	if _, err := New(p, epoch); err == nil {
		t.Error("two correlations with one name were accepted")
	}
}

func TestAReplayWindowThatWouldReportEveryOscillation(t *testing.T) {
	if _, err := New(Policy{Telemetry: Telemetry{Enabled: true, ReplayWindow: 2}}, epoch); err == nil {
		t.Error("a replay window of two was accepted")
	}
	if _, err := New(Policy{Telemetry: Telemetry{Enabled: true, ReplayWindow: 64}}, epoch); err == nil {
		t.Error("a replay window that cannot fit twice in the history was accepted")
	}
}

// The bounds, and the blinding they cause, which is the failure mode this
// package is most careful about: a detector that quietly stopped detecting.
func TestABoundBlindsRatherThanWidening(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, Novelty: Novelty{Symbols: true, MaxSymbols: 3}})
	at := epoch
	for i := range 6 {
		at = at.Add(time.Second)
		s.Observe(Event{Actor: scanner, Symbol: "sym" + string(rune('a'+i)), At: at})
	}
	st := s.Status()
	if st.Blinded == 0 {
		t.Error("a peer past its symbol bound was not counted as blinded")
	}
	// And nothing new is claimed about it afterwards, rather than the set
	// being widened.
	at = at.Add(time.Second)
	if fs := s.Observe(Event{Actor: scanner, Symbol: "something-else", At: at}); len(fs) != 0 {
		t.Errorf("a blinded peer still reported %s", reasons(fs))
	}
}

func TestTheActorsAreBoundedAndTheOldestGoes(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, MaxActors: 2, Novelty: Novelty{Symbols: true}})
	at := epoch
	for i := range 4 {
		at = at.Add(time.Second)
		s.Observe(Event{Actor: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), Symbol: "read", At: at})
	}
	st := s.Status()
	if st.Actors > 2 {
		t.Errorf("%d actors held against a bound of 2", st.Actors)
	}
	if st.Dropped == 0 {
		t.Error("the evictions were not counted")
	}
}

func TestTheStatusNamesTheModelsThatAreOn(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond,
		Novelty:      Novelty{Symbols: true},
		Cycle:        Cycle{Enabled: true},
		Telemetry:    Telemetry{Enabled: true},
		Correlations: []Correlation{{Name: "x", A: "a", B: "b", Ratio: 1}}})
	got := strings.Join(s.Status().Models, ",")
	if got != "correlation,cycle,novelty,telemetry" {
		t.Errorf("models %q", got)
	}
}

// Every finding's reason is one this package declares, so the mapping in
// internal/attack and the documentation can be held against a list.
func TestEveryReasonIsDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, r := range Reasons() {
		declared[r] = true
	}
	s := newSet(t, Policy{Settle: time.Nanosecond,
		Novelty:   Novelty{Symbols: true, WritePoints: true, Burst: 2, Period: time.Minute},
		Cycle:     Cycle{Enabled: true, MinSamples: 2},
		Sequence:  Sequence{Enabled: true},
		Talkers:   Talkers{Enabled: true, ReadyAfter: time.Nanosecond},
		Telemetry: Telemetry{Enabled: true, FrozenSamples: 4, ReplayWindow: 4},
		Correlations: []Correlation{{Name: "pair", A: "p1", B: "p2",
			Difference: 1, MaxAge: time.Minute}}})
	at := epoch.Add(time.Hour)
	seen := map[string]bool{}
	// Enough traffic to make every model speak at least once.
	for i := range 40 {
		at = at.Add(time.Duration(200+i*7) * time.Millisecond)
		for _, e := range []Event{
			{Actor: scanner, Symbol: "s" + string(rune('a'+i%5)), Device: "d" + string(rune('a'+i%3)),
				Write: i%2 == 0, Point: "p" + string(rune('a'+i%4)), At: at},
			{Actor: scanner, Point: "p1", Value: float64(i % 3), HasValue: true, At: at},
			{Actor: scanner, Point: "p2", Value: float64(100 * (i % 2)), HasValue: true, At: at},
		} {
			for _, f := range s.Observe(e) {
				if !declared[f.Reason] {
					t.Errorf("undeclared reason %q from model %s", f.Reason, f.Model)
				}
				seen[f.Reason] = true
			}
		}
	}
	if len(seen) < 5 {
		t.Errorf("only %d of the reasons were reachable: %v", len(seen), seen)
	}
}

// A detector is written to by every connection of a listener.
func TestConcurrentUse(t *testing.T) {
	s := newSet(t, Policy{Settle: time.Nanosecond, MaxActors: 32,
		Novelty:   Novelty{Symbols: true, WritePoints: true, Burst: 4, Period: time.Second},
		Cycle:     Cycle{Enabled: true, MinSamples: 5},
		Sequence:  Sequence{Enabled: true},
		Talkers:   Talkers{Enabled: true, ReadyAfter: time.Nanosecond},
		Telemetry: Telemetry{Enabled: true}})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := netip.AddrFrom4([4]byte{10, 1, 0, byte(i)})
			for j := range 300 {
				s.Observe(Event{Actor: a, Symbol: "s" + string(rune('a'+j%7)),
					Device: "d", Write: j%3 == 0, Point: "p" + string(rune('a'+j%5)),
					Value: float64(j % 11), HasValue: true})
				_ = s.Status()
			}
		}(i)
	}
	wg.Wait()
}
