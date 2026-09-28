package modbus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/modbus"
)

var (
	learnDay  = time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	learnRead = []byte{3, 0x00, 0x64, 0x00, 0x0A} // read 10 registers at 100
	learnNext = []byte{3, 0x00, 0x6E, 0x00, 0x05} // read 5 registers at 110
	learnFar  = []byte{3, 0x03, 0xE8, 0x00, 0x02} // read 2 registers at 1000
	learnWrit = []byte{6, 0x01, 0x90, 0x00, 0x32} // write 50 to register 400
	learnHigh = []byte{6, 0x01, 0x90, 0x00, 0x64} // write 100 to register 400
	learnMode = []byte{6, 0x01, 0x91, 0x00, 0x02} // write 2 to register 401
)

// The report is the answer to "what is this plant's Modbus traffic": the
// subjects seen, the ranges actually used, and a rule set that permits
// exactly them.
func TestTheLearningReportIsARuleSetToStartFrom(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.7", "", 3, learnRead), true, learnDay)
	l.Observe(req(t, "10.0.0.7", "", 3, learnNext), true, learnDay.Add(time.Second))
	l.Observe(req(t, "10.0.0.7", "", 3, learnFar), true, learnDay.Add(2*time.Second))
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnHigh), true, learnDay)
	// A second register in the same subject, holding a mode rather than a
	// setpoint. This is what the per-subject span got wrong.
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnMode), true, learnDay)

	r := l.Report()
	for _, want := range []string{
		"observed:",
		"client: 10.0.0.7",
		"unit: 3",
		"function: read_holding_registers",
		"access: read",
		"frames: 3",
		// Two adjacent ranges become one, and the far one stays its own:
		// a learning run that widened 100-114 and 1000-1001 into
		// 100-1001 would be writing a policy nobody asked for.
		"addresses: [100-114, 1000-1001]",
		"role: engineer",
		"values_written: {min: 2, max: 100}",
		"rules:",
		"name: learned-10-0-0-7-u3-read_holding_registers",
		"clients: [10.0.0.7/32]",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("the report does not carry %q:\n%s", want, r)
		}
	}
	// The rule set no longer proposes a value bound, because a bound derived
	// from every register a subject touched is looser than the traffic it came
	// from: this subject wrote a 50..100 setpoint and a mode of 2, and one span
	// over both would permit setting the mode to 100. The bounds are proposed
	// per address instead, below the rules.
	_, rules, ok := strings.Cut(r, "\nrules:")
	if !ok {
		t.Fatalf("the report proposes no rules:\n%s", r)
	}
	proposal, _, _ := strings.Cut(rules, "\n# What the values themselves were")
	if strings.Contains(proposal, "values:") {
		t.Errorf("a rule still proposes a value bound from the whole subject:\n%s", proposal)
	}
	// A subject is a client, a role, a unit and a function code, not a
	// frame: three reads from one master are one subject, and the rule
	// set stays a rule set somebody reads.
	if l.Subjects() != 2 {
		t.Errorf("subjects: %d, want 2", l.Subjects())
	}
}

// A request the device itself refuses is written out of the policy rather
// than into it, so the report says so where an engineer will see it.
func TestTheReportNamesWhatTheDeviceRefused(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	r := req(t, "10.0.0.7", "", 3, learnRead)
	l.Observe(r, true, learnDay)
	l.ObserveException(r, learnDay.Add(time.Second))
	l.ObserveException(r, learnDay.Add(2*time.Second))
	out := l.Report()
	if !strings.Contains(out, "device_exceptions: 2") {
		t.Errorf("the report does not count the device's refusals:\n%s", out)
	}
	if !strings.Contains(out, `comment: "the device refused 2 of these"`) {
		t.Errorf("the rule does not say the device refused these:\n%s", out)
	}
	// An exception for a subject never seen is not a subject: a device
	// answering somebody else's request must not invent an observation.
	l2 := NewLearner("plant", "", time.Minute, 64)
	l2.ObserveException(req(t, "10.0.0.9", "", 1, learnRead), learnDay)
	if l2.Subjects() != 0 {
		t.Errorf("an exception invented a subject: %d", l2.Subjects())
	}
}

// A refusal recorded while learning is the interesting line in the
// report: it is what the policy would have broken.
func TestTheReportCountsWhatThePolicyWouldHaveRefused(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.7", "", 3, learnWrit), false, learnDay)
	if out := l.Report(); !strings.Contains(out, "denied_by_policy: 1") {
		t.Errorf("the report does not count the refusals:\n%s", out)
	}
}

// The bound is a bound, and a learning run that quietly stopped learning
// is worse than one that says so.
func TestTheSubjectBoundDropsTheOldestAndSaysSo(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 2)
	for _, unit := range []byte{1, 2, 3, 4} {
		l.Observe(req(t, "10.0.0.7", "", unit, learnRead), true, learnDay)
	}
	if l.Subjects() != 2 {
		t.Fatalf("subjects: %d, want the bound of 2", l.Subjects())
	}
	if l.Dropped.Load() != 2 {
		t.Fatalf("dropped: %d, want 2", l.Dropped.Load())
	}
	if out := l.Report(); !strings.Contains(out, "2 subjects dropped at the bound") {
		t.Errorf("the report does not say the bound was reached:\n%s", out)
	}
}

// Past the range bound the set collapses to its span, which is wider than
// the truth and says so rather than forgetting what did not fit.
func TestTheRangeSetCollapsesRatherThanForgetting(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	for i := 0; i < maxObservedRanges+4; i++ {
		// Each read is its own range, two apart so none is adjacent.
		addr := i * 4
		pdu := []byte{3, byte(addr >> 8), byte(addr), 0x00, 0x01}
		l.Observe(req(t, "10.0.0.7", "", 1, pdu), true, learnDay)
	}
	out := l.Report()
	if !strings.Contains(out, "addresses: [0-") {
		t.Errorf("the collapsed span is not in the report:\n%s", out)
	}
	if strings.Count(out, "addresses:") != 2 { // one observation, one rule
		t.Errorf("the ranges were not collapsed to one span:\n%s", out)
	}
}

// The file is replaced atomically and owner readable only: a report half
// written is a report an engineer reads as the truth.
func TestTheReportFileIsReplacedAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned.yaml")
	l := NewLearner("plant", path, time.Minute, 64)
	l.Observe(req(t, "10.0.0.7", "", 3, learnRead), true, learnDay)
	if err := l.Write(); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	first, _ := os.ReadFile(path)
	l.Observe(req(t, "10.0.0.8", "", 4, learnRead), true, learnDay)
	if err := l.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	second, _ := os.ReadFile(path)
	if len(second) <= len(first) || !strings.Contains(string(second), "unit: 4") {
		t.Error("the shutdown write did not replace the report")
	}
	// No temporary file is left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the directory holds %d files, want only the report", len(entries))
	}
	if l.Writes.Load() != 2 {
		t.Errorf("writes: %d, want 2", l.Writes.Load())
	}
}

// A learner with nothing to say still writes a file, because an empty
// report is an answer and a missing file is a mystery.
func TestAnEmptyReportIsStillAReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learned.yaml")
	l := NewLearner("plant", path, time.Minute, 64)
	if err := l.Write(); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "observed:\n  []") {
		t.Errorf("an empty report should say it is empty:\n%s", b)
	}
}

// A nil learner is the listener with learning turned off, and every call
// on it has to be a no-op rather than a panic in the data path.
func TestALearnerThatIsNotThere(t *testing.T) {
	var l *Learner
	l.Start(nil)
	l.Observe(req(t, "10.0.0.7", "", 1, learnRead), true, learnDay)
	l.ObserveException(req(t, "10.0.0.7", "", 1, learnRead), learnDay)
	if err := l.Write(); err != nil {
		t.Errorf("write: %v", err)
	}
	if err := l.Stop(); err != nil {
		t.Errorf("stop: %v", err)
	}
	if l.Subjects() != 0 {
		t.Error("a learner that is not there holds nothing")
	}
}

// The trace stops at its bound rather than filling the disk the plant's
// historian is also on, and says how many lines it dropped.
func TestTheTraceStopsAtItsBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	tr, err := NewTracer("plant", path, 300, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	r := req(t, "10.0.0.7", "", 3, learnRead)
	for i := 0; i < 20; i++ {
		tr.Request(TraceEntry{Client: "10.0.0.7", Decision: "allow"}, r.pdu, learnRead)
	}
	if !tr.Full() {
		t.Fatal("the trace did not stop at its bound")
	}
	if tr.Dropped.Load() == 0 {
		t.Fatal("the dropped lines were not counted")
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) > 300+256 {
		t.Fatalf("the trace wrote %d bytes past a bound of 300", len(b))
	}
	if !strings.Contains(string(b), `"direction":"request"`) {
		t.Errorf("the trace does not name the direction:\n%s", b)
	}
	// The bound is reported once, where somebody reading the file sees
	// it rather than having to notice the file stopped growing.
	if !strings.Contains(string(b), "trace_full") {
		t.Errorf("the trace does not say it stopped:\n%s", b)
	}
}

// The directions are selectable, because a trace of the requests is
// usually what an engineer wants and the responses double the file.
func TestTheTraceDirectionsAreSelectable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	tr, err := NewTracer("plant", path, 1<<20, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	r := req(t, "10.0.0.7", "", 3, learnRead)
	tr.Request(TraceEntry{Client: "10.0.0.7"}, r.pdu, learnRead)
	tr.Response(TraceEntry{Client: "10.0.0.7"}, r.pdu, learnRead)
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), `"direction":"response"`) {
		t.Errorf("a response was traced on a request-only trace:\n%s", b)
	}
	if strings.Contains(string(b), `"data"`) {
		t.Errorf("the data was written on a trace that did not ask for it:\n%s", b)
	}
	if strings.Count(string(b), "\n") != 1 {
		t.Errorf("want one line:\n%s", b)
	}
}

// The defect the per-address baseline exists to fix: a value bound derived from
// every register a subject touched is looser than the traffic it came from.
//
// A master writing a 0..40 bar setpoint at register 400 and a 0..3 mode at 401
// used to produce one span over both, and a rule built from it permitted setting
// the mode to 40. An engineer who pasted that got a value policy that was wrong
// in a way that looked derived from evidence, which is worse than having none.
func TestValueBoundsAreProposedPerAddress(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay) // 50 at 400
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnHigh), true, learnDay) // 100 at 400
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnMode), true, learnDay) // 2 at 401

	r := l.Report()
	_, values, ok := strings.Cut(r, "\n# The same, as the value policy would be written.")
	if !ok {
		t.Fatalf("the report proposes no value policy:\n%s", r)
	}
	for _, want := range []string{
		// The setpoint keeps its own envelope and its own step.
		"registers: \"400\"",
		"min: 50",
		"max: 100",
		"max_delta: 50",
		// And the mode keeps its own, which is the whole point.
		"registers: \"401\"",
		"min: 2",
		"max: 2",
	} {
		if !strings.Contains(values, want) {
			t.Errorf("the value policy has no %q:\n%s", want, values)
		}
	}
	// Nothing proposes a bound of 100 on the mode register.
	if strings.Contains(values, "registers: \"400-401\"") {
		t.Errorf("two registers with different envelopes were folded into one bound:\n%s", values)
	}
}

// Adjacent registers that really do share a baseline are one entry, because a
// report with a line per register of a forty-register block is a report nobody
// reads.
func TestAdjacentRegistersSharingABaselineAreOneEntry(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	// Write the same value to four consecutive registers, twice.
	four := []byte{16, 0x01, 0x90, 0x00, 0x04, 8,
		0x00, 0x0A, 0x00, 0x0A, 0x00, 0x0A, 0x00, 0x0A}
	l.Observe(req(t, "10.0.0.8", "engineer", 3, four), true, learnDay)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, four), true, learnDay.Add(time.Second))

	r := l.Report()
	if !strings.Contains(r, `registers: "400-403"`) {
		t.Errorf("four registers with one baseline were not folded:\n%s", r)
	}
}

// A read is not a baseline. A bound proposed from the values the *process*
// produced would permit a master to write anything the plant ever reached on its
// own, which is the opposite of a bound.
func TestAReadDoesNotSetABaseline(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.7", "", 3, learnRead), true, learnDay)
	r := l.Report()
	if strings.Contains(r, "observed_values:") {
		t.Errorf("a read produced a value baseline:\n%s", r)
	}
}

// The write rate is what a burst is measured against, and it is a sliding minute
// rather than a counter per minute: a burst that straddles a boundary is still a
// burst.
func TestThePeakWriteRateIsASlidingMinute(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	// Three writes 25 seconds apart: the first and the third are 50 seconds
	// apart, so all three sit inside one minute at some point.
	for i := 0; i < 3; i++ {
		l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true,
			learnDay.Add(time.Duration(i)*25*time.Second))
	}
	r := l.Report()
	if !strings.Contains(r, "peak_writes_per_minute: 3") {
		t.Errorf("the sliding window did not see three writes in a minute:\n%s", r)
	}
	if !strings.Contains(r, "rate: {max: 3, period: 1m}") {
		t.Errorf("the rate was not proposed from the peak:\n%s", r)
	}
}

// And a write outside the window does not count towards the peak.
func TestAWriteOutsideTheWindowIsNotABurst(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay.Add(2*time.Minute))
	r := l.Report()
	if !strings.Contains(r, "peak_writes_per_minute: 1") {
		t.Errorf("two writes two minutes apart were counted as a burst:\n%s", r)
	}
}

// A run where every write carried the same value observed no step, and a
// max_delta of 0 would refuse every change -- so the key is left out and the
// report says why.
func TestNoObservedStepProposesNoMaxDelta(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay.Add(time.Second))
	r := l.Report()
	if strings.Contains(r, "max_delta: 0") {
		t.Errorf("a max_delta of 0 was proposed, which refuses every change:\n%s", r)
	}
	if !strings.Contains(r, "no step was observed") {
		t.Errorf("the report does not say why max_delta is absent:\n%s", r)
	}
}

// The report says a baseline is not a control. It is derived from traffic, and
// traffic is what somebody who was already inside has been shaping.
func TestTheReportWarnsThatABaselineIsNotAControl(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay)
	r := l.Report()
	for _, want := range []string{
		"A BASELINE IS WHERE A CONVERSATION STARTS AND NOT A CONTROL",
		"has been quietly driven out of its envelope",
		"instrument ranges before pasting",
		// And where to paste it. It said `modbus.values` once, which is not a
		// key the loader reads: a value policy belongs to a rule. An engineer
		// following that instruction gets a validation error and concludes the
		// tool is broken rather than that the line is wrong.
		"modbus.rules[].values",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("the report does not say %q:\n%s", want, r)
		}
	}
}

// A coil has no envelope. Proposing "this coil may only be set" from a run where
// nobody cleared it would refuse the reset somebody needs at three in the
// morning, so the observation stands alone and no rule is proposed.
func TestACoilIsObservedAndNotProposed(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	// Write a single coil on at address 20.
	on := []byte{5, 0x00, 0x14, 0xFF, 0x00}
	l.Observe(req(t, "10.0.0.8", "engineer", 3, on), true, learnDay)
	r := l.Report()
	if !strings.Contains(r, "driven: {set: true, cleared: false}") {
		t.Errorf("the coil was not recorded:\n%s", r)
	}
	_, values, ok := strings.Cut(r, "\n# The same, as the value policy would be written.")
	if !ok {
		t.Fatalf("the report has no value policy section:\n%s", r)
	}
	if strings.Contains(values, "coils:") {
		t.Errorf("a coil rule was proposed:\n%s", values)
	}
	// And the coil must not have been recorded as a *register* as well. Code 5
	// carries the bit as 0xFF00 on the wire and the decoder keeps that word in
	// Registers, so a baseline that read Registers for every writing code
	// recorded an envelope of 65280..65280 at the coil's address -- and
	// proposed it, as a value bound on a register that is not one.
	if strings.Contains(r, "65280") {
		t.Errorf("the coil's wire encoding was recorded as a register value:\n%s", r)
	}
	if strings.Contains(values, `registers: "20"`) {
		t.Errorf("a value bound was proposed for a coil's address:\n%s", values)
	}
}

// The two other function codes whose Registers are not values at addresses.
//
// Code 22 carries an AND mask and an OR mask, and code 8 a diagnostic argument.
// Reading either as a value would put a number in the report that the plant
// never wrote anywhere, and the runtime check refuses to apply a value bound to
// a masked write for the same reason.
func TestMasksAndDiagnosticsAreNotValues(t *testing.T) {
	for _, c := range []struct {
		name  string
		frame []byte
		// seen is a decimal the frame's data words would show up as.
		seen string
	}{
		// Mask write at register 300: AND 0xF0F0, OR 0x0A0A.
		{"mask write", []byte{22, 0x01, 0x2C, 0xF0, 0xF0, 0x0A, 0x0A}, "61680"},
		// Diagnostic sub-function 0 (return query data) with 0x1234.
		{"diagnostic", []byte{8, 0x00, 0x00, 0x12, 0x34}, "4660"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := NewLearner("plant", "", time.Minute, 64)
			l.Observe(req(t, "10.0.0.8", "engineer", 3, c.frame), true, learnDay)
			r := l.Report()
			if strings.Contains(r, "value_seen:") {
				t.Errorf("a value envelope was recorded from %s:\n%s", c.name, r)
			}
			if strings.Contains(r, c.seen) {
				t.Errorf("a data word of %s reached the report as a value:\n%s", c.name, r)
			}
		})
	}
}

// The bound on remembered addresses is a bound, and a run that quietly stopped
// recording them would be a report nobody could trust.
func TestTheBaselineAddressBoundIsCounted(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	for i := 0; i < maxBaselinePoints+50; i++ {
		w := []byte{6, byte(i >> 8), byte(i), 0x00, 0x01}
		l.Observe(req(t, "10.0.0.8", "engineer", 3, w), true, learnDay)
	}
	r := l.Report()
	if !strings.Contains(r, "addresses were dropped at the bound") {
		t.Errorf("the bound was reached and the report does not say so:\n%s", r)
	}
}

// The envelope is an envelope, not the first value seen. A setpoint driven down
// after being driven up has a minimum, and a bound that kept only the first value
// as the floor would refuse the low end of its own range.
func TestTheEnvelopeGrowsDownwardsToo(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnHigh), true, learnDay) // 100
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay) // 50
	r := l.Report()
	if !strings.Contains(r, "value_seen: {min: 50, max: 100}") {
		t.Errorf("the envelope did not grow downwards:\n%s", r)
	}
}

// A step is a distance. A setpoint dropped by fifty moved as far as one raised by
// fifty, and a signed comparison would record the fall as no step at all --
// leaving max_delta absent on exactly the point that is driven down hard.
func TestADownwardStepIsAStep(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnHigh), true, learnDay)                  // 100
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay.Add(time.Second)) // 50
	r := l.Report()
	if !strings.Contains(r, "largest_step: 50") {
		t.Errorf("a fall of fifty was not recorded as a step:\n%s", r)
	}
}

// Function 23 reads one range and writes another. The baseline belongs at the
// address the values were *written* to: recorded at the read address it would
// describe a register nobody wrote and leave the one they did unbounded.
func TestAReadWriteMultipleBaselinesTheWriteAddress(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	// Read 2 registers at 100, write 1 register at 400 with the value 7.
	rw := []byte{23, 0x00, 0x64, 0x00, 0x02, 0x01, 0x90, 0x00, 0x01, 2, 0x00, 0x07}
	l.Observe(req(t, "10.0.0.8", "engineer", 3, rw), true, learnDay)
	r := l.Report()
	if !strings.Contains(r, `registers: "400"`) {
		t.Errorf("the baseline is not at the write address:\n%s", r)
	}
	if strings.Contains(r, `registers: "100"`) {
		t.Errorf("the baseline was recorded at the read address:\n%s", r)
	}
}

// The peak is a high-water mark. A burst an hour ago is what an engineer needs to
// know about when writing a rate bound, and a peak that decayed back to the
// current window would forget it.
func TestThePeakIsAHighWaterMark(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	for i := 0; i < 3; i++ {
		l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true,
			learnDay.Add(time.Duration(i)*time.Second))
	}
	// And one write an hour later, alone in its own window.
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay.Add(time.Hour))
	r := l.Report()
	if !strings.Contains(r, "peak_writes_per_minute: 3") {
		t.Errorf("the peak decayed back to the current window:\n%s", r)
	}
}

// Two addresses with the same baseline and a gap between them are two entries. A
// run that folded across the gap would propose a bound over registers nobody
// wrote, which on a device that maps something else there is a bound permitting
// what was never observed.
func TestARunDoesNotFoldAcrossAGap(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	at400 := []byte{6, 0x01, 0x90, 0x00, 0x0A} // 10 at 400
	at500 := []byte{6, 0x01, 0xF4, 0x00, 0x0A} // 10 at 500
	l.Observe(req(t, "10.0.0.8", "engineer", 3, at400), true, learnDay)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, at500), true, learnDay)
	r := l.Report()
	if strings.Contains(r, `registers: "400-500"`) {
		t.Errorf("two addresses a hundred apart were folded into one bound:\n%s", r)
	}
	for _, want := range []string{`registers: "400"`, `registers: "500"`} {
		if !strings.Contains(r, want) {
			t.Errorf("the report has no %q:\n%s", want, r)
		}
	}
}

// Adjacent addresses whose *values* differ are two entries even when everything
// else about them matches, which is the whole reason the envelope is per address.
func TestAdjacentAddressesWithDifferentValuesStaySeparate(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	at400 := []byte{6, 0x01, 0x90, 0x00, 0x0A} // 10 at 400
	at401 := []byte{6, 0x01, 0x91, 0x00, 0x14} // 20 at 401
	l.Observe(req(t, "10.0.0.8", "engineer", 3, at400), true, learnDay)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, at401), true, learnDay)
	r := l.Report()
	if strings.Contains(r, `registers: "400-401"`) {
		t.Errorf("two adjacent registers with different values were folded:\n%s", r)
	}
	if !strings.Contains(r, "value_seen: {min: 10, max: 10}") ||
		!strings.Contains(r, "value_seen: {min: 20, max: 20}") {
		t.Errorf("the two envelopes were not kept apart:\n%s", r)
	}
}

// The proposal has to load.
//
// This is the test that catches the class of mistake the `rate` key already was:
// the report wrote `per: 1m` where the policy reads `period`, so a block an
// engineer pasted would have been refused by validation. A proposal in a
// vocabulary the configuration does not read is worse than no proposal, because
// the engineer's conclusion is that the tool is broken rather than that the line
// is wrong.
func TestTheProposedValuePolicyLoads(t *testing.T) {
	l := NewLearner("plant", "", time.Minute, 64)
	// A spread wide enough to exercise every key the proposal can emit: a
	// setpoint with a step and a rate, a single-valued register with neither,
	// a multi-register run, and a coil.
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnWrit), true, learnDay)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnHigh), true, learnDay.Add(time.Second))
	l.Observe(req(t, "10.0.0.8", "engineer", 3, learnMode), true, learnDay)
	four := []byte{16, 0x02, 0x58, 0x00, 0x04, 8, 0x00, 0x0A, 0x00, 0x0A, 0x00, 0x0A, 0x00, 0x0A}
	l.Observe(req(t, "10.0.0.8", "engineer", 3, four), true, learnDay)
	l.Observe(req(t, "10.0.0.8", "engineer", 3, []byte{5, 0x00, 0x14, 0xFF, 0x00}), true, learnDay)

	_, tail, ok := strings.Cut(l.Report(), "\n# The same, as the value policy would be written.")
	if !ok {
		t.Fatalf("the report proposes no value policy")
	}
	_, block, ok := strings.Cut(tail, "\nvalues:\n")
	if !ok {
		t.Fatalf("the proposal has no values block:\n%s", tail)
	}
	if strings.TrimSpace(block) == "[]" {
		t.Fatalf("the proposal is empty, so this test asserts nothing")
	}
	// Re-indent the block as the `values:` of a rule -- which is where a value
	// policy lives, and where the report now says to paste it -- and ask the
	// real loader.
	var indented strings.Builder
	for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		indented.WriteString("            " + line + "\n")
	}
	cfg := `
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:1502"
      kind: modbus
      modbus:
        upstream: plc
        rules:
          - name: engineer_writes
            action: allow
            values:
` + indented.String() + `
upstreams:
  - {name: plc, endpoints: [{address: "10.0.0.9:502"}]}
`
	if _, err := config.Parse([]byte(cfg)); err != nil {
		t.Fatalf("the proposed value policy does not load: %v\n%s", err, cfg)
	}
}

// Folding is only for entries that say the same thing, and the entry says more
// than its envelope: the largest step, the peak write rate and the number of
// writes are all printed. Two addresses folded on the strength of a matching
// envelope alone print one address's numbers for the other's.
func TestARunFoldsOnlyWhatIsIdentical(t *testing.T) {
	// Every case writes the same two values to two adjacent registers, so the
	// envelope always matches and only the field under test differs.
	at600 := func(v byte) []byte { return []byte{6, 0x02, 0x58, 0x00, v} }
	at601 := func(v byte) []byte { return []byte{6, 0x02, 0x59, 0x00, v} }
	for _, c := range []struct {
		name string
		// each function writes 10 and 20 to its address, differing only in how.
		write func(l *Learner)
	}{
		{"the step differs", func(l *Learner) {
			// Three writes each, at the same instants, reaching the same
			// envelope: 600 goes 10, 20, 10 and jumps by 10, while 601 goes 10,
			// 15, 20 and never moves by more than 5. Everything else about the
			// two matches, so only the step can keep them apart.
			for i, v := range []byte{10, 20, 10} {
				l.Observe(req(t, "10.0.0.8", "engineer", 3, at600(v)), true, learnDay.Add(time.Duration(i)*time.Second))
			}
			for i, v := range []byte{10, 15, 20} {
				l.Observe(req(t, "10.0.0.8", "engineer", 3, at601(v)), true, learnDay.Add(time.Duration(i)*time.Second))
			}
		}},
		{"the peak rate differs", func(l *Learner) {
			// Both are written twice with the same step; 600's two writes are a
			// second apart and 601's an hour, so one peaked at two a minute and
			// the other at one.
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at600(10)), true, learnDay)
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at600(20)), true, learnDay.Add(time.Second))
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at601(10)), true, learnDay)
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at601(20)), true, learnDay.Add(time.Hour))
		}},
		{"the write count differs", func(l *Learner) {
			// 601 is written the same two values twice over, an hour apart, so
			// its envelope, step and peak all match 600's and its count does
			// not. An entry claiming two writes for an address that had four is
			// a report that misreports the traffic it exists to describe.
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at600(10)), true, learnDay)
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at600(20)), true, learnDay.Add(time.Second))
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at601(10)), true, learnDay)
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at601(20)), true, learnDay.Add(time.Second))
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at601(10)), true, learnDay.Add(time.Hour))
			l.Observe(req(t, "10.0.0.8", "engineer", 3, at601(20)), true, learnDay.Add(time.Hour+time.Second))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := NewLearner("plant", "", time.Minute, 64)
			c.write(l)
			r := l.Report()
			if strings.Contains(r, `registers: "600-601"`) {
				t.Errorf("two addresses were folded although %s:\n%s", c.name, r)
			}
			for _, want := range []string{`registers: "600"`, `registers: "601"`} {
				if !strings.Contains(r, want) {
					t.Errorf("the report has no %q:\n%s", want, r)
				}
			}
		})
	}
}

// A response is not a write.
//
// observe says "only writes" and means it: a read-coils *response* carries the
// coils it read and the address the request named, and writeSpan reports "writes
// nothing" for it as hi == -1. Without that check the response's coils would be
// recorded as coils this master drove -- and at addresses 0 upwards, since
// writeSpan returns no base address for a request that writes nothing, so a read
// of eight coils at 100 would come back as eight coils driven at 0.
func TestAResponseDrivesNothing(t *testing.T) {
	ask, err := wire.ParseRequest([]byte{1, 0x00, 0x64, 0x00, 0x08}) // read 8 coils at 100
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	answer, err := wire.ParseResponse([]byte{1, 0x01, 0xFF}, ask) // all eight on
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	if len(answer.Coils) != 8 {
		t.Fatalf("the response carries %d coils, so this test asserts nothing", len(answer.Coils))
	}
	b := newBaselines()
	b.observe(3, answer, learnDay)
	if len(b.points) != 0 {
		t.Errorf("a read response set %d baselines: %+v", len(b.points), b.points)
	}
}
