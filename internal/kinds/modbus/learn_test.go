package modbus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	learnDay  = time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	learnRead = []byte{3, 0x00, 0x64, 0x00, 0x0A} // read 10 registers at 100
	learnNext = []byte{3, 0x00, 0x6E, 0x00, 0x05} // read 5 registers at 110
	learnFar  = []byte{3, 0x03, 0xE8, 0x00, 0x02} // read 2 registers at 1000
	learnWrit = []byte{6, 0x01, 0x90, 0x00, 0x32} // write 50 to register 400
	learnHigh = []byte{6, 0x01, 0x90, 0x00, 0x64} // write 100 to register 400
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
		"values_written: {min: 50, max: 100}",
		"rules:",
		"name: learned-10-0-0-7-u3-read_holding_registers",
		"clients: [10.0.0.7/32]",
		"values: [{min: 50, max: 100}]",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("the report does not carry %q:\n%s", want, r)
		}
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
