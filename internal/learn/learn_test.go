package learn

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// obs is a test observation with a slice field, because the aliasing that a
// slice field causes is the thing Clone exists for.
type obs struct {
	count int
	seen  []int
}

func cloneObs(o obs) obs {
	out := o
	if o.seen != nil {
		out.seen = make([]int, len(o.seen))
		copy(out.seen, o.seen)
	}
	return out
}

func render(listener string, subjects []Subject[string, obs], st Stats) string {
	var b strings.Builder
	b.WriteString(Header("test", listener, st, time.Unix(0, 0)))
	for _, s := range subjects {
		b.WriteString(s.Key + "\n")
	}
	return b.String()
}

func newRun(t *testing.T, path string, max int) *Run[string, obs] {
	t.Helper()
	return New(Options[string, obs]{
		Kind: "test", Listener: "relay", Path: path, Max: max,
		Render: render, Clone: cloneObs,
		Less: func(a, b string) bool { return a < b },
	})
}

// What a learning run is for: it records what it saw, per subject, and the
// report says how much.
func TestARunRecordsWhatItSaw(t *testing.T) {
	r := newRun(t, "", 0)
	for i := 0; i < 3; i++ {
		r.Observe("alice", func(o *obs, first bool) {
			o.count++
			o.seen = append(o.seen, i)
		})
	}
	r.Observe("bob", func(o *obs, first bool) { o.count++ })
	if n := r.Subjects(); n != 2 {
		t.Errorf("held %d subjects, want 2", n)
	}
	if n := r.Observed.Load(); n != 4 {
		t.Errorf("recorded %d events, want 4", n)
	}
	got := r.Report()
	if !strings.Contains(got, "4 events, 2 subjects") {
		t.Errorf("the header does not say what was seen: %q", got)
	}
	// Ordered, so two runs over the same traffic produce the same file and a
	// diff between them means something.
	if want := "alice\nbob\n"; !strings.HasSuffix(got, want) {
		t.Errorf("the report is %q, want it ending %q", got, want)
	}
}

// first is true exactly once per subject, which is how a caller sets the
// first-seen time and initialises a map.
func TestTheFirstEventForASubjectSaysSo(t *testing.T) {
	r := newRun(t, "", 0)
	firsts := 0
	for i := 0; i < 4; i++ {
		r.Observe("alice", func(o *obs, first bool) {
			if first {
				firsts++
			}
		})
	}
	if firsts != 1 {
		t.Errorf("first was true %d times, want once", firsts)
	}
}

// The bound. A run that quietly stopped learning is worse than one that says
// so, so the drops are counted and the report carries the count.
func TestTheBoundIsCountedAndReported(t *testing.T) {
	r := newRun(t, "", 2)
	for _, who := range []string{"a", "b", "c", "d"} {
		r.Observe(who, func(o *obs, first bool) { o.count++ })
	}
	if n := r.Subjects(); n != 2 {
		t.Errorf("held %d subjects, want the bound of 2", n)
	}
	if n := r.Dropped.Load(); n != 2 {
		t.Errorf("dropped %d, want 2", n)
	}
	// The events that were dropped are not counted as observed: the number in
	// the header is what the report actually rests on.
	if n := r.Observed.Load(); n != 2 {
		t.Errorf("recorded %d events, want 2", n)
	}
	if got := r.Report(); !strings.Contains(got, "2 subjects dropped at the bound") {
		t.Errorf("the header does not mention the bound: %q", got)
	}
	// And the subjects kept are the ones seen first, not a random two: the
	// first thing a run saw is the thing it has had longest to tell you about.
	got := r.Report()
	if !strings.Contains(got, "a\nb\n") {
		t.Errorf("the bound dropped the wrong subjects: %q", got)
	}
}

// The report is written whole or not at all, so a reader never sees half of
// one.
func TestTheReportIsReplacedAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.yaml")
	r := newRun(t, path, 0)
	r.Observe("alice", func(o *obs, first bool) { o.count++ })
	if err := r.Write(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "alice") {
		t.Errorf("the report is %q", body)
	}
	if n := r.Writes.Load(); n != 1 {
		t.Errorf("counted %d writes, want 1", n)
	}
	// Only the report is left behind: a temporary file that survived would be
	// a directory that fills up.
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0].Name() != "report.yaml" {
		got := make([]string, 0, len(names))
		for _, n := range names {
			got = append(got, n.Name())
		}
		t.Errorf("the directory holds %v", got)
	}
	// The mode is the operator's business and not the world's: the report says
	// what the estate's traffic is.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("the report is mode %v", perm)
	}
}

// A write that cannot happen is counted and returned rather than swallowed: a
// learning run whose file is not there is a week nobody gets back.
func TestAReportThatCannotBeWrittenSaysSo(t *testing.T) {
	r := newRun(t, filepath.Join(t.TempDir(), "no-such-directory", "report.yaml"), 0)
	r.Observe("alice", func(o *obs, first bool) { o.count++ })
	if err := r.Write(); err == nil {
		t.Fatal("a report written into a directory that does not exist succeeded")
	} else if !strings.Contains(err.Error(), "test learn:") {
		t.Errorf("the error does not name the kind: %v", err)
	}
	if n := r.Failures.Load(); n != 1 {
		t.Errorf("counted %d failures, want 1", n)
	}
}

// No path means no file, which is how a run that only counts is configured.
func TestNoPathWritesNothing(t *testing.T) {
	r := newRun(t, "", 0)
	r.Observe("alice", func(o *obs, first bool) { o.count++ })
	if err := r.Write(); err != nil {
		t.Fatalf("a run with no path failed: %v", err)
	}
	if n := r.Writes.Load(); n != 0 {
		t.Errorf("counted %d writes for a run with no path", n)
	}
}

// Stop writes the report one last time, because the interesting part of a
// learning run is often the end of it.
func TestStopWritesTheReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.yaml")
	r := newRun(t, path, 0)
	r.Start(nil)
	r.Observe("alice", func(o *obs, first bool) { o.count++ })
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the report was not written at shutdown: %v", err)
	}
	// Stopping twice is not an error, because a listener's lifecycle may reach
	// it from two directions.
	if err := r.Stop(); err != nil {
		t.Errorf("stopping twice: %v", err)
	}
}

// A shutdown that arrives before the loop started must not deadlock: the
// listener's lifecycle can reach Stop without ever reaching Start.
func TestStopBeforeStart(t *testing.T) {
	r := newRun(t, "", 0)
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	r.Start(nil) // no-op, and must not leave a goroutine behind
}

// A nil run is a listener with learning off, and every call on it does nothing
// rather than panicking.
func TestANilRunDoesNothing(t *testing.T) {
	var r *Run[string, obs]
	r.Observe("alice", func(o *obs, first bool) { t.Error("a nil run recorded something") })
	r.Start(nil)
	if n := r.Subjects(); n != 0 {
		t.Errorf("a nil run holds %d subjects", n)
	}
	if got := r.Report(); got != "" {
		t.Errorf("a nil run reported %q", got)
	}
	if err := r.Write(); err != nil {
		t.Errorf("a nil run's write: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Errorf("a nil run's stop: %v", err)
	}
}

// Recording and reporting at the same time is what a running listener does, and
// the race detector is the point of this test: without Clone the renderer reads
// a slice a concurrent append is still writing to.
func TestRecordingWhileReporting(t *testing.T) {
	r := New(Options[string, obs]{
		Kind: "test", Listener: "relay", Max: 64, Clone: cloneObs,
		Render: func(_ string, subjects []Subject[string, obs], _ Stats) string {
			// The elements, not just the length: reading len() of a copied
			// slice header never touches the backing array, so it would not
			// notice a shallow copy handing the renderer a slice that a
			// concurrent append is still writing to.
			n := 0
			for _, s := range subjects {
				for _, v := range s.Obs.seen {
					n += v
				}
			}
			return string(rune('0' + n%10))
		},
	})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			r.Observe("alice", func(o *obs, first bool) {
				o.count++
				o.seen = append(o.seen, i)
				// And a mutation of an element a snapshot can already see,
				// which is what makes a shallow copy unsafe. An append alone
				// would not: it writes past the end of every snapshot taken
				// before it, so no renderer ever reads that index. Merging
				// ranges in place, as a real observation does, is this.
				o.seen[0] = i
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = r.Report()
		}
	}()
	wg.Wait()
}

// ObserveExisting is for an event that says something about a subject other than
// the one it arrived as. It must never invent that subject: a run that created
// one from an answer alone would report a request it never saw asked for.
func TestObserveExistingOnlyUpdatesWhatIsThere(t *testing.T) {
	r := newRun(t, "", 0)
	if r.ObserveExisting("alice", func(o *obs) { o.count = 99 }) {
		t.Error("a subject nobody had seen was updated")
	}
	if n := r.Subjects(); n != 0 {
		t.Fatalf("it invented %d subjects", n)
	}
	// Once the subject is there it is updated, and the update is not counted as
	// an event of its own: the event was already counted where it arrived.
	r.Observe("alice", func(o *obs, first bool) { o.count = 1 })
	before := r.Observed.Load()
	if !r.ObserveExisting("alice", func(o *obs) { o.count += 10 }) {
		t.Fatal("a subject that is there was not updated")
	}
	if n := r.Observed.Load(); n != before {
		t.Errorf("the update was counted as %d extra events", n-before)
	}
	var got int
	r.ObserveExisting("alice", func(o *obs) { got = o.count })
	if got != 11 {
		t.Errorf("the observation holds %d, want 11", got)
	}
}

// Sanitise, because a client name or a path arrives off the network and the
// report is a file somebody pastes into a configuration.
func TestSanitise(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{name: "an ordinary address", in: "10.20.1.5", want: "10.20.1.5"},
		{name: "a newline that would forge a line", in: "a\nb: c", want: "ab: c"},
		{name: "quotes that would break out of a string", in: `a"b'c\d`, want: "abcd"},
		{name: "a control character", in: "a\x00\x1bb", want: "ab"},
		{name: "a carriage return", in: "a\rb", want: "ab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sanitise(tc.in); got != tc.want {
				t.Errorf("Sanitise(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// And it is bounded, because the length is the client's to choose.
	if got := Sanitise(strings.Repeat("x", 300)); len(got) != 128 {
		t.Errorf("a 300-character name became %d characters", len(got))
	}
}

// The header is the same in every kind's report, and says plainly whether the
// run is still learning everything it sees.
func TestTheHeaderSaysWhatTheRunIsWorth(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	got := Header("Modbus", "plant", Stats{Observed: 10, Subjects: 3}, at)
	for _, want := range []string{"Modbus traffic", `listener "plant"`, "2026-03-04T05:06:07Z", "10 events, 3 subjects"} {
		if !strings.Contains(got, want) {
			t.Errorf("the header has no %q: %q", want, got)
		}
	}
	if strings.Contains(got, "dropped") {
		t.Errorf("a run that dropped nothing mentions the bound: %q", got)
	}
	if got := Header("Modbus", "plant", Stats{Dropped: 4}, at); !strings.Contains(got, "4 subjects dropped at the bound") {
		t.Errorf("a run that dropped subjects does not say so: %q", got)
	}
}
