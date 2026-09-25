package shadow

import (
	"strconv"
	"sync"
	"testing"
)

// The ledger is what makes a policy switchable on: an operator reads it,
// fixes what it names, and enforces. So the tests are about the three
// things that would make it useless -- losing counts, losing the order
// that puts the worst rule at the top, and growing without limit on what
// came off the network.

func TestOneKindOfRefusalIsOneEntryWithACount(t *testing.T) {
	l := NewLedger(0)
	for i := 0; i < 5; i++ {
		l.Record("modbus", "line-2", "rule_deny", "setpoints", "unit 2 write_single_register 40010")
	}
	l.Record("modbus", "line-2", "rule_deny", "other", "unit 3 write_single_coil 1")
	rep := l.Report()
	if len(rep) != 2 {
		t.Fatalf("%d entries: %+v", len(rep), rep)
	}
	if rep[0].Count != 5 || rep[0].Rule != "setpoints" {
		t.Fatalf("the busiest entry is %+v", rep[0])
	}
	if rep[0].Sample == "" || rep[0].First == "" || rep[0].Last == "" {
		t.Errorf("an entry with no example or no times: %+v", rep[0])
	}
	// The first sample stays: the first example of what a rule would have
	// refused is the one an operator reads, and rewriting it on every hit
	// would make the report a moving target while it is being read.
	l.Record("modbus", "line-2", "rule_deny", "setpoints", "something else entirely")
	if got := l.Report()[0].Sample; got != "unit 2 write_single_register 40010" {
		t.Errorf("the sample changed to %q", got)
	}
	st := l.Status()
	if st.Entries != 2 || st.Recorded != 7 || st.Dropped != 0 || st.Full {
		t.Errorf("status %+v", st)
	}
}

func TestTheReportIsWorstFirstAndStable(t *testing.T) {
	l := NewLedger(0)
	l.Record("ssh", "operators", "command_refused", "", "rm -rf /")
	for i := 0; i < 3; i++ {
		l.Record("ftp", "intake", "command_refused", "", "DELE")
	}
	for i := 0; i < 2; i++ {
		l.Record("dns", "resolver", "blocked", "", "ads.example")
	}
	rep := l.Report()
	if len(rep) != 3 {
		t.Fatalf("%d entries", len(rep))
	}
	if rep[0].Kind != "ftp" || rep[1].Kind != "dns" || rep[2].Kind != "ssh" {
		t.Fatalf("order %s %s %s", rep[0].Kind, rep[1].Kind, rep[2].Kind)
	}
	// Equal counts are ordered by kind, listener, reason and rule, so two
	// reports of the same ledger read the same way round.
	l.Record("dns", "resolver", "blocked", "", "x")
	first := l.Report()
	second := l.Report()
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("entry %d differs between reports: %+v %+v", i, first[i], second[i])
		}
	}
}

func TestTheLedgerIsBoundedAndSaysSo(t *testing.T) {
	l := NewLedger(8)
	for i := 0; i < 50; i++ {
		l.Record("mqtt", "fleet", "publish_topic_refused", "rule"+strconv.Itoa(i), "topic/"+strconv.Itoa(i))
	}
	if n := len(l.Report()); n != 8 {
		t.Fatalf("%d entries past a bound of 8", n)
	}
	st := l.Status()
	if !st.Full || st.Dropped != 42 {
		t.Fatalf("status %+v", st)
	}
	// What is already there keeps counting: a full ledger must not stop
	// measuring the rules it is already watching.
	before := l.Report()[0].Count
	l.Record("mqtt", "fleet", "publish_topic_refused", "rule0", "topic/0")
	if after := l.Report()[0].Count; after != before+1 {
		t.Errorf("a full ledger stopped counting a rule it holds: %d then %d", before, after)
	}
	// And a bound larger than the maximum is the maximum, because the
	// operator's number cannot be the thing that makes this unbounded.
	if NewLedger(1<<30).max != MaxEntries {
		t.Error("a bound past the maximum was taken")
	}
}

func TestASampleIsClippedAndANilLedgerIsSafe(t *testing.T) {
	l := NewLedger(0)
	long := make([]byte, MaxSample*4)
	for i := range long {
		long[i] = 'x'
	}
	l.Record("syslog", "collector", "pattern", "", string(long))
	if got := len(l.Report()[0].Sample); got != MaxSample {
		t.Fatalf("a sample of %d bytes", got)
	}
	// An empty reason is not an entry: a counter with no label reads as a
	// broken exporter, and here it would be an entry nobody can act on.
	l.Record("syslog", "collector", "", "", "x")
	if n := len(l.Report()); n != 1 {
		t.Errorf("%d entries", n)
	}
	var none *Ledger
	none.Record("ssh", "a", "b", "c", "d")
	if none.Report() != nil || none.Status().Entries != 0 {
		t.Error("a nil ledger reported something")
	}
	none.Reset()
}

func TestResetEmptiesItForTheNextWeeksReport(t *testing.T) {
	l := NewLedger(0)
	l.Record("ntp", "plant", "stratum_not_allowed", "", "stratum 9")
	l.Reset()
	if n := len(l.Report()); n != 0 {
		t.Fatalf("%d entries after a reset", n)
	}
	if st := l.Status(); st.Recorded != 0 || st.Dropped != 0 {
		t.Fatalf("status %+v", st)
	}
	// And it still records afterwards, which is the point of resetting.
	l.Record("ntp", "plant", "stratum_not_allowed", "", "stratum 9")
	if n := len(l.Report()); n != 1 {
		t.Fatalf("%d entries after recording again", n)
	}
}

func TestTheLedgerIsSafeFromSeveralGoroutines(t *testing.T) {
	l := NewLedger(0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				l.Record("modbus", "line-"+strconv.Itoa(n%3), "rule_deny",
					"rule"+strconv.Itoa(j%5), "unit "+strconv.Itoa(j))
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = l.Report()
				_ = l.Status()
			}
		}()
	}
	wg.Wait()
	if got := l.Status().Recorded; got != 1600 {
		t.Fatalf("recorded %d of 1600", got)
	}
}
