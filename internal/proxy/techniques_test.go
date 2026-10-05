package proxy

import (
	"strings"
	"testing"
	"time"
)

// The ATT&CK view over the refusal counters.
//
// The mapping itself lives in internal/attack and is tested there against the
// documentation. What is here is the counting: a refusal is counted once under
// its own reason and once under every technique that reason maps to, the table
// stays bounded because both halves of the key come from fixed vocabularies, and
// the identifiers come back sorted -- which matters because this is what a view
// lists, and a list that reordered itself between reads would read as movement.
func TestARefusalIsCountedUnderEveryTechniqueItMapsTo(t *testing.T) {
	var s Stats
	if got := s.TechniqueCounts(); got != nil {
		t.Errorf("a process that refused nothing reported %v", got)
	}
	if got := s.TechniqueIDs(); len(got) != 0 {
		t.Errorf("a process that refused nothing listed %v", got)
	}

	// A reason that maps to two techniques: the broad one and the sub-technique
	// under it. Both are counted, because a view that showed only one would
	// under-report whichever an operator was looking at.
	s.Refuse("imap", "fetch_too_large")
	counts := s.TechniqueCounts()
	if counts["T1114"] != 1 || counts["T1114.002"] != 1 {
		t.Fatalf("one mail-collection refusal counted %v", counts)
	}
	// A second refusal of the same shape adds to both, and a different reason
	// mapping to one of them adds to that one alone.
	s.Refuse("imap", "open_sequence_set")
	s.Refuse("imap", "mailbox_denied")
	counts = s.TechniqueCounts()
	if counts["T1114"] != 3 || counts["T1114.002"] != 2 {
		t.Fatalf("three refusals counted %v", counts)
	}
	// A reason with no mapping is still a refusal and is simply not a
	// technique: the table is about what the taxonomy covers, not about what
	// was refused.
	s.Refuse("imap", "literal_argument")
	before := len(s.TechniqueCounts())
	s.Refuse("vnc", "version")
	if got := len(s.TechniqueCounts()); got < before {
		t.Errorf("the technique table shrank from %d to %d", before, got)
	}
	// And a kind the roster does not have counts nothing at all, which is how
	// the table stays bounded whatever a caller passes.
	was := s.TechniqueCounts()
	s.Refuse("not-a-protocol", "fetch_too_large")
	if got := s.TechniqueCounts(); len(got) != len(was) {
		t.Errorf("a kind outside the roster added %d identifiers", len(got)-len(was))
	}
	// The identifiers come back sorted.
	ids := s.TechniqueIDs()
	if len(ids) < 2 {
		t.Fatalf("the identifiers seen are %v", ids)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Fatalf("the identifiers are not sorted: %v", ids)
		}
	}
	// Every identifier listed has a count, and every counted identifier is
	// listed: the two views are of one table.
	if len(ids) != len(counts) && len(ids) != len(s.TechniqueCounts()) {
		t.Errorf("%d identifiers listed against %d counted", len(ids), len(s.TechniqueCounts()))
	}
	for _, id := range ids {
		if !strings.HasPrefix(id, "T") {
			t.Errorf("%q is not an ATT&CK identifier", id)
		}
		if s.TechniqueCounts()[id] == 0 {
			t.Errorf("%s is listed with no count", id)
		}
	}
}

// The three renderings the metrics exporter leans on, each of which exists
// because the obvious answer reads as something else on a dashboard.
func TestTheMetricRenderingsSayWhatTheyMean(t *testing.T) {
	// An empty list kind reads as a broken exporter, and "cidr" is what the
	// configuration means by leaving it out.
	if got := listKind(""); got != "cidr" {
		t.Errorf("an unnamed list kind is exported as %q", got)
	}
	for _, kind := range []string{"cidr", "ja4", "domain", "url", "hash"} {
		if got := listKind(kind); got != kind {
			t.Errorf("list kind %q is exported as %q", kind, got)
		}
	}
	if b2f(true) != 1 || b2f(false) != 0 {
		t.Errorf("a boolean gauge exports as %v and %v", b2f(true), b2f(false))
	}
	// A staleness gauge of 1.7e9 on a list that was never read would fire
	// every threshold there is and say nothing, so a zero time is zero.
	if got := sinceSeconds(time.Time{}); got != 0 {
		t.Errorf("something that never happened is %v seconds ago", got)
	}
	if got := sinceSeconds(time.Now().Add(-2 * time.Second)); got < 1.5 || got > 60 {
		t.Errorf("two seconds ago is reported as %v seconds", got)
	}
}
