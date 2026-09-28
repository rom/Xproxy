package s7

import (
	"testing"

	"github.com/rom/xproxy/internal/numrange"
)

// An observation is copied before it is rendered, because the report is written
// outside the table's lock and the ranges are merged in place. A copy that
// shared them would let a request arriving mid-report change the report -- and,
// worse, be a data race on a slice the renderer is walking.
func TestAnObservationIsCopiedDeeply(t *testing.T) {
	o := learnObs{
		bytes:      []numrange.Range{{Lo: 0, Hi: 3}},
		writeBytes: []numrange.Range{{Lo: 8, Hi: 9}},
		transports: map[string]bool{"byte": true},
		functions:  map[string]bool{"read_var": true},
	}
	c := cloneS7Obs(o)
	o.bytes[0].Hi = 99
	o.writeBytes[0].Hi = 99
	o.transports["word"] = true
	o.functions["write_var"] = true

	if c.bytes[0].Hi != 3 {
		t.Errorf("the copied read ranges follow the original: %s", rangeText(c.bytes))
	}
	if c.writeBytes[0].Hi != 9 {
		t.Errorf("the copied write ranges follow the original: %s", rangeText(c.writeBytes))
	}
	if c.transports["word"] {
		t.Error("the copied transport set follows the original")
	}
	if c.functions["write_var"] {
		t.Error("the copied function set follows the original")
	}
}

// The byte ranges a learning run remembers.
//
// A report with a line per request is a report nobody reads, so adjacent reads
// have to fold into one span. And a client walking a whole block must not be
// able to make the report grow without end.

func rangeText(rs []numrange.Range) string { return s7RangeText(rs) }

func TestAdjacentReadsBecomeOneRange(t *testing.T) {
	var rs []numrange.Range
	rs = addS7Range(rs, 0, 3)
	rs = addS7Range(rs, 4, 7)
	if len(rs) != 1 {
		t.Fatalf("two adjacent reads produced %d ranges: %s", len(rs), rangeText(rs))
	}
	if rs[0].Lo != 0 || rs[0].Hi != 7 {
		t.Errorf("the merged range is %s, want 0-7", rangeText(rs))
	}
}

func TestASeparateRangeStaysSeparate(t *testing.T) {
	var rs []numrange.Range
	rs = addS7Range(rs, 0, 3)
	rs = addS7Range(rs, 8, 11)
	if len(rs) != 2 {
		t.Fatalf("a gap of four bytes was swallowed: %s", rangeText(rs))
	}
}

// A range that swallows the gap between two others collapses all three, because
// the bytes really are contiguous now.
func TestARangeThatBridgesTwoCollapsesThem(t *testing.T) {
	var rs []numrange.Range
	rs = addS7Range(rs, 0, 3)
	rs = addS7Range(rs, 10, 13)
	rs = addS7Range(rs, 4, 9)
	if len(rs) != 1 || rs[0].Lo != 0 || rs[0].Hi != 13 {
		t.Fatalf("the bridge left %s, want one 0-13", rangeText(rs))
	}
}

// An item whose length the parser reports as zero is still one byte, and never a
// range that runs backwards.
func TestARangeNeverRunsBackwards(t *testing.T) {
	rs := addS7Range(nil, 12, 4)
	if len(rs) != 1 || rs[0].Lo != 12 || rs[0].Hi != 12 {
		t.Fatalf("a backwards span became %s", rangeText(rs))
	}
}

// A client walking a block one disjoint byte at a time stops at the bound
// rather than growing the report without end.
func TestTheRangeCountIsBounded(t *testing.T) {
	var rs []numrange.Range
	for i := 0; i < maxLearnedS7Ranges*4; i++ {
		rs = addS7Range(rs, i*4, i*4)
	}
	if len(rs) != maxLearnedS7Ranges {
		t.Fatalf("a walk produced %d ranges, want the bound of %d", len(rs), maxLearnedS7Ranges)
	}
	// And past the bound, a span that touches one already there still widens it:
	// the bound is on how many are remembered, not on what each covers.
	rs = addS7Range(rs, 1, 2)
	if len(rs) != maxLearnedS7Ranges {
		t.Fatalf("widening past the bound changed the count to %d", len(rs))
	}
	if rs[0].Lo != 0 || rs[0].Hi != 2 {
		t.Errorf("the first range is %s, want it widened to 0-2", rangeText(rs[:1]))
	}
}
