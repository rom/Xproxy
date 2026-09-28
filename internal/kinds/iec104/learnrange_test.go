package iec104

import (
	"testing"

	"github.com/rom/xproxy/internal/numrange"
)

// The ranges in a learning report are what makes it readable. A station
// reporting a thousand consecutive points has to come out as one range, and a
// station reporting a thousand scattered ones has to stop somewhere.

func rangesOf(t *testing.T, addrs ...int) []numrange.Range {
	t.Helper()
	var rs []numrange.Range
	for _, a := range addrs {
		rs = addLearnedRange(rs, a)
	}
	return rs
}

func rangeStrings(rs []numrange.Range) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}

func sameRanges(got []numrange.Range, want ...string) bool {
	gs := rangeStrings(got)
	if len(gs) != len(want) {
		return false
	}
	for i := range gs {
		if gs[i] != want[i] {
			return false
		}
	}
	return true
}

// Consecutive addresses become one range whichever order they arrive in, so a
// report on a station that scans its own point list is one line rather than a
// thousand.
func TestConsecutiveAddressesBecomeOneRange(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []int
		want  []string
	}{
		{name: "upwards", addrs: []int{100, 101, 102}, want: []string{"100-102"}},
		{name: "downwards", addrs: []int{102, 101, 100}, want: []string{"100-102"}},
		{name: "the gap filled last", addrs: []int{100, 102, 101}, want: []string{"100-102"}},
		{name: "a repeat is not a range", addrs: []int{100, 100, 100}, want: []string{"100"}},
		{name: "two clusters stay two", addrs: []int{100, 101, 500, 501}, want: []string{"100-101", "500-501"}},
		{name: "one inside a range changes nothing", addrs: []int{100, 101, 102, 101}, want: []string{"100-102"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rangesOf(t, tc.addrs...); !sameRanges(got, tc.want...) {
				t.Errorf("%v became %v, want %v", tc.addrs, rangeStrings(got), tc.want)
			}
		})
	}
}

// The bound, which is what stops a station reporting ten thousand scattered
// points from producing a report nobody can read.
func TestTheAddressRangesAreBounded(t *testing.T) {
	var rs []numrange.Range
	// Scattered addresses, each two apart so none of them merges.
	for i := 0; i < maxLearnedRanges+50; i++ {
		rs = addLearnedRange(rs, i*2)
	}
	if len(rs) != maxLearnedRanges {
		t.Fatalf("held %d ranges, want the bound of %d", len(rs), maxLearnedRanges)
	}
	// What is kept is the ranges seen first: they are the ones the run has had
	// longest to tell you about, and the report says plainly how many frames
	// the subject had, so a reader can tell the list is partial.
	if rs[0].Lo != 0 {
		t.Errorf("the bound dropped the first range: %v", rangeStrings(rs))
	}

	// And at the bound an address that extends a range it already holds is
	// still folded in, rather than dropped: the ranges are full, not the
	// knowledge of them. This is the case a report would otherwise get wrong by
	// saying a station reads 0-0 when it reads 0-1.
	rs = addLearnedRange(rs, 1)
	if len(rs) > maxLearnedRanges {
		t.Fatalf("extending a range at the bound grew the list past it, to %d", len(rs))
	}
	if !rs[0].Contains(0) || !rs[0].Contains(1) {
		t.Errorf("an address extending the first range at the bound was dropped: %v", rangeStrings(rs)[:1])
	}
	// Extending it also closed the gap to the next range, so the list is one
	// shorter than the bound: a range that grows into its neighbour frees a
	// slot, which is how a run that starts scattered gets tidier as it learns
	// rather than staying at the bound for ever.
	if len(rs) != maxLearnedRanges-1 {
		t.Errorf("held %d ranges after the merge, want %d", len(rs), maxLearnedRanges-1)
	}
}
