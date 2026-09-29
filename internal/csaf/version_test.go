package csaf

import (
	"errors"
	"strings"
	"testing"
)

// The versions this compares, and the ones it refuses.
//
// The refusals are the half worth testing hardest: every string in the second
// table is one a device somewhere really reports, and each one has to come back
// as an error rather than as a number this package invented.
func TestTheVersionsItCompares(t *testing.T) {
	for _, c := range []struct {
		in   string
		nums []uint64
		kind string
		ord  uint64
	}{
		{"V4.2", []uint64{4, 2}, ordNone, 0},
		{"v4.2.1", []uint64{4, 2, 1}, ordNone, 0},
		{"4.2.1", []uint64{4, 2, 1}, ordNone, 0},
		{"Version 4.2.1", []uint64{4, 2, 1}, ordNone, 0},
		{"  V2.70  ", []uint64{2, 70}, ordNone, 0},
		{"4.2.1-3", []uint64{4, 2, 1, 3}, ordNone, 0},
		{"4.2.1_3", []uint64{4, 2, 1, 3}, ordNone, 0},
		{"V2.9.2 Update 4", []uint64{2, 9, 2}, ordUpdate, 4},
		{"V2.9.2 Upd4", []uint64{2, 9, 2}, ordUpdate, 4},
		{"V1.2 SP3", []uint64{1, 2}, ordSP, 3},
		{"V1.2 Service Pack 3", []uint64{1, 2}, ordSP, 3},
		{"V1.2 HF1", []uint64{1, 2}, ordHotfix, 1},
		{"V4.2 P01", []uint64{4, 2}, ordPatch, 1},
	} {
		v, err := ParseVersion(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if len(v.nums) != len(c.nums) {
			t.Errorf("%q gave %v, want %v", c.in, v.nums, c.nums)
			continue
		}
		for i := range c.nums {
			if v.nums[i] != c.nums[i] {
				t.Errorf("%q gave %v, want %v", c.in, v.nums, c.nums)
				break
			}
		}
		if v.kind != c.kind || v.ord != c.ord {
			t.Errorf("%q gave ordinal %s%d, want %s%d", c.in, v.kind, v.ord, c.kind, c.ord)
		}
		if v.String() != strings.TrimSpace(c.in) {
			t.Errorf("%q printed as %q: a finding has to carry the device's own string", c.in, v.String())
		}
	}
}

// Every one of these is a string some device reports as its firmware, and every
// one of them has to be a refusal. A version this package guessed at would
// produce a "not affected" nobody can check, which is the one output worth
// preventing.
func TestTheVersionsItRefuses(t *testing.T) {
	for _, in := range []string{
		"",
		"   ",
		"v",
		"Rel. 04.03",         // a Hirschmann switch
		"1.20.4 build 7",     // a build identifier
		"2.9.2 Upd4 HF1",     // two ordinals, and no order between them
		"V1.2 SP",            // a service pack with no number
		"AB-1756-L71/B",      // a model number in the version field
		"4.2.1-rc1",          // a pre-release
		"unknown",            //
		"1.2.3.4.5.6.7",      // more components than a version has
		"V4.2 patchlevel",    //
		"1.2.beta",           //
		"V" + longString(80), // past the length bound
	} {
		v, err := ParseVersion(in)
		if err == nil {
			t.Errorf("%q was read as %v; it has to be refused", in, v.nums)
			continue
		}
		if !errors.Is(err, ErrUnreadable) {
			t.Errorf("%q gave %v, which is not an unreadable-version error", in, err)
		}
	}
}

// A date-shaped firmware version is the case where a comparison would be
// arithmetic rather than meaning: 20240115 is a larger number than 4.2 and
// says nothing about whether the device is below V4.2. So it parses -- it is a
// number -- and the comparison against a dotted version is refused, while two
// dates compare as the same scheme twice.
func TestADateIsNotComparedAgainstAVersion(t *testing.T) {
	date, err := ParseVersion("20240115")
	if err != nil {
		t.Fatalf("a dated firmware version is a version: %v", err)
	}
	dotted, err := ParseVersion("V4.2")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Compare(date, dotted); err == nil {
		t.Errorf("20240115 against V4.2 gave %d; two numbering schemes cannot be ordered", got)
	}
	later, err := ParseVersion("20240201")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Compare(date, later); err != nil || got != -1 {
		t.Errorf("20240115 against 20240201 gave %d, %v", got, err)
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '1'
	}
	return string(b)
}

func TestTheComparison(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"V4.2", "V4.3", -1},
		{"V4.3", "V4.2", 1},
		{"V4.2", "V4.2", 0},
		// A missing component is zero, which is what "< V4.2" means to every
		// vendor that writes it.
		{"V4.2", "V4.2.0", 0},
		{"V4.2.1", "V4.2", 1},
		{"V4.10", "V4.9", 1},
		// An ordinal sorts after the bare version it is applied to.
		{"V2.9.2", "V2.9.2 Upd4", -1},
		{"V2.9.2 Upd4", "V2.9.2 Upd5", -1},
		{"V2.9.2 Upd4", "V2.9.2", 1},
	} {
		a, err := ParseVersion(c.a)
		if err != nil {
			t.Fatalf("%q: %v", c.a, err)
		}
		b, err := ParseVersion(c.b)
		if err != nil {
			t.Fatalf("%q: %v", c.b, err)
		}
		got, err := Compare(a, b)
		if err != nil {
			t.Errorf("%q against %q: %v", c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q against %q gave %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// Two different ordinals on the same numbers are not comparable, because
// nothing says whether a service pack precedes a hotfix. The honest answer is
// an error, which the caller turns into "not assessed".
func TestTwoOrdinalKindsAreNotComparable(t *testing.T) {
	a, err := ParseVersion("V1.2 SP3")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseVersion("V1.2 HF1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compare(a, b); err == nil {
		t.Fatal("a service pack was ordered against a hotfix")
	}
	// And the same pair on different numbers *is* comparable, because the
	// numbers decide before the ordinals are reached.
	c, err := ParseVersion("V1.3 HF1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Compare(a, c); err != nil || got != -1 {
		t.Errorf("V1.2 SP3 against V1.3 HF1 gave %d, %v", got, err)
	}
}
