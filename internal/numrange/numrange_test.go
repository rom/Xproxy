package numrange

import "testing"

func TestTheSpellingsAnEngineerWrites(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want Set
	}{
		{[]string{"5"}, Set{{5, 5}}},
		{[]string{"1-16"}, Set{{1, 16}}},
		{[]string{"0x10-0x1F"}, Set{{16, 31}}},
		{[]string{"0X10"}, Set{{16, 16}}},
		// Whitespace around a range and around its ends, because a list
		// written over several YAML lines picks it up.
		{[]string{" 1 - 16 "}, Set{{1, 16}}},
		{[]string{"1", "10-20", "0x30"}, Set{{1, 1}, {10, 20}, {48, 48}}},
		// A range of one is a range.
		{[]string{"7-7"}, Set{{7, 7}}},
		{[]string{"0"}, Set{{0, 0}}},
		{nil, Set{}},
	} {
		got, err := Parse("units", c.in, 0xFFFF)
		if err != nil {
			t.Errorf("Parse(%v): %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("Parse(%v) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("Parse(%v)[%d] = %v, want %v", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestWhatIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []string
		max  int
	}{
		{"an empty entry", []string{""}, 255},
		{"only whitespace", []string{"   "}, 255},
		{"backwards", []string{"20-10"}, 255},
		{"past the bound", []string{"300"}, 255},
		{"a range whose end is past the bound", []string{"1-300"}, 255},
		{"not a number", []string{"five"}, 255},
		{"not hexadecimal", []string{"0xZZ"}, 255},
		{"a negative number", []string{"-5"}, 255},
		{"a range with no end", []string{"5-"}, 255},
		{"a float", []string{"1.5"}, 255},
	} {
		if _, err := Parse("units", c.in, c.max); err == nil {
			t.Errorf("%s (%v) was accepted", c.name, c.in)
		}
	}
}

// The error names the setting, because a policy has several range lists and
// "300 is outside 0 to 255" without the field is a message an operator cannot
// act on.
func TestTheErrorNamesTheSetting(t *testing.T) {
	_, err := Parse("rules.hmi.addresses", []string{"70000"}, 0xFFFF)
	if err == nil {
		t.Fatal("accepted")
	}
	if got := err.Error(); got[:len("rules.hmi.addresses")] != "rules.hmi.addresses" {
		t.Errorf("the error is %q", got)
	}
}

// Covers is the decision the two kinds share, and the conservative reading is
// the point: a request straddling two adjacent ranges is refused rather than
// split, because an operator who wrote two ranges described two regions.
func TestCoversNeedsOneRangeToHoldTheWholeSpan(t *testing.T) {
	s := Set{{0, 99}, {100, 199}, {1000, 1000}}
	for _, c := range []struct {
		name   string
		lo, hi int
		want   bool
	}{
		{"inside one range", 10, 20, true},
		{"exactly one range", 0, 99, true},
		{"a single number", 150, 150, true},
		{"a single-number range", 1000, 1000, true},
		{"straddling two adjacent ranges", 50, 150, false},
		{"starting inside and ending outside", 90, 109, false},
		{"entirely outside", 500, 600, false},
		{"one past the end", 0, 100, false},
	} {
		if got := s.Covers(c.lo, c.hi); got != c.want {
			t.Errorf("%s: Covers(%d, %d) = %v, want %v", c.name, c.lo, c.hi, got, c.want)
		}
	}
}

func TestHasAndContains(t *testing.T) {
	s := Set{{10, 20}}
	for v, want := range map[int]bool{9: false, 10: true, 15: true, 20: true, 21: false} {
		if got := s.Has(v); got != want {
			t.Errorf("Has(%d) = %v, want %v", v, got, want)
		}
		if got := (Range{10, 20}).Contains(v); got != want {
			t.Errorf("Contains(%d) = %v, want %v", v, got, want)
		}
	}
	// An empty set matches nothing. Callers that mean "no list is no bound"
	// check the length themselves, because on some settings an empty list
	// means any and on others it means none.
	if (Set{}).Has(5) || (Set{}).Covers(5, 5) {
		t.Error("an empty set matched")
	}
}

// String renders what an operator could have typed, which is what makes the
// modbus kind's learned output a file somebody can paste into a policy.
func TestStringRoundTrips(t *testing.T) {
	for _, s := range []string{"5", "1-16", "0-65535"} {
		got, err := Parse("x", []string{s}, 0xFFFF)
		if err != nil {
			t.Fatal(err)
		}
		if out := got[0].String(); out != s {
			t.Errorf("%q rendered back as %q", s, out)
		}
	}
}

func TestParseNum(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"0", 0, true}, {"255", 255, true}, {"0x00", 0, true},
		{"0xff", 255, true}, {"0XFF", 255, true}, {"", 0, false},
		{"0x", 0, false}, {"ff", 0, false}, {"0b11", 0, false},
	} {
		got, err := ParseNum(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseNum(%q) err = %v, want ok %v", c.in, err, c.ok)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("ParseNum(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
