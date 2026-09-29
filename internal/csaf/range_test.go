package csaf

import "testing"

// The ranges this reads, checked by asking each one about versions either side
// of its bound.
func TestTheRangesItReads(t *testing.T) {
	for _, c := range []struct {
		raw string
		in  []string
		out []string
	}{
		// vers expressions, which is what the standard asks for.
		{"vers:all/<V4.2", []string{"V4.1", "V4.1.9", "V2.0"}, []string{"V4.2", "V4.2.1", "V5.0"}},
		{"vers:all/<=V4.2", []string{"V4.2", "V4.1"}, []string{"V4.2.1", "V4.3"}},
		{"vers:all/*", []string{"V1.0", "V9.9"}, nil},
		{"vers:all/>=V2.0|<V2.9.2", []string{"V2.0", "V2.9.1"}, []string{"V1.9", "V2.9.2", "V3.0"}},
		{"vers:all/=V4.2", []string{"V4.2", "V4.2.0"}, []string{"V4.2.1", "V4.1"}},
		{"vers:all/<V4.2|!=V4.1", []string{"V4.0"}, []string{"V4.1", "V4.2"}},
		// And the English the vendors write instead.
		{"All versions", []string{"V1.0", "V9.9"}, nil},
		{"All versions < V4.2", []string{"V4.1"}, []string{"V4.2"}},
		{"All versions >= V2.0 < V2.9.2", []string{"V2.5"}, []string{"V1.0", "V2.9.2"}},
		{"< V4.2", []string{"V4.1"}, []string{"V4.2"}},
		{"prior to V4.2", []string{"V4.1"}, []string{"V4.2"}},
		{"V4.2 and earlier", []string{"V4.2", "V4.1"}, []string{"V4.3"}},
		{"V4.2 or later", []string{"V4.2", "V5.0"}, []string{"V4.1"}},
		{"All versions up to and including V1.5", []string{"V1.5", "V1.0"}, []string{"V1.6"}},
		{"V4.0 - V4.2", []string{"V4.0", "V4.1", "V4.2"}, []string{"V3.9", "V4.3"}},
		{"All versions < V2.9.2 and >= V2.0", []string{"V2.5"}, []string{"V1.0", "V3.0"}},
	} {
		r := ParseRange(c.raw)
		if !r.Readable() {
			t.Errorf("%q was not read: %s", c.raw, r.Why())
			continue
		}
		for _, want := range c.in {
			v, err := ParseVersion(want)
			if err != nil {
				t.Fatalf("%q: %v", want, err)
			}
			got, err := r.Contains(v)
			if err != nil {
				t.Errorf("%q against %q: %v", c.raw, want, err)
				continue
			}
			if !got {
				t.Errorf("%q does not contain %q and should", c.raw, want)
			}
		}
		for _, want := range c.out {
			v, err := ParseVersion(want)
			if err != nil {
				t.Fatalf("%q: %v", want, err)
			}
			got, err := r.Contains(v)
			if err != nil {
				t.Errorf("%q against %q: %v", c.raw, want, err)
				continue
			}
			if got {
				t.Errorf("%q contains %q and should not", c.raw, want)
			}
		}
	}
}

// The ranges it refuses, which are the ones that would otherwise be guessed at.
// Each has to come back unreadable *and* carry its own text, because the text is
// the finding: an operator reads which sentence the tool could not evaluate.
func TestTheRangesItRefuses(t *testing.T) {
	for _, raw := range []string{
		"",
		// A condition rather than a version range. This is the one that matters
		// most: the vendor is saying something true and specific, and a matcher
		// that dropped the condition would report every one of those devices as
		// affected whatever card is fitted.
		"All versions < V2.9.2 with CP1604 fitted",
		"All versions with the web server enabled",
		"see the advisory",
		"unknown",
		// Three bounds, which the pairing algorithm this does not implement
		// would be needed for.
		"vers:all/>V1.0|<V2.0|>V3.0",
		"vers:all/<Rel. 04.03",
		"vers:no-slash-here",
		"V4.0 - Rel. 04.03",
	} {
		r := ParseRange(raw)
		if r.Readable() {
			t.Errorf("%q was read as a range", raw)
			continue
		}
		if r.Why() == "" {
			t.Errorf("%q was refused with no reason, so no finding can say why", raw)
		}
		v, err := ParseVersion("V4.1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Contains(v); err == nil {
			t.Errorf("%q answered a containment question it cannot answer", raw)
		}
	}
}

// An unreadable range does not quietly contain nothing. That distinction is the
// whole point: "contains nothing" reads as "no device is affected", and this has
// to read as "nobody has assessed these devices".
func TestAnUnreadableRangeIsAnErrorRatherThanEmpty(t *testing.T) {
	r := ParseRange("All versions < V2.9.2 with CP1604 fitted")
	v, err := ParseVersion("V1.0")
	if err != nil {
		t.Fatal(err)
	}
	in, err := r.Contains(v)
	if err == nil {
		t.Fatal("an unreadable range answered a containment question")
	}
	if in {
		t.Error("an unreadable range said yes")
	}
	if r.Everything() {
		t.Error("an unreadable range claimed to be every version")
	}
}

// A product named with no version at all is every version of it, which is what
// the vendor means and what an exact version is not.
func TestEveryVersionAndOneVersion(t *testing.T) {
	all := AllVersions()
	if !all.Everything() || !all.Readable() {
		t.Fatal("AllVersions is not every version")
	}
	v, err := ParseVersion("V4.2")
	if err != nil {
		t.Fatal(err)
	}
	one := ExactVersion(v)
	if one.Everything() {
		t.Error("an exact version claimed to be every version")
	}
	if in, err := one.Contains(v); err != nil || !in {
		t.Errorf("an exact version does not contain itself: %v %v", in, err)
	}
	other, err := ParseVersion("V4.3")
	if err != nil {
		t.Fatal(err)
	}
	if in, err := one.Contains(other); err != nil || in {
		t.Errorf("V4.2 contains V4.3: %v %v", in, err)
	}
}
