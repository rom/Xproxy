package shed

import "testing"

// A route's priority class decides whether it is shed under load, so a
// value the configuration spells and this package does not recognise
// must land on the safe side — normal, shed like everything else —
// rather than on critical, which would make a typo a route that never
// sheds.
func TestParseClass(t *testing.T) {
	cases := map[string]Class{
		"low":       Low,
		"normal":    Normal,
		"high":      High,
		"critical":  Critical,
		"":          Normal,
		"Low":       Normal,
		"LOW":       Normal,
		"\u0020low": Normal, // a leading space is not a class name
		"lowest":    Normal,
		"urgent":    Normal,
		"0":         Normal,
	}
	for in, want := range cases {
		if got := ParseClass(in); got != want {
			t.Errorf("ParseClass(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestClassString is the other direction, which is what the status
// views and the access log print.
func TestClassString(t *testing.T) {
	for _, c := range []Class{Low, Normal, High, Critical} {
		s := c.String()
		if s == "" {
			t.Fatalf("class %d renders as an empty string", c)
		}
		if ParseClass(s) != c {
			t.Fatalf("%v renders as %q, which parses back as %v", c, s, ParseClass(s))
		}
	}
	// A value no constant names still renders as something printable.
	if got := Class(99).String(); got != "normal" {
		t.Fatalf("an unknown class renders as %q", got)
	}
}
