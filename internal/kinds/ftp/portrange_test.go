package ftp

import (
	"strings"
	"testing"
)

// The passive port range, which is the one piece of this listener's
// configuration that is parsed rather than used as it stands.
//
// It is worth its own test because every wrong reading of it is a listener that
// starts and then fails in the field: a range the firewall does not have open, a
// range of one port, a reversed pair that would let the listener bind anywhere.
// The parse is where all of that is caught.
func TestThePassivePortRangeIsReadOrRefusedAtLoad(t *testing.T) {
	for _, c := range []struct {
		in     string
		lo, hi int
	}{
		// Empty, and the explicit zero pair, both mean "no range of its own":
		// the kernel picks the port.
		{"", 0, 0},
		{"0-0", 0, 0},
		{"50000-50100", 50000, 50100},
		// Spaces around either end are what a hand-edited file has in it.
		{" 50000 - 50100 ", 50000, 50100},
		// A range of one port is a range: an estate with one hole in its
		// firewall is a real configuration.
		{"50000-50000", 50000, 50000},
		{"1-65535", 1, 65535},
	} {
		lo, hi, err := parsePortRange(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if lo != c.lo || hi != c.hi {
			t.Errorf("%q parsed to %d-%d, want %d-%d", c.in, lo, hi, c.lo, c.hi)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"50000", `must be written "low-high"`},
		{"fifty-thousand", "invalid syntax"},
		{"50000-", "invalid syntax"},
		{"-50100", "invalid syntax"},
		// The three bounds that would be a listener binding somewhere nobody
		// meant: below the first port, above the last, and backwards.
		{"0-50100", "must be 1..65535"},
		{"50000-70000", "must be 1..65535"},
		{"50100-50000", "low no higher than high"},
	} {
		_, _, err := parsePortRange(c.in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q returned %v, want an error containing %q", c.in, err, c.want)
		}
	}
}
