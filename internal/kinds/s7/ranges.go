package s7

import (
	"fmt"
	"strconv"
	"strings"
)

// The ranges an operator writes: "5", "1-16", "0x10-0x1F".
//
// The spelling is the modbus kind's, deliberately. An estate that has both
// listeners writes address ranges in one place and unit numbers in another,
// and a plant engineer should not have to remember that the two kinds read
// "0-99" differently -- they do not.

type rng struct{ lo, hi int }

type ranges []rng

// covers says whether the whole span from lo to hi is inside one range.
//
// A request is not allowed by a range that covers half of what it asks for: a
// read of bytes 0 to 200 against a range of 0 to 99 is a read of bytes the
// policy does not name, and splitting it into the part that is allowed is not
// this relay's decision to make.
func (rs ranges) covers(lo, hi int) bool {
	for _, r := range rs {
		if lo >= r.lo && hi <= r.hi {
			return true
		}
	}
	return false
}

// has says whether one number is in any range.
func (rs ranges) has(v int) bool { return rs.covers(v, v) }

func parseRanges(what string, in []string, max int) (ranges, error) {
	out := make(ranges, 0, len(in))
	for _, s := range in {
		text := strings.TrimSpace(s)
		if text == "" {
			return nil, fmt.Errorf("%s: an empty range", what)
		}
		lo, hi := text, text
		if i := strings.IndexByte(text, '-'); i > 0 {
			lo, hi = strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:])
		}
		l, err := parseNum(lo)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		h, err := parseNum(hi)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		if l > h {
			return nil, fmt.Errorf("%s: %q starts after it ends", what, s)
		}
		if l < 0 || h > max {
			return nil, fmt.Errorf("%s: %q is outside 0 to %d", what, s, max)
		}
		out = append(out, rng{l, h})
	}
	return out, nil
}

func parseNum(s string) (int, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 32)
		return int(v), err
	}
	return strconv.Atoi(s)
}
