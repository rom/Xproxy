// Package numrange is the number-range list an operator writes in a policy:
// `5`, `1-16`, `0x10-0x1F`.
//
// Two kinds had their own copy, byte-identical in the part that parses and in
// the part that decides. That is a smaller duplication than the schedule was,
// and it is worth removing for a reason that has nothing to do with the line
// count: the s7 copy's own comment said it was the modbus spelling *on
// purpose*, because "an estate that has both listeners writes address ranges in
// one place and unit numbers in another, and a plant engineer should not have to
// remember that the two kinds read 0-99 differently -- they do not". A promise
// like that held by two copies is a promise waiting to be broken by whoever
// edits one of them.
//
// The decision worth knowing about is Covers. A request is not permitted by a
// range that covers *half* of what it asks for: a read of bytes 0 to 200 against
// a range of 0 to 99 is a read of bytes the policy does not name, and it is
// refused rather than split. Splitting it would mean the relay deciding which
// half the operator meant.
package numrange

import (
	"fmt"
	"strconv"
	"strings"
)

// A Range is an inclusive span. Both ends are inclusive because that is how an
// operator reads `1-16`: sixteen units, not fifteen.
type Range struct {
	Lo, Hi int
}

// Contains says whether one number is in the range.
func (r Range) Contains(v int) bool { return v >= r.Lo && v <= r.Hi }

// String renders a range the way a configuration writes it, so a learned policy
// can be printed back as something an operator could have typed.
//
// There is deliberately no Set.String: the separator between ranges is a
// question about the file being written rather than about the ranges, and the
// modbus kind's learned output joins with a comma and a space. A shared renderer
// that quietly changed that would change a file an operator reads.
func (r Range) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(r.Lo)
	}
	return strconv.Itoa(r.Lo) + "-" + strconv.Itoa(r.Hi)
}

// A Set is a list of ranges. An empty Set matches nothing, and callers treat
// "no list configured" as "no bound" themselves -- the distinction between an
// empty list and an absent one belongs to the policy, not here, because on some
// settings an empty list means "any" and on others it means "none".
type Set []Range

// Covers says whether the whole span from lo to hi is inside a single range.
//
// A single range, not the union: two adjacent ranges `0-99` and `100-199` do
// not together permit a read of 0 to 150. That is deliberate and it is the
// conservative reading -- an operator who wrote two ranges described two
// regions, and a request straddling them is a request neither one names. An
// operator who means one region writes one range.
func (s Set) Covers(lo, hi int) bool {
	for _, r := range s {
		if lo >= r.Lo && hi <= r.Hi {
			return true
		}
	}
	return false
}

// Has says whether one number is in any range.
func (s Set) Has(v int) bool { return s.Covers(v, v) }

// Parse reads the list. `what` names the setting, so an error says which line
// of the file is wrong rather than only what was wrong with it, and max is the
// largest value the setting can hold -- 255 for a Modbus unit identifier, 65535
// for a register, and so on.
func Parse(what string, in []string, max int) (Set, error) {
	out := make(Set, 0, len(in))
	for _, s := range in {
		text := strings.TrimSpace(s)
		if text == "" {
			return nil, fmt.Errorf("%s: an empty range", what)
		}
		lo, hi := text, text
		// IndexByte rather than Cut, and > 0 rather than >= 0, so that a
		// leading minus is a negative number to be refused by the bound
		// below rather than an empty low end.
		if i := strings.IndexByte(text, '-'); i > 0 {
			lo, hi = strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:])
		}
		l, err := ParseNum(lo)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		h, err := ParseNum(hi)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		if l > h {
			return nil, fmt.Errorf("%s: %q starts after it ends", what, s)
		}
		if l < 0 || h > max {
			return nil, fmt.Errorf("%s: %q is outside 0 to %d", what, s, max)
		}
		out = append(out, Range{Lo: l, Hi: h})
	}
	return out, nil
}

// ParseNum reads a decimal number, or a hexadecimal one written `0x10`.
//
// It is exported because a policy reads bare numbers in the same two spellings
// as the ends of a range -- a single register in a value rule, a step size --
// and a setting an operator may write as `0x10` in one field and not another is
// a setting they have to remember an exception about.
//
// Hexadecimal is supported because half the documentation a plant engineer has is
// written that way: a Modbus register map from one vendor lists addresses in
// decimal and from the next in hex, and a policy an engineer has to convert by
// hand before typing is a policy with an arithmetic mistake in it.
func ParseNum(s string) (int, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 32)
		return int(v), err
	}
	return strconv.Atoi(s)
}
