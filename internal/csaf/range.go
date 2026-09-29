package csaf

import (
	"fmt"
	"strings"
)

// The version ranges a CSAF product tree carries, and the ones this package
// will read.
//
// A CSAF product tree names a product's versions two ways. A
// `product_version` branch is one exact version, which is easy. A
// `product_version_range` branch is a *range*, and the standard says its value
// should be a `vers` expression (the Package URL project's version-range
// specification) -- but it does not require it, and in practice vendors write
// English: "All versions < V4.2", "All versions >= V2.0 < V2.9.2", or
// occasionally a sentence about which cards are fitted.
//
// So this reads both, and the rule is the same as everywhere else here: a range
// it cannot read exactly becomes a refusal that names the text, not a guess at
// the vendor's intention. A product whose range is unreadable makes every
// device that matched the product **not assessed** -- which is a line an
// operator can act on ("these are the ones the tool could not decide"), where
// an approximation would be a line nobody can check.
//
// The vers subset is also deliberately narrow. The full specification pairs an
// arbitrary list of constraints into ranges by a documented algorithm; what is
// implemented here is one lower bound, one upper bound, exact versions and
// exclusions, which is every expression the vendors in scope actually emit. A
// list this cannot pair is refused rather than approximated, for the same
// reason.

// Range is a set of versions, as a product tree wrote it.
//
// The zero Range is unreadable: it matches nothing and says so, which is what
// makes an unparsed range visible rather than silently empty.
type Range struct {
	raw string
	// all is a range over every version of the product: "All versions", or
	// vers's own "*". It is the one range that needs no comparison, and it is
	// how most ICS advisories name a product with no fix yet.
	all bool
	// lower and upper are the bounds, when there are any.
	lower, upper *bound
	// equals are exact versions this range is the union of.
	equals []Version
	// nots are versions excluded from it.
	nots []Version
	// ok says the text was read. A Range built from text this could not read
	// is !ok and returns an error from Contains, rather than quietly
	// containing nothing.
	ok bool
	// why is what could not be read, for the finding.
	why string
}

// bound is one end of a range.
type bound struct {
	v         Version
	inclusive bool
}

// AllVersions is the range over every version of a product, which is what an
// advisory means by "All versions" -- usually because there is no fix yet.
func AllVersions() Range { return Range{raw: "all versions", all: true, ok: true} }

// ExactVersion is the range that is one version, which is what a
// product_version branch names.
func ExactVersion(v Version) Range {
	return Range{raw: v.String(), equals: []Version{v}, ok: true}
}

// Readable says whether the range was understood. An unreadable range is not a
// failure to report and move on from: it is the reason a device is not
// assessed, and the caller carries its text into the finding.
func (r Range) Readable() bool { return r.ok }

// String is the range as the document wrote it.
func (r Range) String() string { return r.raw }

// Why is what could not be read, when the range is unreadable.
func (r Range) Why() string { return r.why }

// Everything says whether this range is every version of the product, which a
// caller reports differently: "affected, no version bound given" is a
// different sentence from "affected, below V4.2".
func (r Range) Everything() bool { return r.all }

// ParseRange reads a product_version_range value.
func ParseRange(s string) Range {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Range{raw: s, why: "empty"}
	}
	if strings.HasPrefix(strings.ToLower(raw), "vers:") {
		return parseVers(raw)
	}
	return parseText(raw)
}

// MaxConstraints bounds the constraints in one range. A vers expression with
// more than this is not one of the shapes below, and walking an unbounded list
// would be a document deciding how much work this does.
const MaxConstraints = 16

// parseVers reads a vers expression: vers:<scheme>/<constraint>|<constraint>...
func parseVers(raw string) Range {
	out := Range{raw: raw}
	rest := raw[len("vers:"):]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		out.why = "a vers expression with no scheme"
		return out
	}
	list := strings.Split(rest[slash+1:], "|")
	if len(list) > MaxConstraints {
		out.why = fmt.Sprintf("a vers expression with %d constraints", len(list))
		return out
	}
	for _, c := range list {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if c == "*" {
			// vers's own "every version". It is exclusive of everything else
			// by the specification, so nothing more need be read.
			out.all, out.ok = true, true
			return out
		}
		op, val := splitOp(c)
		v, err := ParseVersion(val)
		if err != nil {
			out.why = fmt.Sprintf("a version this cannot compare: %q", val)
			return out
		}
		if !out.constrain(op, v) {
			// Two lower bounds, or two upper bounds: pairing those is the
			// part of the vers algorithm this does not implement, and
			// guessing the pairing would be inventing the range.
			out.why = fmt.Sprintf("more bounds than this pairs: %q", raw)
			return out
		}
	}
	if out.lower == nil && out.upper == nil && len(out.equals) == 0 {
		out.why = "no constraint"
		return out
	}
	out.ok = true
	return out
}

// constrain adds one comparison, and says whether it fits the shapes this
// package pairs.
func (r *Range) constrain(op string, v Version) bool {
	switch op {
	case "<", "<=":
		if r.upper != nil {
			return false
		}
		r.upper = &bound{v: v, inclusive: op == "<="}
	case ">", ">=":
		if r.lower != nil {
			return false
		}
		r.lower = &bound{v: v, inclusive: op == ">="}
	case "!=":
		r.nots = append(r.nots, v)
	default: // "=" and a bare version
		r.equals = append(r.equals, v)
	}
	return true
}

// splitOp takes the comparator off the front of a constraint.
func splitOp(c string) (op, val string) {
	for _, o := range []string{"<=", ">=", "!=", "<", ">", "="} {
		if strings.HasPrefix(c, o) {
			return o, strings.TrimSpace(c[len(o):])
		}
	}
	return "=", c
}

// parseText reads the English a vendor's advisory tooling writes instead of a
// vers expression.
//
// The forms below are the ones Siemens ProductCERT, Schneider Electric and the
// CISA ICS advisories emit. Everything else is refused with its own text in the
// finding -- including anything conditional ("All versions with CP1604
// fitted"), because a condition this package cannot evaluate is not a version
// range at all.
func parseText(raw string) Range {
	out := Range{raw: raw}
	s := strings.ToLower(raw)
	s = strings.NewReplacer("≤", "<=", "≥", ">=", "−", "-").Replace(s)
	// The collective openings, which say nothing on their own.
	for _, p := range []string{"all versions", "all version", "versions", "version"} {
		if strings.HasPrefix(s, p) {
			s = strings.TrimSpace(s[len(p):])
			break
		}
	}
	// The English comparators, rewritten into the symbols read below. Longest
	// first, so "up to and including" is not read as "up to".
	for _, sub := range [][2]string{
		{"up to and including", "<="},
		{"and prior", "<="},
		{"or prior", "<="},
		{"and earlier", "<="},
		{"or earlier", "<="},
		{"and below", "<="},
		{"or below", "<="},
		{"prior to", "<"},
		{"earlier than", "<"},
		{"before", "<"},
		{"and later", ">="},
		{"or later", ">="},
		{"and above", ">="},
		{"or above", ">="},
		{"and newer", ">="},
		{"or newer", ">="},
	} {
		if !strings.Contains(s, sub[0]) {
			continue
		}
		// A trailing form ("V4.2 and earlier") puts the comparator in front
		// of the version; a leading one ("prior to V4.2") already is.
		s = strings.TrimSpace(strings.Replace(s, sub[0], " "+sub[1]+" ", 1))
		if strings.HasSuffix(s, sub[1]) {
			s = sub[1] + " " + strings.TrimSpace(strings.TrimSuffix(s, sub[1]))
		}
		break
	}
	s = strings.TrimSpace(strings.Trim(s, ":"))
	if s == "" {
		// "All versions", and nothing else: every version of the product.
		out.all, out.ok = true, true
		return out
	}
	// "V4.0 - V4.2" is a closed interval. It is read before the comparators
	// because a hyphen is also a version-component separator, and a hyphen
	// with spaces around it is the only form this reads as a range.
	if i := strings.Index(s, " - "); i > 0 {
		lo, hi := strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+3:])
		a, errA := ParseVersion(lo)
		b, errB := ParseVersion(hi)
		if errA != nil || errB != nil {
			out.why = fmt.Sprintf("an interval this cannot read: %q", raw)
			return out
		}
		out.lower, out.upper = &bound{v: a, inclusive: true}, &bound{v: b, inclusive: true}
		out.ok = true
		return out
	}
	// One or two comparisons, in either order, separated by "and", a comma or
	// nothing at all.
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' })
	var parts []string
	for _, f := range fields {
		for _, p := range strings.Split(f, " and ") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
	}
	if len(parts) == 0 || len(parts) > 2 {
		out.why = fmt.Sprintf("a range this cannot read: %q", raw)
		return out
	}
	for _, p := range parts {
		for _, one := range splitComparisons(p) {
			op, val := splitOp(one)
			v, err := ParseVersion(val)
			if err != nil {
				out.why = fmt.Sprintf("a version this cannot compare: %q", val)
				return out
			}
			if !out.constrain(op, v) {
				out.why = fmt.Sprintf("more bounds than this pairs: %q", raw)
				return out
			}
		}
	}
	if out.lower == nil && out.upper == nil && len(out.equals) == 0 {
		out.why = fmt.Sprintf("a range this cannot read: %q", raw)
		return out
	}
	out.ok = true
	return out
}

// splitComparisons splits ">=v2.0 <v2.9.2" into its two comparisons, which is
// how the advisories write a two-sided bound with no conjunction.
func splitComparisons(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '<' && s[i] != '>' {
			continue
		}
		if i > start {
			if part := strings.TrimSpace(s[start:i]); part != "" {
				out = append(out, part)
			}
		}
		start = i
	}
	if part := strings.TrimSpace(s[start:]); part != "" {
		out = append(out, part)
	}
	return out
}

// Contains says whether a version is in the range.
//
// An unreadable range, or a version the range's own bounds cannot be compared
// against, is an error rather than a false: the caller reports the device as
// not assessed and names the text, which is the only honest answer.
func (r Range) Contains(v Version) (bool, error) {
	if !r.ok {
		return false, fmt.Errorf("%w: %s", ErrUnreadable, r.why)
	}
	if v.Empty() {
		return false, fmt.Errorf("%w: no version to compare", ErrUnreadable)
	}
	for _, n := range r.nots {
		c, err := Compare(v, n)
		if err != nil {
			return false, err
		}
		if c == 0 {
			return false, nil
		}
	}
	for _, e := range r.equals {
		c, err := Compare(v, e)
		if err != nil {
			return false, err
		}
		if c == 0 {
			return true, nil
		}
	}
	if r.all {
		return true, nil
	}
	if r.lower == nil && r.upper == nil {
		// Only exact versions, and none of them matched.
		return false, nil
	}
	if r.lower != nil {
		c, err := Compare(v, r.lower.v)
		if err != nil {
			return false, err
		}
		if c < 0 || (c == 0 && !r.lower.inclusive) {
			return false, nil
		}
	}
	if r.upper != nil {
		c, err := Compare(v, r.upper.v)
		if err != nil {
			return false, err
		}
		if c > 0 || (c == 0 && !r.upper.inclusive) {
			return false, nil
		}
	}
	return true, nil
}
