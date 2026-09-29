package csaf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Comparing a device's firmware version against the versions an advisory
// names, and refusing to guess.
//
// This is the part of the whole exercise where being clever is a security bug.
// An advisory says "all versions < V4.2.3"; the inventory says the device
// reports "V4.2.1". Deciding that is a comparison. But the inventory's string
// is whatever a device chose to say about itself -- "2.9.2 Upd4", "1.20.4
// build 7", "Rel. 04.03", "AB-1756-L71/B" -- and the advisory's is whatever a
// vendor's advisory tooling emitted, and the space between them is where a
// matcher either refuses or invents.
//
// So there are exactly two answers here, and "probably not affected" is not
// one of them:
//
//   - a comparison this can make, which is one this package can defend line by
//     line: an optional V, dot-separated numbers, and one recognised update or
//     service-pack ordinal after them; or
//   - an error, which the caller turns into **not assessed** -- a device whose
//     exposure nobody has established -- and never into "not affected".
//
// That asymmetry is the whole design. A wrong "not affected" is a device
// somebody stops looking at, and the estate that most needs this is the one
// whose devices report the least parseable version strings. Refusing is a
// finding: "these eleven devices are the ones you have to check by hand" is a
// useful sentence. "These eleven devices are fine" would be a lie with a
// number in it.

// ErrUnreadable is returned by every parse here that will not guess. It is
// wrapped with what could not be read, because the text is the finding: an
// operator reading "not assessed: firmware \"Rel. 04.03\"" knows both what to
// do and what to tell the vendor.
var ErrUnreadable = errors.New("not a version this can compare")

// MaxVersionLength bounds a version string. A version longer than this is a
// description, and comparing descriptions is what this package will not do.
const MaxVersionLength = 64

// maxComponents bounds the dot-separated numbers in one version. Four is
// major.minor.patch.build, which is as deep as the vendors here go; a string
// with more is not a version this recognises.
const maxComponents = 6

// Version is a version this package is prepared to compare.
type Version struct {
	// nums are the dot-separated components, most significant first. A
	// missing component compares as zero, so V4.2 and V4.2.0 are the same
	// version -- which is what a range of "< V4.2" means and what every
	// vendor here intends by it.
	nums []uint64
	// kind and ord are a recognised ordinal *after* the numbers: an update,
	// a service pack, a hotfix or a Siemens patch level. They sort after the
	// bare version, so V2.9.2 Upd4 is later than V2.9.2 -- and two different
	// kinds of ordinal on the same numbers are not comparable at all, since
	// nothing says whether a service pack precedes a hotfix.
	kind string
	ord  uint64
	// raw is the string as it was given, for the finding.
	raw string
}

// The ordinal kinds a version may carry after its numbers.
const (
	ordNone   = ""
	ordUpdate = "update"
	ordSP     = "sp"
	ordHotfix = "hf"
	ordPatch  = "p"
)

// String is the version as it was written, not as this package holds it. An
// operator comparing a finding against a device's own display has to see the
// device's own string.
func (v Version) String() string { return v.raw }

// Empty says whether this is the zero Version, which no comparison accepts.
func (v Version) Empty() bool { return len(v.nums) == 0 }

// ParseVersion reads a version string, or refuses it.
//
// What it accepts, and nothing else:
//
//	4.2, V4.2, v4.2.1, Version 4.2.1   an optional V or the word version
//	4.2.1-3, 4.2.1_3                   a hyphen or underscore as a separator
//	V2.9.2 Update 4, V2.9.2 Upd4       an update ordinal
//	V1.2 SP3, V1.2 HF1, V4.2 P01       a service pack, hotfix or patch level
//
// Everything else -- a build identifier, a date, a revision letter, a model
// number carried in the version field, anything with a word in it this does
// not know -- is ErrUnreadable, and an unreadable version is the honest
// outcome rather than an approximate one.
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Version{}, fmt.Errorf("%w: empty", ErrUnreadable)
	}
	if len(raw) > MaxVersionLength {
		return Version{}, fmt.Errorf("%w: %d characters", ErrUnreadable, len(raw))
	}
	work := strings.ToLower(raw)
	// The one prefix form. "V" is Siemens and Schneider; the spelt-out word
	// is what a few advisories write.
	work = strings.TrimPrefix(work, "version")
	work = strings.TrimSpace(work)
	if len(work) > 1 && work[0] == 'v' {
		work = work[1:]
	}
	work = strings.TrimSpace(work)
	if work == "" {
		return Version{}, fmt.Errorf("%w: %q", ErrUnreadable, raw)
	}
	// An ordinal suffix, taken off before the numbers are read: the numbers
	// must be numbers, so anything after them has to be recognised here or
	// refused below.
	body, kind, ord, err := splitOrdinal(work)
	if err != nil {
		return Version{}, fmt.Errorf("%w: %q", err, raw)
	}
	// A hyphen or an underscore between components is a separator like a dot.
	// It is not a range and not a pre-release: both of those are refused
	// below, because the component after it has to parse as a number.
	body = strings.NewReplacer("-", ".", "_", ".").Replace(body)
	parts := strings.Split(body, ".")
	if len(parts) > maxComponents {
		return Version{}, fmt.Errorf("%w: %q has %d components", ErrUnreadable, raw, len(parts))
	}
	v := Version{kind: kind, ord: ord, raw: raw}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return Version{}, fmt.Errorf("%w: %q", ErrUnreadable, raw)
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			// The refusal that matters most: a component with a letter in it
			// is a build tag, a revision or a pre-release, and there is no
			// ordering over those that this package can justify.
			return Version{}, fmt.Errorf("%w: %q", ErrUnreadable, raw)
		}
		v.nums = append(v.nums, n)
	}
	return v, nil
}

// splitOrdinal takes a recognised update or service-pack ordinal off the end.
//
// The separator may be a space, a hyphen, an underscore or nothing at all,
// because every vendor writes it differently and none of them writes it in a
// way that changes the meaning.
func splitOrdinal(s string) (body, kind string, ord uint64, err error) {
	for _, form := range []struct {
		words []string
		kind  string
	}{
		{[]string{"update", "upd", "up"}, ordUpdate},
		{[]string{"servicepack", "service pack", "sp"}, ordSP},
		{[]string{"hotfix", "hf"}, ordHotfix},
		// A bare "p" is Siemens' patch level (V4.2 P01). It is last because
		// it is one letter and would otherwise catch a word above.
		{[]string{"patch", "p"}, ordPatch},
	} {
		for _, w := range form.words {
			i := strings.LastIndex(s, w)
			if i <= 0 {
				// Not present, or the whole string: a version that is only an
				// ordinal is not a version.
				continue
			}
			head, tail := s[:i], s[i+len(w):]
			head = strings.TrimRight(head, " -_.")
			tail = strings.TrimLeft(tail, " -_.")
			if head == "" || tail == "" {
				continue
			}
			n, convErr := strconv.ParseUint(tail, 10, 32)
			if convErr != nil {
				// "V1.2 patchlevel" and "V1.2 SP" name no ordinal. Refusing
				// here rather than ignoring the suffix is the point: a
				// version whose tail this cannot read is one whose ordering
				// against a plain V1.2 nobody can state.
				return "", "", 0, ErrUnreadable
			}
			return head, form.kind, n, nil
		}
	}
	return s, ordNone, 0, nil
}

// Compare orders two versions: -1, 0 or 1, or an error when the two are not
// comparable at all.
//
// Two pairs are incomparable, and both refusals are load-bearing.
//
// Two different ordinal kinds on the same numbers -- V1.2 SP3 against V1.2 HF1
// -- because nothing in any vendor's documentation says which of those is
// later.
//
// And a version of one component against a version of several: "20240115"
// against "V4.2". A single number is as often a date or a build identifier as
// it is a major version, and the arithmetic would say 20240115 is later than
// 4.2 and therefore outside an "all versions below V4.2" range -- a device
// cleared by a comparison between two different numbering schemes. Two single
// numbers *are* compared, because firmware really is dated that way and
// 20240115 against 20240201 is the same scheme twice.
func Compare(a, b Version) (int, error) {
	if a.Empty() || b.Empty() {
		return 0, fmt.Errorf("%w: an empty version", ErrUnreadable)
	}
	if (len(a.nums) == 1) != (len(b.nums) == 1) {
		return 0, fmt.Errorf("%w: %q and %q are not the same numbering scheme", ErrUnreadable, a.raw, b.raw)
	}
	n := len(a.nums)
	if len(b.nums) > n {
		n = len(b.nums)
	}
	for i := 0; i < n; i++ {
		x, y := at(a.nums, i), at(b.nums, i)
		switch {
		case x < y:
			return -1, nil
		case x > y:
			return 1, nil
		}
	}
	switch {
	case a.kind == b.kind:
		switch {
		case a.ord < b.ord:
			return -1, nil
		case a.ord > b.ord:
			return 1, nil
		}
		return 0, nil
	case a.kind == ordNone:
		// A bare version precedes any ordinal on the same numbers: an update
		// is something applied to it.
		return -1, nil
	case b.kind == ordNone:
		return 1, nil
	}
	return 0, fmt.Errorf("%w: %q against %q", ErrUnreadable, a.raw, b.raw)
}

func at(nums []uint64, i int) uint64 {
	if i < len(nums) {
		return nums[i]
	}
	return 0
}
