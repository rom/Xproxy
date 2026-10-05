package simulate

import (
	"fmt"
	"sort"
	"strings"
)

// The differential half: two sets of outcomes for the same inputs, and the
// short list of inputs whose decision moved.
//
// The short list is the product. An operator introducing a WAF rule does not
// want to read a thousand identical decisions; they want the eleven requests
// that would start being refused, and the two that would stop. Everything else
// here exists to make that list trustworthy: an input the simulation could not
// ask about is reported as an error rather than folded into either column,
// because a question nobody answered is not an agreement.

// How a decision moved.
const (
	// NewlyRefused was allowed before and is refused now. This is the column
	// that breaks a plant.
	NewlyRefused = "newly refused"
	// NewlyAllowed was refused before and is allowed now. This is the column
	// that opens a hole, and it is the one people forget to look at.
	NewlyAllowed = "newly allowed"
	// ReasonChanged was refused both times, for different reasons. Usually
	// harmless and occasionally the whole story: a request that used to be
	// refused by a virtual patch and is now refused by the WAF means the patch
	// can go.
	ReasonChanged = "reason changed"
	// StatusChanged was allowed both times with a different answer.
	StatusChanged = "status changed"
	// Unanswerable is one side failing to produce a decision at all.
	Unanswerable = "no decision"
)

// A Change is one input whose decision differs.
type Change struct {
	Input    string `json:"input"`
	Listener string `json:"listener,omitempty"`
	Kind     string `json:"kind,omitempty"`
	// How is one of the constants above.
	How string `json:"how"`
	// Before and After are the two decisions, as "refused (waf:942100)".
	Before string `json:"before"`
	After  string `json:"after"`
}

// A Diff is the whole comparison.
type Diff struct {
	// Items is how many inputs were asked about, Same how many decided
	// identically.
	Items int `json:"items"`
	Same  int `json:"same"`
	// Changes are the ones that moved, worst first: newly allowed before newly
	// refused, because a hole is worse than an outage and this is a security
	// proxy.
	Changes []Change `json:"changes,omitempty"`
	// Counts is how many of each kind of change.
	Counts map[string]int `json:"counts,omitempty"`
}

// Differs reports whether anything moved, which is what an exit status is for.
func (d Diff) Differs() bool { return len(d.Changes) > 0 }

// Compare lines two sets of outcomes up by input name and reports what moved.
//
// An input present on one side only is a Change of its own rather than being
// dropped: two runs over the same corpus should produce the same inputs, and if
// they did not, that is the first thing to say.
func Compare(before, after []Outcome) Diff {
	d := Diff{Counts: map[string]int{}}
	byName := make(map[string]Outcome, len(after))
	for _, o := range after {
		byName[o.Input] = o
	}
	seen := make(map[string]bool, len(before))
	for _, b := range before {
		seen[b.Input] = true
		a, ok := byName[b.Input]
		if !ok {
			d.Items++
			d.add(Change{Input: b.Input, Listener: b.Listener, Kind: b.Kind, How: Unanswerable,
				Before: describe(b), After: "not asked"})
			continue
		}
		d.Items++
		if how := moved(b, a); how != "" {
			d.add(Change{Input: b.Input, Listener: b.Listener, Kind: b.Kind, How: how,
				Before: describe(b), After: describe(a)})
			continue
		}
		d.Same++
	}
	for _, a := range after {
		if !seen[a.Input] {
			d.Items++
			d.add(Change{Input: a.Input, Listener: a.Listener, Kind: a.Kind, How: Unanswerable,
				Before: "not asked", After: describe(a)})
		}
	}
	sort.SliceStable(d.Changes, func(i, j int) bool {
		return rank(d.Changes[i].How) < rank(d.Changes[j].How)
	})
	return d
}

func (d *Diff) add(c Change) {
	d.Changes = append(d.Changes, c)
	d.Counts[c.How]++
}

// moved says how a decision differs, or "" when it does not.
func moved(before, after Outcome) string {
	switch {
	case before.Decision == Errored || after.Decision == Errored:
		if before.Decision == after.Decision && before.Err == after.Err {
			return ""
		}
		return Unanswerable
	case before.Decision == Allowed && after.Decision == Refused:
		return NewlyRefused
	case before.Decision == Refused && after.Decision == Allowed:
		return NewlyAllowed
	case before.Decision == Refused && before.Reason != after.Reason:
		return ReasonChanged
	case before.Decision == Allowed && before.Status != after.Status:
		return StatusChanged
	}
	return ""
}

// rank orders the change classes: a hole first, then an outage, then the rest.
func rank(how string) int {
	switch how {
	case NewlyAllowed:
		return 0
	case NewlyRefused:
		return 1
	case Unanswerable:
		return 2
	case ReasonChanged:
		return 3
	case StatusChanged:
		return 4
	}
	return 5
}

// describe is one decision in one readable phrase.
func describe(o Outcome) string {
	var b strings.Builder
	b.WriteString(o.Decision)
	switch {
	case o.Reason != "":
		fmt.Fprintf(&b, " (%s)", o.Reason)
	case o.Err != "":
		fmt.Fprintf(&b, " (%s)", o.Err)
	}
	if o.Status != 0 {
		fmt.Fprintf(&b, " %d", o.Status)
	}
	return b.String()
}

// Summary is the line an operator reads first.
func (d Diff) Summary() string {
	if !d.Differs() {
		return fmt.Sprintf("%d inputs, every decision the same", d.Items)
	}
	parts := make([]string, 0, len(d.Counts))
	for _, how := range []string{NewlyAllowed, NewlyRefused, Unanswerable, ReasonChanged, StatusChanged} {
		if n := d.Counts[how]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, how))
		}
	}
	return fmt.Sprintf("%d inputs, %d the same, %d changed: %s",
		d.Items, d.Same, len(d.Changes), strings.Join(parts, ", "))
}
