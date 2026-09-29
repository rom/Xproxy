package csaf

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Matching a device against the advisories, and the six answers.
//
// The states are not two, and that is the design rather than a hedge. A tool
// that answered "affected" or "not affected" would be right about the devices
// whose version strings happen to parse and quietly wrong about the rest, and
// the rest is most of an industrial estate. So every device lands in one of
// these, and five of them are not "affected":
//
//	affected            an advisory names this product and this version
//	under_investigation the vendor has not decided yet
//	not_assessed        the version or the range could not be compared
//	fixed               the version this device runs carries the fix
//	not_affected        the vendor says this version is not affected
//	unknown_product     no loaded advisory names a product this could tie to
//
// The two to read carefully are the last two. **not_assessed is work**: it is
// the list of devices somebody has to check by hand, and a run that produces a
// lot of it is telling the truth about how little of the estate reports a
// comparable version. **unknown_product is not clean**: it says the loaded
// documents do not name this device's product, which depends entirely on which
// documents were loaded -- so the status view words it that way and never as
// "no advisory affects this device".
const (
	StateAffected       = "affected"
	StateInvestigating  = "under_investigation"
	StateNotAssessed    = "not_assessed"
	StateFixed          = "fixed"
	StateNotAffected    = "not_affected"
	StateUnknownProduct = "unknown_product"
)

// stateRank orders the states for the one a device is reported as. A device
// with an affected record and a fixed one is affected: the advisory that names
// its running version decides, and the fixed record describes a version it is
// not running.
func stateRank(s string) int {
	switch s {
	case StateAffected:
		return 6
	case StateInvestigating:
		return 5
	case StateNotAssessed:
		return 4
	case StateFixed:
		return 3
	case StateNotAffected:
		return 2
	}
	return 1
}

// MinProductTokens is how much of a product name has to match before this
// package will tie an advisory to a device.
//
// One token is not enough. An advisory for "SIMATIC" would otherwise name
// every SIMATIC device on the network, and an estate that got a hundred
// findings from one advisory would stop reading them. Two contiguous tokens --
// "s7 1200", "modicon m340", "logix 5580" -- is the shortest run that
// identifies a product line rather than a vendor's whole catalogue.
const MinProductTokens = 2

// MaxHits bounds the advisories reported for one device. A controller in a
// family with a long history has dozens; the worst of them are what an operator
// acts on, and the count says how many there were.
const MaxHits = 32

// Subject is the device to assess, as the inventory knows it.
type Subject struct {
	// ID is the inventory's own identifier, carried into the finding.
	ID string
	// Vendor is what the device or its hardware prefix said the maker is. It
	// is carried into the finding and is *not* required to agree with the
	// advisory's vendor: an inventory's vendor comes from an IEEE prefix or a
	// protocol field and an advisory's from a legal entity, so "Siemens"
	// against "Siemens AG" and "Siemens Numerical Control Ltd." are both
	// ordinary -- and a matcher that demanded agreement would drop real
	// findings to tidy up its output. The product name is the evidence.
	Vendor string
	// Model is what the device called itself. It is the field the whole match
	// turns on, and a device that reports none can only be matched by an
	// advisory that names no version.
	Model string
	// Firmware is the version the device reported.
	Firmware string
}

// Assessment is what the advisories say about one device.
type Assessment struct {
	Asset    string `json:"asset"`
	Vendor   string `json:"vendor,omitempty"`
	Product  string `json:"product,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	// State is the worst of the states the records produced.
	State string `json:"state"`
	// Reason is why, in one phrase, for the states that need one: which
	// version string could not be read, which range, or that the device
	// reports no version at all.
	Reason string `json:"reason,omitempty"`
	// Worst and Score are the worst severity and highest base score among
	// the affected records.
	Worst string  `json:"worst_severity,omitempty"`
	Score float64 `json:"worst_score,omitempty"`
	// Hits are the advisories that named this device, worst first.
	Hits []Hit `json:"advisories,omitempty"`
	// Total is how many records named it, before MaxHits cut the list.
	Total int `json:"total,omitempty"`
	// Compared is how many records this device was compared against, which is
	// what makes an empty result readable: nought means no advisory named the
	// product, and a hundred means a hundred did and none matched the version.
	Compared int `json:"compared"`
	// At is when the assessment was made.
	At time.Time `json:"at"`
}

// Affected says whether this device needs somebody's attention today. It is
// deliberately narrow: not assessed is work to do, and it is not this.
func (a *Assessment) Affected() bool { return a.State == StateAffected }

// Hit is one advisory record that named a device.
type Hit struct {
	// Advisory is the document's tracking id, which is what an operator looks
	// up, and Publisher who issued it.
	Advisory  string `json:"advisory"`
	Publisher string `json:"publisher,omitempty"`
	CVE       string `json:"cve,omitempty"`
	Title     string `json:"title,omitempty"`
	// State is what this record said, which need not be the device's own
	// state: a fixed record on a device that is affected by another is worth
	// seeing, because it names the version to move to.
	State string `json:"state"`
	// Severity and Score are the record's CVSS figures.
	Severity string  `json:"severity,omitempty"`
	Score    float64 `json:"score,omitempty"`
	// Product is the name in the advisory's own words, which is how an
	// operator checks the match this package made.
	Product string `json:"product,omitempty"`
	// Versions is the range the record was about, as the document wrote it.
	Versions string `json:"versions,omitempty"`
	// Fixed is the version the document says carries the fix, and Fix the
	// remediation's own words.
	Fixed string `json:"fixed_in,omitempty"`
	Fix   string `json:"remediation,omitempty"`
	URL   string `json:"url,omitempty"`
	// Released is the advisory's own date.
	Released time.Time `json:"released,omitempty"`
}

// severityRank orders the severities for "worst".
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium", "moderate":
		return 3
	case "low":
		return 2
	case "none":
		return 1
	}
	return 0
}

// SeverityAtLeast says whether a severity is at or above a floor, which is how
// a configuration says which findings become security events. An unknown
// severity is *included*: a record a vendor scored with nothing is not a record
// to hide behind a threshold.
func SeverityAtLeast(sev, floor string) bool {
	f := severityRank(floor)
	if f == 0 {
		return true
	}
	r := severityRank(sev)
	if r == 0 {
		return true
	}
	return r >= f
}

// Assess matches one device against the set.
func (s *Set) Assess(sub Subject) *Assessment {
	out := &Assessment{Asset: sub.ID, Vendor: sub.Vendor, Product: sub.Model,
		Firmware: sub.Firmware, State: StateUnknownProduct, At: s.now()}
	// The device's own version, parsed once. A version that will not parse is
	// not a failure yet: an advisory that names every version of the product
	// does not need one, and that is the case that finds the unpatched
	// controller nobody has a version string for.
	var have Version
	var versionErr error
	if sub.Firmware == "" {
		versionErr = fmt.Errorf("%w: the inventory has no firmware version for this device", ErrUnreadable)
	} else if have, versionErr = ParseVersion(sub.Firmware); versionErr != nil {
		versionErr = fmt.Errorf("firmware %q is not a version this can compare", clip(sub.Firmware, 64))
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	model := tokensOf(sub.Model)
	if len(model) == 0 {
		// A device that has never said what it is. It is reported rather than
		// left out, because "this many devices on the network have not named
		// themselves" is a fact about the estate an operator should see -- and
		// it is *not* called not_assessed, because nothing was attempted: there
		// is no product here to compare a version against.
		out.Reason = "this device has not said what it is, so no advisory can name it"
		s.Assessments.Add(1)
		return out
	}
	for _, cand := range s.candidates(model) {
		rec, adv := cand.rec, cand.adv
		name, ok := productMatch(model, rec)
		if !ok {
			continue
		}
		out.Compared++
		state, reason, applies := decide(rec, have, versionErr)
		if state == StateNotAssessed && out.State == StateAffected {
			// A record this could not compare, on a device already known to be
			// affected by one it could. The device's own state does not move
			// backwards, and the reason belongs to the worse finding.
			continue
		}
		if stateRank(state) > stateRank(out.State) {
			out.State, out.Reason = state, reason
		}
		if !applies {
			// The record was read and compared, and the version this device
			// runs is outside the range it is about. That is a real answer --
			// it is what moves the device off unknown_product -- but it is not
			// an advisory to list: a finding padded with the records that
			// cleared it is one nobody reads to the end.
			continue
		}
		out.Total++
		if len(out.Hits) < MaxHits {
			out.Hits = append(out.Hits, hitOf(adv, rec, state, name))
		}
		if state == StateAffected {
			if severityRank(rec.Severity) > severityRank(out.Worst) {
				out.Worst = rec.Severity
			}
			if rec.Score > out.Score {
				out.Score = rec.Score
			}
		}
	}
	sort.SliceStable(out.Hits, func(i, j int) bool {
		a, b := out.Hits[i], out.Hits[j]
		if stateRank(a.State) != stateRank(b.State) {
			return stateRank(a.State) > stateRank(b.State)
		}
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		return a.Score > b.Score
	})

	s.Assessments.Add(1)
	if out.Affected() {
		s.Affected.Add(1)
	}
	return out
}

// decide is what one record says about one device's version.
//
// applies says whether the record is about the version this device runs. A
// record that was compared and does not apply still decides something -- the
// device was assessed against it -- so it returns not_affected with applies
// false: the state counts, the advisory is not listed.
func decide(rec Record, have Version, versionErr error) (state, reason string, applies bool) {
	// A range over every version needs no comparison, which is the case that
	// matters most: it is how an advisory with no fix yet names a product, and
	// it catches the device whose version string nobody can read.
	if rec.Versions.Everything() {
		return asState(rec.Status), "", true
	}
	if versionErr != nil {
		return StateNotAssessed, versionErr.Error(), true
	}
	in, err := rec.Versions.Contains(have)
	if err != nil {
		return StateNotAssessed, fmt.Sprintf("%s: %s", rec.CVE, unwrapReason(err)), true
	}
	if !in {
		return StateNotAffected, "the version this device runs is outside the range this advisory is about", false
	}
	return asState(rec.Status), "", true
}

// asState maps a document's product status onto a device's state.
func asState(status string) string {
	switch status {
	case StatusAffected:
		return StateAffected
	case StatusNotAffected:
		return StateNotAffected
	case StatusFixed:
		return StateFixed
	case StatusInvestigating:
		return StateInvestigating
	}
	return StateNotAssessed
}

func unwrapReason(err error) string {
	s := err.Error()
	return strings.TrimPrefix(s, ErrUnreadable.Error()+": ")
}

func hitOf(adv *Advisory, rec Record, state, product string) Hit {
	h := Hit{Advisory: adv.ID, Publisher: adv.Publisher, CVE: rec.CVE,
		Title: rec.Title, State: state, Severity: rec.Severity, Score: rec.Score,
		Product: product, Versions: rec.Versions.String(), Fixed: rec.Fixed,
		Fix: rec.Fix, URL: rec.FixURL, Released: adv.Released}
	if h.Title == "" {
		h.Title = adv.Title
	}
	if h.URL == "" {
		h.URL = adv.URL
	}
	return h
}

// productMatch decides whether a record's product is this device's, and says
// which of the record's names matched.
//
// The rule is containment of a contiguous token run, in either direction, of at
// least MinProductTokens -- or exact equality, which is allowed to be one
// token. That is narrow enough that "SIMATIC S7-1200" does not match an
// S7-1500, and wide enough that an advisory naming "SIMATIC S7-1200 CPU family"
// matches a device calling itself "SIMATIC S7-1200 CPU 1212C DC/DC/DC".
func productMatch(model []string, rec Record) (string, bool) {
	if len(model) == 0 {
		return "", false
	}
	for _, name := range [2]string{rec.Product, rec.Platform} {
		if name == "" {
			continue
		}
		if runMatch(model, tokensOf(name)) {
			return name, true
		}
	}
	return "", false
}

// runMatch is containment of one token list in the other.
func runMatch(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	if equalTokens(a, b) {
		return true
	}
	short, long := a, b
	if len(long) < len(short) {
		short, long = long, short
	}
	if len(short) < MinProductTokens {
		return false
	}
	for i := 0; i+len(short) <= len(long); i++ {
		if equalTokens(long[i:i+len(short)], short) {
			return true
		}
	}
	return false
}

func equalTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// MaxTokens bounds the tokens taken from one name, so that a document's
// hundred-word product name is not a hundred-word comparison against every
// device.
const MaxTokens = 24

// tokensOf normalises a vendor or product name into comparable tokens.
//
// Punctuation becomes a boundary, so "S7-1200", "S7 1200" and "S7/1200" are the
// same three characters and one number. The collective nouns a vendor adds to
// name a whole line -- "family", "series", "devices" -- are dropped, because a
// device never calls itself one and keeping them would stop every family
// advisory from matching anything.
func tokensOf(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		w := strings.ToLower(cur.String())
		cur.Reset()
		if generic[w] || len(out) >= MaxTokens {
			return
		}
		out = append(out, w)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			cur.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return out
}

// generic are the words that say nothing about which product a name is. The
// list is short on purpose: every entry is a word this package will ignore on
// both sides of a comparison, and a wrong one widens every match at once.
var generic = map[string]bool{
	"family": true, "families": true, "series": true, "devices": true,
	"device": true, "products": true, "product": true, "all": true,
	"versions": true, "version": true, "the": true, "and": true,
}

// States are the six answers, worst first. They are exported as a list because
// a caller that filters on one has to be able to say what the choices are: a
// state filter that silently matched nothing would answer a typo with "the
// estate is clean".
func States() []string {
	return []string{StateAffected, StateInvestigating, StateNotAssessed,
		StateFixed, StateNotAffected, StateUnknownProduct}
}

// KnownState says whether a string is one of the six.
func KnownState(s string) bool {
	for _, one := range States() {
		if one == s {
			return true
		}
	}
	return false
}
