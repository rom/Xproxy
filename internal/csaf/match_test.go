package csaf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The whole thing, end to end: a directory of advisories, and devices the
// inventory has seen.
//
// Every case here is one of the six answers, and the ones that are not
// "affected" are the point. A tool that only got the first case right would be
// the tool this package is written not to be.
func TestTheSixAnswers(t *testing.T) {
	set := loadTestdata(t)

	for _, c := range []struct {
		what     string
		sub      Subject
		state    string
		cve      string
		severity string
		reason   bool
	}{
		{
			// The case the whole thing is for: a controller on a firmware
			// below the advisory's bound, matched through a product name that
			// is not spelled the way the device spells it.
			what: "a controller below the bound",
			sub: Subject{ID: "plc-1", Vendor: "Siemens", Firmware: "V4.2.1",
				Model: "SIMATIC S7-1200 CPU 1212C DC/DC/DC"},
			state: StateAffected, cve: "CVE-2023-99991", severity: "high",
		},
		{
			// The same device, updated. The fixed version is not affected, and
			// saying so is allowed *because the comparison succeeded*.
			what: "the same controller after the update",
			sub: Subject{ID: "plc-2", Vendor: "Siemens", Firmware: "V4.5",
				Model: "SIMATIC S7-1200 CPU 1212C DC/DC/DC"},
			state: StateFixed,
		},
		{
			// A version past the fix, which no record in the document is
			// about. It is not affected by this advisory and this says so
			// without claiming anything about advisories nobody loaded.
			what: "a controller past the fixed version",
			sub: Subject{ID: "plc-3", Vendor: "Siemens", Firmware: "V4.6",
				Model: "SIMATIC S7-1200 CPU 1212C"},
			state: StateNotAffected, reason: true,
		},
		{
			// The refusal that matters: a switch whose firmware string is not
			// a version anything can compare. Not assessed, with the string
			// in the reason, so the device appears on the list of things
			// somebody has to check by hand.
			what: "a device whose firmware string cannot be read",
			sub: Subject{ID: "plc-4", Vendor: "Siemens", Firmware: "Rel. 04.03",
				Model: "SIMATIC S7-1500 CPU 1511-1 PN"},
			state: StateNotAssessed, reason: true,
		},
		{
			// And the other refusal: the advisory's own range carries a
			// condition -- which card is fitted -- that this package will not
			// evaluate. The device is not assessed even though its version
			// parses perfectly.
			what: "an advisory whose range is conditional",
			sub: Subject{ID: "plc-5", Vendor: "Siemens", Firmware: "V2.1",
				Model: "SIMATIC S7-400 CPU 414-3 PN/DP"},
			state: StateNotAssessed, reason: true,
		},
		{
			what: "a device the advisories say nothing about",
			sub: Subject{ID: "hmi-1", Vendor: "Advantech", Firmware: "V1.2",
				Model: "WebAccess HMI Panel"},
			state: StateUnknownProduct,
		},
		{
			// A device with no firmware at all still gets an answer from an
			// advisory that names no version -- and this one does not, so the
			// honest answer is that nobody has assessed it.
			what:  "a controller that reports no firmware version",
			sub:   Subject{ID: "plc-6", Vendor: "Siemens", Model: "SIMATIC S7-1200 CPU 1214C"},
			state: StateNotAssessed, reason: true,
		},
		{
			// The relationship case: the device reports the controller's name
			// and the version is on the firmware inside the advisory.
			what: "a Modicon matched through a relationship",
			sub: Subject{ID: "plc-7", Vendor: "Schneider Electric", Firmware: "V3.10",
				Model: "Modicon M340 BMXP342020"},
			state: StateAffected, cve: "CVE-2024-99992", severity: "critical",
		},
	} {
		got := set.Assess(c.sub)
		if got.State != c.state {
			t.Errorf("%s: state %s (%s), want %s", c.what, got.State, got.Reason, c.state)
			continue
		}
		if c.reason && got.Reason == "" {
			t.Errorf("%s: %s with no reason, so a finding cannot say what to do next", c.what, got.State)
		}
		if c.cve != "" {
			var found bool
			for _, h := range got.Hits {
				if h.CVE == c.cve {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: %s is not among the advisories reported: %+v", c.what, c.cve, got.Hits)
			}
		}
		if c.severity != "" && got.Worst != c.severity {
			t.Errorf("%s: worst severity %q, want %q", c.what, got.Worst, c.severity)
		}
	}
}

// An advisory for one product line does not name another. This is the whole
// risk of matching on names, so it is checked in the direction that would hurt:
// the S7-1500 advisory in the same document must not reach an S7-1200.
func TestOneProductLineIsNotAnother(t *testing.T) {
	set := loadTestdata(t)
	got := set.Assess(Subject{ID: "plc-1200", Vendor: "Siemens", Firmware: "V4.2.1",
		Model: "SIMATIC S7-1200 CPU 1212C"})
	for _, h := range got.Hits {
		if h.Product == "SIMATIC S7-1500 CPU family" {
			t.Errorf("an S7-1500 advisory was reported against an S7-1200: %+v", h)
		}
	}
	// And a one-token product name does not match a device that merely shares
	// the word: "SIMATIC" alone is a catalogue, not a product.
	one := &Set{postings: map[string][]ref{}, now: set.now}
	adv := &Advisory{ID: "SSA-BROAD", Records: []Record{{
		CVE: "CVE-2024-0", Status: StatusAffected, Vendor: "Siemens",
		Product: "SIMATIC", Versions: AllVersions(),
	}}}
	one.advisories = []*Advisory{adv}
	one.postings = index(one.advisories)
	if got := one.Assess(Subject{ID: "x", Model: "SIMATIC S7-1200 CPU 1212C"}); got.State == StateAffected {
		t.Errorf("a one-word product name matched a whole catalogue: %+v", got)
	}
	// The same device against the same one-word name spelled exactly: that is
	// a match, because it is the device's whole name.
	if got := one.Assess(Subject{ID: "x", Model: "SIMATIC"}); got.State != StateAffected {
		t.Errorf("an exact one-word name did not match: %+v", got)
	}
}

// An advisory with no fix yet names a product and no version. Every device of
// that product is affected, whatever its firmware says -- including the device
// whose firmware string nobody can read, which is the case a version-comparing
// matcher would drop.
func TestAnAdvisoryWithNoVersionBoundReachesADeviceWithNoVersion(t *testing.T) {
	set := &Set{now: time.Now}
	set.advisories = []*Advisory{{
		ID: "SSA-NOFIX", Publisher: "Siemens ProductCERT", Severity: "critical",
		Records: []Record{{
			CVE: "CVE-2024-1", Status: StatusAffected, Vendor: "Siemens",
			Product: "SCALANCE X-200 switch family", Versions: AllVersions(),
			Severity: "critical", Score: 9.1,
		}},
	}}
	set.postings = index(set.advisories)
	for _, fw := range []string{"", "Rel. 04.03", "V5.2.5"} {
		got := set.Assess(Subject{ID: "sw-1", Model: "SCALANCE X-200 switch", Firmware: fw})
		if got.State != StateAffected {
			t.Errorf("firmware %q gave %s (%s), want affected: an advisory with no version bound is about every version",
				fw, got.State, got.Reason)
		}
		if got.Worst != "critical" {
			t.Errorf("firmware %q gave worst severity %q", fw, got.Worst)
		}
	}
}

// The severity floor a configuration uses to decide which findings become
// events. A record nobody scored is included rather than hidden behind the
// threshold.
func TestTheSeverityFloor(t *testing.T) {
	for _, c := range []struct {
		sev, floor string
		want       bool
	}{
		{"critical", "high", true},
		{"high", "high", true},
		{"medium", "high", false},
		{"low", "critical", false},
		{"", "critical", true},
		{"medium", "", true},
		{"anything else", "high", true},
	} {
		if got := SeverityAtLeast(c.sev, c.floor); got != c.want {
			t.Errorf("severity %q against floor %q gave %v", c.sev, c.floor, got)
		}
	}
}

func loadTestdata(t *testing.T) *Set {
	t.Helper()
	set, err := Load([]Source{{Name: "testdata", Directory: "testdata"}}, Options{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return set
}

// A directory with no advisories in it is a load error, not an empty set. A
// proxy that came up reporting no advisories because a path was misspelled
// would be claiming an estate has nothing against it.
func TestADirectoryWithNoAdvisoriesIsALoadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"index":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load([]Source{{Name: "empty", Directory: dir}}, Options{}); err == nil {
		t.Error("a directory with no advisories loaded as an empty set")
	}
	if _, err := Load([]Source{{Name: "missing", Directory: filepath.Join(dir, "nope")}}, Options{}); err == nil {
		t.Error("a directory that does not exist loaded")
	}
	if _, err := Load(nil, Options{}); err == nil {
		t.Error("a set with no sources loaded")
	}
}

// A document that is CSAF and will not parse is a failure rather than something
// to skip: an assessment that silently omitted an advisory would be the wrong
// answer with no sign of it.
func TestABrokenAdvisoryIsAFailure(t *testing.T) {
	dir := t.TempDir()
	good, err := os.ReadFile(filepath.Join("testdata", "ssa-482757.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.json"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	broken := `{"document":{"csaf_version":"2.0","category":"csaf_security_advisory","tracking":{}}}`
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load([]Source{{Name: "mixed", Directory: dir}}, Options{}); err == nil {
		t.Fatal("a directory with an unreadable advisory loaded without complaint")
	}
	// On a refresh the rule is the opposite: what that source last gave is
	// kept, and the failure is counted and returned. A directory being
	// rewritten, or a mount that went away for a minute, must not empty the
	// assessment.
	set := loadTestdata(t)
	before := set.Documents()
	if err := set.Refresh([]Source{{Name: "testdata", Directory: dir}}); err == nil {
		t.Error("a refresh onto a broken directory reported nothing")
	}
	if got := set.Documents(); got != before {
		t.Errorf("a failed refresh changed the set from %d documents to %d", before, got)
	}
	// And the same holds per source: one of two sources failing keeps what
	// that source last gave, rather than dropping its advisories from the
	// assessment while the other source's are still there.
	two := []Source{{Name: "good", Directory: "testdata"}, {Name: "other", Directory: dir}}
	fresh, err := Load([]Source{two[0]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Refresh(two); err == nil {
		t.Error("a refresh onto a directory with an unreadable advisory reported nothing")
	}
	if got := fresh.Documents(); got != before {
		t.Errorf("%d documents after a partial failure, want the %d the good source gave", got, before)
	}
	var failures int
	for _, src := range fresh.Counts().Sources {
		failures += src.Failures
		if src.Name == "good" && src.Documents != before {
			t.Errorf("the source that read fine lost documents: %+v", src)
		}
	}
	if failures == 0 {
		t.Error("the failure was not counted against its source")
	}
}

// What the status view is made of.
func TestTheCountsSayWhereEachAdvisoryCameFrom(t *testing.T) {
	set := loadTestdata(t)
	c := set.Counts()
	if c.Documents != 3 {
		t.Errorf("%d documents, want the three advisories in testdata", c.Documents)
	}
	if c.Records == 0 {
		t.Error("no records")
	}
	if len(c.Sources) != 1 || c.Sources[0].Name != "testdata" {
		t.Fatalf("sources %+v", c.Sources)
	}
	if c.Sources[0].Ignored == 0 {
		t.Error("the file that is not an advisory was not counted as ignored")
	}
	if c.Loaded.IsZero() {
		t.Error("the set does not say when it was read")
	}
	// The assessments are counted, which is how a status view says the
	// matching is running at all.
	set.Assess(Subject{ID: "plc-1", Model: "SIMATIC S7-1200 CPU 1212C", Firmware: "V4.2.1"})
	if got := set.Counts(); got.Assessments == 0 || got.Affected == 0 {
		t.Errorf("assessments %d, affected %d", got.Assessments, got.Affected)
	}
	if len(set.Advisories()) != 3 {
		t.Errorf("%d advisories listed", len(set.Advisories()))
	}
}
