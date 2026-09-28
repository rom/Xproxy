package tftp

import (
	"strings"
	"testing"
)

// The bounded sets a learning run remembers, and what a bound does to the
// pattern it proposes.
//
// A firmware directory holds one image per switch model, and a report listing
// four hundred of them is a report nobody reads. What matters is that the bound
// says so, and that it does not silently turn into a pattern derived from a
// sample.

func TestABoundedSetStopsAtItsBound(t *testing.T) {
	m := map[string]bool{}
	full := false
	for i := 0; i < maxLearnedNames*3; i++ {
		addBounded(m, string(rune('a'+i%26))+itoa(i), maxLearnedNames, &full)
	}
	if len(m) != maxLearnedNames {
		t.Errorf("the set holds %d names, want the bound of %d", len(m), maxLearnedNames)
	}
	if !full {
		t.Error("the set filled up and did not say so")
	}
}

// A name already in the set is not a new one, so a device fetching the same
// file every reboot never fills the bound.
func TestARepeatedNameDoesNotFillTheBound(t *testing.T) {
	m := map[string]bool{}
	full := false
	// Exactly the bound's worth of distinct names, which fits.
	for i := 0; i < maxLearnedNames; i++ {
		addBounded(m, "switch"+itoa(i)+".bin", maxLearnedNames, &full)
	}
	if len(m) != maxLearnedNames || full {
		t.Fatalf("the bound's worth of names did not fit: %d names, full=%v", len(m), full)
	}
	// And then one of them again, many times. A device fetching the same file
	// every reboot must not be reported as a directory nobody can summarise.
	for i := 0; i < maxLearnedNames*3; i++ {
		addBounded(m, "switch0.bin", maxLearnedNames, &full)
	}
	if len(m) != maxLearnedNames {
		t.Errorf("a repeated name changed the set to %d names", len(m))
	}
	if full {
		t.Error("a name already in the set was reported as filling the bound")
	}
}

// Many names sharing one extension still generalise: every name's extension is
// recorded whether or not the name itself was, so a pattern from the extensions
// covers the names that were dropped too.
func TestManyNamesOneExtensionStillGeneralise(t *testing.T) {
	var b strings.Builder
	writePatterns(&b, map[string]bool{"firmware": true}, map[string]bool{".bin": true}, false, false)
	if got := b.String(); !strings.Contains(got, `filenames: ["firmware/*.bin"]`) {
		t.Errorf("no pattern was proposed for one extension:\n%s", got)
	}
}

// Extensions outrunning their bound is the case that does not generalise: what
// was recorded is a sample, and a pattern from a sample permits what the sample
// did not contain.
func TestExtensionsPastTheBoundGeneraliseToNothing(t *testing.T) {
	var b strings.Builder
	writePatterns(&b, map[string]bool{"firmware": true}, map[string]bool{".bin": true}, false, true)
	got := b.String()
	if strings.Contains(got, "filenames:") {
		t.Errorf("a pattern was proposed from a sample:\n%s", got)
	}
	if !strings.Contains(got, "No `filenames` pattern is proposed") {
		t.Errorf("the proposal does not say why there is no pattern:\n%s", got)
	}
}

// An observation is copied before it is rendered, because the report is written
// outside the table's lock. A copy that shared the sets would let a request
// arriving mid-report change the report, and race on a map the renderer is
// walking.
func TestATFTPObservationIsCopiedDeeply(t *testing.T) {
	o := learnObs{
		names: map[string]bool{"a.bin": true},
		exts:  map[string]bool{".bin": true},
		modes: map[string]bool{"octet": true},
	}
	c := cloneTFTPObs(o)
	o.names["b.bin"] = true
	o.exts[".cfg"] = true
	o.modes["netascii"] = true

	if c.names["b.bin"] {
		t.Error("the copied name set follows the original")
	}
	if c.exts[".cfg"] {
		t.Error("the copied extension set follows the original")
	}
	if c.modes["netascii"] {
		t.Error("the copied mode set follows the original")
	}
}
