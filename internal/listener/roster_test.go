package listener

import (
	"sort"
	"testing"
)

// notYetAuthorising is every kind that does not consult the estate's
// authorisation policy.
//
// It is empty, and that is the point it was built to reach. It existed so that
// adding a kind to the roster and forgetting the policy was a failing test rather
// than a hole: a kind in neither this list nor authorises fails below, which forced
// somebody to decide. Every kind has now been decided, and the way to use this list
// again is to put a new kind in it with a comment saying why -- not to leave the
// kind in neither, which is the case this test exists to catch.
var notYetAuthorising = map[string]bool{}

// Every kind is on exactly one side of the authorisation line, and nothing
// claims to consult a policy that is not a kind at all.
func TestEveryKindSaysWhetherItAuthorises(t *testing.T) {
	for _, kind := range Kinds() {
		yes, no := Authorises(kind), notYetAuthorising[kind]
		switch {
		case yes && no:
			t.Errorf("kind %q is in both authorises and notYetAuthorising", kind)
		case !yes && !no:
			t.Errorf("kind %q is in neither list: either wire it to internal/authorization "+
				"and add it to authorises, or record here that it does not consult "+
				"the policy -- a kind in neither is a hole in a policy an operator "+
				"believes covers everything", kind)
		}
	}
	for kind := range authorises {
		if _, ok := RoleOf(kind); !ok {
			t.Errorf("authorises names %q, which is not a listener kind", kind)
		}
	}
	for kind := range notYetAuthorising {
		if _, ok := RoleOf(kind); !ok {
			t.Errorf("notYetAuthorising names %q, which is not a listener kind", kind)
		}
	}
}

// The message that tells an operator which kinds do consult the policy has to
// be the list itself, sorted, or the refusal sends them looking in the wrong
// place.
func TestAuthorisingKindsIsTheSortedList(t *testing.T) {
	got := AuthorisingKinds()
	if len(got) != len(authorises) {
		t.Fatalf("AuthorisingKinds() = %v, want %d kinds", got, len(authorises))
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("AuthorisingKinds() = %v, want it sorted", got)
	}
	for _, k := range got {
		if !authorises[k] {
			t.Errorf("AuthorisingKinds() returned %q, which does not authorise", k)
		}
	}
	// And the gate kind wired first is in it, so a change that quietly empties
	// the map fails here rather than at a listener that stops being covered.
	if !Authorises("ssh") {
		t.Error("ssh does not consult the authorisation policy")
	}
	// Every kind is in it now, which is the state the fail-closed load check was
	// built to make reachable: a configuration carrying an authorization section
	// is no longer refused for naming a kind the section does not cover, because
	// there is no such kind.
	if len(got) != len(Kinds()) {
		t.Errorf("AuthorisingKinds() has %d of %d kinds; the ones missing are the "+
			"hole in a policy an operator believes covers everything", len(got), len(Kinds()))
	}
}
