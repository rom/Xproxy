package listener

import (
	"sort"
	"testing"
)

// notYetAuthorising is every kind that does not consult the estate's
// authorisation policy yet.
//
// It is here, spelled out, so that adding a kind to the roster and forgetting
// the policy is a failing test rather than a hole. A kind is moved from this
// list to authorises when it asks internal/authorization at its admission point -- and
// a kind in neither list fails below, which is the decision this test exists to
// force somebody to make.
//
// One kind is left, and it is the interesting one rather than the leftover.
var notYetAuthorising = map[string]bool{
	// The HTTP gateway asks the imported lists already. What it does not have is
	// a session-level question, because a gateway's unit of work is a request
	// and a request is decided by its route -- and the per-request answer is
	// already the `authz` filter. That is a design question rather than an
	// omission, and until it is settled a configuration carrying the
	// `authorization` section alongside an http listener is refused at load,
	// which is the fail-closed rule doing its job and also a real cliff for the
	// commonest deployment. ROADMAP.md records both halves.
	"http": true,
}

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
}
