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

// The roster read the other way round: from a kind to the daemons that carry
// it, and from a daemon to the kinds it owns.
//
// These two are the split's own answer to "which binary serves this port".
// ServedBy is what the daemon-mismatch error names when a listener lands in the
// wrong process -- the one refusal that exists so a listener cannot quietly
// fall through to another kind and answer the wrong protocol on the right port.
// OwnedBy is the default each daemon binds without being told.
//
// Both must agree with the roster they read, and with each other: every kind
// ServedBy names must have that role serving it, and a kind must be owned by
// exactly the first daemon that serves it.
func TestTheRosterReadsBothWays(t *testing.T) {
	owners := map[string]Role{}
	for _, k := range Kinds() {
		served := ServedBy(k)
		if len(served) == 0 {
			t.Errorf("kind %q is served by nobody", k)
			continue
		}
		for _, r := range served {
			if !r.Serves(k) {
				t.Errorf("ServedBy(%q) names %s, which does not serve it", k, r)
			}
		}
		// The first is the owner, which is what Shared and the daemon
		// field are about.
		if got, ok := RoleOf(k); !ok || got != served[0] {
			t.Errorf("RoleOf(%q) = %s, want the first of %v", k, got, served)
		}
		if Shared(k) != (len(served) > 1) {
			t.Errorf("Shared(%q) = %v with %d daemons", k, Shared(k), len(served))
		}
		owners[k] = served[0]
		// The copy is a copy: a caller that sorts or truncates what it
		// got back must not be editing the roster itself.
		served[0] = Role("scribbled")
		if ServedBy(k)[0] == Role("scribbled") {
			t.Fatalf("ServedBy(%q) handed out the roster's own slice", k)
		}
	}

	// And from the other side: the kinds each role owns are exactly the
	// kinds whose first daemon it is, sorted.
	var fromOwnedBy []string
	for _, r := range Roles() {
		owned := OwnedBy(r)
		if !sort.StringsAreSorted(owned) {
			t.Errorf("OwnedBy(%s) is not sorted: %v", r, owned)
		}
		for _, k := range owned {
			if owners[k] != r {
				t.Errorf("OwnedBy(%s) claims %q, owned by %s", r, k, owners[k])
			}
		}
		fromOwnedBy = append(fromOwnedBy, owned...)
	}
	if len(fromOwnedBy) != len(owners) {
		t.Errorf("OwnedBy covers %d kinds, the roster has %d", len(fromOwnedBy), len(owners))
	}

	// A kind no daemon serves has no owner and no daemons, rather than a
	// zero Role that would read as the edge.
	if served := ServedBy("not-a-kind"); len(served) != 0 {
		t.Errorf("ServedBy on an unknown kind = %v", served)
	}
	if _, ok := RoleOf("not-a-kind"); ok {
		t.Error("an unknown kind has a role")
	}
}

// Every role names the program an operator types, and the mapping goes back
// again -- that round trip is what makes `daemon: xrelay` in a listener mean
// something rather than being accepted and ignored.
func TestEveryRoleNamesItsDaemonAndBack(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Roles() {
		d := r.Daemon()
		if d == "" {
			t.Errorf("role %q names no daemon", r)
		}
		if seen[d] {
			t.Errorf("two roles name the daemon %q", d)
		}
		seen[d] = true
		back, ok := RoleByDaemon(d)
		if !ok || back != r {
			t.Errorf("RoleByDaemon(%q) = %s, %v, want %s", d, back, ok, r)
		}
	}
	if _, ok := RoleByDaemon("xnothing"); ok {
		t.Error("a program nobody ships resolved to a role")
	}
}

// The roster read from both ends: every kind a role owns, and every
// role that carries a kind's code.
//
// These two are what a message about a misplaced listener is built from
// ("kind %q is served by %s, not by this daemon"), so what matters is
// that they agree with Owner and with each other: a kind is owned by
// exactly one role, and the role that owns it is the first of the ones
// that serve it.
func TestOwnedByAndServedByAgreeWithTheRoster(t *testing.T) {
	owned := map[string]Role{}
	for _, r := range Roles() {
		ks := OwnedBy(r)
		if !sort.StringsAreSorted(ks) {
			t.Errorf("OwnedBy(%s) is not sorted: %v", r, ks)
		}
		for _, k := range ks {
			if was, dup := owned[k]; dup {
				t.Errorf("kind %q is owned by %s and %s", k, was, r)
			}
			owned[k] = r
			if got, ok := RoleOf(k); !ok || got != r {
				t.Errorf("RoleOf(%q) = %s, %v, want %s", k, got, ok, r)
			}
		}
	}
	for _, k := range Kinds() {
		if _, ok := owned[k]; !ok {
			t.Errorf("kind %q is owned by nobody", k)
		}
		served := ServedBy(k)
		if len(served) == 0 {
			t.Fatalf("kind %q is served by nobody", k)
		}
		if served[0] != owned[k] {
			t.Errorf("kind %q: ServedBy says %s first, OwnedBy says %s", k, served[0], owned[k])
		}
		if len(served) != len(Daemons(k)) || Shared(k) != (len(served) > 1) {
			t.Errorf("kind %q: ServedBy %v disagrees with Daemons %v / Shared %v", k, served, Daemons(k), Shared(k))
		}
		// The returned slice is the caller's: writing to it must not
		// reach the roster the next caller reads.
		served[0] = "scribbled"
		if ServedBy(k)[0] != owned[k] {
			t.Fatalf("ServedBy handed out the roster's own slice for %q", k)
		}
	}
	if got := OwnedBy(Role("xnothing")); len(got) != 0 {
		t.Errorf("OwnedBy of a role nobody has = %v", got)
	}
	// A role with no case in Daemon falls back to its own name, which is
	// what keeps a message about an unknown role readable.
	if got := Role("future").Daemon(); got != "future" {
		t.Errorf("Daemon of an unknown role = %q", got)
	}
}
