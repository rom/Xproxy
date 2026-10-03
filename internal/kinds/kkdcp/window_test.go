package kkdcp

import (
	"net/netip"
	"testing"
	"time"
)

// The counting window, which is what turns two shapes of Kerberos abuse into
// a refusal: a client asking for forty different service principals in a
// minute, and a client failing pre-authentication over and over.
//
// It is tested on its own because the interesting behaviour is in the
// bookkeeping rather than in the protocol: what falls out of the window, what
// the table does when it is full, and the per-client ceiling that stops a
// client who has already tripped the bound from being counted forever.

func TestDistinctValuesAreCountedPerClientInsideTheWindow(t *testing.T) {
	w := newWindow(3, time.Minute)
	ip := peer("10.0.0.5")

	for i, name := range []string{"host/a", "host/b", "host/c"} {
		n, over := w.distinct(ip, name, when)
		if over {
			t.Fatalf("%s tripped the bound at %d names", name, i+1)
		}
		if n != i+1 {
			t.Errorf("after %s the count is %d, want %d", name, n, i+1)
		}
	}
	// The same name again is the same name: enumeration is about how many
	// different ones, not how many requests.
	if n, over := w.distinct(ip, "host/a", when); n != 3 || over {
		t.Errorf("a repeated name counted %d, over=%v", n, over)
	}
	// The fourth distinct name is past a bound of three.
	if n, over := w.distinct(ip, "host/d", when); n != 4 || !over {
		t.Errorf("the fourth name counted %d, over=%v", n, over)
	}
	// Another client is counted separately, which is what per-client means.
	if n, over := w.distinct(peer("10.0.0.6"), "host/a", when); n != 1 || over {
		t.Errorf("a second client started at %d, over=%v", n, over)
	}
	// And count reports without recording, which is what the log line about
	// a refusal needs.
	if n := w.count(ip); n != 4 {
		t.Errorf("count reports %d", n)
	}
	if n := w.count(peer("192.0.2.1")); n != 0 {
		t.Errorf("a client nothing was recorded for counts %d", n)
	}
}

// A name asked for outside the window is not evidence any more, which is the
// difference between a workstation using a handful of services all day and a
// client walking the directory.
func TestANameFallsOutOfTheWindow(t *testing.T) {
	w := newWindow(2, time.Minute)
	ip := peer("10.0.0.5")

	w.distinct(ip, "host/a", when)
	w.distinct(ip, "host/b", when)
	// Thirty seconds later a third name trips the bound, because all three
	// are inside the minute.
	if _, over := w.distinct(ip, "host/c", when.Add(30*time.Second)); !over {
		t.Fatal("three names inside the window did not trip a bound of two")
	}
	// Two minutes on, the first two have fallen out and the count is what
	// is left -- and the client is still tracked, because something was
	// heard from it inside the sweep's own window.
	n, over := w.distinct(ip, "host/d", when.Add(90*time.Second))
	if over || n != 2 {
		t.Errorf("after the window moved the count is %d, over=%v", n, over)
	}
}

// Occurrences, for the spray: one password against a thousand accounts is
// one failure each, so the address is the thing they have in common.
func TestOccurrencesAreCountedAndFallOutOfTheWindow(t *testing.T) {
	w := newWindow(2, time.Minute)
	ip := peer("10.0.0.5")

	for i := 1; i <= 2; i++ {
		if n, over := w.hit(ip, when); n != i || over {
			t.Errorf("failure %d counted %d, over=%v", i, n, over)
		}
	}
	if n, over := w.hit(ip, when); n != 3 || !over {
		t.Errorf("the third failure counted %d, over=%v", n, over)
	}
	if n := w.count(ip); n != 3 {
		t.Errorf("count reports %d failures", n)
	}
	// Two of the three fall out as the window moves.
	if n, over := w.hit(ip, when.Add(90*time.Second)); n != 1 || over {
		t.Errorf("after the window moved the count is %d, over=%v", n, over)
	}
}

// A client past the bound is not counted forever: the bound is also the
// table's bound per client, because a client that has tripped it has already
// told us what we needed to know.
func TestAClientPastTheBoundStopsBeingCounted(t *testing.T) {
	w := newWindow(2, time.Minute)
	ip := peer("10.0.0.5")

	var last int
	for i := 0; i < 50; i++ {
		last, _ = w.distinct(ip, "host/"+string(rune('a'+i%26))+string(rune('a'+i/26)), when)
	}
	if last > 2*4+1 {
		t.Errorf("a client past the bound is still being counted: %d names kept", last)
	}
	// The same ceiling on the occurrence window.
	hits := 0
	for i := 0; i < 50; i++ {
		hits, _ = w.hit(peer("10.0.0.6"), when)
	}
	if hits > 2*4+1 {
		t.Errorf("a client past the failure bound is still being counted: %d hits kept", hits)
	}
}

// The table is bounded, and when it is full a new client is not tracked
// rather than evicting one that is: the alternative is a flood of new
// addresses pushing the real ones out, which is an attack on the detector
// rather than on the KDC.
func TestAFullTableDoesNotEvictAnActiveClient(t *testing.T) {
	w := newWindow(2, time.Minute)
	for i := 0; i < maxClients; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i & 0xff), 1})
		if _, over := w.distinct(ip, "host/a", when); over {
			t.Fatalf("client %d tripped the bound on its first name", i)
		}
	}
	fresh := peer("192.0.2.1")
	if n, over := w.distinct(fresh, "host/a", when); n != 0 || over {
		t.Errorf("a new client against a full table counted %d, over=%v", n, over)
	}
	if n, over := w.hit(fresh, when); n != 0 || over {
		t.Errorf("a new client's failure against a full table counted %d, over=%v", n, over)
	}
	// The clients already there are still counted.
	if n, _ := w.distinct(peer("10.0.0.1"), "host/b", when); n != 2 {
		t.Errorf("a tracked client's second name counted %d", n)
	}
}

// The sweep drops the clients nothing has been heard from for twice the
// window, which is long enough that a client inside its own window is never
// dropped.
func TestTheSweepDropsTheClientsNothingWasHeardFrom(t *testing.T) {
	w := newWindow(2, time.Minute)
	old, recent := peer("10.0.0.5"), peer("10.0.0.6")
	w.distinct(old, "host/a", when)
	w.distinct(recent, "host/a", when.Add(90*time.Second))

	// Three minutes after the first: the first client is past twice the
	// window and the second is not.
	w.distinct(peer("10.0.0.7"), "host/a", when.Add(3*time.Minute))
	if n := w.count(old); n != 0 {
		t.Errorf("a client last heard from three windows ago is still tracked with %d names", n)
	}
	if n := w.count(recent); n != 1 {
		t.Errorf("a client inside the sweep's window was dropped: %d", n)
	}
}

// A listener that did not configure a bound has no window at all, and every
// call has to answer rather than panic.
func TestAnAbsentWindowAnswersNothing(t *testing.T) {
	var w *window
	if n, over := w.distinct(peer("10.0.0.5"), "host/a", when); n != 0 || over {
		t.Errorf("an absent window counted %d, over=%v", n, over)
	}
	if n, over := w.hit(peer("10.0.0.5"), when); n != 0 || over {
		t.Errorf("an absent window counted %d failures, over=%v", n, over)
	}
	if n := w.count(peer("10.0.0.5")); n != 0 {
		t.Errorf("an absent window reports %d", n)
	}
}
