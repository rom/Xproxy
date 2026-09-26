package sesslimit

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestTheZeroGateIsUnbounded(t *testing.T) {
	var g Gate
	for i := 0; i < 1000; i++ {
		if ok, reason := g.Enter(addr("10.0.0.1")); !ok {
			t.Fatalf("session %d refused: %s", i, reason)
		}
	}
	if g.Live() != 1000 {
		t.Errorf("live is %d", g.Live())
	}
	// With no per-client bound there is no table to grow, which is what
	// keeps an unbounded listener from holding one entry per address that
	// has ever connected.
	if g.Clients() != 0 {
		t.Errorf("a gate with no per-client bound is tracking %d clients", g.Clients())
	}
}

func TestTheGlobalBound(t *testing.T) {
	g := New(2, 0)
	for i := 0; i < 2; i++ {
		if ok, _ := g.Enter(addr("10.0.0.1")); !ok {
			t.Fatalf("session %d refused", i)
		}
	}
	ok, reason := g.Enter(addr("10.0.0.2"))
	if ok {
		t.Error("the third session was admitted")
	}
	if reason != ReasonTooMany {
		t.Errorf("the reason was %q", reason)
	}
	// And a release makes room again.
	g.Leave(addr("10.0.0.1"))
	if ok, _ := g.Enter(addr("10.0.0.2")); !ok {
		t.Error("a release did not make room")
	}
}

func TestThePerClientBound(t *testing.T) {
	g := New(0, 2)
	for i := 0; i < 2; i++ {
		if ok, _ := g.Enter(addr("10.0.0.1")); !ok {
			t.Fatalf("session %d refused", i)
		}
	}
	ok, reason := g.Enter(addr("10.0.0.1"))
	if ok {
		t.Error("the third session from one client was admitted")
	}
	if reason != ReasonTooManyPerClient {
		t.Errorf("the reason was %q", reason)
	}
	// Another client is unaffected, which is the point of the bound being
	// per client rather than global.
	if ok, _ := g.Enter(addr("10.0.0.2")); !ok {
		t.Error("a second client was refused by the first one's bound")
	}
}

// TestTheGlobalBoundIsCheckedFirst pins which reason a caller gets when both
// bounds would refuse, because the counters and the logs are read by somebody
// deciding whether the listener is full or one client is greedy.
func TestTheGlobalBoundIsCheckedFirst(t *testing.T) {
	g := New(1, 1)
	if ok, _ := g.Enter(addr("10.0.0.1")); !ok {
		t.Fatal("the first session was refused")
	}
	if _, reason := g.Enter(addr("10.0.0.1")); reason != ReasonTooMany {
		t.Errorf("the reason was %q, want the global one", reason)
	}
}

// TestTheTableDoesNotGrow is the leak this would otherwise be: one entry per
// address that has ever connected is a table an attacker fills for free.
func TestTheTableDoesNotGrow(t *testing.T) {
	g := New(0, 4)
	for i := 0; i < 500; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
		if ok, _ := g.Enter(ip); !ok {
			t.Fatalf("%s refused", ip)
		}
		g.Leave(ip)
	}
	if g.Clients() != 0 {
		t.Errorf("%d client entries survived their sessions", g.Clients())
	}
	if g.Live() != 0 {
		t.Errorf("live is %d after every session left", g.Live())
	}
}

// TestALeaveWithoutAnEnterCannotGoNegative, because a count below zero would
// make room that does not exist -- and a double Leave from a defer somebody
// wrote twice is the likeliest way to get one.
func TestALeaveWithoutAnEnterCannotGoNegative(t *testing.T) {
	g := New(1, 1)
	g.Leave(addr("10.0.0.1"))
	g.Leave(addr("10.0.0.1"))
	if g.Live() != 0 {
		t.Errorf("live is %d", g.Live())
	}
	if ok, _ := g.Enter(addr("10.0.0.1")); !ok {
		t.Error("the gate refused after a stray release")
	}
	if ok, _ := g.Enter(addr("10.0.0.1")); ok {
		t.Error("a stray release made room that did not exist")
	}
}

// TestTheBoundHoldsUnderConcurrentAccepts is the defect this package was
// written for. The six copies read the counter and then incremented it, so
// concurrent accepts all saw room and all took it -- driven this way, a bound of
// two admitted three.
//
// The goroutines spin on a flag rather than waiting on a WaitGroup because the
// window between the old check and the old act was a couple of instructions
// wide: a barrier that parks and wakes them spreads their arrival out far enough
// to hide it. This is how the original was reproduced, and it is kept in that
// shape so the test still has teeth.
func TestTheBoundHoldsUnderConcurrentAccepts(t *testing.T) {
	const per, goroutines = 2, 512
	for round := 0; round < 40; round++ {
		g := New(0, per)
		ip := addr("10.0.0.1")
		var admitted atomic.Int64
		var gate atomic.Bool
		var done sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				for !gate.Load() {
				}
				if ok, _ := g.Enter(ip); ok {
					admitted.Add(1)
				}
			}()
		}
		gate.Store(true)
		done.Wait()
		if got := admitted.Load(); got != per {
			t.Fatalf("round %d: the bound is %d and %d sessions were admitted",
				round, per, got)
		}
		if g.Live() != per {
			t.Fatalf("round %d: live is %d", round, g.Live())
		}
	}
}

// The same for the global bound, which failed the same way and by as much as
// the number of accepts in flight.
func TestTheGlobalBoundHoldsUnderConcurrentAccepts(t *testing.T) {
	const max, goroutines = 8, 512
	for round := 0; round < 40; round++ {
		g := New(max, 0)
		var admitted atomic.Int64
		var gate atomic.Bool
		var done sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			done.Add(1)
			go func(i int) {
				defer done.Done()
				for !gate.Load() {
				}
				ip := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
				if ok, _ := g.Enter(ip); ok {
					admitted.Add(1)
				}
			}(i)
		}
		gate.Store(true)
		done.Wait()
		if got := admitted.Load(); got != max {
			t.Fatalf("round %d: the bound is %d and %d sessions were admitted",
				round, max, got)
		}
	}
}

// An Enter racing a Leave must not lose the increment. In the old shape Leave
// deleted a client's entry while another goroutine held the counter it had
// already fetched, so that increment landed on an orphan and the session went
// uncounted for the rest of its life.
func TestAnEnterRacingALeaveIsStillCounted(t *testing.T) {
	const rounds = 2000
	g := New(0, 64)
	ip := addr("10.0.0.1")
	for round := 0; round < rounds; round++ {
		if ok, _ := g.Enter(ip); !ok {
			t.Fatalf("round %d: refused", round)
		}
		var done sync.WaitGroup
		done.Add(2)
		go func() { defer done.Done(); g.Leave(ip) }()
		go func() {
			defer done.Done()
			if ok, _ := g.Enter(ip); ok {
				g.Leave(ip)
			}
		}()
		done.Wait()
		g.Leave(ip)
		if g.Live() != 0 || g.Clients() != 0 {
			t.Fatalf("round %d: live %d, clients %d", round, g.Live(), g.Clients())
		}
	}
}
