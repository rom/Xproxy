package correlate

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// clock is a settable clock, because a window store tested with sleeps
// would be a test suite that took half an hour.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestStore(t *testing.T, b Bounds) (*Store, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)}
	s := New(b)
	s.SetClock(c.now)
	return s, c
}

// The question the store exists for: one host on three kinds, which no
// listener can see by itself.
func TestOneActorAcrossSeveralKinds(t *testing.T) {
	s, c := newTestStore(t, Bounds{})
	scanner := addr("10.90.0.7")
	for _, kind := range []string{"modbus", "s7", "iec104"} {
		s.Observe(scanner, Fact{Class: ClassSession, Kind: kind, Listener: kind + "-line"})
		c.advance(20 * time.Second)
	}
	if got := s.KindsTouched(scanner, 0); strings.Join(got, ",") != "iec104,modbus,s7" {
		t.Errorf("kinds touched %v", got)
	}
	// An address that did one thing is not a sweep.
	quiet := addr("10.30.1.20")
	s.Observe(quiet, Fact{Class: ClassRead, Kind: "modbus", Listener: "line"})
	if got := s.KindsTouched(quiet, 0); len(got) != 1 {
		t.Errorf("the historian looks like a sweep: %v", got)
	}
}

// The pivot: a bastion session about the machine it reached, then an OT
// session from that machine. Two kinds, two daemons in a real estate, one
// actor -- the jump host.
func TestABastionSessionPrecedingAnOTSession(t *testing.T) {
	s, c := newTestStore(t, Bounds{Window: time.Hour})
	jump := addr("10.20.9.4")
	// The gate kind writes the fact about the machine that was reached.
	s.Merge(jump, Fact{Class: ClassGateSession, Kind: "ssh", Listener: "bastion",
		Identity: "contractor@vendor.example", Detail: "session opened"})
	c.advance(90 * time.Second)
	s.Observe(jump, Fact{Class: ClassSession, Kind: "modbus", Listener: "line"})

	if !s.Seen(jump, ClassGateSession, "", 10*time.Minute) {
		t.Fatal("the gate session did not reach the window")
	}
	fs := s.Recent(jump, 10*time.Minute)
	if len(fs) != 2 || fs[0].Class != ClassGateSession || !fs[0].Remote {
		t.Fatalf("facts %+v", fs)
	}
	if fs[0].Identity != "contractor@vendor.example" {
		t.Errorf("the identity did not survive: %q", fs[0].Identity)
	}
	// And the order is what a chain is read in: oldest first.
	if !fs[0].At.Before(fs[1].At) {
		t.Error("the facts came back newest first, which reads a chain backwards")
	}
}

// The other chain: a clock step is about the daemon rather than about an
// address, and is still there when the command that followed it arrives.
func TestAClockStepIsAboutTheEstate(t *testing.T) {
	s, c := newTestStore(t, Bounds{Window: 30 * time.Minute})
	s.ObserveEstate(Fact{Class: ClassTimeStep, Kind: "ntp", Listener: "time",
		Detail: "offset 2m14s"})
	c.advance(4 * time.Minute)
	if fs := s.RecentEstate(10 * time.Minute); len(fs) != 1 || fs[0].Class != ClassTimeStep {
		t.Fatalf("estate facts %+v", fs)
	}
	// It is not attributed to any address, which would be a false lead.
	if fs := s.Recent(addr("10.0.0.1"), 0); len(fs) != 0 {
		t.Errorf("an estate fact was attributed to an address: %+v", fs)
	}
}

func TestTheWindowForgets(t *testing.T) {
	s, c := newTestStore(t, Bounds{Window: 5 * time.Minute})
	a := addr("10.40.0.9")
	s.Observe(a, Fact{Class: ClassSession, Kind: "modbus"})
	c.advance(4 * time.Minute)
	if !s.Seen(a, ClassSession, "modbus", 0) {
		t.Error("a fact inside the window was forgotten")
	}
	c.advance(2 * time.Minute)
	if s.Seen(a, ClassSession, "modbus", 0) {
		t.Error("a fact outside the window was answered")
	}
	// A shorter question than the window is answered from the window.
	s.Observe(a, Fact{Class: ClassWrite, Kind: "modbus"})
	c.advance(2 * time.Minute)
	if s.Seen(a, ClassWrite, "", time.Minute) {
		t.Error("a two-minute-old fact answered a one-minute question")
	}
	if !s.Seen(a, ClassWrite, "", 4*time.Minute) {
		t.Error("a two-minute-old fact did not answer a four-minute question")
	}
}

// A burst is one fact with a count, which is what keeps a flood from
// filling an actor's whole window with the same line.
func TestIdenticalFactsCollapse(t *testing.T) {
	s, _ := newTestStore(t, Bounds{Collapse: time.Second})
	a := addr("10.50.0.3")
	for range 40 {
		s.Observe(a, Fact{Class: ClassRefused, Kind: "modbus", Detail: "read_only"})
	}
	fs := s.Recent(a, 0)
	if len(fs) != 1 {
		t.Fatalf("a burst of one refusal became %d facts", len(fs))
	}
	if fs[0].Count != 40 {
		t.Errorf("count %d", fs[0].Count)
	}
	if got := s.Count(a, ClassRefused, "", 0); got != 40 {
		t.Errorf("Count reported %d, so the collapsed ones were lost", got)
	}
}

func TestADifferentFactDoesNotCollapse(t *testing.T) {
	s, _ := newTestStore(t, Bounds{})
	a := addr("10.50.0.4")
	s.Observe(a, Fact{Class: ClassRefused, Kind: "modbus", Detail: "read_only"})
	s.Observe(a, Fact{Class: ClassRefused, Kind: "modbus", Detail: "unit_not_allowed"})
	if got := len(s.Recent(a, 0)); got != 2 {
		t.Errorf("two different refusals became %d facts", got)
	}
}

// The bounds, which are the interesting part of a table keyed by something
// a stranger picks.
func TestTheFactsPerActorAreBoundedAndTheLossIsVisible(t *testing.T) {
	s, c := newTestStore(t, Bounds{MaxFacts: 4, Collapse: time.Nanosecond})
	a := addr("10.60.0.5")
	for i := range 10 {
		c.advance(time.Second)
		s.Observe(a, Fact{Class: ClassRead, Kind: "modbus", Detail: string(rune('a' + i))})
	}
	fs := s.Recent(a, 0)
	if len(fs) != 4 {
		t.Fatalf("%d facts held against a bound of 4", len(fs))
	}
	// The newest are the ones kept.
	if fs[3].Detail != "j" {
		t.Errorf("the newest fact is %q", fs[3].Detail)
	}
	if !s.Truncated(a) {
		t.Error("a truncated window did not say so, so a detector would read it as whole")
	}
	if st := s.Status(); st.Dropped == 0 {
		t.Errorf("drops were not counted: %+v", st)
	}
}

func TestTheActorsAreBoundedAndTheOldestGoes(t *testing.T) {
	s, c := newTestStore(t, Bounds{MaxActors: 3})
	first := addr("10.70.0.1")
	s.Observe(first, Fact{Class: ClassSession, Kind: "modbus"})
	for i := 2; i <= 4; i++ {
		c.advance(time.Second)
		s.Observe(netip.AddrFrom4([4]byte{10, 70, 0, byte(i)}), Fact{Class: ClassSession, Kind: "modbus"})
	}
	if s.Seen(first, ClassSession, "", 0) {
		t.Error("the least recently active actor was kept and a newer one evicted")
	}
	st := s.Status()
	if st.Actors > 3 || st.Evicted == 0 {
		t.Errorf("status %+v", st)
	}
}

// The estate's facts are not an actor a stranger can create, so a flood of
// addresses must not push out the left half of every chain.
func TestAFloodDoesNotEvictTheEstate(t *testing.T) {
	s, c := newTestStore(t, Bounds{MaxActors: 2})
	s.ObserveEstate(Fact{Class: ClassTimeStep, Kind: "ntp"})
	for i := range 20 {
		c.advance(time.Second)
		s.Observe(netip.AddrFrom4([4]byte{10, 80, 0, byte(i)}), Fact{Class: ClassSession, Kind: "modbus"})
	}
	if fs := s.RecentEstate(0); len(fs) != 1 {
		t.Errorf("the clock step was evicted by a flood of addresses: %+v", fs)
	}
}

// A detail is a peer's string, so it is clipped rather than kept whole.
func TestADetailIsClipped(t *testing.T) {
	s, _ := newTestStore(t, Bounds{})
	a := addr("10.90.0.1")
	s.Observe(a, Fact{Class: ClassRead, Kind: "mms",
		Detail:   strings.Repeat("x", 4096),
		Identity: strings.Repeat("y", 4096)})
	fs := s.Recent(a, 0)
	if len(fs) != 1 {
		t.Fatal("no fact")
	}
	if len(fs[0].Detail) > 300 || len(fs[0].Identity) > 100 {
		t.Errorf("detail %d and identity %d octets came through", len(fs[0].Detail), len(fs[0].Identity))
	}
}

// A nil store answers nothing and records nothing, so a kind need not
// check whether correlation is configured before writing a fact.
func TestANilStoreIsUsable(t *testing.T) {
	var s *Store
	s.Observe(addr("10.0.0.1"), Fact{Class: ClassSession, Kind: "modbus"})
	s.ObserveEstate(Fact{Class: ClassTimeStep, Kind: "ntp"})
	s.Merge(addr("10.0.0.1"), Fact{Class: ClassSession, Kind: "ssh"})
	if s.Seen(addr("10.0.0.1"), ClassSession, "", 0) {
		t.Error("a nil store answered yes")
	}
	if got := s.KindsTouched(addr("10.0.0.1"), 0); got != nil {
		t.Errorf("a nil store returned %v", got)
	}
	if st := s.Status(); st.Actors != 0 || st.Window != "" {
		t.Errorf("a nil store's status is %+v", st)
	}
	if s.Truncated(addr("10.0.0.1")) || s.Window() != 0 {
		t.Error("a nil store reported a window")
	}
	if _, ok := s.First(addr("10.0.0.1"), 0); ok {
		t.Error("a nil store had a first fact")
	}
}

// A fact with no class is a caller mistake and is dropped rather than
// filed under the empty string, which nothing could ever ask for.
func TestAFactWithNoClassIsRefused(t *testing.T) {
	s, _ := newTestStore(t, Bounds{})
	a := addr("10.0.0.2")
	s.Observe(a, Fact{Kind: "modbus"})
	if fs := s.Recent(a, 0); len(fs) != 0 {
		t.Errorf("a classless fact was filed: %+v", fs)
	}
}

func TestTheBoundsTakeDefaultsAndCeilings(t *testing.T) {
	s := New(Bounds{})
	if s.Window() != DefaultWindow {
		t.Errorf("default window %s", s.Window())
	}
	st := s.Status()
	if st.MaxActors != DefaultActors || st.MaxFacts != DefaultFacts {
		t.Errorf("defaults %+v", st)
	}
	big := New(Bounds{Window: 72 * time.Hour, MaxActors: 1 << 30, MaxFacts: 1 << 20})
	if big.Window() != MaxWindow {
		t.Errorf("a 72h window was accepted: %s", big.Window())
	}
	if st := big.Status(); st.MaxActors != MaxActorsCeil || st.MaxFacts != MaxFactsCeil {
		t.Errorf("ceilings %+v", st)
	}
}

// Concurrent writers and readers, because every listener of a daemon
// writes to this one table.
func TestConcurrentUse(t *testing.T) {
	s := New(Bounds{MaxActors: 64, MaxFacts: 8})
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := netip.AddrFrom4([4]byte{10, 0, 1, byte(i)})
			for j := range 200 {
				s.Observe(a, Fact{Class: ClassSession, Kind: "modbus", Detail: string(rune('a' + j%26))})
				_ = s.KindsTouched(a, 0)
				_ = s.Count(a, ClassSession, "modbus", 0)
				s.ObserveEstate(Fact{Class: ClassTimeStep, Kind: "ntp"})
				_ = s.Status()
			}
		}(i)
	}
	wg.Wait()
	if st := s.Status(); st.Observed == 0 {
		t.Errorf("nothing was recorded: %+v", st)
	}
}
