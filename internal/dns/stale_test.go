package dns

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// failing is an upstream that answers while it is up and stops
// answering when it is taken down, which is the outage serve-stale is
// about. It can also be made to answer SERVFAIL instead, which is what
// a broken forwarder does.
type failing struct {
	udp      net.PacketConn
	up       atomic.Bool
	servfail atomic.Bool
	queries  atomic.Int64
	// ttl is the TTL the answers carry, in seconds.
	ttl uint32
}

func newFailing(t *testing.T, ttl uint32) *failing {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &failing{udp: udp, ttl: ttl}
	f.up.Store(true)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := f.answer(buf[:n]); resp != nil {
				_, _ = udp.WriteTo(resp, from)
			}
		}
	}()
	t.Cleanup(func() { _ = udp.Close() })
	return f
}

func (f *failing) addr() string { return f.udp.LocalAddr().String() }

func (f *failing) answer(query []byte) []byte {
	f.queries.Add(1)
	h, err := ParseHeader(query)
	if err != nil {
		return nil
	}
	q, qEnd, err := ParseQuestion(query)
	if err != nil {
		return nil
	}
	switch {
	case !f.up.Load():
		return nil
	case f.servfail.Load():
		return Reply(query, qEnd, h, RcodeServFail)
	}
	return AnswerA(query, qEnd, h, q, []byte{93, 184, 216, 34}, f.ttl)
}

func stalePolicy(f *failing, stale, staleTTL time.Duration) *Policy {
	return &Policy{Resolver: NewResolver([]string{f.addr()}, 150*time.Millisecond),
		MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute,
		ServeStale: stale, StaleTTL: staleTTL}
}

// A resolver outage should not take the network with it. The answer is
// out of date by definition, and a name almost always still resolves
// where it did a minute ago -- while a client that cannot be told
// anything cannot reach the upstream itself either.
//
// The TTL is asserted as well as the address, because an expired answer
// served with the TTL the zone published would tell the client to keep
// something this resolver already knows is old.
func TestAnExpiredAnswerIsBetterThanNoAnswer(t *testing.T) {
	up := newFailing(t, 1) // one second, so it expires inside the test
	s, addr := startServer(t, stalePolicy(up, time.Hour, 30*time.Second), Hooks{})

	if got := answered(t, udpQuery(t, addr, mustQuery(t, 1, "a.test", TypeA))); len(got) != 1 {
		t.Fatalf("no answer to cache: %v", got)
	}
	// Past the TTL, with the upstream gone.
	time.Sleep(1100 * time.Millisecond)
	up.up.Store(false)
	resp := udpQuery(t, addr, mustQuery(t, 2, "a.test", TypeA))
	if resp == nil {
		t.Fatal("no answer at all: the stale entry was not served")
	}
	h, _ := ParseHeader(resp)
	if h.Rcode() != RcodeNoError {
		t.Fatalf("rcode %d, want NOERROR", h.Rcode())
	}
	got := answered(t, resp)
	if len(got) != 1 || got[0].String() != "93.184.216.34" {
		t.Fatalf("addresses %v, want the cached one", got)
	}
	_, qEnd, _ := ParseQuestion(resp)
	if ttl, ok := MinTTL(resp, qEnd, h); !ok || ttl != 30 {
		t.Fatalf("stale ttl %d, want 30 (RFC 8767 asks for a short one)", ttl)
	}
	if s.Stale.Load() != 1 {
		t.Fatalf("stale counted %d, want 1", s.Stale.Load())
	}

	// And without the setting there is nothing to fall back to, which is
	// what proves the answer above came from the window and not from an
	// entry that never expired.
	off := stalePolicy(up, 0, 30*time.Second)
	s2, addr2 := startServer(t, off, Hooks{})
	up.up.Store(true)
	if got := answered(t, udpQuery(t, addr2, mustQuery(t, 3, "b.test", TypeA))); len(got) != 1 {
		t.Fatal("no answer to cache on the second listener")
	}
	time.Sleep(1100 * time.Millisecond)
	up.up.Store(false)
	resp = udpQuery(t, addr2, mustQuery(t, 4, "b.test", TypeA))
	if resp == nil {
		t.Fatal("expected a SERVFAIL, got nothing")
	}
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeServFail {
		t.Fatalf("rcode %d, want SERVFAIL without serve_stale", h.Rcode())
	}
	if s2.Stale.Load() != 0 {
		t.Fatal("an answer was served stale with serve_stale off")
	}
}

// A stale answer is the last resort and not a cache hit: the upstream is
// asked every time, so the moment it comes back the client gets the
// current answer.
func TestStaleIsTriedOnlyAfterTheUpstream(t *testing.T) {
	up := newFailing(t, 1)
	s, addr := startServer(t, stalePolicy(up, time.Hour, 30*time.Second), Hooks{})
	_ = udpQuery(t, addr, mustQuery(t, 1, "a.test", TypeA))
	before := up.queries.Load()
	time.Sleep(1100 * time.Millisecond)
	up.up.Store(false)
	_ = udpQuery(t, addr, mustQuery(t, 2, "a.test", TypeA))
	if up.queries.Load() <= before {
		t.Fatal("the upstream was not asked before the stale answer was used")
	}
	// With the upstream back, the answer is the fresh one and nothing is
	// counted as stale.
	up.up.Store(true)
	stale := s.Stale.Load()
	resp := udpQuery(t, addr, mustQuery(t, 3, "a.test", TypeA))
	if got := answered(t, resp); len(got) != 1 {
		t.Fatalf("no answer once the upstream returned: %v", got)
	}
	_, qEnd, _ := ParseQuestion(resp)
	h, _ := ParseHeader(resp)
	if ttl, _ := MinTTL(resp, qEnd, h); ttl == 30 {
		t.Fatal("the fresh answer carries the stale TTL")
	}
	if s.Stale.Load() != stale {
		t.Fatal("a stale answer was served while the upstream was answering")
	}
}

// A SERVFAIL is a broken upstream when nothing is being validated, and
// an answer somebody rejected when something is. Standing in for the
// second with an expired answer of our own would undo the validation:
// the client would be handed, as a last resort, exactly the answer that
// was refused.
func TestAServfailIsStoodInForOnlyWithoutValidation(t *testing.T) {
	up := newFailing(t, 1)
	s, addr := startServer(t, stalePolicy(up, time.Hour, 30*time.Second), Hooks{})
	_ = udpQuery(t, addr, mustQuery(t, 1, "a.test", TypeA))
	time.Sleep(1100 * time.Millisecond)
	up.servfail.Store(true)
	if got := answered(t, udpQuery(t, addr, mustQuery(t, 2, "a.test", TypeA))); len(got) != 1 {
		t.Fatalf("a SERVFAIL was not stood in for: %v", got)
	}
	if s.Stale.Load() != 1 {
		t.Fatalf("stale counted %d, want 1", s.Stale.Load())
	}
}

// The other half of that rule is asserted where it lives, because
// standing a rejected answer in for is the thing that must not happen
// and a listener with real anchors is not needed to say so: with
// validation on, a SERVFAIL is not a failure a stale answer may cover.
func TestWithValidationAServfailIsNotAnOutage(t *testing.T) {
	withDNSSEC := &Policy{DNSSEC: &Validator{}}
	without := &Policy{}
	cases := []struct {
		name string
		p    *Policy
		lk   lookup
		want bool
	}{
		{"no answer at all, validating", withDNSSEC, lookup{err: errNoUpstream}, true},
		{"no answer at all, not validating", without, lookup{err: errNoUpstream}, true},
		{"servfail, not validating", without, lookup{rcode: RcodeServFail}, true},
		{"servfail, validating", withDNSSEC, lookup{rcode: RcodeServFail}, false},
		{"an answer, validating", withDNSSEC, lookup{rcode: RcodeNoError}, false},
		{"nxdomain, not validating", without, lookup{rcode: RcodeNXDomain}, false},
	}
	for _, tc := range cases {
		if got := tc.lk.failed(tc.p); got != tc.want {
			t.Errorf("%s: failed()=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// Past the window the entry is gone, not kept forever.
func TestTheStaleWindowEnds(t *testing.T) {
	c := NewCache(10)
	c.SetStale(500 * time.Millisecond)
	q := Question{Name: "a.test", Type: TypeA, Class: ClassIN}
	query := mustQuery(t, 1, "a.test", TypeA)
	h, _ := ParseHeader(query)
	_, qEnd, _ := ParseQuestion(query)
	resp := AnswerA(query, qEnd, h, q, []byte{93, 184, 216, 34}, 60)
	rh, _ := ParseHeader(resp)
	now := time.Now()
	c.Put(q, resp, qEnd, rh, time.Second, now)

	// Live: a hit, and no stale answer.
	if got, _ := c.Get(q, 2, now.Add(500*time.Millisecond)); got == nil {
		t.Fatal("a live entry was not a hit")
	}
	if got, _ := c.Stale(q, 2, now.Add(500*time.Millisecond), 30); got != nil {
		t.Fatal("a live entry was served as stale")
	}
	// Expired but inside the window: a miss, and a stale answer.
	if got, _ := c.Get(q, 2, now.Add(1200*time.Millisecond)); got != nil {
		t.Fatal("an expired entry was a hit")
	}
	got, _ := c.Stale(q, 2, now.Add(1200*time.Millisecond), 30)
	if got == nil {
		t.Fatal("no stale answer inside the window")
	}
	if gh, _ := ParseHeader(got); gh.ID != 2 {
		t.Fatalf("stale answer carries id %d, want the query's", gh.ID)
	}
	// Past the window: nothing, and the entry is dropped.
	if got, _ := c.Stale(q, 2, now.Add(2*time.Second), 30); got != nil {
		t.Fatal("a stale answer past the window")
	}
	if got, _ := c.Get(q, 2, now.Add(2*time.Second)); got != nil {
		t.Fatal("a hit past the window")
	}
	if c.Len() != 0 {
		t.Fatalf("cache holds %d entries past the window, want none", c.Len())
	}
}

// A nearly expired entry is refreshed by the query that found it, so a
// popular name is answered from the cache continuously instead of one
// client per TTL waiting for the upstream. The client that triggered the
// refresh waits for nothing: it is answered from the cache.
func TestAPopularNameIsRefreshedBeforeItExpires(t *testing.T) {
	up := newFailing(t, 2)
	p := stalePolicy(up, 0, 30*time.Second)
	p.Prefetch, p.PrefetchThreshold = true, 0.9 // almost any hit triggers one
	s, addr := startServer(t, p, Hooks{})
	if got := answered(t, udpQuery(t, addr, mustQuery(t, 1, "a.test", TypeA))); len(got) != 1 {
		t.Fatal("no answer to cache")
	}
	before := up.queries.Load()
	// A cache hit with most of the TTL left still triggers a refresh at
	// this threshold.
	time.Sleep(300 * time.Millisecond)
	resp := udpQuery(t, addr, mustQuery(t, 2, "a.test", TypeA))
	if got := answered(t, resp); len(got) != 1 {
		t.Fatalf("the triggering query was not answered from the cache: %v", got)
	}
	if s.Hits.Load() != 1 {
		t.Fatalf("cache hits %d, want 1: the client should not have waited on the upstream", s.Hits.Load())
	}
	if !waitFor(func() bool { return up.queries.Load() > before }) {
		t.Fatal("no refresh reached the upstream")
	}
	if s.Prefetched.Load() != 1 {
		t.Fatalf("prefetched counted %d, want 1", s.Prefetched.Load())
	}
}

// A hit with plenty of TTL left refreshes nothing: prefetch is about the
// end of a TTL, and refreshing on every hit would be a resolver doing
// its upstream traffic over again for no reason.
func TestAFreshEntryIsNotRefreshed(t *testing.T) {
	up := newFailing(t, 600)
	p := stalePolicy(up, 0, 30*time.Second)
	p.Prefetch, p.PrefetchThreshold = true, 0.1
	s, addr := startServer(t, p, Hooks{})
	_ = udpQuery(t, addr, mustQuery(t, 1, "a.test", TypeA))
	before := up.queries.Load()
	for i := 0; i < 5; i++ {
		_ = udpQuery(t, addr, mustQuery(t, uint16(10+i), "a.test", TypeA))
	}
	time.Sleep(100 * time.Millisecond)
	if up.queries.Load() != before {
		t.Fatalf("the upstream saw %d refreshes of an entry with its whole TTL left", up.queries.Load()-before)
	}
	if s.Prefetched.Load() != 0 {
		t.Fatalf("prefetched counted %d, want 0", s.Prefetched.Load())
	}
}

// The stampede this feature exists to prevent is the one it would
// otherwise cause: a hundred clients arriving on a nearly expired name
// must produce one refresh, not a hundred. The claim lives on the cache
// entry, which is what makes that true.
func TestABurstOnANearlyExpiredNameRefreshesOnce(t *testing.T) {
	up := newFailing(t, 2)
	p := stalePolicy(up, 0, 30*time.Second)
	p.Prefetch, p.PrefetchThreshold = true, 0.9
	// Room for the whole burst. With the usual worker budget the
	// listener would drop most of it for want of a slot, and a burst
	// that never arrived would say nothing about the claim on the cache
	// entry -- it would only say that eight queries fit through eight
	// slots.
	s, addr := startServerInFlight(t, p, Hooks{}, 32)
	_ = udpQuery(t, addr, mustQuery(t, 1, "a.test", TypeA))
	// Far enough into the two second TTL that every query in the burst
	// is past the threshold and would each start a refresh of its own.
	time.Sleep(400 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = udpQuery(t, addr, mustQuery(t, uint16(100+n), "a.test", TypeA))
		}(i)
	}
	wg.Wait()
	got := s.Prefetched.Load()
	if got == 0 {
		t.Fatal("no refresh at all, so this says nothing about the burst")
	}
	if got > 2 {
		t.Fatalf("%d refreshes started for one name, want one (or two across the refresh that landed)", got)
	}
}

// A refresh must not be attributed to the client whose query triggered
// it: that client did nothing wrong, and a security event against its
// address would be a ban somebody else earned.
//
// The shape of the assertion is the point. The first query screens the
// answer and is the querying client's; the second is a cache hit on the
// already-screened answer, so it raises nothing; the refresh screens the
// upstream's answer again and belongs to nobody. Two events, one with an
// address and one without.
func TestARefreshIsNobodysQuery(t *testing.T) {
	up := newScripted(t, map[string][]string{"rebind.test": {"127.0.0.1"}})
	var mu sync.Mutex
	var clients []string
	hooks := Hooks{Event: func(c netip.Addr, reason string, _ bool, _ ...any) {
		if reason == "dns_answer_denied" {
			mu.Lock()
			clients = append(clients, c.String())
			mu.Unlock()
		}
	}}
	p := screenPolicy(up, &AnswerPolicy{Deny: PrivateRanges(), Action: AnswerStrip})
	// The stripped answer has no addresses left, so it is cached for
	// negative_ttl (a minute here): the threshold and the wait are
	// chosen against that rather than against the zone's TTL.
	p.Prefetch, p.PrefetchThreshold = true, 0.99
	s, addr := startServer(t, p, hooks)
	_ = udpQuery(t, addr, mustQuery(t, 1, "rebind.test", TypeA))
	time.Sleep(800 * time.Millisecond)
	_ = udpQuery(t, addr, mustQuery(t, 2, "rebind.test", TypeA))
	if !waitFor(func() bool { return s.Prefetched.Load() != 0 }) {
		t.Fatalf("prefetched %d, want 1", s.Prefetched.Load())
	}
	// The refresh's own event comes after the counter: the prefetch is
	// counted when it starts, and the answer it screens is denied when it
	// lands, so the second event is a separate wait rather than the same
	// one.
	waitFor(func() bool { mu.Lock(); defer mu.Unlock(); return len(clients) >= 2 })
	mu.Lock()
	defer mu.Unlock()
	if len(clients) != 2 {
		t.Fatalf("events %v, want one for the client and one for the refresh", clients)
	}
	mine, nobody := 0, 0
	for _, c := range clients {
		switch c {
		case "127.0.0.1":
			mine++
		case (netip.Addr{}).String():
			nobody++
		default:
			t.Errorf("event attributed to %q, which sent no query", c)
		}
	}
	if mine != 1 || nobody != 1 {
		t.Fatalf("events %v, want exactly one from the client and one from the refresh", clients)
	}
}
