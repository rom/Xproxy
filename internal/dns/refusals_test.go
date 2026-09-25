package dns

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/limits"
)

// A dropped query used to be one number for four causes: no worker
// slot, a datagram that is not a question, a banned client and the rate
// limit. An operator watching drops climb could not tell which, and the
// four want different answers — raise max_in_flight, ignore it, nothing,
// raise the rate. Each now names itself.
func TestEveryDropNamesItsReason(t *testing.T) {
	up := newFakeUpstream(t)
	var mu sync.Mutex
	seen := map[string]int{}
	// Read on the listener's goroutine and written on this one, so it
	// is atomic rather than a plain bool.
	var banned atomic.Bool
	hooks := Hooks{
		Refuse: func(reason string) { mu.Lock(); seen[reason]++; mu.Unlock() },
		Banned: func(netip.Addr) bool { return banned.Load() },
	}
	policy := &Policy{Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL: time.Second, MaxTTL: time.Hour}
	s, addr := startServer(t, policy, hooks)

	count := func(reason string) int { mu.Lock(); defer mu.Unlock(); return seen[reason] }

	// A response sent where a question belongs.
	resp := mustQuery(t, 1, "a.test", TypeA)
	resp[2] |= 0x80
	if !udpDropped(t, addr, resp) {
		t.Fatal("a response was answered")
	}
	if got := count(DropMalformed); got != 1 {
		t.Errorf("%s counted %d, want 1 (have %v)", DropMalformed, got, seen)
	}

	// A banned client.
	banned.Store(true)
	if !udpDropped(t, addr, mustQuery(t, 2, "a.test", TypeA)) {
		t.Fatal("a banned client was answered")
	}
	banned.Store(false)
	if got := count(DropBanned); got != 1 {
		t.Errorf("%s counted %d, want 1 (have %v)", DropBanned, got, seen)
	}

	// The per-client rate.
	rated := *policy
	rated.RateLimit = limits.NewKeyedLimiter(0.001, 1, 16) // no refill within the test
	s.Apply(&rated, 100)
	for i := 0; i < 4; i++ {
		_ = udpDropped(t, addr, mustQuery(t, uint16(10+i), "a.test", TypeA))
	}
	if got := count(DropRateLimit); got < 2 {
		t.Errorf("%s counted %d after four queries past a burst of 1 (have %v)", DropRateLimit, got, seen)
	}
	if got := count(DropWorkersBusy); got != 0 {
		t.Errorf("a rate limit was reported as %s %d times", DropWorkersBusy, got)
	}
}

// The refusals that are answered rather than dropped name themselves
// too: a blocked name and a client outside allow_clients are both
// visible in the counters, and separately.
func TestAnsweredRefusalsNameThemselves(t *testing.T) {
	up := newFakeUpstream(t)
	block, err := NewBlockList([]string{"ads.test"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string]int{}
	hooks := Hooks{Refuse: func(reason string) { mu.Lock(); seen[reason]++; mu.Unlock() }}
	policy := &Policy{Block: block, BlockAction: "nxdomain",
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour}
	s, addr := startServer(t, policy, hooks)

	if udpQuery(t, addr, mustQuery(t, 1, "ads.test", TypeA)) == nil {
		t.Fatal("a blocked name went unanswered")
	}
	// An ANY question over UDP, which is refused with TC rather than
	// expanded: the amplification case.
	if udpQuery(t, addr, mustQuery(t, 2, "a.test", TypeANY)) == nil {
		t.Fatal("an ANY query went unanswered")
	}
	acl := *policy
	acl.AllowClients = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	s.Apply(&acl, 100)
	if udpQuery(t, addr, mustQuery(t, 3, "a.test", TypeA)) == nil {
		t.Fatal("a refused client went unanswered")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, reason := range []string{"blocked", "any_over_udp", "client_not_allowed"} {
		if seen[reason] != 1 {
			t.Errorf("%s counted %d, want 1 (have %v)", reason, seen[reason], seen)
		}
	}
}
