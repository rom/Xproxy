package limits

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// Tests in this file pin exact boundaries that mutation testing found
// unobserved: off-by-one in comparisons, arithmetic in refill and
// eviction, and the bounds of the tracking maps.

func TestFNV(t *testing.T) {
	if fnv("") != 2166136261 {
		t.Fatalf("fnv(\"\") = %d", fnv(""))
	}
	if fnv("a") != 0xe40c292c { // FNV-1a 32 bit reference value
		t.Fatalf("fnv(\"a\") = %#x", fnv("a"))
	}
	if fnv("ab") == fnv("ba") {
		t.Fatal("order insensitive")
	}
}

func TestMaxKeysDefault(t *testing.T) {
	if l := NewKeyedLimiter(1, 1, 0); l.maxKeys != 4096 {
		t.Fatalf("maxKeys %d", l.maxKeys)
	}
	if l := NewKeyedLimiter(1, 1, -5); l.maxKeys != 4096 {
		t.Fatalf("maxKeys %d", l.maxKeys)
	}
	if l := NewKeyedLimiter(1, 1, 1); l.maxKeys != 1 {
		t.Fatalf("maxKeys %d", l.maxKeys)
	}
}

// sameShardKeys returns n distinct keys that hash to the same shard.
func sameShardKeys(n int) []string {
	want := fnv("k0") % 64
	out := []string{"k0"}
	for i := 1; len(out) < n; i++ {
		k := fmt.Sprintf("k%d", i)
		if fnv(k)%64 == want {
			out = append(out, k)
		}
	}
	return out
}

func TestTokenBoundaries(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewKeyedLimiter(1, 2, 100) // 1 token/s, burst 2
	l.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if !l.Allow("a") {
			t.Fatalf("burst request %d refused", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("third request should exceed the burst of 2")
	}
	// No time passes: nothing refills.
	if l.Allow("a") {
		t.Fatal("refilled without time passing")
	}
	now = now.Add(time.Second) // exactly one token
	if !l.AllowN("a", 1) || l.AllowN("a", 0.001) {
		t.Fatal("exactly one token should allow exactly one")
	}
	now = now.Add(time.Hour) // capped at burst, not more
	if !l.AllowN("a", 2) || l.AllowN("a", 0.001) {
		t.Fatal("refill must cap at burst")
	}
}

func TestShardBoundExact(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewKeyedLimiter(1, 1, 1) // one tracked key per shard, full again after 1s
	l.now = func() time.Time { return now }
	keys := sameShardKeys(3)
	if !l.Allow(keys[0]) || l.Allow(keys[0]) {
		t.Fatal("first key")
	}
	// Shard full and nothing stale: the second key is allowed untracked
	// (bounded by burst) and does not evict the active first key.
	if !l.AllowN(keys[1], 1) || l.AllowN(keys[1], 1.5) {
		t.Fatal("untracked key should be bounded by burst only")
	}
	if l.Len() != 1 {
		t.Fatalf("tracked %d", l.Len())
	}
	// Just before the bucket is full again nothing is evicted; at exactly
	// full it is.
	now = now.Add(time.Second - time.Nanosecond)
	l.Allow(keys[2])
	if l.Len() != 1 {
		t.Fatalf("evicted early: %d", l.Len())
	}
	now = now.Add(time.Nanosecond)
	if !l.Allow(keys[2]) || l.Len() != 1 {
		t.Fatalf("eviction at exactly full: tracked %d", l.Len())
	}
	if _, ok := l.shards[fnv(keys[0])%64].buckets[keys[0]]; ok {
		t.Fatal("stale key kept")
	}
}

func TestPeerBoundaries(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewKeyedLimiter(10, 100, 100)
	l.now = func() time.Time { return now }
	l.SetPeerStale(2 * time.Second)
	if !l.AllowN("k", 100) {
		t.Fatal("drain")
	}
	// A peer consuming 4/s leaves 6/s locally.
	l.ReportPeer("p1", []PeerReport{{Key: "k", Rate: 4}})
	now = now.Add(time.Second)
	if !l.AllowN("k", 6) || l.AllowN("k", 0.001) {
		t.Fatal("refill at rate minus peer rate")
	}
	// Peers over the local rate clamp to zero, never negative.
	l.ReportPeer("p1", []PeerReport{{Key: "k", Rate: 50}})
	now = now.Add(time.Second)
	if l.AllowN("k", 0.001) {
		t.Fatal("negative rate should clamp to zero")
	}
	// At exactly peer_stale the report still counts; a nanosecond later
	// it is dropped and the full rate returns.
	l.ReportPeer("p1", []PeerReport{{Key: "k", Rate: 10}})
	now = now.Add(2 * time.Second)
	if l.AllowN("k", 0.001) {
		t.Fatal("report at exactly stale age should still apply")
	}
	now = now.Add(time.Nanosecond)
	now = now.Add(time.Second)
	if !l.AllowN("k", 10) {
		t.Fatal("stale report should be dropped")
	}
	// Reports are keyed by peer: an update replaces, a new peer adds, and
	// at most 64 peers are kept.
	if !l.AllowN("k", 1e9) { // drain whatever is left
		_ = l.AllowN("k", l.burst)
	}
	l.AllowN("k", 1e9)
	for i := 0; i < 70; i++ {
		l.ReportPeer(fmt.Sprintf("peer%d", i), []PeerReport{{Key: "k", Rate: 0.1}})
	}
	l2 := NewKeyedLimiter(100, 1000, 100)
	l2.now = l.now
	l2.SetPeerStale(2 * time.Second)
	l2.AllowN("k", 1000)
	for i := 0; i < 70; i++ {
		l2.ReportPeer(fmt.Sprintf("peer%d", i), []PeerReport{{Key: "k", Rate: 1}})
	}
	now = now.Add(time.Second)
	if !l2.AllowN("k", 36) || l2.AllowN("k", 0.5) {
		t.Fatal("only 64 peers should reduce the rate (100 - 64 = 36)")
	}
	// A report for a key in a full shard is dropped.
	l3 := NewKeyedLimiter(10, 10, 1)
	l3.now = l.now
	l3.SetPeerStale(2 * time.Second)
	keys := sameShardKeys(2)
	l3.Allow(keys[0])
	l3.ReportPeer("p", []PeerReport{{Key: keys[1], Rate: 10}})
	if l3.Len() != 1 {
		t.Fatalf("report created a bucket in a full shard: %d", l3.Len())
	}
	// Without peer sharing enabled reports are ignored entirely.
	l4 := NewKeyedLimiter(10, 10, 100)
	l4.ReportPeer("p", []PeerReport{{Key: "x", Rate: 10}})
	if l4.Len() != 0 {
		t.Fatal("report tracked without peer_stale")
	}
}

func TestFlushBoundaries(t *testing.T) {
	l := NewKeyedLimiter(100, 100, 100)
	for i := 0; i < 3; i++ {
		l.Allow("a")
	}
	l.Allow("b")
	l.Allow("b")
	l.Allow("c")
	l.Allow("zero") // tracked but consumption flushed below first
	first := l.Flush(0)
	if first["a"] != 3 || first["b"] != 2 || first["c"] != 1 || first["zero"] != 1 {
		t.Fatalf("flush %v", first)
	}
	if again := l.Flush(0); len(again) != 0 {
		t.Fatalf("second flush not empty: %v", again)
	}
	l.Allow("a")
	l.Allow("a")
	l.Allow("b")
	l.Allow("c")
	// limit equal to the key count returns everything; one less keeps the
	// largest consumers.
	if out := l.Flush(3); len(out) != 3 {
		t.Fatalf("limit == keys: %v", out)
	}
	l.Allow("a")
	l.Allow("a")
	l.Allow("b")
	out := l.Flush(2)
	if len(out) != 2 || out["a"] != 2 || out["b"] != 1 {
		t.Fatalf("limit below keys: %v", out)
	}
}

func TestConnPerIPBoundary(t *testing.T) {
	c := NewConnLimiter(10, 2)
	ip := netip.MustParseAddr("192.0.2.1")
	if ok, _ := c.acquire(ip); !ok {
		t.Fatal("first")
	}
	if ok, _ := c.acquire(ip); !ok {
		t.Fatal("second (at the limit)")
	}
	if ok, reason := c.acquire(ip); ok || reason != "max_connections_per_ip" {
		t.Fatalf("third: %v %q", ok, reason)
	}
	c.release(ip)
	if ok, _ := c.acquire(ip); !ok {
		t.Fatal("after a release one more fits")
	}
	if c.perIP[ip] != 2 {
		t.Fatalf("count %d", c.perIP[ip])
	}
	c.release(ip)
	c.release(ip)
	if _, tracked := c.perIP[ip]; tracked {
		t.Fatal("address kept after the last release")
	}
	if c.total.Load() != 0 {
		t.Fatalf("total %d", c.total.Load())
	}
	// Total limit boundary.
	c = NewConnLimiter(1, 10)
	if ok, _ := c.acquire(ip); !ok {
		t.Fatal("one fits")
	}
	if ok, reason := c.acquire(netip.MustParseAddr("192.0.2.2")); ok || reason != "max_connections" {
		t.Fatalf("second over total: %v %q", ok, reason)
	}
}
