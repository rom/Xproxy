package limits

import (
	"testing"
	"time"
)

func TestSlidingWindow(t *testing.T) {
	l := NewWindowLimiter(10, time.Second, 0)
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	if l.Window() != time.Second {
		t.Fatal("window")
	}
	for i := 0; i < 10; i++ {
		if !l.Allow("k") {
			t.Fatalf("request %d refused", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("11th request in the window allowed")
	}
	if l.Allow("other") != true {
		t.Fatal("keys are independent")
	}
	// Half a window later the previous window still weighs one half:
	// 10 * 0.5 = 5 counted, so 5 more fit and no more.
	now = now.Add(1500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if !l.Allow("k") {
			t.Fatalf("request %d in the next window refused", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("estimate exceeded at the window edge")
	}
	top := l.Top(1)
	if len(top) != 1 || top[0].Key != "k" || top[0].Total != 15 || top[0].Tokens != 0 {
		t.Fatalf("top: %+v", top)
	}
	// Two idle windows reset the count entirely.
	now = now.Add(2 * time.Second)
	for i := 0; i < 10; i++ {
		if !l.Allow("k") {
			t.Fatalf("after reset request %d refused", i)
		}
	}
	// A peer consuming 4 per second in the same window leaves 6 here.
	l.SetPeerStale(5 * time.Second)
	now = now.Add(3 * time.Second)
	l.ReportPeer("n2", []PeerReport{{Key: "k", Rate: 4}})
	n := 0
	for l.Allow("k") {
		n++
	}
	if n != 6 {
		t.Fatalf("with a peer at 4/s: %d allowed, want 6", n)
	}
	// Stale reports stop counting.
	now = now.Add(10 * time.Second)
	n = 0
	for l.Allow("k") {
		n++
	}
	if n != 10 {
		t.Fatalf("after the peer report expired: %d allowed, want 10", n)
	}
	// Idle keys are evicted after two windows: with one key per shard,
	// a new key in k's shard fits only once k is stale.
	l.SetMaxKeysForTest(1)
	sh := &l.shards[fnv("k")%uint32(len(l.shards))]
	now = now.Add(3 * time.Second)
	l.evict(sh, now)
	if _, still := sh.buckets["k"]; still {
		t.Fatal("idle window key not evicted")
	}
	if !l.Allow("fresh") {
		t.Fatal("fresh key refused")
	}
	// Flush reports consumption since the last flush.
	if f := l.Flush(0); f["fresh"] != 1 {
		t.Fatalf("flush: %v", f)
	}
}
