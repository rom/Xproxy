package limits

import (
	"testing"
	"time"
)

// A peer reports what it has served, so it may legitimately claim the
// whole policy rate. What it may not do is claim more: before the
// clamp, one message carrying an absurd rate drove the local refill to
// zero and denied that key on every other node for the whole peer_stale
// window, and repeating it each gossip interval made that permanent.
func TestPeerReportCannotExceedThePolicyRate(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewKeyedLimiter(10, 10, 100)
	l.now = func() time.Time { return now }
	l.SetPeerStale(3 * time.Second)
	for i := 0; i < 10; i++ {
		l.Allow("k") // drain the burst
	}
	// An absurd report must count as "the whole rate", no worse.
	l.ReportPeer("rogue", []PeerReport{{Key: "k", Rate: 1e12}})
	now = now.Add(time.Second)
	if l.Allow("k") {
		t.Fatal("a peer at the full rate leaves nothing to refill, which is the design")
	}
	// Once the report goes stale the key recovers at the full rate. Before
	// the clamp the arithmetic was the same, but a repeated report would
	// have kept the bucket at zero however long the window.
	now = now.Add(4 * time.Second)
	if !l.Allow("k") {
		t.Fatal("the key never recovered after the report went stale")
	}
	// A negative rate must not credit tokens.
	l = NewKeyedLimiter(10, 10, 100)
	l.now = func() time.Time { return now }
	l.SetPeerStale(3 * time.Second)
	for i := 0; i < 10; i++ {
		l.Allow("n")
	}
	l.ReportPeer("rogue", []PeerReport{{Key: "n", Rate: -1e9}})
	now = now.Add(time.Second)
	allowed := 0
	for i := 0; i < 100; i++ {
		if l.Allow("n") {
			allowed++
		}
	}
	if allowed > 10 {
		t.Fatalf("a negative peer rate credited %d extra tokens", allowed)
	}
}
