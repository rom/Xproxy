package ban

import (
	"net/netip"
	"testing"
	"time"
)

// A peer sets the deadline on a ban it shares, so it needs the ceiling
// the local paths already have. Without it a node whose clock is a year
// fast turns every ten-minute ban it shares into a year-long one on
// every other node, and a compromised node simply names a date next
// century.
func TestPeerBanLifetimeIsClamped(t *testing.T) {
	l, now := newList(t, cfg())
	far := now.Add(400 * 24 * time.Hour)
	if err := l.Apply(Entry{Target: "203.0.113.7", Until: far, Reason: "peer"}, false, "node-a"); err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Entries() {
		if e.Target != "203.0.113.7" {
			continue
		}
		if e.Until.After(now.Add(MaxDuration + time.Minute)) {
			t.Fatalf("peer ban runs to %v, past the ceiling", e.Until)
		}
		return
	}
	t.Fatal("the peer ban was not applied at all")
}

// Removal is the one message that takes protection away. A peer lifting
// an operator's own ban everywhere, silently and durably, is the thing
// a shared ban list must not allow.
func TestPeerCannotRemoveAnOperatorBan(t *testing.T) {
	l, now := newList(t, cfg())
	if _, err := l.Ban("203.0.113.8", time.Hour, "operator: confirmed attacker"); err != nil {
		t.Fatal(err)
	}
	if err := l.Apply(Entry{Target: "203.0.113.8"}, true, "node-a"); err != nil {
		t.Fatal(err)
	}
	if !l.Banned(netip.MustParseAddr("203.0.113.8")) {
		t.Fatal("a peer removed an operator's ban")
	}
	// A peer's own ban is still a peer's to lift.
	if err := l.Apply(Entry{Target: "203.0.113.9", Until: now.Add(time.Hour)}, false, "node-a"); err != nil {
		t.Fatal(err)
	}
	if err := l.Apply(Entry{Target: "203.0.113.9"}, true, "node-a"); err != nil {
		t.Fatal(err)
	}
	if l.Banned(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("a peer could not lift its own ban")
	}
}
