package snmp

import (
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/snmp"
)

// What this relay remembers about the agents it signs messages to.
//
// A v3 message is authenticated against the agent's own engine identifier and
// its clock, so the relay has to learn both and keep them -- and what it will
// not learn is the security: a clock that went backwards is a reordered
// datagram or a replay, an engine identifier that does not match a pinned one
// is not the agent the operator named, and a table with no bound is a
// megabyte of key derivation per answer from anybody who answers twice.

func engineReport(boots, secs int64, id string) *wire.V3Header {
	return &wire.V3Header{EngineID: []byte(id), EngineBoots: boots, EngineTime: secs}
}

func newOriginator() *originator {
	return &originator{user: "relay", level: wire.AuthNoPriv, max: 4,
		keys: map[string]*usmKeys{}, engines: map[string]*upstreamEngine{}}
}

// TestTheAgentsClockIsLearnedAndNotUnlearned: the first report is believed,
// a later one with a higher clock replaces it, and one that goes backwards
// does not.
func TestTheAgentsClockIsLearnedAndNotUnlearned(t *testing.T) {
	o := newOriginator()
	now := time.Date(2025, 5, 6, 11, 0, 0, 0, time.UTC)
	const addr = "192.0.2.10:161"

	o.learn(addr, engineReport(3, 500, "agent-one"), now)
	if n := o.Discovered.Load(); n != 1 {
		t.Errorf("the discovery was counted %d times", n)
	}
	if o.Engines() != 1 {
		t.Errorf("the relay knows %d engines", o.Engines())
	}

	// Later in the same boot: believed.
	o.learn(addr, engineReport(3, 900, "agent-one"), now.Add(400*time.Second))
	// Backwards in the same boot: a reordered datagram, or a replay of one.
	o.learn(addr, engineReport(3, 100, "agent-one"), now.Add(401*time.Second))
	// A boot counter that fell: the same.
	o.learn(addr, engineReport(2, 5000, "agent-one"), now.Add(402*time.Second))
	e, send := o.engineFor(addr, now.Add(410*time.Second))
	if send || e == nil {
		t.Fatalf("a known agent asked for a discovery: %v %v", e, send)
	}
	if e.boots != 3 || e.time < 900 {
		t.Errorf("the clock is boots %d time %d, want the latest it was told", e.boots, e.time)
	}
	// A restart is the one thing that moves the clock back, and the boots
	// counter is what says so.
	o.learn(addr, engineReport(4, 10, "agent-one"), now.Add(500*time.Second))
	if e, _ = o.engineFor(addr, now.Add(500*time.Second)); e.boots != 4 {
		t.Errorf("a restart left the relay on boots %d", e.boots)
	}
	// The time sent advances with the wall clock, because the agent's does
	// whether or not anybody is asking -- a stale one is outside the replay
	// window and every message would be refused.
	e, _ = o.engineFor(addr, now.Add(560*time.Second))
	if e.time < 60 {
		t.Errorf("the time sent is %d, which has not advanced", e.time)
	}

	// A header with nothing in it teaches nothing: a discovery message is
	// exactly that shape, and believing one would let anybody set the clock.
	before := o.Engines()
	o.learn("192.0.2.11:161", nil, now)
	o.learn("192.0.2.11:161", engineReport(1, 1, ""), now)
	if o.Engines() != before {
		t.Errorf("an empty header was learned as an engine")
	}
}

// TestAColdAgentIsAskedOnceAndThenSignedTo: the first request to an agent the
// relay has never spoken to asks for a discovery, and a burst behind it waits
// rather than sending one discovery each.
func TestAColdAgentIsAskedOnceAndThenSignedTo(t *testing.T) {
	o := newOriginator()
	now := time.Date(2025, 5, 6, 11, 0, 0, 0, time.UTC)
	const addr = "192.0.2.20:161"

	if e, send := o.engineFor(addr, now); !send || e != nil {
		t.Fatalf("a cold agent answered %v %v, want a discovery", e, send)
	}
	// The second request in the same moment: the discovery is outstanding.
	if e, send := o.engineFor(addr, now.Add(time.Millisecond)); send || e != nil {
		t.Errorf("a burst behind the first sent another discovery")
	}
	// And after the retry window, one more.
	if _, send := o.engineFor(addr, now.Add(discoveryRetry+time.Second)); !send {
		t.Error("a discovery that was never answered was never retried")
	}
}

// TestAPinnedEngineIsNotAdopted: pinning the identifier is how an operator
// says which agent this is. An agent that calls itself something else is not
// learned -- adopting it would be the relay signing to whatever answered on
// that address.
func TestAPinnedEngineIsNotAdopted(t *testing.T) {
	o := newOriginator()
	o.pinned = []byte("agent-one")
	now := time.Date(2025, 5, 6, 11, 0, 0, 0, time.UTC)
	const addr = "192.0.2.30:161"

	// The pinned identifier is there from the start, and the clock is still
	// the agent's, so a discovery is still sent.
	if _, send := o.engineFor(addr, now); !send {
		t.Error("a pinned agent was signed to without a clock")
	}
	o.learn(addr, engineReport(1, 100, "somebody-else"), now)
	if e, send := o.engineFor(addr, now.Add(discoveryRetry+time.Second)); e != nil || !send {
		t.Errorf("an agent that renamed itself was adopted: %v %v", e, send)
	}
	// The pinned one is believed.
	o.learn(addr, engineReport(1, 100, "agent-one"), now)
	if e, send := o.engineFor(addr, now.Add(time.Second)); send || e == nil {
		t.Errorf("the pinned agent was not believed: %v %v", e, send)
	}
}

// TestTheEngineTableIsBounded: an address table with no bound is a key
// derivation per answer for anybody who answers. The bound refuses to learn
// a new agent rather than forgetting one that is being polled.
func TestTheEngineTableIsBounded(t *testing.T) {
	o := newOriginator()
	now := time.Date(2025, 5, 6, 11, 0, 0, 0, time.UTC)
	for i := 0; i < maxUpstreamEngines; i++ {
		o.engines[string(rune(i))+":161"] = &upstreamEngine{id: []byte("a"), at: now}
	}
	if n := o.Engines(); n != maxUpstreamEngines {
		t.Fatalf("the table holds %d", n)
	}
	o.learn("192.0.2.99:161", engineReport(1, 1, "one-too-many"), now)
	if n := o.Engines(); n != maxUpstreamEngines {
		t.Errorf("the table grew to %d", n)
	}
	if e, send := o.engineFor("192.0.2.99:161", now); e != nil || send {
		t.Errorf("an agent past the bound was answered %v %v", e, send)
	}
	// And a nil originator -- a listener with no identity of its own --
	// knows no engines rather than panicking when a status view asks.
	var none *originator
	if none.Engines() != 0 {
		t.Error("a listener with no upstream identity reported engines")
	}
}
