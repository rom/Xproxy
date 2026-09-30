package proxy

import (
	"net/netip"
	"testing"

	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/correlate"
)

// The window the engine owns: on by default, off when the configuration
// says so, and a nil store that every kind can write to without checking.
func TestTheWindowIsOnByDefaultAndCanBeTurnedOff(t *testing.T) {
	if s := newCorrelation(&config.Config{}); s == nil {
		t.Fatal("a configuration with no correlation section has no window")
	}
	off := false
	if s := newCorrelation(&config.Config{Correlation: &config.Correlation{Enabled: &off}}); s != nil {
		t.Error("correlation.enabled: false still built a window")
	}
	// The bounds reach the store.
	s := newCorrelation(&config.Config{Correlation: &config.Correlation{
		Window: config.Duration(5 * 60 * 1e9), MaxActors: 8, MaxFacts: 4}})
	if s.Window().Minutes() != 5 {
		t.Errorf("window %s", s.Window())
	}
	if st := s.Status(); st.MaxActors != 8 || st.MaxFacts != 4 {
		t.Errorf("bounds %+v", st)
	}
}

// A fact whose other half would be in a sibling daemon is shared; one
// every daemon can already see about its own listeners is not. The
// difference is the whole of the sharing policy, because a session per
// device per listener across an estate would be a gossip flood.
func TestOnlyTheFactsWithAnotherHalfElsewhereAreShared(t *testing.T) {
	for _, c := range []struct {
		class  correlate.Class
		shared bool
	}{
		{correlate.ClassGateSession, true},
		{correlate.ClassTimeStep, true},
		{correlate.ClassEngineering, true},
		{correlate.ClassCredential, true},
		{correlate.ClassSession, false},
		{correlate.ClassRead, false},
		{correlate.ClassWrite, false},
		{correlate.ClassRefused, false},
		{correlate.ClassDiscovery, false},
	} {
		if got := correlationShared(c.class); got != c.shared {
			t.Errorf("%s shared=%v, want %v", c.class, got, c.shared)
		}
	}
}

// A peer's fact comes back in, which is the point: on this design the
// bastion is xgate and the plant is xot, so the pivot is two processes.
func TestAPeersFactIsMerged(t *testing.T) {
	s := &Server{correlation: correlate.New(correlate.Bounds{}), stats: &Stats{}}
	jump := netip.MustParseAddr("10.20.9.4")
	e := cluster.Event{Kind: eventCorrelate,
		Key:   correlationKey(jump, correlate.Fact{Class: correlate.ClassGateSession, Kind: "ssh"}),
		Route: "contractor@vendor.example"}
	if !s.applyCorrelationEvent(e, "xgate") {
		t.Fatal("a correlation event was not recognised")
	}
	fs := s.correlation.Recent(jump, 0)
	if len(fs) != 1 {
		t.Fatalf("facts %+v", fs)
	}
	if fs[0].Class != correlate.ClassGateSession || fs[0].Kind != "ssh" || !fs[0].Remote {
		t.Errorf("fact %+v", fs[0])
	}
	if fs[0].Identity != "contractor@vendor.example" {
		t.Errorf("identity %q", fs[0].Identity)
	}
	if fs[0].Listener != "xgate" {
		t.Errorf("a peer's fact should say which peer, got %q", fs[0].Listener)
	}
	if s.stats.CorrelationMerged.Load() != 1 {
		t.Error("the merge was not counted")
	}
}

// A fact about the estate rather than about an address crosses too: the
// clock moved on a sibling, and the commands that followed arrive here.
func TestAPeersEstateFactIsMerged(t *testing.T) {
	s := &Server{correlation: correlate.New(correlate.Bounds{}), stats: &Stats{}}
	e := cluster.Event{Kind: eventCorrelate,
		Key: correlationKey(netip.Addr{}, correlate.Fact{Class: correlate.ClassTimeStep, Kind: "ntp"})}
	if !s.applyCorrelationEvent(e, "xrelay") {
		t.Fatal("not recognised")
	}
	if fs := s.correlation.RecentEstate(0); len(fs) != 1 || fs[0].Class != correlate.ClassTimeStep {
		t.Errorf("estate facts %+v", fs)
	}
}

// A key that does not decode is refused and counted rather than filed
// under something nothing can ask for.
func TestAMalformedPeerFactIsRefused(t *testing.T) {
	s := &Server{correlation: correlate.New(correlate.Bounds{}), stats: &Stats{}}
	for _, key := range []string{
		"",                              // nothing
		"session\x1fmodbus",             // two fields
		"nonsense\x1fmodbus\x1f1.2.3.4", // a class this build does not have
		"session\x1fmodbus\x1fnot-an-address",
	} {
		if !s.applyCorrelationEvent(cluster.Event{Kind: eventCorrelate, Key: key}, "peer") {
			t.Errorf("%q was handed on rather than refused", key)
		}
	}
	if got := s.stats.CorrelationRefused.Load(); got != 4 {
		t.Errorf("refused %d of 4", got)
	}
	if st := s.correlation.Status(); st.Actors != 0 {
		t.Errorf("a malformed fact reached the table: %+v", st)
	}
}

// An event that is not ours is handed on, so the plane still gets its own.
func TestAnotherEventIsNotClaimed(t *testing.T) {
	s := &Server{correlation: correlate.New(correlate.Bounds{}), stats: &Stats{}}
	if s.applyCorrelationEvent(cluster.Event{Kind: "honeypot", Key: "10.0.0.1"}, "peer") {
		t.Error("a honeypot event was claimed by the correlation handler")
	}
}

// ObserveFact with no window configured does nothing, and with one writes
// about the address -- or about the daemon when there is no address.
func TestObserveFact(t *testing.T) {
	off := &Server{stats: &Stats{}}
	off.ObserveFact(netip.MustParseAddr("10.0.0.1"), correlate.Fact{Class: correlate.ClassSession, Kind: "modbus"})

	s := &Server{correlation: correlate.New(correlate.Bounds{}), stats: &Stats{}}
	a := netip.MustParseAddr("10.40.1.9")
	s.ObserveFact(a, correlate.Fact{Class: correlate.ClassSession, Kind: "modbus", Listener: "line"})
	s.ObserveFact(netip.Addr{}, correlate.Fact{Class: correlate.ClassTimeStep, Kind: "ntp"})
	if !s.correlation.Seen(a, correlate.ClassSession, "modbus", 0) {
		t.Error("the address's fact is missing")
	}
	if len(s.correlation.RecentEstate(0)) != 1 {
		t.Error("the daemon's own fact is missing")
	}
	// And the cross-kind question, which is what the store is for.
	s.ObserveFact(a, correlate.Fact{Class: correlate.ClassSession, Kind: "s7", Listener: "cell"})
	s.ObserveFact(a, correlate.Fact{Class: correlate.ClassSession, Kind: "iec104", Listener: "substation"})
	if got := s.correlation.KindsTouched(a, 0); len(got) != 3 {
		t.Errorf("one host on three control protocols read as %v", got)
	}
}

// The snapshot carries the window, so a status view and the exporter read
// the same table.
func TestSnapshotCarriesTheCorrelationWindow(t *testing.T) {
	var s Stats
	if sn := s.snapshot(); sn.Correlation != nil {
		t.Errorf("a snapshot with no window carries %+v", sn.Correlation)
	}
}
