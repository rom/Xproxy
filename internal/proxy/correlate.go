package proxy

import (
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/correlate"
)

// The cross-listener window the engine owns.
//
// It lives here for the same reason the device inventory does: it is about
// an actor across every listener of this process, and a listener kind
// cannot hold something that spans its siblings. The engine has the
// process, so the engine has the window.
//
// What the engine adds on top of internal/correlate is the two things that
// need the process: the facts worth sharing go to the cluster peers, and a
// peer's facts come back in. That is not a nicety -- on this design the
// bastion is xgate and the plant is xot, two processes, so a pivot from
// one into the other is invisible to both of them alone.

// eventCorrelate is the cluster event kind carrying a fact.
//
// The key is class, listener kind and address, joined by a character that
// cannot appear in any of them; the route field carries the identity where
// the protocol had one. The detail does not cross: it is a peer's string,
// it is only ever printed, and a cluster message is not the place to carry
// one.
const eventCorrelate = "correlate"

// correlationShared are the classes worth a cluster message.
//
// Not every fact: a session per device per listener across an estate would
// be a gossip flood for something each daemon can already see about its
// own listeners. These four are the ones whose *other half* is in another
// daemon -- somebody logged in over there, the clock moved over there, an
// engineering operation happened over there, a credential failed over
// there.
func correlationShared(c correlate.Class) bool {
	switch c {
	case correlate.ClassGateSession, correlate.ClassTimeStep,
		correlate.ClassEngineering, correlate.ClassCredential:
		return true
	}
	return false
}

// newCorrelation builds the window from the configuration.
func newCorrelation(c *config.Config) *correlate.Store {
	if !c.CorrelationEnabled() {
		// A nil store is usable: every kind writes facts to it without
		// checking, and it answers nothing.
		return nil
	}
	var b correlate.Bounds
	if cc := c.Correlation; cc != nil {
		b = correlate.Bounds{
			Window:    time.Duration(cc.Window),
			MaxActors: cc.MaxActors,
			MaxFacts:  cc.MaxFacts,
		}
	}
	return correlate.New(b)
}

// Correlate implements Host: the cross-listener window, or nil when the
// configuration turned it off.
func (s *Server) Correlate() *correlate.Store { return s.correlation }

// ObserveFact implements Host: record what a listener saw about an
// address, and -- for the classes whose other half lives in a sibling
// daemon -- tell the cluster.
//
// A kind calls this rather than the store directly so that it does not
// have to know whether this estate has a cluster, which is a deployment
// question and not a protocol one.
func (s *Server) ObserveFact(addr netip.Addr, f correlate.Fact) {
	if s.correlation == nil {
		return
	}
	if addr.IsValid() {
		s.correlation.Observe(addr, f)
	} else {
		s.correlation.ObserveEstate(f)
	}
	if !s.shareFacts || !correlationShared(f.Class) {
		return
	}
	s.publishEvent(cluster.Event{
		Kind:  eventCorrelate,
		Key:   correlationKey(addr, f),
		Route: f.Identity,
		// The fact is worth as much as the window is long and no longer.
		Until: time.Now().Add(s.correlation.Window()),
	})
}

// correlationKey encodes a fact for a cluster message.
func correlationKey(addr netip.Addr, f correlate.Fact) string {
	a := ""
	if addr.IsValid() {
		a = addr.String()
	}
	return string(f.Class) + "\x1f" + f.Kind + "\x1f" + a
}

// applyCorrelationEvent merges a peer's fact. It reports whether the event
// was one, so the caller can hand everything else on.
//
// A peer is trusted completely by design (the cluster socket's permissions
// and the user id the kernel reports are the boundary), but a malformed key
// is still refused rather than filed under something nothing can ask for --
// a fact with an empty class or a class this build does not have would sit
// in the window unreadable.
func (s *Server) applyCorrelationEvent(e cluster.Event, peer string) bool {
	if e.Kind != eventCorrelate {
		return false
	}
	if s.correlation == nil {
		return true
	}
	parts := strings.Split(e.Key, "\x1f")
	if len(parts) != 3 {
		s.stats.CorrelationRefused.Add(1)
		return true
	}
	class := correlate.Class(parts[0])
	known := false
	for _, c := range correlate.Classes() {
		if c == class {
			known = true
			break
		}
	}
	if !known {
		s.stats.CorrelationRefused.Add(1)
		return true
	}
	f := correlate.Fact{Class: class, Kind: parts[1], Listener: peer, Identity: e.Route}
	if parts[2] == "" {
		// A fact about the estate rather than about an address: the clock
		// moved on a sibling, which is the left half of a chain whose
		// right half arrives here.
		f.Remote = true
		s.correlation.ObserveEstate(f)
		s.stats.CorrelationMerged.Add(1)
		return true
	}
	addr, err := netip.ParseAddr(parts[2])
	if err != nil {
		s.stats.CorrelationRefused.Add(1)
		return true
	}
	s.correlation.Merge(addr, f)
	s.stats.CorrelationMerged.Add(1)
	return true
}
