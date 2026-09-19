package proxy

import (
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/filter"
)

// Event kinds the server itself publishes and consumes. Filters use their
// own kinds (the OIDC filter shares revoked provider sessions).
const (
	eventHoneypotMark = "honeypot_mark"
	// eventTicketKeys carries a node's session ticket key fingerprint.
	eventTicketKeys     = "ticket_keys"
	eventHoneypotUnmark = "honeypot_unmark"
)

// eventBus is the filter.Events implementation handed to one runtime
// generation. Publishing goes to the cluster node (nothing happens
// without one); subscriptions are per generation and vanish with it, so a
// reload never leaves a stale filter receiving events.
type eventBus struct {
	s    *Server
	mu   sync.RWMutex
	subs map[string][]func(filter.Event)
}

func newEventBus(s *Server) *eventBus {
	return &eventBus{s: s, subs: map[string][]func(filter.Event){}}
}

func (b *eventBus) Publish(e filter.Event) {
	if b.s != nil {
		b.s.publishEvent(cluster.Event{Kind: e.Kind, Key: e.Key, Until: e.Until})
	}
}

func (b *eventBus) Subscribe(kind string, fn func(filter.Event)) {
	if kind == "" || fn == nil {
		return
	}
	b.mu.Lock()
	b.subs[kind] = append(b.subs[kind], fn)
	b.mu.Unlock()
}

// dispatch delivers a peer's event to the generation's subscribers and
// reports whether any existed.
func (b *eventBus) dispatch(e cluster.Event) bool {
	b.mu.RLock()
	fns := b.subs[e.Kind]
	b.mu.RUnlock()
	for _, fn := range fns {
		fn(filter.Event{Kind: e.Kind, Key: e.Key, Until: e.Until})
	}
	return len(fns) > 0
}

// publishEvent hands an event to the cluster node when there is one.
func (s *Server) publishEvent(e cluster.Event) {
	if node := s.cluster.Load(); node != nil {
		node.PublishEvent(e)
	}
}

// onClusterEvent applies an event received from a peer: the server's own
// kinds directly, every other kind through the live generation's bus.
func (s *Server) onClusterEvent(e cluster.Event, peer string) {
	now := time.Now()
	switch e.Kind {
	case eventTicketKeys:
		if s.tickets != nil && !s.tickets.PeerFingerprint(peer, e.Key) {
			s.ticketMismatch.Hit(s.logs.Error, "session ticket keys differ from a peer; tickets will not resume across these nodes (check the shared secret file and clocks)", "peer", peer, "peer_fingerprint", e.Key, "fingerprint", s.tickets.Fingerprint())
		}
	case eventHoneypotMark:
		ip, err := netip.ParseAddr(e.Key)
		if err != nil {
			return
		}
		s.marks.add(ip.Unmap(), "peer:"+peer+"/"+e.Route, e.Until.Sub(now), now)
	case eventHoneypotUnmark:
		ip, err := netip.ParseAddr(e.Key)
		if err != nil {
			return
		}
		s.marks.remove(ip.Unmap())
	default:
		if rt := s.rt.Load(); rt != nil && rt.events != nil {
			rt.events.dispatch(e)
		}
	}
}
