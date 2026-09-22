package http

import (
	"github.com/rom/xproxy/internal/limits"
)

// The cluster's view of this plane's rate limiters. It always reads the
// live generation, so a reload does not detach the cluster from the
// limiters. The engine owns the connection to the peers and routes
// these three questions here, because the limiters are the data plane's.

// Flush offers this node's consumption to the peers.
func (s *engine) Flush(limit int) map[string]map[string]float64 {
	rt := s.rt.Load()
	out := make(map[string]map[string]float64, len(rt.rateLimits))
	for name, rl := range rt.rateLimits {
		m := rl.lim.Flush(limit)
		// An exact policy's owner is authoritative; the other nodes'
		// consumption (fallback decisions only) is not gossiped.
		if len(m) > 0 && rl.cfg.Distributed != "exact" {
			out[name] = m
		}
	}
	return out
}

// Decide is the owner side of an exact policy: the local limiter
// answers for the peer that asked.
func (s *engine) Decide(policy, key string, n float64) (allowed, ok bool) {
	rt := s.rt.Load()
	rl, ok := rt.rateLimits[policy]
	if !ok || rl.cfg.Distributed != "exact" {
		return false, false
	}
	allowed = rl.lim.AllowFallback(key, nil, n)
	if allowed {
		rl.allowed.Add(1)
	} else {
		rl.denied.Add(1)
	}
	return allowed, true
}

// Report applies a peer's consumption to an approximate policy.
func (s *engine) Report(peer, policy string, reports []limits.PeerReport) {
	rt := s.rt.Load()
	if rl, ok := rt.rateLimits[policy]; ok && rl.cfg.Distributed != "exact" {
		rl.lim.ReportPeer(peer, reports)
	}
}
