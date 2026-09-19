package proxy

import (
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/limits"
)

// rateSource adapts the current runtime's rate limiters to the cluster
// layer. It always reads the live generation, so a reload does not detach
// the cluster from the limiters.
type rateSource struct{ s *Server }

func (r rateSource) Flush(limit int) map[string]map[string]float64 {
	rt := r.s.rt.Load()
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

// Decide is the owner side of an exact policy: the local limiter answers
// for the peer that asked.
func (r rateSource) Decide(policy, key string, n float64) (allowed, ok bool) {
	rt := r.s.rt.Load()
	rl, ok := rt.rateLimits[policy]
	if !ok || rl.cfg.Distributed != "exact" {
		return false, false
	}
	allowed = rl.lim.AllowFallback(key, "", n)
	if allowed {
		rl.allowed.Add(1)
	} else {
		rl.denied.Add(1)
	}
	return allowed, true
}

func (r rateSource) Report(peer, policy string, reports []limits.PeerReport) {
	rt := r.s.rt.Load()
	if rl, ok := rt.rateLimits[policy]; ok && rl.cfg.Distributed != "exact" {
		rl.lim.ReportPeer(peer, reports)
	}
}

// Cluster returns the cluster node, or nil when clustering is not
// configured.
func (s *Server) Cluster() *cluster.Node { return s.cluster.Load() }
