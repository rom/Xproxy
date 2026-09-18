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
		if m := rl.lim.Flush(limit); len(m) > 0 {
			out[name] = m
		}
	}
	return out
}

func (r rateSource) Report(peer, policy string, reports []limits.PeerReport) {
	rt := r.s.rt.Load()
	if rl, ok := rt.rateLimits[policy]; ok {
		rl.lim.ReportPeer(peer, reports)
	}
}

// Cluster returns the cluster node, or nil when clustering is not
// configured.
func (s *Server) Cluster() *cluster.Node { return s.cluster.Load() }
