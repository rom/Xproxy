package proxy

import (
	"github.com/rom/xproxy/internal/dns"
)

// DNS reports the status of every dns listener.
func (s *Server) DNS() []dns.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []dns.Status
	for _, bl := range s.listeners {
		if bl.dns != nil {
			out = append(out, bl.dns.Status())
		}
	}
	return out
}

// PurgeDNS empties the caches of every dns listener and returns the
// number of entries dropped.
func (s *Server) PurgeDNS() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, bl := range s.listeners {
		if bl.dns != nil {
			n += bl.dns.Purge()
		}
	}
	return n
}

// dnsTotals sums listener counters for the stats snapshot.
func (s *Server) dnsTotals(snap *Snapshot) {
	for _, st := range s.DNS() {
		snap.DNSQueries += st.Queries
		snap.DNSCacheHits += st.CacheHits
		snap.DNSBlocked += st.Blocked
		snap.DNSRefused += st.Refused
		snap.DNSDropped += st.Dropped
		snap.DNSServFail += st.ServFail
		snap.DNSCacheEntries += st.CacheEntries
		if t := st.Tunnel; t != nil {
			snap.DNSTunnels += t.Detections
			snap.DNSTunnelBlocked += t.Blocked
			snap.DNSTunnelTracked += t.Tracked
		}
	}
}
