package proxy

import (
	"net/http"

	"github.com/rom/xproxy/internal/dns"
)

// dnsServer finds a bound kind: dns listener by name.
func (s *Server) dnsServer(name string) *dns.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, bl := range s.listeners {
		if bl.dns != nil && bl.cfg.Name == name {
			return bl.dns
		}
	}
	return nil
}

// doh answers DNS over HTTPS (RFC 8484) on a route: GET with the query
// in the dns parameter (base64url, no padding) or POST with an
// application/dns-message body, handled by the named dns listener's
// policy and cache. The answer's smallest TTL becomes max-age.
func (s *Server) doh(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute) {
	srv := s.dnsServer(cr.cfg.DoH.Listener)
	if srv == nil {
		s.plainStatus(rw, r, http.StatusServiceUnavailable)
		return
	}
	query, status, reason := dns.DoHRequest(r)
	if status != 0 {
		if status == http.StatusMethodNotAllowed {
			rw.Header().Set("Allow", "GET, POST")
		} else {
			st.denied = reason
		}
		s.plainStatus(rw, r, status)
		return
	}
	resp := srv.Handle(query, st.clientIP, true)
	if resp == nil {
		// Dropped by policy (banned, rate limited, malformed): nothing
		// to say to the client beyond the status.
		st.denied = "doh:dropped"
		s.plainStatus(rw, r, http.StatusForbidden)
		return
	}
	if rcode := dns.WriteDoH(rw, resp); rcode >= 0 {
		st.extra = append(st.extra, "dns_rcode", rcode)
	}
}
