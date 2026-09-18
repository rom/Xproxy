package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"strconv"

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
	var query []byte
	switch r.Method {
	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" || len(b64) > 8192 {
			st.denied = "doh:query"
			s.plainStatus(rw, r, http.StatusBadRequest)
			return
		}
		q, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			st.denied = "doh:base64"
			s.plainStatus(rw, r, http.StatusBadRequest)
			return
		}
		query = q
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			st.denied = "doh:content_type"
			s.plainStatus(rw, r, http.StatusUnsupportedMediaType)
			return
		}
		q, err := io.ReadAll(io.LimitReader(r.Body, dns.MaxMessage+1))
		if err != nil || len(q) > dns.MaxMessage {
			st.denied = "doh:body"
			s.plainStatus(rw, r, http.StatusBadRequest)
			return
		}
		query = q
	default:
		rw.Header().Set("Allow", "GET, POST")
		s.plainStatus(rw, r, http.StatusMethodNotAllowed)
		return
	}
	if len(query) < 12 {
		st.denied = "doh:short"
		s.plainStatus(rw, r, http.StatusBadRequest)
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
	h := rw.Header()
	h.Set("Content-Type", "application/dns-message")
	h.Set("X-Content-Type-Options", "nosniff")
	maxAge := 0
	if rh, err := dns.ParseHeader(resp); err == nil {
		if _, qEnd, err := dns.ParseQuestion(resp); err == nil {
			if ttl, ok := dns.MinTTL(resp, qEnd, rh); ok {
				maxAge = int(ttl)
			}
		}
		st.extra = append(st.extra, "dns_rcode", rh.Rcode())
	}
	h.Set("Cache-Control", "max-age="+strconv.Itoa(maxAge))
	h.Set("Content-Length", strconv.Itoa(len(resp)))
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(resp)
}
