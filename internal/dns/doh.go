package dns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// ALPN identifiers on an encrypted dns listener.
const (
	ALPNDoT  = "dot"
	ALPNH2   = "h2"
	ALPNHTTP = "http/1.1"
)

// DefaultDoHPath is the RFC 8484 path served when none is configured.
const DefaultDoHPath = "/dns-query"

// DoHRequest extracts the DNS query from an RFC 8484 request: GET with
// the base64url query in the dns parameter or POST with an
// application/dns-message body. On failure it returns the HTTP status to
// answer and a short reason for the log.
func DoHRequest(r *http.Request) (query []byte, status int, reason string) {
	switch r.Method {
	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" || len(b64) > 8192 {
			return nil, http.StatusBadRequest, "doh:query"
		}
		q, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			return nil, http.StatusBadRequest, "doh:base64"
		}
		query = q
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, http.StatusUnsupportedMediaType, "doh:content_type"
		}
		q, err := io.ReadAll(io.LimitReader(r.Body, MaxMessage+1))
		if err != nil || len(q) > MaxMessage {
			return nil, http.StatusBadRequest, "doh:body"
		}
		query = q
	default:
		return nil, http.StatusMethodNotAllowed, "doh:method"
	}
	if len(query) < headerLen {
		return nil, http.StatusBadRequest, "doh:short"
	}
	return query, 0, ""
}

// WriteDoH writes a DNS response as application/dns-message with
// Cache-Control from the smallest TTL. It returns the rcode for the log.
func WriteDoH(w http.ResponseWriter, resp []byte) int {
	h := w.Header()
	h.Set("Content-Type", "application/dns-message")
	h.Set("X-Content-Type-Options", "nosniff")
	maxAge, rcode := 0, -1
	if rh, err := ParseHeader(resp); err == nil {
		rcode = rh.Rcode()
		if _, qEnd, err := ParseQuestion(resp); err == nil {
			if ttl, ok := MinTTL(resp, qEnd, rh); ok {
				maxAge = int(ttl)
			}
		}
	}
	h.Set("Cache-Control", "max-age="+strconv.Itoa(maxAge))
	h.Set("Content-Length", strconv.Itoa(len(resp)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
	return rcode
}

// ServeHTTP answers DoH on the listener's own TLS port (RFC 8484): only
// the configured path, GET and POST, the client taken from the
// connection.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := s.DoHPath
	if path == "" {
		path = DefaultDoHPath
	}
	if r.URL.Path != path {
		http.NotFound(w, r)
		return
	}
	// Admit the request before reading its body. In particular, an HTTP/2
	// client must not be able to occupy unbounded handlers with partial POSTs
	// while bypassing the listener's in-flight limit.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.drop()
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	query, status, _ := DoHRequest(r)
	if status != 0 {
		if status == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", "GET, POST")
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	var client netip.Addr
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		client = ap.Addr().Unmap()
	}
	resp := s.handle(query, client, true, "doh")
	if resp == nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	WriteDoH(w, resp)
}

// chanListener hands connections the TLS demultiplexer classified as
// HTTP to the DoH http.Server.
type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	once sync.Once
	done chan struct{}
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{ch: make(chan net.Conn), addr: addr, done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

// offer hands a connection to the http server, or closes it when the
// server is gone.
func (l *chanListener) offer(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		_ = c.Close()
	}
}

// demux classifies an accepted connection of an encrypted listener by
// its negotiated ALPN: DoT (or no ALPN) is served as DNS over the
// stream, HTTP/2 and HTTP/1.1 go to the DoH server. It returns false
// when the connection was handed over.
func (s *Server) demux(c net.Conn) (serveDNS bool) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		_ = tc.Close()
		return false
	}
	switch tc.ConnectionState().NegotiatedProtocol {
	case ALPNH2, ALPNHTTP:
		if s.doh == nil {
			_ = tc.Close()
			return false
		}
		s.doh.offer(tc)
		return false
	default:
		return true
	}
}
