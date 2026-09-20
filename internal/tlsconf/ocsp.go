package tlsconf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/rom/xproxy/internal/config"
)

// staple is one fetched OCSP response.
type staple struct {
	der        []byte
	status     string // good, revoked, unknown
	thisUpdate time.Time
	nextUpdate time.Time
	fetched    time.Time
	responder  string
	err        string
}

// OCSPStatus is the management view of one certificate's staple.
type OCSPStatus struct {
	Status     string    `json:"status"` // good, revoked, unknown, error, none, disabled
	Responder  string    `json:"responder,omitempty"`
	ThisUpdate time.Time `json:"this_update,omitempty"`
	NextUpdate time.Time `json:"next_update,omitempty"`
	Fetched    time.Time `json:"fetched,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// stapler fetches and refreshes OCSP responses for the certificates a
// Reloadable serves, file and managed alike, and hands the current one
// to the handshake. It never blocks a handshake: a missing or stale
// staple means the handshake goes out without one (unless required),
// and fetching happens in its own goroutine.
type stapler struct {
	cfg    config.OCSPStapling
	client *http.Client
	log    *slog.Logger
	certs  func() []tls.Certificate

	mu      sync.RWMutex
	staples map[[32]byte]*staple

	stop chan struct{}
	wg   sync.WaitGroup
	once sync.Once
	kick chan struct{}
}

func newStapler(cfg config.OCSPStapling, certs func() []tls.Certificate, log *slog.Logger) *stapler {
	return &stapler{cfg: cfg, certs: certs, log: log, staples: map[[32]byte]*staple{}, stop: make(chan struct{}), kick: make(chan struct{}, 1),
		client: &http.Client{Timeout: cfg.Timeout.D(), Transport: &http.Transport{Proxy: nil, MaxIdleConns: 2, DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") }}}
}

func leafKey(c *tls.Certificate) ([32]byte, bool) {
	if c == nil || len(c.Certificate) == 0 {
		return [32]byte{}, false
	}
	return sha256.Sum256(c.Certificate[0]), true
}

// start runs the refresh loop; the first fetch happens at once.
func (s *stapler) start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.refreshAll()
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				s.refreshAll()
			case <-s.kick:
				s.refreshAll()
			}
		}
	}()
}

// wake asks for a refresh pass soon (after a certificate reload).
func (s *stapler) wake() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *stapler) close() {
	s.once.Do(func() { close(s.stop) })
	s.wg.Wait()
}

// refreshAll fetches for every certificate whose staple is missing, past
// half its validity, older than refresh, or failed.
func (s *stapler) refreshAll() {
	now := time.Now()
	for _, c := range s.certs() {
		c := c
		key, ok := leafKey(&c)
		if !ok {
			continue
		}
		// Decide on a copy of the current entry; the map and its entries
		// are only touched under the lock.
		s.mu.RLock()
		var cur staple
		have := false
		if st := s.staples[key]; st != nil {
			cur, have = *st, true
		}
		s.mu.RUnlock()
		if have && cur.err == "" && !s.due(&cur, now) {
			continue
		}
		if have && cur.err != "" && now.Sub(cur.fetched) < time.Minute {
			continue // failed recently: back off to the next tick
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout.D())
		res := s.fetch(ctx, &c)
		cancel()
		s.mu.Lock()
		if st := s.staples[key]; res.err != "" && st != nil && len(st.der) > 0 && now.Before(st.nextUpdate) {
			// Keep serving the still valid staple; remember the failure.
			// The condition is "we still hold a response that has not
			// expired", not "this is the first failure": with the retry
			// backoff a minute long, the old test dropped the staple two
			// minutes into a responder outage, which is exactly when a
			// must-staple certificate needs it.
			st.err = res.err
			st.fetched = now
		} else {
			s.staples[key] = res
		}
		// Log from a copy: once stored, the entry belongs to the map and
		// may be updated by a later pass.
		logged := *res
		s.mu.Unlock()
		if logged.err != "" {
			s.log.Warn("ocsp fetch failed", "responder", logged.responder, "err", logged.err)
		} else if logged.status != "good" {
			s.log.Error("ocsp status is not good", "responder", logged.responder, "status", logged.status)
		}
	}
}

func (s *stapler) due(st *staple, now time.Time) bool {
	if now.After(st.nextUpdate) {
		return true
	}
	if !st.nextUpdate.IsZero() && now.After(st.thisUpdate.Add(st.nextUpdate.Sub(st.thisUpdate)/2)) {
		return true
	}
	return now.Sub(st.fetched) >= s.cfg.Refresh.D()
}

// fetch performs one OCSP request for the leaf against its issuer, which
// must be the next certificate in the chain.
func (s *stapler) fetch(ctx context.Context, c *tls.Certificate) *staple {
	now := time.Now()
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return &staple{fetched: now, err: "leaf: " + err.Error()}
		}
	}
	if len(leaf.OCSPServer) == 0 {
		return &staple{fetched: now, status: "none", err: "certificate names no OCSP responder"}
	}
	if len(c.Certificate) < 2 {
		return &staple{fetched: now, responder: leaf.OCSPServer[0], err: "issuer certificate missing from the chain file"}
	}
	issuer, err := x509.ParseCertificate(c.Certificate[1])
	if err != nil {
		return &staple{fetched: now, responder: leaf.OCSPServer[0], err: "issuer: " + err.Error()}
	}
	req, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return &staple{fetched: now, responder: leaf.OCSPServer[0], err: "request: " + err.Error()}
	}
	responder := leaf.OCSPServer[0]
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, responder, bytes.NewReader(req))
	if err != nil {
		return &staple{fetched: now, responder: responder, err: err.Error()}
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return &staple{fetched: now, responder: responder, err: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &staple{fetched: now, responder: responder, err: fmt.Sprintf("responder answered HTTP %d", resp.StatusCode)}
	}
	der, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return &staple{fetched: now, responder: responder, err: err.Error()}
	}
	parsed, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return &staple{fetched: now, responder: responder, err: "response: " + err.Error()}
	}
	st := &staple{der: der, thisUpdate: parsed.ThisUpdate, nextUpdate: parsed.NextUpdate, fetched: now, responder: responder}
	switch parsed.Status {
	case ocsp.Good:
		st.status = "good"
	case ocsp.Revoked:
		st.status = "revoked"
	default:
		st.status = "unknown"
		st.err = "responder does not know the certificate"
	}
	if st.nextUpdate.IsZero() {
		st.nextUpdate = now.Add(s.cfg.Refresh.D())
	}
	return st
}

// current returns the staple bytes to send for c, or nil.
func (s *stapler) current(c *tls.Certificate) []byte {
	key, ok := leafKey(c)
	if !ok {
		return nil
	}
	s.mu.RLock()
	st := s.staples[key]
	s.mu.RUnlock()
	if st == nil || len(st.der) == 0 || time.Now().After(st.nextUpdate) {
		return nil
	}
	return st.der
}

// status reports the staple state of c.
func (s *stapler) status(c *tls.Certificate) OCSPStatus {
	key, ok := leafKey(c)
	if !ok {
		return OCSPStatus{Status: "none"}
	}
	s.mu.RLock()
	st := s.staples[key]
	s.mu.RUnlock()
	if st == nil {
		return OCSPStatus{Status: "pending"}
	}
	out := OCSPStatus{Status: st.status, Responder: st.responder, ThisUpdate: st.thisUpdate, NextUpdate: st.nextUpdate, Fetched: st.fetched, Error: st.err}
	if out.Status == "" {
		out.Status = "error"
	}
	return out
}
