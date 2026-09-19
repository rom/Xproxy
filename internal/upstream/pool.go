package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/tlsconf"
)

// Pool is a named, load balanced set of endpoints with a shared transport.
type Pool struct {
	Name      string
	Cfg       *config.Upstream
	Transport *http.Transport
	// h2c carries HTTP/2 without TLS when the upstream sets h2c.
	h2c    *http.Transport
	Scheme string

	endpoints []*Endpoint
	bal       balancer
	aff       *affinity
	// clientCert is the reloadable mTLS client certificate, or nil.
	clientCert *tlsconf.ClientReloadable
	log        *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
	now    func() time.Time
	// hcSem bounds health probes in flight (HealthCheck.MaxConcurrent).
	hcSem chan struct{}
	// hcTransport carries probes: the pool transport with keep_alive, or a
	// dedicated one that opens a fresh connection per probe.
	hcTransport *http.Transport
	// breaker, gate and canary are nil when not configured.
	breaker *Breaker
	gate    *Gate
	canary  *canaryState
}

// Breaker returns the circuit breaker, or nil.
func (p *Pool) Breaker() *Breaker { return p.breaker }

// Gate returns the concurrency gate, or nil.
func (p *Pool) Gate() *Gate { return p.gate }

// Status returns the pool level management view.
func (p *Pool) Status() PoolStatus {
	now := p.now()
	st := PoolStatus{Name: p.Name, Balancer: p.Cfg.Balancer, Endpoints: len(p.endpoints)}
	for _, e := range p.endpoints {
		if e.Available(now) {
			st.Available++
		}
		st.Active += e.active.Load()
	}
	if p.breaker != nil {
		c := p.breaker.Status()
		st.Circuit = &c
	}
	if p.gate != nil {
		q := p.gate.Status()
		st.Queue = &q
	}
	if c := p.canary; c != nil {
		st.Canary = &CanaryStatus{Header: c.header, Cookie: c.cookie, Percent: c.percent, Endpoints: c.count,
			Requests: c.requests.Load(), Fallbacks: c.fallbacks.Load()}
	}
	return st
}

// NewPool builds a pool from configuration. Call Start to begin health
// checks and Stop to release resources.
func NewPool(cfg *config.Upstream, log *slog.Logger) (*Pool, error) {
	p := &Pool{Name: cfg.Name, Cfg: cfg, Scheme: cfg.Scheme, log: log.With("upstream", cfg.Name), now: time.Now}
	for i, e := range cfg.Endpoints {
		ep := &Endpoint{Address: e.Address, Weight: e.Weight, Canary: e.Canary, index: i}
		// Without active checks every endpoint starts healthy. With checks,
		// endpoints start healthy too so that a restart does not drop all
		// traffic until the first probe; the first failed probe ejects.
		ep.healthy.Store(true)
		p.endpoints = append(p.endpoints, ep)
	}
	switch cfg.Balancer {
	case "weighted":
		p.bal = &weighted{}
	case "least_conn":
		p.bal = &leastConn{}
	case "hash":
		p.bal = newRing(p.endpoints)
	default:
		p.bal = &roundRobin{}
	}
	if cfg.CircuitBreaker != nil {
		p.breaker = newBreaker(cfg.CircuitBreaker, p.now)
	}
	if c := cfg.Canary; c != nil {
		cs := &canaryState{header: http.CanonicalHeaderKey(c.Header), cookie: c.Cookie, percent: c.Percent,
			fallback: c.Fallback == nil || *c.Fallback, values: map[string]bool{}}
		for _, v := range c.Values {
			cs.values[v] = true
		}
		for _, e := range p.endpoints {
			if e.Canary {
				cs.count++
			}
		}
		p.canary = cs
	}
	if cfg.MaxConcurrent > 0 {
		size, timeout := 0, time.Duration(0)
		if cfg.Queue != nil {
			size, timeout = cfg.Queue.Size, cfg.Queue.Timeout.D()
		}
		p.gate = newGate(cfg.MaxConcurrent, size, timeout)
	}
	if cfg.Affinity != nil {
		a, err := newAffinity(cfg.Affinity.CookieName, cfg.Affinity.TTL.D(), cfg.Affinity.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", cfg.Name, err)
		}
		p.aff = a
	}
	var tc *tls.Config
	if cfg.Scheme == "https" {
		var err error
		tc, p.clientCert, err = tlsconf.Client(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", cfg.Name, err)
		}
	}
	dialer := &net.Dialer{Timeout: cfg.Timeouts.Connect.D(), KeepAlive: 30 * time.Second}
	p.Transport = &http.Transport{
		Proxy:                  nil, // never honour HTTP_PROXY from the environment
		DialContext:            dialer.DialContext,
		TLSClientConfig:        tc,
		ForceAttemptHTTP2:      cfg.Scheme == "https",
		MaxIdleConns:           cfg.MaxIdleConnsPerHost * max(len(cfg.Endpoints), 1),
		MaxIdleConnsPerHost:    cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:        cfg.Timeouts.Idle.D(),
		TLSHandshakeTimeout:    cfg.Timeouts.Connect.D(),
		ResponseHeaderTimeout:  cfg.Timeouts.ResponseHeader.D(),
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true, // pass encodings through untouched
	}
	if cfg.H2C {
		// Prior knowledge HTTP/2 over plain TCP: the same transport
		// settings with only the unencrypted HTTP/2 protocol enabled.
		t := p.Transport.Clone()
		t.Protocols = new(http.Protocols)
		t.Protocols.SetUnencryptedHTTP2(true)
		t.HTTP2 = &http.HTTP2Config{SendPingTimeout: cfg.Timeouts.Connect.D(), PingTimeout: cfg.Timeouts.Connect.D()}
		p.h2c = t
	}
	if hc := cfg.HealthCheck; hc != nil {
		if hc.KeepAlive {
			p.hcTransport = p.Transport
		} else {
			t := p.Transport.Clone()
			t.DisableKeepAlives = true
			t.MaxIdleConns = 0
			t.MaxIdleConnsPerHost = 0
			p.hcTransport = t
		}
	}
	return p, nil
}

// Start launches active health checking if configured.
func (p *Pool) Start() {
	if p.Cfg.HealthCheck == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.hcSem = make(chan struct{}, max(p.Cfg.HealthCheck.MaxConcurrent, 1))
	for _, e := range p.endpoints {
		p.wg.Add(1)
		go p.healthLoop(ctx, e)
	}
}

// StopChecks ends health checking without touching the transport, so a
// superseded generation stops probing at once while its in-flight requests
// finish.
func (p *Pool) StopChecks() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}

// Stop ends health checks and closes idle connections.
func (p *Pool) Stop() {
	p.StopChecks()
	p.Transport.CloseIdleConnections()
	if p.h2c != nil {
		p.h2c.CloseIdleConnections()
	}
}

// RoundTripper is the transport requests use: HTTP/2 cleartext when the
// upstream sets h2c, the ordinary transport otherwise.
func (p *Pool) RoundTripper() http.RoundTripper {
	if p.h2c != nil {
		return p.h2c
	}
	return p.Transport
}

// ReloadClientCertificate re-reads the upstream client certificate, if
// any, and drops idle connections so new ones present it.
func (p *Pool) ReloadClientCertificate() error {
	if p.clientCert == nil {
		return nil
	}
	if err := p.clientCert.Load(); err != nil {
		return fmt.Errorf("upstream %s: %w", p.Name, err)
	}
	p.Transport.CloseIdleConnections()
	return nil
}

// Endpoints returns the endpoints (read only).
func (p *Pool) Endpoints() []*Endpoint { return p.endpoints }

// AffinityCookie returns the affinity cookie name, or "".
func (p *Pool) AffinityCookie() string {
	if p.aff == nil {
		return ""
	}
	return p.aff.cookie
}

// Pick selects an endpoint. hashKey feeds the hash balancer; cookie is the
// affinity cookie value from the request, if any. exclude lists endpoints
// already tried; mode applies the canary policy (CanaryAny without one).
// The second result is a fresh cookie value to set on the response, or
// "" when none is needed.
func (p *Pool) Pick(hashKey, cookie string, exclude map[*Endpoint]bool, mode CanaryMode) (*Endpoint, string) {
	now := p.now()
	if p.aff != nil && cookie != "" {
		if i := p.aff.verify(cookie, now); i >= 0 && i < len(p.endpoints) {
			if e := p.endpoints[i]; available(e, exclude, now) {
				return e, ""
			}
		}
	}
	e := p.bal.pick(p.endpoints, hashKey, p.canaryExclude(mode, exclude), now)
	if e == nil && mode != CanaryAny && p.canary != nil && p.canary.fallback {
		// The selected side is empty: the other side takes the request.
		p.canary.fallbacks.Add(1)
		e = p.bal.pick(p.endpoints, hashKey, exclude, now)
	}
	if e == nil {
		return nil, ""
	}
	if e.Canary && p.canary != nil {
		p.canary.requests.Add(1)
	}
	if p.aff != nil {
		return e, p.aff.issue(e.index, now)
	}
	return e, ""
}

// Begin marks a request in flight on e.
func (p *Pool) Begin(e *Endpoint) {
	e.active.Add(1)
	e.requests.Add(1)
}

// End records the outcome of a request on e. A failure is a transport level
// error or a 5xx if the outlier policy counts those.
func (p *Pool) End(e *Endpoint, failed bool) {
	e.active.Add(-1)
	if !failed {
		e.failures.Store(0)
		return
	}
	e.errors.Add(1)
	oe := p.Cfg.OutlierEjection
	if oe == nil {
		return
	}
	if n := e.failures.Add(1); n >= int64(oe.ConsecutiveFailures) {
		if p.canEject() {
			e.ejections.Add(1)
			// Exponential back-off: base * number of ejections, capped.
			mult := int64(min(e.ejections.Load(), 10)) //nolint:gosec // capped at 10
			until := p.now().Add(oe.BaseEjectionTime.D() * time.Duration(mult))
			e.ejectedNS.Store(until.UnixNano())
			e.failures.Store(0)
			p.log.Warn("endpoint ejected", "endpoint", e.Address, "until", until)
		}
	}
}

// canEject checks the max_ejection_percent bound.
func (p *Pool) canEject() bool {
	oe := p.Cfg.OutlierEjection
	now := p.now()
	ejected := 0
	for _, e := range p.endpoints {
		if e.ejectedNS.Load() > now.UnixNano() {
			ejected++
		}
	}
	return (ejected+1)*100 <= oe.MaxEjectionPercent*len(p.endpoints) || oe.MaxEjectionPercent == 100
}

// Stats returns a snapshot for the management API.
func (p *Pool) Stats() []Stats {
	now := p.now()
	out := make([]Stats, 0, len(p.endpoints))
	for _, e := range p.endpoints {
		out = append(out, e.stats(now))
	}
	return out
}
