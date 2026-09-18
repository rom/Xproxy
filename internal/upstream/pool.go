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
	Scheme    string

	endpoints []*Endpoint
	bal       balancer
	aff       *affinity
	log       *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
	now    func() time.Time
}

// NewPool builds a pool from configuration. Call Start to begin health
// checks and Stop to release resources.
func NewPool(cfg *config.Upstream, log *slog.Logger) (*Pool, error) {
	p := &Pool{Name: cfg.Name, Cfg: cfg, Scheme: cfg.Scheme, log: log.With("upstream", cfg.Name), now: time.Now}
	for i, e := range cfg.Endpoints {
		ep := &Endpoint{Address: e.Address, Weight: e.Weight, index: i}
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
		tc, err = tlsconf.Client(cfg.TLS)
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
	return p, nil
}

// Start launches active health checking if configured.
func (p *Pool) Start() {
	if p.Cfg.HealthCheck == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	for _, e := range p.endpoints {
		p.wg.Add(1)
		go p.healthLoop(ctx, e)
	}
}

// Stop ends health checks and closes idle connections.
func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	p.Transport.CloseIdleConnections()
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
// already tried. The second result is a fresh cookie value to set on the
// response, or "" when none is needed.
func (p *Pool) Pick(hashKey, cookie string, exclude map[*Endpoint]bool) (*Endpoint, string) {
	now := p.now()
	if p.aff != nil && cookie != "" {
		if i := p.aff.verify(cookie, now); i >= 0 && i < len(p.endpoints) {
			if e := p.endpoints[i]; available(e, exclude, now) {
				return e, ""
			}
		}
	}
	e := p.bal.pick(p.endpoints, hashKey, exclude, now)
	if e == nil {
		return nil, ""
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
