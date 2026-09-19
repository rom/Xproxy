package upstream

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// MaxProbesInFlight bounds health probes across every pool of the process,
// on top of the per pool bound. With ten thousand endpoints the per pool
// bound alone still allows thousands of simultaneous probes when a backend
// stalls; this keeps descriptors and goroutines in check.
var MaxProbesInFlight = 512

var globalProbes = make(chan struct{}, MaxProbesInFlight)

// healthLoop probes one endpoint until ctx is cancelled. Probes are jittered
// so that a fleet of proxies does not hit a backend in lock-step.
func (p *Pool) healthLoop(ctx context.Context, e *Endpoint) {
	defer p.wg.Done()
	hc := p.Cfg.HealthCheck
	var hcTransport http.RoundTripper = p.hcTransport
	if p.h2c != nil {
		hcTransport = p.h2c // probes share the h2c connection like requests
	}
	client := &http.Client{
		Transport: hcTransport,
		Timeout:   hc.Timeout.D(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := p.Scheme + "://" + e.Address + hc.Path
	if hc.Type == "grpc" {
		url = p.Scheme + "://" + e.Address
	}
	var ok, bad int
	// Initial jitter of up to one interval.
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(rand.Int64N(int64(hc.Interval.D())))): //nolint:gosec // jitter only, not security relevant
	}
	t := time.NewTicker(hc.Interval.D())
	defer t.Stop()
	for {
		// Bound probes in flight per pool: with thousands of endpoints the
		// jitter spreads them out on average, the semaphore caps the peaks.
		select {
		case p.hcSem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		select {
		case globalProbes <- struct{}{}:
		case <-ctx.Done():
			<-p.hcSem
			return
		}
		var healthy bool
		if hc.Type == "grpc" {
			healthy = p.probeGRPC(ctx, client, url)
		} else {
			healthy = p.probe(ctx, client, url)
		}
		<-globalProbes
		<-p.hcSem
		if healthy {
			bad = 0
			ok++
			if ok >= hc.HealthyThreshold && !e.healthy.Load() {
				e.startRamp(p.now())
				e.healthy.Store(true)
				p.log.Info("endpoint healthy", "endpoint", e.Address)
			}
		} else {
			ok = 0
			bad++
			if bad >= hc.UnhealthyThreshold && e.healthy.Load() {
				e.healthy.Store(false)
				p.log.Warn("endpoint unhealthy", "endpoint", e.Address)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Pool) probe(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "xproxy-health/1")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain a bounded amount so the connection can be reused.
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	for _, s := range p.Cfg.HealthCheck.ExpectedStatus {
		if resp.StatusCode == s {
			return true
		}
	}
	return false
}
