// Package upstream manages pools of backend endpoints: load balancing,
// active and passive health checking and session affinity.
package upstream

import (
	"context"
	"math"
	"sync/atomic"
	"time"
)

// Endpoint is one backend address with its live state.
type Endpoint struct {
	Address string
	Weight  int
	Canary  bool
	// Discovered marks an endpoint that came from DNS discovery.
	Discovered bool
	// socket is the Unix domain socket path this endpoint dials, and
	// urlHost the synthetic authority it wears in a URL; both empty for
	// an ordinary network endpoint. See unixsocket.go.
	socket  string
	urlHost string
	index   int
	// slowStart is the pool's ramp; readyNS is when the current ramp
	// started (0: at full share).
	slowStart time.Duration
	readyNS   atomic.Int64
	// cancel stops the endpoint's health loop when discovery removes it.
	cancel context.CancelFunc

	healthy atomic.Bool // active health check result
	// draining is an operator's decision to stop sending new work here
	// while what is already running finishes. It is not a health
	// result and is never set by a probe; see drain.go.
	draining atomic.Bool
	// maxActive bounds the requests or connections in flight here at
	// once; 0 is no bound. Set when the endpoint is built and not
	// changed afterwards, so it needs no atomic.
	maxActive int64
	ejectedNS atomic.Int64 // passive ejection expiry, unix nanos; 0 = none
	active    atomic.Int64 // in-flight requests
	failures  atomic.Int64 // consecutive passive failures
	requests  atomic.Uint64
	errors    atomic.Uint64
	ejections atomic.Uint64
	// latency is the smoothed time to first byte in nanoseconds (float
	// bits), samples the responses since the endpoint last became
	// available and latencyEjections the ejections it caused.
	latency          atomic.Uint64
	latencySamples   atomic.Int64
	latencyEjections atomic.Uint64
	// smooth weighted round robin state, guarded by pool.mu
	current int
}

// Available reports whether the endpoint may receive traffic now.
func (e *Endpoint) Available(now time.Time) bool {
	// Draining is checked first because it is a decision rather than a
	// measurement: a healthy endpoint somebody is about to patch must
	// not be picked because it is still answering.
	if e.draining.Load() {
		return false
	}
	if !e.healthy.Load() {
		return false
	}
	if until := e.ejectedNS.Load(); until != 0 {
		if now.UnixNano() < until {
			return false
		}
		// Ejection expired: give the endpoint another chance.
		e.ejectedNS.CompareAndSwap(until, 0)
	}
	return true
}

// Healthy reports the active health check state.
func (e *Endpoint) Healthy() bool { return e.healthy.Load() }

// ramp returns the endpoint's slow start share in (0, 1]: 1 when not
// ramping, otherwise from 0.1 at the start of the ramp to 1 at its end.
func (e *Endpoint) ramp(now time.Time) float64 {
	if e.slowStart <= 0 {
		return 1
	}
	ready := e.readyNS.Load()
	if ready == 0 {
		return 1
	}
	elapsed := time.Duration(now.UnixNano() - ready)
	if elapsed >= e.slowStart {
		e.readyNS.CompareAndSwap(ready, 0)
		return 1
	}
	if elapsed < 0 {
		return 0.1
	}
	return 0.1 + 0.9*float64(elapsed)/float64(e.slowStart)
}

// startRamp begins a slow start ramp at now (no-op without slow start).
func (e *Endpoint) startRamp(now time.Time) {
	if e.slowStart > 0 {
		e.readyNS.Store(now.UnixNano())
	}
}

// effectiveWeight is the weight scaled by the slow start ramp, at least 1.
func (e *Endpoint) effectiveWeight(now time.Time) int {
	w := int(float64(e.Weight) * e.ramp(now))
	return max(w, 1)
}

// Active returns in-flight requests.
func (e *Endpoint) Active() int64 { return e.active.Load() }

// Stats is a snapshot of an endpoint for the management API.
type Stats struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
	Canary  bool   `json:"canary,omitempty"`
	Healthy bool   `json:"healthy"`
	Ejected bool   `json:"ejected"`
	// Draining is an operator's decision, not a health result: no new
	// work, and what is running finishes.
	Draining bool `json:"draining,omitempty"`
	// MaxActive is the endpoint's own concurrency bound, 0 for none.
	MaxActive int64  `json:"max_active,omitempty"`
	Active    int64  `json:"active"`
	Requests  uint64 `json:"requests"`
	Errors    uint64 `json:"errors"`
	Ejections uint64 `json:"ejections"`
	// Discovered endpoints came from DNS; Ramp is the slow start share,
	// 1 at full weight.
	Discovered bool    `json:"discovered,omitempty"`
	Ramp       float64 `json:"ramp"`
	// LatencyMS is the smoothed time to first byte; LatencyEjections
	// counts ejections for latency.
	LatencyMS        float64 `json:"latency_ms"`
	LatencyEjections uint64  `json:"latency_ejections"`
}

// latencyNS returns the smoothed latency in nanoseconds (0 without a
// sample).
func (e *Endpoint) latencyNS() float64 { return math.Float64frombits(e.latency.Load()) }

// observeLatency folds one sample into the moving average (factor 0.2)
// and returns the new average and sample count.
func (e *Endpoint) observeLatency(d time.Duration) (float64, int64) {
	const alpha = 0.2
	for {
		old := e.latency.Load()
		cur := math.Float64frombits(old)
		next := float64(d)
		if cur > 0 {
			next = cur + alpha*(float64(d)-cur)
		}
		if e.latency.CompareAndSwap(old, math.Float64bits(next)) {
			return next, e.latencySamples.Add(1)
		}
	}
}

// resetLatency forgets the average, for an endpoint that becomes
// available again.
func (e *Endpoint) resetLatency() {
	e.latency.Store(0)
	e.latencySamples.Store(0)
}

func (e *Endpoint) stats(now time.Time) Stats {
	return Stats{
		Address:          e.Address,
		Weight:           e.Weight,
		Canary:           e.Canary,
		Discovered:       e.Discovered,
		Ramp:             e.ramp(now),
		Healthy:          e.healthy.Load(),
		Draining:         e.draining.Load(),
		MaxActive:        e.maxActive,
		Ejected:          e.ejectedNS.Load() > now.UnixNano(),
		Active:           e.active.Load(),
		Requests:         e.requests.Load(),
		Errors:           e.errors.Load(),
		Ejections:        e.ejections.Load(),
		LatencyMS:        math.Round(e.latencyNS()/1e3) / 1e3,
		LatencyEjections: e.latencyEjections.Load(),
	}
}
