// Package upstream manages pools of backend endpoints: load balancing,
// active and passive health checking and session affinity.
package upstream

import (
	"sync/atomic"
	"time"
)

// Endpoint is one backend address with its live state.
type Endpoint struct {
	Address string
	Weight  int
	index   int

	healthy   atomic.Bool  // active health check result
	ejectedNS atomic.Int64 // passive ejection expiry, unix nanos; 0 = none
	active    atomic.Int64 // in-flight requests
	failures  atomic.Int64 // consecutive passive failures
	requests  atomic.Uint64
	errors    atomic.Uint64
	ejections atomic.Uint64
	// smooth weighted round robin state, guarded by pool.mu
	current int
}

// Available reports whether the endpoint may receive traffic now.
func (e *Endpoint) Available(now time.Time) bool {
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

// Active returns in-flight requests.
func (e *Endpoint) Active() int64 { return e.active.Load() }

// Stats is a snapshot of an endpoint for the management API.
type Stats struct {
	Address   string `json:"address"`
	Weight    int    `json:"weight"`
	Healthy   bool   `json:"healthy"`
	Ejected   bool   `json:"ejected"`
	Active    int64  `json:"active"`
	Requests  uint64 `json:"requests"`
	Errors    uint64 `json:"errors"`
	Ejections uint64 `json:"ejections"`
}

func (e *Endpoint) stats(now time.Time) Stats {
	return Stats{
		Address:   e.Address,
		Weight:    e.Weight,
		Healthy:   e.healthy.Load(),
		Ejected:   e.ejectedNS.Load() > now.UnixNano(),
		Active:    e.active.Load(),
		Requests:  e.requests.Load(),
		Errors:    e.errors.Load(),
		Ejections: e.ejections.Load(),
	}
}
