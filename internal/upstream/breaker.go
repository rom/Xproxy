package upstream

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Circuit breaker states.
const (
	CircuitClosed   = "closed"
	CircuitOpen     = "open"
	CircuitHalfOpen = "half_open"
)

// ErrCircuitOpen is returned when the pool's circuit refuses a request.
var ErrCircuitOpen = errors.New("upstream circuit open")

// Breaker is a pool wide circuit breaker, distinct from per endpoint
// outlier ejection: ejection removes one bad endpoint from a healthy
// pool, the breaker stops sending to a pool that fails as a whole. Closed
// counts consecutive failures; at the threshold it opens for open_for
// (growing with each reopen, capped at ten times) and refuses at once;
// then it lets half_open_requests trials through, a success closes it
// and a failure reopens it.
type Breaker struct {
	cfg *config.CircuitBreaker
	now func() time.Time

	mu       sync.Mutex
	state    string
	failures int
	trials   int // half-open requests in flight
	until    time.Time
	openedAt time.Time
	reopens  int

	opens    atomic.Uint64
	rejected atomic.Uint64
}

// CircuitStatus is the management view.
type CircuitStatus struct {
	State      string    `json:"state"`
	Failures   int       `json:"failures"`
	Threshold  int       `json:"threshold"`
	OpenedAt   time.Time `json:"opened_at,omitempty"`
	Until      time.Time `json:"until,omitempty"`
	Opens      uint64    `json:"opens"`
	Rejected   uint64    `json:"rejected"`
	HalfOpenIn int       `json:"half_open_in_flight"`
}

func newBreaker(cfg *config.CircuitBreaker, now func() time.Time) *Breaker {
	return &Breaker{cfg: cfg, now: now, state: CircuitClosed}
}

// Allow decides whether a request may go to the pool. The returned done
// must be called with the outcome exactly once when it may; retryAfter
// says how long the circuit stays open when it may not.
func (b *Breaker) Allow() (done func(success bool), retryAfter time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	switch b.state {
	case CircuitOpen:
		if now.Before(b.until) {
			b.rejected.Add(1)
			return nil, b.until.Sub(now)
		}
		b.state = CircuitHalfOpen
		b.trials = 0
		fallthrough
	case CircuitHalfOpen:
		if b.trials >= b.cfg.HalfOpenRequests {
			b.rejected.Add(1)
			return nil, time.Second
		}
		b.trials++
		return b.trialDone, 0
	default:
		return b.closedDone, 0
	}
}

func (b *Breaker) closedDone(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != CircuitClosed {
		return // an outcome from before a transition
	}
	if success {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.cfg.ConsecutiveFailures {
		b.open()
	}
}

func (b *Breaker) trialDone(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != CircuitHalfOpen {
		return
	}
	b.trials--
	if success {
		b.state = CircuitClosed
		b.failures = 0
		b.reopens = 0
		return
	}
	b.open()
}

// open transitions to open with a back-off that grows per reopen.
func (b *Breaker) open() {
	b.reopens++
	mult := min(b.reopens, 10)
	b.state = CircuitOpen
	b.openedAt = b.now()
	b.until = b.openedAt.Add(b.cfg.OpenFor.D() * time.Duration(mult))
	b.failures = 0
	b.trials = 0
	b.opens.Add(1)
}

// Status returns the management view.
func (b *Breaker) Status() CircuitStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := CircuitStatus{State: b.state, Failures: b.failures, Threshold: b.cfg.ConsecutiveFailures,
		Opens: b.opens.Load(), Rejected: b.rejected.Load(), HalfOpenIn: b.trials}
	if b.state != CircuitClosed {
		st.OpenedAt, st.Until = b.openedAt, b.until
	}
	if b.state == CircuitOpen && !b.now().Before(b.until) {
		st.State = CircuitHalfOpen // will transition on the next request
	}
	return st
}

// Gate bounds requests in flight to a pool and queues the excess for a
// bounded time, so a slow upstream sees a steady load and callers get a
// prompt 503 instead of a pile-up.
type Gate struct {
	sem      chan struct{}
	maxQueue int
	timeout  time.Duration

	waiting  atomic.Int64
	timeouts atomic.Uint64
	full     atomic.Uint64
	queued   atomic.Uint64
}

// Queue errors.
var (
	ErrQueueFull    = errors.New("upstream queue full")
	ErrQueueTimeout = errors.New("upstream queue timeout")
)

// QueueStatus is the management view.
type QueueStatus struct {
	MaxConcurrent int    `json:"max_concurrent"`
	InFlight      int    `json:"in_flight"`
	QueueSize     int    `json:"queue_size"`
	Waiting       int64  `json:"waiting"`
	Queued        uint64 `json:"queued"`
	Timeouts      uint64 `json:"timeouts"`
	Full          uint64 `json:"full"`
}

func newGate(maxConcurrent, maxQueue int, timeout time.Duration) *Gate {
	return &Gate{sem: make(chan struct{}, maxConcurrent), maxQueue: maxQueue, timeout: timeout}
}

// Acquire takes a slot, waiting in the queue when none is free. release
// must be called when the request finishes.
func (g *Gate) Acquire(ctx context.Context) (release func(), err error) {
	select {
	case g.sem <- struct{}{}:
		return g.release, nil
	default:
	}
	if g.maxQueue <= 0 || g.waiting.Add(1) > int64(g.maxQueue) {
		if g.maxQueue > 0 {
			g.waiting.Add(-1)
		}
		g.full.Add(1)
		return nil, ErrQueueFull
	}
	defer g.waiting.Add(-1)
	g.queued.Add(1)
	timer := time.NewTimer(g.timeout)
	defer timer.Stop()
	select {
	case g.sem <- struct{}{}:
		return g.release, nil
	case <-timer.C:
		g.timeouts.Add(1)
		return nil, ErrQueueTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (g *Gate) release() { <-g.sem }

// Status returns the management view.
func (g *Gate) Status() QueueStatus {
	return QueueStatus{MaxConcurrent: cap(g.sem), InFlight: len(g.sem), QueueSize: g.maxQueue,
		Waiting: g.waiting.Load(), Queued: g.queued.Load(), Timeouts: g.timeouts.Load(), Full: g.full.Load()}
}

// PoolStatus is the management view of one pool beyond its endpoints.
type PoolStatus struct {
	Name      string         `json:"name"`
	Balancer  string         `json:"balancer"`
	Endpoints int            `json:"endpoints"`
	Available int            `json:"available"`
	Active    int64          `json:"active"`
	Circuit   *CircuitStatus `json:"circuit,omitempty"`
	Queue     *QueueStatus   `json:"queue,omitempty"`
	Canary    *CanaryStatus  `json:"canary,omitempty"`
	// SlowStart is the configured ramp, "" when off; Discovery is nil
	// without a discovery section.
	SlowStart string           `json:"slow_start,omitempty"`
	Discovery *DiscoveryStatus `json:"discovery,omitempty"`
}
