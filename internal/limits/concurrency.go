package limits

import "sync/atomic"

// Concurrency is a non-blocking admission counter for in-flight requests.
// Requests above the bound are rejected immediately with 503 rather than
// queued, because a queue is exactly what a flood attacker wants to fill.
type Concurrency struct {
	max     int64
	current atomic.Int64
	// Rejected counts admissions refused.
	Rejected atomic.Uint64
}

// NewConcurrency creates a limiter admitting at most max requests at once.
func NewConcurrency(max int) *Concurrency {
	return &Concurrency{max: int64(max)}
}

// Acquire tries to admit one request. The returned release function must be
// called exactly once when ok is true.
func (c *Concurrency) Acquire() (release func(), ok bool) {
	if c.current.Add(1) > c.max {
		c.current.Add(-1)
		c.Rejected.Add(1)
		return nil, false
	}
	var done atomic.Bool
	return func() {
		if done.CompareAndSwap(false, true) {
			c.current.Add(-1)
		}
	}, true
}

// InFlight returns the number of admitted requests.
func (c *Concurrency) InFlight() int64 { return c.current.Load() }
