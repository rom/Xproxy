package limits

import "sync/atomic"

// Concurrency is a non-blocking admission counter for in-flight requests.
// Requests above the bound are rejected immediately with 503 rather than
// queued, because a queue is exactly what a flood attacker wants to fill.
type Concurrency struct {
	// max is an atomic so a reload can change it; it used to be fixed
	// at start, so max_concurrent_requests and max_tarpits were the two
	// settings a reload silently ignored.
	max     atomic.Int64
	current atomic.Int64
	// Rejected counts admissions refused.
	Rejected atomic.Uint64
}

// NewConcurrency creates a limiter admitting at most max requests at once.
func NewConcurrency(max int) *Concurrency {
	c := &Concurrency{}
	c.max.Store(int64(max))
	return c
}

// Resize changes the ceiling. Requests already admitted are not
// disturbed: a lowered ceiling takes effect as they finish.
func (c *Concurrency) Resize(max int) { c.max.Store(int64(max)) }

// Max returns the current ceiling.
func (c *Concurrency) Max() int64 { return c.max.Load() }

// Acquire tries to admit one request. The returned release function must be
// called exactly once when ok is true.
func (c *Concurrency) Acquire() (release func(), ok bool) {
	return c.AcquireN(1)
}

// AcquireN atomically reserves n slots. It is used where one admitted object
// can create a known number of units of work before the individual work is
// visible to the normal request admission path.
func (c *Concurrency) AcquireN(n int64) (release func(), ok bool) {
	if n <= 0 {
		return func() {}, true
	}
	for {
		cur := c.current.Load()
		if cur > c.max.Load()-n {
			c.Rejected.Add(1)
			return nil, false
		}
		if c.current.CompareAndSwap(cur, cur+n) {
			break
		}
	}
	var done atomic.Bool
	return func() {
		if done.CompareAndSwap(false, true) {
			c.current.Add(-n)
		}
	}, true
}

// InFlight returns the number of admitted requests.
func (c *Concurrency) InFlight() int64 { return c.current.Load() }
