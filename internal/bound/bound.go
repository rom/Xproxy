// Package bound makes bounded tables audible. Every table in xproxy that
// caps its size (rate limit keys, ban windows, honeypot marks, WAF rule
// statistics, export queues) has to do something when it is full: evict,
// refuse or drop. That is the right behaviour under attack, but it must
// never be silent, because a full table changes decisions. A Notice counts
// every occurrence and writes a warning at most once per interval, with
// the number of occurrences since the previous warning, so the log stays
// readable under a flood and the status shows the total.
package bound

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultInterval is the minimum spacing between two warnings of one
// Notice.
const DefaultInterval = time.Minute

// Notice is one bounded resource. The zero value is ready to use.
type Notice struct {
	// Interval between warnings; DefaultInterval when zero.
	Interval time.Duration

	total atomic.Uint64
	mu    sync.Mutex
	last  time.Time
	since uint64 // occurrences since the last warning
	now   func() time.Time
}

// Hit records one occurrence and warns through log (slog.Default when nil)
// if the interval has passed. attrs are appended to the warning together
// with "occurrences" (since the last warning) and "total".
func (n *Notice) Hit(log *slog.Logger, msg string, attrs ...any) {
	n.total.Add(1)
	n.mu.Lock()
	n.since++
	now := time.Now()
	if n.now != nil {
		now = n.now()
	}
	interval := n.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	if !n.last.IsZero() && now.Sub(n.last) < interval {
		n.mu.Unlock()
		return
	}
	since := n.since
	n.since = 0
	n.last = now
	n.mu.Unlock()
	if log == nil {
		log = slog.Default()
	}
	log.Warn(msg, append(append([]any{}, attrs...), "occurrences", since, "total", n.total.Load())...)
}

// Total returns the number of occurrences so far.
func (n *Notice) Total() uint64 { return n.total.Load() }
