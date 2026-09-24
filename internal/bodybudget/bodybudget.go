// Package bodybudget is the process-wide ceiling on request bodies held
// in memory at once.
//
// A dozen features materialise a whole request body — upload_guard,
// sensitive_data, account_guard, openapi, graphql, body_rewrite, wasm,
// the SAML assertion consumer endpoint,
// the WAF's body inspection, a virtual patch's body pattern, a mirrored
// request — and each one was bounded only per request. The product was
// the real ceiling: max_connections_per_ip (256 by default) times
// max_body_bytes (10 MiB) is about 2.5 GiB of heap from one address,
// sent slowly enough to stay inside read_timeout and fast enough never
// to finish. This package turns that product into one number an
// operator sets.
package bodybudget

import (
	"sync"
	"sync/atomic"
)

// Budget is a byte semaphore: reservations are taken for the life of a
// request and released when it ends. The zero value is unbounded, which
// is what a build without the setting had.
type Budget struct {
	mu    sync.Mutex
	limit int64
	used  int64
	// Refused counts reservations that did not fit.
	Refused atomic.Uint64
	// Peak is the high-water mark, for the status view.
	peak int64
}

// SetLimit changes the ceiling; 0 or less is unbounded. Reservations
// already held are not disturbed, so a reload that lowers the limit
// takes effect as requests finish.
func (b *Budget) SetLimit(n int64) {
	b.mu.Lock()
	b.limit = n
	b.mu.Unlock()
}

// Reserve takes n bytes. It returns a release function and true, or nil
// and false when the budget is full. n below one costs nothing and
// always succeeds, so a caller need not special-case an empty body.
func (b *Budget) Reserve(n int64) (func(), bool) {
	if n < 1 {
		return func() {}, true
	}
	b.mu.Lock()
	if b.limit > 0 && b.used+n > b.limit {
		b.mu.Unlock()
		b.Refused.Add(1)
		return nil, false
	}
	b.used += n
	if b.used > b.peak {
		b.peak = b.used
	}
	b.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			b.used -= n
			b.mu.Unlock()
		})
	}, true
}

// Stats is the management view: the ceiling, what is held now, the
// high-water mark and how many requests were refused.
type Stats struct {
	Limit   int64  `json:"limit"`
	Used    int64  `json:"used"`
	Peak    int64  `json:"peak"`
	Refused uint64 `json:"refused"`
}

// Stats returns the current numbers.
func (b *Budget) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{Limit: b.limit, Used: b.used, Peak: b.peak, Refused: b.Refused.Load()}
}
