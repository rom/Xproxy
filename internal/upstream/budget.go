package upstream

import "sync/atomic"

// retryBudget bounds the retries in flight to a pool as a share of the
// requests in flight, with a floor so a quiet pool can still retry. It
// protects a struggling origin from a retry storm: as live traffic falls
// the allowance falls with it.
type retryBudget struct {
	percent float64
	minConc int64
	active  atomic.Int64 // requests in their attempt phase
	retries atomic.Int64 // retries (and hedged copies) in flight
}

func newRetryBudget(percent float64, minConcurrency int) *retryBudget {
	return &retryBudget{percent: percent, minConc: int64(minConcurrency)}
}

func (b *retryBudget) begin() { b.active.Add(1) }
func (b *retryBudget) end()   { b.active.Add(-1) }

// allow reserves a retry slot, returning false when the budget is spent.
// A successful reservation must be paired with release.
func (b *retryBudget) allow() bool {
	limit := b.minConc
	if l := int64(b.percent / 100 * float64(b.active.Load())); l > limit {
		limit = l
	}
	if b.retries.Add(1) > limit {
		b.retries.Add(-1)
		return false
	}
	return true
}

func (b *retryBudget) release() { b.retries.Add(-1) }

// BeginRequest and EndRequest bracket the attempt phase of one request so
// the retry budget can size its allowance against live traffic. They are
// no-ops without a configured budget.
func (p *Pool) BeginRequest() {
	if p.budget != nil {
		p.budget.begin()
	}
}

// EndRequest ends the window opened by BeginRequest.
func (p *Pool) EndRequest() {
	if p.budget != nil {
		p.budget.end()
	}
}

// AllowRetry reports whether the retry budget has room for another retry
// (or hedged copy). It reserves a slot that ReleaseRetry frees. With no
// budget configured every retry is allowed and ReleaseRetry is a no-op.
func (p *Pool) AllowRetry() bool {
	if p.budget == nil {
		return true
	}
	return p.budget.allow()
}

// ReleaseRetry frees a slot reserved by AllowRetry.
func (p *Pool) ReleaseRetry() {
	if p.budget != nil {
		p.budget.release()
	}
}

// RetryBudgetStats reports the current active request and in-flight retry
// counts, or false when no budget is configured.
func (p *Pool) RetryBudgetStats() (active, retries int64, ok bool) {
	if p.budget == nil {
		return 0, 0, false
	}
	return p.budget.active.Load(), p.budget.retries.Load(), true
}
