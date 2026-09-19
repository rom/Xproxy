package upstream

import "testing"

func TestRetryBudget(t *testing.T) {
	// 50% of live requests, floor of 2.
	b := newRetryBudget(50, 2)

	// With no live traffic the floor still allows two retries.
	first, second := b.allow(), b.allow()
	if !first || !second {
		t.Fatal("floor retries denied")
	}
	if b.allow() {
		t.Fatal("third retry allowed past the floor")
	}
	b.release()
	b.release()

	// Ten requests in flight lift the allowance to five (50%).
	for i := 0; i < 10; i++ {
		b.begin()
	}
	got := 0
	for b.allow() {
		got++
		if got > 100 {
			t.Fatal("allow never denied")
		}
	}
	if got != 5 {
		t.Fatalf("allowance %d, want 5", got)
	}
	for i := 0; i < got; i++ {
		b.release()
	}
	// Releasing the slots restores the full allowance.
	if !b.allow() {
		t.Fatal("slot not freed")
	}
	b.release()
	for i := 0; i < 10; i++ {
		b.end()
	}
	if a, r, ok := b.active.Load(), b.retries.Load(), true; !ok || a != 0 || r != 0 {
		t.Fatalf("counters not balanced: active=%d retries=%d", a, r)
	}
}

func TestPoolRetryBudgetAbsent(t *testing.T) {
	// A pool without a budget allows every retry and its accessors are safe.
	p := &Pool{}
	p.BeginRequest()
	a, b := p.AllowRetry(), p.AllowRetry()
	if !a || !b {
		t.Fatal("retry denied without a budget")
	}
	p.ReleaseRetry()
	p.ReleaseRetry()
	p.EndRequest()
	if _, _, ok := p.RetryBudgetStats(); ok {
		t.Fatal("stats reported for a pool without a budget")
	}
}
