package upstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func TestBreaker(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newBreaker(&config.CircuitBreaker{ConsecutiveFailures: 2, OpenFor: config.Duration(10 * time.Second), HalfOpenRequests: 1}, func() time.Time { return now })
	allow := func() func(bool) {
		t.Helper()
		done, wait := b.Allow()
		if done == nil {
			t.Fatalf("refused for %v in state %s", wait, b.Status().State)
		}
		return done
	}
	// A success resets the count.
	allow()(false)
	allow()(true)
	allow()(false)
	if st := b.Status(); st.State != CircuitClosed || st.Failures != 1 {
		t.Fatalf("closed: %+v", st)
	}
	allow()(false) // second consecutive failure opens
	st := b.Status()
	if st.State != CircuitOpen || st.Opens != 1 || !st.Until.Equal(now.Add(10*time.Second)) {
		t.Fatalf("open: %+v", st)
	}
	if done, wait := b.Allow(); done != nil || wait != 10*time.Second {
		t.Fatalf("open circuit admitted (done set: %v) for %v", done != nil, wait)
	}
	// Half open: one trial at a time; a second caller is refused.
	now = now.Add(11 * time.Second)
	trial := allow()
	if done, _ := b.Allow(); done != nil {
		t.Fatal("second trial admitted")
	}
	if st := b.Status(); st.State != CircuitHalfOpen || st.HalfOpenIn != 1 {
		t.Fatalf("half open: %+v", st)
	}
	trial(false) // failed trial reopens with a longer back-off
	if st := b.Status(); st.State != CircuitOpen || st.Opens != 2 || !st.Until.Equal(now.Add(20*time.Second)) {
		t.Fatalf("reopened: %+v", st)
	}
	now = now.Add(21 * time.Second)
	allow()(true) // successful trial closes and resets the back-off
	if st := b.Status(); st.State != CircuitClosed || st.Failures != 0 || st.Rejected != 2 {
		t.Fatalf("closed again: %+v", st)
	}
	allow()(false)
	allow()(false)
	if st := b.Status(); !st.Until.Equal(now.Add(10 * time.Second)) {
		t.Fatalf("back-off not reset: %+v", st)
	}
	// An outcome reported after a transition is ignored.
	now = now.Add(11 * time.Second)
	stale := allow()
	stale(true)
	stale(false)
	if st := b.Status(); st.State != CircuitClosed {
		t.Fatalf("stale outcome applied: %+v", st)
	}
}

func TestGate(t *testing.T) {
	g := newGate(1, 1, 50*time.Millisecond)
	rel, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// One waiter fits in the queue and times out; a second is refused at once.
	errs := make(chan error, 1)
	go func() { _, err := g.Acquire(context.Background()); errs <- err }()
	time.Sleep(10 * time.Millisecond)
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("second waiter: %v", err)
	}
	if err := <-errs; !errors.Is(err, ErrQueueTimeout) {
		t.Fatalf("waiter: %v", err)
	}
	st := g.Status()
	if st.InFlight != 1 || st.Timeouts != 1 || st.Full != 1 || st.Queued != 1 || st.Waiting != 0 {
		t.Fatalf("status %+v", st)
	}
	// A release lets a waiter through; a cancelled context leaves the queue.
	go func() { time.Sleep(10 * time.Millisecond); rel() }()
	rel2, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(5 * time.Millisecond); cancel() }()
	if _, err := g.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	rel2()
	if st := g.Status(); st.InFlight != 0 || st.Waiting != 0 {
		t.Fatalf("after release %+v", st)
	}
	// Without a queue the excess is refused immediately.
	g = newGate(1, 0, 0)
	rel, _ = g.Acquire(context.Background())
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("no queue: %v", err)
	}
	rel()
}
