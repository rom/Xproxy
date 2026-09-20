package passwd

import (
	"context"
	"sync/atomic"
)

// MaxQueuePerSlot bounds how many callers may wait for one semaphore slot
// before new callers are refused outright.
const MaxQueuePerSlot = 4

// Acquire takes a slot of sem for a password verification, giving up when
// ctx ends (the client went away) or when more than MaxQueuePerSlot
// callers per slot are already waiting. A caller that blocked
// unconditionally kept its request slot for the whole wait, so a stream of
// distinct wrong passwords (each one a full hash behind the semaphore)
// could pin every request slot of the process. waiting counts the queued
// callers. The caller releases the slot with <-sem when Acquire returns
// true.
func Acquire(ctx context.Context, sem chan struct{}, waiting *atomic.Int32) bool {
	if ctx.Err() != nil {
		// The caller is already gone. A select would pick the free slot
		// half the time and spend a hash on an answer nobody reads.
		return false
	}
	if int(waiting.Add(1)) > MaxQueuePerSlot*cap(sem) {
		waiting.Add(-1)
		return false
	}
	defer waiting.Add(-1)
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}
