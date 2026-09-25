// Package acceptgroup tracks the sessions a listener has accepted, so that
// shutting it down waits for them.
//
// It exists because the obvious way to write that is wrong, and wrong in a way
// that only a race detector or a bad afternoon will tell you about. The obvious
// way is a sync.WaitGroup: Add one per accepted connection in the accept loop,
// Done when the session ends, Wait in shutdown. But a WaitGroup's Add must not
// run concurrently with its Wait while the counter is at zero -- and an accept
// loop does exactly that, because a connection can be accepted at the moment
// shutdown begins.
//
// What goes wrong is not a detector warning. It is that the session either is or
// is not waited for depending on the scheduler: shutdown can return while a
// session is still reading a connection the process is about to close, so the
// last thing a relay does before exiting is mishandle somebody's traffic. On a
// reload that is a session dropped mid-command; on a shutdown it is a log line
// written after the log file was closed.
//
// So the check and the Add happen under one lock, and Close takes the same lock
// before it waits. After Close returns from that lock, no Add can begin: a
// connection accepted afterwards is refused by Enter rather than tracked, and the
// caller closes it. That is the modbus kind's pattern, lifted out so the kinds
// that share the bug can share the fix -- and so it can be tested once rather
// than four times not at all.
package acceptgroup

import (
	"context"
	"sync"
)

// Group tracks accepted sessions. The zero value is ready to use.
type Group struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	closed bool
}

// Enter registers a session, and reports whether it may run.
//
// False means the listener is shutting down, and the caller must close the
// connection rather than serve it: a session started now would be one nothing
// waits for.
func (g *Group) Enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.wg.Add(1)
	return true
}

// Leave marks a session finished. It is paired with a true return from Enter, and
// belongs in a defer so a panicking session still releases it -- otherwise one
// bad session turns every later shutdown into a hang.
func (g *Group) Leave() { g.wg.Done() }

// Closing reports whether Close has been called, for an accept loop that wants to
// tell a deliberate shutdown from a real error.
func (g *Group) Closing() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

// Close refuses new sessions and reports whether this was the first call.
//
// It does not wait. A listener has a socket to close between refusing new
// sessions and waiting for the old ones, and doing that in the wrong order means
// waiting for sessions that are still arriving.
func (g *Group) Close() (first bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.closed = true
	return true
}

// Wait blocks until every session that entered has left, or the context is done.
//
// The context is what makes a shutdown bounded rather than hopeful: a session
// blocked on a peer that has stopped reading would otherwise hold the process
// open for as long as the peer cared to hold it.
func (g *Group) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
