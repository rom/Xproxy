package acceptgroup

import (
	"context"
	"sync"
	"testing"
	"time"
)

// The ordinary path: sessions enter, Wait blocks until they leave.
func TestWaitWaitsForTheSessionsThatEntered(t *testing.T) {
	var g Group
	release := make(chan struct{})
	var started sync.WaitGroup
	for i := 0; i < 8; i++ {
		if !g.Enter() {
			t.Fatal("Enter refused a session before Close")
		}
		started.Add(1)
		go func() {
			defer g.Leave()
			started.Done()
			<-release
		}()
	}
	started.Wait()
	if !g.Close() {
		t.Fatal("the first Close reported it was not the first")
	}
	if g.Close() {
		t.Fatal("the second Close reported it was the first")
	}

	waited := make(chan struct{})
	go func() {
		g.Wait(context.Background())
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("Wait returned while eight sessions were still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after every session left")
	}
}

// After Close, a session is refused rather than tracked.
//
// This is the half that makes the lock worth having: a connection accepted at the
// moment shutdown begins must be closed by the accept loop rather than served,
// because a session started now is one nothing waits for.
func TestAfterCloseASessionIsRefused(t *testing.T) {
	var g Group
	g.Close()
	if g.Enter() {
		t.Fatal("Enter admitted a session after Close")
	}
	if !g.Closing() {
		t.Fatal("Closing said no after Close")
	}
	// And Wait returns at once, rather than waiting for a session that was
	// refused.
	done := make(chan struct{})
	go func() { g.Wait(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait blocked with nothing to wait for")
	}
}

// Wait is bounded by its context, which is what makes a shutdown finish rather
// than hope. A session blocked on a peer that has stopped reading would otherwise
// hold the process open for as long as the peer cared to.
func TestWaitIsBoundedByItsContext(t *testing.T) {
	var g Group
	if !g.Enter() {
		t.Fatal("Enter refused")
	}
	defer g.Leave() // the session never finishes during the test
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	g.Wait(ctx)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Wait took %v with a 50ms context", d)
	}
}

// The race this package exists for: Enter concurrent with Close and Wait.
//
// A bare WaitGroup fails here -- Add must not run concurrently with Wait at zero
// -- and the failure is not a detector warning but a session that either is or is
// not waited for depending on the scheduler. Run with -race to see the
// difference.
func TestEnterDoesNotRaceCloseAndWait(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		var g Group
		var acceptors sync.WaitGroup
		for i := 0; i < 4; i++ {
			acceptors.Add(1)
			go func() {
				defer acceptors.Done()
				for j := 0; j < 50; j++ {
					if g.Enter() {
						go g.Leave()
					}
				}
			}()
		}
		go func() {
			g.Close()
			g.Wait(context.Background())
		}()
		acceptors.Wait()
		g.Close()
		g.Wait(context.Background())
	}
}
