package dns

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A listener stopped the moment it starts is where a WaitGroup whose Add
// races its Wait counts one thing or the other by the scheduler's whim.
// Under -race this fails on the version where Serve registered its
// goroutines outside the lock Shutdown takes before waiting, which is how
// the bug was found: a test that started a listener and let its cleanup
// stop it at once.
func TestServeAndShutdownDoNotRaceOnTheWaitGroup(t *testing.T) {
	for i := 0; i < 25; i++ {
		udp, tcp := listenPair(t)
		s := New("dns", udp, tcp, 100, 8, &Policy{}, Hooks{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Serve()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.Shutdown(ctx)
		cancel()
		wg.Wait()
		// And Serve after a Shutdown starts nothing rather than adding to
		// a WaitGroup nobody will wait on again.
		s.Serve()
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		s.Shutdown(ctx2)
		cancel2()
	}
}
