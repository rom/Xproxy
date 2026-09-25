package vnc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// A listener started and shut down at the moment it starts, two hundred
// times, under the race detector.
//
// The obvious way to write session tracking is a sync.WaitGroup whose Add
// runs in the accept loop and whose Wait runs in shutdown, and it is wrong:
// a connection can be accepted at the moment shutdown begins, and Add must
// not run concurrently with Wait at zero. What goes wrong is not a detector
// warning but a session that either is or is not waited for depending on
// the scheduler -- so shutdown returns while a session is still reading a
// connection the process is about to close. vnc now uses
// internal/acceptgroup, which does the check and the Add under one lock.
//
// The server is built by hand rather than through the engine because the
// engine's own lifecycle is what this test needs out of the way. Nothing
// connects, so the only state touched is the listener and the group.
func TestServeAndShutdownDoNotRaceOnTheSessionGroup(t *testing.T) {
	for i := 0; i < 200; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s := &server{ln: ln, cons: map[net.Conn]struct{}{}, v: &config.VNCListener{MaxConnections: 8}}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serve()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.shutdown(ctx)
		cancel()
		_ = ln.Close()
		wg.Wait()
		// A session admitted after a shutdown is refused rather than
		// started, so the accept loop closes the connection instead of
		// serving one nothing waits for.
		client, peer := net.Pipe()
		if s.admit(client) {
			t.Fatal("a session was admitted after shutdown")
		}
		_ = client.Close()
		_ = peer.Close()
	}
}
