package proxy

import (
	"io"
	"sync"
	"time"
)

// idleReader wraps a response body and cancels the request when no bytes
// arrive for the idle timeout, so a stalled streaming upstream does not
// hold the exchange until the total deadline. Each Read resets the timer;
// the first firing cancels the request context, which unblocks the copy.
type idleReader struct {
	rc     io.ReadCloser
	idle   time.Duration
	cancel func()
	mu     sync.Mutex
	timer  *time.Timer
	closed bool
}

func newIdleReader(rc io.ReadCloser, idle time.Duration, cancel func()) *idleReader {
	ir := &idleReader{rc: rc, idle: idle, cancel: cancel}
	ir.timer = time.AfterFunc(idle, ir.fire)
	return ir
}

func (ir *idleReader) fire() {
	if ir.cancel != nil {
		ir.cancel()
	}
}

func (ir *idleReader) Read(p []byte) (int, error) {
	n, err := ir.rc.Read(p)
	if n > 0 {
		ir.mu.Lock()
		if !ir.closed {
			ir.timer.Reset(ir.idle)
		}
		ir.mu.Unlock()
	}
	return n, err
}

func (ir *idleReader) Close() error {
	ir.mu.Lock()
	ir.closed = true
	ir.timer.Stop()
	ir.mu.Unlock()
	return ir.rc.Close()
}
