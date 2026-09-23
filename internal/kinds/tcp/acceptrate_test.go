package tcp_test

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/tcp" // the kind under test
	"github.com/rom/xproxy/internal/proxytest"
)

// A connection rate is the bound max_connections does not give: a client
// that connects, costs the server the expensive half of a handshake and
// disconnects never holds two connections at once. Here the listener
// takes its own rate, and what arrives faster is closed at accept
// before a byte is read.
func TestListenerConnectionRate(t *testing.T) {
	ln := sink(t, 0)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      connection_rate: {per_second: 1, burst: 2}
      tcp:
        default: backend
logging: {access: {enabled: false}}
upstreams:
  - name: backend
    endpoints: [{address: %s}]
`, ln.Addr().String())
	s := proxytest.Start(t, yaml)
	addr := s.Addrs()["l4"]

	// Ten connections at once, against a burst of two. A refused
	// connection is closed at accept, so the dial succeeds (the kernel
	// completed the handshake from the backlog) and the read ends.
	refused := 0
	for i := 0; i < 10; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			refused++
			continue
		}
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err != nil {
			// Either the gate closed it (EOF) or nothing came back
			// within the deadline, which for an admitted connection to
			// a silent sink is the normal case. Only a close counts.
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				refused++
			}
		}
		_ = c.Close()
	}
	if refused < 5 {
		t.Fatalf("only %d of ten connections were refused by a burst of two", refused)
	}
	waitFor(t, 5*time.Second, "the refusals to be counted", func() bool {
		return s.Stats().RateRefusedConns > 0
	})
}

// The process-wide rate in server.limits applies to a listener that
// sets none of its own.
func TestProcessWideConnectionRate(t *testing.T) {
	ln := sink(t, 0)
	yaml := fmt.Sprintf(`
version: 1
server:
  limits:
    connection_rate_per_source: {per_second: 1, burst: 1}
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        default: backend
logging: {access: {enabled: false}}
upstreams:
  - name: backend
    endpoints: [{address: %s}]
`, ln.Addr().String())
	s := proxytest.Start(t, yaml)
	addr := s.Addrs()["l4"]
	for i := 0; i < 6; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
		}
	}
	waitFor(t, 5*time.Second, "the process rate to refuse something", func() bool {
		return s.Stats().RateRefusedConns > 0
	})
}
