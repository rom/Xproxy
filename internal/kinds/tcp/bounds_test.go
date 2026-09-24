package tcp_test

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/tcp" // the kind under test
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// sink is a TCP server that reads everything and can be told to send a
// flood back, which is what a byte bound in the other direction needs.
func sink(t *testing.T, reply int) net.Listener { return sinkMode(t, reply, false) }

// sinkEcho answers everything it is sent, which keeps both directions
// active: the lifetime bound has to end a connection that is working,
// and on a half-silent one the idle timeout would do it instead.
func sinkEcho(t *testing.T) net.Listener { return sinkMode(t, 0, true) }

func sinkMode(t *testing.T, reply int, echo bool) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if reply > 0 {
					_, _ = c.Write([]byte(strings.Repeat("y", reply)))
				}
				if echo {
					_, _ = io.Copy(c, c)
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln
}

// boundedRelay starts a kind: tcp listener with extra bounds in front of
// a sink.
func boundedRelay(t *testing.T, target string, extra string) (*proxy.Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        default: backend
%s
logging: {access: {enabled: false}}
upstreams:
  - name: backend
    endpoints: [{address: %s}]
`, extra, target)
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["l4"]
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if ok() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s and it did not happen", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A connection that relays more than max_bytes_in is closed. It is
// closed rather than silently stopped: a relay that kept the socket
// open and stopped forwarding would look to both peers like a network
// that had gone quiet, which is the hardest failure to diagnose.
func TestTCPByteBoundClosesTheConnection(t *testing.T) {
	ln := sink(t, 0)
	s, addr := boundedRelay(t, ln.Addr().String(), "        idle_timeout: 10s\n        max_bytes_in: 4096")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// Write past the bound. The write may succeed into the socket
	// buffer; what must happen is that the connection ends.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Write([]byte(strings.Repeat("x", 8192))); err != nil {
			break
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the connection stayed open past max_bytes_in")
	}
	waitFor(t, 5*time.Second, "the bound to be counted", func() bool {
		return s.Stats().TCPBounded == 1
	})
}

// The same in the other direction, which is the one an operator sets to
// bound what a client can pull out of an estate.
func TestTCPByteBoundOnWhatComesBack(t *testing.T) {
	ln := sink(t, 1<<20)
	s, addr := boundedRelay(t, ln.Addr().String(), "        idle_timeout: 10s\n        max_bytes_out: 4096")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("go ahead")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.Copy(io.Discard, c)
	if err != nil && !strings.Contains(err.Error(), "reset") {
		// A reset is a perfectly good way for this to end.
		t.Logf("read ended with %v", err)
	}
	if got > 1<<19 {
		t.Fatalf("%d bytes came back through a bound of 4096", got)
	}
	waitFor(t, 5*time.Second, "the bound to be counted", func() bool {
		return s.Stats().TCPBounded == 1
	})
}

// session_timeout ends a connection that is busy, which is what
// separates it from idle_timeout: on a busy connection the idle one
// never fires.
func TestTCPSessionTimeoutEndsABusyConnection(t *testing.T) {
	ln := sinkEcho(t)
	s, addr := boundedRelay(t, ln.Addr().String(), "        idle_timeout: 1s\n        session_timeout: 2s")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, 64)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := c.Write([]byte("busy enough to settle the peek")); err != nil {
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(buf); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	waitFor(t, 15*time.Second, "the busy connection to reach its lifetime", func() bool {
		return s.Stats().TCPBounded == 1
	})
}

// A connection inside every bound ends with no bound counted: these are
// for saying the proxy ended it, and an ordinary close is not that.
func TestTCPWithinTheBoundsIsNotCounted(t *testing.T) {
	ln := sink(t, 0)
	s, addr := boundedRelay(t, ln.Addr().String(), "        idle_timeout: 10s\n        max_bytes_in: 1048576\n        session_timeout: 1h")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("small")); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	waitFor(t, 5*time.Second, "the connection to be accounted", func() bool {
		return s.Stats().TCPConnections == 1 && s.Stats().TCPBytesIn > 0
	})
	if n := s.Stats().TCPBounded; n != 0 {
		t.Fatalf("a connection inside every bound counted %d bounds", n)
	}
}

// TestTCPRelaysAServerThatSpeaksFirst is the regression for a deadlock
// the bounds work turned up. The listener peeks for a ClientHello
// before it dials, and plenty of what it carries is server-first --
// SSH sends its banner before the client says anything, and so do SMTP,
// FTP, MySQL and PostgreSQL. Such a client waits for a greeting the
// proxy has not gone to fetch while the proxy waits for a hello the
// client will never send, and the connection used to sit there until
// the peek's hard bound turned it into a read error. Silence is now an
// answer: the connection is relayed with nothing peeked.
func TestTCPRelaysAServerThatSpeaksFirst(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	_, addr := boundedRelay(t, ln.Addr().String(), "        idle_timeout: 10s")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no banner from a server-first upstream: %v", err)
	}
	if got := string(buf[:n]); !strings.HasPrefix(got, "SSH-2.0-") {
		t.Fatalf("banner was %q", got)
	}
	// And the connection still works in both directions afterwards.
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("echo was %q", got)
	}
}
