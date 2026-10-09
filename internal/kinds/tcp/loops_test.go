package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The two read loops this listener runs -- one accepting streams, one reading
// datagrams -- and what each does with something that is not a connection.
//
// Neither is reachable through a real socket, which is why both are here: a
// listener does not fail transiently on demand. And the three cases the loops
// separate are the ones that matter. A timeout is nothing happening, and the
// loop goes round again. A closed socket is the end -- a reload retired this
// listener -- and the loop must return rather than spin on a socket that will
// never answer. Anything else is unexplained, and there the loop must neither
// abandon the listener nor spin at full speed on it: one unexplained error has
// to cost something, or a persistent one costs a core.

// closedSocket is the error a listener gives after its socket was closed. The
// loops recognise it by shape, so a test that drives them has to produce the
// shape rather than a sentinel.
func closedSocket() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: errors.New("use of closed network connection")}
}

// timedOut is a deadline passing, which is what the engine's own read
// deadlines produce.
func timedOut() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.ErrDeadlineExceeded}
}

// scriptedAccepts answers each Accept from a script and then reports its
// socket closed, so a loop driven by it always ends.
type scriptedAccepts struct {
	mu    sync.Mutex
	next  []acceptResult
	calls int
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func (l *scriptedAccepts) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if len(l.next) == 0 {
		return nil, closedSocket()
	}
	r := l.next[0]
	l.next = l.next[1:]
	return r.conn, r.err
}

func (l *scriptedAccepts) Close() error   { return nil }
func (l *scriptedAccepts) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9} }

func (l *scriptedAccepts) seen() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func TestTheAcceptLoopKeepsGoingOnAnErrorAndEndsOnAClosedSocket(t *testing.T) {
	ln := &scriptedAccepts{next: []acceptResult{
		{err: timedOut()},
		{err: errors.New("something the kernel has not explained")},
		{err: closedSocket()},
	}}
	srv := &server{
		cfg:  config.Listener{Name: "l4", TCP: &config.TCPListener{MaxConnections: 10}},
		ln:   ln,
		cons: map[net.Conn]struct{}{},
		done: make(chan struct{}),
	}
	start := time.Now()
	finished := make(chan struct{})
	go func() { srv.serve(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the accept loop did not return on a closed socket")
	}
	if n := ln.seen(); n != 3 {
		t.Errorf("the loop called Accept %d times, want all three of the script", n)
	}
	// The unexplained error cost the loop its backoff. Without it one
	// listener whose socket answers an error immediately spins a core until
	// somebody notices the fans.
	if took := time.Since(start); took < 10*time.Millisecond {
		t.Errorf("the loop went round an unexplained error in %v, with no pause at all", took)
	}
}

func TestAConnectionAcceptedAfterTheListenerIsRetiredIsDropped(t *testing.T) {
	client, accepted := net.Pipe()
	srv := &server{
		cfg:  config.Listener{Name: "l4", TCP: &config.TCPListener{MaxConnections: 10}},
		ln:   &scriptedAccepts{next: []acceptResult{{conn: accepted}}},
		cons: map[net.Conn]struct{}{},
		done: make(chan struct{}),
	}
	// Retired between the accept and the admission, which is what a reload
	// that removes a listener does to a connection already on the queue.
	close(srv.done)
	srv.serve()

	if n := srv.open.Load(); n != 0 {
		t.Errorf("the listener still counts %d open connections", n)
	}
	if len(srv.cons) != 0 {
		t.Errorf("the connection was tracked by a listener that is going away: %v", srv.cons)
	}
	// And it was closed rather than left for nobody to serve.
	if _, err := client.Write([]byte("anybody there")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("writing to the dropped connection gave %v, want it closed", err)
	}
}

// scriptedPackets answers each ReadFrom from a script and then reports its
// socket closed.
type scriptedPackets struct {
	mu    sync.Mutex
	next  []readResult
	calls int
}

type readResult struct {
	payload []byte
	addr    net.Addr
	err     error
}

func (p *scriptedPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if len(p.next) == 0 {
		return 0, nil, net.ErrClosed
	}
	r := p.next[0]
	p.next = p.next[1:]
	return copy(b, r.payload), r.addr, r.err
}

func (p *scriptedPackets) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p *scriptedPackets) Close() error                              { return nil }
func (p *scriptedPackets) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
}
func (p *scriptedPackets) SetDeadline(time.Time) error      { return nil }
func (p *scriptedPackets) SetReadDeadline(time.Time) error  { return nil }
func (p *scriptedPackets) SetWriteDeadline(time.Time) error { return nil }

func (p *scriptedPackets) seen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestTheDatagramLoopKeepsGoingOnAnErrorAndEndsOnAClosedSocket(t *testing.T) {
	pc := &scriptedPackets{next: []readResult{
		{err: timedOut()},
		{err: errors.New("something the kernel has not explained")},
		// A datagram from an address that is not a UDP address cannot be
		// routed back to, so there is nothing to do with it.
		{payload: []byte("not routable"), addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}},
		{err: net.ErrClosed},
	}}
	srv := &server{
		cfg: config.Listener{Name: "l4", TCP: &config.TCPListener{
			MaxConnections:  10,
			QUICIdleTimeout: config.Duration(time.Second),
		}},
		cons: map[net.Conn]struct{}{},
		done: make(chan struct{}),
	}
	q := newQUICRelay(srv, pc)
	start := time.Now()
	finished := make(chan struct{})
	go func() { q.serve(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the datagram loop did not return on a closed socket")
	}
	q.shutdown()
	if n := pc.seen(); n != 4 {
		t.Errorf("the loop read %d times, want all four of the script", n)
	}
	if took := time.Since(start); took < 10*time.Millisecond {
		t.Errorf("the loop went round an unexplained error in %v, with no pause at all", took)
	}

	t.Run("and it does not start at all once the listener is shutting down", func(t *testing.T) {
		// A reload can retire a listener between its socket opening and its
		// loop being scheduled. Entering then would be a goroutine nothing
		// waits for, holding the socket of a listener that is gone.
		again := &scriptedPackets{next: []readResult{{payload: []byte("x"), addr: pc.LocalAddr()}}}
		dead := newQUICRelay(srv, again)
		dead.shutdown()
		dead.serve()
		if n := again.seen(); n != 0 {
			t.Errorf("the loop read %d datagrams after shutdown", n)
		}
	})
}

func TestTheConnectionsStillOpenWhenTheGraceEndsAreClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &server{
		cfg:  config.Listener{Name: "l4", TCP: &config.TCPListener{MaxConnections: 10}},
		ln:   ln,
		cons: map[net.Conn]struct{}{},
		done: make(chan struct{}),
	}
	// A connection that ends when, and only when, it is closed: the one
	// the grace period is about.
	client, accepted := net.Pipe()
	if !srv.admit(accepted) {
		t.Fatal("a serving listener did not admit a connection")
	}
	reading := make(chan struct{})
	go func() {
		defer srv.wg.Done()
		defer srv.untrack(accepted)
		close(reading)
		_, _ = accepted.Read(make([]byte, 1))
	}()
	<-reading

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := make(chan struct{})
	go func() { srv.shutdown(ctx); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not return after its grace period ended")
	}
	if _, err := client.Write([]byte("anybody there")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("writing to the connection gave %v, want it closed by the shutdown", err)
	}
	// And a connection arriving afterwards is not admitted: a session
	// started now would be one nothing waits for.
	_, late := net.Pipe()
	if srv.admit(late) {
		t.Error("a connection was admitted after the listener shut down")
	}
	// Shutting down twice is what a reload racing a signal does.
	srv.shutdown(context.Background())
}
