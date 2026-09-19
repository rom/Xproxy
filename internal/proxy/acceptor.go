package proxy

import (
	"errors"
	"net"
	"sync"
)

// acceptor owns an accept socket for the life of the process (or until
// the listener is removed) and hands connections to the current front.
// A reload that rebuilds a listener with a new TLS or protocol setting on
// the same address opens a new front on the same acceptor, so the socket
// (which may be systemd owned and on a privileged port) is never closed
// and re-bound and no connection is refused during the switch.
type acceptor struct {
	raw  net.Listener
	ch   chan accepted
	once sync.Once
}

type accepted struct {
	c   net.Conn
	err error
}

func newAcceptor(raw net.Listener) *acceptor {
	a := &acceptor{raw: raw, ch: make(chan accepted)}
	go a.loop()
	return a
}

// loop accepts until the socket is closed; the channel is unbuffered so
// the socket only accepts when a front is ready, as a plain listener
// would.
func (a *acceptor) loop() {
	defer close(a.ch)
	for {
		c, err := a.raw.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			a.ch <- accepted{err: err}
			continue
		}
		a.ch <- accepted{c: c}
	}
}

// close closes the socket; the loop ends and every front sees a closed
// listener.
func (a *acceptor) close() {
	a.once.Do(func() { _ = a.raw.Close() })
}

// front is the net.Listener served by one listener generation. Closing
// it stops that generation without touching the socket.
type front struct {
	a      *acceptor
	closed chan struct{}
	once   sync.Once
}

func (a *acceptor) newFront() *front {
	return &front{a: a, closed: make(chan struct{})}
}

func (f *front) Accept() (net.Conn, error) {
	select {
	case <-f.closed:
		return nil, f.closedErr()
	default:
	}
	select {
	case <-f.closed:
		return nil, f.closedErr()
	case r, ok := <-f.a.ch:
		if !ok {
			return nil, f.closedErr()
		}
		if r.err != nil {
			return nil, r.err
		}
		select {
		case <-f.closed:
			// Closed while a connection arrived: keep it rather than
			// drop it, the caller drains it like any other.
		default:
		}
		return r.c, nil
	}
}

func (f *front) closedErr() error {
	return &net.OpError{Op: "accept", Net: "tcp", Addr: f.a.raw.Addr(), Err: net.ErrClosed}
}

func (f *front) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *front) Addr() net.Addr { return f.a.raw.Addr() }
