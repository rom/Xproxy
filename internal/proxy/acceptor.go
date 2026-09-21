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
	raw net.Listener
	ch  chan accepted
	// back holds connections a retiring front took from the channel
	// before it saw that it was closed. Its own server will not serve
	// them, so they are handed to the next generation instead of being
	// dropped: a reload must not refuse a connection that arrived
	// during the switch, which is the whole reason the socket is
	// shared.
	back chan net.Conn
	once sync.Once
}

type accepted struct {
	c   net.Conn
	err error
}

func newAcceptor(raw net.Listener) *acceptor {
	a := &acceptor{raw: raw, ch: make(chan accepted), back: make(chan net.Conn, 16)}
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
// listener. Anything handed back and not yet taken is closed here, so a
// removed listener leaves no connection open with nobody serving it.
func (a *acceptor) close() {
	a.once.Do(func() {
		_ = a.raw.Close()
		for {
			select {
			case c := <-a.back:
				_ = c.Close()
			default:
				return
			}
		}
	})
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
	case c := <-f.a.back:
		// A connection a retiring generation took and could not serve.
		return c, nil
	case r, ok := <-f.a.ch:
		if !ok {
			return nil, f.closedErr()
		}
		if r.err != nil {
			return nil, r.err
		}
		select {
		case <-f.closed:
			// Closed while a connection arrived. This generation's
			// server is shutting down and will not serve it, so keeping
			// it would mean closing it on a client that did nothing
			// wrong. Hand it to the next generation instead.
			select {
			case f.a.back <- r.c:
			default:
				// Nowhere to put it: a refused connection the client
				// will retry, rather than one held open by nobody.
				_ = r.c.Close()
			}
			return nil, f.closedErr()
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
