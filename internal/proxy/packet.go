package proxy

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A datagram socket, shared between the generations of one listener.
//
// The acceptor beside this does the same for an accept socket, and for the
// same reason: a reload that rebuilds a listener must not close and re-bind
// the socket it was serving on. On the stream side the cost of getting that
// wrong is a connection refused during the switch. On the datagram side it is
// worse, because a UDP socket cannot be bound twice: a rebuilt listener that
// opened its own socket failed with "address already in use" about a port this
// process was itself holding, and the reload failed with it. That is what a
// reload of a tftp, ntp, dhcp, dhcpv6, bacnet, coap, snmp or syslog listener
// did before this existed -- and for the three kinds the engine knew bound
// UDP, it refused the reload up front and asked for a restart instead.
//
// What one generation gets is a front: a net.PacketConn that reads the shared
// socket and can be closed without closing it. Closing a front stops that
// generation reading, which is the whole point of the handover. On these
// protocols a datagram is a whole conversation, so the generation that answers
// it is the generation whose policy decided it: once a reload has switched,
// every datagram that arrives must be the new policy's, and one answered under
// the old rules a moment later is exactly the bug an operator would report.
//
// Writes are not stopped. A reply the retiring generation is still composing
// belongs to a request it accepted before the switch, and cutting it off would
// drop an answer rather than police one -- the same reason its already-accepted
// connections drain instead of being closed.

// packetSource owns one datagram socket for the life of a listener, across
// however many generations serve on it.
type packetSource struct {
	raw net.PacketConn
	// handing is set while the readers of a front that has just closed
	// are being woken, so the deadline that wakes them is not mistaken
	// by another generation for a deadline a kind asked for.
	handing atomic.Bool
	once    sync.Once
}

func newPacketSource(raw net.PacketConn) *packetSource {
	return &packetSource{raw: raw}
}

// front returns the connection one generation reads and writes.
func (s *packetSource) front() *packetFront {
	return &packetFront{s: s, closed: make(chan struct{})}
}

// close closes the socket itself, which is the engine's to do when the
// listener is gone rather than the kind's: a kind closes its front.
func (s *packetSource) close() {
	s.once.Do(func() { _ = s.raw.Close() })
}

// handover stops the generation holding these fronts, so the one taking over
// answers every datagram that arrives from now on.
func (s *packetSource) handover(fronts []*packetFront) {
	for _, f := range fronts {
		_ = f.Close()
	}
}

// wake brings the readers of a front that has just closed out of the kernel.
//
// It is the half of closing a front that cannot be skipped: closing it does
// not close the socket, so a goroutine already blocked in ReadFrom would stay
// blocked until a datagram happened to arrive -- and a kind that closes its
// socket and then waits for its read loop to end (which is how every one of
// them shuts down) would wait for ever. A deadline in the past wakes the
// blocked read, and the deadline is then cleared for whoever reads next.
//
// The wait is bounded because nothing here may hang a reload or a shutdown.
// Past the bound the worst case is one more datagram delivered to a generation
// that is going away, which is what happens to a connection the retiring front
// accepted a microsecond before the switch.
func (s *packetSource) wake(f *packetFront) {
	s.handing.Store(true)
	defer s.handing.Store(false)
	_ = s.raw.SetReadDeadline(time.Now())
	deadline := time.Now().Add(packetHandoverWait)
	for f.reading.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Microsecond)
	}
	// Cleared for the generation taking over, where there is one.
	// Datagrams that arrived in between are in the socket's receive buffer
	// and are read by it, which is why a handover loses nothing: the
	// socket was never closed.
	_ = s.raw.SetReadDeadline(time.Time{})
}

// packetHandoverWait bounds how long closing a front waits for that
// generation's readers to come out of the kernel.
const packetHandoverWait = 250 * time.Millisecond

// packetFront is the net.PacketConn one generation of a listener reads. It is
// what Setup.Packet hands a kind, so a kind needs to know nothing about any of
// this: it reads, writes and closes an ordinary datagram socket.
type packetFront struct {
	s      *packetSource
	closed chan struct{}
	once   sync.Once
	// reading counts this front's readers inside ReadFrom, so closing it
	// can wait for them to come out rather than race them.
	reading atomic.Int64
}

var _ net.PacketConn = (*packetFront)(nil)

func (f *packetFront) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if f.isClosed() {
			return 0, nil, net.ErrClosed
		}
		f.reading.Add(1)
		n, addr, err := f.s.raw.ReadFrom(p)
		f.reading.Add(-1)
		if err == nil {
			return n, addr, nil
		}
		var ne net.Error
		if f.s.handing.Load() && errors.As(err, &ne) && ne.Timeout() {
			// The deadline a handover set to wake the generation that is
			// going away. This front is not that one -- a closed front
			// returned above -- so the read simply starts again.
			continue
		}
		return n, addr, err
	}
}

func (f *packetFront) WriteTo(p []byte, addr net.Addr) (int, error) {
	return f.s.raw.WriteTo(p, addr)
}

// Close stops this generation reading. The socket stays open: the next
// generation is serving on it, or the engine closes it when the listener is
// gone. Whatever this front has blocked in the kernel is woken, so a kind that
// closes its socket and waits for its read loop does not wait for ever.
func (f *packetFront) Close() error {
	woke := false
	f.once.Do(func() {
		close(f.closed)
		woke = true
	})
	if woke {
		f.s.wake(f)
	}
	return nil
}

func (f *packetFront) LocalAddr() net.Addr               { return f.s.raw.LocalAddr() }
func (f *packetFront) SetDeadline(t time.Time) error     { return f.s.raw.SetDeadline(t) }
func (f *packetFront) SetReadDeadline(t time.Time) error { return f.s.raw.SetReadDeadline(t) }
func (f *packetFront) SetWriteDeadline(t time.Time) error {
	return f.s.raw.SetWriteDeadline(t)
}

func (f *packetFront) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}
