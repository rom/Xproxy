package dtlsx

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Mux demultiplexes one PacketConn into a PacketConn per remote address.
//
// This is the piece the kernel supplies for a stream listener and not for a
// datagram one: the kernel gives a TCP listener one connection per peer, and a
// UDP socket gives one stream of datagrams from everybody, so a DTLS server
// needs a PacketConn per remote address before it can have a session per
// remote address.
//
// Everything about it is bounded, because every input is a datagram from a
// peer that has proved nothing: the number of peers, the datagrams held for
// each, and the peers waiting to be accepted.
//
// The library's own listener is not used, for a reason worth writing down: its
// Accept performs the handshake before returning, so one slow or hostile peer
// would stop every other peer establishing. The accept loop belongs to the
// caller instead.
type Mux struct {
	pc net.PacketConn
	b  Bounds

	mu    sync.Mutex
	peers map[netip.AddrPort]*peerConn

	pending chan *peerConn
	done    chan struct{}
	once    sync.Once

	// dropped counts the datagrams thrown away for want of room, which is the
	// number that says a bound is being reached rather than merely existing.
	dropped atomic.Uint64
}

// NewMux builds the demultiplexer over a socket. Run reads it, Accept hands
// out each new peer, and Close ends every session on it.
func NewMux(pc net.PacketConn, b Bounds) *Mux {
	b = b.withDefaults()
	return &Mux{
		pc: pc, b: b,
		peers:   map[netip.AddrPort]*peerConn{},
		pending: make(chan *peerConn, b.Pending),
		done:    make(chan struct{}),
	}
}

// Dropped is how many datagrams were thrown away for want of room.
func (m *Mux) Dropped() uint64 { return m.dropped.Load() }

// Run reads the socket and routes each datagram to its peer. It returns when
// the socket fails, which a Close on the listener's socket is.
//
// A listener that carries something other than DTLS on the same socket does
// not call this: it reads the socket itself and hands over the datagrams that
// are records, with Deliver.
func (m *Mux) Run() {
	buf := make([]byte, m.b.Datagram())
	for {
		n, from, err := m.pc.ReadFrom(buf)
		if err != nil {
			m.Close()
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		m.Deliver(raw, from)
	}
}

// Deliver routes one datagram to its peer's socket, making the peer if it is
// new and Accept has room for it.
//
// It is exported for the listener that shares its port: SNMP's DTLS mode can
// take plain datagrams and records on one socket, because a BER SEQUENCE and a
// DTLS record cannot be confused, and the code that tells them apart has to be
// the code that reads the socket. What it must not do is take the datagram's
// octets after handing them over -- the buffer belongs to the session now.
func (m *Mux) Deliver(raw []byte, from net.Addr) {
	p, fresh := m.peerFor(from)
	if p == nil {
		// The peer table is full. Dropping is the only thing left: there is
		// no one to answer, because there is no session to answer in.
		m.dropped.Add(1)
		return
	}
	p.deliver(raw)
	if fresh {
		select {
		case m.pending <- p:
		default:
			// More peers arriving than are being accepted. The new one is
			// dropped rather than queued without bound, and its datagram
			// goes with it: a peer whose first datagram was not answered
			// retransmits, which is what DTLS does anyway.
			m.dropped.Add(1)
			m.forget(p)
		}
	}
}

// peerFor finds or makes the connection for a remote address, saying whether
// it is new.
func (m *Mux) peerFor(from net.Addr) (*peerConn, bool) {
	ap := AddrPort(from)
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[ap]; ok {
		return p, false
	}
	if len(m.peers) >= m.b.Peers {
		return nil, false
	}
	p := &peerConn{
		mux: m, ap: ap, remote: from,
		in:    make(chan []byte, m.b.Queue),
		gone:  make(chan struct{}),
		reset: make(chan struct{}),
	}
	m.peers[ap] = p
	return p, true
}

func (m *Mux) forget(p *peerConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.peers[p.ap]; ok && cur == p {
		delete(m.peers, p.ap)
	}
}

// Accept hands out the next new peer as a socket of its own.
func (m *Mux) Accept() (net.PacketConn, net.Addr, error) {
	select {
	case p := <-m.pending:
		return p, p.remote, nil
	case <-m.done:
		return nil, nil, net.ErrClosed
	}
}

// Close ends every session and stops accepting.
func (m *Mux) Close() {
	m.once.Do(func() {
		close(m.done)
		m.mu.Lock()
		for _, p := range m.peers {
			p.shut()
		}
		m.peers = map[netip.AddrPort]*peerConn{}
		m.mu.Unlock()
	})
}

// Peers is how many sessions the mux is holding, which is what says a bound is
// being approached.
func (m *Mux) Peers() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.peers)
}

// peerConn is one remote address's view of the shared socket: a PacketConn
// that reads only what that address sent and writes only to it.
type peerConn struct {
	mux    *Mux
	ap     netip.AddrPort
	remote net.Addr

	in   chan []byte
	gone chan struct{}
	once sync.Once

	mu       sync.Mutex
	deadline time.Time
	// reset is closed and replaced whenever the deadline moves, so that a read
	// already blocked notices. net.Conn requires exactly that -- a deadline
	// affects the calls already waiting, not only the next ones -- and here it
	// is load-bearing rather than pedantry: the DTLS handshake bound is set on
	// this connection and cleared again once the handshake is done, while the
	// library's own reader goroutine is reading it. A pending read that had
	// already taken the handshake deadline would keep it, fire at it, and kill
	// an established session at the handshake bound -- which on the default
	// ten seconds is every DTLS session in the estate, ten seconds in,
	// whenever the clear lands a moment too late.
	reset chan struct{}
}

// deliver hands a datagram to the peer, dropping it if the peer is behind.
//
// Dropping is right here rather than blocking: this runs on the one goroutine
// reading the shared socket, so a peer that stopped reading would otherwise
// stop every other peer on the listener. It is UDP, and a dropped datagram is
// what the network does.
func (p *peerConn) deliver(b []byte) {
	select {
	case p.in <- b:
	case <-p.gone:
	default:
		p.mux.dropped.Add(1)
	}
}

func (p *peerConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Closure is checked before the deadline, and before anything is read.
	// Otherwise a read on a closed connection whose deadline had already passed
	// would report a timeout, and a caller told "try again" about a connection
	// that will never have anything is a caller that retries forever.
	select {
	case <-p.gone:
		return 0, nil, net.ErrClosed
	case <-p.mux.done:
		return 0, nil, net.ErrClosed
	default:
	}
	for {
		p.mu.Lock()
		d, reset := p.deadline, p.reset
		p.mu.Unlock()
		var timeout <-chan time.Time
		var t *time.Timer
		if !d.IsZero() {
			t = time.NewTimer(time.Until(d))
			timeout = t.C
		}
		n, addr, err, again := p.readOnce(b, timeout, reset)
		if t != nil {
			t.Stop()
		}
		if again {
			// The deadline moved while this read was waiting. Taking the new
			// one is the whole point: the old one may have been the handshake
			// bound, which the session it established must not inherit.
			continue
		}
		return n, addr, err
	}
}

// readOnce waits for a datagram under one deadline, and says whether the
// deadline changed under it rather than expiring.
func (p *peerConn) readOnce(b []byte, timeout <-chan time.Time, reset <-chan struct{}) (int, net.Addr, error, bool) {
	select {
	case raw := <-p.in:
		n := copy(b, raw)
		if n < len(raw) {
			// The caller's buffer is smaller than the datagram. Reporting the
			// truncation rather than the short read is what stops a record being
			// read as a shorter, different record.
			return n, p.remote, fmt.Errorf("dtlsx: a datagram of %d octets into %d", len(raw), len(b)), false
		}
		return n, p.remote, nil, false
	case <-timeout:
		return 0, nil, timeoutError{}, false
	case <-reset:
		return 0, nil, nil, true
	case <-p.gone:
		return 0, nil, net.ErrClosed, false
	case <-p.mux.done:
		return 0, nil, net.ErrClosed, false
	}
}

// WriteTo writes onto the shared socket. The address is the peer's own
// whatever the caller passes, because this connection is that peer and nothing
// else.
func (p *peerConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-p.gone:
		return 0, net.ErrClosed
	default:
	}
	return p.mux.pc.WriteTo(b, p.remote)
}

func (p *peerConn) Close() error {
	p.shut()
	p.mux.forget(p)
	return nil
}

func (p *peerConn) shut() { p.once.Do(func() { close(p.gone) }) }

func (p *peerConn) LocalAddr() net.Addr { return p.mux.pc.LocalAddr() }

func (p *peerConn) SetDeadline(t time.Time) error {
	return p.SetReadDeadline(t)
}

// SetReadDeadline sets the deadline for the reads already waiting as well as
// the ones to come, which is what net.Conn's contract says and what the
// handshake bound above depends on.
func (p *peerConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	// Wake whatever is already waiting, so that it takes this deadline rather
	// than the one it started under.
	old := p.reset
	p.reset = make(chan struct{})
	p.mu.Unlock()
	close(old)
	return nil
}

// SetWriteDeadline is a no-op: a write goes straight onto the shared socket,
// whose own deadline is not this peer's to set.
func (p *peerConn) SetWriteDeadline(time.Time) error { return nil }

// timeoutError is what a read past its deadline returns, in the shape the
// library and net.Error expect.
type timeoutError struct{}

func (timeoutError) Error() string   { return "dtlsx: read deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// AddrPort is an address as a comparable key, whatever concrete type the
// socket handed over.
func AddrPort(a net.Addr) netip.AddrPort {
	if ua, ok := a.(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
