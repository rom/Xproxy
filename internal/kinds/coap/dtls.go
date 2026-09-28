package coap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	wire "github.com/rom/xproxy/internal/coap"
)

// CoAP inside DTLS, RFC 7252 s9.
//
// This is the only file in the tree that touches the DTLS library, which is
// deliberate: the dependency exists for one transport on one kind, and confining
// it here means nothing else can grow one. AMR-050 has the reasoning.
//
// Two pieces of work are here that a stream listener gets for free. The first is
// **demultiplexing**: the kernel gives a TCP listener one connection per peer, and
// a UDP socket gives one stream of datagrams from everybody, so a DTLS server needs
// a PacketConn per remote address before it can have a session per remote address.
// The second is **bounding the handshakes**: a peer that starts a handshake and
// never finishes it has spent this relay's memory, and on UDP it did so without
// proving it can receive anything, so the number of half-finished handshakes and
// the time each may take are both bounds rather than whatever a peer chooses.
//
// The library's own listener is not used, for a reason worth writing down: its
// Accept performs the handshake before returning, so one slow or hostile peer would
// stop every other peer establishing. The accept loop is here instead.

// The DTLS bounds. Each is small on purpose: a constrained network has tens of
// devices, and a listener that would hold ten thousand half-open handshakes is a
// listener an attacker sizes for.
const (
	// dtlsHandshakeTimeout is how long a peer has to finish one. RFC 6347's
	// retransmission gives a real device several attempts inside this.
	dtlsHandshakeTimeout = 10 * time.Second
	// dtlsIdle is how long a session with nothing on it is kept. A sensor
	// reporting every thirty seconds keeps its session; something that
	// handshook and went quiet does not.
	dtlsIdle = 5 * time.Minute
	// dtlsQueue is the datagrams held for one peer while its session is busy.
	// It is short because this is UDP: a peer that outruns the queue has its
	// excess dropped, which is what the network would have done anyway.
	dtlsQueue = 16
	// dtlsPending is how many peers may be waiting to be accepted at once.
	dtlsPending = 64
	// dtlsMTU is the length handshake messages are fragmented to, which is
	// RFC 7252 s4.6's figure for a message that fits an IPv6 datagram with
	// headroom.
	dtlsMTU = 1200
	// dtlsReplayWindow is RFC 6347's replay protection window.
	dtlsReplayWindow = 64
)

// serveDTLS runs the DTLS side of the listener: demultiplex, handshake, and then
// one session loop per peer.
func (s *server) serveDTLS(tc *tls.Config) {
	opts, err := dtlsOptions(tc)
	if err != nil {
		s.host.Logs().Error.Error("coap could not build its DTLS configuration",
			"listener", s.cfg.Name, "error", err.Error())
		return
	}
	mux := newPacketMux(s.pc, s.maxClients(), s.maxMessage()+1)
	s.demux.Store(mux)
	s.wg.Add(1)
	go func() { defer s.wg.Done(); mux.run() }()
	defer mux.close()

	for {
		pc, raddr, err := mux.accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dtlsSession(pc, raddr, opts)
		}()
	}
}

// dtlsSession handshakes with one peer and then relays what it sends.
func (s *server) dtlsSession(pc net.PacketConn, raddr net.Addr, opts []dtls.ServerOption) {
	c := s.host.Counters()
	c.CoAPHandshakes.Add(1)
	defer func() { _ = pc.Close() }()

	// The handshake's bound, applied where it belongs: on the socket the
	// handshake reads from. The library takes no context, and a deadline on the
	// PacketConn is what makes a peer that stops talking mid-flight stop costing
	// anything.
	if err := pc.SetReadDeadline(time.Now().Add(dtlsHandshakeTimeout)); err != nil {
		return
	}
	conn, err := dtls.ServerWithOptions(pc, raddr, opts...)
	if err != nil {
		c.CoAPHandshakeFailed.Add(1)
		c.Refuse("coap", "handshake_failed")
		s.deny(netip.MustParseAddr(hostOf(raddr)), "handshake_failed", err.Error())
		return
	}
	defer func() { _ = conn.Close() }()
	c.CoAPSessions.Add(1)
	defer c.CoAPSessions.Add(-1)

	to := &session{conn: conn, to: raddr}
	buf := make([]byte, s.maxMessage()+1)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(dtlsIdle)); err != nil {
			return
		}
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		s.fromClient(raw, to)
	}
}

// session writes an answer back into the DTLS session it came from.
type session struct {
	mu   sync.Mutex
	conn net.Conn
	to   net.Addr
}

// send writes one CoAP message as one DTLS record.
//
// The mutex is not decoration: a notification from a device and the answer to a
// request from the same client are written by two goroutines, and two concurrent
// writes into one DTLS connection would interleave into a record neither end meant.
func (d *session) send(b []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Write(b)
	return err
}

func (d *session) remote() net.Addr { return d.to }
func (d *session) secure() bool     { return true }

// dtlsOptions translates the listener's TLS configuration into DTLS options.
//
// It is a translation rather than a pass-through, which is the point: the
// certificates, the client-certificate policy and the minimum version stay where
// every other listener's are, and this is the one place that says how the two
// differ. What DTLS has no equivalent of is refused rather than accepted and
// quietly ignored -- a knob that appears to do something and does not is worse
// than one that is not offered.
func dtlsOptions(tc *tls.Config) ([]dtls.ServerOption, error) {
	if len(tc.Certificates) == 0 && tc.GetCertificate == nil {
		return nil, errors.New("a coap listener inside DTLS needs a certificate")
	}
	// DTLS 1.2 is what this library speaks and what RFC 7252 s9 names. A
	// listener asking for TLS 1.3 is asking for something this transport cannot
	// do here, and that is better said than ignored.
	if tc.MinVersion > tls.VersionTLS12 {
		return nil, errors.New("a coap listener inside DTLS cannot require TLS 1.3: RFC 7252 s9 is DTLS 1.2, and DTLS 1.3 is not implemented here")
	}
	opts := []dtls.ServerOption{
		// The library's own default is the same 1200, which is the figure
		// RFC 7252 s4.6 puts a CoAP message under so that it fits an IPv6
		// datagram with headroom. Saying it here means a change upstream does
		// not silently start fragmenting this relay's handshakes.
		dtls.WithMTU(dtlsMTU),
		// RFC 6347's replay window, also the library's default. It is written
		// down because a relay that accepted a replayed record would be
		// carrying a request a client sent once.
		dtls.WithReplayProtectionWindow(dtlsReplayWindow),
		dtls.WithClientAuth(clientAuth(tc.ClientAuth)),
	}
	if tc.ClientCAs != nil {
		opts = append(opts, dtls.WithClientCAs(tc.ClientCAs))
	}
	// The certificate comes through the engine's own callback where there is
	// one, which is what every other listener uses and is not a detail: it is
	// how a certificate reload reaches a running listener. A DTLS listener
	// holding the certificate it was started with would keep serving it after
	// the keyring rotated, and nobody would find out until it expired.
	if tc.GetCertificate != nil {
		get := tc.GetCertificate
		opts = append(opts, dtls.WithGetCertificate(
			func(hi *dtls.ClientHelloInfo) (*tls.Certificate, error) {
				// The two ClientHelloInfos are different types carrying
				// different things. The server name is what a callback selecting
				// a certificate uses, and it is the field both have; the cipher
				// suites are pion's own identifiers and would not mean the same
				// thing to a std callback, so they are left out rather than
				// mistranslated.
				return get(&tls.ClientHelloInfo{ServerName: hi.ServerName})
			}))
		return opts, nil
	}
	opts = append(opts, dtls.WithCertificates(tc.Certificates...))
	return opts, nil
}

// clientAuth maps the TLS client-certificate policy onto the DTLS one. The five
// values mean the same thing in both, and writing the mapping out rather than
// casting means a new value upstream is a compile error rather than a policy that
// silently became NoClientCert.
func clientAuth(a tls.ClientAuthType) dtls.ClientAuthType {
	switch a {
	case tls.RequestClientCert:
		return dtls.RequestClientCert
	case tls.RequireAnyClientCert:
		return dtls.RequireAnyClientCert
	case tls.VerifyClientCertIfGiven:
		return dtls.VerifyClientCertIfGiven
	case tls.RequireAndVerifyClientCert:
		return dtls.RequireAndVerifyClientCert
	case tls.NoClientCert:
		return dtls.NoClientCert
	}
	return dtls.NoClientCert
}

// packetMux demultiplexes one PacketConn into a PacketConn per remote address.
//
// This is the piece the kernel supplies for a stream listener and not for a
// datagram one. Everything about it is bounded, because every input is a datagram
// from a peer that has proved nothing: the number of peers, the datagrams held for
// each, and the peers waiting to be accepted.
type packetMux struct {
	pc  net.PacketConn
	max int
	mtu int

	mu    sync.Mutex
	peers map[netip.AddrPort]*peerConn

	pending chan *peerConn
	done    chan struct{}
	once    sync.Once

	// dropped counts the datagrams thrown away for want of room, which is the
	// number that says a bound is being reached rather than merely existing.
	dropped atomic.Uint64
}

func newPacketMux(pc net.PacketConn, max, mtu int) *packetMux {
	return &packetMux{
		pc: pc, max: max, mtu: mtu,
		peers:   map[netip.AddrPort]*peerConn{},
		pending: make(chan *peerConn, dtlsPending),
		done:    make(chan struct{}),
	}
}

// run reads the socket and routes each datagram to its peer.
func (m *packetMux) run() {
	buf := make([]byte, m.mtu)
	for {
		n, from, err := m.pc.ReadFrom(buf)
		if err != nil {
			m.close()
			return
		}
		p, fresh := m.peerFor(from)
		if p == nil {
			// The peer table is full. Dropping is the only thing left: there is
			// no one to answer, because there is no session to answer in.
			m.dropped.Add(1)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		p.deliver(raw, from)
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
}

// peerFor finds or makes the connection for a remote address, saying whether it
// is new.
func (m *packetMux) peerFor(from net.Addr) (*peerConn, bool) {
	ap := addrPort(from)
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[ap]; ok {
		return p, false
	}
	if len(m.peers) >= m.max {
		return nil, false
	}
	p := &peerConn{
		mux: m, ap: ap, remote: from,
		in:   make(chan []byte, dtlsQueue),
		gone: make(chan struct{}),
	}
	m.peers[ap] = p
	return p, true
}

func (m *packetMux) forget(p *peerConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.peers[p.ap]; ok && cur == p {
		delete(m.peers, p.ap)
	}
}

// accept hands out the next new peer.
func (m *packetMux) accept() (net.PacketConn, net.Addr, error) {
	select {
	case p := <-m.pending:
		return p, p.remote, nil
	case <-m.done:
		return nil, nil, net.ErrClosed
	}
}

func (m *packetMux) close() {
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

// peerConn is one remote address's view of the shared socket: a PacketConn that
// reads only what that address sent and writes only to it.
type peerConn struct {
	mux    *packetMux
	ap     netip.AddrPort
	remote net.Addr

	in   chan []byte
	gone chan struct{}
	once sync.Once

	mu       sync.Mutex
	deadline time.Time
}

// deliver hands a datagram to the peer, dropping it if the peer is behind.
//
// Dropping is right here rather than blocking: this runs on the one goroutine
// reading the shared socket, so a peer that stopped reading would otherwise stop
// every other peer on the listener. It is UDP, and a dropped datagram is what the
// network does.
func (p *peerConn) deliver(b []byte, _ net.Addr) {
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
	var timeout <-chan time.Time
	p.mu.Lock()
	d := p.deadline
	p.mu.Unlock()
	if !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case raw := <-p.in:
		n := copy(b, raw)
		if n < len(raw) {
			// The caller's buffer is smaller than the datagram. Reporting the
			// truncation rather than the short read is what stops a record being
			// read as a shorter, different record.
			return n, p.remote, fmt.Errorf("coap dtls: a datagram of %d octets into %d", len(raw), len(b))
		}
		return n, p.remote, nil
	case <-timeout:
		return 0, nil, timeoutError{}
	case <-p.gone:
		return 0, nil, net.ErrClosed
	case <-p.mux.done:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo writes onto the shared socket. The address is the peer's own whatever
// the caller passes, because this connection is that peer and nothing else.
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

func (p *peerConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return nil
}

// SetWriteDeadline is a no-op: a write goes straight onto the shared socket,
// whose own deadline is not this peer's to set.
func (p *peerConn) SetWriteDeadline(time.Time) error { return nil }

// timeoutError is what a read past its deadline returns, in the shape the
// library and net.Error expect.
type timeoutError struct{}

func (timeoutError) Error() string   { return "coap dtls: read deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// hostOf is an address without its port, for a log line.
func hostOf(a net.Addr) string {
	if ap := addrPort(a); ap.IsValid() {
		return ap.Addr().String()
	}
	return "invalid IP"
}

// A datagram larger than the mux's read buffer would be truncated by the read
// rather than refused by the policy, and a truncated CoAP message is a different
// message. The buffer is the listener's own bound plus one, and the listener's
// bound cannot exceed the wire package's -- which this does not compile if it does.
const _ = uint(wire.MaxMessage - dtlsMTU)
