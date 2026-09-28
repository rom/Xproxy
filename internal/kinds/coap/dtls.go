package coap

import (
	"crypto/tls"
	"net"
	"net/netip"
	"time"

	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/proxy"
)

// CoAP inside DTLS, RFC 7252 s9.
//
// The transport itself is internal/dtlsx: the demultiplexing a datagram
// listener has to do for itself, the bounds a handshake from an unproven peer
// needs, and the one translation from the engine's TLS configuration into the
// library's. It lived in this file while this was the only kind that needed
// it; SNMP over DTLS (RFC 6353) is the second, so it moved out rather than
// being copied. AMR-050 has the reasoning and AMR-051 says why it moved.
//
// What is left here is what is CoAP's: which bounds this protocol has an
// opinion about, what a handshake failure is called in this listener's
// counters, and the session loop that hands each datagram to the relay.

// serveDTLS runs the DTLS side of the listener: demultiplex, handshake, and then
// one session loop per peer.
func (s *server) serveDTLS(tc *tls.Config) {
	b := s.dtlsBounds()
	dc, err := dtlsx.NewConfig("coap", tc, b)
	if err != nil {
		s.host.Logs().Error.Error("coap could not build its DTLS configuration",
			"listener", s.cfg.Name, "error", err.Error())
		return
	}
	mux := dtlsx.NewMux(s.pc, b)
	s.demux.Store(mux)
	s.wg.Add(1)
	go func() { defer s.wg.Done(); mux.Run() }()
	defer mux.Close()

	for {
		pc, raddr, err := mux.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dtlsSession(pc, raddr, dc)
		}()
	}
}

// dtlsBounds are the transport's bounds for this listener: the two a CoAP
// deployment moves, and the message size this protocol reads.
//
// The message bound is this listener's own, and the transport derives the socket
// buffer from it: a record is larger than the plaintext it carries, so a buffer
// sized to the plaintext would truncate the largest real messages in the read
// and refuse them at the record layer, which is a bound that looks like a
// network fault. dtlsx.RecordOverhead is where that arithmetic lives.
func (s *server) dtlsBounds() dtlsx.Bounds {
	return dtlsx.Bounds{
		Handshake: s.m.DTLSHandshakeTimeout.D(),
		Idle:      s.m.DTLSIdleTimeout.D(),
		Peers:     s.maxClients(),
		Message:   s.maxMessage() + 1,
	}
}

// dtlsSession handshakes with one peer and then relays what it sends.
//
// The handshake is run explicitly rather than left to the first Read, and that is
// the whole shape of this function. pion's ServerWithOptions does not handshake:
// it builds a Conn and the handshake happens inside the first Read or Write, under
// whatever deadline that call carries. So a relay that bounded the constructor
// bounded nothing — a peer that sends one flight and stops was held for the *idle*
// timeout instead of the handshake one, and counted as an established session that
// never existed. Calling HandshakeContext here is what makes the bound real, makes
// a failure countable, and keeps a peer that has proved nothing from occupying a
// socket, a goroutine and a slot in the peer table for minutes.
func (s *server) dtlsSession(pc net.PacketConn, raddr net.Addr, dc *dtlsx.Config) {
	c := s.host.Counters()
	c.CoAPHandshakes.Add(1)
	defer func() { _ = pc.Close() }()

	conn, err := dc.Accept(pc, raddr, s.handshakeTimeout())
	if err != nil {
		s.handshakeFailed(c, raddr, err)
		return
	}
	defer func() { _ = conn.Close() }()
	c.CoAPSessions.Add(1)
	defer c.CoAPSessions.Add(-1)

	to := &session{conn: conn, to: raddr}
	buf := make([]byte, s.maxMessage()+1)
	for {
		// The idle bound is the session's own deadline rather than the socket's,
		// so it bounds the peer's silence and not the record layer's own reads.
		if err := conn.SetReadDeadline(time.Now().Add(s.idleTimeout())); err != nil {
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

// handshakeFailed records a handshake that did not complete.
func (s *server) handshakeFailed(c *proxy.Stats, raddr net.Addr, err error) {
	c.CoAPHandshakeFailed.Add(1)
	c.Refuse("coap", "handshake_failed")
	s.deny(netip.MustParseAddr(hostOf(raddr)), "handshake_failed", err.Error())
}

// handshakeTimeout and idleTimeout are the two bounds a deployment may move.
//
// They are read from the listener rather than fixed because the two ends of the
// range are both real: a plant network wants the handshake bound tight, and an
// estate of battery-powered sensors reporting hourly wants the idle bound long,
// because for those devices the handshake is the expensive part of the exchange
// and one every hour is a measurable share of the battery.
func (s *server) handshakeTimeout() time.Duration {
	if d := s.m.DTLSHandshakeTimeout.D(); d > 0 {
		return d
	}
	return dtlsx.DefaultHandshake
}

func (s *server) idleTimeout() time.Duration {
	if d := s.m.DTLSIdleTimeout.D(); d > 0 {
		return d
	}
	return dtlsx.DefaultIdle
}

// session writes an answer back into the DTLS session it came from.
//
// It holds no lock of its own: a notification from a device and the answer to a
// request from the same client are written by two goroutines, and serialising
// them is the transport's job -- dtlsx.Session does it, because two concurrent
// writes into one DTLS connection would interleave into a record neither end
// meant whichever kind was doing the writing.
type session struct {
	conn *dtlsx.Session
	to   net.Addr
}

// send writes one CoAP message as one DTLS record.
func (d *session) send(b []byte) error {
	_, err := d.conn.Write(b)
	return err
}

func (d *session) remote() net.Addr { return d.to }
func (d *session) secure() bool     { return true }

// hostOf is an address without its port, for a log line.
func hostOf(a net.Addr) string {
	if ap := addrPort(a); ap.IsValid() {
		return ap.Addr().String()
	}
	return "invalid IP"
}

// The listener's message bound cannot exceed the wire package's -- which this
// does not compile if it does.
const _ = uint(wire.MaxMessage - dtlsx.DefaultMTU)
