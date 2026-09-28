package snmp

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
)

// SNMP inside DTLS: RFC 6353's transport model on the transport this protocol
// actually uses.
//
// The transport itself is internal/dtlsx. What is here is what is SNMP's about
// it, and there are three things.
//
// **The identity.** A DTLS peer presents a certificate, and RFC 6353 s5.3 says
// how that becomes the security name a rule names -- see certname.go. It is
// derived once per session rather than per datagram, because the certificate
// cannot change inside a session and hashing it per message would be paying a
// hash for a fact already known.
//
// **The level the transport gave.** A session with an AEAD cipher suite
// authenticated and encrypted every record, which RFC 6353 s3.1.2 calls
// authPriv. A message inside it claiming less than that is disagreeing with the
// session it arrived in, and a transport security model message claiming less
// is refused -- not because the protocol forbids it, but because the flags are
// supposed to be copied *from* the transport and a sender that wrote something
// else either did not implement the model or is probing for a listener that
// takes the flags as policy.
//
// **The port it shares.** In detect mode the same socket carries records and
// plain datagrams, which works because a DTLS record begins with a content type
// of 20 to 25 followed by a version whose major octet is 0xFE, and an SNMP
// message begins with 0x30. Neither can be read as the other. The read loop is
// this file's rather than the mux's, because the code that tells them apart has
// to be the code that reads the socket.

// The DTLS record header, which is what the discriminator reads.
const (
	// dtlsMinRecord is the record header's length: type, version, epoch,
	// sequence number, length. A datagram shorter than this is not a record
	// whatever its first octet says.
	dtlsMinRecord = 13
	// dtlsFirstType and dtlsLastType bound the content types DTLS 1.2
	// defines: change_cipher_spec, alert, handshake, application_data,
	// heartbeat and the connection identifier record of RFC 9146.
	dtlsFirstType = 20
	dtlsLastType  = 25
	// dtlsVersionMajor is the first octet of every DTLS version: 0xFEFF is
	// 1.0 and 0xFEFD is 1.2, both of which are 0xFE first. It is checked
	// as well as the content type because one octet in range is a weaker
	// statement than two.
	dtlsVersionMajor = 0xFE
)

// looksLikeDTLS says whether a datagram is a DTLS record rather than an SNMP
// message.
//
// The two are distinguishable and that is the whole basis of detect mode: an
// SNMP message is a BER SEQUENCE, so its first octet is 0x30, which is not a
// DTLS content type; a DTLS record's first octet is 20 to 25, none of which can
// begin a SEQUENCE. So this is not a guess that could go either way -- a
// datagram this calls a record cannot be a message and the other way round.
func looksLikeDTLS(b []byte) bool {
	return len(b) >= dtlsMinRecord &&
		b[0] >= dtlsFirstType && b[0] <= dtlsLastType &&
		b[1] == dtlsVersionMajor
}

// dtlsBounds are the transport's bounds for this listener.
//
// The message bound is this listener's own plus one -- the plus one is what
// makes "larger than the bound" detectable rather than silently exact -- and
// the socket buffer is the transport's to derive from it, because what arrives
// on the socket is a record and a record is larger than the message inside it.
// A buffer sized to the message bound would truncate a message at the bound in
// the read, and a truncated record is refused by the record layer: the bound
// would stop working for exactly the largest real messages and say nothing
// about why. dtlsx.RecordOverhead is where that arithmetic lives.
func (t *server) dtlsBounds() dtlsx.Bounds {
	return dtlsx.Bounds{
		Handshake: t.m.DTLSHandshakeTimeout.D(),
		Idle:      t.m.DTLSIdleTimeout.D(),
		Peers:     t.maxDTLSPeers(),
		Message:   t.maxMessage() + 1,
	}
}

func (t *server) maxDTLSPeers() int {
	if n := t.m.MaxDTLSPeers; n > 0 {
		return n
	}
	return 64
}

func (t *server) dtlsHandshakeTimeout() time.Duration {
	if d := t.m.DTLSHandshakeTimeout.D(); d > 0 {
		return d
	}
	return dtlsx.DefaultHandshake
}

func (t *server) dtlsIdleTimeout() time.Duration {
	if d := t.m.DTLSIdleTimeout.D(); d > 0 {
		return d
	}
	return dtlsx.DefaultIdle
}

// serveDTLS runs the datagram side of a listener whose datagrams are inside
// DTLS: demultiplex, handshake, and then one session loop per peer.
//
// In detect mode the read loop here also carries the plain datagrams, which is
// why it is not dtlsx.Mux.Run: the mux is handed the records and nothing else.
func (t *server) serveDTLS() {
	agent, err := t.agentSocket()
	if err != nil {
		t.host.Logs().Error.Error("snmp agent socket could not be opened",
			"listener", t.cfg.Name, "error", err.Error())
		return
	}
	defer func() { _ = agent.Close() }()
	if t.running.Enter() {
		go func() {
			defer t.running.Leave()
			defer safe.Guard("snmp agent reader")
			t.readAgent(agent)
		}()
	}
	mux := dtlsx.NewMux(t.pc, t.dtlsBounds())
	t.demux.Store(mux)
	defer mux.Close()
	// The accept loop, which handshakes each new peer and then reads it.
	if t.running.Enter() {
		go func() {
			defer t.running.Leave()
			defer safe.Guard("snmp dtls accept")
			for {
				pc, raddr, err := mux.Accept()
				if err != nil {
					return
				}
				if !t.running.Enter() {
					_ = pc.Close()
					return
				}
				go func() {
					defer t.running.Leave()
					defer safe.Guard("snmp dtls session")
					t.dtlsSession(agent, pc, raddr)
				}()
			}
		}()
	}
	t.readDTLSSocket(mux, agent)
}

// readDTLSSocket reads the listener's socket and sends each datagram where it
// belongs: a record to the session layer, a plain message straight into the
// policy when this listener takes both.
func (t *server) readDTLSSocket(mux *dtlsx.Mux, agent net.PacketConn) {
	// The socket carries records, so the buffer is the transport's figure and
	// not this listener's message bound: see dtlsBounds.
	buf := make([]byte, t.dtlsBounds().Datagram())
	detect := t.m.DTLSMode == "detect"
	for {
		select {
		case <-t.done:
			return
		default:
		}
		_ = t.pc.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := t.pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		switch {
		case looksLikeDTLS(raw):
			mux.Deliver(raw, from)
			// The drops are published where they happen, because the two
			// bounds that produce them -- the peer table and one peer's queue
			// -- are both reached by traffic rather than by configuration, and
			// a bound being approached is what an operator wants to see before
			// it is reached.
			t.host.Counters().SNMPDTLSDropped.Store(mux.Dropped())
		case detect:
			// A plain message on a port that also carries records. It is
			// decided about exactly as it would be on a listener with no DTLS
			// at all -- and its transport is udp, so a rule that names dtls
			// does not cover it. That is the whole of what keeps detect mode
			// honest: the policy is what requires the certificate, because the
			// client chooses which of the two it speaks.
			t.fromManager(agent, raw, t.plainPeer(from))
		default:
			// Cleartext at a listener that requires DTLS. It is counted and
			// refused rather than answered: answering would tell a scanner
			// that something is here, and there is no session to answer in.
			c := t.host.Counters()
			c.SNMPRejected.Add(1)
			c.Refuse("snmp", "cleartext_at_dtls_listener")
			t.deny(netutil.AddrOf(from.String()), "snmp_cleartext_at_dtls_listener", "")
		}
	}
}

// dtlsSession handshakes with one peer, derives the name its certificate
// carries, and then relays what it sends.
func (t *server) dtlsSession(agent net.PacketConn, pc net.PacketConn, raddr net.Addr) {
	c := t.host.Counters()
	ip := netutil.AddrOf(raddr.String())
	c.SNMPDTLSHandshakes.Add(1)
	defer func() { _ = pc.Close() }()

	sess, err := t.dtlsConfig().Accept(pc, raddr, t.dtlsHandshakeTimeout())
	if err != nil {
		t.handshakeFailed(c, ip, err)
		return
	}
	defer func() { _ = sess.Close() }()

	// The name the certificate carries, derived once: the certificate cannot
	// change inside a session, and hashing it per datagram would be paying for
	// a fact already known. A session whose certificate maps to no name is
	// still established -- what that costs is require_security_name's
	// business, and it is a decision per message rather than per session
	// because a listener may carry v2c inside DTLS for confidentiality alone.
	name, why := t.securityName(sess)
	p := &peer{ip: ip, from: raddr, transport: TransportDTLS, name: name,
		nameWhy: why, sess: sess}
	c.SNMPDTLSSessions.Add(1)
	defer c.SNMPDTLSSessions.Add(-1)
	t.logDTLSSession(p)

	// Plaintext, read into a buffer the size of a whole record, because a
	// record's plaintext is never larger than the record that carried it: a
	// message past the bound is then refused by the bound below rather than by
	// a short read, and the session survives it.
	buf := make([]byte, t.dtlsBounds().Datagram())
	for {
		// The idle bound is the session's own deadline rather than the
		// socket's, so it bounds the peer's silence and not the record layer's
		// own reads.
		if err := sess.SetReadDeadline(time.Now().Add(t.dtlsIdleTimeout())); err != nil {
			return
		}
		n, err := sess.Read(buf)
		if err != nil {
			return
		}
		if n > t.maxMessage() {
			// Past the bound, refused unread: reading it to find out what it
			// asked for is the work the bound exists to avoid. Inside a
			// session there is somebody to say so to, but the message cannot
			// be parsed and there is therefore no request identifier to
			// answer against, so it is counted and dropped.
			c.SNMPMalformed.Add(1)
			c.Refuse("snmp", "message_too_large")
			t.deny(ip, "snmp_message_too_large", "")
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		t.fromManager(agent, raw, p)
	}
}

// securityName derives the name a session's certificate carries, or the reason
// it has none.
func (t *server) securityName(sess *dtlsx.Session) (string, string) {
	chain, err := sess.PeerCertificates()
	if err != nil {
		return "", certReason(err)
	}
	return t.names.Name(chain)
}

// certReason names why a session has no certificate to derive from.
//
// The two are different facts about a peer and an operator reading one would
// look in a different place than an operator reading the other: a peer that
// offered no certificate is a client that was not configured with one, and a
// certificate that would not parse is a client that was.
func certReason(err error) string {
	if errors.Is(err, dtlsx.ErrNoCertificate) {
		return "no_certificate"
	}
	return "bad_certificate"
}

// handshakeFailed records a handshake that did not complete.
//
// It is a refusal reason of its own rather than a log line, because on a
// datagram listener it is the count that separates "the estate's certificates
// have expired" from "somebody is sending flights of nonsense at the port".
func (t *server) handshakeFailed(c *proxy.Stats, ip netip.Addr, err error) {
	c.SNMPDTLSHandshakeFailed.Add(1)
	c.Refuse("snmp", "dtls_handshake_failed")
	t.deny(ip, "snmp_dtls_handshake_failed", err.Error())
}

// plainPeer is a datagram that arrived with no session: the address is the
// answer's destination and there is no identity beyond it.
func (t *server) plainPeer(from net.Addr) *peer {
	return &peer{ip: netutil.AddrOf(from.String()), from: from, transport: TransportUDP}
}

// streamPeer is a client on the stream side, whose transport depends on
// whether this listener terminated TLS for it.
func (t *server) streamPeer(c net.Conn, secure bool) *peer {
	tr := TransportTCP
	if secure {
		tr = TransportTLS
	}
	return &peer{ip: netutil.AddrOf(c.RemoteAddr().String()), from: c.RemoteAddr(), transport: tr}
}
