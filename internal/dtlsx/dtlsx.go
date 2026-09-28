// Package dtlsx is the DTLS transport the datagram listener kinds share: the
// demultiplexing a stream listener gets from the kernel, the bounds a
// handshake from an unproven peer needs, and the translation from the
// engine's TLS configuration into the library's own.
//
// It exists because two protocols need it. RFC 7252 s9 puts CoAP inside DTLS
// on UDP 5684, and RFC 6353 puts SNMP inside DTLS on UDP 10161; both are
// datagram protocols whose only transport-level identity is a certificate,
// and both are served by relays in this tree. The first of them carried this
// code inside its own kind, which was right while it was the only one: the
// dependency existed for one transport on one listener and confining it to
// one file meant nothing else could grow one. A second kind needing it makes
// that confinement a copy, so the file became a package instead -- the same
// claim, one level out. AMR-050 has the original reasoning and AMR-051 says
// why it moved.
//
// Nothing here knows anything about either protocol. What a kind supplies is
// the socket, the bounds and what to do with a session once it exists; what
// this package supplies is a session per peer, established or refused inside
// a bound.
package dtlsx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

// The transport's bounds, each small on purpose. A constrained network has
// tens of devices, and a listener that would hold ten thousand half-open
// handshakes is a listener an attacker sizes for.
const (
	// DefaultHandshake is how long a peer has to finish one. RFC 6347's
	// retransmission gives a real device several attempts inside this.
	DefaultHandshake = 10 * time.Second
	// DefaultIdle is how long a session with nothing on it is kept. A sensor
	// reporting every thirty seconds keeps its session; something that
	// handshook and went quiet does not.
	DefaultIdle = 5 * time.Minute
	// DefaultQueue is the datagrams held for one peer while its session is
	// busy. It is short because this is UDP: a peer that outruns the queue has
	// its excess dropped, which is what the network would have done anyway.
	DefaultQueue = 16
	// DefaultPending is how many peers may be waiting to be accepted at once.
	DefaultPending = 64
	// DefaultPeers is how many peers one listener may hold sessions for.
	DefaultPeers = 64
	// DefaultMTU is the length handshake messages are fragmented to, which is
	// RFC 7252 s4.6's figure for a message that fits an IPv6 datagram with
	// headroom.
	DefaultMTU = 1200
	// DefaultReplayWindow is RFC 6347's replay protection window.
	DefaultReplayWindow = 64
)

// Bounds are the transport's bounds. A zero field takes the default above,
// so a caller sets the ones its protocol has an opinion about and leaves the
// rest.
type Bounds struct {
	// Handshake is how long a peer has to finish a handshake, and Idle how
	// long a session that says nothing is kept.
	//
	// Both ends of the range are real, which is why they are a caller's to
	// set: a plant network wants the handshake bound tight, and an estate of
	// battery-powered sensors reporting hourly wants the idle bound long,
	// because for those devices the handshake is the expensive part of the
	// exchange and one an hour is a measurable share of the battery.
	Handshake, Idle time.Duration
	// Peers bounds the sessions one listener holds, Queue the datagrams held
	// for one peer, and Pending the peers waiting to be accepted.
	Peers, Queue, Pending int
	// MTU is the handshake fragment size and Datagram the largest datagram
	// read from the socket at all. Datagram defaults to MTU.
	MTU, Datagram int
	// ReplayWindow is RFC 6347's replay protection window.
	ReplayWindow int
}

// withDefaults fills the zero fields.
func (b Bounds) withDefaults() Bounds {
	if b.Handshake <= 0 {
		b.Handshake = DefaultHandshake
	}
	if b.Idle <= 0 {
		b.Idle = DefaultIdle
	}
	if b.Peers <= 0 {
		b.Peers = DefaultPeers
	}
	if b.Queue <= 0 {
		b.Queue = DefaultQueue
	}
	if b.Pending <= 0 {
		b.Pending = DefaultPending
	}
	if b.MTU <= 0 {
		b.MTU = DefaultMTU
	}
	if b.Datagram <= 0 {
		b.Datagram = b.MTU
	}
	if b.ReplayWindow <= 0 {
		b.ReplayWindow = DefaultReplayWindow
	}
	return b
}

// Config is a listener's DTLS configuration: the translated options and the
// bounds every session on it takes.
//
// It is a type rather than a slice of the library's own options so that no
// package outside this one names a type from the library. That is the
// confinement AMR-050 claimed when this code was one file in one kind, kept
// while it serves two: the dependency is in this package's imports and
// nowhere else, so what a kind can ask the transport for is this file's list
// rather than whatever the library happens to expose.
type Config struct {
	what string
	opts []dtls.ServerOption
	b    Bounds
}

// Bounds are the bounds this configuration was built with, defaults filled
// in.
func (c *Config) Bounds() Bounds { return c.b }

// NewConfig translates a listener's TLS configuration into a DTLS one.
//
// It is a translation rather than a pass-through, which is the point: the
// certificates, the client-certificate policy and the minimum version stay
// where every other listener's are, and this is the one place that says how
// the two differ. What DTLS has no equivalent of is refused rather than
// accepted and quietly ignored -- a knob that appears to do something and
// does not is worse than one that is not offered.
//
// The kind names itself in what, so that a configuration fault an operator
// reads says which listener could not be built.
func NewConfig(what string, tc *tls.Config, b Bounds) (*Config, error) {
	b = b.withDefaults()
	if tc == nil || (len(tc.Certificates) == 0 && tc.GetCertificate == nil) {
		return nil, fmt.Errorf("a %s listener inside DTLS needs a certificate", what)
	}
	// DTLS 1.2 is what this library speaks. A listener asking for TLS 1.3 is
	// asking for something this transport cannot do here, and that is better
	// said than ignored.
	if tc.MinVersion > tls.VersionTLS12 {
		return nil, fmt.Errorf("a %s listener inside DTLS cannot require TLS 1.3: DTLS 1.2 is what this transport speaks, and DTLS 1.3 is not implemented here", what)
	}
	opts := []dtls.ServerOption{
		// The library's own default is the same 1200, which is the figure
		// RFC 7252 s4.6 puts a CoAP message under so that it fits an IPv6
		// datagram with headroom. Saying it here means a change upstream does
		// not silently start fragmenting this relay's handshakes.
		dtls.WithMTU(b.MTU),
		// RFC 6347's replay window, also the library's default. It is written
		// down because a relay that accepted a replayed record would be
		// carrying a request a client sent once.
		dtls.WithReplayProtectionWindow(b.ReplayWindow),
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
				// different things. The server name is what a callback
				// selecting a certificate uses, and it is the field both
				// have; the cipher suites are pion's own identifiers and
				// would not mean the same thing to a std callback, so they
				// are left out rather than mistranslated.
				return get(&tls.ClientHelloInfo{ServerName: hi.ServerName})
			}))
		return &Config{what: what, opts: opts, b: b}, nil
	}
	opts = append(opts, dtls.WithCertificates(tc.Certificates...))
	return &Config{what: what, opts: opts, b: b}, nil
}

// clientAuth maps the TLS client-certificate policy onto the DTLS one. The
// five values mean the same thing in both, and writing the mapping out rather
// than casting means a new value upstream is a compile error rather than a
// policy that silently became NoClientCert.
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

// Accept builds a session on one peer's socket and handshakes it inside the
// bound.
//
// The handshake is run explicitly rather than left to the first Read, and
// that is the whole point of this function. pion's ServerWithOptions does not
// handshake: it builds a Conn and the handshake happens inside the first Read
// or Write, under whatever deadline that call carries. So a relay that
// bounded the constructor bounded nothing -- a peer that sends one flight and
// stops was held for the *idle* timeout instead of the handshake one, and
// counted as an established session that never existed. Handshaking here is
// what makes the bound real, makes a failure countable, and keeps a peer that
// has proved nothing from occupying a socket, a goroutine and a slot in the
// peer table for minutes.
//
// The deadline is cleared on success, which matters as much as setting it.
// It is on the socket underneath the session, and pion reads that socket for
// as long as the session lives: a handshake deadline left in place would end
// every session the moment it passed, however long the idle bound said. On an
// estate of sensors reporting once a minute that would mean a handshake per
// report -- which is the expensive part of the exchange and the thing the
// idle bound exists to avoid.
func (c *Config) Accept(pc net.PacketConn, raddr net.Addr, handshake time.Duration) (*Session, error) {
	if handshake <= 0 {
		handshake = c.b.Handshake
	}
	conn, err := dtls.ServerWithOptions(pc, raddr, c.opts...)
	if err != nil {
		return nil, err
	}
	// The bound, in both the places it can be applied. The deadline on the
	// socket is the one that fires: the handshake cannot make progress without
	// reading, and every read goes through this PacketConn, so an absolute
	// deadline on it ends any peer that stalls. The context is defence in
	// depth against the library blocking somewhere that is not a read -- a
	// verification callback, a timer it waits on -- which the tests here
	// cannot reach and a dependency upgrade could introduce. It is
	// deliberately redundant today.
	ctx, cancel := context.WithTimeout(context.Background(), handshake)
	defer cancel()
	if err := pc.SetReadDeadline(time.Now().Add(handshake)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := pc.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Session{conn: conn, remote: raddr}, nil
}

// Session is one established DTLS session.
//
// The methods are the ones a relay needs and no more, and the library's
// connection is not reachable through it, for the reason Config gives: the
// dependency is this package's.
type Session struct {
	conn   *dtls.Conn
	remote net.Addr

	// mu guards writes. It is not decoration: on a relay two goroutines can
	// answer into one session -- a response to a request and something the
	// far side sent unprompted -- and two concurrent writes into one DTLS
	// connection would interleave into a record neither end meant.
	mu sync.Mutex
}

// Read reads one datagram's plaintext.
func (s *Session) Read(b []byte) (int, error) { return s.conn.Read(b) }

// Write writes one datagram's plaintext, as one record.
func (s *Session) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Write(b)
}

// Close ends the session.
func (s *Session) Close() error { return s.conn.Close() }

// SetReadDeadline bounds the peer's silence.
func (s *Session) SetReadDeadline(t time.Time) error { return s.conn.SetReadDeadline(t) }

// RemoteAddr is the peer's address, as the socket gave it.
func (s *Session) RemoteAddr() net.Addr { return s.remote }

// ErrNoCertificate is what PeerCertificates returns when the peer presented
// none. It is separate from a certificate that would not parse, because the
// two are different facts about a peer: one did not offer an identity and the
// other offered something that is not one.
var ErrNoCertificate = errors.New("dtlsx: the peer presented no certificate")

// PeerCertificates are the peer's certificates, leaf first, parsed.
//
// A transport security model derives the name it decides about from the leaf
// (RFC 6353 s5.3), so a listener that maps a certificate to a name needs the
// certificate rather than the fact that there was one. The library keeps them
// as DER, which is the right thing for it to keep and not what a caller can
// read a subject alternative name out of.
func (s *Session) PeerCertificates() ([]*x509.Certificate, error) {
	st, ok := s.conn.ConnectionState()
	if !ok || len(st.PeerCertificates) == 0 {
		return nil, ErrNoCertificate
	}
	out := make([]*x509.Certificate, 0, len(st.PeerCertificates))
	for _, der := range st.PeerCertificates {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("dtlsx: the peer's certificate: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}
