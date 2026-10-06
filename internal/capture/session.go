package capture

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// WriteSession writes one relayed or gated session, if a rule wants it.
//
// The flow machinery underneath is already protocol-agnostic: a pair of
// addresses and the bytes each way. What a session needs beyond that is the
// identity a rule selects on -- the listener and the kind -- and the comment that
// makes the file readable without the access log beside it.
func (c *Capturer) WriteSession(s *Session) {
	if c == nil || s == nil || !c.Active() {
		return
	}
	r := c.match(subject{kind: s.Kind, listener: s.Listener, client: s.Client.Addr(),
		reason: s.Denied, session: true}, false)
	if r == nil || !r.take() {
		c.skipped.Add(1)
		return
	}
	if s.ToServerTruncated || s.ToClientTruncated {
		c.truncated.Add(1)
	}
	// A session that was refused never dialled, so there is no upstream address
	// -- and that is the capture an operator most wants, because `denied: true`
	// is the common rule. The flow writer builds an IP header from these, so a
	// zero address has to become the placeholder the HTTP side already uses
	// rather than reaching it: Addr.As4 panics on the zero value, and a panic in
	// the session's own defer would take the connection's goroutine with it.
	client, server := s.Client, s.Server
	if !client.Addr().IsValid() {
		client = netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), client.Port())
	}
	if !server.Addr().IsValid() {
		server = netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), server.Port())
	}

	e := &Exchange{
		Start:             s.Start,
		Client:            client,
		Server:            server,
		RequestID:         s.ID,
		Kind:              s.Kind,
		Listener:          s.Listener,
		User:              s.User,
		Denied:            s.Denied,
		Request:           s.ToServer,
		Response:          s.ToClient,
		RequestTruncated:  s.ToServerTruncated,
		ResponseTruncated: s.ToClientTruncated,
	}
	if err := c.writeFlow(e); err != nil {
		c.writeFailures.Add(1)
		return
	}
	c.captured.Add(1)
}

// Tap records one session's bytes and writes it when it ends.
//
// A kind wraps its two connections and forgets about it. The zero value and a nil
// Tap are both usable and do nothing, which is what lets a kind write
//
//	tap := host.Capture().Open("mysql", listener, id, client)
//	defer tap.Close()
//	conn = tap.Client(conn)
//
// without a branch for the ordinary case where nothing is recording.
type Tap struct {
	c  *Capturer
	mu sync.Mutex
	s  Session
	// to and from keep the first max bytes each way.
	to, from *boundedBuf
	// paused is set while an in-band TLS handshake runs over a connection this
	// tap is already wrapping (see Pause).
	paused bool
}

// Open returns a Tap when a rule wants this session, and nil otherwise. Nil is
// the common answer: no capture section, not recording, or no rule interested.
//
// client is the connection's remote address rather than a parsed one, because
// that is what every kind has in hand at the moment it accepts.
func (c *Capturer) Open(kind, listener, id string, client net.Addr) *Tap {
	cl := addrPort(client)
	if c == nil || !c.WantsSession(kind, listener, cl.Addr()) {
		return nil
	}
	n := c.MaxBody()
	if n <= 0 {
		// `bodies: false` means payloads are not recorded, and a session is
		// payload: there is no head to keep the way an HTTP request has one.
		// So this records nothing rather than recording an empty flow, and the
		// configuration says so at load rather than leaving an operator to
		// find an empty file (see Config.Advice).
		c.skipped.Add(1)
		return nil
	}
	if id == "" {
		// Most kinds have no session identifier of their own -- only the nine
		// that register with the session table do -- and a capture holding
		// several sessions is unreadable without one. So the tap names the
		// session when the kind cannot.
		id = newID()
	}
	return &Tap{
		c:    c,
		s:    Session{Start: time.Now(), Client: cl, Kind: kind, Listener: listener, ID: id},
		to:   &boundedBuf{max: n},
		from: &boundedBuf{max: n},
	}
}

// newID is eight random bytes as hex, the same shape the session table uses, so
// that a kind which has an identifier and one which does not read alike. Random
// rather than sequential because it appears in a file an operator may share.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Only a broken kernel CSPRNG gets here, and a capture is not worth
		// failing a session over: the start time still separates two sessions.
		return "unnamed"
	}
	return hex.EncodeToString(b[:])
}

// addrPort is a net.Addr as a comparable address, or the zero value when it is
// not an IP address at all -- a Unix socket, or a kind's own stub.
func addrPort(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	p, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(p.Addr().Unmap(), p.Port())
}

// Client wraps the client's connection: what is read from it goes to the server,
// and what is written to it came from the server.
func (t *Tap) Client(c net.Conn) net.Conn {
	if t == nil {
		return c
	}
	t.mu.Lock()
	t.paused = false
	t.mu.Unlock()
	return &tapped{t: t, Conn: c, read: t.to, wrote: t.from}
}

// Pause stops recording until the next Client.
//
// It is what a protocol that upgrades in band -- MySQL's CLIENT_SSL, Postgres's
// SSLRequest, STARTTLS, FTP's AUTH TLS -- calls before the handshake, so that the
// capture holds the protocol the proxy reads and not the TLS records it arrives
// in. The wrapper already in place keeps serving the handshake, it just stops
// copying; Client on the upgraded connection resumes, and the bytes of the
// handshake itself belong to neither. Without it a capture of an upgraded session
// would be two readable packets followed by ciphertext.
func (t *Tap) Pause() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.paused = true
	t.mu.Unlock()
}

// Upstream wraps the server's connection and records its address, which is not
// known until the dial has succeeded.
func (t *Tap) Upstream(c net.Conn) net.Conn {
	if t == nil {
		return c
	}
	if a := addrPort(c.RemoteAddr()); a.IsValid() {
		t.mu.Lock()
		t.s.Server = a
		t.mu.Unlock()
	}
	// The same two buffers, from the other end: what this connection reads came
	// from the server, and what is written to it is going there. Wrapping both
	// conns would double every byte, so only the client side records -- this one
	// exists for the address and for a kind that has no client conn to wrap.
	return c
}

// Deny records why the session was turned away, if it has not been turned away
// already.
//
// The first reason rather than the last, because it is the one that ended the
// session; anything after it is a consequence. It lives here rather than in each
// kind's own session state because every kind needs it and none needs it for
// anything else: a kind calls this from the one or two funnels its refusals
// already go through, and has no field to add.
func (t *Tap) Deny(reason string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.s.Denied == "" {
		t.s.Denied = reason
	}
	t.mu.Unlock()
}

// Name replaces the identifier the tap chose with the kind's own.
//
// The nine kinds that register with the session table have one, and it is the
// identifier an operator reads in `xproxyctl sessions`, in the access log and on
// a recording file -- so a capture that reuses it can be lined up against all
// three. The tap cannot ask for it at Open, because it is opened before anything
// can refuse the session and the registration comes after.
func (t *Tap) Name(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	t.s.ID = id
	t.mu.Unlock()
}

// User records the login once the protocol has named one.
func (t *Tap) User(name string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.s.User = name
	t.mu.Unlock()
}

// Close writes the session, whether it was allowed or refused: `denied: true` is
// the rule an operator writes most often, so a refusal is a capture rather than
// the absence of one.
func (t *Tap) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	s := t.s
	s.ToServer, s.ToServerTruncated = t.to.bytes()
	s.ToClient, s.ToClientTruncated = t.from.bytes()
	t.mu.Unlock()
	t.c.WriteSession(&s)
}

// tapped copies what passes through a connection into two bounded buffers.
type tapped struct {
	net.Conn
	t           *Tap
	read, wrote *boundedBuf
}

// Unwrap returns the connection underneath, for a caller that has to know what it
// really is.
//
// A tap sits between a kind and its socket, and Go has no way to forward a type
// assertion: `conn.(*tls.Conn)` on a wrapped connection is false however much TLS
// is underneath it, and a kind that asked whether its client was encrypted would
// get the wrong answer. netutil.TLSConn follows this; so should anything else that
// needs the concrete connection rather than its behaviour.
func (t *tapped) Unwrap() net.Conn { return t.Conn }

// CloseWrite forwards the half-close, which is how a relay tells the other end
// that one direction is finished. The embedded net.Conn does not carry it, so
// without this a tapped TCP connection would stop propagating it and a spliced
// session would hang until a timeout rather than ending.
func (t *tapped) CloseWrite() error {
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (t *tapped) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.t.mu.Lock()
		if !t.t.paused {
			t.read.add(p[:n])
		}
		t.t.mu.Unlock()
	}
	return n, err
}

func (t *tapped) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.t.mu.Lock()
		if !t.t.paused {
			t.wrote.add(p[:n])
		}
		t.t.mu.Unlock()
	}
	return n, err
}

// boundedBuf keeps the first max bytes and remembers that it stopped.
type boundedBuf struct {
	b         []byte
	max       int
	truncated bool
}

func (b *boundedBuf) add(p []byte) {
	if b == nil || b.max <= 0 {
		return
	}
	room := b.max - len(b.b)
	if room <= 0 {
		b.truncated = b.truncated || len(p) > 0
		return
	}
	if len(p) > room {
		b.b = append(b.b, p[:room]...)
		b.truncated = true
		return
	}
	b.b = append(b.b, p...)
}

func (b *boundedBuf) bytes() ([]byte, bool) {
	if b == nil {
		return nil, false
	}
	return b.b, b.truncated
}
