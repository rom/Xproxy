package capture

import (
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
//	defer tap.Close(reason)
//	conn = tap.Client(conn)
//
// without a branch for the ordinary case where nothing is recording.
type Tap struct {
	c  *Capturer
	mu sync.Mutex
	s  Session
	// to and from keep the first max bytes each way.
	to, from *boundedBuf
}

// Open returns a Tap when a rule wants this session, and nil otherwise. Nil is
// the common answer: no capture section, not recording, or no rule interested.
func (c *Capturer) Open(kind, listener, id string, client netip.AddrPort) *Tap {
	if c == nil || !c.WantsSession(kind, listener, client.Addr()) {
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
	return &Tap{
		c:    c,
		s:    Session{Start: time.Now(), Client: client, Kind: kind, Listener: listener, ID: id},
		to:   &boundedBuf{max: n},
		from: &boundedBuf{max: n},
	}
}

// Client wraps the client's connection: what is read from it goes to the server,
// and what is written to it came from the server.
func (t *Tap) Client(c net.Conn) net.Conn {
	if t == nil {
		return c
	}
	return &tapped{Conn: c, read: t.to, wrote: t.from, mu: &t.mu}
}

// Upstream wraps the server's connection and records its address, which is not
// known until the dial has succeeded.
func (t *Tap) Upstream(c net.Conn) net.Conn {
	if t == nil {
		return c
	}
	if a, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		t.mu.Lock()
		t.s.Server = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
		t.mu.Unlock()
	}
	// The same two buffers, from the other end: what this connection reads came
	// from the server, and what is written to it is going there. Wrapping both
	// conns would double every byte, so only the client side records -- this one
	// exists for the address and for a kind that has no client conn to wrap.
	return c
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

// Close writes the session. reason is the refusal, or empty when the session was
// allowed, and it is the selector an operator capturing "what I turned away" uses.
func (t *Tap) Close(reason string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	s := t.s
	s.Denied = reason
	s.ToServer, s.ToServerTruncated = t.to.bytes()
	s.ToClient, s.ToClientTruncated = t.from.bytes()
	t.mu.Unlock()
	t.c.WriteSession(&s)
}

// tapped copies what passes through a connection into two bounded buffers.
type tapped struct {
	net.Conn
	read, wrote *boundedBuf
	mu          *sync.Mutex
}

func (t *tapped) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.mu.Lock()
		t.read.add(p[:n])
		t.mu.Unlock()
	}
	return n, err
}

func (t *tapped) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.mu.Lock()
		t.wrote.add(p[:n])
		t.mu.Unlock()
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
