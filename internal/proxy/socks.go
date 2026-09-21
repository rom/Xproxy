package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/passwd"
)

// SOCKS5 (RFC 1928) and its username/password authentication (RFC 1929)
// on a forward listener.
//
// A forward listener already knows how to decide where a client may go:
// the destination policy, the port list, the private-range refusal, the
// credentials, the ban list, the counters and the access log are all
// there, written for CONNECT. SOCKS5 is the other half of "an explicit
// proxy a client configures", and it is what everything that is not a
// browser speaks: ssh -o ProxyCommand, git, curl --socks5-hostname,
// database clients, package managers. Adding the parser puts all of
// that traffic under the same policy instead of outside it.
//
// The two protocols share a port. A SOCKS greeting begins with the
// version byte 0x05 and an HTTP request begins with a method, so one
// peeked byte separates them with no ambiguity, and nothing has to be
// configured twice.
//
// UDP ASSOCIATE is implemented because the clients that matter use it
// (DNS and QUIC through a proxy), and because the alternative —
// refusing it — pushes those flows outside the policy entirely. Each
// association is bound to the client address that asked for it, holds
// its own socket, and dies with the TCP control connection, which is
// what RFC 1928 requires and what keeps it from becoming an open
// reflector.

const (
	socksVersion = 0x05
	socks4       = 0x04

	socksAuthNone     = 0x00
	socksAuthUserPass = 0x02
	socksAuthNone2    = 0xFF // no acceptable method

	socksCmdConnect      = 0x01
	socksCmdBind         = 0x02
	socksCmdUDPAssociate = 0x03

	socksAddrIPv4   = 0x01
	socksAddrDomain = 0x03
	socksAddrIPv6   = 0x04

	socksReplyOK               = 0x00
	socksReplyGeneralFailure   = 0x01
	socksReplyNotAllowed       = 0x02
	socksReplyNetUnreachable   = 0x03
	socksReplyHostUnreachable  = 0x04
	socksReplyRefused          = 0x05
	socksReplyCmdNotSupported  = 0x07
	socksReplyAddrNotSupported = 0x08
)

// socksHandshakeTimeout bounds the greeting, the authentication and the
// request. A client that opens a connection and says nothing costs a
// socket and a goroutine until this expires.
const socksHandshakeTimeout = 30 * time.Second

// maxUDPDatagram is the largest datagram relayed through an
// association. Anything larger is not a datagram anyone sends; the
// bound keeps one client from choosing the buffer size.
const maxUDPDatagram = 64 << 10

// socksIsGreeting reports whether the first byte begins a SOCKS
// greeting rather than an HTTP request.
func socksIsGreeting(b byte) bool { return b == socksVersion || b == socks4 }

// serveSOCKS handles one connection that began with a SOCKS greeting.
// It owns the connection and closes it.
func (f *forwardServer) serveSOCKS(c net.Conn) {
	defer func() { _ = c.Close() }()
	s := f.s
	start := time.Now()
	ip := remoteAddr(c.RemoteAddr())
	s.stats.ForwardRequests.Add(1)
	s.stats.ForwardSOCKS.Add(1)
	f.track(c, true)
	f.wg.Add(1)
	defer f.wg.Done()
	defer f.track(c, false)

	_ = c.SetDeadline(time.Now().Add(socksHandshakeTimeout))
	p := f.policy.Load()
	user, err := f.socksGreeting(c, p)
	if err != nil {
		// SOCKS4 and an unacceptable method both end here. There is no
		// status line to send: the refusal is a byte and a close.
		s.stats.ForwardAuthFailed.Add(1)
		f.logSOCKS(ip, "", "", 0, 0, start, err.Error())
		return
	}
	cmd, host, port, err := f.socksRequest(c)
	if err != nil {
		f.logSOCKS(ip, user, "", 0, 0, start, err.Error())
		return
	}
	dest := net.JoinHostPort(host, strconv.Itoa(port))
	switch cmd {
	case socksCmdConnect:
		f.socksConnect(c, p, ip, user, host, port, dest, start)
	case socksCmdUDPAssociate:
		f.socksUDP(c, p, ip, user, start)
	default:
		// BIND is not implemented: it asks the proxy to accept an
		// inbound connection on the client's behalf, which is a
		// listening socket opened on a client's say-so.
		_ = socksReply(c, socksReplyCmdNotSupported, netip.AddrPort{})
		s.stats.ForwardDenied.Add(1)
		f.logSOCKS(ip, user, dest, 0, 0, start, "command")
	}
}

// socksGreeting negotiates the authentication method and runs it.
func (f *forwardServer) socksGreeting(c net.Conn, p *forwardPolicy) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", errors.New("greeting")
	}
	if head[0] == socks4 {
		// SOCKS4 has no authentication and no domain names (SOCKS4a
		// added them as a hack). Refusing it is not a limitation worth
		// working around.
		return "", errors.New("socks4")
	}
	if head[0] != socksVersion {
		return "", errors.New("version")
	}
	n := int(head[1])
	if n == 0 {
		return "", errors.New("no methods")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", errors.New("methods")
	}
	want := byte(socksAuthNone)
	if p.cfg.Auth != nil {
		want = socksAuthUserPass
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
			break
		}
	}
	if !offered {
		_, _ = c.Write([]byte{socksVersion, socksAuthNone2})
		return "", errors.New("auth_method")
	}
	if _, err := c.Write([]byte{socksVersion, want}); err != nil {
		return "", errors.New("greeting_reply")
	}
	if want == socksAuthNone {
		return "", nil
	}
	return f.socksAuth(c, p)
}

// socksAuth runs RFC 1929 username/password against the same users file
// the HTTP side uses, with the same cache and the same bounded hashing.
func (f *forwardServer) socksAuth(c net.Conn, p *forwardPolicy) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x01 {
		return "", errors.New("auth_version")
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return "", errors.New("auth_user")
	}
	var plen [1]byte
	if _, err := io.ReadFull(c, plen[:]); err != nil {
		return "", errors.New("auth_password_length")
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return "", errors.New("auth_password")
	}
	name := string(user)
	if name == "" || !f.socksVerify(p, name, string(pass)) {
		_, _ = c.Write([]byte{0x01, 0x01}) // failure
		return "", errors.New("auth")
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
		return "", errors.New("auth_reply")
	}
	return name, nil
}

// socksVerify shares the HTTP side's credential cache and semaphore, so
// the hash cost and the queue bound are the listener's, not per
// protocol.
func (f *forwardServer) socksVerify(p *forwardPolicy, user, pass string) bool {
	hash, known := p.users[user]
	key := sha256.Sum256([]byte(user + "\x00" + pass))
	now := time.Now()
	if known {
		f.authMu.Lock()
		exp, hit := f.authCache[key]
		f.authMu.Unlock()
		if hit && now.Before(exp) {
			return true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), socksHandshakeTimeout)
	defer cancel()
	if !passwd.Acquire(ctx, f.authSem, &f.authWaiting) {
		return false
	}
	ok := false
	if known {
		ok = passwd.Verify(hash, pass)
	} else {
		// The same cost as a wrong password, so the protocol does not
		// answer "does this user exist" faster than "is this right".
		passwd.VerifyDummy(pass)
	}
	<-f.authSem
	if !ok {
		return false
	}
	f.authMu.Lock()
	if len(f.authCache) >= 4096 {
		f.authCache = map[[32]byte]time.Time{}
	}
	f.authCache[key] = now.Add(forwardAuthTTL)
	f.authMu.Unlock()
	return true
}

// socksRequest reads the command and destination.
func (f *forwardServer) socksRequest(c net.Conn) (cmd byte, host string, port int, err error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return 0, "", 0, errors.New("request")
	}
	if head[0] != socksVersion {
		return 0, "", 0, errors.New("request_version")
	}
	switch head[3] {
	case socksAddrIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return 0, "", 0, errors.New("address")
		}
		host = netip.AddrFrom4(b).String()
	case socksAddrIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return 0, "", 0, errors.New("address")
		}
		host = netip.AddrFrom16(b).Unmap().String()
	case socksAddrDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return 0, "", 0, errors.New("address")
		}
		if l[0] == 0 {
			return 0, "", 0, errors.New("empty_name")
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return 0, "", 0, errors.New("address")
		}
		host = string(name)
		// A name is used as sent, except that the checks below fold
		// case and drop a trailing dot; a name with a NUL or a slash in
		// it is not a name.
		for _, r := range host {
			if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
				return 0, "", 0, errors.New("bad_name")
			}
		}
	default:
		_ = socksReply(c, socksReplyAddrNotSupported, netip.AddrPort{})
		return 0, "", 0, errors.New("address_type")
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return 0, "", 0, errors.New("port")
	}
	return head[1], host, int(binary.BigEndian.Uint16(pb[:])), nil
}

// socksConnect applies the destination policy and splices.
func (f *forwardServer) socksConnect(c net.Conn, p *forwardPolicy, ip netip.Addr, user, host string, port int, dest string, start time.Time) {
	s := f.s
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.ConnectTimeout.D())
	defer cancel()
	ips, reason := f.check(ctx, p, host, port)
	if reason != "" {
		_ = socksReply(c, socksDenyCode(reason), netip.AddrPort{})
		s.stats.ForwardDenied.Add(1)
		s.logs.SecurityEvent(context.Background(), "deny", "forward_"+reason,
			"listener", f.name, "protocol", "socks5", "client_ip", ip.String(), "user", user, "destination", dest)
		if bl := s.bans.Load(); bl != nil {
			bl.Observe(ip, "forward_denied")
		}
		f.logSOCKS(ip, user, dest, 0, 0, start, reason)
		return
	}
	select {
	case <-f.done:
		_ = socksReply(c, socksReplyGeneralFailure, netip.AddrPort{})
		f.logSOCKS(ip, user, dest, 0, 0, start, "shutting_down")
		return
	default:
	}
	if f.open.Add(1) > int64(p.cfg.MaxTunnels) {
		f.open.Add(-1)
		s.stats.ForwardRejected.Add(1)
		_ = socksReply(c, socksReplyGeneralFailure, netip.AddrPort{})
		f.logSOCKS(ip, user, dest, 0, 0, start, "tunnel_limit")
		return
	}
	defer f.open.Add(-1)
	dctx := context.WithValue(ctx, forwardDialKey{}, ips)
	dst, err := f.dialChecked(dctx, "tcp", dest)
	if err != nil {
		s.stats.ForwardErrors.Add(1)
		_ = socksReply(c, socksReplyHostUnreachable, netip.AddrPort{})
		f.logSOCKS(ip, user, dest, 0, 0, start, "dial")
		return
	}
	defer func() { _ = dst.Close() }()
	local, _ := netip.ParseAddrPort(dst.LocalAddr().String())
	if err := socksReply(c, socksReplyOK, local); err != nil {
		return
	}
	s.stats.ForwardTunnels.Add(1)
	s.stats.ForwardTunnelsOpen.Add(1)
	defer s.stats.ForwardTunnelsOpen.Add(-1)
	// The handshake deadline must go before the relay, or a long lived
	// tunnel dies at 30 seconds.
	_ = c.SetDeadline(time.Time{})
	in, out := splice(c, dst, p.cfg.IdleTimeout.D())
	s.stats.ForwardBytesIn.Add(uint64(in))   //nolint:gosec // non-negative
	s.stats.ForwardBytesOut.Add(uint64(out)) //nolint:gosec // non-negative
	f.logSOCKS(ip, user, dest, in, out, start, "")
}

// socksDenyCode maps a policy refusal to the closest reply code, so a
// client reports something truthful rather than "general failure".
func socksDenyCode(reason string) byte {
	switch reason {
	case "resolve":
		return socksReplyHostUnreachable
	case "port", "deny", "not_allowed", "private":
		return socksReplyNotAllowed
	default:
		return socksReplyGeneralFailure
	}
}

// socksReply writes a reply with a bound address. A zero address is
// sent as 0.0.0.0:0, which every client accepts.
func socksReply(c net.Conn, code byte, bound netip.AddrPort) error {
	buf := make([]byte, 0, 22)
	buf = append(buf, socksVersion, code, 0x00)
	switch {
	case bound.Addr().Is4():
		a := bound.Addr().As4()
		buf = append(buf, socksAddrIPv4)
		buf = append(buf, a[:]...)
	case bound.Addr().Is6():
		a := bound.Addr().As16()
		buf = append(buf, socksAddrIPv6)
		buf = append(buf, a[:]...)
	default:
		buf = append(buf, socksAddrIPv4, 0, 0, 0, 0)
	}
	buf = binary.BigEndian.AppendUint16(buf, bound.Port())
	_ = c.SetWriteDeadline(time.Now().Add(socksHandshakeTimeout))
	_, err := c.Write(buf)
	return err
}

// logSOCKS writes the forward access line for a SOCKS exchange. There
// is no status code in SOCKS the way there is in HTTP: the reply code
// went to the client and the reason field carries it here.
func (f *forwardServer) logSOCKS(ip netip.Addr, user, dest string, in, out int64, start time.Time, reason string) {
	attrs := []any{"listener", f.name, "protocol", "socks5", "client_ip", ip.String(), "user", user,
		"destination", dest, "bytes_in", in, "bytes_out", out,
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	f.s.logs.Access.Info("forward", attrs...)
}

// socksListener splits SOCKS greetings off a forward listener before
// the HTTP server sees them. The first byte decides: 0x05 (or 0x04)
// begins a SOCKS greeting, and every HTTP request begins with a method
// name, so there is no overlap to get wrong.
type socksListener struct {
	net.Listener
	f *forwardServer
}

func (l *socksListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		// One byte, under a deadline: a client that connects and says
		// nothing must not hold the accept loop.
		_ = c.SetReadDeadline(time.Now().Add(socksHandshakeTimeout))
		var first [1]byte
		n, err := c.Read(first[:])
		if err != nil || n == 0 {
			_ = c.Close()
			continue
		}
		_ = c.SetReadDeadline(time.Time{})
		peeked := &peekedConn{Conn: c, first: first[0]}
		if socksIsGreeting(first[0]) {
			go l.f.serveSOCKS(peeked)
			continue
		}
		return peeked, nil
	}
}

// peekedConn gives back the byte the demux read.
type peekedConn struct {
	net.Conn
	mu    sync.Mutex
	first byte
	done  bool
}

func (p *peekedConn) Read(b []byte) (int, error) {
	p.mu.Lock()
	if !p.done {
		p.done = true
		p.mu.Unlock()
		if len(b) == 0 {
			return 0, nil
		}
		b[0] = p.first
		// Only the peeked byte is returned here. The caller reads again
		// for the rest, which is what every buffered reader does anyway.
		return 1, nil
	}
	p.mu.Unlock()
	return p.Conn.Read(b)
}

// socksEnabled reports whether the listener should demultiplex.
func (f *forwardServer) socksEnabled() bool {
	p := f.policy.Load()
	return p != nil && p.cfg.SOCKS5
}

// socksUDP sets up a UDP association: a socket bound for this client,
// a reply naming it, and a relay that lives as long as the TCP control
// connection. RFC 1928 ties the two together deliberately — when the
// control connection dies the association must, or the socket becomes
// an open reflector that anyone can aim.
func (f *forwardServer) socksUDP(c net.Conn, p *forwardPolicy, ip netip.Addr, user string, start time.Time) {
	s := f.s
	if !p.cfg.SOCKSUDP {
		_ = socksReply(c, socksReplyCmdNotSupported, netip.AddrPort{})
		f.logSOCKS(ip, user, "", 0, 0, start, "udp_disabled")
		return
	}
	if f.open.Add(1) > int64(p.cfg.MaxTunnels) {
		f.open.Add(-1)
		s.stats.ForwardRejected.Add(1)
		_ = socksReply(c, socksReplyGeneralFailure, netip.AddrPort{})
		f.logSOCKS(ip, user, "", 0, 0, start, "tunnel_limit")
		return
	}
	defer f.open.Add(-1)
	// Bind on the same address family and interface the control
	// connection arrived on, so the address handed back is reachable
	// by that client.
	local, _ := netip.ParseAddrPort(c.LocalAddr().String())
	bindAddr := "0.0.0.0:0"
	if local.Addr().Is6() {
		bindAddr = "[::]:0"
	}
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", bindAddr)
	if err != nil {
		s.stats.ForwardErrors.Add(1)
		_ = socksReply(c, socksReplyGeneralFailure, netip.AddrPort{})
		f.logSOCKS(ip, user, "", 0, 0, start, "udp_bind")
		return
	}
	defer func() { _ = pc.Close() }()
	bound, _ := netip.ParseAddrPort(pc.LocalAddr().String())
	// The port is the one that matters; the address the client should
	// send to is the one it already reached us on.
	reply := netip.AddrPortFrom(local.Addr(), bound.Port())
	if err := socksReply(c, socksReplyOK, reply); err != nil {
		return
	}
	s.stats.ForwardUDPAssociations.Add(1)
	s.stats.ForwardUDPOpen.Add(1)
	defer s.stats.ForwardUDPOpen.Add(-1)
	_ = c.SetDeadline(time.Time{})

	a := &socksAssoc{f: f, p: p, pc: pc, client: ip, user: user,
		idle: p.cfg.IdleTimeout.D(), peers: map[netip.AddrPort]time.Time{}}
	done := make(chan struct{})
	go func() {
		// The control connection carries no data: a read returning
		// anything (or failing) means the client is finished, and the
		// association goes with it.
		buf := make([]byte, 1)
		for {
			if _, err := c.Read(buf); err != nil {
				break
			}
		}
		close(done)
		_ = pc.Close()
	}()
	in, out := a.relay(done)
	f.logSOCKS(ip, user, "udp", in, out, start, "")
}

// socksAssoc is one UDP association.
type socksAssoc struct {
	f      *forwardServer
	p      *forwardPolicy
	pc     net.PacketConn
	client netip.Addr
	user   string
	idle   time.Duration

	// clientAddr is fixed by the first datagram: an association belongs
	// to one client, and the address it sends from is that client.
	// Without this any host could inject datagrams into the relay.
	clientAddr netip.AddrPort
	// peers are the destinations this client has sent to. A datagram
	// coming back from anywhere else is dropped, so the socket cannot
	// be used to reach the client from outside.
	mu    sync.Mutex
	peers map[netip.AddrPort]time.Time
}

// maxAssocPeers bounds the peer table: a client that sprays datagrams
// at thousands of destinations must not grow a map without limit.
const maxAssocPeers = 256

func (a *socksAssoc) relay(done <-chan struct{}) (in, out int64) {
	buf := make([]byte, maxUDPDatagram)
	for {
		select {
		case <-done:
			return in, out
		default:
		}
		_ = a.pc.SetReadDeadline(time.Now().Add(a.idle))
		n, from, err := a.pc.ReadFrom(buf)
		if err != nil {
			return in, out
		}
		src, perr := netip.ParseAddrPort(from.String())
		if perr != nil {
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if a.fromClient(src) {
			written, sent := a.toDestination(buf[:n], src)
			in += int64(n)
			out += written
			_ = sent
			continue
		}
		// An answer from a destination: only from one this client
		// actually sent to, and only once the client address is known.
		if !a.knownPeer(src) {
			a.f.s.stats.ForwardUDPDropped.Add(1)
			continue
		}
		msg := socksUDPHeader(src)
		msg = append(msg, buf[:n]...)
		_ = a.pc.SetWriteDeadline(time.Now().Add(a.idle))
		if _, err := a.pc.WriteTo(msg, net.UDPAddrFromAddrPort(a.clientAddr)); err != nil {
			return in, out
		}
		out += int64(n)
	}
}

// fromClient reports whether a datagram came from the associated
// client, fixing the address on the first one.
func (a *socksAssoc) fromClient(src netip.AddrPort) bool {
	if a.clientAddr.IsValid() {
		return a.clientAddr == src
	}
	// The first datagram must come from the address that opened the
	// control connection; its port is whatever the client chose.
	if src.Addr().Unmap() != a.client {
		a.f.s.stats.ForwardUDPDropped.Add(1)
		return false
	}
	a.clientAddr = src
	return true
}

func (a *socksAssoc) knownPeer(src netip.AddrPort) bool {
	if !a.clientAddr.IsValid() {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.peers[src]
	if !ok {
		return false
	}
	if time.Since(t) > a.idle {
		delete(a.peers, src)
		return false
	}
	return true
}

// toDestination parses the client's datagram header, applies the same
// destination policy the TCP side uses, and forwards the payload.
func (a *socksAssoc) toDestination(msg []byte, _ netip.AddrPort) (int64, bool) {
	host, port, payload, err := parseSOCKSUDP(msg)
	if err != nil {
		a.f.s.stats.ForwardUDPDropped.Add(1)
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.p.cfg.ConnectTimeout.D())
	defer cancel()
	ips, reason := a.f.check(ctx, a.p, host, port)
	if reason != "" {
		a.f.s.stats.ForwardDenied.Add(1)
		a.f.s.stats.ForwardUDPDropped.Add(1)
		a.f.s.logs.SecurityEvent(ctx, "deny", "forward_"+reason,
			"listener", a.f.name, "protocol", "socks5-udp", "client_ip", a.client.String(),
			"user", a.user, "destination", net.JoinHostPort(host, strconv.Itoa(port)))
		if bl := a.f.s.bans.Load(); bl != nil {
			bl.Observe(a.client, "forward_denied")
		}
		return 0, false
	}
	dst := netip.AddrPortFrom(ips[0], uint16(port)) //nolint:gosec // port is 0..65535 from a uint16
	a.mu.Lock()
	if len(a.peers) >= maxAssocPeers {
		// Sweep rather than grow. A dropped peer means a later answer
		// from it is discarded, which is the safe direction.
		for k, t := range a.peers {
			if time.Since(t) > a.idle {
				delete(a.peers, k)
			}
		}
		if len(a.peers) >= maxAssocPeers {
			a.mu.Unlock()
			a.f.s.stats.ForwardUDPDropped.Add(1)
			return 0, false
		}
	}
	a.peers[dst] = time.Now()
	a.mu.Unlock()
	_ = a.pc.SetWriteDeadline(time.Now().Add(a.idle))
	n, err := a.pc.WriteTo(payload, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return 0, false
	}
	return int64(n), true
}

// parseSOCKSUDP reads the RFC 1928 datagram header.
func parseSOCKSUDP(b []byte) (host string, port int, payload []byte, err error) {
	if len(b) < 10 {
		return "", 0, nil, errors.New("short datagram")
	}
	if b[0] != 0 || b[1] != 0 {
		return "", 0, nil, errors.New("reserved bytes")
	}
	if b[2] != 0 {
		// Fragmentation is not implemented, and no client that matters
		// uses it. A fragment is dropped rather than reassembled.
		return "", 0, nil, errors.New("fragmented")
	}
	rest := b[4:]
	switch b[3] {
	case socksAddrIPv4:
		if len(rest) < 4+2 {
			return "", 0, nil, errors.New("short ipv4")
		}
		host = netip.AddrFrom4([4]byte(rest[:4])).String()
		rest = rest[4:]
	case socksAddrIPv6:
		if len(rest) < 16+2 {
			return "", 0, nil, errors.New("short ipv6")
		}
		host = netip.AddrFrom16([16]byte(rest[:16])).Unmap().String()
		rest = rest[16:]
	case socksAddrDomain:
		if len(rest) < 1 {
			return "", 0, nil, errors.New("short name")
		}
		l := int(rest[0])
		if l == 0 || len(rest) < 1+l+2 {
			return "", 0, nil, errors.New("short name")
		}
		host = string(rest[1 : 1+l])
		for _, r := range host {
			if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
				return "", 0, nil, errors.New("bad name")
			}
		}
		rest = rest[1+l:]
	default:
		return "", 0, nil, errors.New("address type")
	}
	port = int(binary.BigEndian.Uint16(rest[:2]))
	return host, port, rest[2:], nil
}

// socksUDPHeader builds the header prefixed to an answer.
func socksUDPHeader(from netip.AddrPort) []byte {
	out := []byte{0, 0, 0}
	if from.Addr().Is4() {
		a := from.Addr().As4()
		out = append(out, socksAddrIPv4)
		out = append(out, a[:]...)
	} else {
		a := from.Addr().As16()
		out = append(out, socksAddrIPv6)
		out = append(out, a[:]...)
	}
	return binary.BigEndian.AppendUint16(out, from.Port())
}
