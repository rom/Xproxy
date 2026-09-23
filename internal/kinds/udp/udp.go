// Package udp serves the kind: udp listener: a generic datagram relay,
// the symmetric primitive to kind: tcp for services whose protocol this
// proxy does not parse.
//
// There is no connection to hold state on, so the relay holds a session
// table instead. The first datagram from a client address picks an
// endpoint through the pool's balancer and opens a connected socket
// towards it; every later datagram from that address takes the same
// path, and whatever the endpoint answers goes back to that address.
// The session ends when it has been idle, when it reaches one of its
// bounds, or at shutdown.
//
// Two things about UDP shape the whole package. A datagram cannot be
// refused -- there is no reply that means "no", and an error sent to a
// source that did not really send anything is itself an attack on that
// source -- so everything this relay will not forward is dropped and
// counted, with the reason in the security log. And a source address is
// whatever the sender wrote, so the session table has to be bounded per
// source as well as in total, or a few forged datagrams a second fill
// it and the service stops for everyone who is real.
package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: udp listener.
type server struct {
	engine proxy.Host
	cfg    config.Listener
	udp    *config.UDPListener
	pc     net.PacketConn
	allow  []netip.Prefix
	rate   *limits.KeyedLimiter // nil disables

	mu       sync.Mutex
	sessions map[netip.AddrPort]*session
	perIP    map[netip.Addr]int
	wg       sync.WaitGroup
	done     chan struct{}
	once     sync.Once
}

// session is one client address relayed to one endpoint.
type session struct {
	client   netip.AddrPort
	up       *net.UDPConn
	pool     *upstream.Pool
	endpoint *upstream.Endpoint
	start    time.Time
	// last is the unix nanoseconds of the last datagram either way. The
	// read loop and the endpoint's pump both touch it, and the sweeper
	// reads it, so it is an atomic rather than a plain field.
	last                atomic.Int64
	in, out             atomic.Int64
	dgramsIn, dgramsOut atomic.Int64
	ended               atomic.Bool
}

func (s *session) touch() { s.last.Store(time.Now().UnixNano()) }

func (s *session) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, s.last.Load()))
}

func newServer(engine proxy.Host, cfg config.Listener, pc net.PacketConn) (*server, error) {
	u := cfg.UDP
	s := &server{engine: engine, cfg: cfg, udp: u, pc: pc,
		sessions: map[netip.AddrPort]*session{}, perIP: map[netip.Addr]int{}, done: make(chan struct{})}
	for _, c := range u.AllowClients {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		s.allow = append(s.allow, p)
	}
	if u.RateLimit != nil {
		s.rate = limits.NewKeyedLimiter(u.RateLimit.PPS, u.RateLimit.Burst, u.MaxSessions)
	}
	return s, nil
}

func (s *server) serve() {
	s.wg.Add(1)
	go s.sweep()
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		s.datagram(ua.AddrPort(), buf[:n])
	}
}

// datagram relays one client datagram, opening a session for a client
// that has none. It runs on the listener's own read loop, so a panic
// here would end every session on this listener; Guard holds it to the
// one datagram. Every mutex region is a map operation that cannot
// panic, so nothing is left locked behind it.
func (s *server) datagram(client netip.AddrPort, b []byte) {
	defer safe.Guard("udp datagram")
	c := s.engine.Counters()
	if !s.admitted(client, len(b)) {
		return
	}
	s.mu.Lock()
	se := s.sessions[client]
	s.mu.Unlock()
	if se == nil {
		var ok bool
		if se, ok = s.open(client); !ok {
			return
		}
	}
	se.touch()
	n, err := se.up.Write(b)
	if err != nil {
		s.finish(se, "upstream_write")
		return
	}
	se.in.Add(int64(n))
	se.dgramsIn.Add(1)
	c.UDPDatagramsIn.Add(1)
	c.UDPBytesIn.Add(uint64(n)) //nolint:gosec // non-negative
	s.checkBounds(se)
}

// admitted applies everything that decides whether a datagram is
// relayed at all: the ban list, the client policy, the rate limit and
// the datagram bound. Each refusal is a drop, because there is nothing
// to refuse a datagram with.
func (s *server) admitted(client netip.AddrPort, size int) bool {
	c := s.engine.Counters()
	drop := func(reason string) bool {
		c.UDPDropped.Add(1)
		s.deny(client, reason)
		return false
	}
	if bl := s.engine.Bans(); bl != nil && bl.Banned(client.Addr()) {
		c.UDPDropped.Add(1) // a banned client is already a logged decision
		return false
	}
	if len(s.allow) > 0 {
		in := false
		for _, p := range s.allow {
			if p.Contains(client.Addr()) {
				in = true
				break
			}
		}
		if !in {
			return drop("client_not_allowed")
		}
	}
	if size > s.udp.MaxDatagramBytes {
		// Truncating would hand the endpoint a datagram the client
		// never sent, which for a length-prefixed protocol is worse
		// than losing it.
		return drop("datagram_too_large")
	}
	if s.rate != nil && !s.rate.Allow(client.Addr().String()) {
		return drop("rate_limit")
	}
	return true
}

// open starts a session for a client that has none.
func (s *server) open(client netip.AddrPort) (*session, bool) {
	c := s.engine.Counters()
	s.mu.Lock()
	if se, ok := s.sessions[client]; ok { // another datagram won the race
		s.mu.Unlock()
		return se, true
	}
	switch {
	case len(s.sessions) >= s.udp.MaxSessions:
		s.mu.Unlock()
		c.UDPRejected.Add(1)
		s.deny(client, "max_sessions")
		return nil, false
	case s.udp.MaxSessionsPerIP > 0 && s.perIP[client.Addr()] >= s.udp.MaxSessionsPerIP:
		s.mu.Unlock()
		c.UDPRejected.Add(1)
		s.deny(client, "max_sessions_per_ip")
		return nil, false
	}
	// The slot is taken before the endpoint is dialled, so a flood of
	// first datagrams cannot each start a dial.
	se := &session{client: client, start: time.Now()}
	se.touch()
	s.sessions[client] = se
	s.perIP[client.Addr()]++
	s.mu.Unlock()

	pool := s.engine.Pool(s.udp.Upstream)
	if pool == nil {
		s.finish(se, "no_pool")
		return nil, false
	}
	tried := map[*upstream.Endpoint]bool{}
	var uc *net.UDPConn
	var ep *upstream.Endpoint
	for attempt := 0; attempt < 3 && uc == nil; attempt++ {
		e, _ := pool.Pick(client.Addr().String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		ra, err := net.ResolveUDPAddr("udp", e.Address)
		if err != nil {
			continue
		}
		// A connected socket, so the kernel drops anything from an
		// address other than the endpoint's: an answer forged by a
		// third party never reaches the client.
		conn, err := net.DialUDP("udp", nil, ra)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			s.engine.Logs().Error.Warn("udp upstream dial failed", "listener", s.cfg.Name, "endpoint", e.Address, "err", err.Error())
			continue
		}
		uc, ep = conn, e
	}
	if uc == nil {
		c.UDPErrors.Add(1)
		s.finish(se, "upstream_unavailable")
		return nil, false
	}
	se.up, se.endpoint, se.pool = uc, ep, pool
	c.UDPSessions.Add(1)
	c.UDPSessionsOpen.Add(1)
	s.wg.Add(1)
	go s.pump(se)
	return se, true
}

// pump copies datagrams from the endpoint back to the client.
func (s *server) pump(se *session) {
	defer s.wg.Done()
	defer safe.Guard("udp upstream pump")
	c := s.engine.Counters()
	buf := make([]byte, 65535)
	idle := s.udp.IdleTimeout.D()
	client := net.UDPAddrFromAddrPort(se.client)
	for {
		_ = se.up.SetReadDeadline(time.Now().Add(idle))
		n, err := se.up.Read(buf)
		if n > 0 {
			if n > s.udp.MaxDatagramBytes {
				c.UDPDropped.Add(1)
				s.deny(se.client, "upstream_datagram_too_large")
			} else {
				se.touch()
				if w, werr := s.pc.WriteTo(buf[:n], client); werr == nil {
					se.out.Add(int64(w))
					se.dgramsOut.Add(1)
					c.UDPDatagramsOut.Add(1)
					c.UDPBytesOut.Add(uint64(w)) //nolint:gosec // non-negative
				}
			}
			if s.checkBounds(se) {
				return
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && se.idleFor(time.Now()) < idle {
				continue // the client side was active; keep reading
			}
			s.finish(se, "")
			return
		}
	}
}

// checkBounds ends a session that has reached one of its own bounds and
// reports whether it did.
func (s *server) checkBounds(se *session) bool {
	u := s.udp
	switch {
	case u.MaxDatagrams > 0 && se.dgramsIn.Load()+se.dgramsOut.Load() >= u.MaxDatagrams:
		s.finish(se, "max_datagrams")
	case u.MaxBytesIn > 0 && se.in.Load() >= u.MaxBytesIn:
		s.finish(se, "max_bytes_in")
	case u.MaxBytesOut > 0 && se.out.Load() >= u.MaxBytesOut:
		s.finish(se, "max_bytes_out")
	case u.SessionTimeout > 0 && time.Since(se.start) >= u.SessionTimeout.D():
		s.finish(se, "session_timeout")
	default:
		return false
	}
	return true
}

// finish ends a session once, whichever goroutine gets there first.
func (s *server) finish(se *session, reason string) {
	if !se.ended.CompareAndSwap(false, true) {
		return
	}
	s.mu.Lock()
	if s.sessions[se.client] == se {
		delete(s.sessions, se.client)
		if n := s.perIP[se.client.Addr()] - 1; n <= 0 {
			delete(s.perIP, se.client.Addr())
		} else {
			s.perIP[se.client.Addr()] = n
		}
	}
	s.mu.Unlock()
	ep := ""
	if se.up != nil {
		_ = se.up.Close()
		se.pool.End(se.endpoint, false, 0)
		ep = se.endpoint.Address
		s.engine.Counters().UDPSessionsOpen.Add(-1)
	}
	attrs := []any{"listener", s.cfg.Name, "proto", "udp", "client_ip", se.client.Addr().String(),
		"upstream", s.udp.Upstream, "endpoint", ep,
		"datagrams_in", se.dgramsIn.Load(), "datagrams_out", se.dgramsOut.Load(),
		"bytes_in", se.in.Load(), "bytes_out", se.out.Load(),
		"duration_ms", float64(time.Since(se.start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
	}
	s.engine.Logs().Access.Info("udp", attrs...)
}

// deny records a datagram this relay would not forward. It is a
// security event and a ban observation, because the alternative --
// answering the source -- would make the relay a weapon pointed at
// whoever the source claimed to be.
func (s *server) deny(client netip.AddrPort, reason string) {
	s.engine.Logs().SecurityEvent(context.Background(), "deny", "udp_denied",
		"listener", s.cfg.Name, "proto", "udp", "client_ip", client.Addr().String(), "detail", reason)
	if bl := s.engine.Bans(); bl != nil && client.Addr().IsValid() {
		bl.Observe(client.Addr(), "udp_denied")
	}
}

// sweep ends idle sessions and sessions past their absolute bound.
func (s *server) sweep() {
	defer s.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		idle := s.udp.IdleTimeout.D()
		limit := s.udp.SessionTimeout.D()
		now := time.Now()
		s.mu.Lock()
		var stale []*session
		var reasons []string
		for _, se := range s.sessions {
			switch {
			case se.idleFor(now) > idle:
				stale, reasons = append(stale, se), append(reasons, "idle_timeout")
			case limit > 0 && now.Sub(se.start) > limit:
				stale, reasons = append(stale, se), append(reasons, "session_timeout")
			}
		}
		s.mu.Unlock()
		for i, se := range stale {
			s.finish(se, reasons[i])
		}
	}
}

func (s *server) shutdown(ctx context.Context) {
	s.once.Do(func() {
		close(s.done)
		_ = s.pc.Close()
	})
	s.mu.Lock()
	open := make([]*session, 0, len(s.sessions))
	for _, se := range s.sessions {
		open = append(open, se)
	}
	s.mu.Unlock()
	for _, se := range open {
		s.finish(se, "shutdown")
	}
	finished := make(chan struct{})
	go func() { s.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
	}
}
