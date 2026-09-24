package tcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

// quicRelay forwards QUIC datagrams of a kind: tcp listener with quic
// enabled. The first Initial packet of a client is decrypted with the
// version 1 Initial keys to read the ClientHello's server name, the
// flow is routed like a TCP connection, and every later datagram from
// that client address goes to the same endpoint (and back) until the
// flow is idle. Nothing after the Initial is read.
type quicRelay struct {
	t  *server
	pc net.PacketConn

	mu    sync.Mutex
	flows map[netip.AddrPort]*quicFlow
	// incomplete counts flows still assembling a ClientHello. Anyone can
	// forge an Initial from a spoofed source, so these are bounded apart
	// from the connection limit and cannot fill it.
	incomplete int
	wg         sync.WaitGroup
	done       chan struct{}
	once       sync.Once
}

const (
	// maxIncompleteQUICFlows bounds flows without a complete ClientHello.
	maxIncompleteQUICFlows = 1024
	// maxQUICPending bounds the bytes held for one flow while its
	// ClientHello is incomplete (a hello spans at most a few Initials).
	maxQUICPending = 16 << 10
)

type quicFlow struct {
	client   netip.AddrPort
	up       *net.UDPConn // set under the relay lock once, read afterwards
	pool     *upstream.Pool
	endpoint *upstream.Endpoint
	// sni is written by the read loop when the ClientHello completes and
	// read by the sweeper when it closes an idle flow, so it is an
	// atomic rather than a plain field.
	sni     atomic.Pointer[string]
	start   time.Time
	last    atomic.Int64 // unix nanoseconds of the last datagram either way
	in, out atomic.Int64
	hello   *netutil.QUICHelloAssembler
	pending [][]byte // datagrams held while the ClientHello is incomplete
	// pendingBytes is the size of pending, bounded by maxQUICPending.
	pendingBytes int
	// release returns this routed flow's slot to the server-wide limiter.
	release func()
}

func (f *quicFlow) touch() { f.last.Store(time.Now().UnixNano()) }

func (f *quicFlow) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, f.last.Load()))
}

func newQUICRelay(t *server, pc net.PacketConn) *quicRelay {
	return &quicRelay{t: t, pc: pc, flows: map[netip.AddrPort]*quicFlow{}, done: make(chan struct{})}
}

func (q *quicRelay) serve() {
	q.wg.Add(2) // the sweeper and this loop
	go q.sweep()
	defer q.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := q.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-q.done:
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
		q.datagram(ua.AddrPort(), buf[:n])
	}
}

// datagram routes one client datagram. It runs on the listener's own
// read loop, so a panic here would end every flow on this listener and
// the process with them; the ClientHello parsing it drives is the most
// attacker-controlled code in the proxy. Guard contains that to the one
// datagram. Every mutex region below is a map operation that cannot
// panic, so nothing is left locked behind it.
func (q *quicRelay) datagram(client netip.AddrPort, b []byte) {
	defer safe.Guard("quic datagram")
	s := q.t.engine
	now := time.Now()
	q.mu.Lock()
	f := q.flows[client]
	var up *net.UDPConn
	if f != nil {
		up = f.up
	}
	q.mu.Unlock()
	if up != nil {
		f.touch()
		if n, err := up.Write(b); err == nil {
			f.in.Add(int64(n))
		}
		return
	}
	if bl := s.Bans(); bl != nil && bl.Banned(client.Addr()) {
		return
	}
	frames, err := netutil.QUICCryptoData(b)
	if err != nil {
		if f != nil { // a flow still assembling: later Initial only
			return
		}
		// Not an Initial we can read: a short header of a flow we never
		// saw (a migration, a restart) or another version. Dropped: the
		// client retries or gives up.
		return
	}
	if f == nil {
		q.mu.Lock()
		if len(q.flows) >= q.t.cfg.TCP.MaxConnections || q.incomplete >= min(maxIncompleteQUICFlows, q.t.cfg.TCP.MaxConnections) {
			q.mu.Unlock()
			s.Counters().QUICRejected.Add(1)
			return
		}
		f = &quicFlow{client: client, start: now, hello: &netutil.QUICHelloAssembler{}}
		f.touch()
		q.flows[client] = f
		q.incomplete++
		q.mu.Unlock()
	}
	f.touch()
	f.pending = append(f.pending, append([]byte(nil), b...))
	f.pendingBytes += len(b)
	sni, err := f.hello.Add(frames)
	if errors.Is(err, netutil.ErrQUICNeedMore) {
		if len(f.pending) < 8 && f.pendingBytes <= maxQUICPending {
			return
		}
		err = netutil.ErrNotTLS
	}
	if err != nil {
		sni = ""
	}
	f.sni.Store(&sni)
	upName, ok := q.t.resolve(sni)
	if !ok {
		s.Counters().QUICRejected.Add(1)
		q.drop(f, "no_route")
		return
	}
	release, _ := s.ConnLimiter().Admit(client.Addr())
	if release == nil {
		s.Counters().QUICRejected.Add(1)
		q.drop(f, "connection_limit")
		return
	}
	f.release = release
	pool := s.Pool(upName)
	if pool == nil {
		q.drop(f, "no_pool")
		return
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
		c, err := net.DialUDP("udp", nil, ra)
		if err != nil {
			pool.Begin(e)
			pool.End(e, true, 0)
			continue
		}
		uc, ep = c, e
		pool.Begin(e)
	}
	if uc == nil {
		s.Counters().TCPErrors.Add(1)
		q.drop(f, "upstream_unavailable")
		return
	}
	q.mu.Lock()
	f.up, f.endpoint, f.pool = uc, ep, pool
	if q.flows[client] == f {
		q.incomplete--
	}
	q.mu.Unlock()
	s.Counters().QUICFlows.Add(1)
	for _, d := range f.pending {
		if n, err := uc.Write(d); err == nil {
			f.in.Add(int64(n))
		}
	}
	f.pending = nil
	q.wg.Add(1)
	go q.pump(f)
}

// pump copies datagrams from the endpoint back to the client.
func (q *quicRelay) pump(f *quicFlow) {
	defer q.wg.Done()
	buf := make([]byte, 65535)
	idle := q.t.cfg.TCP.QUICIdleTimeout.D()
	client := net.UDPAddrFromAddrPort(f.client)
	for {
		_ = f.up.SetReadDeadline(time.Now().Add(idle))
		n, err := f.up.Read(buf)
		if n > 0 {
			f.touch()
			if w, werr := q.pc.WriteTo(buf[:n], client); werr == nil {
				f.out.Add(int64(w))
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && f.idleFor(time.Now()) < idle {
				continue // the client side was active; keep reading
			}
			q.finish(f, "")
			return
		}
	}
}

// drop ends a flow that never reached an endpoint.
func (q *quicRelay) drop(f *quicFlow, reason string) {
	q.finish(f, reason)
}

func (q *quicRelay) finish(f *quicFlow, reason string) {
	q.mu.Lock()
	if q.flows[f.client] != f {
		q.mu.Unlock()
		return
	}
	delete(q.flows, f.client)
	if f.up == nil {
		q.incomplete--
	}
	q.mu.Unlock()
	s := q.t.engine
	in, out := f.in.Load(), f.out.Load()
	if f.up != nil {
		_ = f.up.Close()
		f.pool.End(f.endpoint, false, 0)
		s.Counters().TCPBytesIn.Add(uint64(in))   //nolint:gosec // non-negative
		s.Counters().TCPBytesOut.Add(uint64(out)) //nolint:gosec // non-negative
	}
	if f.release != nil {
		f.release()
	}
	ep := ""
	if f.endpoint != nil {
		ep = f.endpoint.Address
	}
	attrs := []any{"listener", q.t.cfg.Name, "proto", "quic", "client_ip", f.client.Addr().String(), "sni", f.serverName(), "endpoint", ep,
		"bytes_in", in, "bytes_out", out, "duration_ms", float64(time.Since(f.start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
		if reason == "no_route" {
			s.Logs().SecurityEvent(context.Background(), "deny", "tcp_no_route", attrs...)
			if bl := s.Bans(); bl != nil {
				bl.Observe(f.client.Addr(), "tcp_no_route")
			}
		}
	}
	s.Logs().Access.Info("tcp", attrs...)
}

// sweep ends idle flows and flows that never completed a ClientHello.
func (q *quicRelay) sweep() {
	defer q.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-q.done:
			return
		case <-t.C:
		}
		idle := q.t.cfg.TCP.QUICIdleTimeout.D()
		now := time.Now()
		q.mu.Lock()
		var stale []*quicFlow
		for _, f := range q.flows {
			switch {
			case f.up == nil && now.Sub(f.start) > 5*time.Second:
				stale = append(stale, f)
			case f.up != nil && f.idleFor(now) > idle:
				stale = append(stale, f)
			}
		}
		q.mu.Unlock()
		for _, f := range stale {
			if f.up != nil {
				_ = f.up.Close() // the pump finishes the flow
			} else {
				q.finish(f, "hello_incomplete")
			}
		}
	}
}

// open reports flows with an endpoint.
func (q *quicRelay) open() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, f := range q.flows {
		if f.up != nil {
			n++
		}
	}
	return n
}

func (q *quicRelay) shutdown() {
	q.once.Do(func() {
		close(q.done)
		_ = q.pc.Close()
	})
	q.mu.Lock()
	flows := make([]*quicFlow, 0, len(q.flows))
	for _, f := range q.flows {
		flows = append(flows, f)
	}
	q.mu.Unlock()
	for _, f := range flows {
		if f.up != nil {
			_ = f.up.Close()
		} else {
			q.finish(f, "shutdown")
		}
	}
	q.wg.Wait()
}

// serverName is the flow's peeked server name, or "" before the
// ClientHello completed.
func (f *quicFlow) serverName() string {
	if p := f.sni.Load(); p != nil {
		return *p
	}
	return ""
}
