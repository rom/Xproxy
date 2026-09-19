package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/upstream"
)

// tcpServer serves a kind: tcp listener: connections are routed by the
// server name of a peeked ClientHello and spliced to an upstream endpoint
// without terminating TLS. Bans and connection limits apply at accept
// through the shared limiter (the listener is wrapped like every other).
type tcpServer struct {
	s    *Server
	cfg  config.Listener
	ln   net.Listener
	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	once sync.Once
	quic *quicRelay // when the listener relays QUIC too
	cons map[net.Conn]struct{}
	done chan struct{}
}

const helloPeekTimeout = 10 * time.Second

func newTCPServer(s *Server, cfg config.Listener, ln net.Listener) *tcpServer {
	return &tcpServer{s: s, cfg: cfg, ln: ln, cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
}

func (t *tcpServer) serve() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			var opErr *net.OpError
			if errors.As(err, &opErr) && strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if t.open.Add(1) > int64(t.cfg.TCP.MaxConnections) {
			t.open.Add(-1)
			t.s.stats.TCPRejected.Add(1)
			_ = c.Close()
			continue
		}
		if !t.admit(c) {
			// Closed between the accept and the admission (a reload
			// retired the listener); the connection is dropped.
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.wg.Done()
			defer t.open.Add(-1)
			defer t.untrack(c)
			t.handle(c)
		}()
	}
}

// admit registers a connection and its goroutine unless the server is
// shutting down; the wait group is only added to under the same mutex
// that closes done, so shutdown's Wait cannot race a late Add.
func (t *tcpServer) admit(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return false
	default:
	}
	t.cons[c] = struct{}{}
	t.wg.Add(1)
	return true
}

func (t *tcpServer) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

// shutdown stops accepting, waits for connections up to ctx, then closes
// the rest.
func (t *tcpServer) shutdown(ctx context.Context) {
	t.once.Do(func() {
		t.mu.Lock()
		close(t.done)
		t.mu.Unlock()
		_ = t.ln.Close()
	})
	if t.quic != nil {
		t.quic.shutdown()
	}
	finished := make(chan struct{})
	go func() { t.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
		t.mu.Lock()
		for c := range t.cons {
			_ = c.Close()
		}
		t.mu.Unlock()
		<-finished
	}
}

// resolve picks the upstream for a server name.
func (t *tcpServer) resolve(sni string) (string, bool) {
	tc := t.cfg.TCP
	if sni != "" {
		for _, r := range tc.Routes {
			for _, pat := range r.SNI {
				if matchSNI(pat, sni) {
					return r.Upstream, true
				}
			}
		}
	}
	if tc.Default != "" {
		return tc.Default, true
	}
	return "", false
}

func matchSNI(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(name, suffix) && len(name) > len(suffix) && !strings.Contains(strings.TrimSuffix(name, suffix), ".")
	}
	return pattern == name
}

func (t *tcpServer) handle(client net.Conn) {
	s := t.s
	start := time.Now()
	s.stats.TCPConnections.Add(1)
	clientIP := addrOf(client.RemoteAddr().String())
	// Peek the first record without terminating TLS. Non-TLS traffic and
	// hellos without a name take the default route.
	_ = client.SetReadDeadline(time.Now().Add(helloPeekTimeout))
	buf := make([]byte, 0, 4096)
	sni := ""
	for {
		tmp := make([]byte, 4096)
		n, err := client.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			var perr error
			sni, perr = netutil.ClientHelloSNI(buf)
			if perr == nil || errors.Is(perr, netutil.ErrNotTLS) {
				break
			}
			if len(buf) > 16<<10 { // no single ClientHello is this large
				sni = ""
				break
			}
		}
		if err != nil {
			t.finish(client, clientIP, start, sni, "", "", "read_error", 0, 0)
			return
		}
	}
	_ = client.SetReadDeadline(time.Time{})
	upName, ok := t.resolve(sni)
	if !ok {
		s.stats.TCPRejected.Add(1)
		t.finish(client, clientIP, start, sni, "", "", "no_route", 0, 0)
		return
	}
	pool := s.rt.Load().pools[upName]
	if pool == nil {
		t.finish(client, clientIP, start, sni, upName, "", "no_pool", 0, 0)
		return
	}
	var ep *upstream.Endpoint
	var up net.Conn
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(clientIP.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: pool.Cfg.Timeouts.Connect.D()}
		c, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true)
			s.logs.Error.Warn("tcp upstream dial failed", "listener", t.cfg.Name, "endpoint", e.Address, "err", err.Error())
			continue
		}
		ep, up = e, c
		break
	}
	if up == nil {
		s.stats.TCPErrors.Add(1)
		t.finish(client, clientIP, start, sni, upName, "", "upstream_unavailable", 0, 0)
		return
	}
	if t.cfg.TCP.ProxyProtocol {
		if _, err := up.Write(proxyV2Header(client.RemoteAddr(), client.LocalAddr())); err != nil {
			pool.End(ep, true)
			_ = up.Close()
			t.finish(client, clientIP, start, sni, upName, ep.Address, "upstream_write", 0, 0)
			return
		}
	}
	if _, err := up.Write(buf); err != nil {
		pool.End(ep, true)
		_ = up.Close()
		t.finish(client, clientIP, start, sni, upName, ep.Address, "upstream_write", 0, 0)
		return
	}
	in, out := splice(client, up, t.cfg.TCP.IdleTimeout.D())
	pool.End(ep, false)
	s.stats.TCPBytesIn.Add(uint64(in + int64(len(buf)))) //nolint:gosec // non-negative
	s.stats.TCPBytesOut.Add(uint64(out))                 //nolint:gosec // non-negative
	t.finish(client, clientIP, start, sni, upName, ep.Address, "", in+int64(len(buf)), out)
}

func (t *tcpServer) finish(client net.Conn, ip netip.Addr, start time.Time, sni, up, endpoint, reason string, in, out int64) {
	_ = client.Close()
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "sni", sni, "upstream", up, "endpoint", endpoint,
		"bytes_in", in, "bytes_out", out, "duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
		if reason == "no_route" {
			t.s.logs.SecurityEvent(context.Background(), "deny", "tcp_no_route", append([]any{"proto", "tcp"}, attrs...)...)
			if bl := t.s.bans.Load(); bl != nil {
				bl.Observe(ip, "tcp_no_route")
			}
		}
	}
	t.s.logs.Access.Info("tcp", attrs...)
}

// splice copies in both directions until one side ends or the idle
// timeout passes with no bytes either way. It returns bytes client to
// upstream and upstream to client.
func splice(client, up net.Conn, idle time.Duration) (in, out int64) {
	var wg sync.WaitGroup
	copyDir := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			r, err := src.Read(buf)
			if r > 0 {
				w, werr := dst.Write(buf[:r])
				*n += int64(w)
				if werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		// Half close where possible so the other direction can drain.
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go copyDir(up, client, &in)
	go copyDir(client, up, &out)
	wg.Wait()
	_ = client.Close()
	_ = up.Close()
	return in, out
}

// proxyV2Header builds a PROXY protocol version 2 header for a TCP
// connection (client and proxy side addresses).
func proxyV2Header(remote, local net.Addr) []byte {
	sig := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	r, rok := remote.(*net.TCPAddr)
	l, lok := local.(*net.TCPAddr)
	if !rok || !lok {
		return append(sig, 0x20, 0x00, 0x00, 0x00) // LOCAL command, unspecified
	}
	hdr := append([]byte{}, sig...)
	hdr = append(hdr, 0x21) // version 2, PROXY command
	rip, lip := r.IP.To4(), l.IP.To4()
	if rip != nil && lip != nil {
		hdr = append(hdr, 0x11) // TCP over IPv4
		hdr = binary.BigEndian.AppendUint16(hdr, 12)
		hdr = append(hdr, rip...)
		hdr = append(hdr, lip...)
	} else {
		hdr = append(hdr, 0x21) // TCP over IPv6
		hdr = binary.BigEndian.AppendUint16(hdr, 36)
		hdr = append(hdr, r.IP.To16()...)
		hdr = append(hdr, l.IP.To16()...)
	}
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(r.Port)) //nolint:gosec // port range
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(l.Port)) //nolint:gosec // port range
	return hdr
}

// addrOf parses the host part of a host:port string.
func addrOf(hostport string) netip.Addr {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
