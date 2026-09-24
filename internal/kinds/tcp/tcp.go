package tcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/relay"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/streamscan"
	"github.com/rom/xproxy/internal/upstream"
)

// server serves a kind: tcp listener: connections are routed by the
// server name of a peeked ClientHello and spliced to an upstream endpoint
// without terminating TLS. Bans and connection limits apply at accept
// through the shared limiter (the listener is wrapped like every other).
type server struct {
	engine proxy.Host
	cfg    config.Listener
	ln     net.Listener
	open   atomic.Int64
	wg     sync.WaitGroup
	mu     sync.Mutex
	once   sync.Once
	quic   *quicRelay        // when the listener relays QUIC too
	yara   *streamscan.Guard // when the listener scans the bytes it relays
	cons   map[net.Conn]struct{}
	done   chan struct{}
	// allowDst are the destinations an intercepted connection may be
	// relayed to, parsed once; see intercept.go.
	allowDst []netip.Prefix
}

const (
	// helloPeekTimeout bounds the whole peek: a client that has started
	// sending a ClientHello and never finishes it holds a connection,
	// so there is a hard stop.
	helloPeekTimeout = 10 * time.Second
	// helloSettleTimeout is how long a connection that has sent nothing
	// at all is waited on before it is taken to be a protocol where the
	// server speaks first.
	//
	// Plenty of what a layer 4 listener carries is server-first: SSH
	// sends its banner before the client says anything, and so do SMTP,
	// FTP, MySQL and PostgreSQL. Waiting for a ClientHello from such a
	// client is waiting for something that will never come while the
	// client waits for a greeting that this proxy has not gone to fetch
	// -- a deadlock broken only by the hard bound above, and then by an
	// error. So silence is an answer: after this, the connection is
	// relayed on the default route with nothing peeked.
	helloSettleTimeout = time.Second
)

func newServer(engine proxy.Host, cfg config.Listener, ln net.Listener) (*server, error) {
	t := &server{engine: engine, cfg: cfg, ln: ln, cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	if cfg.TCP != nil {
		for _, c := range cfg.TCP.AllowDestinations {
			pfx, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, err
			}
			t.allowDst = append(t.allowDst, pfx)
		}
	}
	if cfg.TCP != nil && cfg.TCP.YARA != nil {
		g, err := streamscan.New(cfg.TCP.YARA)
		if err != nil {
			return nil, err
		}
		t.yara = g
	}
	return t, nil
}

func (t *server) serve() {
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
			t.engine.Counters().TCPRejected.Add(1)
			t.engine.Counters().Refuse("tcp", "max_connections")
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
			// Registered last, so it unwinds first: a panic parsing a
			// client's first bytes ends this connection, not the process.
			defer safe.Guard("layer 4 connection")
			t.handle(c)
		}()
	}
}

// admit registers a connection and its goroutine unless the server is
// shutting down; the wait group is only added to under the same mutex
// that closes done, so shutdown's Wait cannot race a late Add.
func (t *server) admit(c net.Conn) bool {
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

func (t *server) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

// shutdown stops accepting, waits for connections up to ctx, then closes
// the rest.
func (t *server) shutdown(ctx context.Context) {
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
func (t *server) resolve(sni string) (string, bool) {
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

func (t *server) handle(client net.Conn) {
	s := t.engine
	start := time.Now()
	s.Counters().TCPConnections.Add(1)
	clientIP := addrOf(client.RemoteAddr().String())
	// Peek the first record without terminating TLS. Non-TLS traffic and
	// hellos without a name take the default route.
	hard := time.Now().Add(helloPeekTimeout)
	buf := make([]byte, 0, 4096)
	sni := ""
	for {
		// A default-only connection that has said nothing yet is given the
		// settle timeout. Once it has started speaking it gets the hard
		// bound, because a ClientHello split across packets is ordinary.
		deadline := hard
		// Silence is only enough to select the default when there are no
		// SNI routes to bypass. With routes configured, wait for the hard
		// bound so a delayed ClientHello cannot be sent to the default.
		if len(t.cfg.TCP.Routes) == 0 {
			deadline = time.Now().Add(helloSettleTimeout)
		}
		if len(buf) > 0 || deadline.After(hard) {
			deadline = hard
		}
		_ = client.SetReadDeadline(deadline)
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
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && len(buf) == 0 {
				// Nothing at all: a server-first protocol. Relay it.
				break
			}
			t.finish(client, clientIP, start, sni, "", "", "read_error", 0, 0)
			return
		}
	}
	_ = client.SetReadDeadline(time.Time{})
	if t.cfg.TCP.OriginalDestination {
		t.intercepted(client, clientIP, start, sni, buf)
		return
	}
	upName, ok := t.resolve(sni)
	if !ok {
		s.Counters().TCPRejected.Add(1)
		s.Counters().Refuse("tcp", "no_route")
		t.finish(client, clientIP, start, sni, "", "", "no_route", 0, 0)
		return
	}
	pool := s.Pool(upName)
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
		network, address := e.Dial()
		c, err := d.DialContext(context.Background(), network, address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			s.Logs().Error.Warn("tcp upstream dial failed", "listener", t.cfg.Name, "endpoint", e.Address, "err", err.Error())
			continue
		}
		ep, up = e, c
		break
	}
	if up == nil {
		s.Counters().TCPErrors.Add(1)
		t.finish(client, clientIP, start, sni, upName, "", "upstream_unavailable", 0, 0)
		return
	}
	if t.cfg.TCP.ProxyProtocol {
		if _, err := up.Write(proxyV2Header(client.RemoteAddr(), client.LocalAddr())); err != nil {
			pool.End(ep, true, 0)
			_ = up.Close()
			t.finish(client, clientIP, start, sni, upName, ep.Address, "upstream_write", 0, 0)
			return
		}
	}
	if _, err := up.Write(buf); err != nil {
		pool.End(ep, true, 0)
		_ = up.Close()
		t.finish(client, clientIP, start, sni, upName, ep.Address, "upstream_write", 0, 0)
		return
	}
	in, out, end := t.spliceScanned(client, up, clientIP, sni)
	pool.End(ep, false, 0)
	s.Counters().TCPBytesIn.Add(uint64(in + int64(len(buf)))) //nolint:gosec // non-negative
	s.Counters().TCPBytesOut.Add(uint64(out))                 //nolint:gosec // non-negative
	if end != "" {
		s.Counters().TCPBounded.Add(1)
	}
	t.finish(client, clientIP, start, sni, upName, ep.Address, end, in+int64(len(buf)), out)
}

func (t *server) finish(client net.Conn, ip netip.Addr, start time.Time, sni, up, endpoint, reason string, in, out int64) {
	_ = client.Close()
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "sni", sni, "upstream", up, "endpoint", endpoint,
		"bytes_in", in, "bytes_out", out, "duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
		if reason == "no_route" {
			t.engine.Logs().SecurityEvent(context.Background(), "deny", "tcp_no_route", append([]any{"proto", "tcp"}, attrs...)...)
			if bl := t.engine.Bans(); bl != nil {
				bl.Observe(ip, "tcp_no_route")
			}
		}
	}
	t.engine.Logs().Access.Info("tcp", attrs...)
}

// spliceScanned relays a connection, giving each direction to the YARA
// scanner when one is configured. The bytes forwarded are the bytes
// scanned: nothing is held back waiting for a verdict, because a stream
// cannot be paused without the peer noticing, so what a match decides
// is whether the connection continues.
func (t *server) spliceScanned(client, up net.Conn, ip netip.Addr, sni string) (in, out int64, end string) {
	limits := t.relayLimits()
	if t.yara == nil {
		return relay.Bounded(client, up, limits, nil, nil)
	}
	toUpstream := t.yara.Stream("client")
	toClient := t.yara.Stream("upstream")
	var closed atomic.Bool
	watch := func(s *streamscan.Stream) func([]byte) bool {
		if s == nil {
			return nil
		}
		return func(b []byte) bool {
			t.engine.Counters().YARAScanned.Add(uint64(len(b))) //nolint:gosec // non-negative
			if !s.Feed(b) {
				return true
			}
			if !t.yaraReport(s, ip, sni) {
				return true
			}
			if closed.CompareAndSwap(false, true) {
				_ = client.Close()
				_ = up.Close()
			}
			return false
		}
	}
	return relay.Bounded(client, up, limits, watch(toUpstream), watch(toClient))
}

// proxyV2Header is netutil.ProxyV2Header under the name the engine has
// always used for it.
func proxyV2Header(remote, local net.Addr) []byte {
	return netutil.ProxyV2Header(remote, local)
}

// addrOf parses the host part of a host:port string.
// addrOf is netutil.AddrOf under the name the engine has always used
// for it.
func addrOf(hostport string) netip.Addr { return netutil.AddrOf(hostport) }
