// Package ntske serves a kind: ntske listener: NTS key establishment
// (RFC 8915) on TCP 4460.
//
// NTS has two halves on two ports, and they are different things. The
// time exchanges are UDP 123 with authentication carried in extension
// fields, which is what the kind: ntp listener handles. The key
// establishment is TLS on TCP 4460 with the ALPN "ntske/1": the client
// authenticates the server, the two derive the NTS keys from the TLS
// exporter, and the server hands back cookies the time exchanges then
// use. It happens rarely -- once, and again when the cookies run low --
// and it is where all the cryptography is.
//
// This listener relays it rather than terminating it, and that is a
// decision rather than a limitation. Terminating NTS key establishment
// honestly means deriving the keys from the TLS exporter, holding the
// same cookie keys the time servers hold, rotating them with an overlap
// so a cookie issued before a rotation still works after it, and
// recovering all of that across a restart. An implementation that faked
// any part would be telling clients their time was authenticated when
// nobody had checked -- so instead this listener does the part a relay
// can do honestly: it reads the one thing a TLS handshake shows in the
// clear, refuses a connection that is not an NTS client, bounds the
// handshakes in flight, and hands the rest to the key establishment
// server whose keys they are.
package ntske

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	wire "github.com/rom/xproxy/internal/ntp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/relay"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

// The bounds on the peek, which is all this listener reads.
const (
	// peekSettle is how long a connection that has said nothing is
	// given, and peekHard the whole peek: a ClientHello split across
	// packets is ordinary, a client that says nothing is not an NTS
	// client.
	peekSettle = 2 * time.Second
	peekHard   = 5 * time.Second
	// maxHello bounds the bytes read while looking for the ClientHello.
	maxHello = 16 << 10
)

// server is one kind: ntske listener.
type server struct {
	host proxy.Host
	cfg  config.Listener
	k    *config.NTSKEListener
	ln   net.Listener

	allow, deny []netip.Prefix
	names       []string
	// handshakes bounds the peeks and dials in flight, because the
	// expensive part of NTS is the handshake and a flood of them is the
	// denial of service this port has.
	handshakes chan struct{}

	open atomic.Int64
	mu   sync.Mutex
	cons map[net.Conn]struct{}
	// sessions is what a shutdown waits for. It is acceptgroup rather than
	// a bare WaitGroup because the check and the Add have to happen under
	// one lock that the close also takes: the engine closes the front
	// socket before it calls Shutdown, which leaves the accept goroutine
	// between a connection it has accepted and the Add it has not reached.
	// The race detector found this one through test/shutdown.
	sessions acceptgroup.Group
	done     chan struct{}
	once     sync.Once
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener) (*server, error) {
	k := cfg.NTSKE
	s := &server{host: host, cfg: cfg, k: k, ln: ln,
		cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	for _, list := range []struct {
		in  []string
		out *[]netip.Prefix
	}{{k.AllowClients, &s.allow}, {k.DenyClients, &s.deny}} {
		for _, c := range list.in {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, err
			}
			*list.out = append(*list.out, p.Masked())
		}
	}
	for _, n := range k.ServerNames {
		s.names = append(s.names, strings.ToLower(n))
	}
	n := k.MaxConcurrentHandshakes
	if n <= 0 {
		n = 32
	}
	s.handshakes = make(chan struct{}, n)
	return s, nil
}

func (s *server) maxConnections() int {
	if s.k.MaxConnections > 0 {
		return s.k.MaxConnections
	}
	return 256
}

func (s *server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if s.open.Add(1) > int64(s.maxConnections()) {
			s.open.Add(-1)
			s.host.Counters().NTSKERejected.Add(1)
			s.host.Counters().Refuse("ntske", "max_connections")
			_ = c.Close()
			continue
		}
		if !s.track(c) {
			s.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer s.sessions.Leave()
			defer s.open.Add(-1)
			defer s.untrack(c)
			defer safe.Guard("ntske session")
			s.handle(c)
		}()
	}
}

func (s *server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessions.Enter() {
		return false
	}
	s.cons[c] = struct{}{}
	return true
}

func (s *server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.cons, c)
	s.mu.Unlock()
}

// handle peeks one connection and relays it.
func (s *server) handle(client net.Conn) {
	c := s.host.Counters()
	start := time.Now()
	c.NTSKESessions.Add(1)
	ip := netutil.AddrOf(client.RemoteAddr().String())
	defer func() { _ = client.Close() }()
	if bl := s.host.Bans(); bl != nil && bl.Banned(ip) {
		c.Refuse("ntske", "banned")
		return
	}
	if !s.clientAllowed(ip) {
		s.deny_(ip, "client_not_allowed", "")
		s.log(ip, start, "", nil, "client_not_allowed", 0, 0)
		return
	}
	// The handshake slot. A client that cannot get one is refused
	// rather than queued: a queue here is a queue of TLS handshakes,
	// which is the thing being bounded.
	select {
	case s.handshakes <- struct{}{}:
		defer func() { <-s.handshakes }()
	case <-time.After(time.Second):
		c.NTSKEHandshakeLimited.Add(1)
		s.deny_(ip, "handshake_limit", "")
		s.log(ip, start, "", nil, "handshake_limit", 0, 0)
		return
	}
	name, protos, peeked, reason := s.peek(client)
	if reason != "" {
		s.deny_(ip, reason, name)
		s.log(ip, start, name, protos, reason, 0, 0)
		return
	}
	if s.k.ALPNRequired() && !offers(protos, wire.ALPN) {
		// The one check a relay can make from the handshake alone, and
		// the reason this listener is worth having: a connection to 4460
		// that does not offer ntske/1 is not an NTS client, whatever
		// else it is.
		c.NTSKENotNTS.Add(1)
		s.deny_(ip, "alpn_not_offered", strings.Join(protos, ","))
		s.log(ip, start, name, protos, "alpn_not_offered", 0, 0)
		return
	}
	if !s.nameAllowed(name) {
		s.deny_(ip, "server_name_not_allowed", name)
		s.log(ip, start, name, protos, "server_name_not_allowed", 0, 0)
		return
	}
	up, ep, pool, err := s.dial(ip)
	if err != nil {
		c.NTSKEUpstreamFailed.Add(1)
		s.host.Logs().Error.Warn("ntske could not reach a key establishment server",
			"listener", s.cfg.Name, "error", err.Error())
		s.log(ip, start, name, protos, "upstream_unavailable", 0, 0)
		return
	}
	defer func() {
		_ = up.Close()
		pool.End(ep, false, 0)
	}()
	// The bytes already read are the start of the handshake, so they go
	// first and unchanged: this listener never rewrites a handshake.
	if len(peeked) > 0 {
		if _, err := up.Write(peeked); err != nil {
			s.log(ip, start, name, protos, "upstream_write", 0, 0)
			return
		}
	}
	c.NTSKERelayed.Add(1)
	limits := relay.Limits{Idle: s.idle(), BytesIn: s.k.MaxBytes, BytesOut: s.k.MaxBytes}
	in, out, end := relay.Bounded(client, up, limits, nil, nil)
	s.log(ip, start, name, protos, end, in, out)
}

// peek reads the ClientHello and returns the server name and the
// application protocols it offers.
func (s *server) peek(client net.Conn) (name string, protos []string, buf []byte, reason string) {
	hard := time.Now().Add(peekHard)
	if d := s.k.HandshakeTimeout.D(); d > 0 {
		hard = time.Now().Add(d)
	}
	buf = make([]byte, 0, 4096)
	for {
		deadline := time.Now().Add(peekSettle)
		if len(buf) > 0 || deadline.After(hard) {
			deadline = hard
		}
		_ = client.SetReadDeadline(deadline)
		tmp := make([]byte, 4096)
		n, err := client.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			sni, serr := netutil.ClientHelloSNI(buf)
			alpn, aerr := netutil.ClientHelloALPN(buf)
			switch {
			case errors.Is(serr, netutil.ErrNotTLS) || errors.Is(aerr, netutil.ErrNotTLS):
				// This port carries one protocol, and it starts with a
				// TLS ClientHello. Anything else is not a client that
				// took a wrong turn; it is a scan.
				return "", nil, buf, "not_tls"
			case serr == nil && aerr == nil:
				_ = client.SetReadDeadline(time.Time{})
				return sni, alpn, buf, ""
			}
			if len(buf) > maxHello {
				return "", nil, buf, "hello_too_large"
			}
		}
		if err != nil {
			if len(buf) == 0 {
				return "", nil, buf, "no_hello"
			}
			return "", nil, buf, "incomplete_hello"
		}
	}
}

func offers(protos []string, want string) bool {
	for _, p := range protos {
		if p == want {
			return true
		}
	}
	return false
}

func (s *server) clientAllowed(a netip.Addr) bool {
	for _, p := range s.deny {
		if p.Contains(a) {
			return false
		}
	}
	if len(s.allow) == 0 {
		return true
	}
	for _, p := range s.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// nameAllowed applies the server name list. An empty list accepts any
// name, including a handshake with none -- which is legal, and which a
// deployment fronting one key establishment server does not need.
func (s *server) nameAllowed(name string) bool {
	if len(s.names) == 0 {
		return true
	}
	name = strings.ToLower(name)
	for _, n := range s.names {
		if n == name {
			return true
		}
		if strings.HasPrefix(n, "*.") && strings.HasSuffix(name, n[1:]) &&
			len(name) > len(n)-1 && !strings.Contains(strings.TrimSuffix(name, n[1:]), ".") {
			return true
		}
	}
	return false
}

func (s *server) idle() time.Duration {
	if d := s.k.IdleTimeout.D(); d > 0 {
		return d
	}
	return 30 * time.Second
}

// dial opens a connection to a key establishment server.
func (s *server) dial(client netip.Addr) (net.Conn, *upstream.Endpoint, *upstream.Pool, error) {
	pool := s.host.Pool(s.k.Upstream)
	if pool == nil {
		return nil, nil, nil, errors.New("the upstream has no pool")
	}
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(client.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			continue
		}
		return conn, e, pool, nil
	}
	return nil, nil, nil, errors.New("no reachable endpoint")
}

// deny_ records a refusal.
func (s *server) deny_(ip netip.Addr, reason, detail string) {
	s.host.Counters().NTSKERefused.Add(1)
	s.host.Counters().Refuse("ntske", reason)
	if !s.k.Alerts() {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "proto", "ntske", "client_ip", ip.String(), "detail", reason}
	if detail != "" {
		attrs = append(attrs, "reason_detail", detail)
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", "ntske_denied", attrs...)
	if bl := s.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "ntske_denied")
	}
}

func (s *server) log(ip netip.Addr, start time.Time, name string, protos []string, end string, in, out int64) {
	if !s.k.LogSessions {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(),
		"server_name", name, "alpn", strings.Join(protos, ","),
		"bytes_in", in, "bytes_out", out,
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if end != "" {
		attrs = append(attrs, "closed", end)
	}
	s.host.Logs().Access.Info("ntske", attrs...)
}

func (s *server) shutdown(ctx context.Context) {
	s.once.Do(func() {
		close(s.done)
		_ = s.ln.Close()
	})
	s.sessions.Close()
	s.sessions.Wait(ctx)
	if ctx.Err() == nil {
		return
	}
	s.mu.Lock()
	for c := range s.cons {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.sessions.Wait(context.Background())
}
