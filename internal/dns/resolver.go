package dns

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// Upstream transports.
const (
	transportPlain = iota // UDP with TCP fallback (host:port)
	transportTLS          // DNS over TLS, RFC 7858 (tls://host:port)
	transportHTTPS        // DNS over HTTPS, RFC 8484 (https://host/path)
	transportQUIC         // DNS over QUIC, RFC 9250 (quic://host:port)
)

// upstreamServer is one parsed upstream.
type upstreamServer struct {
	raw       string
	transport int
	addr      string // host:port for plain and tls
	url       string // for https
	host      string // TLS server name
	// idle holds reusable DNS over TLS connections.
	idle chan net.Conn
	// quic is the reused DNS over QUIC connection, guarded by mu.
	mu   sync.Mutex
	quic *quic.Conn
}

// Resolver forwards queries to upstream servers. Every query goes out
// with a fresh transaction id; plain UDP queries also use a fresh
// socket (random source port); the answer must echo the id and the
// question. Encrypted transports reuse connections.
type Resolver struct {
	servers []*upstreamServer
	timeout time.Duration
	next    atomic.Uint32
	dialer  net.Dialer
	tlsConf *tls.Config
	client  *http.Client
	// Failures counts upstream attempts that did not answer, and
	// Resumed the encrypted connections that resumed a session instead
	// of running a full handshake.
	Failures, Resumed atomic.Uint64
}

// upstreamSessions bounds the session tickets held for encrypted
// upstreams. A resolver has a handful of them, and a ticket is only
// worth keeping while its upstream is still the one configured.
const upstreamSessions = 32

// ParseUpstream validates one upstream string: host:port, tls://host:port,
// quic://host:port or https://host[:port]/path.
func ParseUpstream(s string) (*upstreamServer, error) {
	switch {
	case strings.HasPrefix(s, "tls://"):
		addr := strings.TrimPrefix(s, "tls://")
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" {
			return nil, fmt.Errorf("%q must be tls://host:port", s)
		}
		return &upstreamServer{raw: s, transport: transportTLS, addr: addr, host: host, idle: make(chan net.Conn, 4)}, nil
	case strings.HasPrefix(s, "quic://"):
		addr := strings.TrimPrefix(s, "quic://")
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" {
			return nil, fmt.Errorf("%q must be quic://host:port", s)
		}
		return &upstreamServer{raw: s, transport: transportQUIC, addr: addr, host: host}, nil
	case strings.HasPrefix(s, "https://"):
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.Path == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, fmt.Errorf("%q must be https://host[:port]/path", s)
		}
		return &upstreamServer{raw: s, transport: transportHTTPS, url: s, host: u.Hostname()}, nil
	case strings.Contains(s, "://"):
		return nil, fmt.Errorf("%q: unknown transport (use host:port, tls://, quic:// or https://)", s)
	default:
		host, port, err := net.SplitHostPort(s)
		if err != nil || host == "" || port == "" {
			return nil, fmt.Errorf("%q must be host:port", s)
		}
		return &upstreamServer{raw: s, transport: transportPlain, addr: s, host: host}, nil
	}
}

// NewResolver takes upstream strings (see ParseUpstream) and a per
// attempt timeout; strings are assumed valid (use NewResolverTLS to get
// errors).
func NewResolver(servers []string, timeout time.Duration) *Resolver {
	r, err := NewResolverTLS(servers, timeout, "")
	if err != nil {
		r = &Resolver{timeout: timeout, dialer: net.Dialer{Timeout: timeout}}
	}
	return r
}

// NewResolverTLS builds a resolver; caFile pins the CA of tls:// and
// https:// upstreams (system pool when empty).
func NewResolverTLS(servers []string, timeout time.Duration, caFile string) (*Resolver, error) {
	r := &Resolver{timeout: timeout, dialer: net.Dialer{Timeout: timeout}}
	for _, s := range servers {
		u, err := ParseUpstream(s)
		if err != nil {
			return nil, err
		}
		r.servers = append(r.servers, u)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // configured path
		if err != nil {
			return nil, fmt.Errorf("upstream_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("upstream_ca_file contains no certificates")
		}
		tc.RootCAs = pool
	}
	// One session cache for every encrypted upstream. A reconnect then
	// resumes instead of running a full handshake, which is most of the
	// cost of DoT and DoQ on a resolver that reconnects whenever its
	// idle connection is dropped.
	//
	// Go keys the cache by the server name, so two upstreams never see
	// each other's tickets, and the Go client never sends early data --
	// so the replay window 0-RTT opens is not opened here. The QUIC
	// dialler keeps Allow0RTT false for the same reason.
	tc.ClientSessionCache = tls.NewLRUClientSessionCache(upstreamSessions)
	r.tlsConf = tc
	r.client = &http.Client{Timeout: timeout, Transport: &http.Transport{
		TLSClientConfig: tc, Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConns: 8, MaxIdleConnsPerHost: 4,
		IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: timeout, DisableCompression: true,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") }}
	return r, nil
}

// SetSessionResumption turns the session cache for encrypted upstreams
// on or off. Off means every DoT, DoH and DoQ connection runs a full
// handshake: the reason to want that is an upstream whose tickets are
// broken, or a policy that forbids resumption, not security here -- the
// Go client sends no early data, so nothing is replayable.
func (r *Resolver) SetSessionResumption(on bool) {
	if r.tlsConf == nil {
		return
	}
	switch {
	case on && r.tlsConf.ClientSessionCache == nil:
		r.tlsConf.ClientSessionCache = tls.NewLRUClientSessionCache(upstreamSessions)
	case !on:
		r.tlsConf.ClientSessionCache = nil
	}
	if r.client != nil {
		// The HTTP transport holds the same config, and a ticket already
		// cached would otherwise still be offered.
		r.client.CloseIdleConnections()
	}
}

// SessionResumption reports whether encrypted upstreams keep session
// tickets. It is what a listener's own test asks, and what the status
// reports, rather than each of them reaching into the TLS config.
func (r *Resolver) SessionResumption() bool {
	return r != nil && r.tlsConf != nil && r.tlsConf.ClientSessionCache != nil
}

// Servers lists the upstreams as configured.
func (r *Resolver) Servers() []string {
	out := make([]string, 0, len(r.servers))
	for _, s := range r.servers {
		out = append(out, s.raw)
	}
	return out
}

// Close drops idle encrypted connections.
func (r *Resolver) Close() {
	for _, s := range r.servers {
		if s.idle == nil {
			continue
		}
		for {
			select {
			case c := <-s.idle:
				_ = c.Close()
				continue
			default:
			}
			break
		}
	}
	if r.client != nil {
		r.client.CloseIdleConnections()
	}
}

// Exchange sends query and returns the response with the client's id
// restored. tcp forces TCP (a client that asked over TCP, or a retry
// after truncation); over UDP a truncated answer is retried over TCP.
func (r *Resolver) Exchange(ctx context.Context, query []byte, qEnd int, q Question, tcp bool) ([]byte, error) {
	if len(r.servers) == 0 {
		return nil, errNoUpstream
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	clientID := binary.BigEndian.Uint16(query)
	out := make([]byte, len(query))
	copy(out, query)
	SetID(out, id)
	if !tcp {
		// The forwarded query carries the client's own OPT record, so
		// without this the client picks how large an answer the upstream
		// may send while exchangeUDP can only read one buffer.
		if qh, err := ParseHeader(out); err == nil {
			if _, qEnd, qerr := ParseQuestion(out); qerr == nil {
				ClampEDNSSize(out, qEnd, qh, udpReadBuffer-1)
			}
		}
	}
	start := int(r.next.Add(1) - 1)
	lastErr := errNoUpstream
	for i := 0; i < len(r.servers); i++ {
		server := r.servers[(start+i)%len(r.servers)]
		actx, cancel := context.WithTimeout(ctx, r.timeout)
		var resp []byte
		var err error
		want := id
		switch server.transport {
		case transportTLS:
			resp, err = r.exchangeTLS(actx, server, out)
		case transportQUIC:
			// RFC 9250: the id is zero on the wire, as with DoH.
			SetID(out, 0)
			want = 0
			resp, err = r.exchangeQUIC(actx, server, out)
			SetID(out, id)
		case transportHTTPS:
			// RFC 8484: the id is 0 so responses cache well; the
			// question still has to match.
			SetID(out, 0)
			want = 0
			resp, err = r.exchangeHTTPS(actx, server, out)
			SetID(out, id)
		default:
			if tcp {
				resp, err = r.exchangeTCP(actx, server.addr, out)
			} else {
				resp, err = r.exchangeUDP(actx, server.addr, out)
				switch {
				case errors.Is(err, errUDPOverflow):
					resp, err = r.exchangeTCP(actx, server.addr, out)
				case err == nil:
					if h, herr := ParseHeader(resp); herr == nil && h.Truncated() {
						resp, err = r.exchangeTCP(actx, server.addr, out)
					}
				}
			}
		}
		cancel()
		if err != nil {
			r.Failures.Add(1)
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if !r.matches(resp, want, q) {
			r.Failures.Add(1)
			lastErr = errors.New("dns: answer does not match the question")
			continue
		}
		SetID(resp, clientID)
		return resp, nil
	}
	return nil, lastErr
}

func (r *Resolver) matches(resp []byte, id uint16, q Question) bool {
	h, err := ParseHeader(resp)
	if err != nil || h.ID != id || !h.Response() || h.QDCount != 1 {
		return false
	}
	rq, _, err := ParseQuestion(resp)
	return err == nil && rq == q
}

// udpReadBuffer is what exchangeUDP takes from one datagram; the
// forwarded query's OPT record is clamped just below it.
const udpReadBuffer = 4096

// errUDPOverflow says the answer filled the read buffer, so bytes may
// have been chopped off: the query is asked again over TCP.
var errUDPOverflow = errors.New("dns: udp answer larger than the read buffer")

func (r *Resolver) exchangeUDP(ctx context.Context, server string, query []byte) ([]byte, error) {
	c, err := r.dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, udpReadBuffer)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= headerLen && binary.BigEndian.Uint16(buf) == binary.BigEndian.Uint16(query) {
			if n == len(buf) {
				// The kernel chops a datagram larger than the buffer and
				// reports no error at all, and the header, the id and the
				// question all survive in the first bytes, so the checks
				// above accept the stump. It would then be cached and
				// served to every later client for the TTL. Ask again
				// over TCP instead.
				return nil, errUDPOverflow
			}
			return append([]byte(nil), buf[:n]...), nil
		}
		// A stray datagram for another id: keep waiting for ours.
	}
}

func (r *Resolver) exchangeTCP(ctx context.Context, server string, query []byte) ([]byte, error) {
	c, err := r.dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := WriteTCP(c, query); err != nil {
		return nil, err
	}
	return ReadTCP(c, MaxMessage)
}

// exchangeTLS sends over DNS over TLS, reusing an idle connection when
// one is available and dialling otherwise; a failed connection is
// dropped and the query retried once on a fresh one.
func (r *Resolver) exchangeTLS(ctx context.Context, s *upstreamServer, query []byte) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var c net.Conn
		select {
		case c = <-s.idle:
		default:
			raw, err := r.dialer.DialContext(ctx, "tcp", s.addr)
			if err != nil {
				return nil, err
			}
			tc := r.tlsConf.Clone()
			tc.ServerName = s.host
			tc.NextProtos = []string{"dot"}
			tconn := tls.Client(raw, tc)
			if dl, ok := ctx.Deadline(); ok {
				_ = tconn.SetDeadline(dl)
			}
			if err := tconn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			if tconn.ConnectionState().DidResume {
				r.Resumed.Add(1)
			}
			c = tconn
			attempt++ // a fresh connection is not retried
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		if err := WriteTCP(c, query); err != nil {
			_ = c.Close()
			continue
		}
		resp, err := ReadTCP(c, MaxMessage)
		if err != nil {
			_ = c.Close()
			continue
		}
		_ = c.SetDeadline(time.Time{})
		select {
		case s.idle <- c:
		default:
			_ = c.Close()
		}
		return resp, nil
	}
	return nil, errors.New("dns: tls upstream connection failed")
}

// exchangeHTTPS posts the query as application/dns-message.
func (r *Resolver) exchangeHTTPS(ctx context.Context, s *upstreamServer, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "xproxy-dns/1")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxMessage+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dns: https upstream answered HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/dns-message") {
		return nil, fmt.Errorf("dns: https upstream answered %q", ct)
	}
	if len(body) < headerLen || len(body) > MaxMessage {
		return nil, errors.New("dns: https upstream answer size")
	}
	return body, nil
}

// WriteTCP writes a length prefixed message.
func WriteTCP(w io.Writer, msg []byte) error {
	if len(msg) > MaxMessage {
		return errors.New("dns: message too large")
	}
	buf := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg))) //nolint:gosec // bounded above
	_, err := w.Write(append(buf, msg...))
	return err
}

// ReadTCP reads one length prefixed message of at most limit bytes.
func ReadTCP(rd io.Reader, limit int) ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(rd, lb[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n < headerLen || n > limit {
		return nil, errors.New("dns: bad message length")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(rd, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
