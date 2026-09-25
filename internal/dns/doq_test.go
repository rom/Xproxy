package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/testutil"
)

// doqServer starts a DoQ listener in front of a fake upstream and
// returns its address and the server.
func doqServer(t *testing.T, p *Policy) (string, *Server, *DoQServer, *limits.ConnLimiter) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "dns.test")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New("doq", nil, nil, 100, 8, p, Hooks{})
	s.Encrypted = true
	limiter := limits.NewConnLimiter(100, 100)
	q, err := NewDoQ(s, pc, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, 30*time.Second, 64, limiter)
	if err != nil {
		t.Fatal(err)
	}
	q.Serve()
	t.Cleanup(func() { _ = q.Close() })
	return q.Addr().String(), s, q, limiter
}

// doqQuery sends one query over a fresh QUIC connection, the way a
// client does, and returns the answer.
func doqQuery(t *testing.T, addr string, query []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNDoQ},
		ServerName:         "dns.test",
	}, &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(out, uint16(len(query))) //nolint:gosec // test input
	copy(out[2:], query)
	if _, err := st.Write(out); err != nil {
		return nil, err
	}
	if err := st.Close(); err != nil {
		return nil, err
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	var length [2]byte
	if _, err := io.ReadFull(st, length[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(st, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// TestDoQEndToEnd: a query over QUIC is answered like any other, and
// the answer carries the zero id RFC 9250 requires.
func TestDoQEndToEnd(t *testing.T) {
	up := newFakeUpstream(t)
	p := &Policy{Resolver: NewResolver([]string{up.addr()}, time.Second), MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute}
	addr, s, q, _ := doqServer(t, p)

	query := mustQuery(t, 0, "a.example.test", TypeA)
	resp, err := doqQuery(t, addr, query)
	if err != nil {
		t.Fatalf("doq query: %v", err)
	}
	h, err := ParseHeader(resp)
	if err != nil || !h.Response() || h.Rcode() != RcodeNoError {
		t.Fatalf("answer header: %+v %v", h, err)
	}
	if h.ID != 0 {
		t.Fatalf("answer id %d, want 0 (RFC 9250 section 4.2.1)", h.ID)
	}
	if got, _, err := ParseQuestion(resp); err != nil || got.Name != "a.example.test" {
		t.Fatalf("answer question %+v %v", got, err)
	}
	if st := s.Status(); st.QueriesDoQ != 1 || st.Queries != 1 {
		t.Fatalf("status = %+v", st)
	}
	if q.Streams.Load() != 1 || q.Conns.Load() != 1 {
		t.Fatalf("streams %d conns %d", q.Streams.Load(), q.Conns.Load())
	}
	// A second query on a second connection, to prove the listener
	// keeps working after a connection closes.
	if _, err := doqQuery(t, addr, mustQuery(t, 0, "b.example.test", TypeA)); err != nil {
		t.Fatalf("second query: %v", err)
	}
}

func TestDoQConnectionAdmission(t *testing.T) {
	addr, _, q, limiter := doqServer(t, &Policy{})
	if q.tr.VerifySourceAddress == nil || !q.tr.VerifySourceAddress(q.Addr()) {
		t.Fatal("DoQ transport does not require source address validation")
	}
	if q.tr.ConnContext == nil {
		t.Fatal("DoQ transport has no connection admission callback")
	}

	limiter.SetLimits(1, 1)
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53000}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := q.tr.ConnContext(ctx, &quic.ClientInfo{RemoteAddr: remote, AddrVerified: true}); err != nil {
		t.Fatalf("first connection from %s: %v", addr, err)
	}
	if _, err := q.tr.ConnContext(context.Background(), &quic.ClientInfo{RemoteAddr: remote, AddrVerified: true}); err == nil {
		t.Fatal("second connection bypassed the per-IP limit")
	}
	if got := limiter.Rejected.Load(); got != 1 {
		t.Fatalf("rejected connections = %d, want 1", got)
	}
	cancel()
	for deadline := time.Now().Add(time.Second); limiter.Open() != 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if got := limiter.Open(); got != 0 {
		t.Fatalf("connections after context cancellation = %d, want 0", got)
	}

	limiter.Banned = func(netip.Addr) bool { return true }
	if _, err := q.tr.ConnContext(context.Background(), &quic.ClientInfo{RemoteAddr: remote, AddrVerified: true}); err == nil {
		t.Fatal("banned connection was admitted")
	}
}

// TestDoQMalformed: the stream parser runs on bytes from anyone who can
// reach the port.
func TestDoQMalformed(t *testing.T) {
	up := newFakeUpstream(t)
	p := &Policy{Resolver: NewResolver([]string{up.addr()}, time.Second), MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute}
	addr, _, _, _ := doqServer(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, c := range []struct {
		name string
		send []byte
	}{
		{"no length", []byte{}},
		{"half a length", []byte{0x00}},
		{"a length with no message", []byte{0x00, 0x20}},
		{"a message shorter than a header", []byte{0x00, 0x04, 1, 2, 3, 4}},
		{"a length of zero", []byte{0x00, 0x00}},
		{"a truncated message", append([]byte{0x00, 0x40}, make([]byte, 12)...)},
	} {
		conn, err := quic.DialAddr(ctx, addr, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{ALPNDoQ},
			ServerName:         "dns.test",
		}, &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("%s: dial: %v", c.name, err)
		}
		st, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("%s: stream: %v", c.name, err)
		}
		_, _ = st.Write(c.send)
		_ = st.Close()
		_ = st.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, _ := st.Read(make([]byte, 64)); n > 0 {
			t.Errorf("%s: the server answered %d bytes", c.name, n)
		}
		_ = conn.CloseWithError(0, "")
	}
}

// TestDoQWrongALPN: a client that does not say it speaks DoQ does not
// get a DoQ connection. The ALPN is the only thing separating this from
// HTTP/3 on the same port.
func TestDoQWrongALPN(t *testing.T) {
	up := newFakeUpstream(t)
	p := &Policy{Resolver: NewResolver([]string{up.addr()}, time.Second), MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute}
	addr, _, _, _ := doqServer(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
		ServerName:         "dns.test",
	}, &quic.Config{HandshakeIdleTimeout: 3 * time.Second})
	if err == nil {
		t.Fatal("a connection with the h3 ALPN was accepted as DoQ")
	}
}

// TestDoQUpstream: the resolver speaks DoQ to an upstream, which is the
// other half of the transport.
func TestDoQUpstream(t *testing.T) {
	// A DoQ server in front of a plain fake upstream, used as this
	// resolver's upstream.
	up := newFakeUpstream(t)
	inner := &Policy{Resolver: NewResolver([]string{up.addr()}, time.Second), MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute}
	addr, _, _, _ := doqServer(t, inner)

	r, err := NewResolverTLS([]string{"quic://" + addr}, 5*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	r.tlsConf.InsecureSkipVerify = true //nolint:gosec // self-signed test certificate
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q := mustQuery(t, 42, "a.example.test", TypeA)
	qu, qEnd, err := ParseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.Exchange(ctx, q, qEnd, qu, false)
	if err != nil {
		t.Fatalf("exchange over doq: %v", err)
	}
	h, err := ParseHeader(resp)
	if err != nil || h.ID != 42 {
		// The id on the wire is zero; the resolver restores the
		// client's id before returning.
		t.Fatalf("answer id %d, want the client's 42: %v", h.ID, err)
	}
	// A second query reuses the connection rather than handshaking again.
	q2 := mustQuery(t, 43, "b.example.test", TypeA)
	qu2, qEnd2, err := ParseQuestion(q2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Exchange(ctx, q2, qEnd2, qu2, false); err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	// And a connection that has gone away is dialled again, resuming the
	// session rather than running a full handshake: a QUIC handshake is
	// the expensive half of DoQ, and a resolver loses its connection
	// whenever the upstream's idle timeout is shorter than the gap
	// between queries.
	srv := r.servers[0]
	srv.mu.Lock()
	conn := srv.quic
	srv.mu.Unlock()
	srv.dropQUIC(conn)
	_ = conn.CloseWithError(doqNoError, "")
	q3 := mustQuery(t, 44, "c.example.test", TypeA)
	qu3, qEnd3, err := ParseQuestion(q3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Exchange(ctx, q3, qEnd3, qu3, false); err != nil {
		t.Fatalf("exchange after the connection was dropped: %v", err)
	}
	if r.Resumed.Load() == 0 {
		t.Error("the redialled DoQ connection did not resume a session")
	}
}

func TestParseQUICUpstream(t *testing.T) {
	u, err := ParseUpstream("quic://dns.example.com:853")
	if err != nil || u.transport != transportQUIC || u.host != "dns.example.com" {
		t.Fatalf("parse = %+v %v", u, err)
	}
	for _, bad := range []string{"quic://dns.example.com", "quic://", "quic://:853", "sctp://x:1"} {
		if _, err := ParseUpstream(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseUpstream("quic://x"); err == nil || !strings.Contains(err.Error(), "quic://host:port") {
		t.Errorf("the error does not say the form: %v", err)
	}
}
