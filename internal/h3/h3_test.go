package h3

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/testutil"
)

// The HTTP/3 endpoint is the only place quic-go is reached from, so the
// tests here drive a real server over a real UDP socket: a client that
// speaks HTTP/3 to it, an address the connection limiter refuses, and
// the shutdown that has to give the socket back.

// serverTLS is a self-signed certificate for h3.test, with the pool a
// client needs to trust it.
func serverTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile := testutil.WriteCert(t, dir, "h3.test")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the certificate is not a pool")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, pool
}

func clientTLS(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, ServerName: "h3.test", MinVersion: tls.VersionTLS13}
}

func defaultLimits() config.Limits {
	return config.Limits{
		MaxHeaderBytes:      64 << 10,
		ReadHeaderTimeout:   config.Duration(5 * time.Second),
		IdleTimeout:         config.Duration(30 * time.Second),
		MaxConnections:      64,
		MaxConnectionsPerIP: 8,
	}
}

func TestNewRefusesIncompleteOptions(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	tc, _ := serverTLS(t)
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	lim := limits.NewConnLimiter(8, 4)

	full := Options{Conn: pc, TLS: tc, Handler: h, Limiter: lim, Limits: defaultLimits(), H3: config.H3{MaxStreams: 10}}
	for name, o := range map[string]Options{
		"no socket":  {TLS: tc, Handler: h, Limiter: lim},
		"no tls":     {Conn: pc, Handler: h, Limiter: lim},
		"no handler": {Conn: pc, TLS: tc, Limiter: lim},
		"no limiter": {Conn: pc, TLS: tc, Handler: h},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	s, err := New(full)
	if err != nil {
		t.Fatalf("a complete set: %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	// The UDP socket is the caller's: the transport closes its own state
	// but hands the descriptor back, which is what lets a reload move an
	// endpoint to a new generation without losing the port. A second
	// shutdown is a no-op rather than a panic.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.Shutdown(ctx)
	_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the socket came back as %v, want it still open", err)
	}
}

func TestServeAndClientRoundTrip(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tc, pool := serverTLS(t)
	var gotProto, gotTE atomic.Value
	gotProto.Store("")
	gotTE.Store("")
	s, err := New(Options{
		Conn: pc, TLS: tc, Port: pc.LocalAddr().(*net.UDPAddr).Port,
		Limits: defaultLimits(), H3: config.H3{MaxStreams: 10, ValidateAddresses: "under_load"},
		Limiter: limits.NewConnLimiter(64, 8), Log: slog.New(slog.DiscardHandler),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotProto.Store(r.Proto)
			gotTE.Store(r.Header.Get("Te"))
			w.Header().Set("X-Served", "h3")
			_, _ = io.WriteString(w, "hello over quic")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.WebTransport() {
		t.Error("WebTransport is on without being asked for")
	}
	if _, err := s.Upgrade(nil, nil); err == nil {
		t.Error("an endpoint without WebTransport accepted a session")
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()

	// The advertised endpoint is this socket's.
	if s.Addr().String() != pc.LocalAddr().String() {
		t.Errorf("Addr = %v want %v", s.Addr(), pc.LocalAddr())
	}
	ct := NewClientTransport(ClientOptions{
		TLS: clientTLS(pool), Handshake: 5 * time.Second, Idle: 10 * time.Second, ResponseHeader: 5 * time.Second,
	})
	defer func() { _ = ct.Close() }()
	req, err := http.NewRequest("GET", "https://"+pc.LocalAddr().String()+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "h3.test"
	// Te is hop by hop and must never reach an HTTP/3 upstream.
	req.Header.Set("Te", "trailers")
	resp, err := ct.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "hello over quic" || resp.Header.Get("X-Served") != "h3" {
		t.Errorf("response %q / %v", body, resp.Header)
	}
	if p := gotProto.Load().(string); p != "HTTP/3.0" {
		t.Errorf("the handler saw %q", p)
	}
	if te := gotTE.Load().(string); te != "" {
		t.Errorf("Te reached the upstream as %q", te)
	}
	// The original request is not modified by the header removal.
	if req.Header.Get("Te") != "trailers" {
		t.Error("RoundTrip modified the caller's request")
	}
	ct.CloseIdleConnections()

	// Alt-Svc advertises this endpoint's port; the header only exists
	// once the listener is serving, which the round trip above proves.
	h := http.Header{}
	s.SetAltSvc(h)
	if !strings.Contains(h.Get("Alt-Svc"), "h3=") {
		t.Errorf("Alt-Svc = %q", h.Get("Alt-Svc"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	select {
	case err := <-done:
		// A closed server is not a failure to report.
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return after the shutdown")
	}
}

func TestClientRefusesAnUnreachableServer(t *testing.T) {
	ct := NewClientTransport(ClientOptions{
		TLS: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "nobody.test"}, Handshake: 300 * time.Millisecond, Idle: time.Second,
	})
	defer func() { _ = ct.Close() }()
	req, err := http.NewRequest("GET", "https://127.0.0.1:1/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ct.RoundTrip(req)
	if err == nil {
		t.Fatal("a round trip to nowhere succeeded")
	}
	// The caller retries over TCP only for a QUIC layer failure, so the
	// classification has to hold for the errors quic-go really returns.
	if !IsTransportError(err) {
		t.Errorf("a handshake that never completed is not a transport error: %v (%T)", err, err)
	}
}

func TestIsTransportError(t *testing.T) {
	if IsTransportError(nil) {
		t.Error("nil is a transport error")
	}
	for _, err := range []error{
		&quic.TransportError{ErrorCode: quic.ConnectionRefused},
		&quic.ApplicationError{ErrorCode: 1},
		&quic.IdleTimeoutError{},
		&quic.HandshakeTimeoutError{},
		&quic.StatelessResetError{},
	} {
		if !IsTransportError(err) {
			t.Errorf("%T is not reported as a transport error", err)
		}
		// Wrapped once, as a caller will see it.
		if !IsTransportError(wrap(err)) {
			t.Errorf("a wrapped %T is not reported as a transport error", err)
		}
	}
	// An error from above the QUIC layer is not one: a 502 from the
	// upstream must not be retried over TCP as if the connection failed.
	for _, err := range []error{
		errors.New("upstream said no"),
		context.DeadlineExceeded,
		io.ErrUnexpectedEOF,
	} {
		if IsTransportError(err) {
			t.Errorf("%v is reported as a transport error", err)
		}
	}
}

func wrap(err error) error { return errWrap{err} }

type errWrap struct{ err error }

func (e errWrap) Error() string { return "wrapped: " + e.err.Error() }
func (e errWrap) Unwrap() error { return e.err }

func TestAddrOf(t *testing.T) {
	cases := map[net.Addr]string{
		&net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}:   "198.51.100.9",
		&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1}: "192.0.2.1",
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}:      "2001:db8::1",
		&net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}:   "198.51.100.9",
	}
	for in, want := range cases {
		if got := addrOf(in); got.String() != want {
			t.Errorf("addrOf(%v) = %v want %v", in, got, want)
		}
	}
	// An address the limiter cannot key on is the zero address, which it
	// treats as untrusted rather than as one shared client.
	for _, a := range []net.Addr{
		&net.UnixAddr{Name: "/tmp/s", Net: "unixgram"},
		&net.UDPAddr{},
		stringAddr("not an address"),
	} {
		if got := addrOf(a); got.IsValid() {
			t.Errorf("addrOf(%v) = %v, want the zero address", a, got)
		}
	}
}

type stringAddr string

func (s stringAddr) Network() string { return "test" }
func (s stringAddr) String() string  { return string(s) }

func TestSocketBufferAdvice(t *testing.T) {
	if !strings.Contains(SocketBufferAdvice(), "rmem_max") {
		t.Errorf("advice = %q", SocketBufferAdvice())
	}
}

func TestConnectionsPastTheLimitAreRefused(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tc, pool := serverTLS(t)
	// One connection in total: the second client must be refused by the
	// same admission the TCP listener applies, before any request runs.
	s, err := New(Options{
		Conn: pc, TLS: tc, Limits: defaultLimits(), H3: config.H3{MaxStreams: 10},
		Limiter: limits.NewConnLimiter(1, 1), Log: slog.New(slog.DiscardHandler),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }),
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()

	first := NewClientTransport(ClientOptions{TLS: clientTLS(pool), Handshake: 5 * time.Second, Idle: 30 * time.Second})
	defer func() { _ = first.Close() }()
	req, _ := http.NewRequest("GET", "https://"+pc.LocalAddr().String()+"/x", nil)
	req.Host = "h3.test"
	resp, err := first.RoundTrip(req)
	if err != nil {
		t.Fatalf("the first connection: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// A second transport opens its own connection, which the limiter
	// refuses; the client sees a connection error rather than a response.
	second := NewClientTransport(ClientOptions{TLS: clientTLS(pool), Handshake: 2 * time.Second, Idle: 5 * time.Second})
	defer func() { _ = second.Close() }()
	req2, _ := http.NewRequest("GET", "https://"+pc.LocalAddr().String()+"/x", nil)
	req2.Host = "h3.test"
	if resp, err := second.RoundTrip(req2); err == nil {
		_ = resp.Body.Close()
		t.Error("a connection past the limit was served")
	}
}

func TestSessionCode(t *testing.T) {
	// A session that ended with a code carries it to the other side, so
	// the peer of a relay sees why the first one went away.
	if got := sessionCode(&webtransport.SessionError{ErrorCode: 42}); got != 42 {
		t.Errorf("sessionCode = %d want 42", got)
	}
	if got := sessionCode(wrap(&webtransport.SessionError{ErrorCode: 7})); got != 7 {
		t.Errorf("a wrapped session error = %d want 7", got)
	}
	// Anything else closes the other side cleanly rather than inventing
	// a code the application would read as a protocol failure.
	for _, err := range []error{nil, errors.New("the connection went away"), context.Canceled, io.EOF} {
		if got := sessionCode(err); got != 0 {
			t.Errorf("sessionCode(%v) = %d want 0", err, got)
		}
	}
}

func TestWebTransportEndpointServes(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tc, _ := serverTLS(t)
	s, err := New(Options{
		Conn: pc, TLS: tc, Limits: defaultLimits(), H3: config.H3{MaxStreams: 10},
		Limiter: limits.NewConnLimiter(8, 4), Log: slog.New(slog.DiscardHandler), WebTransport: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !s.WebTransport() {
		t.Error("the endpoint does not report WebTransport")
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	select {
	case err := <-done:
		// A closed endpoint is not a failure: the accept loop ends with
		// the server rather than logging a stop nobody caused.
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the WebTransport accept loop did not stop")
	}
	// Shutting down twice is a no-op, which a reload followed by an exit
	// takes.
	_ = s.Shutdown(ctx)
}
