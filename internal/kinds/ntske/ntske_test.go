package ntske_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/ntske"
	wire "github.com/rom/xproxy/internal/ntp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// keServer is a key establishment server: TLS with the NTS application
// protocol, one exchange, and a count of the sessions that got through.
type keServer struct {
	ln       net.Listener
	sessions atomic.Int64
	// alpn records what the last session negotiated, which is what the
	// relay is supposed to have insisted on.
	alpn atomic.Pointer[string]
}

func startKEServer(t *testing.T, certFile, keyFile string) *keServer {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{wire.ALPN},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &keServer{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				tc, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				if err := tc.Handshake(); err != nil {
					return
				}
				proto := tc.ConnectionState().NegotiatedProtocol
				s.alpn.Store(&proto)
				s.sessions.Add(1)
				buf := make([]byte, 16)
				n, err := tc.Read(buf)
				if err != nil || n == 0 {
					return
				}
				// The shape of an NTS-KE exchange is a record the client
				// sends and records the server answers with; what the
				// test needs is that both directions cross the relay.
				_, _ = tc.Write([]byte("cookies"))
			}()
		}
	}()
	return s
}

func (s *keServer) addr() string { return s.ln.Addr().String() }

const ntskeYAML = `
version: 1
server:
  listeners:
    - name: ke
      address: "127.0.0.1:0"
      kind: ntske
      ntske:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: ke_servers, endpoints: [{address: %q}]}
`

func ntskeServer(t *testing.T, section string, up *keServer) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(ntskeYAML, section, up.addr()))
	return s, proxytest.Addr(t, s, "ke")
}

// clientConfig trusts the key establishment server's own certificate,
// because the relay passes the handshake through: the client
// authenticates the server, not the relay, which is the whole reason this
// listener does not terminate.
func clientConfig(t *testing.T, certFile, name string, protos ...string) *tls.Config {
	t.Helper()
	pem, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the certificate did not load")
	}
	return &tls.Config{RootCAs: pool, ServerName: name, NextProtos: protos, MinVersion: tls.VersionTLS13}
}

// An NTS client gets through, and the handshake it completes is with the
// key establishment server rather than with the relay.
func TestNTSKERelaysAnNTSClient(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers
        allow_clients: ["127.0.0.0/8"]
        log_sessions: true`, up)

	c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", wire.ALPN))
	if err != nil {
		t.Fatalf("an NTS client could not get through: %v", err)
	}
	defer func() { _ = c.Close() }()
	if got := c.ConnectionState().NegotiatedProtocol; got != wire.ALPN {
		t.Fatalf("negotiated %q, want %q", got, wire.ALPN)
	}
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "cookies" {
		t.Fatalf("the answer did not come back: %q %v", buf[:n], err)
	}
	if up.sessions.Load() != 1 {
		t.Fatalf("the server saw %d sessions", up.sessions.Load())
	}
	sn := s.Stats()
	if sn.NTSKESessions != 1 || sn.NTSKERelayed != 1 {
		t.Fatalf("counters: sessions %d relayed %d", sn.NTSKESessions, sn.NTSKERelayed)
	}
}

// A connection to 4460 that does not offer the NTS application protocol
// is not an NTS client, and that is knowable from the handshake alone --
// which is the one check a relay that does not terminate TLS can make.
func TestNTSKERefusesWhatIsNotAnNTSClient(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers`, up)

	c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", "h2"))
	if err == nil {
		_ = c.Close()
		t.Fatal("a connection offering the wrong application protocol got through")
	}
	if got := s.Stats().Refusals["ntske"]["alpn_not_offered"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
	}
	if s.Stats().NTSKENotNTS != 1 {
		t.Errorf("not-NTS counter: %d", s.Stats().NTSKENotNTS)
	}
	if up.sessions.Load() != 0 {
		t.Fatal("the refused connection reached the server")
	}
	// A client offering nothing at all is the same refusal: a handshake
	// with no application protocol is not this protocol.
	if c2, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test")); err == nil {
		_ = c2.Close()
		t.Fatal("a connection offering no application protocol got through")
	}
}

// The server name list, for a relay in front of more than one key
// establishment server.
func TestNTSKEServerNameList(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers
        server_names: ["ke.test"]`, up)

	if c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", wire.ALPN)); err != nil {
		t.Fatalf("the named server was refused: %v", err)
	} else {
		_ = c.Close()
	}
	// A name the list does not have: the handshake never reaches the
	// server, so it fails at the relay.
	cfg := clientConfig(t, cert, "other.test", wire.ALPN)
	cfg.InsecureSkipVerify = true //nolint:gosec // the refusal is the point; nothing is trusted here
	if c, err := tls.Dial("tcp", addr, cfg); err == nil {
		_ = c.Close()
		t.Fatal("a server name outside the list got through")
	}
	if got := s.Stats().Refusals["ntske"]["server_name_not_allowed"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
	}
}

// This port carries one protocol and it starts with a TLS ClientHello.
// Anything else is a scan, and it is refused without reaching the server.
func TestNTSKERefusesWhatIsNotTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers`, up)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if n, err := c.Read(buf); err == nil && n > 0 {
		t.Fatalf("something was answered: %q", buf[:n])
	}
	if got := s.Stats().Refusals["ntske"]["not_tls"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
	}
	if up.sessions.Load() != 0 {
		t.Fatal("the scan reached the server")
	}
}

// The client list decides before the handshake is read at all.
func TestNTSKEClientList(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers
        allow_clients: ["10.0.0.0/8"]`, up)

	if c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", wire.ALPN)); err == nil {
		_ = c.Close()
		t.Fatal("a client outside the allow list got through")
	}
	if got := s.Stats().Refusals["ntske"]["client_not_allowed"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
	}
}

// The handshake bound: the expensive part of NTS is the handshake, so a
// flood of them is what this port has to be protected against. A client
// that cannot get a slot is refused rather than queued, because a queue
// here is a queue of handshakes.
func TestNTSKEBoundsTheHandshakesInFlight(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers
        max_concurrent_handshakes: 1
        handshake_timeout: 2s`, up)

	// One connection that says nothing holds the only slot while its
	// peek runs.
	held, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	// A second client cannot get a slot within the second the relay
	// waits, so it is refused.
	done := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", wire.ALPN))
		if err == nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a second handshake got a slot that was taken")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("the second handshake neither completed nor was refused")
	}
	if got := s.Stats().Refusals["ntske"]["handshake_limit"]; got == 0 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
	}
	if s.Stats().NTSKEHandshakeLimited == 0 {
		t.Error("the bound was not counted")
	}
}

// A session past the connection bound is closed rather than queued.
func TestNTSKEMaxConnections(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers
        max_connections: 1`, up)
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	// The first connection is still in its peek, holding the one slot.
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := second.Read(buf); err == nil {
		t.Fatal("the connection past the bound was not closed")
	}
	if got := s.Stats().Refusals["ntske"]["max_connections"]; got == 0 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
	}
	if s.Stats().NTSKERejected == 0 {
		t.Error("the rejected connection was not counted")
	}
}
