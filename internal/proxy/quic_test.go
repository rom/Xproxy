package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/rom/xproxy/internal/testutil"
)

// quicEcho is a QUIC server that echoes each stream, on the same port
// as a TCP listener so the passthrough can be tested for both.
func quicEcho(t *testing.T, cert, key string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.Listen(pc, &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"echo"}, MinVersion: tls.VersionTLS13}, &quic.Config{MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = pc.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					st, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						b, _ := io.ReadAll(st)
						_, _ = st.Write(append([]byte("echo:"), b...))
						_ = st.Close()
					}()
				}
			}()
		}
	}()
	return pc.LocalAddr().String()
}

// TestQUICPassthrough relays QUIC flows by the ClientHello's server
// name read from the Initial packet: a stream echoes end to end with
// the origin's certificate verified by the client, a second flow reuses
// nothing, an unknown name is dropped, and counters report flows.
func TestQUICPassthrough(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "q.test")
	origin := quicEcho(t, cert, key)
	yaml := `
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        quic: true
        quic_idle_timeout: 2s
        routes:
          - {sni: [q.test], upstream: q}
logging:
  access: {enabled: false}
upstreams:
  - name: q
    endpoints: [{address: %s}]
`
	s, _ := startServer(t, fmt.Sprintf(yaml, origin))
	relay := s.Addrs()["l4"]
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	dial := func(sni string) (*quic.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return quic.DialAddr(ctx, relay, &tls.Config{ServerName: sni, RootCAs: pool, NextProtos: []string{"echo"}, MinVersion: tls.VersionTLS13}, &quic.Config{HandshakeIdleTimeout: 2 * time.Second})
	}
	conn, err := dial("q.test")
	if err != nil {
		t.Fatalf("dial through the relay: %v", err)
	}
	for i := 0; i < 2; i++ {
		st, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(st, "hello %d", i)
		_ = st.Close()
		b, err := io.ReadAll(st)
		if err != nil || string(b) != fmt.Sprintf("echo:hello %d", i) {
			t.Fatalf("stream %d: %q %v", i, b, err)
		}
	}
	if sn := s.Stats(); sn.QUICFlows != 1 || sn.QUICFlowsOpen != 1 {
		t.Fatalf("flow counters: %+v", sn)
	}
	// A name without a route never reaches an endpoint: the handshake
	// times out on the client.
	if _, err := dial("other.test"); err == nil {
		t.Fatal("unknown name relayed")
	}
	if sn := s.Stats(); sn.QUICRejected == 0 {
		t.Fatalf("rejection not counted: %+v", sn)
	}
	// Closing the connection ends the flow after the idle timeout.
	_ = conn.CloseWithError(0, "bye")
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && s.Stats().QUICFlowsOpen != 0 {
		time.Sleep(100 * time.Millisecond)
	}
	if sn := s.Stats(); sn.QUICFlowsOpen != 0 || sn.TCPBytesIn == 0 || sn.TCPBytesOut == 0 {
		t.Fatalf("after close: %+v", sn)
	}
	if !strings.Contains(relay, "127.0.0.1") {
		t.Fatal("relay address")
	}
}
