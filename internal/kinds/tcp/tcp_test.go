package tcp_test

import (
	"github.com/rom/xproxy/internal/proxytest"

	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	_ "github.com/rom/xproxy/internal/kinds/tcp"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
)

// tlsOrigin is an HTTPS server for one name, answering its name.
func tlsOrigin(t *testing.T, name string, ca *testutil.CA, dir string) *httptest.Server {
	t.Helper()
	cert, key := ca.Issue(t, dir, name)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s:%s", name, r.URL.Path)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestTCPPassthrough routes TLS connections by server name to different
// origins without terminating TLS (the client verifies the origin's own
// certificate), sends non-TLS bytes to the default upstream, refuses an
// unknown name when there is no default, and reports counters.
func TestTCPPassthrough(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	a := tlsOrigin(t, "a.test", ca, dir)
	b := tlsOrigin(t, "b.test", ca, dir)
	// A plain TCP echo as the default upstream.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	yaml := `
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        idle_timeout: 2s
        routes:
          - {sni: [a.test, "*.a.test"], upstream: a}
          - {sni: [b.test], upstream: b}
        default: echo
    - name: strict
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        routes:
          - {sni: [a.test], upstream: a}
logging:
  access: {enabled: false}
upstreams:
  - name: a
    endpoints: [{address: %s}]
  - name: b
    endpoints: [{address: %s}]
  - name: echo
    endpoints: [{address: %s}]
`
	s := proxytest.Start(t, fmt.Sprintf(yaml, strings.TrimPrefix(a.URL, "https://"), strings.TrimPrefix(b.URL, "https://"), echoLn.Addr().String()))
	addr := s.Addrs()["l4"]
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	fetch := func(via, sni string) (string, error) {
		conn, err := tls.Dial("tcp", via, &tls.Config{ServerName: sni, RootCAs: pool, MinVersion: tls.VersionTLS12})
		if err != nil {
			return "", err
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "GET /x HTTP/1.0\r\nHost: "+sni+"\r\n\r\n"); err != nil {
			return "", err
		}
		resp, err := io.ReadAll(conn)
		if err != nil {
			return "", err
		}
		body := string(resp)
		return body[strings.LastIndex(body, "\n")+1:], nil
	}
	if body, err := fetch(addr, "a.test"); err != nil || body != "a.test:/x" {
		t.Fatalf("a.test: %q %v", body, err)
	}
	if body, err := fetch(addr, "b.test"); err != nil || body != "b.test:/x" {
		t.Fatalf("b.test: %q %v", body, err)
	}
	// Initial silence must not select the default before an SNI route can
	// be inspected. This models a client that delays its ordinary hello
	// beyond the server-first settle timeout.
	delayed, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	tlsDelayed := tls.Client(delayed, &tls.Config{ServerName: "a.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	_ = tlsDelayed.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsDelayed.Handshake(); err != nil {
		_ = delayed.Close()
		t.Fatalf("delayed a.test ClientHello: %v", err)
	}
	if _, err := io.WriteString(tlsDelayed, "GET /delayed HTTP/1.0\r\nHost: a.test\r\n\r\n"); err != nil {
		_ = tlsDelayed.Close()
		t.Fatal(err)
	}
	response, err := io.ReadAll(tlsDelayed)
	_ = tlsDelayed.Close()
	if err != nil || !strings.HasSuffix(string(response), "a.test:/delayed") {
		t.Fatalf("delayed a.test: %q %v", response, err)
	}
	if body, err := fetch(addr, "www.a.test"); err == nil || body != "" {
		// The wildcard routes to a, whose certificate is for a.test only:
		// the client refuses it, proving the TLS session is end to end.
		t.Fatalf("wildcard to a: expected a certificate name error, got %q %v", body, err)
	}
	// Non-TLS bytes go to the default upstream (echo).
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "hello over tcp\n")
	line := make([]byte, 15)
	if _, err := io.ReadFull(c, line); err != nil || string(line) != "hello over tcp\n" {
		t.Fatalf("echo: %q %v", line, err)
	}
	_ = c.Close()
	// Unknown name on the strict listener: closed without a byte.
	strict := s.Addrs()["strict"]
	if _, err := fetch(strict, "nope.test"); err == nil {
		t.Fatal("unknown name accepted on the strict listener")
	}
	if body, err := fetch(strict, "a.test"); err != nil || body != "a.test:/x" {
		t.Fatalf("strict a.test: %q %v", body, err)
	}
	st := s.Stats()
	if st.TCPConnections < 6 || st.TCPRejected != 1 || st.TCPBytesIn == 0 || st.TCPBytesOut == 0 {
		t.Fatalf("stats %+v", st)
	}
	if up := s.Upstreams()["a"]; up[0].Requests < 2 {
		t.Fatalf("pool accounting %+v", up)
	}
	// Idle timeout closes a silent connection.
	c, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "x")
	_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
	buf := make([]byte, 8)
	_, _ = c.Read(buf) // the echo of "x"
	start := time.Now()
	if _, err := c.Read(buf); err == nil {
		t.Fatal("idle connection not closed")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("idle timeout not applied")
	}
	_ = c.Close()
}

// TestTCPProxyProtocol: the upstream receives a PROXY v2 header with the
// client's address before the client's bytes.
func TestTCPProxyProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		n, _ := io.ReadAtLeast(c, buf, 16+12+5)
		got <- buf[:n]
		_ = c.Close()
	}()
	yaml := `
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp: {default: back, proxy_protocol: true}
logging:
  access: {enabled: false}
upstreams:
  - name: back
    endpoints: [{address: %s}]
`
	s := proxytest.Start(t, fmt.Sprintf(yaml, ln.Addr().String()))
	c, err := net.Dial("tcp", s.Addrs()["l4"])
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "hello")
	select {
	case b := <-got:
		if len(b) < 33 || string(b[:12]) != "\r\n\r\n\x00\r\nQUIT\n" || b[12] != 0x21 || b[13] != 0x11 || binary.BigEndian.Uint16(b[14:16]) != 12 {
			t.Fatalf("proxy header %x", b)
		}
		clientPort := binary.BigEndian.Uint16(b[24:26])
		if _, p, _ := net.SplitHostPort(c.LocalAddr().String()); fmt.Sprint(clientPort) != p {
			t.Fatalf("client port %d, want %s", clientPort, p)
		}
		if string(b[28:]) != "hello" {
			t.Fatalf("payload %q", b[28:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream received nothing")
	}
	_ = c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.Shutdown(ctx)
}
