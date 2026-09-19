package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/h3"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/testutil"
)

// h3Backend serves handler over HTTP/3 on a fresh UDP port with the
// certificate files; it returns the address.
func h3Backend(t *testing.T, cert, key string, handler http.Handler, wt bool) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lim := config.Limits{MaxConnections: 100, MaxConnectionsPerIP: 100, MaxHeaderBytes: 1 << 16,
		ReadHeaderTimeout: config.Duration(5 * time.Second), IdleTimeout: config.Duration(30 * time.Second)}
	srv, err := h3.New(h3.Options{Conn: pc, Port: pc.LocalAddr().(*net.UDPAddr).Port, TLS: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13},
		Handler: handler, Limits: lim, H3: config.H3{MaxStreams: 16, ValidateAddresses: "under_load", AltSvcMaxAge: config.Duration(time.Hour)},
		Limiter: limits.NewConnLimiter(100, 100), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), WebTransport: wt})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })
	lastH3Backend = srv
	return pc.LocalAddr().String()
}

// lastH3Backend is the server h3Backend built most recently (a handler
// that upgrades WebTransport sessions needs it).
var lastH3Backend *h3.Server

func TestHTTP3Upstream(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "backend.test")
	addr := h3Backend(t, cert, key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Proto, r.URL.Path)
	}), false)
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: b
    scheme: https
    h3: true
    retries: 0
    endpoints: [{address: "%s"}]
    tls: {server_name: backend.test, ca_file: %s}
    timeouts: {connect: 2s}
routes:
  - {name: r, upstream: b}
`
	s, url := startServer(t, fmt.Sprintf(yaml, addr, ca.Path))
	if _, body := get(t, url+"/x"); body != "HTTP/3.0 /x" {
		t.Fatalf("body %q", body)
	}
	for _, p := range s.Pools() {
		if p.Protocol != "h3" || p.H3Fallbacks != 0 {
			t.Fatalf("pool status %+v", p)
		}
	}
}

func TestHTTP3UpstreamFallback(t *testing.T) {
	// The endpoint speaks only TCP: QUIC to its port times out and the
	// request is retried over TCP on the same endpoint.
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "backend.test")
	pair, _ := tls.LoadX509KeyPair(cert, key)
	tcpOnly := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Proto, r.URL.Path)
	}))
	tcpOnly.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	tcpOnly.StartTLS()
	defer tcpOnly.Close()
	addr := strings.TrimPrefix(tcpOnly.URL, "https://")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: b
    scheme: https
    h3: true
    retries: 0
    endpoints: [{address: "%s"}]
    tls: {server_name: backend.test, ca_file: %s}
    timeouts: {connect: 500ms}
routes:
  - {name: r, upstream: b}
`
	s, url := startServer(t, fmt.Sprintf(yaml, addr, ca.Path))
	resp, body := get(t, url+"/y")
	if resp.StatusCode != 200 || !strings.HasSuffix(body, " /y") || strings.HasPrefix(body, "HTTP/3") {
		t.Fatalf("fallback: %d %q", resp.StatusCode, body)
	}
	for _, p := range s.Pools() {
		if p.H3Fallbacks != 1 {
			t.Fatalf("fallbacks %+v", p)
		}
	}
	// With the fallback off the request fails.
	s2, url2 := startServer(t, strings.Replace(fmt.Sprintf(yaml, addr, ca.Path), "h3: true", "h3: true\n    h3_fallback: false", 1))
	if resp, _ := get(t, url2+"/z"); resp.StatusCode != 502 {
		t.Fatalf("without fallback: %d", resp.StatusCode)
	}
	_ = s2
	_ = io.Discard
}
