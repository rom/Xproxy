package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/rom/xproxy/internal/testutil"
)

const h3YAML = `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
      protocols: [h1, h2, h3]
      h3: {max_streams: 8, validate_addresses: always}
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
  limits: {max_connections: %d, max_connections_per_ip: %d}
upstreams:
  - name: u
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: u
`

func h3Client(t *testing.T) *http3.Transport {
	t.Helper()
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "h3.test"}, QUICConfig: &quic.Config{}} //nolint:gosec // test
	t.Cleanup(func() { tr.Close() })
	return tr
}

func TestHTTP3(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "h3.test")
	s, _ := startServer(t, fmt.Sprintf(h3YAML, cert, key, 100, 100, a.addr()))
	addrs := s.Addrs()
	udp := addrs["main/udp"]
	if udp == "" {
		t.Fatalf("no h3 endpoint: %v", addrs)
	}

	// Alt-Svc is advertised on the TLS listener.
	tcp := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "h3.test"}}} //nolint:gosec // test
	resp, err := tcp.Get("https://" + addrs["main"] + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if alt := resp.Header.Get("Alt-Svc"); !strings.HasPrefix(alt, "h3=") {
		t.Fatalf("Alt-Svc: %q", alt)
	}

	// A request over QUIC reaches the backend with the same pipeline.
	c := &http.Client{Transport: h3Client(t)}
	resp, err = c.Get("https://" + udp + "/via/h3?q=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "a:/via/h3" || resp.ProtoMajor != 3 {
		t.Fatalf("h3: %d %q %s", resp.StatusCode, body, resp.Proto)
	}
	if resp.Header.Get("X-Request-Id") == "" || resp.Header.Get("Server") != "" || resp.Header.Get("Alt-Svc") != "" {
		t.Fatalf("headers over h3: %v", resp.Header)
	}
	last := a.last.Load()
	if last.Header.Get("X-Forwarded-Proto") != "https" || last.Header.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Fatalf("forwarding over h3: %v", last.Header)
	}

	// The same limits apply: no route -> 404, body limit -> 413.
	req, _ := http.NewRequest("POST", "https://"+udp+"/p", strings.NewReader(strings.Repeat("x", 20<<20)))
	resp, err = c.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != 413 {
			t.Fatalf("body limit over h3: %d", resp.StatusCode)
		}
	}
	if st := s.Stats(); st.OpenConnections < 1 {
		t.Fatalf("quic connection not counted: %+v", st)
	}
}

func TestHTTP3ConnectionLimit(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "h3.test")
	s, _ := startServer(t, fmt.Sprintf(h3YAML, cert, key, 1, 1, a.addr()))
	udp := s.Addrs()["main/udp"]

	c1 := &http.Client{Transport: h3Client(t)}
	resp, err := c1.Get("https://" + udp + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// A second QUIC connection from the same address is refused during the
	// handshake; the first keeps working.
	c2 := &http.Client{Transport: h3Client(t), Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+udp+"/", nil)
	if resp, err := c2.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("second connection admitted over the limit")
	}
	resp, err = c1.Get("https://" + udp + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if st := s.Stats(); st.RejectedConns < 1 {
		t.Fatalf("rejection not counted: %+v", st)
	}
}
