package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

const proxyProtoYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0", proxy_protocol: true}]
trusted_proxies: [%s]
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: acl
    hosts: [acl.test]
    deny_cidrs: [203.0.113.0/24]
    upstream: a
  - name: all
    upstream: a
`

// proxyV2 builds a version 2 PROXY header for an IPv4 TCP connection.
func proxyV2(src, dst string, sport, dport uint16) []byte {
	h := []byte("\r\n\r\n\x00\r\nQUIT\n")
	h = append(h, 0x21, 0x11)
	h = binary.BigEndian.AppendUint16(h, 12)
	h = append(h, net.ParseIP(src).To4()...)
	h = append(h, net.ParseIP(dst).To4()...)
	h = binary.BigEndian.AppendUint16(h, sport)
	return binary.BigEndian.AppendUint16(h, dport)
}

// rawRequest sends prefix followed by one HTTP/1.1 request and returns the
// status code, or the read error when the proxy dropped the connection.
func rawRequest(t *testing.T, addr string, prefix []byte, host string) (int, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	req := fmt.Sprintf("GET /x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	if _, err := c.Write(append(prefix, req...)); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func TestProxyProtocolInbound(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(proxyProtoYAML, "127.0.0.0/8", a.addr()))
	addr := strings.TrimPrefix(url, "http://")

	// A version 2 header from a trusted balancer: the real client address
	// reaches the upstream and drives the ACL.
	hdr := proxyV2("203.0.113.9", "10.0.0.1", 40000, 443)
	if code, err := rawRequest(t, addr, hdr, "app.test"); err != nil || code != 200 {
		t.Fatalf("v2 header: %d %v", code, err)
	}
	last := a.last.Load()
	if got := last.Header.Get("X-Real-Ip"); got != "203.0.113.9" {
		t.Fatalf("real ip %q, want the PROXY source", got)
	}
	if got := last.Header.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Fatalf("xff %q", got)
	}
	if code, err := rawRequest(t, addr, hdr, "acl.test"); err != nil || code != 403 {
		t.Fatalf("deny_cidrs against the PROXY source: %d %v", code, err)
	}

	// Version 1 text header.
	v1 := []byte("PROXY TCP4 198.51.100.7 10.0.0.1 5000 80\r\n")
	if code, err := rawRequest(t, addr, v1, "app.test"); err != nil || code != 200 {
		t.Fatalf("v1 header: %d %v", code, err)
	}
	if got := a.last.Load().Header.Get("X-Real-Ip"); got != "198.51.100.7" {
		t.Fatalf("v1 real ip %q", got)
	}

	// LOCAL command (health checks from the balancer): the balancer's own
	// address stands.
	local := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x20, 0x00, 0, 0)
	if code, err := rawRequest(t, addr, local, "app.test"); err != nil || code != 200 {
		t.Fatalf("local: %d %v", code, err)
	}
	if got := a.last.Load().Header.Get("X-Real-Ip"); got != "127.0.0.1" {
		t.Fatalf("local real ip %q", got)
	}

	// A trusted peer that sends no header is refused before any HTTP
	// parsing: the bytes never become a request.
	hits := a.hits.Load()
	if _, err := rawRequest(t, addr, nil, "app.test"); err == nil {
		t.Fatal("missing header accepted from a trusted peer")
	}
	if a.hits.Load() != hits {
		t.Fatal("request without header reached the upstream")
	}
	if got := s.Stats().RejectedConns; got == 0 {
		t.Fatalf("rejection not counted: %+v", s.Stats())
	}
}

func TestProxyProtocolUntrustedPeer(t *testing.T) {
	a := newBackend(t, "a")
	_, url := startServer(t, fmt.Sprintf(proxyProtoYAML, "10.0.0.0/8", a.addr()))
	addr := strings.TrimPrefix(url, "http://")

	// Loopback is not a trusted balancer here: the header is not parsed,
	// so a client cannot pick its own address. The bytes reach the HTTP
	// parser as a malformed request.
	hdr := proxyV2("203.0.113.9", "10.0.0.1", 40000, 443)
	hits := a.hits.Load()
	code, err := rawRequest(t, addr, hdr, "app.test")
	if err == nil && code == 200 {
		t.Fatal("header from an untrusted peer honoured")
	}
	if a.hits.Load() != hits {
		if got := a.last.Load().Header.Get("X-Real-Ip"); got == "203.0.113.9" {
			t.Fatal("untrusted peer chose its address")
		}
	}
	// Without a header the connection works as before.
	if code, err := rawRequest(t, addr, nil, "app.test"); err != nil || code != 200 {
		t.Fatalf("plain request: %d %v", code, err)
	}
	if got := a.last.Load().Header.Get("X-Real-Ip"); got != "127.0.0.1" {
		t.Fatalf("real ip %q", got)
	}
}
