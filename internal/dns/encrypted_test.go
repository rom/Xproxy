package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
)

// TestEncryptedListener: one TLS port serves DNS over TLS (ALPN dot or
// none) and DNS over HTTPS (ALPN h2 or http/1.1) on the configured path.
func TestEncryptedListener(t *testing.T) {
	up := newFakeUpstream(t)
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "dns.test")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
		NextProtos: []string{ALPNDoT, ALPNH2, ALPNHTTP}})
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Resolver: NewResolver([]string{up.addr()}, time.Second), MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute}
	s := New("dot", nil, ln, 100, 8, p, Hooks{})
	s.Encrypted = true
	s.DoHPath = "/dns"
	s.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	addr := ln.Addr().String()
	q := mustQuery(t, 7, "a.example.test", TypeA)

	// DoT with the dot ALPN and without any ALPN.
	for _, protos := range [][]string{{ALPNDoT}, nil} {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: protos}) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteTCP(c, q); err != nil {
			t.Fatal(err)
		}
		resp, err := ReadTCP(c, MaxMessage)
		_ = c.Close()
		if err != nil {
			t.Fatal(err)
		}
		if h, qu, ip := answerIP(t, resp); h.ID != 7 || qu.Name != "a.example.test" || !bytes.Equal(ip, []byte{10, 0, 0, 14}) {
			t.Fatalf("dot answer %v %v %v", h, qu, ip)
		}
	}
	// DoH over HTTP/2 (POST) and HTTP/1.1 (GET).
	h2 := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test
	resp, err := h2.Post("https://"+addr+"/dns", "application/dns-message", bytes.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 || resp.Header.Get("Content-Type") != "application/dns-message" || !strings.HasPrefix(resp.Header.Get("Cache-Control"), "max-age=") {
		t.Fatalf("doh h2: %d %s %v", resp.StatusCode, resp.Proto, resp.Header)
	}
	if _, _, ip := answerIP(t, body); !bytes.Equal(ip, []byte{10, 0, 0, 14}) {
		t.Fatalf("doh h2 answer %v", ip)
	}
	h1 := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{ALPNHTTP}}}} //nolint:gosec // test
	resp, err = h1.Get("https://" + addr + "/dns?dns=" + base64.RawURLEncoding.EncodeToString(q))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 1 {
		t.Fatalf("doh h1: %d %s", resp.StatusCode, resp.Proto)
	}
	if _, _, ip := answerIP(t, body); !bytes.Equal(ip, []byte{10, 0, 0, 14}) {
		t.Fatalf("doh h1 answer %v", ip)
	}
	// Wrong path, wrong method, wrong content type.
	if resp, err := h1.Get("https://" + addr + "/other?dns=AAAA"); err != nil || resp.StatusCode != 404 {
		t.Fatalf("path: %v %v", resp, err)
	}
	req, _ := http.NewRequest(http.MethodPut, "https://"+addr+"/dns", nil)
	if resp, err := h1.Do(req); err != nil || resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, POST" {
		t.Fatalf("method: %v %v", resp, err)
	}
	if resp, err := h1.Post("https://"+addr+"/dns", "text/plain", bytes.NewReader(q)); err != nil || resp.StatusCode != 415 {
		t.Fatalf("content type: %v %v", resp, err)
	}
	st := s.Status()
	if !st.Encrypted || st.DoHPath != "/dns" || st.QueriesDoT != 2 || st.QueriesDoH != 2 || st.QueriesUDP != 0 || st.Queries != 4 {
		t.Fatalf("status %+v", st)
	}
	if _, _, reason := DoHRequest(&http.Request{Method: http.MethodPost, Header: http.Header{"Content-Type": {"application/dns-message"}}, Body: io.NopCloser(strings.NewReader("short"))}); reason != "doh:short" {
		t.Fatalf("short body reason %q", reason)
	}
}
