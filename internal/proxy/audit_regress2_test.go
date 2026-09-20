package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// More regression tests for the security audit findings.

// TestErrorPageEscapesRequestValues: a custom HTML error page that expands
// ${path} must not reflect markup from the URL (reflected XSS).
func TestErrorPageEscapesRequestValues(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "404.html"), []byte("<p>Not found: ${path}</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: r
    hosts: [app.test]
    paths: [/app]
    upstream: a
    error_pages: {dir: %s, pages: {"404": "404.html"}, json: false, intercept_upstream: [404]}
`
	_, url := startServer(t, fmt.Sprintf(yaml, backend.addr(), dir))
	// The upstream answers 404, so the route's page renders with the
	// crafted path segment expanded into it.
	backend.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
	resp, body := get(t, url+"/app/%3Csvg%20onload=alert(1)%3E", "Host", "app.test")
	if resp.StatusCode != 404 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if strings.Contains(body, "<svg") {
		t.Fatalf("markup reflected unescaped: %q", body)
	}
	if !strings.Contains(body, "&lt;svg") {
		t.Fatalf("path not rendered (escaped) at all: %q", body)
	}
}

// TestUnicodeFoldCannotRewritePath: with unicode: nfkc a path whose folded
// form gains "..", "/" or "%" is refused, so it cannot be routed by one
// path and served by another.
func TestUnicodeFoldCannotRewritePath(t *testing.T) {
	backend := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  normalization: {unicode: nfkc}
logging: {access: {enabled: false}}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - {name: admin, paths: [/admin], deny_cidrs: [0.0.0.0/0, "::/0"], upstream: a}
  - {name: all, upstream: a}
`
	_, url := startServer(t, fmt.Sprintf(yaml, backend.addr()))
	// U+2025 TWO DOT LEADER folds to ".." under NFKC.
	for _, p := range []string{"/admin/%E2%80%A5/secret", "/x%EF%BC%8Fadmin", "/a%EF%BC%85e2"} {
		if resp, _ := get(t, url+p); resp.StatusCode != 400 {
			t.Fatalf("%s: %d, want 400", p, resp.StatusCode)
		}
	}
	// Folding that adds no path syntax (a ligature) still routes.
	if resp, _ := get(t, url+"/%EF%AC%81le"); resp.StatusCode != 200 {
		t.Fatalf("harmless fold refused: %d", resp.StatusCode)
	}
}

// TestMirrorMarkerStripped: a client cannot label live traffic as a mirror
// copy.
func TestMirrorMarkerStripped(t *testing.T) {
	backend := newBackend(t, "a")
	_, url := startServer(t, fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - {name: r, upstream: a}
`, backend.addr()))
	if resp, _ := get(t, url+"/x", mirrorHeader, "1"); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := backend.last.Load().Header.Get(mirrorHeader); got != "" {
		t.Fatalf("mirror marker reached the upstream: %q", got)
	}
}

// TestCacheKeyIncludesRawHost: a response fetched with an odd Host (port,
// case) must not be served to visitors using the canonical Host.
func TestCacheKeyIncludesRawHost(t *testing.T) {
	var hits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "host=%s", r.Host)
	}))
	defer origin.Close()
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
cache: {}
upstreams:
  - name: app
    endpoints: [{address: "%s"}]
routes:
  - name: r
    hosts: [www.example.com]
    cache: {ttl: 60s}
    upstream: app
`
	_, url := startServer(t, fmt.Sprintf(yaml, strings.TrimPrefix(origin.URL, "http://")))
	if _, body := get(t, url+"/", "Host", "www.example.com:1337"); !strings.Contains(body, ":1337") {
		t.Fatalf("poisoning request body %q", body)
	}
	_, body := get(t, url+"/", "Host", "www.example.com")
	if strings.Contains(body, ":1337") {
		t.Fatalf("canonical host served the poisoned entry: %q", body)
	}
	if hits != 2 {
		t.Fatalf("origin hits %d, want 2 (separate entries)", hits)
	}
}

// TestGRPCWebFrameBound: a text-mode frame whose length prefix exceeds the
// bound fails the stream instead of buffering gigabytes.
func TestGRPCWebFrameBound(t *testing.T) {
	hdr := make([]byte, 5)
	binary.BigEndian.PutUint32(hdr[1:], maxGRPCWebFrame+1)
	b := &grpcWebBody{text: true, rc: http.NoBody}
	b.ingest(hdr)
	if !b.failed || b.pending != nil {
		t.Fatalf("oversized frame accepted: %+v", b)
	}
	if _, err := b.Read(make([]byte, 8)); err == nil {
		t.Fatal("failed stream read without error")
	}
	ok := &grpcWebBody{text: true, rc: http.NoBody}
	small := append([]byte{0, 0, 0, 0, 3}, 'a', 'b', 'c')
	ok.ingest(small)
	if ok.failed || !bytes.Contains(ok.buf.Bytes(), []byte("AAAAAANhYmM=")) {
		t.Fatalf("small frame not encoded: failed=%v buf=%q", ok.failed, ok.buf.String())
	}
}

// TestPrivateAddrCoversTransitionRanges: the forward proxy's private-address
// check includes the blocks that embed or alias internal addresses.
func TestPrivateAddrCoversTransitionRanges(t *testing.T) {
	for _, s := range []string{"100.64.1.1", "0.1.2.3", "192.0.0.9", "198.18.0.1", "240.0.0.1", "64:ff9b::a00:1", "2002:c0a8:101::1", "2001:0:53aa:64c:0:bfff:3f57:fefe", "10.1.1.1", "127.0.0.1", "::1"} {
		if !privateAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s not treated as private", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "2606:4700::1111"} {
		if privateAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s wrongly treated as private", s)
		}
	}
}
