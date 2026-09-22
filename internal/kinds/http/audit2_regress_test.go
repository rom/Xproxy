package http

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/httpx"
)

// Regression tests for the second security audit round.

// rawGet sends a request line verbatim (the client library would repair
// the target) and returns the response.
func rawGet(t *testing.T, addr, target string, headers ...string) (*http.Response, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET " + target + " HTTP/1.1\r\nHost: h.test\r\nConnection: close\r\n"
	for _, h := range headers {
		req += h + "\r\n"
	}
	if _, err := c.Write([]byte(req + "\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

// TestCacheIgnoresNonCanonicalPaths: the upstream receives the path as
// sent while the cache key is the routing path, so a request for "//x" or
// a Unicode-folded spelling must not fill the entry for "/x".
func TestCacheIgnoresNonCanonicalPaths(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.html" {
			w.WriteHeader(404)
			fmt.Fprintf(w, "NOTFOUND raw=%s", r.RequestURI)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprint(w, "INDEX")
	}))
	defer origin.Close()
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  normalization: {unicode: nfkc, reject_dot_segments: false}
logging: {access: {enabled: false}}
cache: {}
upstreams:
  - name: app
    endpoints: [{address: "%s"}]
routes:
  - {name: r, cache: {ttl: 60s}, upstream: app}
`
	_, url := startServer(t, fmt.Sprintf(yaml, strings.TrimPrefix(origin.URL, "http://")))
	addr := strings.TrimPrefix(url, "http://")
	for _, poison := range []string{"//index.html", "/./index.html", "/x/../index.html", "/%EF%BD%89ndex.html", "/index%2Ehtml"} {
		resp, body := rawGet(t, addr, poison)
		if resp.Header.Get("X-Cache") != "" && resp.Header.Get("X-Cache") != "BYPASS" {
			t.Fatalf("%s: cache state %q body %q", poison, resp.Header.Get("X-Cache"), body)
		}
		resp, body = rawGet(t, addr, "/index.html")
		if resp.StatusCode != 200 || body != "INDEX" {
			t.Fatalf("after %s: canonical path served %d %q", poison, resp.StatusCode, body)
		}
	}
}

// TestCachedResponseHeaderTemplatesPerRequest: a response header template
// that expands request data of the first visitor must not be replayed
// from the cache to the next one.
func TestCachedResponseHeaderTemplatesPerRequest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprint(w, "body")
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
    cache: {ttl: 60s}
    response_headers: {set: {X-Who: "${header:X-Client}"}}
    upstream: app
`
	_, url := startServer(t, fmt.Sprintf(yaml, strings.TrimPrefix(origin.URL, "http://")))
	if resp, _ := get(t, url+"/", "X-Client", "attacker"); resp.Header.Get("X-Who") != "attacker" || resp.Header.Get("X-Cache") != "MISS" {
		t.Fatalf("first: %v", resp.Header)
	}
	resp, _ := get(t, url+"/", "X-Client", "victim")
	if resp.Header.Get("X-Cache") != "HIT" {
		t.Fatalf("second not a hit: %v", resp.Header)
	}
	if got := resp.Header.Get("X-Who"); got != "victim" {
		t.Fatalf("hit replayed the first visitor's header: %q", got)
	}
}

// TestDotSegmentsRefusedByDefault: a path with "." or ".." segments (and
// the "..;" servlet form) is refused, since routing would resolve it while
// the upstream receives it as sent. Encoded and backslash forms that the
// default checks do not cover are documented options.
func TestDotSegmentsRefusedByDefault(t *testing.T) {
	a := newBackend(t, "a")
	_, url := startServer(t, fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - {name: admin, paths: [/admin], respond: {status: 403, body: forbidden}}
  - {name: root, upstream: a}
`, a.addr()))
	addr := strings.TrimPrefix(url, "http://")
	for _, target := range []string{"/admin/../x", "/x/../admin", "/static/..;/admin", "/static/.;/admin", "/./x", "/static/%2e%2e/admin"} {
		a.last.Store(nil)
		if resp, _ := rawGet(t, addr, target); resp.StatusCode != 400 {
			t.Errorf("%s: %d, want 400", target, resp.StatusCode)
		}
		if a.last.Load() != nil {
			t.Errorf("%s reached the upstream", target)
		}
	}
	if resp, _ := rawGet(t, addr, "/a.b/c..d/.hidden"); resp.StatusCode != 200 {
		t.Errorf("dots inside segments refused: %d", resp.StatusCode)
	}
	off := false
	n := &config.Normalization{RejectDotSegments: &off}
	if n.DotSegments() {
		t.Fatal("option not honoured")
	}
}

// TestStaticDirectoryRedirectUsesCleanPath: "//name" must not produce a
// protocol-relative Location.
func TestStaticDirectoryRedirectUsesCleanPath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "evil.example"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, url := startServer(t, fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
routes:
  - {name: site, static: {root: %q}}
`, root))
	resp, _ := rawGet(t, strings.TrimPrefix(url, "http://"), "//evil.example")
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "/evil.example/" {
		t.Fatalf("redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// TestErrorPageEscapingByContentType: markup escaping applies to every
// browser-rendered type, and JSON pages get JSON string escaping.
func TestErrorPageEscapingByContentType(t *testing.T) {
	for ctype, want := range map[string]string{
		"text/html; charset=utf-8": "html", "application/xhtml+xml": "html", "image/svg+xml": "html", "text/xml": "html",
		"application/json": "json", "application/problem+json": "json", "text/plain": "", "text/csv": "", "x/unknown": "html",
	} {
		if got := escapingFor(ctype); got != want {
			t.Errorf("%s: %q, want %q", ctype, got, want)
		}
	}
	j := jsonEscaping{stubResolver{`a"b\c` + "\n"}}
	if v, _ := j.Resolve("path", ""); v != `a\"b\\c\n` {
		t.Fatalf("json escaping %q", v)
	}
}

type stubResolver struct{ v string }

func (s stubResolver) Resolve(string, string) (string, bool) { return s.v, true }

// TestMirrorDropsHopByHopHeaders: the mirror copy is sent outside
// ReverseProxy, so connection-scoped headers are removed by hand.
func TestMirrorDropsHopByHopHeaders(t *testing.T) {
	h := http.Header{"Connection": {"close, X-Hop"}, "X-Hop": {"1"}, "Keep-Alive": {"timeout=5"}, "Proxy-Authorization": {"Basic x"}, "TE": {"trailers"}, "X-Keep": {"y"}}
	httpx.StripHopByHop(h)
	for _, gone := range []string{"Connection", "X-Hop", "Keep-Alive", "Proxy-Authorization", "TE"} {
		if h.Get(gone) != "" {
			t.Errorf("%s survived", gone)
		}
	}
	if h.Get("X-Keep") != "y" {
		t.Error("end-to-end header dropped")
	}
}

// TestGRPCTimeoutOverflow: an absurd grpc-timeout is treated as absent
// rather than wrapping into a negative deadline.
func TestGRPCTimeoutOverflow(t *testing.T) {
	if d := parseGRPCTimeout("99999999H"); d != 0 {
		t.Fatalf("overflowing timeout %v", d)
	}
	if d := parseGRPCTimeout("10S"); d != 10*time.Second {
		t.Fatalf("plain timeout %v", d)
	}
}

// TestCORSWildcardHostBoundary: an origin whose "wildcard" part carries
// characters that end the host of a URL does not match.
func TestCORSWildcardHostBoundary(t *testing.T) {
	for _, o := range []string{"https://evil.com?.example.com", "https://a@evil.com.example.com", "https://a\\.example.com", "https://evil.com:.example.com", "https://evil.com#.example.com"} {
		if matchOriginPattern("https://*.example.com", o) {
			t.Errorf("%s matched", o)
		}
	}
	if !matchOriginPattern("https://*.example.com", "https://a.b.example.com") {
		t.Error("ordinary subdomain refused")
	}
}

// TestReloadRefusesChallengeWithoutKey: a reload that adds a challenge
// section whose secret cannot be read fails as a whole instead of leaving
// the routes in mode always unchallenged.
func TestReloadRefusesChallengeWithoutKey(t *testing.T) {
	a := newBackend(t, "a")
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
%s
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - {name: r, upstream: a%s}
`
	s, url := startServer(t, fmt.Sprintf(base, "", a.addr(), ""))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k"), []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(base, "challenge: {secret_file: "+filepath.Join(dir, "k")+"}", a.addr(), ", challenge: {mode: always}")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), "challenge") {
		t.Fatalf("reload with an unreadable challenge key: %v", err)
	}
	if resp, _ := get(t, url+"/x"); resp.StatusCode != 200 {
		t.Fatalf("old generation gone: %d", resp.StatusCode)
	}
}
