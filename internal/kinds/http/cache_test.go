package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestResponseCache covers hits and misses, HEAD, conditional requests,
// the never-cache rules, Vary, the object bound, purge and counters.
func TestResponseCache(t *testing.T) {
	var hits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Etag", `"v1"`)
		switch {
		case strings.HasPrefix(r.URL.Path, "/nostore"):
			w.Header().Set("Cache-Control", "no-store")
		case strings.HasPrefix(r.URL.Path, "/cookie"):
			w.Header().Set("Set-Cookie", "sid=1")
		case strings.HasPrefix(r.URL.Path, "/vary"):
			w.Header().Set("Vary", "Accept-Encoding")
			w.Header().Set("Content-Encoding", r.Header.Get("Accept-Encoding"))
		case strings.HasPrefix(r.URL.Path, "/big"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(strings.Repeat("b", 3000)))
			return
		case strings.HasPrefix(r.URL.Path, "/maxage"):
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		fmt.Fprintf(w, "body-%d", hits.Load())
	}))
	t.Cleanup(origin.Close)
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
logging:
  access: {enabled: false}
cache: {max_bytes: 1048576, max_object_bytes: 2048}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
routes:
  - name: cached
    paths: ["/"]
    cache: {ttl: 60s}
    upstream: app
`
	s, url := startServer(t, fmt.Sprintf(yaml, strings.TrimPrefix(origin.URL, "http://")))
	req := func(method, path string, hdr ...string) (*http.Response, string) {
		r, _ := http.NewRequest(method, url+path, nil)
		r.Host = "h.test"
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 8192)
		n, _ := resp.Body.Read(b)
		_ = resp.Body.Close()
		return resp, string(b[:n])
	}
	resp, body := req("GET", "/page")
	if resp.StatusCode != 200 || body != "body-1" || resp.Header.Get("X-Cache") != "MISS" {
		t.Fatalf("first: %d %q %s", resp.StatusCode, body, resp.Header.Get("X-Cache"))
	}
	resp, body = req("GET", "/page")
	if body != "body-1" || resp.Header.Get("X-Cache") != "HIT" || resp.Header.Get("Age") == "" || hits.Load() != 1 {
		t.Fatalf("second: %q %s age=%q hits=%d", body, resp.Header.Get("X-Cache"), resp.Header.Get("Age"), hits.Load())
	}
	resp, body = req("HEAD", "/page")
	if resp.StatusCode != 200 || body != "" || resp.Header.Get("X-Cache") != "HIT" {
		t.Fatalf("HEAD from cache: %d %q %s", resp.StatusCode, body, resp.Header.Get("X-Cache"))
	}
	resp, _ = req("GET", "/page", "If-None-Match", `"v1"`)
	if resp.StatusCode != 304 {
		t.Fatalf("conditional: %d", resp.StatusCode)
	}
	if resp, _ = req("GET", "/page?x=1"); resp.Header.Get("X-Cache") != "MISS" {
		t.Fatal("query string should be part of the key")
	}
	// Never cached.
	req("GET", "/nostore")
	if resp, _ = req("GET", "/nostore"); resp.Header.Get("X-Cache") != "MISS" {
		t.Fatal("no-store cached")
	}
	req("GET", "/cookie")
	if resp, _ = req("GET", "/cookie"); resp.Header.Get("X-Cache") != "MISS" {
		t.Fatal("Set-Cookie response cached")
	}
	if resp, _ = req("GET", "/page", "Cookie", "a=b"); resp.Header.Get("X-Cache") != "BYPASS" {
		t.Fatalf("cookie request: %s", resp.Header.Get("X-Cache"))
	}
	if resp, _ = req("GET", "/page", "Authorization", "Bearer x"); resp.Header.Get("X-Cache") != "BYPASS" {
		t.Fatal("authorized request served from cache")
	}
	// Vary: one entry per encoding.
	req("GET", "/vary", "Accept-Encoding", "gzip")
	req("GET", "/vary", "Accept-Encoding", "br")
	resp, _ = req("GET", "/vary", "Accept-Encoding", "gzip")
	if resp.Header.Get("X-Cache") != "HIT" || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("vary gzip: %s %s", resp.Header.Get("X-Cache"), resp.Header.Get("Content-Encoding"))
	}
	resp, _ = req("GET", "/vary", "Accept-Encoding", "br")
	if resp.Header.Get("X-Cache") != "HIT" || resp.Header.Get("Content-Encoding") != "br" {
		t.Fatalf("vary br: %s %s", resp.Header.Get("X-Cache"), resp.Header.Get("Content-Encoding"))
	}
	// Above the object bound: streamed, not stored.
	req("GET", "/big")
	if resp, body = req("GET", "/big"); resp.Header.Get("X-Cache") != "MISS" || len(body) != 3000 {
		t.Fatalf("big: %s %d", resp.Header.Get("X-Cache"), len(body))
	}
	// max-age from the upstream wins over the route ttl (observable in
	// the stored expiry through a purge count only; assert it caches).
	req("GET", "/maxage")
	if resp, _ = req("GET", "/maxage"); resp.Header.Get("X-Cache") != "HIT" {
		t.Fatal("max-age response not cached")
	}
	// Purge.
	if n := eng(s).cache.Load().Purge("other.test", "/"); n != 0 {
		t.Fatalf("purged %d for another host", n)
	}
	if n := eng(s).cache.Load().Purge("h.test", "/pa"); n != 2 { // /page and /page?x=1
		t.Fatalf("purged %d, want 2", n)
	}
	if resp, _ = req("GET", "/page"); resp.Header.Get("X-Cache") != "MISS" {
		t.Fatal("entry survived purge")
	}
	st := eng(s).cache.Load().Stats()
	if st.Hits < 4 || st.Stores < 5 || st.Entries == 0 {
		t.Fatalf("stats %+v", st)
	}
	var mb strings.Builder
	if err := s.WriteMetrics(&mb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mb.String(), "xproxy_cache_hits_total ") {
		t.Fatal("metric missing")
	}
}
