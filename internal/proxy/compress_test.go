package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/rom/xproxy/internal/config"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompression(t *testing.T) {
	big := strings.Repeat(`{"k":"value"},`, 400) // ~5.6 KiB
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"abc"`)
			w.Header().Set("Content-Length", fmt.Sprint(len(big)))
			_, _ = io.WriteString(w, big)
		case "/small":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		case "/chunked":
			w.Header().Set("Content-Type", "text/plain")
			for i := 0; i < 50; i++ {
				_, _ = io.WriteString(w, strings.Repeat("line\n", 20))
				w.(http.Flusher).Flush()
			}
		case "/pre":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = io.WriteString(gz, big)
			_ = gz.Close()
		case "/notransform":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "no-transform")
			_, _ = io.WriteString(w, big)
		case "/image":
			w.Header().Set("Content-Type", "image/png")
			_, _ = io.WriteString(w, big)
		case "/range":
			w.Header().Set("Content-Type", "text/plain")
			http.ServeContent(w, r, "x.txt", time.Time{}, strings.NewReader(big))
		case "/empty":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(origin.Close)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(strings.Repeat("var x = 1;\n", 300)), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
compression: {level: 6, min_bytes: 512}
upstreams:
  - name: o
    endpoints: [{address: %q}]
routes:
  - name: raw
    paths: [/raw]
    strip_prefix: /raw
    compress: false
    upstream: o
  - name: static
    paths: [/static]
    strip_prefix: /static
    static: {root: %q}
  - name: text
    paths: [/text]
    respond: {status: 200, body: %q}
  - name: app
    paths: [/]
    upstream: o
`, strings.TrimPrefix(origin.URL, "http://"), dir, strings.Repeat("hello world ", 200))
	s, url := startServer(t, yaml)

	fetch := func(path string, hdr ...string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, url+path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		tr := &http.Transport{DisableCompression: true}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var rd io.Reader = resp.Body
		if resp.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(resp.Body)
			if err != nil {
				t.Fatalf("%s: not gzip: %v", path, err)
			}
			rd = gz
		}
		b, _ := io.ReadAll(rd)
		return resp, string(b)
	}

	// A proxied JSON body with a known length: compressed, length dropped,
	// ETag weakened, Vary added.
	resp, body := fetch("/json")
	if resp.Header.Get("Content-Encoding") != "gzip" || body != big || resp.Header.Get("Content-Length") != "" || resp.Header.Get("ETag") != `W/"abc"` || !strings.Contains(resp.Header.Get("Vary"), "Accept-Encoding") {
		t.Fatalf("json: %v %d", resp.Header, len(body))
	}
	// Small bodies (unknown length, below min_bytes at close) pass as is,
	// with a length and the Vary header.
	if resp, body := fetch("/small"); resp.Header.Get("Content-Encoding") != "" || body != `{"ok":true}` || !strings.Contains(resp.Header.Get("Vary"), "Accept-Encoding") {
		t.Fatalf("small: %v %q", resp.Header, body)
	}
	// Streamed text is compressed and arrives whole.
	if resp, body := fetch("/chunked"); resp.Header.Get("Content-Encoding") != "gzip" || len(body) != 50*100 {
		t.Fatalf("chunked: %v %d", resp.Header, len(body))
	}
	// Already encoded, no-transform, unlisted type, range, 204: untouched.
	if resp, body := fetch("/pre"); resp.Header.Get("Content-Encoding") != "gzip" || body != big || resp.Header.Get("Vary") != "" {
		t.Fatalf("pre-encoded: %v", resp.Header)
	}
	if resp, body := fetch("/notransform"); resp.Header.Get("Content-Encoding") != "" || body != big {
		t.Fatalf("no-transform: %v", resp.Header)
	}
	if resp, body := fetch("/image"); resp.Header.Get("Content-Encoding") != "" || body != big || resp.Header.Get("Vary") != "" {
		t.Fatalf("image: %v", resp.Header)
	}
	if resp, body := fetch("/range", "Range", "bytes=0-9"); resp.StatusCode != 206 || resp.Header.Get("Content-Encoding") != "" || body != big[:10] {
		t.Fatalf("range: %d %v %q", resp.StatusCode, resp.Header, body)
	}
	if resp, _ := fetch("/empty"); resp.StatusCode != 204 || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("204: %d %v", resp.StatusCode, resp.Header)
	}
	// Clients that accept none of the offered encodings, or refuse them,
	// get identity.
	for _, ae := range []string{"", "deflate", "gzip;q=0, br;q=0, zstd;q=0", "*;q=0", "identity"} {
		if resp, body := fetch("/json", "Accept-Encoding", ae); resp.Header.Get("Content-Encoding") != "" || body != big {
			t.Fatalf("accept-encoding %q: %v", ae, resp.Header)
		}
	}
	if resp, body := fetch("/json", "Accept-Encoding", "deflate, *;q=0.5"); resp.Header.Get("Content-Encoding") != "br" {
		t.Fatalf("wildcard: %v", resp.Header)
	} else if dec, err := io.ReadAll(brotli.NewReader(strings.NewReader(body))); err != nil || string(dec) != big {
		t.Fatalf("wildcard body: %v", err)
	}
	// HEAD is never compressed.
	head, _ := http.NewRequest(http.MethodHead, url+"/json", nil)
	head.Header.Set("Accept-Encoding", "gzip")
	if resp, err := http.DefaultTransport.RoundTrip(head); err != nil || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("head: %v %v", resp, err)
	}
	// Per route opt-out.
	if resp, body := fetch("/raw/json"); resp.Header.Get("Content-Encoding") != "" || body != big {
		t.Fatalf("compress: false: %v", resp.Header)
	}
	// Static files and respond bodies go through the same writer.
	if resp, body := fetch("/static/app.js"); resp.Header.Get("Content-Encoding") != "gzip" || len(body) != 3300 || !strings.HasPrefix(resp.Header.Get("ETag"), `W/"`) {
		t.Fatalf("static: %v %d", resp.Header, len(body))
	}
	if resp, body := fetch("/text"); resp.Header.Get("Content-Encoding") != "gzip" || len(body) != 2400 {
		t.Fatalf("respond: %v %d", resp.Header, len(body))
	}
	if st := s.Stats(); st.Compressed < 5 || st.CompressedRawBytes < 10000 {
		t.Fatalf("counters %+v", st)
	}
}

func TestWantsGzip(t *testing.T) {
	cases := map[string]bool{
		"":                        false,
		"gzip":                    true,
		"GZIP, deflate":           true,
		"x-gzip":                  true,
		"gzip;q=0":                false,
		"gzip;q=0.001":            true,
		"br, *":                   true,
		"br, *;q=0":               false,
		"identity":                false,
		"deflate;q=1.0, gzip;q=0": false,
	}
	for ae, want := range cases {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		if ae != "" {
			r.Header.Set("Accept-Encoding", ae)
		}
		if got := wantsGzip(r); got != want {
			t.Errorf("%q: %v", ae, got)
		}
	}
}

// TestCompressionEncodings covers Brotli and zstd next to gzip: bodies
// decode, quality and order decide, and the offer can be restricted.
func TestCompressionEncodings(t *testing.T) {
	big := strings.Repeat(`{"k":"value"},`, 400)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(len(big)))
		_, _ = io.WriteString(w, big)
	}))
	t.Cleanup(origin.Close)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
compression: {min_bytes: 512, brotli_level: 5, zstd_level: 3}
upstreams:
  - name: o
    endpoints: [{address: %q}]
routes:
  - {name: r, upstream: o}
`, strings.TrimPrefix(origin.URL, "http://"))
	_, url := startServer(t, yaml)
	tr := &http.Transport{DisableCompression: true}
	fetch := func(accept string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest("GET", url+"/", nil)
		req.Header.Set("Accept-Encoding", accept)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, body
	}
	decode := func(enc string, body []byte) string {
		t.Helper()
		var r io.Reader
		switch enc {
		case "br":
			r = brotli.NewReader(bytes.NewReader(body))
		case "zstd":
			d, err := zstd.NewReader(bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			r = d
		case "gzip":
			g, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			r = g
		default:
			return string(body)
		}
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	cases := []struct{ accept, want string }{
		{"br", "br"},
		{"zstd", "zstd"},
		{"gzip", "gzip"},
		{"gzip, br", "br"},              // equal quality: server order
		{"br;q=0.5, gzip", "gzip"},      // client quality wins
		{"*", "br"},                     // wildcard: the preferred one
		{"deflate", ""},                 // nothing offered
		{"br;q=0, zstd;q=0, *", "gzip"}, // refused ones are skipped, * covers the rest
	}
	for _, c := range cases {
		resp, body := fetch(c.accept)
		got := resp.Header.Get("Content-Encoding")
		if got != c.want {
			t.Fatalf("Accept-Encoding %q: got %q want %q", c.accept, got, c.want)
		}
		if decode(got, body) != big {
			t.Fatalf("Accept-Encoding %q: body does not decode", c.accept)
		}
		if c.want != "" && (resp.Header.Get("Vary") != "Accept-Encoding" || len(body) >= len(big)) {
			t.Fatalf("Accept-Encoding %q: vary %q size %d", c.accept, resp.Header.Get("Vary"), len(body))
		}
	}

	// An offer restricted to gzip leaves a Brotli only client uncompressed.
	_, url2 := startServer(t, strings.Replace(yaml, "compression: {min_bytes: 512, brotli_level: 5, zstd_level: 3}", "compression: {min_bytes: 512, encodings: [gzip]}", 1))
	req, _ := http.NewRequest("GET", url2+"/", nil)
	req.Header.Set("Accept-Encoding", "br")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("gzip only offer compressed with %q", resp.Header.Get("Content-Encoding"))
	}

	// Validation.
	for name, snippet := range map[string]string{
		"encoding":  "compression: {encodings: [deflate]}",
		"duplicate": "compression: {encodings: [br, br]}",
		"brotli":    "compression: {brotli_level: 12}",
		"zstd":      "compression: {zstd_level: 9}",
	} {
		if _, err := config.ParseWith([]byte(strings.Replace(yaml, "compression: {min_bytes: 512, brotli_level: 5, zstd_level: 3}", snippet, 1)), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Compressing the response to a request that carried the victim's
// authority is the BREACH condition: a secret and attacker-chosen text
// in one compressed body leak the secret through its length, a
// character at a time, and a request a browser sends with the victim's
// cookies is exactly what an attacker can arrange.
func TestCompressionSkipsCredentialedRequests(t *testing.T) {
	body := strings.Repeat("hello world ", 200)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
compression: {level: 6, min_bytes: 512}
routes:
  - name: opted
    paths: [/opted]
    compress_authenticated: true
    respond: {status: 200, body: %q}
  - name: text
    paths: [/]
    respond: {status: 200, body: %q}
`, body, body)
	_, url := startServer(t, yaml)
	get := func(path string, hdr ...string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, url+path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		tr := &http.Transport{DisableCompression: true}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Header.Get("Content-Encoding")
	}
	if enc := get("/text"); enc != "gzip" {
		t.Fatalf("an anonymous request was not compressed: %q", enc)
	}
	for _, h := range [][]string{{"Cookie", "session=abc"}, {"Authorization", "Bearer x"}} {
		if enc := get("/text", h...); enc != "" {
			t.Fatalf("%s: compressed anyway (%q)", h[0], enc)
		}
		// The route that opts in is compressed as before.
		if enc := get("/opted", h...); enc != "gzip" {
			t.Fatalf("%s: the opted-in route was not compressed: %q", h[0], enc)
		}
	}
}
