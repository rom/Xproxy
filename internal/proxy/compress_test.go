package proxy

import (
	"compress/gzip"
	"fmt"
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
	// Clients that do not accept gzip, or refuse it, get identity.
	for _, ae := range []string{"", "br", "gzip;q=0", "*;q=0", "identity"} {
		if resp, body := fetch("/json", "Accept-Encoding", ae); resp.Header.Get("Content-Encoding") != "" || body != big {
			t.Fatalf("accept-encoding %q: %v", ae, resp.Header)
		}
	}
	if resp, body := fetch("/json", "Accept-Encoding", "deflate, *;q=0.5"); resp.Header.Get("Content-Encoding") != "gzip" || body != big {
		t.Fatalf("wildcard: %v", resp.Header)
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
