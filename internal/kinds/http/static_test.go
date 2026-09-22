package http

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticFiles(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(root, "index.html"), []byte("<h1>home</h1>"), 0o600))
	must(os.WriteFile(filepath.Join(root, "app.js"), []byte("console.log(1)"), 0o600))
	must(os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET=1"), 0o600))
	must(os.WriteFile(filepath.Join(root, "big.bin"), make([]byte, 100), 0o600))
	must(os.MkdirAll(filepath.Join(root, "sub", ".git"), 0o700))
	must(os.WriteFile(filepath.Join(root, "sub", "a.txt"), []byte("aaa"), 0o600))
	must(os.WriteFile(filepath.Join(root, "sub", ".git", "config"), []byte("[core]"), 0o600))
	must(os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o600))
	must(os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "link")))
	must(os.Symlink(outside, filepath.Join(root, "dir-link")))

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
routes:
  - name: site
    paths: [/site]
    strip_prefix: /site
    static: {root: %[1]q, cache_control: "public, max-age=60"}
  - name: spa
    paths: [/spa]
    strip_prefix: /spa
    static: {root: %[1]q, fallback: /index.html}
  - name: list
    paths: [/list]
    strip_prefix: /list
    static: {root: %[1]q, listing: true, index: ""}
  - name: small
    paths: [/small]
    strip_prefix: /small
    static: {root: %[1]q, max_file_bytes: 10}
  - name: dots
    paths: [/dots]
    strip_prefix: /dots
    static: {root: %[1]q, dot_files: true}
`, root)
	s, url := startServer(t, yaml)

	resp, body := get(t, url+"/site/")
	if resp.StatusCode != 200 || body != "<h1>home</h1>" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("index: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if resp.Header.Get("Cache-Control") != "public, max-age=60" || resp.Header.Get("ETag") == "" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", resp.Header)
	}
	etag := resp.Header.Get("ETag")
	if resp, _ := get(t, url+"/site/index.html", "If-None-Match", etag); resp.StatusCode != 304 {
		t.Fatalf("conditional: %d", resp.StatusCode)
	}
	if resp, body := get(t, url+"/site/app.js"); resp.StatusCode != 200 || body != "console.log(1)" || resp.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatalf("js: %d %q %v", resp.StatusCode, body, resp.Header.Get("Content-Type"))
	}
	if resp, body := get(t, url+"/site/sub/a.txt", "Range", "bytes=0-1"); resp.StatusCode != 206 || body != "aa" {
		t.Fatalf("range: %d %q", resp.StatusCode, body)
	}
	// Directory without a slash redirects; with a slash and no index and
	// no listing it is 404.
	if resp, _ := get(t, url+"/site/sub"); resp.StatusCode != 301 || resp.Header.Get("Location") != "/site/sub/" {
		t.Fatalf("dir redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := get(t, url+"/site/sub/"); resp.StatusCode != 404 {
		t.Fatalf("dir without index: %d", resp.StatusCode)
	}
	// Nothing leaves the root or exposes dot files.
	// Dot-segment forms are refused by the normalization guard (400)
	// before the static handler; the rest are 404.
	for _, p := range []string{"/site/.env", "/site/sub/.git/config", "/site/link", "/site/dir-link/secret", "/site/../../etc/passwd", "/site/%2e%2e/%2e%2e/etc/passwd", "/site/missing", "/site/sub/../.env"} {
		if resp, body := get(t, url+p); (resp.StatusCode != 404 && resp.StatusCode != 400) || strings.Contains(body, "SECRET") || strings.Contains(body, "outside") {
			t.Fatalf("%s: %d %q", p, resp.StatusCode, body)
		}
	}
	if resp, body := get(t, url+"/dots/.env"); resp.StatusCode != 200 || body != "SECRET=1" {
		t.Fatalf("dot_files: %d %q", resp.StatusCode, body)
	}
	// Methods.
	req, _ := http.NewRequest(http.MethodPost, url+"/site/index.html", strings.NewReader("x"))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("post: %v %v", resp, err)
	}
	head, _ := http.NewRequest(http.MethodHead, url+"/site/app.js", nil)
	if resp, err := http.DefaultClient.Do(head); err != nil || resp.StatusCode != 200 || resp.ContentLength != 14 {
		t.Fatalf("head: %v %v", resp, err)
	}
	// Fallback for single page applications.
	if resp, body := get(t, url+"/spa/some/deep/route"); resp.StatusCode != 200 || body != "<h1>home</h1>" {
		t.Fatalf("fallback: %d %q", resp.StatusCode, body)
	}
	if resp, body := get(t, url+"/spa/app.js"); resp.StatusCode != 200 || body != "console.log(1)" {
		t.Fatalf("spa asset: %d %q", resp.StatusCode, body)
	}
	// Listing hides dot files and links directories.
	resp, body = get(t, url+"/list/")
	if resp.StatusCode != 200 || !strings.Contains(body, `href="sub/"`) || !strings.Contains(body, `href="app.js"`) || strings.Contains(body, ".env") {
		t.Fatalf("listing: %d %q", resp.StatusCode, body)
	}
	if resp, body := get(t, url+"/list/sub/"); resp.StatusCode != 200 || !strings.Contains(body, `href="../"`) || strings.Contains(body, ".git") {
		t.Fatalf("sub listing: %d %q", resp.StatusCode, body)
	}
	// Size bound.
	if resp, _ := get(t, url+"/small/big.bin"); resp.StatusCode != 404 {
		t.Fatalf("max_file_bytes: %d", resp.StatusCode)
	}
	if resp, body := get(t, url+"/small/sub/a.txt"); resp.StatusCode != 200 || body != "aaa" {
		t.Fatalf("small file under bound: %d %q", resp.StatusCode, body)
	}
	st := s.Stats()
	// Three of the probes above carried dot segments and were refused by
	// the normalization guard before the static handler counted them.
	if st.StaticServed < 8 || st.StaticNotFound < 5 || st.DeniedNormalization < 3 {
		t.Fatalf("counters %+v", st)
	}
	// A vanished root fails the reload, the old generation keeps serving.
	cfg := mustParse(t, yaml)
	cfg.Routes[0].Static.Root = filepath.Join(root, "nope")
	if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), "static root") {
		t.Fatalf("reload with missing root: %v", err)
	}
	if resp, _ := get(t, url+"/site/"); resp.StatusCode != 200 {
		t.Fatalf("after failed reload: %d", resp.StatusCode)
	}
}
