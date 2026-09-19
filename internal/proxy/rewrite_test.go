package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

const rewriteYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  error_pages:
    dir: %[2]s
    pages: {"404": "404.html", "5xx": "5xx.html", "default": "default.html"}
    intercept_upstream: [503]
trusted_proxies: [127.0.0.0/8]
upstreams:
  - name: a
    endpoints: [{address: "%[1]s"}]
  - name: flaky
    endpoints: [{address: "%[3]s"}]
routes:
  - name: api
    hosts: [api.test]
    paths: [/api/]
    rewrite_regex: {pattern: "^/api/v([0-9]+)/(?P<rest>.*)$", replace: "/internal/v${1}/${rest}"}
    request_headers:
      set: {X-Client-Ip: "${client_ip}", X-Api-Version: "${1}", X-Rest: "${rest}", X-Tenant-Seen: "${header:X-Tenant}", X-Req: "${request_id}", X-Literal: "cost $$5"}
      remove: [X-Tenant]
    response_headers:
      set: {X-Route: "${route}", X-Scheme: "${scheme}", X-Q: "${query:q}"}
    tenant: shop
    upstream: a
  - name: legacy
    hosts: [old.test]
    redirect: {to: "https://new.test${path}?${raw_query}", status: 308}
  - name: denied
    hosts: [deny.test]
    deny_cidrs: [192.0.2.0/24]
    error_pages: {dir: %[2]s, pages: {"403": "403.html"}, json: false}
    upstream: a
  - name: flaky
    hosts: [flaky.test]
    upstream: flaky
`

func writeErrorPages(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pages := map[string]string{
		"404.html":     "<h1>${status} ${status_text}</h1><p>${request_id} ${host} ${path}</p><script>const x = `${notavar}`;</script>",
		"5xx.html":     "<h1>upstream trouble ${status}</h1>",
		"default.html": "<h1>default ${status}</h1>",
		"403.html":     "<h1>route page ${status} ${reason}</h1>",
	}
	for name, body := range pages {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRegexRewriteAndTemplates(t *testing.T) {
	a := newBackend(t, "a")
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "upstream body")
	}))
	defer flaky.Close()
	dir := writeErrorPages(t)
	_, url := startServer(t, fmt.Sprintf(rewriteYAML, a.addr(), dir, strings.TrimPrefix(flaky.URL, "http://")))

	// Regex rewrite with a numbered and a named group; templated request
	// and response headers.
	resp, body := getAs(t, url+"/api/v2/users/7?q=hello", "api.test", "192.0.2.9", "X-Tenant", "acme")
	if resp.StatusCode != 200 || body != "a:/internal/v2/users/7" {
		t.Fatalf("rewrite: %d %q", resp.StatusCode, body)
	}
	last := a.last.Load()
	for h, want := range map[string]string{"X-Client-Ip": "192.0.2.9", "X-Api-Version": "2", "X-Rest": "users/7", "X-Tenant-Seen": "acme", "X-Literal": "cost $5", "X-Tenant": ""} {
		if got := last.Header.Get(h); got != want {
			t.Errorf("request header %s = %q want %q", h, got, want)
		}
	}
	if last.Header.Get("X-Req") == "" {
		t.Error("request id template empty")
	}
	if resp.Header.Get("X-Route") != "api" || resp.Header.Get("X-Scheme") != "http" || resp.Header.Get("X-Q") != "hello" {
		t.Errorf("response headers %v", resp.Header)
	}
	// A path that does not match the pattern goes through unchanged.
	if _, body := getAs(t, url+"/api/other", "api.test", "192.0.2.9"); body != "a:/api/other" {
		t.Fatalf("non matching path rewritten: %q", body)
	}

	// Redirect target built from variables.
	req, _ := http.NewRequest("GET", url+"/blog/post?x=1", nil)
	req.Host = "old.test"
	rr, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = rr.Body.Close()
	if rr.StatusCode != 308 || rr.Header.Get("Location") != "https://new.test/blog/post?x=1" {
		t.Fatalf("redirect: %d %q", rr.StatusCode, rr.Header.Get("Location"))
	}

	// Server level 404 page for an unknown host, HTML and JSON forms.
	resp, body = get(t, url+"/nothing", "Host", "nobody.test", "Accept", "text/html")
	if resp.StatusCode != 404 || !strings.Contains(body, "<h1>404 Not Found</h1>") || !strings.Contains(body, "nobody.test /nothing") || !strings.Contains(body, "`${notavar}`") {
		t.Fatalf("404 page: %d %q", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content type %q", ct)
	}
	resp, body = get(t, url+"/nothing", "Host", "nobody.test", "Accept", "application/json")
	if resp.StatusCode != 404 || !strings.Contains(body, `"status":404`) || !strings.Contains(body, `"request_id":"`) || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("404 json: %d %q", resp.StatusCode, body)
	}
	// HEAD gets the headers only.
	hreq, _ := http.NewRequest("HEAD", url+"/nothing", nil)
	hreq.Host = "nobody.test"
	hr, _ := http.DefaultTransport.RoundTrip(hreq)
	hb, _ := io.ReadAll(hr.Body)
	_ = hr.Body.Close()
	if hr.StatusCode != 404 || len(hb) != 0 {
		t.Fatalf("head: %d %d bytes", hr.StatusCode, len(hb))
	}

	// Route level page overrides, with json off and the reason available.
	resp, body = getAs(t, url+"/", "deny.test", "192.0.2.5", "Accept", "application/json")
	if resp.StatusCode != 403 || !strings.Contains(body, "route page 403 acl") {
		t.Fatalf("route page: %d %q", resp.StatusCode, body)
	}

	// Upstream 503 body replaced by the 5xx page; other statuses pass.
	resp, body = getAs(t, url+"/x", "flaky.test", "192.0.2.6")
	if resp.StatusCode != 503 || body != "<h1>upstream trouble 503</h1>" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("intercept: %d %q %q", resp.StatusCode, body, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Content-Length") != "29" {
		t.Fatalf("content length %q", resp.Header.Get("Content-Length"))
	}
}

func TestRewriteConfigRejects(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: a
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    %s
    upstream: a
`
	cases := map[string]string{
		"bad pattern":       `rewrite_regex: {pattern: "(", replace: "/x"}`,
		"replace no slash":  `rewrite_regex: {pattern: "^/a", replace: "x"}`,
		"unknown capture":   `rewrite_regex: {pattern: "^/a", replace: "/${nope}"}`,
		"with rewrite_path": "rewrite_regex: {pattern: \"^/a\", replace: \"/x\"}\n    rewrite_path: /y",
		"header variable":   `request_headers: {set: {X-A: "${bogus}"}}`,
		"header arg":        `response_headers: {add: {X-A: "${header}"}}`,
		"redirect variable": `redirect: {to: "https://x/${zz}", status: 301}`,
		"pages key":         `error_pages: {pages: {"200": "/tmp/x.html"}}`,
		"pages relative":    `error_pages: {pages: {"404": "x.html"}}`,
		"pages empty":       `error_pages: {dir: /tmp}`,
		"intercept range":   `error_pages: {dir: /tmp, pages: {"404": "x.html"}, intercept_upstream: [200]}`,
	}
	for name, snippet := range cases {
		if _, err := config.ParseWith([]byte(strings.Replace(base, "%s", snippet, 1)), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := strings.Replace(base, "%s", `rewrite_regex: {pattern: "^/a/(?P<id>[0-9]+)$", replace: "/b/${id}"}
    request_headers: {set: {X-Id: "${id}", X-Ip: "${client_ip}"}}
    error_pages: {dir: /tmp, pages: {"404": "x.html", "5xx": "/tmp/five.html", "default": "d.html"}, intercept_upstream: [502, 503]}`, 1)
	if _, err := config.ParseWith([]byte(ok), false); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
}
