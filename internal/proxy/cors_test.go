package proxy

import (
	"fmt"
	"net/http"
	"testing"
)

const corsYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - name: api
    hosts: [api.test]
    upstream: app
    cors:
      allow_origins: ["https://app.example", "https://*.trusted.example"]
      allow_methods: [GET, POST]
      allow_headers: [X-Custom]
      expose_headers: [X-Total]
      allow_credentials: true
      max_age: 1h
  - name: any
    hosts: [any.test]
    upstream: app
    cors: {allow_origins: ["*"]}
`

func TestCORS(t *testing.T) {
	a := newBackend(t, "a")
	_, url := startServer(t, fmt.Sprintf(corsYAML, a.addr()))
	do := func(method, host, origin string, hdr ...string) *http.Response {
		r, _ := http.NewRequest(method, url+"/x", nil)
		r.Host = host
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	// Preflight from an allowed exact origin: 204 with the headers, no
	// backend hit.
	before := a.hits.Load()
	resp := do("OPTIONS", "api.test", "https://app.example", "Access-Control-Request-Method", "POST", "Access-Control-Request-Headers", "X-Custom")
	if resp.StatusCode != 204 || a.hits.Load() != before {
		t.Fatalf("preflight status %d hits", resp.StatusCode)
	}
	h := resp.Header
	if h.Get("Access-Control-Allow-Origin") != "https://app.example" || h.Get("Access-Control-Allow-Credentials") != "true" ||
		h.Get("Access-Control-Allow-Methods") != "GET, POST" || h.Get("Access-Control-Allow-Headers") != "X-Custom" || h.Get("Access-Control-Max-Age") != "3600" {
		t.Fatalf("preflight headers %v", h)
	}
	// A wildcard host origin is allowed.
	resp = do("OPTIONS", "api.test", "https://a.trusted.example", "Access-Control-Request-Method", "GET")
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://a.trusted.example" {
		t.Fatalf("wildcard preflight: %v", resp.Header)
	}
	// A disallowed origin: 204 without the allow header, so the browser blocks it.
	resp = do("OPTIONS", "api.test", "https://evil.example", "Access-Control-Request-Method", "POST")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("evil origin allowed: %v", resp.Header)
	}
	// An actual request from the allowed origin carries the headers and
	// reaches the backend.
	before = a.hits.Load()
	resp = do("GET", "api.test", "https://app.example")
	if resp.StatusCode != 200 || a.hits.Load() != before+1 {
		t.Fatalf("actual request: %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" || resp.Header.Get("Access-Control-Expose-Headers") != "X-Total" {
		t.Fatalf("actual headers %v", resp.Header)
	}
	// An actual request from a disallowed origin gets no CORS headers.
	resp = do("GET", "api.test", "https://evil.example")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("evil actual allowed: %v", resp.Header)
	}
	// The any-origin route echoes "*" without credentials.
	resp = do("OPTIONS", "any.test", "https://whatever.example", "Access-Control-Request-Method", "GET")
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("any origin: %v", resp.Header)
	}
	// A request with no Origin is untouched.
	resp = do("GET", "api.test", "")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("no-origin request got CORS headers: %v", resp.Header)
	}
}

func TestCORSPatternUnit(t *testing.T) {
	cases := []struct {
		pattern, origin string
		want            bool
	}{
		{"https://*.example.com", "https://a.example.com", true},
		{"https://*.example.com", "https://a.b.example.com", true},
		{"https://*.example.com", "https://example.com", false},
		{"https://*.example.com", "http://a.example.com", false},
		{"https://*.example.com", "https://a.evil.com", false},
		{"https://*.example.com", "https://a.example.com.evil.com", false},
	}
	for _, c := range cases {
		if got := matchOriginPattern(c.pattern, c.origin); got != c.want {
			t.Errorf("%s vs %s: got %v want %v", c.pattern, c.origin, got, c.want)
		}
	}
}
