package http

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
)

const policyYAML = `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
virtual_patches:
  - id: cve-2024-1234
    description: legacy export RCE
    paths: [/plugins/legacy-export]
    methods: [GET, POST]
    query: [{name: cmd}]
    status: 404
  - id: header-probe
    hosts: ["*.test"]
    headers: [{name: X-Exploit, pattern: "(?i)^\\$\\{jndi:"}]
  - id: body-probe
    routes: [api]
    body: {pattern: "__proto__", content_types: [application/json]}
  - id: logged
    paths: [/watch]
    action: log
  - id: gone
    paths: [/gone]
    expires: "2001-01-01"
  - id: off
    paths: [/off]
    enabled: false
upstreams:
  - name: app
    endpoints: [{address: %s}]
routes:
  - name: api
    hosts: [api.test]
    paths: [/]
    upstream: app
    policy:
      methods: [GET, POST]
      content_types: [application/json, text/*]
      require_content_type: true
      max_uri_length: 200
      max_query_bytes: 100
      max_query_params: 10
      max_headers: 20
      max_header_bytes: 4096
      deny_unknown_query: true
      query:
        - {name: id, type: int, required: true}
        - {name: page, type: int}
        - {name: kind, type: enum, values: [a, b]}
        - {name: tag, type: string, max_length: 5, pattern: "[a-z]+", max_repeat: 2}
        - {name: ref, type: uuid}
        - {name: flag, type: bool}
        - {name: price, type: number}
  - name: web
    paths: [/]
    upstream: app
`

func TestRoutePolicy(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(policyYAML, a.addr()))
	req := func(method, path, ct, body string, hdr ...string) *http.Response {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		r, _ := http.NewRequest(method, url+path, rd)
		r.Host = "api.test"
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Add(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	if resp := req("GET", "/items?id=7&kind=a&tag=ab&tag=cd&ref=123e4567-e89b-12d3-a456-426614174000&flag=true&price=1.5", "", ""); resp.StatusCode != 200 {
		t.Fatalf("valid request: %d", resp.StatusCode)
	}
	if resp := req("POST", "/items?id=1", "application/json", `{"a":1}`); resp.StatusCode != 200 {
		t.Fatalf("valid post: %d", resp.StatusCode)
	}
	cases := []struct {
		name   string
		resp   *http.Response
		status int
	}{
		{"method", req("DELETE", "/items?id=1", "", ""), 405},
		{"content type", req("POST", "/items?id=1", "application/xml", "<a/>"), 415},
		{"content type param", req("POST", "/items?id=1", "text/plain; charset=utf-8", "x"), 200},
		{"missing content type", req("POST", "/items?id=1", "", "x"), 415},
		{"missing required", req("GET", "/items?page=2", "", ""), 400},
		{"unknown param", req("GET", "/items?id=1&zzz=1", "", ""), 400},
		{"not int", req("GET", "/items?id=abc", "", ""), 400},
		{"enum", req("GET", "/items?id=1&kind=z", "", ""), 400},
		{"too long", req("GET", "/items?id=1&tag=abcdefg", "", ""), 400},
		{"pattern", req("GET", "/items?id=1&tag=AB", "", ""), 400},
		{"repeat", req("GET", "/items?id=1&tag=a&tag=b&tag=c", "", ""), 400},
		{"uuid", req("GET", "/items?id=1&ref=nope", "", ""), 400},
		{"bool", req("GET", "/items?id=1&flag=maybe", "", ""), 400},
		{"number", req("GET", "/items?id=1&price=x", "", ""), 400},
		{"query bytes", req("GET", "/items?id=1&tag="+strings.Repeat("a", 5)+"&"+strings.Repeat("x", 100), "", ""), 414},
		{"uri length", req("GET", "/"+strings.Repeat("p", 195)+"?id=1", "", ""), 414},
		{"header count", req("GET", "/items?id=1", "", "", manyHeaders(25)...), 431},
		{"header bytes", req("GET", "/items?id=1", "", "", "X-Big", strings.Repeat("v", 5000)), 431},
	}
	for _, c := range cases {
		if c.resp.StatusCode != c.status {
			t.Errorf("%s: got %d want %d", c.name, c.resp.StatusCode, c.status)
		}
	}
	if resp := req("DELETE", "/items?id=1", "", ""); resp.Header.Get("Allow") != "GET, POST" {
		t.Fatalf("allow header %q", resp.Header.Get("Allow"))
	}
	// The other route has no policy.
	r, _ := http.NewRequest("DELETE", url+"/anything?zzz=1", nil)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("route without policy: %d", resp.StatusCode)
	}
	if sn := s.Stats(); sn.DeniedPolicy < 17 {
		t.Fatalf("denied_policy = %d", sn.DeniedPolicy)
	}
}

func manyHeaders(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("X-H%d", i), "v")
	}
	return out
}

func TestVirtualPatches(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(policyYAML, a.addr()))
	do := func(method, host, path, ct, body string, hdr ...string) *http.Response {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		r, _ := http.NewRequest(method, url+path, rd)
		r.Host = host
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Add(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	// Path, method and query parameter all required for the first patch.
	if resp := do("GET", "web.test", "/plugins/legacy-export/run?cmd=id", "", ""); resp.StatusCode != 404 {
		t.Fatalf("patched path: %d", resp.StatusCode)
	}
	if resp := do("GET", "web.test", "/plugins/legacy-export/run?other=1", "", ""); resp.StatusCode != 200 {
		t.Fatalf("path without the parameter: %d", resp.StatusCode)
	}
	if resp := do("PUT", "web.test", "/plugins/legacy-export/run?cmd=id", "", ""); resp.StatusCode != 200 {
		t.Fatalf("other method: %d", resp.StatusCode)
	}
	// Header pattern scoped to wildcard hosts.
	if resp := do("GET", "shop.test", "/", "", "", "X-Exploit", "${jndi:ldap://x}"); resp.StatusCode != 403 {
		t.Fatalf("header probe: %d", resp.StatusCode)
	}
	if resp := do("GET", "shop.test", "/", "", "", "X-Exploit", "harmless"); resp.StatusCode != 200 {
		t.Fatalf("header without pattern match: %d", resp.StatusCode)
	}
	if resp := do("GET", "other.example", "/", "", "", "X-Exploit", "${jndi:ldap://x}"); resp.StatusCode != 200 {
		t.Fatalf("host outside the pattern: %d", resp.StatusCode)
	}
	// Body pattern scoped to a route and media type; the body is replayed.
	if resp := do("POST", "api.test", "/x?id=1", "application/json", `{"__proto__":{"admin":true}}`); resp.StatusCode != 403 {
		t.Fatalf("body probe: %d", resp.StatusCode)
	}
	if resp := do("POST", "api.test", "/x?id=1", "application/json", `{"name":"ok"}`); resp.StatusCode != 200 {
		t.Fatalf("clean body: %d", resp.StatusCode)
	}
	if got := a.last.Load().Header.Get("X-Test-Body"); got != `{"name":"ok"}` {
		t.Fatalf("body not replayed: %q", got)
	}
	if resp := do("POST", "api.test", "/x?id=1", "text/plain", `__proto__`); resp.StatusCode != 200 {
		t.Fatalf("other media type inspected: %d", resp.StatusCode)
	}
	if resp := do("POST", "web.test", "/x", "application/json", `{"__proto__":1}`); resp.StatusCode != 200 {
		t.Fatalf("other route: %d", resp.StatusCode)
	}
	// Log action, expired and disabled patches let requests through.
	for _, p := range []string{"/watch", "/gone", "/off"} {
		if resp := do("GET", "web.test", p, "", ""); resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	ps := s.VirtualPatches()
	byID := map[string]proxy.PatchStatus{}
	for _, p := range ps {
		byID[p.ID] = p
	}
	if len(ps) != 6 || byID["cve-2024-1234"].Hits != 1 || byID["header-probe"].Hits != 1 || byID["body-probe"].Hits != 1 || byID["logged"].Hits != 1 {
		t.Fatalf("patch status %+v", ps)
	}
	if byID["gone"].Hits != 0 || !byID["gone"].Expired || byID["off"].Enabled || byID["cve-2024-1234"].LastHit.IsZero() || byID["cve-2024-1234"].Status != 404 {
		t.Fatalf("patch flags %+v", byID)
	}
	if sn := s.Stats(); sn.DeniedVirtualPatch != 3 {
		t.Fatalf("denied_virtual_patch = %d", sn.DeniedVirtualPatch)
	}
	// Counters survive a reload.
	if err := s.Reload(mustParse(t, fmt.Sprintf(policyYAML, a.addr()))); err != nil {
		t.Fatal(err)
	}
	for _, p := range s.VirtualPatches() {
		if p.ID == "cve-2024-1234" && p.Hits != 1 {
			t.Fatalf("hits lost on reload: %+v", p)
		}
	}
	time.Sleep(10 * time.Millisecond)
}

func TestPolicyHelpers(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"*.test", "a.test", true}, {"*.test", "a.b.test", false}, {"*.test", "test", false}, {"api.test", "api.test", true}, {"api.test", "x.api.test", false},
	} {
		if got := hostMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("hostMatches(%q,%q)=%v", tc.pattern, tc.host, got)
		}
	}
	if !mediaAllowed([]string{"text/*"}, "text/html") || mediaAllowed([]string{"text/*"}, "application/json") || !mediaAllowed([]string{"*/*"}, "x/y") {
		t.Fatal("mediaAllowed")
	}
	if !isUUID("123e4567-e89b-12d3-a456-426614174000") || isUUID("123e4567-e89b-12d3-a456-42661417400g") {
		t.Fatal("isUUID")
	}
}

// A virtual patch is the emergency control that holds a known
// vulnerability while the application is fixed, so a body it could not
// read counts as a match by default: padding past max_bytes used to
// carry the same payload straight to the origin, while the WAF and
// ICAP both refuse an oversize body.
func TestVirtualPatchOverLimit(t *testing.T) {
	a := newBackend(t, "a")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: %q}]
virtual_patches:
  - id: strict
    paths: [/strict]
    body: {pattern: "__proto__", max_bytes: 1024}
  - id: lenient
    paths: [/lenient]
    body: {pattern: "__proto__", max_bytes: 1024, over_limit: skip}
routes:
  - name: r
    paths: [/]
    upstream: u
`, a.addr())
	_, url := startServer(t, yaml)
	post := func(path, body string) int {
		t.Helper()
		resp, err := http.Post(url+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	payload := `{"__proto__":{"admin":true}}`
	padded := `{"pad":"` + strings.Repeat("x", 2048) + `","__proto__":{"admin":true}}`
	if got := post("/strict", payload); got != 403 {
		t.Fatalf("the payload was not caught: %d", got)
	}
	if got := post("/strict", padded); got != 403 {
		t.Fatalf("padding past max_bytes carried the payload through: %d", got)
	}
	if got := post("/lenient", payload); got != 403 {
		t.Fatalf("over_limit: skip changed a body it could read: %d", got)
	}
	if got := post("/lenient", padded); got != 200 {
		t.Fatalf("over_limit: skip refused an oversize body: %d", got)
	}
}
