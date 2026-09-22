package http

import (
	"fmt"
	"strings"
	"testing"
)

const routingYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
  - name: b
    endpoints: [{address: "%s"}]
routes:
  - name: canary
    hosts: [app.test]
    headers: [{name: X-Canary, exact: "1"}]
    upstream: b
  - name: beta-cookie
    hosts: [app.test]
    cookies: [{name: beta, present: true}]
    upstream: b
  - name: versioned
    hosts: [app.test]
    path_regex: ['/api/v[0-9]+/items/[0-9]+']
    strip_prefix: /api
    upstream: b
  - name: app
    hosts: [app.test]
    upstream: a
`

func TestRoutingByRegexAndHeaders(t *testing.T) {
	a, b := newBackend(t, "a"), newBackend(t, "b")
	_, url := startServer(t, fmt.Sprintf(routingYAML, a.addr(), b.addr()))

	check := func(path, want string, hdr ...string) {
		t.Helper()
		resp, body := get(t, url+path, append([]string{"Host", "app.test"}, hdr...)...)
		if resp.StatusCode != 200 || body != want {
			t.Fatalf("%s %v: %d %q, want %q", path, hdr, resp.StatusCode, body, want)
		}
	}
	check("/x", "a:/x")
	check("/x", "b:/x", "X-Canary", "1")
	check("/x", "a:/x", "X-Canary", "0")
	check("/x", "b:/x", "Cookie", "beta=on; other=1")
	check("/x", "a:/x", "Cookie", "other=1")
	check("/api/v2/items/17", "b:/v2/items/17")
	check("/api/v2/items/seventeen", "a:/api/v2/items/seventeen")
	check("/api/v2/items/17/x", "a:/api/v2/items/17/x")
	// Dot segments are refused before matching by default (the upstream
	// would receive them unresolved); with the check off they are cleaned
	// for routing.
	if resp, _ := get(t, url+"/api/v2/../v3/items/1", "Host", "app.test"); resp.StatusCode != 400 {
		t.Fatalf("dot segment routed: %d", resp.StatusCode)
	}
	lenient := "server:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\n  normalization: {reject_dot_segments: false}\n"
	_, url = startServer(t, fmt.Sprintf(strings.Replace(routingYAML, "server:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\n", lenient, 1), a.addr(), b.addr()))
	check("/api/v2/../v3/items/1", "b:/v3/items/1")
}
