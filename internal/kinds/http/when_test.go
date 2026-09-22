package http

import (
	"fmt"
	"strings"
	"testing"
)

func TestWhenRoutingAndHeaders(t *testing.T) {
	a, b := newBackend(t, "a"), newBackend(t, "b")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - {name: a, endpoints: [{address: "%s"}]}
  - {name: b, endpoints: [{address: "%s"}]}
routes:
  - name: beta
    paths: ["/"]
    when: 'header("X-Env") == "beta" && client_ip in cidr("127.0.0.0/8") && method in ["GET", "HEAD"]'
    upstream: b
    request_headers: {set: {X-Debug: "on"}, when: 'query("debug") == "1"'}
  - name: main
    paths: ["/"]
    upstream: a
    response_headers: {set: {X-Served: "${upstream}"}, when: 'starts_with(path, "/api") and not has_cookie("quiet")'}
`
	_, url := startServer(t, fmt.Sprintf(yaml, a.addr(), b.addr()))
	if _, body := get(t, url+"/x"); body != "a:/x" {
		t.Fatalf("no header: %s", body)
	}
	if _, body := get(t, url+"/x", "X-Env", "beta"); body != "b:/x" {
		t.Fatalf("beta header: %s", body)
	}
	if resp, _ := get(t, url+"/x?debug=1", "X-Env", "beta"); resp.Header.Get("X-Served") != "" {
		t.Fatal("response ops of the other route applied")
	}
	// The request header operation is gated by its own condition.
	if _, body := get(t, url+"/x?debug=1", "X-Env", "beta"); !strings.HasPrefix(body, "b:") {
		t.Fatalf("debug: %s", body)
	}
	if got := b.last.Load().Header.Get("X-Debug"); got != "on" {
		t.Fatalf("X-Debug with debug=1: %q", got)
	}
	if _, body := get(t, url+"/y", "X-Env", "beta"); body != "b:/y" {
		t.Fatal(body)
	}
	if got := b.last.Load().Header.Get("X-Debug"); got != "" {
		t.Fatalf("X-Debug without debug=1: %q", got)
	}
	// Response header operation with a condition on path and cookie.
	if resp, _ := get(t, url+"/api/v1"); resp.Header.Get("X-Served") != "a" {
		t.Fatalf("X-Served: %q", resp.Header.Get("X-Served"))
	}
	if resp, _ := get(t, url+"/api/v1", "Cookie", "quiet=1"); resp.Header.Get("X-Served") != "" {
		t.Fatal("X-Served set despite the cookie")
	}
	if resp, _ := get(t, url+"/other"); resp.Header.Get("X-Served") != "" {
		t.Fatal("X-Served set outside /api")
	}
}
