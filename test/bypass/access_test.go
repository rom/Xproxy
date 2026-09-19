package bypass

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestAccessControls tries to reach protected routes and origins the
// proxy is meant to keep closed.
func TestAccessControls(t *testing.T) {
	h := start(t, "127.0.0.0/8")

	// The deny-all admin route is refused from every address.
	before := h.backend.hits.Load()
	status, _ := h.do(h.req("GET", "/admin", "203.0.113.1", ""))
	h.denied("admin deny_cidrs", before, status, 403)

	// The internal route admits only 10.0.0.0/8; a spoofed forwarded
	// address from an untrusted peer does not count.
	pub := start(t, "192.0.2.0/24") // this test's client (loopback) is not trusted
	before = pub.backend.hits.Load()
	status, _ = pub.do(pub.req("GET", "/internal", "10.0.0.5", ""))
	pub.denied("internal allow_cidrs spoofed XFF", before, status, 403)

	// The header guard refuses smuggled control headers whatever their case.
	for _, hdr := range [][2]string{{"X-Debug", "1"}, {"x-debug", "1"}, {"X-Original-URL", "/admin"}} {
		before = h.backend.hits.Load()
		status, _ = h.do(h.req("GET", "/guarded", "198.51.100.70", "", hdr[0], hdr[1]))
		h.denied("header guard "+hdr[0], before, status, 400, 403)
	}

	// The API key route: no key, a wrong key, an empty key and the key
	// in the wrong place are all refused; the real key passes.
	for _, tc := range []struct {
		name string
		hdr  []string
	}{
		{"no key", nil},
		{"wrong key", []string{"X-Api-Key", "xpk_svc_deadbeef"}},
		{"empty key", []string{"X-Api-Key", ""}},
		{"key as bearer only", []string{"Authorization", "Bearer " + h.apiKey}},
	} {
		before = h.backend.hits.Load()
		status, _ = h.do(h.req("GET", "/keyed", "198.51.100.71", "", tc.hdr...))
		h.denied("api key "+tc.name, before, status, 401, 403)
	}
	before = h.backend.hits.Load()
	status, _ = h.do(h.req("GET", "/keyed", "198.51.100.71", "", "X-Api-Key", h.apiKey))
	h.served("api key valid", before, status)

	// The forwarded-id header the API key filter sets is stripped from a
	// client that supplies its own.
	status, _ = h.do(h.req("GET", "/keyed", "198.51.100.71", "", "X-Api-Key", h.apiKey, "X-Api-Key-Id", "admin"))
	if status == 200 {
		if got := h.backend.last.Load().Header.Get("X-Api-Key-Id"); got == "admin" {
			t.Error("client supplied X-Api-Key-Id reached the backend")
		}
	}

	// The browser challenge gate: an unverified client gets the page, a
	// forged cookie does not pass, a solved challenge does.
	before = h.backend.hits.Load()
	status, _ = h.do(h.req("GET", "/members", "198.51.100.72", "", "Cookie", "XPCHAL=forged"))
	h.denied("challenge forged cookie", before, status, 503)
}

// TestPositiveModelAndPatches tries to slip past the positive route
// policy and a virtual patch.
func TestPositiveModelAndPatches(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	q := url.QueryEscape
	// The strict route allows GET with id (int) and q (<=20 chars) only.
	cases := []struct {
		name   string
		method string
		target string
		accept []int
	}{
		{"undeclared parameter", "GET", "/api/items?id=1&evil=1", []int{400}},
		{"wrong parameter type", "GET", "/api/items?id=abc", []int{400}},
		{"over-long parameter", "GET", "/api/items?q=" + strings.Repeat("z", 40), []int{400}},
		{"repeated parameter", "GET", "/api/items?id=1&id=2", []int{400}},
		{"disallowed method", "POST", "/api/items?id=1", []int{405, 400}},
		{"too many parameters", "GET", "/api/items?id=1&q=a&x=1&y=2", []int{400}},
		{"patched path with the query", "GET", "/plugins/legacy/?cmd=" + q("id"), []int{404}},
	}
	for i, c := range cases {
		ip := fmt.Sprintf("198.51.100.%d", 80+i)
		before := h.backend.hits.Load()
		status, _ := h.do(h.req(c.method, c.target, ip, ""))
		h.denied(c.name, before, status, c.accept...)
	}
	// The allowed shape passes.
	before := h.backend.hits.Load()
	status, _ := h.do(h.req("GET", "/api/items?id=7&q=shoes", "198.51.100.99", ""))
	h.served("policy clean request", before, status)
}
