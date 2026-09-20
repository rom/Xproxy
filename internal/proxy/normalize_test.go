package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

const normYAML = `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
  normalization:
    reject_double_encoding: true
    reject_encoded_slashes: true
    reject_backslashes: true
    unicode: %s
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: %s}]
routes:
  - {name: users, paths: [/users], upstream: app}
  - {name: cafe, paths: ["/café"], upstream: app}
`

// rawStatus sends a request line and headers verbatim and returns the
// status code, so the client library cannot repair the encoding.
func rawStatus(t *testing.T, addr, target string, headers ...string) int {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET " + target + " HTTP/1.1\r\nHost: x\r\n"
	for _, h := range headers {
		req += h + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestNormalizationGuard(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(normYAML, "off", a.addr()))
	addr := strings.TrimPrefix(url, "http://")
	cases := []struct {
		name   string
		target string
		status int
	}{
		{"plain", "/users/1", 200},
		{"encoded ok", "/users/%C3%A9", 200},
		{"double encoded", "/users/%252e%252e/admin", 400},
		{"encoded slash", "/users%2F..%2Fadmin", 400},
		{"encoded backslash", "/users%5Cadmin", 400},
		{"backslash", "/users\\admin", 400},
		{"nul", "/users/%00", 400},
		{"control", "/users/%0d%0ax", 400},
		{"query control", "/users?x=%00", 400},
		{"invalid utf8", "/users/%c0%af", 400},
		{"overlong", "/users/%e0%80%af", 400},
	}
	for _, c := range cases {
		if got := rawStatus(t, addr, c.target); got != c.status {
			t.Errorf("%s (%s): got %d want %d", c.name, c.target, got, c.status)
		}
	}
	// Framing: the parser or the guard refuses ambiguous messages.
	if got := rawStatus(t, addr, "/users", "Content-Length: 3", "Content-Length: 5"); got != 400 {
		t.Errorf("two content lengths: %d", got)
	}
	if got := rawStatus(t, addr, "/users", "Transfer-Encoding: gzip, chunked", "Content-Length: 0"); got/100 != 4 && got != 501 {
		t.Errorf("odd transfer coding with length: %d", got)
	}
	if sn := s.Stats(); sn.DeniedNormalization < 9 {
		t.Fatalf("denied_normalization = %d", sn.DeniedNormalization)
	}
	// Unicode folding is off: a fullwidth spelling finds no route, a
	// decomposed e-acute does not match the composed route.
	if got := rawStatus(t, addr, "/%EF%BD%95sers"); got != 404 {
		t.Errorf("fullwidth without folding: %d", got)
	}
	if got := rawStatus(t, addr, "/cafe%CC%81"); got != 404 {
		t.Errorf("decomposed without folding: %d", got)
	}

	// nfc folds composed and decomposed spellings; nfkc also
	// compatibility forms. The upstream still receives the original.
	_, url = startServer(t, fmt.Sprintf(normYAML, "nfc", a.addr()))
	addr = strings.TrimPrefix(url, "http://")
	if got := rawStatus(t, addr, "/cafe%CC%81/menu"); got != 200 {
		t.Errorf("nfc decomposed: %d", got)
	}
	if got := rawStatus(t, addr, "/%EF%BD%95sers"); got != 404 {
		t.Errorf("nfc must not fold compatibility forms: %d", got)
	}
	_, url = startServer(t, fmt.Sprintf(normYAML, "nfkc", a.addr()))
	addr = strings.TrimPrefix(url, "http://")
	if got := rawStatus(t, addr, "/%EF%BD%95sers/7"); got != 200 {
		t.Errorf("nfkc fullwidth: %d", got)
	}
	if p := a.last.Load().URL.Path; p != "/ｕsers/7" {
		t.Fatalf("upstream path rewritten: %q", p)
	}
}

func TestNormalizationDefaults(t *testing.T) {
	// Without a section the safe checks are on and the strict ones off.
	a := newBackend(t, "a")
	_, url := startServer(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: %s}]
routes:
  - {name: all, upstream: app}
`, a.addr()))
	addr := strings.TrimPrefix(url, "http://")
	if got := rawStatus(t, addr, "/x/%00"); got != 400 {
		t.Errorf("nul with defaults: %d", got)
	}
	if got := rawStatus(t, addr, "/x/%c0%af"); got != 400 {
		t.Errorf("invalid utf8 with defaults: %d", got)
	}
	if got := rawStatus(t, addr, "/x/%252e"); got != 200 {
		t.Errorf("double encoding with defaults: %d", got)
	}
	if got := rawStatus(t, addr, "/x%2Fy"); got != 200 {
		t.Errorf("encoded slash with defaults: %d", got)
	}
}

func TestCheckNormalizationUnit(t *testing.T) {
	off := false
	n := &config.Normalization{RejectDoubleEncoding: true, RejectEncodedSlashes: true}
	req := func(target string, hdr ...string) *http.Request {
		u, err := url.ParseRequestURI(target)
		if err != nil {
			t.Fatal(err)
		}
		r := &http.Request{Method: "GET", URL: u, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Add(hdr[i], hdr[i+1])
		}
		return r
	}
	for _, tc := range []struct {
		target string
		hdr    []string
		want   string
	}{
		{"/ok/path?q=1", nil, ""},
		{"/a%252e", nil, "path_double_encoding"},
		{"/a%2Fb", nil, "path_encoded_slash"},
		{"/a%5cb", nil, "path_encoded_slash"},
		{"/a%00", nil, "path_control_char"},
		{"/a?q=%7f", nil, "query_control_char"},
		{"/a%ff", nil, "path_invalid_utf8"},
		{"/a", []string{"Content-Length", "1", "Content-Length", "2"}, "framing_content_length"},
		{"/a", []string{"Content-Length", "1", "Content-Length", "1"}, ""},
		{"/a", []string{"Transfer-Encoding", "chunked", "Content-Length", "1"}, "framing_te_cl"},
		{"/a", []string{"Transfer-Encoding", "gzip"}, "framing_transfer_encoding"},
	} {
		if got := checkNormalization(n, req(tc.target, tc.hdr...)); got != tc.want {
			t.Errorf("%s %v: got %q want %q", tc.target, tc.hdr, got, tc.want)
		}
	}
	relaxed := &config.Normalization{RejectControlChars: &off, RejectInvalidUTF8: &off, RejectAmbiguousFraming: &off}
	if got := checkNormalization(relaxed, req("/a%00%ff", "Content-Length", "1", "Content-Length", "2")); got != "" {
		t.Fatalf("relaxed: %q", got)
	}
	if got := checkNormalization(&config.Normalization{}, req("/a%252e")); got != "" {
		t.Fatalf("defaults refuse strict cases: %q", got)
	}
	// A backslash and a path parameter are refused by default: the
	// servers behind the proxy read "/static\\..\\admin" and "/admin;x"
	// as /admin, while routing here reads one opaque segment and misses
	// the /admin route with its access lists, filters and WAF profile.
	defaults := &config.Normalization{}
	for _, tc := range []struct{ target, want string }{
		{"/static%5c..%5cadmin", "path_backslash"},
		{"/static/..%5cadmin", "path_backslash"},
		{"/admin;x", "path_parameter"},
		{"/admin;jsessionid=abc", "path_parameter"},
		{"/admin%3bx", "path_parameter"},
		{"/static/..;/admin", "path_parameter"},
		{"/static/../admin", "path_dot_segment"},
	} {
		if got := checkNormalization(defaults, req(tc.target)); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.target, got, tc.want)
		}
	}
	// With both refusals off, the dot-segment check still sees through a
	// backslash separator and a path parameter.
	loose := &config.Normalization{RejectBackslashes: &off, RejectPathParams: &off}
	for _, target := range []string{"/static%5c..%5cadmin", "/static/..%5cadmin", "/static/..;/admin", "/static/.;/admin"} {
		if got := checkNormalization(loose, req(target)); got != "path_dot_segment" {
			t.Errorf("%s with the refusals off: got %q", target, got)
		}
	}
}
