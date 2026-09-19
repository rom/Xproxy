package bodyrewrite

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func TestRewrite(t *testing.T) {
	f, err := filtertest.Build("body_rewrite", "links", filter.Options{
		"request": map[string]any{
			"types": []any{"application/json"},
			"rules": []any{map[string]any{"regex": `"userName"`, "replace": `"user_name"`}},
		},
		"response": map[string]any{
			"max_bytes": 64,
			"rules": []any{
				map[string]any{"find": "http://intranet/", "replace": "https://www.example.com/"},
				map[string]any{"regex": `(\d{3})-\d{2}-(\d{4})`, "replace": "$1-**-$2", "max": 1},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := func(ct, body string) *http.Request {
		r, _ := http.NewRequest("POST", "http://h.test/x", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		r.ContentLength = int64(len(body))
		return r
	}
	resp := func(ct, body string, hdr ...string) *http.Response {
		rs := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
		rs.Header.Set("Content-Type", ct)
		rs.Header.Set("ETag", `"x"`)
		for i := 0; i+1 < len(hdr); i += 2 {
			rs.Header.Set(hdr[i], hdr[i+1])
		}
		return rs
	}
	read := func(rc io.Reader) string { b, _ := io.ReadAll(rc); return string(b) }

	// Both directions change; lengths and validators follow.
	r := req("application/json; charset=utf-8", `{"userName":"a","userName2":"b"}`)
	rs := resp("text/html", `<a href="http://intranet/a">123-45-6789 and 987-65-4321</a>`)
	res := filtertest.Run(f, r, rs)
	if res.Request.Deny || res.Response.Deny {
		t.Fatalf("denied: %+v %+v", res.Request, res.Response)
	}
	if got := read(r.Body); got != `{"user_name":"a","userName2":"b"}` || r.ContentLength != int64(len(got)) || r.Header.Get("Content-Length") != "33" {
		t.Fatalf("request: %q %d %q", got, r.ContentLength, r.Header.Get("Content-Length"))
	}
	if got := read(rs.Body); got != `<a href="https://www.example.com/a">123-**-6789 and 987-65-4321</a>` || rs.ContentLength != int64(len(got)) || rs.Header.Get("ETag") != "" {
		t.Fatalf("response: %q %d %v", got, rs.ContentLength, rs.Header)
	}
	if len(res.Attrs) != 2 || res.Attrs[1] != "request,response" {
		t.Fatalf("attrs: %v", res.Attrs)
	}

	// Unlisted type, encoded body and oversize bodies pass through whole.
	rs = resp("image/png", "http://intranet/")
	filtertest.Run(f, req("text/plain", "x"), rs)
	if read(rs.Body) != "http://intranet/" {
		t.Fatal("image rewritten")
	}
	rs = resp("text/html", "http://intranet/", "Content-Encoding", "gzip")
	filtertest.Run(f, req("text/plain", "x"), rs)
	if read(rs.Body) != "http://intranet/" || rs.Header.Get("ETag") == "" {
		t.Fatal("encoded body rewritten")
	}
	big := strings.Repeat("http://intranet/", 10) // 160 bytes > 64
	rs = resp("text/html", big)
	rs.ContentLength = -1 // unknown length: the bound is discovered while buffering
	res = filtertest.Run(f, req("text/plain", "x"), rs)
	if got := read(rs.Body); got != big || res.Attrs != nil {
		t.Fatalf("oversize body altered or truncated: %d bytes, attrs %v", len(got), res.Attrs)
	}
	// A request without a body or with a GET is untouched.
	g, _ := http.NewRequest("GET", "http://h.test/", nil)
	if res := filtertest.Run(f, g, nil); res.Request.Deny || res.Attrs != nil {
		t.Fatalf("GET: %+v", res)
	}
	// Nothing to change: no attributes, validators kept.
	rs = resp("text/html", "plain")
	res = filtertest.Run(f, req("text/plain", "x"), rs)
	if res.Attrs != nil || rs.Header.Get("ETag") != `"x"` {
		t.Fatalf("unchanged body reported: %v %v", res.Attrs, rs.Header)
	}
}

func TestValidateOptions(t *testing.T) {
	bad := []filter.Options{
		{},
		{"response": map[string]any{"rules": []any{}}},
		{"response": map[string]any{"rules": []any{map[string]any{"replace": "x"}}}},
		{"response": map[string]any{"rules": []any{map[string]any{"find": "a", "regex": "b"}}}},
		{"response": map[string]any{"rules": []any{map[string]any{"regex": "(", "replace": ""}}}},
		{"response": map[string]any{"types": []any{"html"}, "rules": []any{map[string]any{"find": "a"}}}},
		{"response": map[string]any{"max_bytes": -1, "rules": []any{map[string]any{"find": "a"}}}},
		{"request": map[string]any{"rules": []any{map[string]any{"find": "a", "max": -2}}}},
		{"bogus": true},
	}
	for i, o := range bad {
		if _, err := filtertest.Build("body_rewrite", "x", o); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := filtertest.Build("body_rewrite", "x", filter.Options{"response": map[string]any{"rules": []any{map[string]any{"find": "a", "replace": ""}}}}); err != nil {
		t.Fatal(err)
	}
}
