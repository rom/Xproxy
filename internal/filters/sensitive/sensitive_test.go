package sensitive

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func TestDetectors(t *testing.T) {
	cases := []struct {
		det   string
		text  string
		found bool
	}{
		{"card", "pay with 4111 1111 1111 1111 today", true},
		{"card", "card 4111-1111-1111-1112", false},
		{"card", "order 1111111111111111", false},
		{"card", "5555555555554444", true},
		{"personnummer", "pnr 19811218-9876 ok", true},
		{"personnummer", "pnr 811218-9876", true},
		{"personnummer", "pnr 811278-9873", true},
		{"personnummer", "pnr 811318-9876", false},
		{"personnummer", "pnr 811218-9875", false},
		{"iban", "IBAN SE45 5000 0000 0583 9825 7466", true},
		{"iban", "IBAN GB82 WEST 1234 5698 7654 32", true},
		{"iban", "IBAN GB82 WEST 1234 5698 7654 33", false},
		{"ssn_us", "ssn 123-45-6789", true},
		{"ssn_us", "ssn 666-45-6789", false},
		{"email", "mail alice@example.com now", true},
		{"email", "not an email", false},
		{"jwt", "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", true},
		{"jwt", "token eyJub3RoaW5nIjoxfQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", false},
		{"private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE", true},
		{"api_keys", "aws AKIAIOSFODNN7EXAMPLE", true},
		{"api_keys", "gh ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD", true},
		{"api_keys", "stripe sk_live_0123456789abcdefghijklmnop", true},
		{"api_keys", "nothing here", false},
	}
	for _, c := range cases {
		d := builtin(c.det)
		found := false
		for _, m := range d.re.FindAllString(c.text, -1) {
			if d.validate(m) {
				found = true
			}
		}
		if found != c.found {
			t.Errorf("%s %q: found %v want %v", c.det, c.text, found, c.found)
		}
	}
	if got := keepLast4("4111 1111 1111 1111"); got != "**** **** **** 1111" {
		t.Fatalf("keepLast4 %q", got)
	}
	if got := maskEmail("alice@example.com"); got != "a***@example.com" {
		t.Fatalf("maskEmail %q", got)
	}
	if got := keepFirst8("AKIAIOSFODNN7EXAMPLE"); got != "AKIAIOSF************" {
		t.Fatalf("keepFirst8 %q", got)
	}
}

func build(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	f, err := filtertest.Build("sensitive_data", "dlp", opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func post(body, ctype string) *http.Request {
	r := httptest.NewRequest("POST", "http://app.test/api", strings.NewReader(body))
	r.Header.Set("Content-Type", ctype)
	return r
}

func response(body, ctype string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {ctype}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func TestSensitiveFilter(t *testing.T) {
	// Log mode records kinds and places without touching anything.
	f := build(t, filter.Options{"request": map[string]any{"action": "log"}, "response": map[string]any{"action": "log"}})
	r := post(`{"card":"4111 1111 1111 1111","mail":"bob@example.org"}`, "application/json")
	r.Header.Set("X-Note", "AKIAIOSFODNN7EXAMPLE")
	r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	res := filtertest.Run(f, r, response("pnr 811218-9876", "text/plain"))
	if res.Request.Deny || res.Response.Deny {
		t.Fatalf("log mode denied %+v %+v", res.Request, res.Response)
	}
	attrs := map[string]any{}
	for i := 0; i+1 < len(res.Attrs); i += 2 {
		attrs[res.Attrs[i].(string)] = res.Attrs[i+1]
	}
	if attrs["sensitive_types"] != "api_keys,card,email,personnummer" || attrs["sensitive_count"] != 4 || attrs["sensitive_where"] != "body,headers,response_body" {
		t.Fatalf("attrs %v", attrs)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), "4111 1111 1111 1111") {
		t.Fatal("log mode altered the body")
	}
	// Ignored headers (Authorization) are not scanned; the jwt in it was not counted.
	// Query passwords and a decoded query value.
	res = filtertest.Run(f, httptest.NewRequest("GET", "http://app.test/login?user=a&password=hunter2&note=4111%201111%201111%201111", nil), nil)
	if len(res.Attrs) == 0 || !strings.Contains(res.Attrs[1].(string), "password_query") || !strings.Contains(res.Attrs[1].(string), "card") {
		t.Fatalf("query attrs %v", res.Attrs)
	}

	// Mask mode rewrites bodies and headers and fixes the length.
	f = build(t, filter.Options{"request": map[string]any{"action": "mask"}, "response": map[string]any{"action": "mask"}})
	r = post(`card=4111111111111111&mail=bob@example.org`, "application/x-www-form-urlencoded")
	r.Header.Set("X-Card", "5555 5555 5555 4444")
	resp := response(`{"iban":"SE4550000000058398257466","key":"-----BEGIN PRIVATE KEY-----"}`, "application/json")
	resp.Header.Set("ETag", `"x"`)
	res = filtertest.Run(f, r, resp)
	body, _ = io.ReadAll(r.Body)
	if string(body) != "card=************1111&mail=b***@example.org" || r.ContentLength != int64(len(body)) {
		t.Fatalf("masked request %q %d", body, r.ContentLength)
	}
	if got := r.Header.Get("X-Card"); got != "**** **** **** 4444" {
		t.Fatalf("masked header %q", got)
	}
	out, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(out), `"iban":"********************7466"`) || !strings.Contains(string(out), "[masked]") || resp.Header.Get("ETag") != "" || resp.ContentLength != int64(len(out)) {
		t.Fatalf("masked response %q %v", out, resp.Header)
	}

	// Block mode refuses with a problem body naming kinds, never values.
	f = build(t, filter.Options{"request": map[string]any{"action": "block"}, "response": map[string]any{"action": "block"}, "block_status": 422})
	res = filtertest.Run(f, post(`{"ssn":"123-45-6789"}`, "application/json"), nil)
	if !res.Request.Deny || res.Request.Status != 422 || res.Request.Reason != "sensitive_data" || res.Request.Detail != "request:ssn_us" {
		t.Fatalf("block request %+v", res.Request)
	}
	pb, _ := io.ReadAll(res.Request.Response.Body)
	if !strings.Contains(string(pb), `"ssn_us"`) || strings.Contains(string(pb), "123-45") {
		t.Fatalf("problem body %s", pb)
	}
	res = filtertest.Run(f, post(`{"ok":true}`, "application/json"), response("leak 4111111111111111", "text/plain"))
	if res.Request.Deny || !res.Response.Deny || res.Response.Detail != "response:card" {
		t.Fatalf("block response %+v %+v", res.Request, res.Response)
	}

	// Unlisted media types and bodies that claim an encoding they do not
	// have pass unscanned; an oversize body is not judged at request
	// time but its stream is cut at the finding in block mode.
	f = build(t, filter.Options{"request": map[string]any{"action": "block", "max_bytes": 64}})
	if res := filtertest.Run(f, post(`4111111111111111`, "application/octet-stream"), nil); res.Request.Deny {
		t.Fatal("octet-stream scanned")
	}
	enc := post(`4111111111111111`, "text/plain")
	enc.Header.Set("Content-Encoding", "gzip")
	if res := filtertest.Run(f, enc, nil); res.Request.Deny {
		t.Fatal("undecodable body scanned")
	}
	big := post(strings.Repeat("x", 100)+" 4111111111111111", "text/plain")
	res = filtertest.Run(f, big, nil)
	if res.Request.Deny {
		t.Fatal("oversize body judged before it flowed")
	}
	if _, err := io.ReadAll(big.Body); !errors.Is(err, ErrBlocked) {
		t.Fatalf("oversize body stream not cut: %v", err)
	}
	// Selected detectors, custom detectors and min_findings.
	f = build(t, filter.Options{"detectors": []any{"email"}, "custom": []any{map[string]any{"name": "order_secret", "regex": "OS-[0-9]{12}"}},
		"request": map[string]any{"action": "block"}, "min_findings": 2})
	if res := filtertest.Run(f, post(`card 4111111111111111 mail a@b.se`, "text/plain"), nil); res.Request.Deny {
		t.Fatalf("one finding below min_findings blocked: %+v", res.Request)
	}
	if res := filtertest.Run(f, post(`OS-123456789012 mail a@b.se`, "text/plain"), nil); !res.Request.Deny || res.Request.Detail != "request:email,order_secret" {
		t.Fatalf("custom detector %+v", res.Request)
	}
	// Bad options.
	for _, o := range []filter.Options{
		{}, {"request": map[string]any{"action": "drop"}}, {"request": map[string]any{"scan": []any{"query"}}, "response": map[string]any{"scan": []any{"query"}}},
		{"request": map[string]any{"types": []any{"nope"}}}, {"detectors": []any{"cards"}, "request": map[string]any{}}, {"custom": []any{map[string]any{"name": "x", "regex": "("}}, "request": map[string]any{}},
		{"block_status": 200, "request": map[string]any{}}, {"min_findings": 0.5, "request": map[string]any{}},
	} {
		if _, err := filtertest.Build("sensitive_data", "d", o); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
}

func TestCounters(t *testing.T) {
	before := Snapshot()
	f, err := filtertest.Build("sensitive_data", "dlp", filter.Options{"detectors": []any{"card", "email"},
		"request": map[string]any{"action": "log"}, "response": map[string]any{"action": "block"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://a/x", strings.NewReader(`{"card":"4111 1111 1111 1111"}`))
	r.Header.Set("Content-Type", "application/json")
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"e":"a@example.com"}`)), ContentLength: -1}
	res := filtertest.Run(f, r, resp)
	if res.Request.Deny || !res.Response.Deny {
		t.Fatalf("verdicts %+v", res)
	}
	after := Snapshot()
	kind := func(c Counters, k string) uint64 {
		for _, f := range c.Findings {
			if f.Kind == k {
				return f.Count
			}
		}
		return 0
	}
	act := func(c Counters, d, o string) uint64 {
		for _, a := range c.Actions {
			if a.Direction == d && a.Outcome == o {
				return a.Count
			}
		}
		return 0
	}
	if kind(after, "card")-kind(before, "card") != 1 || kind(after, "email")-kind(before, "email") != 1 {
		t.Fatalf("findings %+v", after.Findings)
	}
	if act(after, "request", "logged")-act(before, "request", "logged") != 1 || act(after, "response", "blocked")-act(before, "response", "blocked") != 1 {
		t.Fatalf("actions %+v", after.Actions)
	}
	if len(after.Actions) != 6 {
		t.Fatalf("action combinations %d", len(after.Actions))
	}
}

func encode(t *testing.T, enc string, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch enc {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	case "br":
		w = brotli.NewWriter(&buf)
	case "zstd":
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		w = zw
	}
	_, _ = w.Write([]byte(text))
	_ = w.Close()
	return buf.Bytes()
}

func TestEncodedBodies(t *testing.T) {
	build := func(reqAction, respAction string, extra map[string]any) filter.Filter {
		req := map[string]any{"action": reqAction}
		resp := map[string]any{"action": respAction}
		for k, v := range extra {
			req[k], resp[k] = v, v
		}
		f, err := filtertest.Build("sensitive_data", "dlp", filter.Options{"detectors": []any{"card", "email"}, "request": req, "response": resp})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	body := `{"card":"4111 1111 1111 1111","email":"anna@example.com"}`
	for _, enc := range []string{"gzip", "deflate", "br", "zstd"} {
		// A masked compressed request is forwarded decoded and rewritten.
		f := build("mask", "log", nil)
		r := httptest.NewRequest("POST", "http://a/x", bytes.NewReader(encode(t, enc, body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Content-Encoding", enc)
		res := filtertest.Run(f, r, nil)
		out, _ := io.ReadAll(r.Body)
		if res.Request.Deny || r.Header.Get("Content-Encoding") != "" || !strings.Contains(string(out), "**** **** **** 1111") || strings.Contains(string(out), "anna@") || r.ContentLength != int64(len(out)) {
			t.Fatalf("%s masked request: %+v enc %q body %q len %d", enc, res.Request, r.Header.Get("Content-Encoding"), out, r.ContentLength)
		}
		// A logged compressed response is scanned but forwarded as it was.
		f = build("log", "log", nil)
		raw := encode(t, enc, body)
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {enc}}, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw))}
		res = filtertest.Run(f, httptest.NewRequest("GET", "http://a/x", nil), resp)
		got, _ := io.ReadAll(resp.Body)
		if !bytes.Equal(got, raw) || resp.Header.Get("Content-Encoding") != enc || fmt.Sprint(res.Attrs) == "[]" || !strings.Contains(fmt.Sprint(res.Attrs), "card") {
			t.Fatalf("%s logged response: %v %q", enc, res.Attrs, resp.Header)
		}
		// A blocked compressed response is refused.
		f = build("log", "block", nil)
		resp = &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {enc}}, Body: io.NopCloser(bytes.NewReader(encode(t, enc, body))), ContentLength: -1}
		if res = filtertest.Run(f, httptest.NewRequest("GET", "http://a/x", nil), resp); !res.Response.Deny {
			t.Fatalf("%s blocked response passed", enc)
		}
	}
	// encoded: skip leaves compressed bodies alone; unknown encodings
	// and ranges are never touched.
	f := build("block", "block", map[string]any{"encoded": "skip"})
	r := httptest.NewRequest("POST", "http://a/x", bytes.NewReader(encode(t, "gzip", body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Encoding", "gzip")
	if res := filtertest.Run(f, r, nil); res.Request.Deny {
		t.Fatalf("encoded skip scanned: %+v", res.Request)
	}
	f = build("block", "block", nil)
	for _, h := range []http.Header{{"Content-Encoding": {"compress"}}, {"Content-Range": {"bytes 0-9/100"}}} {
		r := httptest.NewRequest("POST", "http://a/x", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range h {
			r.Header[k] = v
		}
		if res := filtertest.Run(f, r, nil); res.Request.Deny {
			t.Fatalf("%v scanned: %+v", h, res.Request)
		}
	}
	// Corrupt compressed data passes untouched.
	r = httptest.NewRequest("POST", "http://a/x", strings.NewReader("not gzip at all"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Encoding", "gzip")
	res := filtertest.Run(f, r, nil)
	if out, _ := io.ReadAll(r.Body); res.Request.Deny || string(out) != "not gzip at all" {
		t.Fatalf("corrupt gzip: %+v %q", res.Request, out)
	}
	// A body that decodes past max_decoded_bytes is streamed decoded.
	f, err := filtertest.Build("sensitive_data", "dlp", filter.Options{"detectors": []any{"card"},
		"request": map[string]any{"action": "log", "max_bytes": 4096, "max_decoded_bytes": 4096}})
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("a", 10000) + " 4111 1111 1111 1111 " + strings.Repeat("b", 10000)
	r = httptest.NewRequest("POST", "http://a/x", bytes.NewReader(encode(t, "gzip", big)))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Content-Encoding", "gzip")
	in := f.Begin(context.Background(), &filter.Info{})
	if v := in.Request(r); v.Deny {
		t.Fatalf("bomb-ish request denied: %+v", v)
	}
	out, err := io.ReadAll(r.Body)
	if err != nil || string(out) != big || r.ContentLength != -1 || r.Header.Get("Content-Encoding") != "" {
		t.Fatalf("decoded stream: %v len %d cl %d enc %q", err, len(out), r.ContentLength, r.Header.Get("Content-Encoding"))
	}
	if attrs := fmt.Sprint(in.End()); !strings.Contains(attrs, "card") {
		t.Fatalf("stream findings missing: %s", attrs)
	}
}

func TestOversizeStreams(t *testing.T) {
	build := func(action string, extra map[string]any) filter.Filter {
		ph := map[string]any{"action": action, "max_bytes": 1024}
		for k, v := range extra {
			ph[k] = v
		}
		f, err := filtertest.Build("sensitive_data", "dlp", filter.Options{"detectors": []any{"card"}, "request": ph, "response": ph})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	// The card sits exactly across a read boundary of the source.
	head := strings.Repeat("x", 40000)
	body := head + " 4111 1111 1111 1111 " + strings.Repeat("y", 40000)
	chunked := func() io.ReadCloser { return io.NopCloser(iotest.OneByteReader(strings.NewReader(body))) }
	// Log mode: everything flows, the finding is recorded at the end.
	f := build("log", nil)
	r := httptest.NewRequest("POST", "http://a/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	in := f.Begin(context.Background(), &filter.Info{})
	if v := in.Request(r); v.Deny || r.ContentLength != -1 {
		t.Fatalf("log stream: %+v cl %d", v, r.ContentLength)
	}
	out, err := io.ReadAll(r.Body)
	if err != nil || string(out) != body {
		t.Fatalf("log stream body: %v %d", err, len(out))
	}
	if attrs := fmt.Sprint(in.End()); !strings.Contains(attrs, "card") || !strings.Contains(attrs, "body") {
		t.Fatalf("log stream attrs: %s", attrs)
	}
	// Mask mode: the value is rewritten even when the source delivers a
	// byte at a time.
	f = build("mask", nil)
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}, "Etag": {"x"}}, Body: chunked(), ContentLength: int64(len(body))}
	in = f.Begin(context.Background(), &filter.Info{})
	if v := in.Response(resp); v.Deny || resp.ContentLength != -1 || resp.Header.Get("Etag") != "" {
		t.Fatalf("mask stream: %+v", v)
	}
	out, err = io.ReadAll(resp.Body)
	if err != nil || len(out) != len(body) || strings.Contains(string(out), "4111 1111 1111 1111") || !strings.Contains(string(out), "1111") {
		t.Fatalf("mask stream body: %v %d %q", err, len(out), string(out[39990:40032]))
	}
	// Block mode: the stream ends with ErrBlocked at the finding; bytes
	// before the held back tail may have flowed.
	f = build("block", nil)
	r = httptest.NewRequest("POST", "http://a/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	in = f.Begin(context.Background(), &filter.Info{})
	if v := in.Request(r); v.Deny {
		t.Fatalf("block stream denied at request time: %+v", v)
	}
	if _, err := io.ReadAll(r.Body); !errors.Is(err, ErrBlocked) {
		t.Fatalf("block stream error %v", err)
	}
	// oversize: skip forwards large bodies unscanned.
	f = build("block", map[string]any{"oversize": "skip"})
	r = httptest.NewRequest("POST", "http://a/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	in = f.Begin(context.Background(), &filter.Info{})
	if v := in.Request(r); v.Deny || r.ContentLength != int64(len(body)) {
		t.Fatalf("oversize skip: %+v", v)
	}
	if out, err := io.ReadAll(r.Body); err != nil || string(out) != body || in.End() != nil {
		t.Fatalf("oversize skip body: %v %d %v", err, len(out), in.End())
	}
	// A body with an unknown length is buffered up to the bound and
	// streamed beyond it.
	f = build("log", nil)
	r = httptest.NewRequest("POST", "http://a/x", strings.NewReader(body))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "text/plain")
	in = f.Begin(context.Background(), &filter.Info{})
	in.Request(r)
	if out, err := io.ReadAll(r.Body); err != nil || string(out) != body || !strings.Contains(fmt.Sprint(in.End()), "card") {
		t.Fatalf("unknown length stream: %v %d", err, len(out))
	}
	for i, bad := range []map[string]any{{"encoded": "maybe"}, {"oversize": "buffer"}, {"max_decoded_bytes": 10}} {
		ph := map[string]any{"action": "log", "max_bytes": 1024}
		for k, v := range bad {
			ph[k] = v
		}
		if _, err := filtertest.Build("sensitive_data", "dlp", filter.Options{"request": ph}); err == nil {
			t.Errorf("options %d accepted", i)
		}
	}
}
