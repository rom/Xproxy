package sensitive

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	// Unlisted media types, encoded bodies and oversize bodies pass unscanned.
	f = build(t, filter.Options{"request": map[string]any{"action": "block", "max_bytes": 64}})
	if res := filtertest.Run(f, post(`4111111111111111`, "application/octet-stream"), nil); res.Request.Deny {
		t.Fatal("octet-stream scanned")
	}
	enc := post(`4111111111111111`, "text/plain")
	enc.Header.Set("Content-Encoding", "gzip")
	if res := filtertest.Run(f, enc, nil); res.Request.Deny {
		t.Fatal("encoded body scanned")
	}
	big := post(strings.Repeat("x", 100)+" 4111111111111111", "text/plain")
	res = filtertest.Run(f, big, nil)
	if res.Request.Deny {
		t.Fatal("oversize body scanned")
	}
	if b, _ := io.ReadAll(big.Body); len(b) != 117 {
		t.Fatalf("oversize body not replayed: %d", len(b))
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
