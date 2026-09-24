package formguard

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// testClient is the address filtertest.Run gives every request, so a
// fixture that plants a fetch time plants it here.
var testClient = netip.MustParseAddr("198.51.100.7")

func build(t *testing.T, opts filter.Options) *guard {
	t.Helper()
	f, err := filtertest.Build("form_guard", "signup", opts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	g, ok := f.(*guard)
	if !ok {
		t.Fatalf("build returned %T", f)
	}
	return g
}

func get(path string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://h.example.test"+path, nil)
	return r
}

func post(path, body string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "http://h.example.test"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ContentLength = int64(len(body))
	return r
}

// fetchedAt plants a form fetch for the test client.
func fetchedAt(g *guard, when time.Time) {
	g.fetched.mu.Lock()
	defer g.fetched.mu.Unlock()
	g.fetched.seen[testClient] = when
}

func TestDeclaresBufferedBody(t *testing.T) {
	if !filter.BuffersBody("form_guard") {
		t.Fatal("form_guard must charge the process-wide buffered-body budget")
	}
}

func TestHiddenField(t *testing.T) {
	g := build(t, filter.Options{"fields": []any{"contact_reason", "website"}})

	if v := filtertest.Run(g, post("/signup", "name=ada&email=ada%40example.test"), nil).Request; v.Deny {
		t.Fatalf("honest submission denied: %+v", v)
	}
	// A field that arrives empty is what the browser sends.
	if v := filtertest.Run(g, post("/signup", "name=ada&website=+%09"), nil).Request; v.Deny {
		t.Fatalf("empty hidden field denied: %+v", v)
	}
	v := filtertest.Run(g, post("/signup", "name=bot&website=http%3A%2F%2Fspam.test"), nil).Request
	if !v.Deny || v.Status != http.StatusForbidden || v.Reason != "signup" || v.Detail != "field:website" {
		t.Fatalf("filled hidden field: %+v", v)
	}
	// Smuggled in the query string of the submission instead.
	v = filtertest.Run(g, post("/signup?contact_reason=x", "name=bot"), nil).Request
	if !v.Deny || v.Detail != "field:contact_reason" {
		t.Fatalf("query string hidden field: %+v", v)
	}
	// A method that is not a submission is not this filter's business.
	if v := filtertest.Run(g, get("/signup?website=x"), nil).Request; v.Deny {
		t.Fatalf("GET denied: %+v", v)
	}
}

func TestBodyIsReplayed(t *testing.T) {
	g := build(t, filter.Options{"fields": []any{"website"}})
	const body = "name=ada&email=ada%40example.test"
	r := post("/signup", body)
	if v := filtertest.Run(g, r, nil).Request; v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("body after inspection = %q, want %q", got, body)
	}
}

func TestOtherEncodingsPass(t *testing.T) {
	g := build(t, filter.Options{"fields": []any{"website"}})
	r := post("/api/signup", `{"website":"http://spam.test"}`)
	r.Header.Set("Content-Type", "application/json")
	if v := filtertest.Run(g, r, nil).Request; v.Deny {
		t.Fatalf("JSON body denied: %+v", v)
	}
	// Past the bound: not inspected, and not refused for being large.
	g = build(t, filter.Options{"fields": []any{"website"}, "max_body_bytes": 1024})
	big := "website=" + strings.Repeat("x", 2048)
	if v := filtertest.Run(g, post("/signup", big), nil).Request; v.Deny {
		t.Fatalf("oversize body denied: %+v", v)
	}
}

func TestTiming(t *testing.T) {
	g := build(t, filter.Options{
		"fields":      []any{"website"},
		"min_seconds": 2.0,
		"max_seconds": 3600.0,
		"form_paths":  []any{"/signup"},
	})
	// No fetch on record is not evidence.
	if v := filtertest.Run(g, post("/signup", "name=ada"), nil).Request; v.Deny {
		t.Fatalf("submission with no fetch denied: %+v", v)
	}
	// The form page itself is remembered, and a submission that follows
	// it immediately is too fast to have been read.
	if v := filtertest.Run(g, get("/signup"), nil).Request; v.Deny {
		t.Fatalf("form fetch denied: %+v", v)
	}
	if _, ok := g.fetched.get(testClient); !ok {
		t.Fatal("form fetch not recorded")
	}
	res := filtertest.Run(g, post("/signup", "name=bot"), nil)
	if !res.Request.Deny || res.Request.Detail != "too_fast" {
		t.Fatalf("instant submission: %+v", res.Request)
	}
	if !hasAttr(res.Attrs, "form_seconds") {
		t.Fatalf("attrs = %v, want form_seconds", res.Attrs)
	}
	// Read the page, filled it in, submitted: allowed.
	fetchedAt(g, time.Now().Add(-30*time.Second))
	if v := filtertest.Run(g, post("/signup", "name=ada"), nil).Request; v.Deny {
		t.Fatalf("paced submission denied: %+v", v)
	}
	// A page fetched yesterday.
	fetchedAt(g, time.Now().Add(-48*time.Hour))
	if v := filtertest.Run(g, post("/signup", "name=bot"), nil).Request; !v.Deny || v.Detail != "too_old" {
		t.Fatalf("stale submission: %+v", v)
	}
	// Timing is checked before the fields, so a stale submission is
	// refused whether or not it filled the hidden field in.
	fetchedAt(g, time.Now())
	if v := filtertest.Run(g, post("/signup", "website=x"), nil).Request; !v.Deny || v.Detail != "too_fast" {
		t.Fatalf("timing before fields: %+v", v)
	}
}

func TestRequireFetch(t *testing.T) {
	g := build(t, filter.Options{
		"min_seconds":   1.0,
		"form_paths":    []any{"/signup"},
		"require_fetch": true,
		"status":        429,
		"reason":        "no_form",
	})
	v := filtertest.Run(g, post("/signup", "name=bot"), nil).Request
	if !v.Deny || v.Status != 429 || v.Reason != "no_form" || v.Detail != "no_form_fetch" {
		t.Fatalf("unfetched submission: %+v", v)
	}
	fetchedAt(g, time.Now().Add(-10*time.Second))
	if v := filtertest.Run(g, post("/signup", "name=ada"), nil).Request; v.Deny {
		t.Fatalf("fetched submission denied: %+v", v)
	}
}

func TestFormPathPrefix(t *testing.T) {
	g := build(t, filter.Options{"min_seconds": 2.0, "form_paths": []any{"/account/"}})
	if v := filtertest.Run(g, get("/account/signup"), nil).Request; v.Deny {
		t.Fatalf("form fetch denied: %+v", v)
	}
	if _, ok := g.fetched.get(testClient); !ok {
		t.Fatal("prefix path not treated as a form page")
	}
	if !g.isFormPath("/account") || g.isFormPath("/accounts/x") {
		t.Fatal("isFormPath matches the wrong paths")
	}
}

func TestMethods(t *testing.T) {
	g := build(t, filter.Options{"fields": []any{"website"}, "methods": []any{"put"}})
	if v := filtertest.Run(g, post("/signup", "website=x"), nil).Request; v.Deny {
		t.Fatalf("POST checked although only PUT was named: %+v", v)
	}
	r := post("/signup", "website=x")
	r.Method = http.MethodPut
	if v := filtertest.Run(g, r, nil).Request; !v.Deny {
		t.Fatal("PUT not checked")
	}
}

// TestEvict proves a full table sweeps rather than grows, and that
// losing a fetch is permissive rather than a refusal.
func TestEvict(t *testing.T) {
	f := newFetches(128)
	base := time.Now()
	n := 0
	f.now = func() time.Time { n++; return base.Add(time.Duration(n) * time.Second) }
	for i := range 400 {
		f.put(netip.AddrFrom4([4]byte{198, 51, 100, byte(i % 251)}))
	}
	f.mu.Lock()
	size := len(f.seen)
	f.mu.Unlock()
	if size > 128 {
		t.Fatalf("table grew to %d, want at most 128", size)
	}

	g := build(t, filter.Options{"min_seconds": 5.0, "form_paths": []any{"/signup"}, "max_clients": 128})
	if v := filtertest.Run(g, post("/signup", "name=ada"), nil).Request; v.Deny {
		t.Fatalf("forgotten fetch refused: %+v", v)
	}
}

func TestOptionsAreValidated(t *testing.T) {
	bad := []filter.Options{
		{},                       // checks nothing
		{"fields": []any{"a b"}}, // not a field name
		{"fields": []any{""}},    // empty
		{"min_seconds": -1.0},    // out of range
		{"min_seconds": 4000.0},  // out of range
		{"max_seconds": 1.0, "min_seconds": 2.0, "form_paths": []any{"/x"}}, // min past max
		{"min_seconds": 2.0},                                // timing without form_paths
		{"require_fetch": true},                             // same
		{"min_seconds": 2.0, "form_paths": []any{"signup"}}, // path without /
		{"fields": []any{"a"}, "methods": []any{"GET"}},     // not a submission
		{"fields": []any{"a"}, "status": 200},               // not a refusal
		{"fields": []any{"a"}, "status": 503},               // not a 4xx
		{"fields": []any{"a"}, "max_body_bytes": 16},        // too small
		{"fields": []any{"a"}, "max_body_bytes": 64 << 20},  // too large
		{"fields": []any{"a"}, "max_clients": 4},            // too small
		{"fields": []any{"a"}, "bogus": 1},                  // unknown key
	}
	for i, o := range bad {
		if _, err := filtertest.Build("form_guard", "g", o); err == nil {
			t.Errorf("case %d accepted: %v", i, o)
		}
	}
	if _, err := filtertest.Build("form_guard", "g", filter.Options{
		"fields": []any{"website"}, "min_seconds": 2.0, "form_paths": []any{"/signup"},
	}); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
}

func hasAttr(attrs []any, name string) bool {
	for i := 0; i+1 < len(attrs); i += 2 {
		if s, ok := attrs[i].(string); ok && s == name {
			return true
		}
	}
	return false
}
