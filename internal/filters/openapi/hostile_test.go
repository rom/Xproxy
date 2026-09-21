package openapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// The description is the positive security policy: what it says is
// allowed is what reaches the API. A document that compiles into the
// wrong thing, or a description server that answers with something
// else, is a hole in that policy.

func TestSpecURLOK(t *testing.T) {
	good := []string{
		"https://api.example.com/openapi.json",
		"https://127.0.0.1:8443/spec",
		"http://localhost/spec",
		"http://localhost:8080/spec.yaml",
		"http://127.0.0.1:9000/spec",
		"http://[::1]:9000/spec",
	}
	for _, u := range good {
		if !specURLOK(u) {
			t.Errorf("%q was refused", u)
		}
	}
	bad := []string{
		"",
		"http://api.example.com/spec",        // plain http off the host
		"http://169.254.169.254/latest/meta", // the metadata service
		"http://LOCALHOST.evil.example/spec", // a name that merely starts with it
		"http://localhost.evil.example/spec",
		"http://127.0.0.1.evil.example/spec",
		"file:///etc/passwd",
		"ftp://example.com/spec",
		"ldap://example.com/spec",
		"https://",
		"//example.com/spec",
		"/spec.yaml",
		"spec.yaml",
		"http://",
		"://example.com",
	}
	for _, u := range bad {
		if specURLOK(u) {
			t.Errorf("%q was accepted", u)
		}
	}
}

func TestCompileSpecRefusals(t *testing.T) {
	bad := map[string]string{
		"empty":                      "",
		"not a document":             "just a string\n",
		"a list":                     "- a\n- b\n",
		"not yaml":                   "a: [1,\n",
		"no version":                 "info: {title: x}\npaths: {}\n",
		"version 2":                  "swagger: \"2.0\"\npaths: {}\n",
		"version 4":                  "openapi: 4.0.0\npaths: {}\n",
		"a version that is a number": "openapi: 3\npaths: {}\n",
		"no paths":                   "openapi: 3.0.3\ninfo: {title: x, version: \"1\"}\n",
		"paths that are a list":      "openapi: 3.0.3\npaths: [a, b]\n",
		"an unterminated parameter":  "openapi: 3.0.3\npaths:\n  /a/{id:\n    get: {}\n",
	}
	for name, doc := range bad {
		if a, err := compileSpec([]byte(doc), ""); err == nil {
			t.Errorf("%s compiled into %d exact and %d templated paths", name, len(a.exact), len(a.templ))
		}
	}
	// A document larger than the ceiling is refused without compiling.
	big := "openapi: 3.0.3\ninfo: {title: x, version: \"1\"}\npaths:\n  /a: {get: {}}\n# " + strings.Repeat("p", 33<<20)
	if _, err := compileSpec([]byte(big), ""); err == nil {
		t.Error("a 33 MiB description was compiled")
	}
	// A document that compiles: the paths land where the matcher can
	// find them.
	a, err := compileSpec([]byte(spec), "/v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.exact) == 0 || len(a.templ) == 0 || a.basePath != "/v1" {
		t.Fatalf("compiled: %d exact, %d templated, base %q", len(a.exact), len(a.templ), a.basePath)
	}
}

func TestLiteralPrefixOrdersTemplates(t *testing.T) {
	cases := map[string]int{
		"/orders":        7,
		"/orders/{id}":   8,
		"/{id}":          1,
		"{id}":           0,
		"":               0,
		"/a/b/c/{x}/{y}": 7,
		"/orders/latest": 14,
	}
	for tmpl, want := range cases {
		if got := literalPrefix(tmpl); got != want {
			t.Errorf("literalPrefix(%q) = %d want %d", tmpl, got, want)
		}
	}
	// The ordering it drives: a longer literal prefix wins, so
	// /orders/{id}/items is tried before /orders/{id}.
	doc := `
openapi: 3.0.3
info: {title: x, version: "1"}
paths:
  /a/{id}: {get: {}}
  /a/b/{id}: {get: {}}
  /{any}: {get: {}}
`
	a, err := compileSpec([]byte(doc), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.templ) != 3 {
		t.Fatalf("%d templates", len(a.templ))
	}
	if a.templ[0].template != "/a/b/{id}" || a.templ[2].template != "/{any}" {
		t.Fatalf("order: %q %q %q", a.templ[0].template, a.templ[1].template, a.templ[2].template)
	}
	// A request matches the most specific template.
	if pi, _, ok := a.match("GET", "/a/b/7"); !ok || pi.template != "/a/b/{id}" {
		t.Errorf("/a/b/7 matched %v", pi)
	}
	// A path parameter never spans a separator: /a/b/c must not match
	// /a/{id}, or one operation's policy would cover another's path.
	if pi, _, ok := a.match("GET", "/a/b/c"); ok && pi.template == "/a/{id}" {
		t.Error("a path parameter spanned a separator")
	}
}

// TestDocumentedAndOperations covers the two views the API inventory
// reads to tell a documented endpoint from a shadow one.
func TestDocumentedAndOperations(t *testing.T) {
	f, err := filtertest.Build("openapi", "orders", filter.Options{"spec_file": write(t, spec), "base_path": "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	g, ok := f.(*guard)
	if !ok {
		t.Fatalf("the filter is a %T", f)
	}
	t.Cleanup(func() { _ = g.Close() })
	if g.Name() != "orders" {
		t.Errorf("name %q", g.Name())
	}
	cases := map[string]struct {
		method, path string
		want         string
	}{
		"a documented collection":               {"GET", "/v1/orders", "/v1/orders"},
		"a documented item":                     {"GET", "/v1/orders/7", "/v1/orders/{id}"},
		"an exact path over a template":         {"GET", "/v1/orders/latest", "/v1/orders/latest"},
		"a documented delete":                   {"DELETE", "/v1/orders/7", "/v1/orders/{id}"},
		"a HEAD answered by GET":                {"HEAD", "/v1/orders", "/v1/orders"},
		"a method nobody documented":            {"PUT", "/v1/orders", ""},
		"a path nobody documented":              {"GET", "/v1/customers", ""},
		"outside the base path":                 {"GET", "/orders", ""},
		"a path parameter spanning a separator": {"GET", "/v1/orders/7/items", ""},
		"an empty path":                         {"GET", "", ""},
	}
	for name, tc := range cases {
		got, ok := g.Documented(tc.method, tc.path)
		if tc.want == "" {
			if ok {
				t.Errorf("%s was reported as documented (%q)", name, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("%s gave %q,%v want %q", name, got, ok, tc.want)
		}
	}
	ops := g.Operations()
	if len(ops) < 5 {
		t.Fatalf("%d operations", len(ops))
	}
	for _, op := range ops {
		if !strings.HasPrefix(op.Path, "/v1/") {
			t.Errorf("operation %+v is missing the base path", op)
		}
		if op.Method == "" || strings.ToUpper(op.Method) != op.Method {
			t.Errorf("operation %+v has an odd method", op)
		}
	}
	// The response phase is a no-op: this filter judges requests.
	in := g.Begin(context.Background(), &filter.Info{})
	if v := in.Response(&http.Response{StatusCode: 500, Header: http.Header{}}); v.Deny {
		t.Errorf("the response phase denied: %+v", v)
	}
}

// TestSpecServerFailures covers a description fetched over the network:
// the server is somebody else's, and what it sends becomes the policy.
func TestSpecServerFailures(t *testing.T) {
	var body atomic.Value
	body.Store(spec)
	var code atomic.Int32
	code.Store(200)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(int(code.Load()))
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache.yaml")
	opts := func() filter.Options {
		return filter.Options{"spec_url": srv.URL + "/spec", "cache_file": cache, "refresh": "1s", "timeout": "2s"}
	}

	// The first load fetches and caches the description.
	f, err := filtertest.Build("openapi", "orders", opts())
	if err != nil {
		t.Fatalf("the first load: %v", err)
	}
	g := f.(*guard)
	if _, err := os.Stat(cache); err != nil {
		t.Errorf("the description was not cached: %v", err)
	}
	if st, _ := os.Stat(cache); st != nil && st.Mode().Perm()&0o077 != 0 {
		t.Errorf("the cache file is mode %v", st.Mode().Perm())
	}
	_ = g.Close()

	// A server that answers with something else keeps the cached
	// description rather than leaving the route unprotected.
	for name, answer := range map[string]struct {
		code int
		body string
	}{
		"a server error":                   {500, "broken"},
		"not a description":                {200, "<html>hello</html>"},
		"an empty body":                    {200, ""},
		"a description of another version": {200, "swagger: \"2.0\"\npaths: {}\n"},
	} {
		code.Store(int32(answer.code)) //nolint:gosec // test status
		body.Store(answer.body)
		f, err := filtertest.Build("openapi", "orders", opts())
		if err != nil {
			t.Errorf("%s: the cache was not used: %v", name, err)
			continue
		}
		g := f.(*guard)
		if _, ok := g.Documented("GET", "/v1/orders"); !ok {
			t.Errorf("%s: the cached description was not in force", name)
		}
		_ = g.Close()
	}

	// With no cache to fall back on, a broken server is a start-up
	// error: the filter must not come up allowing everything.
	code.Store(500)
	body.Store("broken")
	if _, err := filtertest.Build("openapi", "orders", filter.Options{"spec_url": srv.URL + "/spec", "timeout": "2s"}); err == nil {
		t.Error("a filter came up with no description at all")
	}

	// A refresh that fails leaves the previous description in force and
	// is counted.
	code.Store(200)
	body.Store(spec)
	f, err = filtertest.Build("openapi", "orders", opts())
	if err != nil {
		t.Fatal(err)
	}
	g = f.(*guard)
	defer func() { _ = g.Close() }()
	code.Store(500)
	deadline := time.After(10 * time.Second)
	for g.Failures.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("no failed refresh was counted")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	if _, ok := g.Documented("GET", "/v1/orders"); !ok {
		t.Error("a failed refresh dropped the description")
	}
	// Closing twice is safe.
	_ = g.Close()
	_ = g.Close()
}

// TestOptionRefusals covers the configuration of the filter.
func TestOptionRefusals(t *testing.T) {
	dir := t.TempDir()
	good := write(t, spec)
	notPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := map[string]filter.Options{
		"neither a file nor a url":         {},
		"both a file and a url":            {"spec_file": good, "spec_url": "https://api.example/spec"},
		"a file that is not there":         {"spec_file": filepath.Join(dir, "none.yaml")},
		"a file that is not a description": {"spec_file": write(t, "hello")},
		"a plain http url":                 {"spec_url": "http://api.example/spec"},
		"a file url":                       {"spec_url": "file:///etc/passwd"},
		"a ca file that is not there":      {"spec_url": "https://api.example/spec", "ca_file": filepath.Join(dir, "none.pem")},
		"a ca file with no certificates":   {"spec_url": "https://api.example/spec", "ca_file": notPEM},
		"an unknown option":                {"spec_file": good, "bogus": 1},
	}
	for name, opts := range bad {
		if f, err := filtertest.Build("openapi", "x", opts); err == nil {
			if c, ok := f.(interface{ Close() error }); ok {
				_ = c.Close()
			}
			t.Errorf("%s was accepted", name)
		}
	}
}
