package router

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

func routes() []config.Route {
	return []config.Route{
		{Name: "catch", Paths: []string{"/"}, Respond: &config.Respond{Status: 404}},
		{Name: "exact", Hosts: []string{"Example.com"}, Paths: []string{"/"}, Upstream: "a"},
		{Name: "exact-api", Hosts: []string{"example.com"}, Paths: []string{"/api"}, Upstream: "b"},
		{Name: "exact-api-post", Hosts: []string{"example.com"}, Paths: []string{"/api"}, Methods: []string{"POST"}, Priority: 10, Upstream: "c"},
		{Name: "wild", Hosts: []string{"*.example.com"}, Paths: []string{"/"}, Upstream: "d"},
		{Name: "deep", Hosts: []string{"example.com"}, Paths: []string{"/api/v2/"}, Upstream: "e"},
		{Name: "grpc-any", Hosts: []string{"rpc.test"}, Paths: []string{"/"}, Upstream: "g", GRPC: &config.RouteGRPC{}},
		{Name: "grpc-echo", Hosts: []string{"rpc.test"}, Paths: []string{"/"}, Upstream: "h", GRPC: &config.RouteGRPC{Services: []string{"echo.Echo"}, Methods: []string{"a.B/Do"}}},
		{Name: "rpc-web", Hosts: []string{"rpc.test"}, Paths: []string{"/"}, Upstream: "i"},
	}
}

func TestMatchGRPC(t *testing.T) {
	r := New(routes())
	cases := []struct {
		path string
		grpc bool
		want string
	}{
		{"/echo.Echo/Say", true, "grpc-echo"},
		{"/a.B/Do", true, "grpc-echo"},
		{"/a.B/Other", true, "grpc-any"},
		{"/x.Y/Z", true, "grpc-any"},
		{"/echo.Echo/Say", false, "rpc-web"},
		{"/", true, "grpc-any"},
	}
	for _, c := range cases {
		got := r.MatchRequest("rpc.test", c.path, "POST", c.grpc, nil, nil)
		if got == nil || got.Cfg.Name != c.want {
			t.Errorf("%s grpc=%v: got %v want %s", c.path, c.grpc, got, c.want)
		}
	}
	g := &grpcMatch{services: map[string]bool{"s.S": true}, methods: map[string]bool{}}
	for _, bad := range []string{"/s.S", "/s.S/", "//m", "/s.S/m/x", "/"} {
		if g.matches(bad) {
			t.Errorf("%q matched", bad)
		}
	}
}

func TestMatch(t *testing.T) {
	r := New(routes())
	cases := []struct {
		host, path, method, want string
	}{
		{"example.com", "/", "GET", "exact"},
		{"example.com", "/api", "GET", "exact-api"},
		{"example.com", "/api/", "GET", "exact-api"},
		{"example.com", "/api/x", "GET", "exact-api"},
		{"example.com", "/apix", "GET", "exact"},
		{"example.com", "/api", "POST", "exact-api-post"},
		{"example.com", "/api/v2/users", "GET", "deep"},
		{"example.com", "/api/v2", "GET", "deep"},
		{"a.example.com", "/x", "GET", "wild"},
		{"a.b.example.com", "/x", "GET", "catch"},
		{"other.org", "/x", "GET", "catch"},
		{"", "/", "GET", "catch"},
	}
	for _, c := range cases {
		got := r.Match(c.host, c.path, c.method)
		if got == nil {
			t.Fatalf("%s %s %s: no match", c.host, c.path, c.method)
		}
		if got.Cfg.Name != c.want {
			t.Errorf("%s %s %s: got %s want %s", c.host, c.path, c.method, got.Cfg.Name, c.want)
		}
	}
}

func TestNoMatch(t *testing.T) {
	r := New(routes()[1:2])
	if r.Match("nope.org", "/", "GET") != nil {
		t.Fatal("expected nil")
	}
	if r.Len() != 1 {
		t.Fatal("len")
	}
}

func FuzzMatch(f *testing.F) {
	r := New(routes())
	f.Add("example.com", "/api/v2/x", "GET")
	f.Add("", "", "")
	f.Add("*.example.com", "//", "get")
	f.Fuzz(func(t *testing.T, host, path, method string) {
		_ = r.Match(host, path, method)
	})
}

func BenchmarkMatch(b *testing.B) {
	r := New(routes())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Match("example.com", "/api/v2/users/123", "GET")
	}
}

// manyHostRoutes builds n exact host routes with three paths each, the
// shape of a large virtual hosting configuration.
func manyHostRoutes(n int) []config.Route {
	rs := make([]config.Route, 0, n)
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("site-%d.example.test", i)
		rs = append(rs, config.Route{Name: fmt.Sprintf("r%d", i), Hosts: []string{host}, Paths: []string{"/", "/api/", "/static/"}, Upstream: "u"})
	}
	return rs
}

func BenchmarkMatch1000Hosts(b *testing.B) {
	r := New(manyHostRoutes(1000))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r.Match("site-731.example.test", "/api/v2/users/123", "GET") == nil {
			b.Fatal("no match")
		}
	}
}

func BenchmarkNew1000Hosts(b *testing.B) {
	rs := manyHostRoutes(1000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		New(rs)
	}
}

// TestTieBreaks pins the ordering rules that mutation testing found
// unobserved: equal prefixes are ordered by priority, then by position.
func TestTieBreaks(t *testing.T) {
	rs := []config.Route{
		{Name: "first", Hosts: []string{"h.test"}, Paths: []string{"/x/"}, Upstream: "u"},
		{Name: "second", Hosts: []string{"h.test"}, Paths: []string{"/x/"}, Upstream: "u"},
		{Name: "high", Hosts: []string{"h.test"}, Paths: []string{"/x/"}, Priority: 5, Upstream: "u"},
	}
	r := New(rs)
	if m := r.Match("h.test", "/x/y", "GET"); m == nil || m.Cfg.Name != "high" {
		t.Fatalf("priority should win: %v", m)
	}
	r = New(rs[:2])
	if m := r.Match("h.test", "/x/y", "GET"); m == nil || m.Cfg.Name != "first" {
		t.Fatalf("earlier route should win a tie: %v", m)
	}
}

func TestRegexAndConditions(t *testing.T) {
	yes, no := true, false
	rs := []config.Route{
		{Name: "app", Hosts: []string{"h.test"}, Paths: []string{"/"}, Upstream: "u"},
		{Name: "api", Hosts: []string{"h.test"}, Paths: []string{"/api"}, Upstream: "u"},
		{Name: "versioned", Hosts: []string{"h.test"}, PathRegex: []string{`/api/v[0-9]+/users/[0-9]+`}, Upstream: "u"},
		{Name: "deep", Hosts: []string{"h.test"}, Paths: []string{"/api/v1/users/42/details"}, Upstream: "u"},
		{Name: "canary", Hosts: []string{"h.test"}, Paths: []string{"/"}, Headers: []config.HeaderMatch{{Name: "x-canary", Exact: "1"}}, Upstream: "u"},
		{Name: "beta", Hosts: []string{"h.test"}, Paths: []string{"/"}, Cookies: []config.HeaderMatch{{Name: "beta", Present: &yes}}, Headers: []config.HeaderMatch{{Name: "User-Agent", Regex: `Mozilla.*`}}, Upstream: "u"},
		{Name: "nobot", Hosts: []string{"h.test"}, Paths: []string{"/"}, Headers: []config.HeaderMatch{{Name: "X-Bot", Present: &no}, {Name: "Accept", Prefix: "text/"}}, Upstream: "u"},
		{Name: "files", Hosts: []string{"h.test"}, PathRegex: []string{`/.*\.(png|jpe?g|css)`}, Upstream: "u"},
	}
	r := New(rs)
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Add(kv[i], kv[i+1])
		}
		return h
	}
	cases := []struct {
		path string
		hdr  http.Header
		want string
	}{
		{"/api/v1/users/42", nil, "versioned"},
		{"/api/v12/users/7", nil, "versioned"},
		{"/api/v1/users/42/details", nil, "deep"},         // longer literal prefix wins
		{"/api/v1/users/abc", nil, "api"},                 // pattern fails, prefix stands
		{"/api/v1/users/42/x", nil, "api"},                // anchored at both ends
		{"/img/logo.png", nil, "files"},                   // pattern beats the plain "/" of the same length
		{"/img/logo.PNG", nil, "app"},                     // case sensitive
		{"/styles/a.css", hdr("X-Canary", "1"), "canary"}, // same literal length: the conditioned route comes first
		{"/x", hdr("X-Canary", "1"), "canary"},
		{"/x", hdr("X-Canary", "2"), "app"},
		{"/x", hdr("Cookie", "beta=1", "User-Agent", "Mozilla/5.0"), "beta"},
		{"/x", hdr("Cookie", "beta=1", "User-Agent", "curl/8"), "app"},
		{"/x", hdr("Accept", "text/html"), "nobot"},
		{"/x", hdr("Accept", "text/html", "X-Bot", "yes"), "app"},
		{"/x", hdr("Accept", "application/json"), "app"},
		{"/x", hdr("Accept", "text/html", "Cookie", "beta=1", "User-Agent", "Mozilla"), "beta"}, // two conditions each: configuration order
	}
	for _, c := range cases {
		got := r.MatchRequest("h.test", c.path, "GET", false, c.hdr, nil)
		if got == nil {
			t.Fatalf("%s %v: no match", c.path, c.hdr)
		}
		if got.Cfg.Name != c.want {
			t.Errorf("%s %v: got %s want %s", c.path, c.hdr, got.Cfg.Name, c.want)
		}
	}
}

// TestWildcardHostEdges: a wildcard never matches a host that is only the
// suffix, a host starting with a dot, or a host ending with a dot.
func TestWildcardHostEdges(t *testing.T) {
	r := New([]config.Route{{Name: "w", Hosts: []string{"*.example.com"}, Paths: []string{"/"}, Upstream: "u"}})
	if r.Match("a.example.com", "/", "GET") == nil {
		t.Fatal("wildcard should match a subdomain")
	}
	for _, h := range []string{"example.com", ".example.com", "example.com.", "a.example.com.", "", "."} {
		if m := r.Match(h, "/", "GET"); m != nil {
			t.Errorf("host %q matched %s", h, m.Cfg.Name)
		}
	}
}
