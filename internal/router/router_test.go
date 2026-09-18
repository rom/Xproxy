package router

import (
	"fmt"
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
