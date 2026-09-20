package router

import (
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// One host name must select one route. The host arrives from a client
// as text, and DNS treats "api.example.test" and "api.example.test."
// as the same name, so both spellings must reach the same route table.
// A spelling that misses the exact table falls through to the catch-all
// route, which is where a deployment puts its permissive default: the
// route's WAF profile, access lists, authentication filters, rate
// limits and policy are all skipped for a request that merely spells
// the host differently.
func TestHostSpellingsSelectOneRoute(t *testing.T) {
	r := New([]config.Route{
		{Name: "guarded", Hosts: []string{"api.example.test"}, Paths: []string{"/"}, Upstream: "api"},
		{Name: "catch-all", Paths: []string{"/"}, Upstream: "default"},
	})
	same := []string{
		"api.example.test",
		"api.example.test.",    // the root dot, which clients do send
		"API.Example.Test",     // case
		"api.example.test:443", // a port on the authority
	}
	for _, spelling := range same {
		host := netutil.Host(spelling)
		got := r.MatchRequest(host, "/orders", "GET", false, nil, nil)
		if got == nil {
			t.Errorf("%q (normalised %q): no route", spelling, host)
			continue
		}
		if got.Cfg.Name != "guarded" {
			t.Errorf("%q (normalised %q) reached %q, not the guarded route", spelling, host, got.Cfg.Name)
		}
	}
	// Spellings that are not the name at all must not route either: an
	// empty label is not a host, so the normaliser refuses them and the
	// request is answered without a route rather than by the catch-all.
	for _, bad := range []string{"api.example.test..", ".api.example.test", "api..example.test", "api.example.test..."} {
		if host := netutil.Host(bad); host != "" {
			t.Errorf("%q normalised to %q instead of being refused", bad, host)
		}
	}
}
