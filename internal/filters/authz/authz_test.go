package authz

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// request builds a request carrying a verified identity, the way an
// authenticating filter would have left it.
func request(method, path string, kind, subject string, attrs filter.Attrs) *http.Request {
	r, _ := http.NewRequest(method, "http://api.test"+path, nil)
	ctx, _ := filter.WithIdentity(r.Context())
	if subject != "" {
		filter.SetIdentity(ctx, kind, subject)
		filter.SetAttrs(ctx, kind, attrs)
	}
	return r.WithContext(ctx)
}

func build(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	f, err := filtertest.Build("authz", "policy", opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func rules(rs ...any) filter.Options {
	return filter.Options{"rules": rs}
}

// Nothing verified means nothing to decide about, and deciding on
// values a client supplied is the thing this exists to avoid.
func TestRequiresAuthentication(t *testing.T) {
	f := build(t, rules(map[string]any{"name": "any", "allow": true, "paths": []any{"/x"}}))
	r, _ := http.NewRequest("GET", "http://api.test/x", nil)
	ctx, _ := filter.WithIdentity(r.Context())
	v := filtertest.Run(f, r.WithContext(ctx), nil).Request
	if !v.Deny || v.Status != http.StatusForbidden {
		t.Fatalf("an anonymous request was not refused: %+v", v)
	}
	if !strings.Contains(v.Detail, "unauthenticated") {
		t.Errorf("detail = %q", v.Detail)
	}
}

// A request with no identity is allowed only where the policy says so
// out loud.
func TestAnonymousAllowedWhenSaidSo(t *testing.T) {
	f := build(t, filter.Options{
		"require_authenticated": false,
		"rules":                 []any{map[string]any{"name": "public", "allow": true, "paths": []any{"/public"}}},
	})
	r, _ := http.NewRequest("GET", "http://api.test/public", nil)
	ctx, _ := filter.WithIdentity(r.Context())
	if v := filtertest.Run(f, r.WithContext(ctx), nil).Request; v.Deny {
		t.Fatalf("%+v", v)
	}
}

// The default is deny: a request that matches no rule is refused, which
// is the difference between a policy and a list of exceptions.
func TestDefaultDeny(t *testing.T) {
	f := build(t, rules(map[string]any{
		"name": "read", "allow": true, "methods": []any{"GET"}, "paths": []any{"/v1/orders/**"},
	}))
	ok := request("GET", "/v1/orders/42", "oidc", "alice", filter.Attrs{})
	if v := filtertest.Run(f, ok, nil).Request; v.Deny {
		t.Fatalf("an allowed request was refused: %+v", v)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/v1/orders/42"},    // the method is not allowed
		{"GET", "/v1/invoices"},      // the path is not
		{"GET", "/v1/orders-secret"}, // a prefix that is not a path boundary
	} {
		r := request(c.method, c.path, "oidc", "alice", filter.Attrs{})
		v := filtertest.Run(f, r, nil).Request
		if !v.Deny {
			t.Errorf("%s %s was allowed", c.method, c.path)
		}
	}
}

// Groups come from the directory that verified them, and are compared
// the way a directory compares them.
func TestGroups(t *testing.T) {
	f := build(t, rules(map[string]any{
		"name": "admins", "allow": true,
		"groups": []any{"CN=Admins,OU=Groups,DC=example,DC=com"},
	}))
	in := request("DELETE", "/anything", "ldap", "alice",
		filter.Attrs{Groups: []string{"cn=admins,ou=groups,dc=example,dc=com", "cn=staff"}})
	if v := filtertest.Run(f, in, nil).Request; v.Deny {
		t.Fatalf("a member was refused: %+v", v)
	}
	out := request("DELETE", "/anything", "ldap", "bob", filter.Attrs{Groups: []string{"cn=staff"}})
	if v := filtertest.Run(f, out, nil).Request; !v.Deny {
		t.Fatal("a non-member was allowed")
	}
}

// Scopes are all-of, not any-of: a credential carrying two of the three
// a rule names does not satisfy it.
func TestScopesAreAllOf(t *testing.T) {
	f := build(t, rules(map[string]any{
		"name": "writer", "allow": true, "scopes": []any{"orders:read", "orders:write"},
	}))
	full := request("POST", "/v1/orders", "api_key", "k1",
		filter.Attrs{Scopes: []string{"orders:read", "orders:write", "other"}})
	if v := filtertest.Run(f, full, nil).Request; v.Deny {
		t.Fatalf("a key with both scopes was refused: %+v", v)
	}
	half := request("POST", "/v1/orders", "api_key", "k2",
		filter.Attrs{Scopes: []string{"orders:read"}})
	if v := filtertest.Run(f, half, nil).Request; !v.Deny {
		t.Fatal("a key with one of two scopes was allowed")
	}
}

// The first matching rule decides, so a deny placed above an allow
// carves an exception out of it.
func TestFirstMatchDecides(t *testing.T) {
	f := build(t, rules(
		map[string]any{"name": "no-deletes", "allow": false, "methods": []any{"DELETE"}},
		map[string]any{"name": "staff", "allow": true, "groups": []any{"staff"}},
	))
	del := request("DELETE", "/x", "ldap", "alice", filter.Attrs{Groups: []string{"staff"}})
	res := filtertest.Run(f, del, nil)
	if !res.Request.Deny {
		t.Fatal("the deny above the allow did not decide")
	}
	if !strings.Contains(res.Request.Detail, "no-deletes") {
		t.Errorf("detail = %q", res.Request.Detail)
	}
	get := request("GET", "/x", "ldap", "alice", filter.Attrs{Groups: []string{"staff"}})
	if v := filtertest.Run(f, get, nil).Request; v.Deny {
		t.Fatalf("%+v", v)
	}
}

// Claims are per kind, because two providers can both assert "email"
// and mean different people.
func TestClaims(t *testing.T) {
	f := build(t, rules(map[string]any{
		"name": "verified", "allow": true,
		"claims": map[string]any{"email_verified": "true"},
	}))
	yes := request("GET", "/x", "oidc", "alice",
		filter.Attrs{Claims: map[string]string{"email_verified": "true"}})
	if v := filtertest.Run(f, yes, nil).Request; v.Deny {
		t.Fatalf("%+v", v)
	}
	no := request("GET", "/x", "oidc", "bob",
		filter.Attrs{Claims: map[string]string{"email_verified": "false"}})
	if v := filtertest.Run(f, no, nil).Request; !v.Deny {
		t.Fatal("a claim that does not match was allowed")
	}
}

// "Everybody but" is a separate key rather than a prefix, because a
// group name can begin with anything.
func TestNegativeSelectors(t *testing.T) {
	f := build(t, rules(map[string]any{
		"name": "not-contractors", "allow": true, "not_groups": []any{"contractors"},
	}))
	staff := request("GET", "/x", "ldap", "alice", filter.Attrs{Groups: []string{"staff"}})
	if v := filtertest.Run(f, staff, nil).Request; v.Deny {
		t.Fatalf("%+v", v)
	}
	contractor := request("GET", "/x", "ldap", "bob",
		filter.Attrs{Groups: []string{"staff", "contractors"}})
	if v := filtertest.Run(f, contractor, nil).Request; !v.Deny {
		t.Fatal("a member of the excluded group was allowed")
	}
}

// Which filter verified the identity is itself a selector: a session is
// not an API key.
func TestKindSelector(t *testing.T) {
	f := build(t, rules(map[string]any{
		"name": "sessions-only", "allow": true, "kinds": []any{"oidc"},
	}))
	session := request("GET", "/x", "oidc", "alice", filter.Attrs{})
	if v := filtertest.Run(f, session, nil).Request; v.Deny {
		t.Fatalf("%+v", v)
	}
	key := request("GET", "/x", "api_key", "k1", filter.Attrs{})
	if v := filtertest.Run(f, key, nil).Request; !v.Deny {
		t.Fatal("an API key satisfied a rule that names sessions")
	}
}

func TestNetworkSelectors(t *testing.T) {
	f := build(t, rules(map[string]any{
		"name": "office", "allow": true, "networks": []any{"10.0.0.0/8"},
	}))
	inside := request("GET", "/x", "oidc", "alice", filter.Attrs{})
	res := filtertest.RunWithInfo(f, &filter.Info{ClientIP: netip.MustParseAddr("10.1.2.3")}, inside, nil)
	if res.Request.Deny {
		t.Fatalf("%+v", res.Request)
	}
	outside := request("GET", "/x", "oidc", "alice", filter.Attrs{})
	res = filtertest.RunWithInfo(f, &filter.Info{ClientIP: netip.MustParseAddr("203.0.113.9")}, outside, nil)
	if !res.Request.Deny {
		t.Fatal("a request from outside the network was allowed")
	}
}

// What the policy decided on is passed to the backend, and a value the
// client sent under the same name never is.
func TestForwardHeaders(t *testing.T) {
	f := build(t, filter.Options{
		"forward_groups_header": "X-Groups",
		"forward_scopes_header": "X-Scopes",
		"rules":                 []any{map[string]any{"name": "all", "allow": true, "kinds": []any{"ldap"}}},
	})
	r := request("GET", "/x", "ldap", "alice",
		filter.Attrs{Groups: []string{"staff"}, Scopes: []string{"a", "b"}})
	r.Header.Set("X-Groups", "admins")
	r.Header.Set("X-Scopes", "everything")
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("%+v", v)
	}
	if got := r.Header.Get("X-Groups"); got != "staff" {
		t.Errorf("X-Groups = %q, want the verified groups", got)
	}
	if got := r.Header.Get("X-Scopes"); got != "a b" {
		t.Errorf("X-Scopes = %q", got)
	}
}

// The rule that decided is on the access line, which is the only way to
// tell a policy that allowed from one that never matched.
func TestRecordsTheRule(t *testing.T) {
	f := build(t, rules(map[string]any{"name": "read", "allow": true, "methods": []any{"GET"}}))
	res := filtertest.Run(f, request("GET", "/x", "oidc", "alice", filter.Attrs{}), nil)
	var rule string
	for i := 0; i+1 < len(res.Attrs); i += 2 {
		if res.Attrs[i] == "authz_rule" {
			rule, _ = res.Attrs[i+1].(string)
		}
	}
	if rule != "read" {
		t.Fatalf("attrs = %v", res.Attrs)
	}
}

// An allow rule with no selectors allows everything, which is worth
// having to write as default: allow rather than hiding in a list.
func TestRefusesBlanketAllowRule(t *testing.T) {
	_, err := filtertest.Build("authz", "policy", rules(map[string]any{"name": "everything", "allow": true}))
	if err == nil {
		t.Fatal("a selectorless allow rule was accepted")
	}
	// The same shape as a deny is a legitimate backstop.
	if _, err := filtertest.Build("authz", "policy", rules(
		map[string]any{"name": "nothing-else", "allow": false},
	)); err != nil {
		t.Fatalf("a selectorless deny rule was refused: %v", err)
	}
}

func TestValidation(t *testing.T) {
	for name, opts := range map[string]filter.Options{
		"no rules":       {},
		"bad default":    rules(map[string]any{"name": "a", "allow": false}),
		"unnamed rule":   rules(map[string]any{"allow": false, "methods": []any{"GET"}}),
		"duplicate name": rules(map[string]any{"name": "a", "allow": false, "methods": []any{"GET"}}, map[string]any{"name": "a", "allow": false, "methods": []any{"PUT"}}),
		"bad path":       rules(map[string]any{"name": "a", "allow": true, "paths": []any{"relative"}}),
		"bad cidr":       rules(map[string]any{"name": "a", "allow": true, "networks": []any{"not-a-cidr"}}),
		"bad status":     {"status": 418, "rules": []any{map[string]any{"name": "a", "allow": false, "methods": []any{"GET"}}}},
	} {
		if name == "bad default" {
			opts["default"] = "maybe"
		}
		if _, err := filtertest.Build("authz", "policy", opts); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A refusal says nothing about why: which rule, which group it would
// have needed and whether the path exists are all things a prober would
// like to know.
func TestRefusalIsQuiet(t *testing.T) {
	f := build(t, filter.Options{
		"status": 404,
		"rules":  []any{map[string]any{"name": "admins", "allow": true, "groups": []any{"admins"}}},
	})
	v := filtertest.Run(f, request("GET", "/x", "oidc", "alice", filter.Attrs{}), nil).Request
	if !v.Deny || v.Status != http.StatusNotFound {
		t.Fatalf("%+v", v)
	}
}

var _ = context.Background
