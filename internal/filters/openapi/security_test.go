package openapi

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// securedSpec declares four kinds of credential and uses them in the
// three shapes OpenAPI allows: a global default, an operation that
// overrides it, an operation that opts out entirely, and an alternative
// of two schemes that must both be present.
const securedSpec = `
openapi: 3.0.3
info: {title: Secured, version: "1"}
servers: [{url: https://api.example.com/v1}]
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
    basicAuth: {type: http, scheme: basic}
    apiKeyHeader: {type: apiKey, in: header, name: X-API-Key}
    apiKeyQuery: {type: apiKey, in: query, name: api_key}
    apiKeyCookie: {type: apiKey, in: cookie, name: session}
    oidc: {type: openIdConnect, openIdConnectUrl: "https://idp.example.com/.well-known/openid-configuration"}
    peerCert: {type: mutualTLS}
security:
  - bearerAuth: []
paths:
  /orders:
    get: {}
    post:
      security:
        - apiKeyHeader: []
        - basicAuth: []
  /health:
    get:
      security: []
  /both:
    get:
      security:
        - {apiKeyHeader: [], apiKeyQuery: []}
  /maybe:
    get:
      security:
        - {}
        - bearerAuth: []
  /cookie:
    get:
      security:
        - apiKeyCookie: []
  /oidc:
    get:
      security:
        - oidc: [openid]
  /mtls:
    get:
      security:
        - peerCert: []
`

func securedFilter(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	all := filter.Options{"spec_file": write(t, securedSpec)}
	for k, v := range opts {
		all[k] = v
	}
	f, err := filtertest.Build("openapi", "secured", all)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// An operation that says it needs a credential and gets none is refused
// here rather than answered by an application that may have forgotten to
// check. Every shape the description can take is driven, because getting
// the OR-of-ANDs wrong in either direction is a security bug: too strict
// refuses working clients, too loose is the hole this closes.
func TestTheCredentialTheDescriptionAsksForIsRequired(t *testing.T) {
	f := securedFilter(t, filter.Options{"require_security": true})
	do := func(method, target string, hdr ...string) filter.Verdict {
		t.Helper()
		r, _ := http.NewRequest(method, "http://api.example.com"+target, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Add(hdr[i], hdr[i+1])
		}
		return filtertest.Run(f, r, nil).Request
	}
	ok := func(v filter.Verdict, what string) {
		t.Helper()
		if v.Deny {
			t.Fatalf("%s: denied %+v", what, v)
		}
	}
	denied := func(v filter.Verdict, what string) {
		t.Helper()
		if !v.Deny || v.Status != http.StatusUnauthorized || v.Detail != "security" {
			t.Fatalf("%s: got %+v, want 401 security", what, v)
		}
	}

	// The global requirement, and the same request with the credential.
	denied(do("GET", "/v1/orders"), "no credential at all")
	ok(do("GET", "/v1/orders", "Authorization", "Bearer abc"), "a bearer token")
	// The scheme name is case-insensitive, as RFC 9110 says.
	ok(do("GET", "/v1/orders", "Authorization", "bearer abc"), "a lower case scheme")
	// A header that looks like a credential and is not one.
	denied(do("GET", "/v1/orders", "Authorization", "Bearer"), "a bearer with nothing after it")
	denied(do("GET", "/v1/orders", "Authorization", "Bearer   "), "a bearer with only spaces")
	denied(do("GET", "/v1/orders", "Authorization", "Basic YTpi"), "the wrong scheme for this operation")

	// An operation's own security replaces the global one: either of two
	// alternatives satisfies it, and the global bearer no longer does.
	ok(do("POST", "/v1/orders", "X-API-Key", "k"), "the first alternative")
	ok(do("POST", "/v1/orders", "Authorization", "Basic "+basic("u", "p")), "the second alternative")
	denied(do("POST", "/v1/orders", "Authorization", "Bearer abc"), "the global scheme where the operation overrode it")
	denied(do("POST", "/v1/orders", "Authorization", "Basic not-base64!"), "basic that is not base64")
	denied(do("POST", "/v1/orders", "Authorization", "Basic "+basicRaw("nocolon")), "basic without a colon")
	denied(do("POST", "/v1/orders", "X-API-Key", ""), "an empty api key header")

	// An explicit empty list means this operation needs nothing.
	ok(do("GET", "/v1/health"), "security: [] opts out")

	// One alternative naming two schemes needs both.
	denied(do("GET", "/v1/both", "X-API-Key", "k"), "half of an AND")
	ok(do("GET", "/v1/both?api_key=q", "X-API-Key", "k"), "both halves")

	// The empty object among alternatives is how OpenAPI says the
	// credential is optional, so the request passes without one.
	ok(do("GET", "/v1/maybe"), "an optional credential")

	// A cookie credential, and openIdConnect as a bearer token.
	denied(do("GET", "/v1/cookie"), "no cookie")
	ok(do("GET", "/v1/cookie", "Cookie", "session=s"), "a session cookie")
	ok(do("GET", "/v1/oidc", "Authorization", "Bearer t"), "openIdConnect is a bearer token")

	// mutualTLS was settled by the listener before this filter ran, so
	// it is not refused here.
	ok(do("GET", "/v1/mtls"), "mutualTLS is the listener's business")
}

// A refusal has to tell the client what to send. The registered schemes
// have a challenge; an API key does not, and inventing one would tell a
// client to do something no client understands.
func TestTheRefusalNamesTheSchemeWhenThereIsOneToName(t *testing.T) {
	f := securedFilter(t, filter.Options{"require_security": true})
	r, _ := http.NewRequest("GET", "http://api.example.com/v1/orders", nil)
	v := filtertest.Run(f, r, nil).Request
	if v.Headers["WWW-Authenticate"] != "Bearer" {
		t.Fatalf("WWW-Authenticate %q, want Bearer", v.Headers["WWW-Authenticate"])
	}
	if len(v.Attrs) < 2 || v.Attrs[1] != "bearerAuth" {
		t.Fatalf("attrs %v, want the scheme named", v.Attrs)
	}
	r, _ = http.NewRequest("GET", "http://api.example.com/v1/both", nil)
	v = filtertest.Run(f, r, nil).Request
	if _, has := v.Headers["WWW-Authenticate"]; has {
		t.Fatalf("an api key requirement produced a challenge: %v", v.Headers)
	}
	if len(v.Attrs) < 2 || v.Attrs[1] != "apiKeyHeader+apiKeyQuery" {
		t.Fatalf("attrs %v, want both schemes named", v.Attrs)
	}
}

// Without the setting nothing is refused, because turning it on refuses
// whatever was reaching the API without a credential. The description is
// still compiled, so the same request that passes here is the one the
// setting would refuse.
func TestWithoutTheSettingTheDescriptionIsStillOnlyDocumentation(t *testing.T) {
	f := securedFilter(t, nil)
	r, _ := http.NewRequest("GET", "http://api.example.com/v1/orders", nil)
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("denied without require_security: %+v", v)
	}
}

// A description whose security section names a scheme it never defined
// has a security section that means nothing. Failing at load is the only
// way an operator finds out before the gateway is relied on.
func TestASecurityRequirementMustNameADefinedScheme(t *testing.T) {
	bad := `
openapi: 3.0.3
info: {title: X, version: "1"}
paths:
  /a:
    get:
      security:
        - missingScheme: []
`
	if _, err := filtertest.Build("openapi", "x", filter.Options{"spec_file": write(t, bad)}); err == nil ||
		!strings.Contains(err.Error(), "securitySchemes does not define") {
		t.Fatalf("error %v, want one about an undefined scheme", err)
	}
}

// The scheme definitions themselves are checked, because a broken one is
// a requirement that cannot be enforced and would otherwise be enforced
// as "nothing to look for".
func TestBrokenSchemeDefinitionsAreRefused(t *testing.T) {
	for _, tc := range []struct{ scheme, want string }{
		{"{type: apiKey, name: K}", "in must be header, query or cookie"},
		{"{type: apiKey, in: body, name: K}", "in must be header, query or cookie"},
		{"{type: apiKey, in: header}", "name is required for apiKey"},
		{"{type: http}", "scheme is required for http"},
		{"{type: magic}", "is not one of apiKey"},
	} {
		spec := `
openapi: 3.0.3
info: {title: X, version: "1"}
components: {securitySchemes: {s: ` + tc.scheme + `}}
paths: {/a: {get: {}}}
`
		_, err := filtertest.Build("openapi", "x", filter.Options{"spec_file": write(t, spec)})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", tc.scheme, err, tc.want)
		}
	}
}

func basic(user, pass string) string { return basicRaw(user + ":" + pass) }

func basicRaw(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
