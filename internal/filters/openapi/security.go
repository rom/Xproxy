package openapi

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// The part of a description that is a security control and was being
// read as documentation.
//
// An OpenAPI operation says which credential it needs -- `security:
// [{bearerAuth: []}]` -- and `components.securitySchemes` says where
// that credential lives: a named header, a query parameter, a cookie, or
// an Authorization header with a particular scheme. That is a statement
// about every request the operation accepts, and it is the one statement
// a gateway can act on without knowing anything about the credential
// itself.
//
// Acting on it catches the failure that keeps happening: an endpoint that
// was meant to be authenticated and is not, because the middleware was
// registered for one router and not another, or the annotation was left
// off, or the check sits behind a feature flag somebody turned off. The
// description already says the endpoint needs a credential; the
// application is the thing that might forget.
//
// What this checks is presence and shape -- the header is there, the
// scheme is the declared one, there is something after it -- and not
// validity. Deciding whether a token is real is the identity provider's
// job and the application's, and this filter has no business guessing.
// A request with a forged bearer token still reaches the API and is still
// refused there. A request with no credential at all does not reach it,
// which is the whole point.

// scheme is one securityScheme reduced to where the credential is.
type scheme struct {
	name string
	// kind is the OpenAPI type: apiKey, http, oauth2, openIdConnect or
	// mutualTLS.
	kind string
	// in and param locate an apiKey: header, query or cookie, and the name.
	in, param string
	// httpScheme is the Authorization scheme of an http scheme, lower
	// case (bearer, basic, digest...).
	httpScheme string
}

// requirement is one alternative: every scheme in it must be satisfied.
type requirement []*scheme

// compileSchemes reads components.securitySchemes.
func compileSchemes(spec map[string]any) (map[string]*scheme, error) {
	out := map[string]*scheme{}
	comps, _ := spec["components"].(map[string]any)
	if comps == nil {
		return out, nil
	}
	list, _ := comps["securitySchemes"].(map[string]any)
	names := make([]string, 0, len(list))
	for n := range list {
		names = append(names, n)
	}
	sort.Strings(names) // a deterministic error for a broken description
	for _, n := range names {
		m, _ := list[n].(map[string]any)
		if m == nil {
			return nil, fmt.Errorf("securityScheme %q is not an object", n)
		}
		s := &scheme{name: n}
		s.kind, _ = m["type"].(string)
		switch s.kind {
		case "apiKey":
			s.in, _ = m["in"].(string)
			s.param, _ = m["name"].(string)
			switch s.in {
			case "header", "query", "cookie":
			default:
				return nil, fmt.Errorf("securityScheme %q: in must be header, query or cookie", n)
			}
			if s.param == "" {
				return nil, fmt.Errorf("securityScheme %q: name is required for apiKey", n)
			}
		case "http":
			s.httpScheme, _ = m["scheme"].(string)
			s.httpScheme = strings.ToLower(s.httpScheme)
			if s.httpScheme == "" {
				return nil, fmt.Errorf("securityScheme %q: scheme is required for http", n)
			}
		case "oauth2", "openIdConnect":
			// RFC 6750: the access token travels as a bearer token.
			s.httpScheme = "bearer"
		case "mutualTLS":
			// Nothing to look for in the request: whether the client
			// presented a certificate was settled by the listener's
			// client_auth before this filter ran, and second-guessing it
			// from here would be guessing. Such a requirement counts as
			// met; the listener is where it is enforced.
		default:
			return nil, fmt.Errorf("securityScheme %q: type %q is not one of apiKey, http, oauth2, openIdConnect, mutualTLS", n, s.kind)
		}
		out[n] = s
	}
	return out, nil
}

// compileRequirements turns a security list into alternatives. anonymous
// is true when one alternative is the empty object, which is how OpenAPI
// says the credential is optional.
func compileRequirements(node any, schemes map[string]*scheme, where string) (reqs []requirement, anonymous bool, err error) {
	list, ok := node.([]any)
	if !ok {
		return nil, false, nil
	}
	for _, alt := range list {
		m, _ := alt.(map[string]any)
		if len(m) == 0 {
			// An empty alternative satisfies everything, so the
			// operation is open. Recording it rather than dropping it is
			// what keeps "optional" from reading as "required".
			anonymous = true
			continue
		}
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		var req requirement
		for _, n := range names {
			s, ok := schemes[n]
			if !ok {
				// A description that asks for a scheme it never defined
				// is a description whose security section means nothing.
				// Refusing it at load is the only way an operator finds
				// out before the gateway is relied on.
				return nil, false, fmt.Errorf("%s: security requires %q, which components.securitySchemes does not define", where, n)
			}
			req = append(req, s)
		}
		reqs = append(reqs, req)
	}
	return reqs, anonymous, nil
}

// credential reports whether the request satisfies the operation's
// security, and which schemes would have satisfied it when it does not.
//
// The alternatives are an OR of ANDs, as OpenAPI defines them: any one
// alternative, with every scheme in it, is enough.
func (op *operation) credential(r *http.Request) (want requirement, ok bool) {
	if len(op.security) == 0 || op.anonymous {
		return nil, true
	}
	for _, alt := range op.security {
		met := true
		for _, s := range alt {
			if !s.present(r) {
				met = false
				break
			}
		}
		if met {
			return nil, true
		}
	}
	return op.security[0], false
}

// present reports whether the credential this scheme describes is in the
// request, in the place the description put it, with the shape it named.
func (s *scheme) present(r *http.Request) bool {
	switch s.kind {
	case "apiKey":
		switch s.in {
		case "header":
			return r.Header.Get(s.param) != ""
		case "query":
			return r.URL.Query().Get(s.param) != ""
		case "cookie":
			c, err := r.Cookie(s.param)
			return err == nil && c.Value != ""
		}
		return false
	case "http", "oauth2", "openIdConnect":
		return authScheme(r.Header.Get("Authorization"), s.httpScheme)
	}
	// mutualTLS, and anything a future version of OpenAPI adds: not this
	// filter's to judge, so not this filter's to refuse.
	return true
}

// authScheme reports whether an Authorization header carries the named
// scheme with something after it.
//
// The scheme is matched case-insensitively because RFC 9110 says it is
// case-insensitive, and a client sending "bearer" where the description
// wrote "Bearer" is a client every server accepts. What follows must be
// non-empty: "Authorization: Bearer" with nothing after it is a header
// that looks like a credential and is not one.
func authScheme(header, want string) bool {
	if header == "" || want == "" {
		return false
	}
	name, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(name, want) {
		return false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return false
	}
	if want != "basic" {
		return true
	}
	// Basic is the one scheme whose shape is worth checking, because it
	// is exactly defined: base64 of "user:password". A value that is not
	// that is not a credential the application can read either.
	raw, err := base64.StdEncoding.DecodeString(rest)
	return err == nil && strings.Contains(string(raw), ":")
}

// challenge is the WWW-Authenticate value for a refusal, or "" when the
// schemes have no challenge to offer. An apiKey has none: there is no
// registered challenge for "send this header", and inventing one would
// tell a client to do something no client understands.
func challenge(want requirement) string {
	for _, s := range want {
		switch s.kind {
		case "http":
			return http.CanonicalHeaderKey(s.httpScheme)
		case "oauth2", "openIdConnect":
			return "Bearer"
		}
	}
	return ""
}

// describe names the schemes of an alternative, for the log.
func describe(want requirement) string {
	names := make([]string, 0, len(want))
	for _, s := range want {
		names = append(names, s.name)
	}
	return strings.Join(names, "+")
}
