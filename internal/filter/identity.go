package filter

import (
	"context"
	"sort"
)

// Identity carries the authenticated identities a request's filters
// established, keyed by kind (for example "jwt", "oidc", "api_key",
// "basic"). The data plane attaches an empty one before the filter
// chain runs; identity-producing filters record into it with
// SetIdentity; the proxy then keys identity rate limits on it. A value
// is set only after the filter verified it, so unlike an unverified
// header or claim it cannot be spoofed.
type Identity struct {
	m map[string]string
	// attrs is what each kind learned beyond the name: groups, scopes
	// and claims. It is what makes authorisation possible at all — a
	// subject alone answers "who" and nothing else.
	attrs map[string]Attrs
}

type identityKeyType struct{}

var identityKey identityKeyType

// WithIdentity returns a context carrying a fresh identity set and the
// set, so the caller can read it after the filters have run. Filters
// reach the same set through the context with SetIdentity.
func WithIdentity(ctx context.Context) (context.Context, *Identity) {
	id := &Identity{m: map[string]string{}}
	return context.WithValue(ctx, identityKey, id), id
}

// SetIdentity records a verified identity of the given kind on the
// request's identity set, if one is attached. It is safe to call from a
// filter's Request; the last non-empty value for a kind wins. Not
// concurrency safe: the filter chain runs serially for one request.
func SetIdentity(ctx context.Context, kind, value string) {
	if kind == "" || value == "" {
		return
	}
	if id, ok := ctx.Value(identityKey).(*Identity); ok {
		id.m[kind] = value
	}
}

// Get returns the identity recorded for a kind, or "".
func (id *Identity) Get(kind string) string {
	if id == nil {
		return ""
	}
	return id.m[kind]
}

// Any returns any recorded identity, preferring the given kinds in
// order, then any other; "" when none was recorded.
func (id *Identity) Any(prefer ...string) string {
	if id == nil {
		return ""
	}
	for _, k := range prefer {
		if v := id.m[k]; v != "" {
			return v
		}
	}
	for _, v := range id.m {
		if v != "" {
			return v
		}
	}
	return ""
}

// IdentityFrom returns the identity set attached to a request's
// context, or nil. A filter that acts on who the request is — a second
// factor, an identity-keyed limit — reads it here rather than trusting
// a header, because a value is only in the set once a filter verified
// it.
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

// Attrs are what an authenticating filter learned about a request
// beyond the name: the groups its directory put it in, the scopes its
// credential carries, and whatever claims its token asserted.
//
// They exist so that authorisation has something to decide on. A
// subject alone answers "who" and nothing else, which leaves every
// filter to invent its own allow list from whatever it happens to have
// in hand — and an allow list per filter is a policy nobody can read in
// one place.
//
// Only a filter that verified them records them. Nothing here comes
// from a header a client sent.
type Attrs struct {
	Groups []string
	Scopes []string
	Claims map[string]string
}

// SetAttrs records what a filter learned about the identity it just
// verified, under the same kind it passed to SetIdentity. Calling it
// twice for a kind replaces what was there: a filter that re-verifies
// is the authority on its own answer.
func SetAttrs(ctx context.Context, kind string, a Attrs) {
	if kind == "" {
		return
	}
	id, ok := ctx.Value(identityKey).(*Identity)
	if !ok {
		return
	}
	if id.attrs == nil {
		id.attrs = map[string]Attrs{}
	}
	id.attrs[kind] = a
}

// Groups is every group recorded by any filter, deduplicated. A request
// authenticated twice — a session and an API key, say — carries both
// sets, because both were verified.
func (id *Identity) Groups() []string { return id.union(func(a Attrs) []string { return a.Groups }) }

// Scopes is every scope recorded by any filter, deduplicated.
func (id *Identity) Scopes() []string { return id.union(func(a Attrs) []string { return a.Scopes }) }

func (id *Identity) union(pick func(Attrs) []string) []string {
	if id == nil || len(id.attrs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range id.attrs {
		for _, v := range pick(a) {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// Claim returns the value a filter recorded for a claim, preferring the
// kinds in order and then any other. Claims are per kind because two
// identities can both assert "email" and mean different people.
func (id *Identity) Claim(name string, prefer ...string) string {
	if id == nil || name == "" {
		return ""
	}
	for _, k := range prefer {
		if v := id.attrs[k].Claims[name]; v != "" {
			return v
		}
	}
	for _, a := range id.attrs {
		if v := a.Claims[name]; v != "" {
			return v
		}
	}
	return ""
}

// Kinds is every kind that recorded an identity, sorted, which is what
// a policy means by "authenticated by".
func (id *Identity) Kinds() []string {
	if id == nil {
		return nil
	}
	out := make([]string, 0, len(id.m))
	for k, v := range id.m {
		if v != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
