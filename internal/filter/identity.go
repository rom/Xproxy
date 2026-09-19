package filter

import "context"

// Identity carries the authenticated identities a request's filters
// established, keyed by kind (for example "jwt", "oidc", "api_key",
// "basic"). The data plane attaches an empty one before the filter
// chain runs; identity-producing filters record into it with
// SetIdentity; the proxy then keys identity rate limits on it. A value
// is set only after the filter verified it, so unlike an unverified
// header or claim it cannot be spoofed.
type Identity struct {
	m map[string]string
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
