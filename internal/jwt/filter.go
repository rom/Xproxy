package jwt

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

// Filter returns the per-route filter for this provider.
func (p *Provider) Filter(required bool) filter.Filter {
	return &jwtFilter{p: p, required: required}
}

type jwtFilter struct {
	p        *Provider
	required bool
}

func (f *jwtFilter) Name() string { return "jwt:" + f.p.cfg.Name }

func (f *jwtFilter) Begin(_ context.Context, _ *filter.Info) filter.Instance {
	return &instance{f: f}
}

type instance struct {
	f     *jwtFilter
	attrs []any
}

// extract returns the token and whether one was present.
func (f *jwtFilter) extract(r *http.Request) (string, bool) {
	src := f.p.cfg.Source
	switch {
	case src == "bearer":
		v := r.Header.Get("Authorization")
		if len(v) > 7 && strings.EqualFold(v[:7], "Bearer ") {
			return strings.TrimSpace(v[7:]), true
		}
		// RFC 9449 gives a sender-constrained token its own scheme, so a
		// server that only reads "Bearer " does not see the token at all.
		if f.p.dpop.on() && len(v) > 5 && strings.EqualFold(v[:5], "DPoP ") {
			return strings.TrimSpace(v[5:]), true
		}
		return "", false
	case strings.HasPrefix(src, "header:"):
		v := r.Header.Get(src[7:])
		return v, v != ""
	case strings.HasPrefix(src, "cookie:"):
		c, err := r.Cookie(src[7:])
		if err != nil || c.Value == "" {
			return "", false
		}
		return c.Value, true
	}
	return "", false
}

// strip removes the token from the forwarded request.
func (f *jwtFilter) strip(r *http.Request) {
	src := f.p.cfg.Source
	switch {
	case src == "bearer":
		r.Header.Del("Authorization")
	case strings.HasPrefix(src, "header:"):
		r.Header.Del(src[7:])
	case strings.HasPrefix(src, "cookie:"):
		name := src[7:]
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name != name {
				r.AddCookie(c)
			}
		}
	}
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	f := in.f
	cfg := f.p.cfg
	// Client supplied copies of forwarded claim headers are never trusted,
	// whether or not a token is present.
	for h := range cfg.ForwardClaims {
		r.Header.Del(h)
	}
	token, present := f.extract(r)
	if !present {
		if f.required {
			return deny(http.StatusUnauthorized, "missing", `Bearer realm="xproxy"`)
		}
		return filter.Continue
	}
	claims, err := f.p.Verify(token)
	if err != nil {
		if errors.Is(err, ErrKeysUnavail) {
			return filter.Verdict{Deny: true, Status: http.StatusServiceUnavailable, Reason: "jwt", Detail: "keys_unavailable", Headers: map[string]string{"Retry-After": "5"}}
		}
		if errors.Is(err, ErrIntrospection) {
			return filter.Verdict{Deny: true, Status: http.StatusServiceUnavailable, Reason: "jwt", Detail: "introspection_unavailable", Headers: map[string]string{"Retry-After": "5"}}
		}
		return deny(http.StatusUnauthorized, category(err), `Bearer realm="xproxy", error="invalid_token"`)
	}
	// The proof is checked against claims this proxy has verified:
	// reading cnf.jkt out of an unverified token would let an attacker
	// write their own thumbprint into it.
	if f.p.dpop.on() {
		thumb, derr := f.p.dpop.check(r, token, claims, time.Now())
		if derr != nil {
			return dpopDeny(derr, f.p.dpop.algList)
		}
		if thumb != "" {
			in.attrs = append(in.attrs, "dpop_jkt", thumb)
		}
		// The proof belongs to this hop. Forwarding it invites the
		// backend to verify it against its own URI, which will not match,
		// and leaves a signed statement about this request in a log
		// somewhere else.
		r.Header.Del("DPoP")
	}
	if cfg.Strips() {
		f.strip(r)
	}
	for h, claim := range cfg.ForwardClaims {
		if v, ok := claims[claim]; ok {
			r.Header.Set(h, ClaimString(v))
		}
	}
	if sub := ClaimString(claims["sub"]); sub != "" {
		filter.SetIdentity(r.Context(), "jwt", sub)
	}
	in.attrs = append(in.attrs, "jwt_provider", cfg.Name)
	for _, c := range cfg.LogClaims {
		if v, ok := claims[c]; ok {
			in.attrs = append(in.attrs, "jwt_"+c, ClaimString(v))
		}
	}
	return filter.Continue
}

// dpopDeny answers a proof problem the way RFC 9449 section 7.1 says to:
// invalid_dpop_proof for the proof, invalid_token for a token this route
// will not take as a bearer token, and the algs the client should have
// signed with either way.
func dpopDeny(err error, algs string) filter.Verdict {
	detail, code := "dpop_proof", "invalid_dpop_proof"
	switch {
	case errors.Is(err, ErrDPoPMissing):
		detail, code = "dpop_missing", "invalid_token"
	case errors.Is(err, ErrDPoPUnbound):
		detail, code = "dpop_unbound", "invalid_token"
	case errors.Is(err, ErrDPoPBinding):
		detail = "dpop_binding"
	case errors.Is(err, ErrDPoPReplay):
		detail = "dpop_replay"
	}
	challenge := `DPoP error="` + code + `"`
	if algs != "" {
		challenge += `, algs="` + algs + `"`
	}
	return deny(http.StatusUnauthorized, detail, challenge)
}

func deny(status int, detail, challenge string) filter.Verdict {
	return filter.Verdict{Deny: true, Status: status, Reason: "jwt", Detail: detail, Headers: map[string]string{"WWW-Authenticate": challenge}}
}

func category(err error) string {
	switch {
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrIssuer):
		return "issuer"
	case errors.Is(err, ErrAudience):
		return "audience"
	case errors.Is(err, ErrAlgorithm):
		return "algorithm"
	case errors.Is(err, ErrNoKey):
		return "unknown_key"
	case errors.Is(err, ErrSignature):
		return "signature"
	case errors.Is(err, ErrClaim):
		return "claim"
	case errors.Is(err, ErrInactive):
		return "inactive"
	default:
		return "malformed"
	}
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any { return in.attrs }
