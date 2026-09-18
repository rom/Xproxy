package jwt

import (
	"context"
	"errors"
	"net/http"
	"strings"

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
		return deny(http.StatusUnauthorized, category(err), `Bearer realm="xproxy", error="invalid_token"`)
	}
	if cfg.Strips() {
		f.strip(r)
	}
	for h, claim := range cfg.ForwardClaims {
		if v, ok := claims[claim]; ok {
			r.Header.Set(h, ClaimString(v))
		}
	}
	in.attrs = append(in.attrs, "jwt_provider", cfg.Name)
	for _, c := range cfg.LogClaims {
		if v, ok := claims[c]; ok {
			in.attrs = append(in.attrs, "jwt_"+c, ClaimString(v))
		}
	}
	return filter.Continue
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
	default:
		return "malformed"
	}
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any { return in.attrs }
