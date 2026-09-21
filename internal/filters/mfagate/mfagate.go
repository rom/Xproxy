// Package mfagate is a built-in filter kind that requires a second
// factor on top of whatever established the identity — basic_auth,
// ldap_auth, oidc, a JWT or an API key. It uses the same enrolment
// file, the same replay rule and the same lockout as the SSH bastion,
// because a second factor that means different things on different
// ports is not a second factor.
//
//	filters:
//	  - name: staff-mfa
//	    kind: mfa
//	    options:
//	      file: /etc/xproxy/mfa                     # user:secret lines
//	      cookie_secret_file: /etc/xproxy/mfa.key   # 32+ bytes, created 0600 if absent
//	      cookie_name: __Host-xproxy-mfa            # default
//	      ttl: 12h                                  # how long a verified factor lasts
//	      issuer: xproxy
//	      skew: 1
//	      require_enrolment: true
//	      max_failures: 5
//	      window: 5m
//	      lockout: 15m
//
// The filter must run after the one that establishes the identity: it
// challenges the identity it is given and refuses a request that has
// none, because a second factor with no first factor is a password
// prompt with no account behind it.
package mfagate

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/secret"
)

// Config is the options schema.
type Config struct {
	File             string `json:"file"`
	CookieSecretFile string `json:"cookie_secret_file"`
	CookieName       string `json:"cookie_name"`
	TTL              string `json:"ttl"`
	Issuer           string `json:"issuer"`
	Prompt           string `json:"prompt"`
	Skew             *int   `json:"skew"`
	RequireEnrolment *bool  `json:"require_enrolment"`
	MaxFailures      int    `json:"max_failures"`
	Window           string `json:"window"`
	Lockout          string `json:"lockout"`
	// Identity names the identity kinds to challenge, in order of
	// preference. Empty takes whichever one a filter established.
	Identity []string `json:"identity"`

	ttl     time.Duration
	window  time.Duration
	lockout time.Duration
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.File == "" {
		errs = append(errs, errors.New("file is required"))
	}
	if c.CookieSecretFile == "" {
		errs = append(errs, errors.New("cookie_secret_file is required: the verified factor is carried in a signed cookie"))
	}
	if c.CookieName == "" {
		c.CookieName = "__Host-xproxy-mfa"
	}
	if strings.ContainsAny(c.CookieName, " ;,\r\n=") {
		errs = append(errs, fmt.Errorf("cookie_name: %q is not a cookie name", c.CookieName))
	}
	if c.Issuer == "" {
		c.Issuer = "xproxy"
	}
	if c.Prompt == "" {
		c.Prompt = "One-time code"
	}
	if c.Skew == nil {
		one := 1
		c.Skew = &one
	}
	if *c.Skew < 0 || *c.Skew > 10 {
		errs = append(errs, errors.New("skew: must be 0..10"))
	}
	if c.MaxFailures == 0 {
		c.MaxFailures = 5
	}
	for _, d := range []struct {
		name string
		in   string
		def  time.Duration
		max  time.Duration
		out  *time.Duration
	}{
		{"ttl", c.TTL, 12 * time.Hour, 7 * 24 * time.Hour, &c.ttl},
		{"window", c.Window, 5 * time.Minute, 24 * time.Hour, &c.window},
		{"lockout", c.Lockout, 15 * time.Minute, 7 * 24 * time.Hour, &c.lockout},
	} {
		*d.out = d.def
		if d.in == "" {
			continue
		}
		v, err := time.ParseDuration(d.in)
		if err != nil || v <= 0 || v > d.max {
			errs = append(errs, fmt.Errorf("%s: must be a duration between 0 and %s", d.name, d.max))
			continue
		}
		*d.out = v
	}
	return &c, errors.Join(errs...)
}

type gate struct {
	name  string
	cfg   *Config
	guard *mfa.Guard
	ring  *secret.Keyring
	log   *slog.Logger

	verified atomic.Uint64
	failed   atomic.Uint64
	asked    atomic.Uint64
}

func (g *gate) Name() string { return g.name }

// require reports whether a user with no enrolment is refused.
func (g *gate) require() bool {
	return g.cfg.RequireEnrolment == nil || *g.cfg.RequireEnrolment
}

func (g *gate) Begin(context.Context, *filter.Info) filter.Instance { return &instance{g: g} }

type instance struct {
	g    *gate
	user string
	step string
}

// Request lets a request through only when the identity it carries has
// a second factor verified within the TTL.
func (in *instance) Request(r *http.Request) filter.Verdict {
	g := in.g
	user := filter.IdentityFrom(r.Context()).Any(g.cfg.Identity...)
	if user == "" {
		// No identity: there is nothing to challenge. This is a
		// configuration error rather than an attack, and it fails
		// closed.
		in.step = "no_identity"
		return filter.Verdict{Deny: true, Status: http.StatusUnauthorized, Reason: g.name,
			Detail: "no identity to challenge; put this filter after the one that authenticates"}
	}
	in.user = user
	if !g.guard.Enrolled(user) && !g.require() {
		// An optional second factor: a user who never enrolled is let
		// through, and the log says so. Validation warns about this,
		// because the account that never enrolled is the one an
		// attacker will use.
		in.step = "not_enrolled"
		return filter.Continue
	}
	if in.cookieValid(r, user) {
		in.step = "cookie"
		filter.SetIdentity(r.Context(), "mfa", user)
		return filter.Continue
	}
	if r.Method == http.MethodPost && r.URL.Query().Get("xproxy_mfa") == "verify" {
		return in.verify(r, user)
	}
	g.asked.Add(1)
	in.step = "challenge"
	return in.challenge(r, "")
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any {
	if in.user == "" {
		return nil
	}
	return []any{"mfa_user", in.user, "mfa", in.step}
}

// verify reads the posted code and, on success, sets the cookie and
// sends the client back to where it was going.
func (in *instance) verify(r *http.Request, user string) filter.Verdict {
	g := in.g
	// The form is small by construction; anything larger is not one.
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	_ = r.Body.Close()
	values, err := parseForm(string(body))
	if err != nil {
		in.step = "bad_form"
		return in.challenge(r, "That did not look like a code.")
	}
	code := strings.TrimSpace(values["code"])
	if verr := g.guard.Verify(user, code, time.Now()); verr != nil {
		g.failed.Add(1)
		in.step = "failed"
		g.log.Warn("mfa code refused", "filter", g.name, "user", user, "err", verr.Error())
		// One message for every failure. Telling a wrong code from a
		// replayed one, or from a name that never enrolled, is how an
		// attacker learns which accounts are worth attacking.
		return in.challenge(r, "That code was not accepted.")
	}
	g.verified.Add(1)
	in.step = "verified"
	filter.SetIdentity(r.Context(), "mfa", user)
	next := values["next"]
	if !safeNext(next) {
		next = "/"
	}
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{}}
	resp.Header.Set("Location", next)
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Add("Set-Cookie", in.cookie(user).String())
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusFound, Reason: g.name,
		Detail: "mfa_verified", Response: resp}
}

// challenge serves the form. It is a deny with a body rather than a
// redirect, so the request that needed the factor is the request that
// resumes after it.
func (in *instance) challenge(r *http.Request, message string) filter.Verdict {
	g := in.g
	next := r.URL.RequestURI()
	if !safeNext(next) {
		next = "/"
	}
	note := ""
	if message != "" {
		note = `<p class="err">` + html.EscapeString(message) + `</p>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + html.EscapeString(g.cfg.Issuer) + `</title>` +
		`<style>body{font:16px system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f6f7;color:#1b1b1f}` +
		`form{background:#fff;padding:2rem;border-radius:.5rem;box-shadow:0 1px 3px rgba(0,0,0,.12);max-width:22rem}` +
		`input{font:inherit;padding:.5rem;width:100%;box-sizing:border-box;letter-spacing:.2em}` +
		`button{font:inherit;margin-top:1rem;padding:.5rem 1rem;width:100%}` +
		`.err{color:#a11;margin:0 0 1rem}</style></head><body>` +
		`<form method="post" action="?xproxy_mfa=verify">` + note +
		`<label for="code">` + html.EscapeString(g.cfg.Prompt) + `</label>` +
		`<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus>` +
		`<input type="hidden" name="next" value="` + html.EscapeString(next) + `">` +
		`<button type="submit">Continue</button></form></body></html>`
	resp := &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{},
		Body: io.NopCloser(strings.NewReader(page)), ContentLength: int64(len(page))}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("Content-Length", strconv.Itoa(len(page)))
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusUnauthorized, Reason: g.name,
		Detail: "mfa_challenge", Response: resp}
}

// cookie carries the verified factor: the user, an expiry, and a MAC
// over both under the current key.
func (in *instance) cookie(user string) *http.Cookie {
	g := in.g
	exp := time.Now().Add(g.cfg.ttl)
	payload := user + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := sign(g.ring.Primary(), payload)
	return &http.Cookie{
		Name:     g.cfg.CookieName,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + mac)),
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(g.cfg.ttl / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// cookieValid checks the cookie against every key in the ring, so a key
// rotation does not sign everyone out, and against the user the request
// authenticated as, so a cookie issued for one account is worthless on
// another.
func (in *instance) cookieValid(r *http.Request, user string) bool {
	g := in.g
	c, err := r.Cookie(g.cfg.CookieName)
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().After(time.Unix(exp, 0)) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(parts[0]), []byte(user)) != 1 {
		return false
	}
	payload := parts[0] + "|" + parts[1]
	for _, key := range g.ring.All() {
		if hmac.Equal([]byte(sign(key, payload)), []byte(parts[2])) {
			return true
		}
	}
	return false
}

func sign(key []byte, payload string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// safeNext keeps the redirect inside this site: a target that names a
// host is an open redirect, and one that starts with two slashes names
// a host whatever it looks like.
func safeNext(s string) bool {
	return strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") &&
		!strings.ContainsAny(s, "\\\r\n") && len(s) < 2048
}

// parseForm reads an application/x-www-form-urlencoded body without
// touching r.ParseForm, which would consume the body the upstream may
// still need on another path.
func parseForm(body string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		key, err := unescape(k)
		if err != nil {
			return nil, err
		}
		val, err := unescape(v)
		if err != nil {
			return nil, err
		}
		out[key] = val
	}
	return out, nil
}

func unescape(s string) (string, error) {
	return url.QueryUnescape(strings.ReplaceAll(s, "+", " "))
}

func init() {
	filter.Register(filter.Kind{
		Name:        "mfa",
		Description: "A second factor (TOTP) on top of the filter that established the identity.",
		Validate: func(opts filter.Options) error {
			c, err := parse(opts)
			if err != nil {
				return err
			}
			_, err = mfa.Load(c.File)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			store, err := mfa.Load(c.File)
			if err != nil {
				return nil, err
			}
			ring, err := secret.LoadOrCreate(c.CookieSecretFile)
			if err != nil {
				return nil, fmt.Errorf("cookie secret: %w", err)
			}
			return &gate{name: name, cfg: c, ring: ring, log: env.Log,
				guard: mfa.NewGuard(store, *c.Skew, mfa.Lockout{
					MaxFailures: c.MaxFailures, Window: c.window, Duration: c.lockout,
				})}, nil
		},
	})
}
