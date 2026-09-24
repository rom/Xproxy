package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

// The login flow is exercised end to end through the proxy in
// internal/proxy, which is where a browser's view of it belongs. These
// tests drive the filter directly instead, because the interesting
// cases are the ones a browser cannot produce: a provider that answers
// nonsense, a callback without the state cookie, a redirect URI derived
// from a header the client controls.

// op is a fake OpenID provider: discovery, authorization, token
// exchange with PKCE, JWKS and end session. Each knob is an atomic so a
// test can break one thing at a time.
type op struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	mu        sync.Mutex
	codes     map[string]struct{ challenge, nonce string }
	issued    atomic.Int64
	noNonce   atomic.Bool
	badIssuer atomic.Bool
	claims    atomic.Value // map[string]any of extra claims
	discCode  atomic.Int64
	discBody  atomic.Value // string, when set, replaces the metadata document
	tokenBody atomic.Value // string, when set, replaces the token response
	tokenCode atomic.Int64
}

func newOP(t *testing.T) *op {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	o := &op{key: k, codes: map[string]struct{ challenge, nonce string }{}}
	o.claims.Store(map[string]any{})
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "k1", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}}})

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if code := o.discCode.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		if body, _ := o.discBody.Load().(string); body != "" {
			_, _ = io.WriteString(w, body)
			return
		}
		iss := o.srv.URL
		if o.badIssuer.Load() {
			iss = "https://someone.else.test"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": iss, "authorization_endpoint": o.srv.URL + "/authorize",
			"token_endpoint": o.srv.URL + "/token", "jwks_uri": o.srv.URL + "/jwks",
			"end_session_endpoint": o.srv.URL + "/endsession",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		n := o.issued.Add(1)
		code := fmt.Sprintf("code-%d", n)
		o.mu.Lock()
		o.codes[code] = struct{ challenge, nonce string }{q.Get("code_challenge"), q.Get("nonce")}
		o.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if code := o.tokenCode.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		if body, _ := o.tokenBody.Load().(string); body != "" {
			_, _ = io.WriteString(w, body)
			return
		}
		_ = r.ParseForm()
		o.mu.Lock()
		c, known := o.codes[r.Form.Get("code")]
		delete(o.codes, r.Form.Get("code"))
		o.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !known || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		nonce := c.nonce
		if o.noNonce.Load() {
			nonce = "not-the-nonce"
		}
		now := time.Now().Unix()
		claims := map[string]any{
			"iss": o.srv.URL, "aud": "xproxy", "sub": "alice", "email": "alice@example.com",
			"nonce": nonce, "sid": fmt.Sprintf("sid-%d", o.issued.Load()), "iat": now, "exp": now + 300,
		}
		for k, v := range o.claims.Load().(map[string]any) {
			claims[k] = v
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": o.sign(t, claims), "token_type": "Bearer"})
	})
	mux.HandleFunc("/endsession", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	o.srv = httptest.NewServer(mux)
	t.Cleanup(o.srv.Close)
	return o
}

func (o *op) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`))
	pb, _ := json.Marshal(claims)
	signed := h + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, o.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// build returns a filter wired to the provider, with opts merged over
// the defaults.
func build(t *testing.T, o *op, opts filter.Options) *oidcFilter {
	t.Helper()
	dir := t.TempDir()
	cs := filepath.Join(dir, "client.secret")
	if err := os.WriteFile(cs, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := filter.Options{
		"issuer": o.srv.URL, "allow_http": true, "client_id": "xproxy",
		"client_secret_file": cs, "cookie_secret_file": filepath.Join(dir, "cookie.key"),
		"scopes": []any{"openid", "email"}, "session_ttl": "1h",
		"forward_headers": map[string]any{"X-Remote-User": "sub", "X-Remote-Email": "email"},
	}
	for k, v := range opts {
		if v == nil {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	c, err := parse(base)
	if err != nil {
		t.Fatal(err)
	}
	f, err := newFilter("sso", c, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// info is the per-request context the data plane hands a filter.
func info() *filter.Info {
	return &filter.Info{ClientIP: netip.MustParseAddr("192.0.2.10"), Host: "app.test", Route: "app"}
}

// run drives one request through the filter and returns the verdict.
func run(f *oidcFilter, r *http.Request) filter.Verdict {
	in := f.Begin(context.Background(), info()).(*instance)
	return in.Request(r)
}

// get builds a GET with a Host the filter can derive its base URL from.
func get(target string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = "app.test"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

// setCookie returns the named cookie of a verdict's response.
func setCookie(t *testing.T, v filter.Verdict, name string) *http.Cookie {
	t.Helper()
	if v.Response == nil {
		t.Fatal("the verdict carries no response")
	}
	for _, c := range (&http.Response{Header: v.Response.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", name, v.Response.Header)
	return nil
}

// TestLoginRoundTrip is the whole flow: an unauthenticated request is
// redirected to the provider with PKCE and a nonce, the provider sends
// the browser back to the callback, the callback exchanges the code and
// sets the session, and the next request carries the claims upstream.
func TestLoginRoundTrip(t *testing.T) {
	o := newOP(t)
	o.claims.Store(map[string]any{
		"roles": []any{"staff", "contractors"},
		"scope": "read write", "department": "engineering",
	})
	f := build(t, o, filter.Options{
		"groups_claim": "roles", "attr_claims": []any{"department"},
	})

	v := run(f, get("/page?x=1"))
	if !v.Deny || v.Status != http.StatusFound || v.Detail != "login" {
		t.Fatalf("first request: %+v", v)
	}
	loc, err := url.Parse(v.Response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != "xproxy" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("nonce") == "" || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("authorization request: %s", loc.RawQuery)
	}
	if !strings.HasSuffix(q.Get("redirect_uri"), "/oauth2/callback") {
		t.Fatalf("redirect_uri %q", q.Get("redirect_uri"))
	}
	state := setCookie(t, v, "XPOIDC_state")

	// Follow the provider's redirect by hand.
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get(loc.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if cb.Query().Get("state") != q.Get("state") {
		t.Fatal("the provider did not echo the state")
	}

	v = run(f, get("/oauth2/callback?"+cb.RawQuery, state))
	if !v.Deny || v.Status != http.StatusFound || v.Detail != "login_complete" {
		t.Fatalf("callback: %+v", v)
	}
	if got := v.Response.Header.Get("Location"); got != "/page?x=1" {
		t.Fatalf("landed on %q, not the page first asked for", got)
	}
	sess := setCookie(t, v, "XPOIDC")
	if !sess.HttpOnly || sess.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie is not HttpOnly/Lax: %+v", sess)
	}
	var session session
	if err := f.open(sess.Value, "session", &session); err != nil {
		t.Fatalf("open session: %v", err)
	}
	attrs := f.attrsOf(&session)
	if strings.Join(attrs.Groups, ",") != "staff,contractors" ||
		strings.Join(attrs.Scopes, ",") != "read,write" || attrs.Claims["department"] != "engineering" {
		t.Fatalf("authorization claims were not retained in the session: %+v", attrs)
	}
	if cleared := setCookie(t, v, "XPOIDC_state"); cleared.MaxAge >= 0 {
		t.Fatal("the state cookie was not cleared")
	}

	// The session is now good for ordinary requests.
	r := get("/page", sess)
	if v := run(f, r); v.Deny {
		t.Fatalf("an authenticated request was denied: %+v", v)
	}
	if r.Header.Get("X-Remote-User") != "alice" || r.Header.Get("X-Remote-Email") != "alice@example.com" {
		t.Fatalf("claims not forwarded: %v", r.Header)
	}
	if r.Header.Get("Cookie") != "" {
		t.Fatalf("the session cookie was forwarded upstream: %q", r.Header.Get("Cookie"))
	}
}

// TestClientSuppliedIdentityHeaderIsRemoved is the bypass this filter
// exists to prevent: a client that sets the header the upstream trusts.
// It must be deleted before anything else, on every request, logged in
// or not.
func TestClientSuppliedIdentityHeaderIsRemoved(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	r := get("/page")
	r.Header.Set("X-Remote-User", "root")
	r.Header.Set("X-Remote-Email", "root@example.com")
	run(f, r)
	if r.Header.Get("X-Remote-User") != "" || r.Header.Get("X-Remote-Email") != "" {
		t.Fatalf("a client supplied identity header survived: %v", r.Header)
	}
}

// TestCallbackRejections walks every way a callback can be wrong. Each
// must produce a distinct detail, because the detail is what an
// operator reads in the security log.
func TestCallbackRejections(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	// A valid state cookie to vary from.
	v := run(f, get("/page"))
	state := setCookie(t, v, "XPOIDC_state")
	good := v.Response.Header.Get("Location")
	gq, _ := url.Parse(good)
	stateParam := gq.Query().Get("state")

	cases := []struct {
		name    string
		req     *http.Request
		status  int
		detail  string
		prefix  bool
		cookies bool
	}{
		{name: "post", req: func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/oauth2/callback", nil)
			r.Host = "app.test"
			return r
		}(), status: http.StatusMethodNotAllowed, detail: "callback_method"},
		{name: "provider error", req: get("/oauth2/callback?error=access_denied"), status: http.StatusUnauthorized, detail: "provider_error:", prefix: true},
		{name: "no cookie", req: get("/oauth2/callback?code=c&state=" + url.QueryEscape(stateParam)), status: http.StatusBadRequest, detail: "state_missing"},
		{name: "no code", req: get("/oauth2/callback?state="+url.QueryEscape(stateParam), state), status: http.StatusBadRequest, detail: "state_missing"},
		{name: "no state", req: get("/oauth2/callback?code=c", state), status: http.StatusBadRequest, detail: "state_missing"},
		{name: "forged state", req: get("/oauth2/callback?code=c&state=forged", state), status: http.StatusBadRequest, detail: "state_mismatch"},
		{name: "unknown code", req: get("/oauth2/callback?code=never-issued&state="+url.QueryEscape(stateParam), state), status: http.StatusUnauthorized, detail: "exchange"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := run(f, tc.req)
			if !got.Deny || got.Status != tc.status {
				t.Fatalf("got %d %q, want %d %q", got.Status, got.Detail, tc.status, tc.detail)
			}
			if tc.prefix && !strings.HasPrefix(got.Detail, tc.detail) || !tc.prefix && got.Detail != tc.detail {
				t.Fatalf("detail %q, want %q", got.Detail, tc.detail)
			}
		})
	}
}

// TestStateCookieFromAnotherLoginIsRefused is the cross-login case: a
// state cookie that is itself valid, paired with the state parameter of
// a different login. The digest ties one to the other.
func TestStateCookieFromAnotherLoginIsRefused(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	first := run(f, get("/a"))
	second := run(f, get("/b"))
	firstState := setCookie(t, first, "XPOIDC_state")
	secondLoc, _ := url.Parse(second.Response.Header.Get("Location"))
	v := run(f, get("/oauth2/callback?code=c&state="+url.QueryEscape(secondLoc.Query().Get("state")), firstState))
	if v.Detail != "state_mismatch" {
		t.Fatalf("a state cookie from another login gave %q", v.Detail)
	}
}

// TestExpiredStateIsRefused covers a login left open longer than the
// state's ten minutes.
func TestExpiredStateIsRefused(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	stale, err := f.seal(loginState{Nonce: "n", Verifier: "v", Return: "/", Exp: time.Now().Add(-time.Minute).Unix()}, "state")
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Cookie{Name: "XPOIDC_state", Value: stale}
	param := stale[:min(len(stale), 64)] + "." + stateDigest(stale)
	v := run(f, get("/oauth2/callback?code=c&state="+url.QueryEscape(param), c))
	if v.Detail != "state_invalid" {
		t.Fatalf("an expired state gave %q", v.Detail)
	}
}

// TestWrongNonceIsRefused covers a provider (or a party in the middle)
// that returns an ID token minted for a different login.
func TestWrongNonceIsRefused(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	o.noNonce.Store(true)
	if v := completeLogin(t, f, o, "/page"); v.Detail != "nonce" {
		t.Fatalf("a wrong nonce gave %q", v.Detail)
	}
}

// TestRequiredClaim covers require_claims, which is how an operator
// limits a tenant's login to their own domain.
func TestRequiredClaim(t *testing.T) {
	o := newOP(t)
	f := build(t, o, filter.Options{"require_claims": map[string]any{"hd": "example.com"}})
	o.claims.Store(map[string]any{"hd": "elsewhere.test"})
	v := completeLogin(t, f, o, "/page")
	if v.Status != http.StatusForbidden || v.Detail != "claim:hd" {
		t.Fatalf("a wrong hd gave %d %q", v.Status, v.Detail)
	}
	o.claims.Store(map[string]any{"hd": "example.com"})
	if v := completeLogin(t, f, o, "/page"); v.Detail != "login_complete" {
		t.Fatalf("the right hd gave %q", v.Detail)
	}
}

// TestAuthorizedPartyIsChecked covers an ID token issued to another
// client and forwarded here: the audience alone does not settle it when
// the token carries azp.
func TestAuthorizedPartyIsChecked(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	o.claims.Store(map[string]any{"azp": "some-other-client"})
	if v := completeLogin(t, f, o, "/page"); v.Detail != "azp" {
		t.Fatalf("a token issued to another client gave %q", v.Detail)
	}
}

// completeLogin runs login, follows the provider and returns the
// callback's verdict.
func completeLogin(t *testing.T, f *oidcFilter, o *op, target string) filter.Verdict {
	t.Helper()
	v := run(f, get(target))
	if v.Detail != "login" {
		t.Fatalf("login: %+v", v)
	}
	state := setCookie(t, v, "XPOIDC_state")
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).
		Get(v.Response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return run(f, get("/oauth2/callback?"+cb.RawQuery, state))
}

// TestReturnPathIsNotOpenRedirect covers where the browser lands after
// login. The path comes from the request that started the flow, so a
// scheme-relative or absolute URL there would make the login endpoint an
// open redirect with the site's own name on it.
func TestReturnPathIsNotOpenRedirect(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	for _, target := range []string{
		"http://app.test//evil.example/path",
		"http://app.test/%2F%2Fevil.example",
		"http://app.test/" + strings.Repeat("a", 4000),
	} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Host = "app.test"
		v := run(f, r)
		state := setCookie(t, v, "XPOIDC_state")
		var ls loginState
		if err := f.open(state.Value, "state", &ls); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(ls.Return, "//") || !strings.HasPrefix(ls.Return, "/") || len(ls.Return) > 2048 {
			t.Fatalf("%s produced the return path %q", target, ls.Return)
		}
	}
}

// TestRedirectURIIgnoresUntrustedForwardedProto is the reason `secure`
// exists. The redirect URI is where the provider sends the code, and
// any client can set X-Forwarded-Proto: from an untrusted peer it must
// not change the scheme.
func TestRedirectURIIgnoresUntrustedForwardedProto(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	r := get("/page")
	r.Header.Set("X-Forwarded-Proto", "https")

	untrusted := &filter.Info{ClientIP: netip.MustParseAddr("192.0.2.10"), Host: "app.test"}
	if got := f.redirectURI(r, untrusted); !strings.HasPrefix(got, "http://") {
		t.Fatalf("an untrusted X-Forwarded-Proto changed the redirect URI to %q", got)
	}
	trusted := &filter.Info{ClientIP: netip.MustParseAddr("192.0.2.10"), Host: "app.test", TrustedPeer: true}
	if got := f.redirectURI(r, trusted); !strings.HasPrefix(got, "https://") {
		t.Fatalf("a trusted X-Forwarded-Proto was ignored: %q", got)
	}
	tlsInfo := &filter.Info{ClientIP: netip.MustParseAddr("192.0.2.10"), Host: "app.test", TLS: true}
	if got := f.redirectURI(get("/page"), tlsInfo); !strings.HasPrefix(got, "https://") {
		t.Fatalf("a TLS listener produced %q", got)
	}
}

// TestExternalURLWins covers the setting that stops any of that being
// guessed: with external_url set, neither the Host header nor a
// forwarded scheme is consulted.
func TestExternalURLWins(t *testing.T) {
	o := newOP(t)
	f := build(t, o, filter.Options{"external_url": "https://sso.example.com"})
	r := get("/page")
	r.Host = "attacker.test"
	r.Header.Set("X-Forwarded-Proto", "http")
	if got := f.redirectURI(r, info()); got != "https://sso.example.com/oauth2/callback" {
		t.Fatalf("external_url did not win: %q", got)
	}
}

// TestLogout clears the cookie, revokes the provider session and sends
// the browser to the end session endpoint.
func TestLogout(t *testing.T) {
	o := newOP(t)
	f := build(t, o, filter.Options{"logout_redirect": "/bye"})
	v := completeLogin(t, f, o, "/page")
	sess := setCookie(t, v, "XPOIDC")

	out := run(f, get("/oauth2/logout", sess))
	if !out.Deny || out.Status != http.StatusFound || out.Detail != "logout" {
		t.Fatalf("logout: %+v", out)
	}
	if cleared := setCookie(t, out, "XPOIDC"); cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Fatalf("the session cookie was not cleared: %+v", cleared)
	}
	loc := out.Response.Header.Get("Location")
	if !strings.HasPrefix(loc, o.srv.URL+"/endsession") || !strings.Contains(loc, "post_logout_redirect_uri") {
		t.Fatalf("logout location %q", loc)
	}
	// The cookie still decodes, but the session it names is revoked, so
	// presenting it again is a fresh login.
	if v := run(f, get("/page", sess)); v.Detail != "login" {
		t.Fatalf("a revoked session still worked: %+v", v)
	}
}

// TestFrontChannelLogout is the endpoint the provider loads when the
// user logs out somewhere else. It arrives cross site, normally without
// our cookie, which is why the revocation index exists.
func TestFrontChannelLogout(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	v := completeLogin(t, f, o, "/page")
	sess := setCookie(t, v, "XPOIDC")
	var s session
	if err := f.open(sess.Value, "session", &s); err != nil {
		t.Fatal(err)
	}

	fc := run(f, get("/oauth2/frontchannel-logout?sid="+url.QueryEscape(s.Sid)+"&iss="+url.QueryEscape(o.srv.URL)))
	if !fc.Deny || fc.Status != http.StatusOK || fc.Detail != "frontchannel_logout" {
		t.Fatalf("front channel logout: %+v", fc)
	}
	if v := run(f, get("/page", sess)); v.Detail != "login" {
		t.Fatal("the session survived a front channel logout")
	}

	// And the ways it can be wrong.
	cases := []struct {
		name   string
		req    *http.Request
		detail string
	}{
		{"no sid", get("/oauth2/frontchannel-logout"), "frontchannel_sid"},
		{"long sid", get("/oauth2/frontchannel-logout?sid=" + strings.Repeat("a", 300)), "frontchannel_sid"},
		{"wrong issuer", get("/oauth2/frontchannel-logout?sid=x&iss=https://evil.test"), "frontchannel_issuer"},
		{"post", func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/oauth2/frontchannel-logout?sid=x", nil)
			r.Host = "app.test"
			return r
		}(), "frontchannel_method"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(f, tc.req); got.Detail != tc.detail {
				t.Fatalf("got %q want %q", got.Detail, tc.detail)
			}
		})
	}
}

// TestFrontChannelLogoutIsRateLimited covers the flood: the endpoint is
// unauthenticated by design and writes to a bounded table, so anyone
// who can reach it could otherwise fill it.
func TestFrontChannelLogoutIsRateLimited(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	limited := false
	for i := 0; i < 100; i++ {
		v := run(f, get(fmt.Sprintf("/oauth2/frontchannel-logout?sid=s%d", i)))
		if v.Status == http.StatusTooManyRequests {
			if v.Headers["Retry-After"] == "" {
				t.Fatal("a rate limited response has no Retry-After")
			}
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("the front channel endpoint never rate limited a flood from one address")
	}
}

// TestSessionRejections covers the cookies that must not be a session.
func TestSessionRejections(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	v := completeLogin(t, f, o, "/page")
	good := setCookie(t, v, "XPOIDC")

	cases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"garbage", "not-a-cookie"},
		{"truncated", good.Value[:len(good.Value)/2]},
		{"flipped byte", flip(good.Value)},
		{"oversize", strings.Repeat("a", maxCookie+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := get("/page", &http.Cookie{Name: "XPOIDC", Value: tc.value})
			if got := run(f, r); got.Detail != "login" {
				t.Fatalf("%s was accepted as a session (%q)", tc.name, got.Detail)
			}
		})
	}
}

// flip changes one character of a sealed cookie.
func flip(s string) string {
	b := []byte(s)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// TestProviderFailures covers a provider that is down, slow to agree
// with itself, or answering nonsense. Each must fail closed with a
// distinct detail rather than letting the request through.
func TestProviderFailures(t *testing.T) {
	t.Run("discovery down", func(t *testing.T) {
		o := newOP(t)
		o.discCode.Store(http.StatusInternalServerError)
		f := build(t, o, nil)
		v := run(f, get("/page"))
		if v.Status != http.StatusServiceUnavailable || v.Detail != "provider_unavailable" {
			t.Fatalf("got %d %q", v.Status, v.Detail)
		}
		if v.Headers["Retry-After"] == "" {
			t.Fatal("no Retry-After on an unavailable provider")
		}
	})
	t.Run("discovery is not json", func(t *testing.T) {
		o := newOP(t)
		o.discBody.Store("<html>not json</html>")
		f := build(t, o, nil)
		if v := run(f, get("/page")); v.Detail != "provider_unavailable" {
			t.Fatalf("got %q", v.Detail)
		}
	})
	t.Run("discovery lacks endpoints", func(t *testing.T) {
		o := newOP(t)
		o.discBody.Store(`{"issuer":"x"}`)
		f := build(t, o, nil)
		if v := run(f, get("/page")); v.Detail != "provider_unavailable" {
			t.Fatalf("got %q", v.Detail)
		}
	})
	t.Run("issuer mismatch", func(t *testing.T) {
		o := newOP(t)
		o.badIssuer.Store(true)
		f := build(t, o, nil)
		if v := run(f, get("/page")); v.Detail != "provider_unavailable" {
			t.Fatalf("a provider claiming another issuer was accepted: %q", v.Detail)
		}
	})
	t.Run("token endpoint refuses", func(t *testing.T) {
		o := newOP(t)
		f := build(t, o, nil)
		o.tokenCode.Store(http.StatusUnauthorized)
		if v := completeLogin(t, f, o, "/page"); v.Detail != "exchange" {
			t.Fatalf("got %q", v.Detail)
		}
	})
	t.Run("token response is not json", func(t *testing.T) {
		o := newOP(t)
		f := build(t, o, nil)
		o.tokenBody.Store("nonsense")
		if v := completeLogin(t, f, o, "/page"); v.Detail != "exchange" {
			t.Fatalf("got %q", v.Detail)
		}
	})
	t.Run("token response has no id_token", func(t *testing.T) {
		o := newOP(t)
		f := build(t, o, nil)
		o.tokenBody.Store(`{"access_token":"at"}`)
		if v := completeLogin(t, f, o, "/page"); v.Detail != "exchange" {
			t.Fatalf("got %q", v.Detail)
		}
	})
	t.Run("id token is not a token", func(t *testing.T) {
		o := newOP(t)
		f := build(t, o, nil)
		o.tokenBody.Store(`{"id_token":"not.a.jwt"}`)
		if v := completeLogin(t, f, o, "/page"); v.Detail != "id_token" {
			t.Fatalf("got %q", v.Detail)
		}
	})
	t.Run("id token is enormous", func(t *testing.T) {
		o := newOP(t)
		f := build(t, o, nil)
		o.tokenBody.Store(`{"id_token":"` + strings.Repeat("a", 200000) + `"}`)
		if v := completeLogin(t, f, o, "/page"); v.Detail != "exchange" {
			t.Fatalf("got %q", v.Detail)
		}
	})
}

// TestDiscoveryBacksOff requires a failed discovery not to be retried
// on every request: a provider that is down would otherwise turn each
// arriving request into an outbound one.
func TestDiscoveryBacksOff(t *testing.T) {
	o := newOP(t)
	o.discCode.Store(http.StatusInternalServerError)
	f := build(t, o, nil)
	var hits atomic.Int64
	o.srv.Config.Handler = countingHandler(o.srv.Config.Handler, &hits)
	for i := 0; i < 20; i++ {
		run(f, get("/page"))
	}
	if n := hits.Load(); n > 1 {
		t.Fatalf("a down provider was asked %d times for 20 requests", n)
	}
}

func countingHandler(h http.Handler, n *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h.ServeHTTP(w, r)
	})
}

// TestTokenAuthPost covers the other client authentication method: the
// secret in the form rather than in the Authorization header.
func TestTokenAuthPost(t *testing.T) {
	o := newOP(t)
	f := build(t, o, filter.Options{"token_auth": "post"})
	if v := completeLogin(t, f, o, "/page"); v.Detail != "login_complete" {
		t.Fatalf("token_auth post: %+v", v)
	}
}

// TestConcurrentRequests runs the filter from many goroutines: one
// filter serves every request on its route, and its revocation tables,
// discovery and rate limiter are all shared.
func TestConcurrentRequests(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	v := completeLogin(t, f, o, "/page")
	sess := setCookie(t, v, "XPOIDC")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				switch i % 4 {
				case 0:
					run(f, get("/page", sess))
				case 1:
					run(f, get("/page"))
				case 2:
					run(f, get(fmt.Sprintf("/oauth2/frontchannel-logout?sid=s%d-%d", i, j)))
				case 3:
					run(f, get("/page", &http.Cookie{Name: "XPOIDC", Value: "junk"}))
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestStatus reports what the management view shows.
func TestStatus(t *testing.T) {
	o := newOP(t)
	f := build(t, o, nil)
	completeLogin(t, f, o, "/page")
	st := f.Status()
	if st.Logins == 0 || st.Callbacks == 0 {
		t.Fatalf("status counts nothing after a login: %+v", st)
	}
}

// TestRegisteredKind builds the filter the way the data plane does,
// through the registry, so the registration's own wiring (validation,
// construction, the event bus) is covered too.
func TestRegisteredKind(t *testing.T) {
	o := newOP(t)
	dir := t.TempDir()
	cs := filepath.Join(dir, "client.secret")
	if err := os.WriteFile(cs, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, ok := filter.Lookup("oidc")
	if !ok {
		t.Fatal("the oidc kind is not registered")
	}
	opts := filter.Options{
		"issuer": o.srv.URL, "allow_http": true, "client_id": "xproxy",
		"client_secret_file": cs, "cookie_secret_file": filepath.Join(dir, "cookie.key"),
	}
	if err := k.Validate(opts); err != nil {
		t.Fatal(err)
	}
	if err := k.Validate(filter.Options{"issuer": ""}); err == nil {
		t.Fatal("an empty configuration validated")
	}
	bus := &fakeBus{}
	f, err := k.New("sso", opts, filter.Env{Log: slog.New(slog.DiscardHandler), Events: bus})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.(interface{ Close() error }).Close() }()
	if f.Name() != "sso" {
		t.Fatalf("name %q", f.Name())
	}
	in := f.Begin(context.Background(), info())
	r := get("/page")
	if v := in.Request(r); v.Detail != "login" {
		t.Fatalf("an unauthenticated request through the registry gave %+v", v)
	}
	// The response phase never has an opinion, and End carries the
	// identity into the access log once there is one.
	if v := in.Response(&http.Response{StatusCode: 200, Header: http.Header{}}); v.Deny {
		t.Fatal("the response phase denied")
	}
	if attrs := in.End(); len(attrs) != 0 {
		t.Fatalf("an anonymous request logged %v", attrs)
	}
	// Construction must refuse a broken cookie secret rather than
	// starting with one nobody can decrypt.
	bad := filepath.Join(dir, "sub", "cookie.key")
	if _, err := k.New("sso", filter.Options{
		"issuer": o.srv.URL, "allow_http": true, "client_id": "xproxy",
		"client_secret_file": cs, "cookie_secret_file": bad,
	}, filter.Env{Log: slog.New(slog.DiscardHandler)}); err == nil {
		t.Fatal("a cookie secret in a missing directory was accepted")
	}
	// And a ca_file that holds no certificate.
	pem := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(pem, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := k.New("sso", filter.Options{
		"issuer": o.srv.URL, "allow_http": true, "client_id": "xproxy",
		"client_secret_file": cs, "cookie_secret_file": filepath.Join(dir, "k2"), "ca_file": pem,
	}, filter.Env{Log: slog.New(slog.DiscardHandler)}); err == nil {
		t.Fatal("a ca_file with no certificates was accepted")
	}
}

// TestEndCarriesTheIdentity covers the access log attributes of a
// logged in request, including the claims named by log_claims.
func TestEndCarriesTheIdentity(t *testing.T) {
	o := newOP(t)
	f := build(t, o, filter.Options{"log_claims": []any{"email"}})
	v := completeLogin(t, f, o, "/page")
	sess := setCookie(t, v, "XPOIDC")
	in := f.Begin(context.Background(), info()).(*instance)
	if got := in.Request(get("/page", sess)); got.Deny {
		t.Fatalf("denied: %+v", got)
	}
	attrs := fmt.Sprint(in.End())
	if !strings.Contains(attrs, "oidc_user") || !strings.Contains(attrs, "alice") ||
		!strings.Contains(attrs, "oidc_email") {
		t.Fatalf("the access log attributes are %s", attrs)
	}
}
