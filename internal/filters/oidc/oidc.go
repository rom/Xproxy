// Package oidc is a built-in filter kind that logs browsers in with
// OpenID Connect (authorization code flow with PKCE) and keeps the
// result in an encrypted session cookie. Unauthenticated requests are
// redirected to the provider; the callback exchanges the code, verifies
// the ID token against the provider's JWKS and sets the cookie; later
// requests carry selected claims to the upstream as headers.
//
//	filters:
//	  - name: sso
//	    kind: oidc
//	    options:
//	      issuer: https://login.example.com
//	      client_id: xproxy
//	      client_secret_file: /etc/xproxy/oidc.secret
//	      cookie_secret_file: /etc/xproxy/oidc.cookie   # 32+ bytes, created 0600 if absent
//	      scopes: [openid, email]
//	      forward_headers: {X-Remote-User: sub, X-Remote-Email: email}
//	      require_claims: {hd: example.com}
package oidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/jwt"
)

// Config is the options schema.
type Config struct {
	Issuer           string            `json:"issuer"`
	ClientID         string            `json:"client_id"`
	ClientSecretFile string            `json:"client_secret_file"`
	CookieSecretFile string            `json:"cookie_secret_file"`
	Scopes           []string          `json:"scopes"`
	RedirectPath     string            `json:"redirect_path"`
	LogoutPath       string            `json:"logout_path"`
	LogoutRedirect   string            `json:"logout_redirect"`
	ExternalURL      string            `json:"external_url"`
	CookieName       string            `json:"cookie_name"`
	CookieDomain     string            `json:"cookie_domain"`
	SessionTTL       string            `json:"session_ttl"`
	ForwardHeaders   map[string]string `json:"forward_headers"`
	RequireClaims    map[string]string `json:"require_claims"`
	LogClaims        []string          `json:"log_claims"`
	CAFile           string            `json:"ca_file"`
	AllowHTTP        bool              `json:"allow_http"`
	TokenAuth        string            `json:"token_auth"`
	ttl              time.Duration
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	u, err := url.Parse(c.Issuer)
	switch {
	case c.Issuer == "":
		errs = append(errs, errors.New("issuer is required"))
	case err != nil || u.Host == "" || !schemeOK(u.Scheme, c.AllowHTTP):
		errs = append(errs, errors.New("issuer must be an https URL (http only with allow_http)"))
	}
	if c.ClientID == "" {
		errs = append(errs, errors.New("client_id is required"))
	}
	if c.ClientSecretFile == "" {
		errs = append(errs, errors.New("client_secret_file is required"))
	} else if st, err := os.Stat(c.ClientSecretFile); err != nil {
		errs = append(errs, fmt.Errorf("client_secret_file: %w", err))
	} else if st.Mode().Perm()&0o004 != 0 {
		errs = append(errs, fmt.Errorf("client_secret_file: %s must not be world readable", c.ClientSecretFile))
	}
	if c.CookieSecretFile == "" {
		errs = append(errs, errors.New("cookie_secret_file is required"))
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid"}
	}
	hasOpenID := false
	for _, s := range c.Scopes {
		if s == "openid" {
			hasOpenID = true
		}
		if strings.ContainsAny(s, " \r\n\"") {
			errs = append(errs, fmt.Errorf("scopes: %q is not a scope", s))
		}
	}
	if !hasOpenID {
		errs = append(errs, errors.New("scopes must include openid"))
	}
	if c.RedirectPath == "" {
		c.RedirectPath = "/oauth2/callback"
	}
	if c.LogoutPath == "" {
		c.LogoutPath = "/oauth2/logout"
	}
	for _, p := range []string{c.RedirectPath, c.LogoutPath} {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
			errs = append(errs, fmt.Errorf("%q is not a path", p))
		}
	}
	if c.RedirectPath == c.LogoutPath {
		errs = append(errs, errors.New("redirect_path and logout_path must differ"))
	}
	if c.LogoutRedirect == "" {
		c.LogoutRedirect = "/"
	}
	if c.ExternalURL != "" {
		eu, err := url.Parse(c.ExternalURL)
		if err != nil || eu.Host == "" || !schemeOK(eu.Scheme, c.AllowHTTP) || eu.Path != "" || eu.RawQuery != "" {
			errs = append(errs, errors.New("external_url must be scheme://host with no path"))
		}
	}
	if c.CookieName == "" {
		c.CookieName = "XPOIDC"
	}
	if strings.ContainsAny(c.CookieName, " ;=\r\n") {
		errs = append(errs, errors.New("cookie_name is not a cookie name"))
	}
	c.ttl = 8 * time.Hour
	if c.SessionTTL != "" {
		d, err := time.ParseDuration(c.SessionTTL)
		if err != nil || d < time.Minute || d > 30*24*time.Hour {
			errs = append(errs, errors.New("session_ttl: must be a duration between 1m and 720h"))
		} else {
			c.ttl = d
		}
	}
	for h, claim := range c.ForwardHeaders {
		if h == "" || strings.ContainsAny(h, " :\r\n") || claim == "" {
			errs = append(errs, fmt.Errorf("forward_headers: %q: %q is not a header and claim pair", h, claim))
		}
	}
	for claim := range c.RequireClaims {
		if claim == "" {
			errs = append(errs, errors.New("require_claims: empty claim name"))
		}
	}
	if c.CAFile != "" {
		if _, err := os.Stat(c.CAFile); err != nil {
			errs = append(errs, fmt.Errorf("ca_file: %w", err))
		}
	}
	switch c.TokenAuth {
	case "":
		c.TokenAuth = "basic"
	case "basic", "post":
	default:
		errs = append(errs, errors.New("token_auth must be basic or post"))
	}
	return &c, errors.Join(errs...)
}

func schemeOK(scheme string, allowHTTP bool) bool {
	return scheme == "https" || (scheme == "http" && allowHTTP)
}

// discovery is the subset of the provider metadata the filter uses.
type discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	Issuer                string `json:"issuer"`
}

type oidcFilter struct {
	name   string
	cfg    *Config
	log    *slog.Logger
	secret []byte
	aead   cipher.AEAD
	client *http.Client

	discMu    sync.Mutex
	disc      atomic.Pointer[discovery]
	discTried time.Time
	verifier  atomic.Pointer[jwt.Provider]

	// counters
	Logins, Callbacks, Failures atomic.Uint64
}

func newFilter(name string, c *Config, log *slog.Logger) (*oidcFilter, error) {
	secret, err := os.ReadFile(c.ClientSecretFile) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(c.CookieSecretFile)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file contains no certificates")
		}
		tc.RootCAs = pool
	}
	f := &oidcFilter{name: name, cfg: c, log: log, secret: []byte(strings.TrimSpace(string(secret))), aead: aead,
		client: &http.Client{
			Timeout:       10 * time.Second,
			Transport:     &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 4, ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") },
		}}
	if _, err := f.discover(context.Background()); err != nil {
		log.Warn("oidc discovery failed at load; will retry", "issuer", c.Issuer, "err", err.Error())
	}
	return f, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // operator configured path
		if len(b) < 32 {
			return nil, fmt.Errorf("cookie secret %s is shorter than 32 bytes", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read cookie secret: %w", err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return nil, fmt.Errorf("create cookie secret: %w", err)
	}
	return k, nil
}

// discover fetches the provider metadata once and builds the ID token
// verifier; failures are retried at most every ten seconds.
func (f *oidcFilter) discover(ctx context.Context) (*discovery, error) {
	if d := f.disc.Load(); d != nil {
		return d, nil
	}
	f.discMu.Lock()
	defer f.discMu.Unlock()
	if d := f.disc.Load(); d != nil {
		return d, nil
	}
	if time.Since(f.discTried) < 10*time.Second {
		return nil, errors.New("provider metadata unavailable")
	}
	f.discTried = time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(f.cfg.Issuer, "/")+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: HTTP %d", resp.StatusCode)
	}
	var d discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&d); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, errors.New("discovery: metadata lacks authorization_endpoint, token_endpoint or jwks_uri")
	}
	if strings.TrimSuffix(d.Issuer, "/") != strings.TrimSuffix(f.cfg.Issuer, "/") {
		return nil, fmt.Errorf("discovery: issuer %q does not match %q", d.Issuer, f.cfg.Issuer)
	}
	p, err := jwt.NewProvider(config.JWTProvider{
		Name: f.name, Issuer: d.Issuer, Audiences: []string{f.cfg.ClientID},
		Algorithms: []string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA"},
		JWKSURL:    d.JWKSURI, JWKSCAFile: f.cfg.CAFile, JWKSRefresh: config.Duration(time.Hour), ClockSkew: config.Duration(30 * time.Second),
		RequiredClaims: []string{"sub", "iat"},
	}, f.log)
	if err != nil {
		return nil, err
	}
	p.Start()
	if old := f.verifier.Swap(p); old != nil {
		old.Stop()
	}
	f.disc.Store(&d)
	return &d, nil
}

func (f *oidcFilter) Name() string { return f.name }

func (f *oidcFilter) Begin(_ context.Context, info *filter.Info) filter.Instance {
	return &instance{f: f, info: info}
}

// Close stops the verifier's JWKS refresh.
func (f *oidcFilter) Close() error {
	if p := f.verifier.Load(); p != nil {
		p.Stop()
	}
	return nil
}

type instance struct {
	f    *oidcFilter
	info *filter.Info
	user string
	log  []any
}

// session is the encrypted cookie payload.
type session struct {
	Sub    string         `json:"sub"`
	Exp    int64          `json:"exp"`
	Iat    int64          `json:"iat"`
	Claims map[string]any `json:"c,omitempty"`
}

// loginState is the short lived state cookie of a login in progress.
type loginState struct {
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Exp      int64  `json:"e"`
}

const (
	stateSuffix = "_state"
	stateTTL    = 10 * time.Minute
	maxCookie   = 4096
)

func (in *instance) Request(r *http.Request) filter.Verdict {
	f := in.f
	for h := range f.cfg.ForwardHeaders {
		r.Header.Del(h) // never trust a client supplied identity header
	}
	switch r.URL.Path {
	case f.cfg.RedirectPath:
		return f.callback(r, in)
	case f.cfg.LogoutPath:
		return f.logout(r, in)
	}
	if s, ok := f.session(r); ok {
		in.user = s.Sub
		for h, claim := range f.cfg.ForwardHeaders {
			if v, ok := s.Claims[claim]; ok {
				r.Header.Set(h, claimString(v))
			}
		}
		for _, claim := range f.cfg.LogClaims {
			if v, ok := s.Claims[claim]; ok {
				in.log = append(in.log, "oidc_"+claim, claimString(v))
			}
		}
		f.stripCookies(r)
		return filter.Continue
	}
	return f.login(r, in)
}

func claimString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%.0f", x)
	case bool:
		return fmt.Sprint(x)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// session decodes and checks the session cookie.
func (f *oidcFilter) session(r *http.Request) (*session, bool) {
	c, err := r.Cookie(f.cfg.CookieName)
	if err != nil || len(c.Value) > maxCookie {
		return nil, false
	}
	var s session
	if err := f.open(c.Value, "session", &s); err != nil {
		return nil, false
	}
	now := time.Now().Unix()
	if s.Sub == "" || s.Exp <= now || s.Iat > now+60 {
		return nil, false
	}
	return &s, true
}

// login starts the authorization code flow with PKCE and a nonce.
func (f *oidcFilter) login(r *http.Request, in *instance) filter.Verdict {
	f.Logins.Add(1)
	d, err := f.discover(r.Context())
	if err != nil {
		f.Failures.Add(1)
		return filter.Verdict{Deny: true, Status: http.StatusServiceUnavailable, Reason: f.name, Detail: "provider_unavailable", Headers: map[string]string{"Retry-After": "10"}}
	}
	nonce, verifier := randomToken(), randomToken()
	ret := r.URL.RequestURI()
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") || len(ret) > 2048 {
		ret = "/"
	}
	st, err := f.seal(loginState{Nonce: nonce, Verifier: verifier, Return: ret, Exp: time.Now().Add(stateTTL).Unix()}, "state")
	if err != nil {
		f.Failures.Add(1)
		return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: f.name, Detail: "seal"}
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.cfg.ClientID},
		"redirect_uri":          {f.redirectURI(r, in.info)},
		"scope":                 {strings.Join(f.cfg.Scopes, " ")},
		"state":                 {st[:min(len(st), 64)] + "." + stateDigest(st)},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sha256Bytes(verifier))},
		"code_challenge_method": {"S256"},
	}
	loc := d.AuthorizationEndpoint
	if strings.Contains(loc, "?") {
		loc += "&" + q.Encode()
	} else {
		loc += "?" + q.Encode()
	}
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{}}
	resp.Header.Set("Location", loc)
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName+stateSuffix, st, int(stateTTL.Seconds()), f.secure(r, in.info)).String())
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusFound, Reason: f.name, Detail: "login", Response: resp}
}

// callback exchanges the code for tokens and sets the session cookie.
func (f *oidcFilter) callback(r *http.Request, in *instance) filter.Verdict {
	f.Callbacks.Add(1)
	fail := func(status int, detail string) filter.Verdict {
		f.Failures.Add(1)
		return filter.Verdict{Deny: true, Status: status, Reason: f.name, Detail: detail}
	}
	if r.Method != http.MethodGet {
		return fail(http.StatusMethodNotAllowed, "callback_method")
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return fail(http.StatusUnauthorized, "provider_error:"+sanitize(e))
	}
	code, state := q.Get("code"), q.Get("state")
	sc, err := r.Cookie(f.cfg.CookieName + stateSuffix)
	if err != nil || code == "" || state == "" || len(sc.Value) > maxCookie {
		return fail(http.StatusBadRequest, "state_missing")
	}
	if state != sc.Value[:min(len(sc.Value), 64)]+"."+stateDigest(sc.Value) {
		return fail(http.StatusBadRequest, "state_mismatch")
	}
	var ls loginState
	if err := f.open(sc.Value, "state", &ls); err != nil || ls.Exp < time.Now().Unix() {
		return fail(http.StatusBadRequest, "state_invalid")
	}
	d, err := f.discover(r.Context())
	if err != nil {
		return fail(http.StatusServiceUnavailable, "provider_unavailable")
	}
	idToken, err := f.exchange(r.Context(), d, code, ls.Verifier, f.redirectURI(r, in.info))
	if err != nil {
		f.log.Warn("oidc token exchange failed", "err", err.Error())
		return fail(http.StatusUnauthorized, "exchange")
	}
	p := f.verifier.Load()
	if p == nil {
		return fail(http.StatusServiceUnavailable, "provider_unavailable")
	}
	claims, err := p.Verify(idToken)
	if err != nil {
		f.log.Warn("oidc id token rejected", "err", err.Error())
		return fail(http.StatusUnauthorized, "id_token")
	}
	if n, _ := claims["nonce"].(string); n != ls.Nonce {
		return fail(http.StatusUnauthorized, "nonce")
	}
	for claim, want := range f.cfg.RequireClaims {
		if got, ok := claims[claim]; !ok || claimString(got) != want {
			f.log.Warn("oidc claim requirement not met", "claim", claim, "sub", claims["sub"])
			return fail(http.StatusForbidden, "claim:"+claim)
		}
	}
	sub, _ := claims["sub"].(string)
	now := time.Now()
	s := session{Sub: sub, Iat: now.Unix(), Exp: now.Add(f.cfg.ttl).Unix(), Claims: map[string]any{"sub": sub}}
	for _, claim := range f.cfg.ForwardHeaders {
		if v, ok := claims[claim]; ok {
			s.Claims[claim] = v
		}
	}
	for _, claim := range f.cfg.LogClaims {
		if v, ok := claims[claim]; ok {
			s.Claims[claim] = v
		}
	}
	sealed, err := f.seal(s, "session")
	if err != nil || len(sealed) > maxCookie {
		return fail(http.StatusInternalServerError, "session_size")
	}
	in.user = sub
	secure := f.secure(r, in.info)
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{}}
	resp.Header.Set("Location", ls.Return)
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName, sealed, int(f.cfg.ttl.Seconds()), secure).String())
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName+stateSuffix, "", -1, secure).String())
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusFound, Reason: f.name, Detail: "login_complete", Response: resp,
		Attrs: []any{"oidc_sub", sub}}
}

// logout clears the session and sends the browser on: to the provider's
// end session endpoint when it has one, else to logout_redirect.
func (f *oidcFilter) logout(r *http.Request, in *instance) filter.Verdict {
	loc := f.cfg.LogoutRedirect
	if d := f.disc.Load(); d != nil && d.EndSessionEndpoint != "" {
		q := url.Values{"client_id": {f.cfg.ClientID}, "post_logout_redirect_uri": {f.base(r, in.info) + f.cfg.LogoutRedirect}}
		loc = d.EndSessionEndpoint + "?" + q.Encode()
	}
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{}}
	resp.Header.Set("Location", loc)
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName, "", -1, f.secure(r, in.info)).String())
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusFound, Reason: f.name, Detail: "logout", Response: resp}
}

// exchange posts the code to the token endpoint and returns the ID token.
func (f *oidcFilter) exchange(ctx context.Context, d *discovery, code, verifier, redirectURI string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	if f.cfg.TokenAuth == "post" {
		form.Set("client_id", f.cfg.ClientID)
		form.Set("client_secret", string(f.secret))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if f.cfg.TokenAuth == "basic" {
		req.SetBasicAuth(url.QueryEscape(f.cfg.ClientID), url.QueryEscape(string(f.secret)))
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
	}
	var tr struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("token endpoint: %s", sanitize(tr.Error))
	}
	if tr.IDToken == "" || len(tr.IDToken) > jwt.MaxTokenBytes {
		return "", errors.New("token endpoint: no usable id_token")
	}
	return tr.IDToken, nil
}

func (f *oidcFilter) base(r *http.Request, info *filter.Info) string {
	if f.cfg.ExternalURL != "" {
		return f.cfg.ExternalURL
	}
	scheme := "http"
	if f.secure(r, info) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (f *oidcFilter) redirectURI(r *http.Request, info *filter.Info) string {
	return f.base(r, info) + f.cfg.RedirectPath
}

func (f *oidcFilter) secure(r *http.Request, info *filter.Info) bool {
	if f.cfg.ExternalURL != "" {
		return strings.HasPrefix(f.cfg.ExternalURL, "https://")
	}
	return info.TLS || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (f *oidcFilter) cookie(name, value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", Domain: f.cfg.CookieDomain, MaxAge: maxAge,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
}

// stripCookies removes the filter's cookies from the forwarded request.
func (f *oidcFilter) stripCookies(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == f.cfg.CookieName || c.Name == f.cfg.CookieName+stateSuffix {
			continue
		}
		r.AddCookie(c)
	}
}

// seal encrypts v with the cookie key; purpose binds the ciphertext to
// its use so a state cookie can never be replayed as a session.
func (f *oidcFilter) seal(v any, purpose string) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := f.aead.Seal(nonce, nonce, plain, []byte(purpose))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func (f *oidcFilter) open(s, purpose string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < f.aead.NonceSize() {
		return errors.New("bad cookie")
	}
	ns := f.aead.NonceSize()
	plain, err := f.aead.Open(nil, raw[:ns], raw[ns:], []byte(purpose))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Bytes(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// stateDigest binds the state parameter to the state cookie without
// sending the whole ciphertext through the provider.
func stateDigest(cookie string) string {
	return base64.RawURLEncoding.EncodeToString(sha256Bytes(cookie))[:22]
}

func sanitize(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any {
	if in.user != "" {
		return append([]any{"oidc_user", in.user}, in.log...)
	}
	return in.log
}

// Status is the management view.
type Status struct {
	Issuer     string `json:"issuer"`
	Discovered bool   `json:"discovered"`
	Keys       int    `json:"keys"`
	Logins     uint64 `json:"logins"`
	Callbacks  uint64 `json:"callbacks"`
	Failures   uint64 `json:"failures"`
}

// Status reports discovery state and counters.
func (f *oidcFilter) Status() Status {
	st := Status{Issuer: f.cfg.Issuer, Discovered: f.disc.Load() != nil, Logins: f.Logins.Load(), Callbacks: f.Callbacks.Load(), Failures: f.Failures.Load()}
	if p := f.verifier.Load(); p != nil {
		st.Keys = p.KeyCount()
	}
	return st
}

func init() {
	filter.Register(filter.Kind{
		Name:        "oidc",
		Description: "OpenID Connect login (authorization code with PKCE) with an encrypted session cookie.",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return newFilter(name, c, env.Log)
		},
	})
}
