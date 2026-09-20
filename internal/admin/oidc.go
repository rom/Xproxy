package admin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/jwt"
)

// OIDCOptions enable login through an OpenID Connect provider besides
// passwords and client certificates. The authorization code flow with
// PKCE and a nonce is used; the ID token names the user and its role
// comes from a claim.
type OIDCOptions struct {
	// Issuer is the provider's issuer URL (https); discovery is read
	// from its well-known document. Empty disables OIDC login.
	Issuer string
	// ClientID and ClientSecretFile identify the GUI at the provider.
	ClientID         string
	ClientSecretFile string
	// ExternalURL is the address users reach the GUI at, for the
	// redirect URI (https://admin.example.com); empty derives it from the
	// request.
	ExternalURL string
	// CAFile pins the CA of the provider; empty uses the system pool.
	CAFile string
	// Scopes requested. Default openid, profile, email.
	Scopes []string
	// UserClaim names the user: default email, then preferred_username,
	// then sub.
	UserClaim string
	// RoleClaim holds the values matched against Operators and Viewers
	// (a string or a list). Default groups.
	RoleClaim string
	// Operators and Viewers are claim values that grant a role; a
	// Viewers entry "*" accepts every authenticated user as a viewer.
	// Without a match the login is refused.
	Operators []string
	Viewers   []string
}

// Enabled reports whether OIDC login is configured.
func (o *OIDCOptions) Enabled() bool { return o != nil && o.Issuer != "" }

const (
	oidcStateCookie = "xproxy_admin_oidc"
	oidcStateTTL    = 10 * time.Minute
	oidcLoginPath   = "/api/oidc/login"
	oidcCallback    = "/api/oidc/callback"
)

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// oidcLogin is the server side of the flow.
type oidcLogin struct {
	o      OIDCOptions
	secret string
	client *http.Client
	aead   cipher.AEAD // sealing the state cookie under a per-process key
	log    *slog.Logger

	mu        sync.Mutex
	disc      *oidcDiscovery
	verifier  *jwt.Provider
	discTried time.Time
}

type oidcState struct {
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Exp      int64  `json:"e"`
}

func newOIDCLogin(o OIDCOptions, log *slog.Logger) (*oidcLogin, error) {
	u, err := url.Parse(o.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("oidc issuer must be an https URL")
	}
	if o.ClientID == "" || o.ClientSecretFile == "" {
		return nil, errors.New("oidc client id and client secret file are required")
	}
	if len(o.Operators) == 0 && len(o.Viewers) == 0 {
		return nil, errors.New("oidc needs at least one operator or viewer claim value")
	}
	secret, err := os.ReadFile(o.ClientSecretFile) //nolint:gosec // operator supplied path
	if err != nil {
		return nil, fmt.Errorf("oidc client secret: %w", err)
	}
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "profile", "email"}
	}
	if o.UserClaim == "" {
		o.UserClaim = "email"
	}
	if o.RoleClaim == "" {
		o.RoleClaim = "groups"
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile) //nolint:gosec // operator supplied path
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("oidc ca file contains no certificates")
		}
		tc.RootCAs = pool
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	l := &oidcLogin{o: o, secret: strings.TrimSpace(string(secret)), aead: aead, log: log,
		client: &http.Client{
			Timeout:       10 * time.Second,
			Transport:     &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 4, ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") },
		}}
	if _, err := l.discover(context.Background()); err != nil {
		log.Warn("oidc discovery failed at start; will retry", "issuer", o.Issuer, "err", err.Error())
	}
	return l, nil
}

// discover reads the provider metadata once and builds the ID token
// verifier; failures are retried at most every ten seconds.
func (l *oidcLogin) discover(ctx context.Context) (*oidcDiscovery, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.disc != nil {
		return l.disc, nil
	}
	if time.Since(l.discTried) < 10*time.Second {
		return nil, errors.New("provider metadata unavailable")
	}
	l.discTried = time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(l.o.Issuer, "/")+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: HTTP %d", resp.StatusCode)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&d); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, errors.New("discovery: metadata lacks authorization_endpoint, token_endpoint or jwks_uri")
	}
	if strings.TrimSuffix(d.Issuer, "/") != strings.TrimSuffix(l.o.Issuer, "/") {
		return nil, fmt.Errorf("discovery: issuer %q does not match %q", d.Issuer, l.o.Issuer)
	}
	p, err := jwt.NewProvider(config.JWTProvider{
		Name: "admin-oidc", Issuer: d.Issuer, Audiences: []string{l.o.ClientID},
		Algorithms: []string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA"},
		JWKSURL:    d.JWKSURI, JWKSCAFile: l.o.CAFile, JWKSRefresh: config.Duration(time.Hour), ClockSkew: config.Duration(30 * time.Second),
		RequiredClaims: []string{"sub", "iat"},
	}, l.log)
	if err != nil {
		return nil, err
	}
	p.Start()
	if l.verifier != nil {
		l.verifier.Stop()
	}
	l.verifier, l.disc = p, &d
	return &d, nil
}

func (l *oidcLogin) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.verifier != nil {
		l.verifier.Stop()
	}
}

// redirectURI is the callback address registered at the provider.
func (s *Server) oidcRedirectURI(r *http.Request) string {
	if s.oidc.o.ExternalURL != "" {
		return strings.TrimSuffix(s.oidc.o.ExternalURL, "/") + oidcCallback
	}
	scheme := "http"
	if s.tlsOn || r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + oidcCallback
}

// authMethods tells the GUI which logins are available.
func (s *Server) authMethods(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"password": true, "oidc": s.oidc != nil}
	if s.oidc != nil {
		if u, err := url.Parse(s.oidc.o.Issuer); err == nil {
			out["oidc_issuer"] = u.Host
		}
	}
	writeJSON(w, 200, out)
}

// oidcStart sends the browser to the provider.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	l := s.oidc
	d, err := l.discover(r.Context())
	if err != nil {
		s.log.Warn("oidc login: provider unavailable", "err", err.Error())
		http.Redirect(w, r, "/?sso_error=provider_unavailable", http.StatusFound)
		return
	}
	nonce, verifier := randomToken(), randomToken()
	sealed, err := l.seal(oidcState{Nonce: nonce, Verifier: verifier, Exp: time.Now().Add(oidcStateTTL).Unix()})
	if err != nil {
		http.Redirect(w, r, "/?sso_error=internal", http.StatusFound)
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {l.o.ClientID},
		"redirect_uri":          {s.oidcRedirectURI(r)},
		"scope":                 {strings.Join(l.o.Scopes, " ")},
		"state":                 {stateParam(sealed)},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	loc := d.AuthorizationEndpoint
	if strings.Contains(loc, "?") {
		loc += "&" + q.Encode()
	} else {
		loc += "?" + q.Encode()
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: sealed, Path: "/api/oidc", MaxAge: int(oidcStateTTL.Seconds()), HttpOnly: true, Secure: s.tlsOn, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, loc, http.StatusFound)
}

// oidcFinish exchanges the code, verifies the ID token, maps the role
// and opens a session.
func (s *Server) oidcFinish(w http.ResponseWriter, r *http.Request) {
	l := s.oidc
	fail := func(reason string, kv ...any) {
		s.log.Warn("oidc login failed", append([]any{"reason", reason, "source", sourceOf(r)}, kv...)...)
		http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/oidc", MaxAge: -1, HttpOnly: true, Secure: s.tlsOn, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/?sso_error="+url.QueryEscape(reason), http.StatusFound)
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail("provider:" + sanitizeParam(e))
		return
	}
	code, state := q.Get("code"), q.Get("state")
	sc, err := r.Cookie(oidcStateCookie)
	if err != nil || code == "" || state == "" || len(sc.Value) > 4096 {
		fail("state_missing")
		return
	}
	if state != stateParam(sc.Value) {
		fail("state_mismatch")
		return
	}
	var st oidcState
	if err := l.open(sc.Value, &st); err != nil || st.Exp < time.Now().Unix() {
		fail("state_invalid")
		return
	}
	d, err := l.discover(r.Context())
	if err != nil {
		fail("provider_unavailable")
		return
	}
	idToken, err := l.exchange(r.Context(), d, code, st.Verifier, s.oidcRedirectURI(r))
	if err != nil {
		fail("exchange", "err", err.Error())
		return
	}
	l.mu.Lock()
	p := l.verifier
	l.mu.Unlock()
	claims, err := p.Verify(idToken)
	if err != nil {
		fail("id_token", "err", err.Error())
		return
	}
	if n, _ := claims["nonce"].(string); n != st.Nonce {
		fail("nonce")
		return
	}
	if err := jwt.CheckAuthorizedParty(claims, l.o.ClientID); err != nil {
		fail("azp", "err", err.Error())
		return
	}
	user := ""
	for _, c := range []string{l.o.UserClaim, "preferred_username", "sub"} {
		if v, ok := claims[c].(string); ok && v != "" {
			user = v
			break
		}
	}
	if user == "" || len(user) > 256 {
		fail("no_user")
		return
	}
	role, ok := l.role(claims)
	if !ok {
		fail("role", "user", user)
		return
	}
	tok, err := s.sessions.create(user, role, "oidc")
	if err != nil {
		fail("session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/oidc", MaxAge: -1, HttpOnly: true, Secure: s.tlsOn, SameSite: http.SameSiteLaxMode})
	s.setCookie(w, tok, int(s.o.SessionMax.Seconds()))
	sess, _ := s.sessions.get(tok)
	s.audit(r, sess, "login")
	http.Redirect(w, r, "/", http.StatusFound)
}

// role maps the role claim to operator or viewer.
func (l *oidcLogin) role(claims jwt.Claims) (Role, bool) {
	var values []string
	switch v := claims[l.o.RoleClaim].(type) {
	case string:
		// A string claim is one value; splitting it on separators would let
		// "foo admins" satisfy an entry "admins".
		values = []string{v}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				values = append(values, s)
			}
		}
	}
	has := func(want []string) bool {
		for _, w := range want {
			for _, v := range values {
				if v == w {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has(l.o.Operators):
		return RoleOperator, true
	case has(l.o.Viewers):
		return RoleViewer, true
	}
	for _, v := range l.o.Viewers {
		if v == "*" {
			return RoleViewer, true
		}
	}
	return "", false
}

// exchange posts the code to the token endpoint and returns the ID token.
func (l *oidcLogin) exchange(ctx context.Context, d *oidcDiscovery, code, verifier, redirectURI string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(l.o.ClientID), url.QueryEscape(l.secret))
	resp, err := l.client.Do(req)
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
		return "", fmt.Errorf("token endpoint: %s", sanitizeParam(tr.Error))
	}
	if tr.IDToken == "" || len(tr.IDToken) > jwt.MaxTokenBytes {
		return "", errors.New("token endpoint: no usable id_token")
	}
	return tr.IDToken, nil
}

func (l *oidcLogin) seal(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, l.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := l.aead.Seal(nonce, nonce, plain, []byte("state"))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func (l *oidcLogin) open(s string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < l.aead.NonceSize() {
		return errors.New("bad state")
	}
	plain, err := l.aead.Open(nil, raw[:l.aead.NonceSize()], raw[l.aead.NonceSize():], []byte("state"))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

// stateParam binds the state parameter to the cookie: a prefix of the
// sealed value and its digest.
func stateParam(sealed string) string {
	sum := sha256.Sum256([]byte(sealed))
	return sealed[:min(len(sealed), 64)] + "." + hex.EncodeToString(sum[:16])
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sanitizeParam(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= 40 {
			break
		}
	}
	return b.String()
}
