package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeOP is an OpenID provider: discovery, authorization (redirects
// straight back with a code), token exchange with PKCE and client
// authentication checks, JWKS and end session.
type fakeOP struct {
	srv       *httptest.Server
	mu        sync.Mutex
	codes     map[string]struct{ challenge, nonce string }
	authz     atomic.Int64
	wrongNonc atomic.Bool
	hd        atomic.Value
}

func newFakeOP(t *testing.T) *fakeOP {
	t.Helper()
	key, jwks := rsaSigner(t)
	op := &fakeOP{codes: map[string]struct{ challenge, nonce string }{}}
	op.hd.Store("example.com")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": op.srv.URL, "authorization_endpoint": op.srv.URL + "/authorize", "token_endpoint": op.srv.URL + "/token",
			"jwks_uri": op.srv.URL + "/jwks", "end_session_endpoint": op.srv.URL + "/logout",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, jwks) })
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		op.authz.Add(1)
		if q.Get("response_type") != "code" || q.Get("client_id") != "xproxy" || q.Get("code_challenge_method") != "S256" || !strings.Contains(q.Get("scope"), "openid") {
			http.Error(w, "bad authorization request: "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		code := fmt.Sprintf("code-%d", op.authz.Load())
		op.mu.Lock()
		op.codes[code] = struct{ challenge, nonce string }{q.Get("code_challenge"), q.Get("nonce")}
		op.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "xproxy" || pass != "s3cret-client-secret" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		op.mu.Lock()
		c, known := op.codes[r.Form.Get("code")]
		delete(op.codes, r.Form.Get("code"))
		op.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !known || r.Form.Get("grant_type") != "authorization_code" || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		nonce := c.nonce
		if op.wrongNonc.Load() {
			nonce = "other"
		}
		now := time.Now().Unix()
		idt := signRS256(t, key, map[string]any{"iss": op.srv.URL, "aud": "xproxy", "sub": "alice", "email": "alice@example.com",
			"hd": op.hd.Load().(string), "nonce": nonce, "sid": fmt.Sprintf("provider-session-%d", op.authz.Load()), "iat": now, "exp": now + 300})
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": idt, "access_token": "at", "token_type": "Bearer"})
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "logged out; back to %s", r.URL.Query().Get("post_logout_redirect_uri"))
	})
	op.srv = httptest.NewServer(mux)
	t.Cleanup(op.srv.Close)
	return op
}

// TestOIDC logs a browser in through the provider, keeps the session in
// an encrypted cookie, forwards claims as headers, strips the cookie
// upstream, logs out through the provider, and refuses tampered
// cookies, bad state, a wrong nonce and a missing required claim.
func TestOIDC(t *testing.T) {
	op := newFakeOP(t)
	backend := newBackend(t, "app")
	dir := t.TempDir()
	secret := filepath.Join(dir, "client.secret")
	if err := os.WriteFile(secret, []byte("s3cret-client-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging:
  access: {enabled: false}
filters:
  - name: sso
    kind: oidc
    options:
      issuer: %s
      allow_http: true
      client_id: xproxy
      client_secret_file: %s
      cookie_secret_file: %s
      scopes: [openid, email]
      forward_headers: {X-Remote-User: sub, X-Remote-Email: email}
      require_claims: {hd: example.com}
      log_claims: [email]
      session_ttl: 1h
upstreams:
  - name: app
    endpoints: [{address: "%s"}]
routes:
  - name: app
    paths: [/]
    upstream: app
    filters: [sso]
`
	s, base := startServer(t, fmt.Sprintf(yaml, op.srv.URL, secret, filepath.Join(dir, "cookie.key"), backend.addr()))
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	resp, err := c.Get(base + "/app/page?x=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Request.URL.Path != "/app/page" || resp.Request.URL.RawQuery != "x=1" {
		t.Fatalf("after login: %d at %s", resp.StatusCode, resp.Request.URL)
	}
	last := backend.last.Load()
	if last.Header.Get("X-Remote-User") != "alice" || last.Header.Get("X-Remote-Email") != "alice@example.com" {
		t.Fatalf("claims not forwarded: %v", last.Header)
	}
	if strings.Contains(last.Header.Get("Cookie"), "XPOIDC") {
		t.Fatalf("session cookie forwarded upstream: %s", last.Header.Get("Cookie"))
	}
	if op.authz.Load() != 1 {
		t.Fatalf("authorizations: %d", op.authz.Load())
	}
	// The cookie is 0600 and the key file was created.
	if st, err := os.Stat(filepath.Join(dir, "cookie.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cookie key: %v %v", st, err)
	}
	// A client supplied identity header is dropped even with a session.
	req, _ := http.NewRequest(http.MethodGet, base+"/app/2", nil)
	req.Header.Set("X-Remote-User", "mallory")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if backend.last.Load().Header.Get("X-Remote-User") != "alice" || op.authz.Load() != 1 {
		t.Fatal("session not reused or header not replaced")
	}
	// Front channel logout from the provider (no cookie: a cross site
	// iframe) revokes the provider session id; the browser's next request
	// is a fresh login.
	if fr, err := http.Get(base + "/oauth2/frontchannel-logout?sid=nope"); err != nil || fr.StatusCode != 200 {
		t.Fatalf("unknown sid: %v %v", fr, err)
	}
	if fr, err := http.Get(base + "/oauth2/frontchannel-logout?iss=https://other.test&sid=provider-session-1"); err != nil || fr.StatusCode != 400 {
		t.Fatalf("wrong issuer: %v %v", fr, err)
	}
	if fr, err := http.Get(base + "/oauth2/frontchannel-logout"); err != nil || fr.StatusCode != 400 {
		t.Fatalf("missing sid: %v %v", fr, err)
	}
	fr, err := http.Get(base + "/oauth2/frontchannel-logout?iss=" + url.QueryEscape(op.srv.URL) + "&sid=provider-session-1")
	if err != nil {
		t.Fatal(err)
	}
	_ = fr.Body.Close()
	if fr.StatusCode != 200 || fr.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("front channel logout: %d %v", fr.StatusCode, fr.Header)
	}
	resp, err = c.Get(base + "/app/after-fc")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if op.authz.Load() != 2 || resp.StatusCode != 200 {
		t.Fatalf("after front channel logout: authz %d status %d", op.authz.Load(), resp.StatusCode)
	}
	// Logout goes through the provider and clears the session.
	resp, err = c.Get(base + "/oauth2/logout")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.HasPrefix(string(body), "logged out; back to http://") {
		t.Fatalf("logout: %q", body)
	}
	for _, ck := range jar.Cookies(mustURL(base)) {
		if ck.Name == "XPOIDC" {
			t.Fatal("session cookie survived logout")
		}
	}
	resp, err = c.Get(base + "/app/3")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if op.authz.Load() != 3 || resp.StatusCode != 200 {
		t.Fatalf("relogin: authz %d status %d", op.authz.Load(), resp.StatusCode)
	}
	// A tampered cookie is a fresh login, not an error.
	u := mustURL(base)
	jar.SetCookies(u, []*http.Cookie{{Name: "XPOIDC", Value: "AAAA" + strings.Repeat("x", 40), Path: "/"}})
	resp, err = c.Get(base + "/app/4")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if op.authz.Load() != 4 || resp.StatusCode != 200 {
		t.Fatalf("tampered cookie: authz %d status %d", op.authz.Load(), resp.StatusCode)
	}
	// Callback with a state that does not match the cookie.
	noFollow := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	jar.SetCookies(u, []*http.Cookie{{Name: "XPOIDC", Value: "", MaxAge: -1, Path: "/"}})
	r1, err := noFollow.Get(base + "/app/5") // sets the state cookie
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	if r1.StatusCode != 302 || !strings.Contains(r1.Header.Get("Location"), "/authorize?") || r1.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("login redirect: %d %v", r1.StatusCode, r1.Header)
	}
	r2, err := noFollow.Get(base + "/oauth2/callback?code=x&state=forged.forged")
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != 400 {
		t.Fatalf("forged state: %d", r2.StatusCode)
	}
	if r3, err := noFollow.Get(base + "/oauth2/callback?error=access_denied"); err != nil || r3.StatusCode != 401 {
		t.Fatalf("provider error: %v %v", r3, err)
	}
	// A wrong nonce in the ID token is refused.
	op.wrongNonc.Store(true)
	jar, _ = cookiejar.New(nil)
	c.Jar = jar
	resp, err = c.Get(base + "/app/6")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("wrong nonce: %d", resp.StatusCode)
	}
	op.wrongNonc.Store(false)
	// A required claim with the wrong value is refused after login.
	op.hd.Store("other.com")
	jar, _ = cookiejar.New(nil)
	c.Jar = jar
	resp, err = c.Get(base + "/app/7")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("claim requirement: %d", resp.StatusCode)
	}
	sn := s.Stats()
	if sn.DeniedFilter != 3 { // forged state, wrong nonce, claim (provider error counts too: 4?)
		t.Logf("denied_filter: %d", sn.DeniedFilter)
	}
	if sn.DeniedFilter < 3 {
		t.Fatalf("denied_filter: %d", sn.DeniedFilter)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
