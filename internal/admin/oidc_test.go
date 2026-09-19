package admin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIDP is a minimal OpenID provider: discovery, an authorization
// endpoint that redirects straight back with a code, a token endpoint
// that checks PKCE and the client credentials, and a JWKS.
type fakeIDP struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	user map[string]any // claims of the next login
	seen url.Values     // last authorization request
	chal string
}

func startIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: key, user: map[string]any{"sub": "u1", "email": "alice@example.com", "groups": []string{"proxy-admins"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.seen, f.chal = q, q.Get("code_challenge")
		f.mu.Unlock()
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
			http.Error(w, "bad request", 400)
			return
		}
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=c0de&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		f.mu.Lock()
		chal, nonce := f.chal, f.seen.Get("nonce")
		claims := map[string]any{}
		for k, v := range f.user {
			claims[k] = v
		}
		f.mu.Unlock()
		if !ok || user != "gui" || pass != "gui-secret" || form.Get("code") != "c0de" || base64.RawURLEncoding.EncodeToString(sum[:]) != chal {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		now := time.Now()
		claims["iss"], claims["aud"], claims["nonce"] = f.srv.URL, "gui", nonce
		claims["iat"], claims["exp"] = now.Unix(), now.Add(time.Hour).Unix()
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": f.sign(t, claims), "token_type": "Bearer"})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	p, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIDP) caFile(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "idp-ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOIDCLogin(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	idp := startIDP(t)
	secret := filepath.Join(dir, "gui-secret")
	if err := os.WriteFile(secret, []byte("gui-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir),
		OIDC: &OIDCOptions{Issuer: idp.srv.URL, ClientID: "gui", ClientSecretFile: secret, CAFile: idp.caFile(t, dir),
			Operators: []string{"proxy-admins"}, Viewers: []string{"proxy-viewers"}}})
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	idpClient := idp.srv.Client()
	idpClient.CheckRedirect = noRedirect.CheckRedirect

	if st, body := c.do("GET", "/api/auth", nil, false); st != 200 || !strings.Contains(string(body), `"oidc":true`) {
		t.Fatalf("auth methods: %d %s", st, body)
	}
	// Start: a redirect to the provider with a state cookie.
	resp, err := noRedirect.Get(c.base + "/api/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var stateCookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == oidcStateCookie {
			stateCookie = ck
		}
	}
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || stateCookie == nil || !strings.HasPrefix(loc, idp.srv.URL+"/authorize?") {
		t.Fatalf("login start: %d %q cookie=%v", resp.StatusCode, loc, stateCookie != nil)
	}
	au, _ := url.Parse(loc)
	if au.Query().Get("redirect_uri") != c.base+oidcCallback || au.Query().Get("scope") != "openid profile email" {
		t.Fatalf("authorization request: %v", au.Query())
	}
	// The provider sends the browser back with a code.
	resp, err = idpClient.Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	back := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.HasPrefix(back, c.base+oidcCallback+"?code=") {
		t.Fatalf("provider redirect: %d %q", resp.StatusCode, back)
	}
	callback := func(target string, ck *http.Cookie) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", target, nil)
		if ck != nil {
			req.AddCookie(ck)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	// Without the state cookie the callback is refused.
	if r := callback(back, nil); r.StatusCode != 302 || r.Header.Get("Location") != "/?sso_error=state_missing" {
		t.Fatalf("callback without cookie: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	// With a tampered state it is refused.
	if r := callback(strings.Replace(back, "state=", "state=x", 1), stateCookie); r.Header.Get("Location") != "/?sso_error=state_mismatch" {
		t.Fatalf("tampered state: %q", r.Header.Get("Location"))
	}
	// The real callback opens an operator session.
	r := callback(back, stateCookie)
	if r.StatusCode != 302 || r.Header.Get("Location") != "/" {
		t.Fatalf("callback: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	for _, ck := range r.Cookies() {
		if ck.Name == "xproxy_admin" {
			c.cookie = ck
		}
	}
	if c.cookie == nil {
		t.Fatal("no session cookie")
	}
	st, body := c.do("GET", "/api/me", nil, false)
	if st != 200 || !strings.Contains(string(body), `"user":"alice@example.com"`) || !strings.Contains(string(body), `"role":"operator"`) || !strings.Contains(string(body), `"via":"oidc"`) {
		t.Fatalf("me: %d %s", st, body)
	}
	if st, _ := c.do("POST", "/api/reload", nil, true); st != 200 {
		t.Fatalf("operator action after sso login: %d", st)
	}
	// A user without a mapped group is refused; a viewer group gives viewer.
	for groups, want := range map[string]string{"nobody": "/?sso_error=role", "proxy-viewers": "/"} {
		idp.mu.Lock()
		idp.user = map[string]any{"sub": "u2", "email": "bob@example.com", "groups": []string{groups}}
		idp.mu.Unlock()
		resp, _ := noRedirect.Get(c.base + "/api/oidc/login")
		_ = resp.Body.Close()
		var ck *http.Cookie
		for _, x := range resp.Cookies() {
			if x.Name == oidcStateCookie {
				ck = x
			}
		}
		resp, _ = idpClient.Get(resp.Header.Get("Location"))
		_ = resp.Body.Close()
		r := callback(resp.Header.Get("Location"), ck)
		if r.Header.Get("Location") != want {
			t.Fatalf("groups %s: %q", groups, r.Header.Get("Location"))
		}
		if want == "/" {
			for _, x := range r.Cookies() {
				if x.Name == "xproxy_admin" {
					c.cookie = x
				}
			}
			if st, body := c.do("GET", "/api/me", nil, false); !strings.Contains(string(body), `"role":"viewer"`) {
				t.Fatalf("viewer me: %d %s", st, body)
			}
		}
	}
	// Bad options are refused at start.
	if _, err := New(Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir), OIDC: &OIDCOptions{Issuer: "http://idp", ClientID: "x", ClientSecretFile: secret, Viewers: []string{"*"}}}); err == nil {
		t.Fatal("http issuer accepted")
	}
	if _, err := New(Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir), OIDC: &OIDCOptions{Issuer: idp.srv.URL, ClientID: "x", ClientSecretFile: secret}}); err == nil {
		t.Fatal("no role mapping accepted")
	}
	_ = fmt.Sprint()
}
