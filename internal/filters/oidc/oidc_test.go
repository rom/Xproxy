package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

func TestParse(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "s")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := filter.Options{"issuer": "https://op.test", "client_id": "c", "client_secret_file": secret, "cookie_secret_file": filepath.Join(dir, "k")}
	c, err := parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if c.RedirectPath != "/oauth2/callback" || c.LogoutPath != "/oauth2/logout" || c.CookieName != "XPOIDC" || c.ttl.Hours() != 8 || c.TokenAuth != "basic" || len(c.Scopes) != 1 {
		t.Fatalf("defaults: %+v", c)
	}
	with := func(k string, v any) filter.Options {
		o := filter.Options{}
		for kk, vv := range good {
			o[kk] = vv
		}
		o[k] = v
		return o
	}
	cases := []struct {
		name string
		opts filter.Options
		want string
	}{
		{"no issuer", with("issuer", ""), "issuer is required"},
		{"http issuer", with("issuer", "http://op.test"), "https URL"},
		{"no client", with("client_id", ""), "client_id is required"},
		{"secret missing", with("client_secret_file", filepath.Join(dir, "nope")), "client_secret_file"},
		{"no cookie key", with("cookie_secret_file", ""), "cookie_secret_file is required"},
		{"scopes without openid", with("scopes", []any{"email"}), "must include openid"},
		{"bad scope", with("scopes", []any{"openid", "a b"}), "not a scope"},
		{"bad redirect path", with("redirect_path", "callback"), "not a path"},
		{"same paths", with("logout_path", "/oauth2/callback"), "must differ"},
		{"external url", with("external_url", "https://app.test/base"), "external_url"},
		{"cookie name", with("cookie_name", "a b"), "cookie_name"},
		{"ttl", with("session_ttl", "10s"), "session_ttl"},
		{"header", with("forward_headers", map[string]any{"X Y": "sub"}), "forward_headers"},
		{"ca", with("ca_file", filepath.Join(dir, "nope.pem")), "ca_file"},
		{"token auth", with("token_auth", "jwt"), "token_auth"},
		{"unknown key", with("bogus", 1), "bogus"},
	}
	for _, tc := range cases {
		if _, err := parse(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v want %q", tc.name, err, tc.want)
		}
	}
	if st, err := os.Stat(filepath.Join(dir, "k")); err == nil && st != nil {
		t.Fatal("parse must not create the key file")
	}
}

func TestSealOpen(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ := cipher.NewGCM(block)
	f := &oidcFilter{aead: aead, cfg: &Config{CookieName: "X", ttl: 3600}}
	sealed, err := f.seal(loginState{Nonce: "n", Verifier: "v", Return: "/r", Exp: 1}, "state")
	if err != nil {
		t.Fatal(err)
	}
	var ls loginState
	if err := f.open(sealed, "state", &ls); err != nil || ls.Nonce != "n" || ls.Return != "/r" {
		t.Fatalf("open: %+v %v", ls, err)
	}
	if err := f.open(sealed, "session", &ls); err == nil {
		t.Fatal("state cookie accepted as a session")
	}
	if err := f.open(sealed[:len(sealed)-2]+"zz", "state", &ls); err == nil {
		t.Fatal("tampered cookie accepted")
	}
	if err := f.open("!!", "state", &ls); err == nil {
		t.Fatal("garbage accepted")
	}
	// Session decoding rejects expired and malformed payloads.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	exp, _ := f.seal(session{Sub: "a", Exp: 1, Iat: 0}, "session")
	r.AddCookie(&http.Cookie{Name: "X", Value: exp})
	if _, ok := f.session(r); ok {
		t.Fatal("expired session accepted")
	}
	if _, ok := f.session(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Fatal("missing cookie accepted")
	}
	// Cookie stripping keeps other cookies.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "X", Value: "1"})
	r.AddCookie(&http.Cookie{Name: "X_state", Value: "2"})
	r.AddCookie(&http.Cookie{Name: "app", Value: "3"})
	f.stripCookies(r)
	if got := r.Header.Get("Cookie"); got != "app=3" {
		t.Fatalf("strip: %q", got)
	}
	if claimString(3.0) != "3" || claimString(true) != "true" || claimString([]any{"a"}) != `["a"]` || claimString("s") != "s" {
		t.Fatal("claimString")
	}
	if sanitize("ok\x01"+strings.Repeat("x", 100)) != "ok?"+strings.Repeat("x", 61) {
		t.Fatal("sanitize")
	}
}

func TestRevocation(t *testing.T) {
	f := &oidcFilter{cfg: &Config{RevokedMax: 3, ttl: time.Hour}, revoked: map[string]time.Time{}}
	now := time.Now()
	f.revoke("a", now.Add(time.Hour))
	f.revoke("b", now.Add(-time.Second)) // already expired
	if !f.isRevoked("a") || f.isRevoked("b") || f.isRevoked("") || f.isRevoked("zzz") {
		t.Fatal("membership")
	}
	f.revoke("c", now.Add(2*time.Hour))
	f.revoke("d", now.Add(3*time.Hour))
	f.revoke("e", now.Add(4*time.Hour)) // over the bound: the soonest to expire (a) goes
	if f.revokedCount() != 3 || f.isRevoked("a") || !f.isRevoked("e") {
		t.Fatalf("bound: %d", f.revokedCount())
	}
}
