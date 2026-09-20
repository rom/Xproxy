package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
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
	// claimString shares the jwt filter's rendering: arrays of strings are
	// comma joined, control characters dropped, the value bounded.
	if claimString(3.0) != "3" || claimString(true) != "true" || claimString([]any{"a", "b"}) != "a,b" || claimString("s") != "s" || claimString("a\r\nb") != "ab" {
		t.Fatal("claimString")
	}
	if sanitize("ok\x01"+strings.Repeat("x", 100)) != "ok?"+strings.Repeat("x", 61) {
		t.Fatal("sanitize")
	}
}

// fakeBus records publications and lets a test inject peer events.
type fakeBus struct {
	published []filter.Event
	subs      map[string][]func(filter.Event)
}

func (b *fakeBus) Publish(e filter.Event) { b.published = append(b.published, e) }
func (b *fakeBus) Subscribe(kind string, fn func(filter.Event)) {
	if b.subs == nil {
		b.subs = map[string][]func(filter.Event){}
	}
	b.subs[kind] = append(b.subs[kind], fn)
}

func TestSealAcrossRotation(t *testing.T) {
	newAEAD := func(seed byte) cipher.AEAD {
		sum := sha256.Sum256([]byte{seed})
		block, _ := aes.NewCipher(sum[:])
		a, _ := cipher.NewGCM(block)
		return a
	}
	oldKey, newKey := newAEAD(1), newAEAD(2)
	cfg := &Config{Issuer: "https://idp.test", ClientID: "app"}
	before := &oidcFilter{aead: oldKey, cfg: cfg}
	sealed, err := before.seal(map[string]string{"sub": "x"}, "session")
	if err != nil {
		t.Fatal(err)
	}
	after := &oidcFilter{aead: newKey, olderAEADs: []cipher.AEAD{oldKey}, cfg: cfg}
	var got map[string]string
	if err := after.open(sealed, "session", &got); err != nil || got["sub"] != "x" {
		t.Fatalf("old cookie after rotation: %v %v", err, got)
	}
	dropped := &oidcFilter{aead: newKey, cfg: cfg}
	if err := dropped.open(sealed, "session", &got); err == nil {
		t.Fatal("cookie under a dropped key opened")
	}
	if err := after.open(sealed, "state", &got); err == nil {
		t.Fatal("purpose not bound")
	}
	// Same key, different provider or client: a session from a lenient
	// filter must not satisfy a stricter one that shares the secret file.
	otherIssuer := &oidcFilter{aead: oldKey, cfg: &Config{Issuer: "https://other.test", ClientID: "app"}}
	if err := otherIssuer.open(sealed, "session", &got); err == nil {
		t.Fatal("issuer not bound")
	}
	otherClient := &oidcFilter{aead: oldKey, cfg: &Config{Issuer: "https://idp.test", ClientID: "app2"}}
	if err := otherClient.open(sealed, "session", &got); err == nil {
		t.Fatal("client_id not bound")
	}
	// A trailing slash on the issuer is not a different provider.
	slash := &oidcFilter{aead: oldKey, cfg: &Config{Issuer: "https://idp.test/", ClientID: "app"}}
	if err := slash.open(sealed, "session", &got); err != nil {
		t.Fatalf("issuer with trailing slash: %v", err)
	}
}

func TestRevocationShared(t *testing.T) {
	bus := &fakeBus{}
	f := &oidcFilter{name: "login", cfg: &Config{RevokedMax: 10, ttl: time.Hour}, revoked: map[string]time.Time{}, revokedFC: map[string]time.Time{}, issued: map[string]time.Time{}}
	f.attach(bus)
	exp := time.Now().Add(time.Hour)
	f.revokeAndShare("local-sid", exp, true)
	if !f.isRevoked("local-sid") || len(bus.published) != 1 || bus.published[0].Kind != "oidc_revoke/login" || bus.published[0].Key != "local-sid" || !bus.published[0].Until.Equal(exp) {
		t.Fatalf("published %+v", bus.published)
	}
	// A peer's revocation for this filter lands; another filter's does not.
	fns := bus.subs["oidc_revoke/login"]
	if len(fns) != 1 || len(bus.subs) != 1 {
		t.Fatalf("subscriptions %v", bus.subs)
	}
	fns[0](filter.Event{Kind: "oidc_revoke/login", Key: "peer-sid", Until: exp})
	if !f.isRevoked("peer-sid") {
		t.Fatal("peer revocation not applied")
	}
	if len(bus.published) != 1 {
		t.Fatal("peer revocation republished")
	}
	// Without a bus nothing breaks.
	g := &oidcFilter{name: "solo", cfg: &Config{RevokedMax: 10, ttl: time.Hour}, revoked: map[string]time.Time{}, revokedFC: map[string]time.Time{}, issued: map[string]time.Time{}}
	g.attach(nil)
	g.revokeAndShare("x", exp, true)
	if !g.isRevoked("x") {
		t.Fatal("solo revoke")
	}
}

func TestRevocation(t *testing.T) {
	f := &oidcFilter{cfg: &Config{RevokedMax: 3, ttl: time.Hour}, revoked: map[string]time.Time{}, revokedFC: map[string]time.Time{}, issued: map[string]time.Time{}}
	now := time.Now()
	f.revoke("a", now.Add(time.Hour), true)
	f.revoke("b", now.Add(-time.Second), true) // already expired
	if !f.isRevoked("a") || f.isRevoked("b") || f.isRevoked("") || f.isRevoked("zzz") {
		t.Fatal("membership")
	}
	f.revoke("c", now.Add(2*time.Hour), true)
	f.revoke("d", now.Add(3*time.Hour), true)
	f.revoke("e", now.Add(4*time.Hour), true) // over the bound: the soonest to expire (a) goes
	if f.revokedCount() != 3 || f.isRevoked("a") || !f.isRevoked("e") {
		t.Fatalf("bound: %d", f.revokedCount())
	}
}
