package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

type signer struct {
	alg string
	kid string
	key any
}

func (s signer) jwk() map[string]any {
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		return map[string]any{"kty": "RSA", "kid": s.kid, "use": "sig", "n": b64u(k.N.Bytes()), "e": b64u(big.NewInt(int64(k.E)).Bytes())}
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		return map[string]any{"kty": "EC", "kid": s.kid, "crv": "P-256", "x": b64u(k.X.FillBytes(make([]byte, size))), "y": b64u(k.Y.FillBytes(make([]byte, size)))}
	case ed25519.PrivateKey:
		return map[string]any{"kty": "OKP", "kid": s.kid, "crv": "Ed25519", "x": b64u(k.Public().(ed25519.PublicKey))}
	}
	return nil
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s signer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": s.alg, "typ": "JWT"}
	if s.kid != "" {
		h["kid"] = s.kid
	}
	hb, _ := json.Marshal(h)
	pb, _ := json.Marshal(claims)
	signed := b64u(hb) + "." + b64u(pb)
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	var err error
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		if strings.HasPrefix(s.alg, "PS") {
			sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		}
	case *ecdsa.PrivateKey:
		r, sv, e := ecdsa.Sign(rand.Reader, k, digest[:])
		err = e
		if e == nil {
			sig = append(r.FillBytes(make([]byte, 32)), sv.FillBytes(make([]byte, 32))...)
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(signed))
	case []byte:
		m := hmac.New(sha256.New, k)
		m.Write([]byte(signed))
		sig = m.Sum(nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64u(sig)
}

func keys(t *testing.T) (rs, ps, es, ed signer) {
	t.Helper()
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	return signer{"RS256", "rsa1", rk}, signer{"PS256", "rsa1", rk}, signer{"ES256", "ec1", ek}, signer{"EdDSA", "ed1", edk}
}

func writeJWKS(t *testing.T, dir string, signers ...signer) string {
	t.Helper()
	ks := make([]map[string]any, 0, len(signers))
	for _, s := range signers {
		ks = append(ks, s.jwk())
	}
	b, _ := json.Marshal(map[string]any{"keys": ks})
	p := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func base(claims map[string]any) map[string]any {
	c := map[string]any{"iss": "https://issuer.test/", "aud": "api", "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		c[k] = v
	}
	return c
}

func provider(t *testing.T, cfg config.JWTProvider) *Provider {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "p"
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "https://issuer.test/"
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = config.Duration(30 * time.Second)
	}
	if cfg.JWKSRefresh == 0 {
		cfg.JWKSRefresh = config.Duration(time.Hour)
	}
	if cfg.Source == "" {
		cfg.Source = "bearer"
	}
	p, err := NewProvider(cfg, nolog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	return p
}

func TestVerifyAlgorithms(t *testing.T) {
	rs, ps, es, ed := keys(t)
	dir := t.TempDir()
	jwks := writeJWKS(t, dir, rs, es, ed)
	p := provider(t, config.JWTProvider{Algorithms: []string{"RS256", "PS256", "ES256", "EdDSA"}, JWKSFile: jwks, Audiences: []string{"api"}})
	for _, s := range []signer{rs, ps, es, ed} {
		c, err := p.Verify(s.sign(t, base(nil)))
		if err != nil || c["sub"] != "alice" {
			t.Fatalf("%s: %v %v", s.alg, err, c)
		}
	}
	// Without a kid the matching key type is tried.
	nokid := rs
	nokid.kid = ""
	if _, err := p.Verify(nokid.sign(t, base(nil))); err != nil {
		t.Fatalf("no kid: %v", err)
	}
	if p.KeyCount() != 3 || p.Verified.Load() != 5 {
		t.Fatalf("counters %d %d", p.KeyCount(), p.Verified.Load())
	}
}

func TestVerifyRejections(t *testing.T) {
	rs, _, es, _ := keys(t)
	dir := t.TempDir()
	jwks := writeJWKS(t, dir, rs, es)
	p := provider(t, config.JWTProvider{Algorithms: []string{"RS256", "ES256"}, JWKSFile: jwks, Audiences: []string{"api", "web"}, RequiredClaims: []string{"sub"}})
	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"expired", rs.sign(t, base(map[string]any{"exp": time.Now().Add(-2 * time.Minute).Unix()})), ErrExpired},
		{"within skew", rs.sign(t, base(map[string]any{"exp": time.Now().Add(-10 * time.Second).Unix()})), nil},
		{"nbf future", rs.sign(t, base(map[string]any{"nbf": time.Now().Add(5 * time.Minute).Unix()})), ErrNotYetValid},
		{"issuer", rs.sign(t, base(map[string]any{"iss": "https://other/"})), ErrIssuer},
		{"audience", rs.sign(t, base(map[string]any{"aud": "nope"})), ErrAudience},
		{"audience list ok", rs.sign(t, base(map[string]any{"aud": []string{"x", "web"}})), nil},
		{"missing exp", rs.sign(t, map[string]any{"iss": "https://issuer.test/", "aud": "api", "sub": "a"}), ErrClaim},
		{"missing required", rs.sign(t, map[string]any{"iss": "https://issuer.test/", "aud": "api", "exp": time.Now().Add(time.Hour).Unix()}), ErrClaim},
		{"alg none", strings.Join([]string{b64u([]byte(`{"alg":"none"}`)), b64u([]byte(`{}`)), ""}, "."), ErrMalformed},
		{"alg none with junk signature", strings.Join([]string{b64u([]byte(`{"alg":"none"}`)), b64u([]byte(`{}`)), "AAAA"}, "."), ErrAlgorithm},
		{"alg not allowed", signer{"PS256", "rsa1", rs.key}.sign(t, base(nil)), ErrAlgorithm},
		{"hs with rsa key", signer{"HS256", "rsa1", []byte("x")}.sign(t, base(nil)), ErrAlgorithm},
		{"unknown kid", signer{"RS256", "other", rs.key}.sign(t, base(nil)), ErrNoKey},
		{"wrong key", signer{"RS256", "rsa1", func() any { k, _ := rsa.GenerateKey(rand.Reader, 2048); return k }()}.sign(t, base(nil)), ErrSignature},
		{"alg/key mismatch", signer{"ES256", "rsa1", es.key}.sign(t, base(nil)), ErrNoKey},
		{"tampered payload", func() string {
			tk := rs.sign(t, base(nil))
			i := strings.Index(tk, ".")
			return tk[:i+1] + b64u([]byte(`{"sub":"mallory","iss":"https://issuer.test/","aud":"api","exp":9999999999}`)) + tk[strings.LastIndex(tk, "."):]
		}(), ErrSignature},
		{"garbage", "not.a.token", ErrMalformed},
		{"two parts", "a.b", ErrMalformed},
		{"empty", "", ErrMalformed},
		{"too long", strings.Repeat("a", MaxTokenBytes+1), ErrMalformed},
	}
	for _, c := range cases {
		_, err := p.Verify(c.token)
		if c.want == nil && err != nil {
			t.Errorf("%s: unexpected %v", c.name, err)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

func TestHMAC(t *testing.T) {
	dir := t.TempDir()
	secret := []byte(strings.Repeat("s", 40))
	sf := filepath.Join(dir, "secret")
	os.WriteFile(sf, secret, 0o600)
	p := provider(t, config.JWTProvider{Algorithms: []string{"HS256"}, HMACSecretFile: sf})
	if _, err := p.Verify(signer{"HS256", "", secret}.sign(t, base(nil))); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(signer{"HS256", "", []byte("wrong")}.sign(t, base(nil))); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong secret: %v", err)
	}
	os.WriteFile(sf, []byte("short"), 0o600)
	if _, err := NewProvider(config.JWTProvider{Name: "x", Issuer: "i", Algorithms: []string{"HS256"}, HMACSecretFile: sf, Source: "bearer"}, nolog); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestJWKSURLAndRotation(t *testing.T) {
	rs, _, _, _ := keys(t)
	var current atomic.Value
	current.Store([]signer{rs})
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var ks []map[string]any
		for _, s := range current.Load().([]signer) {
			ks = append(ks, s.jwk())
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": ks})
	}))
	defer srv.Close()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, pemCert(srv.Certificate().Raw), 0o600)

	p := provider(t, config.JWTProvider{Algorithms: []string{"RS256"}, JWKSURL: srv.URL, JWKSCAFile: caPath, JWKSRefresh: config.Duration(time.Minute)})
	if p.KeyCount() != 1 {
		t.Fatalf("initial fetch: %d keys", p.KeyCount())
	}
	if _, err := p.Verify(rs.sign(t, base(nil))); err != nil {
		t.Fatal(err)
	}
	// Rotate: a token with a new kid triggers an on-demand refresh.
	rk2, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs2 := signer{"RS256", "rsa2", rk2}
	current.Store([]signer{rs, rs2})
	if _, err := p.Verify(rs2.sign(t, base(nil))); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	// A second unknown kid within a minute does not refetch.
	before := hits.Load()
	p.Verify(signer{"RS256", "rsa3", rk2}.sign(t, base(nil)))
	if hits.Load() != before {
		t.Fatal("on-demand refresh not rate limited")
	}
	// Unpinned CA fails; keys unavailable until a fetch succeeds.
	p2, err := NewProvider(config.JWTProvider{Name: "u", Issuer: "https://issuer.test/", Algorithms: []string{"RS256"}, JWKSURL: srv.URL, JWKSRefresh: config.Duration(time.Minute), ClockSkew: config.Duration(time.Second), Source: "bearer"}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Stop()
	if _, err := p2.Verify(rs.sign(t, base(nil))); !errors.Is(err, ErrKeysUnavail) {
		t.Fatalf("unpinned: %v", err)
	}
}

func pemCert(der []byte) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END CERTIFICATE-----\n")
}

func TestJWKSParsing(t *testing.T) {
	ks, err := parseJWKS([]byte(`{"keys":[
		{"kty":"RSA","kid":"small","n":"AQAB","e":"AQAB"},
		{"kty":"EC","kid":"badcurve","crv":"P-999","x":"AA","y":"AA"},
		{"kty":"oct","kid":"sym","k":"c2VjcmV0"},
		{"kty":"RSA","kid":"enc","use":"enc","n":"AQAB","e":"AQAB"},
		{"kty":"OKP","kid":"ed","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ks.all) != 1 || ks.all[0].kid != "ed" {
		t.Fatalf("expected only the Ed25519 key, got %d", len(ks.all))
	}
	if _, err := parseJWKS([]byte("{")); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestFilter(t *testing.T) {
	rs, _, _, _ := keys(t)
	dir := t.TempDir()
	jwks := writeJWKS(t, dir, rs)
	p := provider(t, config.JWTProvider{Algorithms: []string{"RS256"}, JWKSFile: jwks, Audiences: []string{"api"},
		ForwardClaims: map[string]string{"X-User": "sub", "X-Scopes": "scope", "X-Admin": "admin"}, LogClaims: []string{"sub"}})
	f := p.Filter(true)
	info := &filter.Info{RequestID: "r"}
	run := func(r *http.Request) (filter.Verdict, []any) {
		in := f.Begin(context.Background(), info)
		v := in.Request(r)
		return v, in.End()
	}
	// Missing token.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-User", "spoofed")
	v, _ := run(r)
	if !v.Deny || v.Status != 401 || v.Headers["WWW-Authenticate"] == "" || r.Header.Get("X-User") != "" {
		t.Fatalf("missing: %+v", v)
	}
	// Optional route lets a missing token through with spoofed headers removed.
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-User", "spoofed")
	in := p.Filter(false).Begin(context.Background(), info)
	if v := in.Request(r); v.Deny || r.Header.Get("X-User") != "" {
		t.Fatal("optional")
	}
	// Valid token: claims forwarded, token stripped, log attrs.
	tok := rs.sign(t, base(map[string]any{"scope": []string{"read", "write"}, "admin": true}))
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("X-User", "spoofed")
	v, attrs := run(r)
	if v.Deny {
		t.Fatalf("valid denied: %+v", v)
	}
	if r.Header.Get("X-User") != "alice" || r.Header.Get("X-Scopes") != "read,write" || r.Header.Get("X-Admin") != "true" || r.Header.Get("Authorization") != "" {
		t.Fatalf("headers: %v", r.Header)
	}
	if len(attrs) != 4 || attrs[2] != "jwt_sub" || attrs[3] != "alice" {
		t.Fatalf("attrs %v", attrs)
	}
	// Invalid token.
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok[:len(tok)-3]+"AAA")
	v, _ = run(r)
	if !v.Deny || v.Status != 401 || v.Detail != "signature" {
		t.Fatalf("invalid: %+v", v)
	}
	// Cookie source with stripping keeps other cookies.
	pc := provider(t, config.JWTProvider{Name: "c", Algorithms: []string{"RS256"}, JWKSFile: jwks, Source: "cookie:tok"})
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "tok", Value: tok})
	r.AddCookie(&http.Cookie{Name: "other", Value: "keep"})
	in = pc.Filter(true).Begin(context.Background(), info)
	if v := in.Request(r); v.Deny {
		t.Fatalf("cookie: %+v", v)
	}
	if _, err := r.Cookie("tok"); err == nil {
		t.Fatal("token cookie not stripped")
	}
	if c, err := r.Cookie("other"); err != nil || c.Value != "keep" {
		t.Fatal("other cookie lost")
	}
	// Header source.
	ph := provider(t, config.JWTProvider{Name: "h", Algorithms: []string{"RS256"}, JWKSFile: jwks, Source: "header:X-Token"})
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Token", tok)
	if v := ph.Filter(true).Begin(context.Background(), info).Request(r); v.Deny || r.Header.Get("X-Token") != "" {
		t.Fatalf("header source: %+v", v)
	}
}

func TestClaimString(t *testing.T) {
	if ClaimString("a\r\nb") != "ab" || ClaimString(json.Number("42")) != "42" || ClaimString(false) != "false" || ClaimString([]any{"x", 1.0}) != "x,1" || ClaimString(map[string]any{"k": "v"}) != `{"k":"v"}` {
		t.Fatal("claim rendering")
	}
	if len(ClaimString(strings.Repeat("x", 5000))) != 1024 {
		t.Fatal("cap")
	}
}
