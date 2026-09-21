package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

// A token's lifetime is three numbers a client sends and the proxy
// believes: exp, nbf and iat. Everything about whether a request is
// authenticated comes down to comparing them against a clock, and the
// interesting cases are the ones at the edges of what a number can be
// rather than the ones in the middle.

// timeProvider is a provider with a known skew and a key whose tokens
// the tests sign.
func timeProvider(t *testing.T, skew time.Duration) (*Provider, signer) {
	t.Helper()
	rs, _, _, _ := keys(t)
	dir := t.TempDir()
	// NewProvider directly rather than the shared helper, which
	// substitutes a default skew for zero — and zero is one of the
	// settings under test.
	p, err := NewProvider(config.JWTProvider{
		Name: "p", Issuer: "https://issuer.test/", Source: "bearer",
		Audiences: []string{"api"}, JWKSFile: writeJWKS(t, dir, rs),
		Algorithms: []string{"RS256"}, ClockSkew: config.Duration(skew),
		JWKSRefresh: config.Duration(time.Hour),
	}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	return p, rs
}

// TestExpiryBoundary walks the instants around exp. The second the
// token expires is the one an implementation gets wrong, and the
// difference between `>` and `>=` there is a token that works for one
// more second than it should — which matters when the token was
// revoked by letting it expire.
func TestExpiryBoundary(t *testing.T) {
	const skew = 30 * time.Second
	p, s := timeProvider(t, skew)
	exp := time.Now().Truncate(time.Second).Add(time.Hour)
	token := s.sign(t, base(map[string]any{"exp": exp.Unix()}))

	cases := []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"well before", exp.Add(-time.Hour), true},
		{"one second before", exp.Add(-time.Second), true},
		{"exactly at exp", exp, true},
		{"one second after", exp.Add(time.Second), true}, // inside the skew
		{"at the edge of the skew", exp.Add(skew), true}, // still inside
		{"one second past the skew", exp.Add(skew + time.Second), false},
		{"long after", exp.Add(24 * time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.verify(token, tc.at)
			if tc.ok && err != nil {
				t.Fatalf("refused at %v: %v", tc.at.Sub(exp), err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("accepted at %v", tc.at.Sub(exp))
				}
				if !errors.Is(err, ErrExpired) {
					t.Fatalf("refused as %v, not as expired", err)
				}
			}
		})
	}
}

// TestNotBeforeBoundary is the same exercise for nbf, where the skew
// works in the other direction.
func TestNotBeforeBoundary(t *testing.T) {
	const skew = 30 * time.Second
	p, s := timeProvider(t, skew)
	nbf := time.Now().Truncate(time.Second).Add(time.Hour)
	token := s.sign(t, base(map[string]any{"nbf": nbf.Unix(), "exp": nbf.Add(time.Hour).Unix()}))

	for _, tc := range []struct {
		at time.Time
		ok bool
	}{
		{nbf.Add(-time.Hour), false},
		{nbf.Add(-skew - time.Second), false},
		{nbf.Add(-skew), true},
		{nbf.Add(-time.Second), true},
		{nbf, true},
		{nbf.Add(time.Second), true},
	} {
		_, err := p.verify(token, tc.at)
		if tc.ok != (err == nil) {
			t.Errorf("at nbf%+v: err=%v, want ok=%v", tc.at.Sub(nbf), err, tc.ok)
		}
		if !tc.ok && !errors.Is(err, ErrNotYetValid) {
			t.Errorf("at nbf%+v refused as %v, not as not-yet-valid", tc.at.Sub(nbf), err)
		}
	}
}

// TestIssuedInTheFuture covers a token whose iat is ahead of the
// verifier's clock by more than the skew plus the minute of slack. A
// token minted in the future is a clock that disagrees, and believing
// it means believing a lifetime that has not started.
func TestIssuedInTheFuture(t *testing.T) {
	p, s := timeProvider(t, 30*time.Second)
	now := time.Now().Truncate(time.Second)
	for _, tc := range []struct {
		ahead time.Duration
		ok    bool
	}{
		{0, true},
		{30 * time.Second, true},
		{89 * time.Second, true},
		{10 * time.Minute, false},
		{24 * time.Hour, false},
	} {
		token := s.sign(t, base(map[string]any{
			"iat": now.Add(tc.ahead).Unix(),
			"exp": now.Add(48 * time.Hour).Unix(),
		}))
		_, err := p.verify(token, now)
		if tc.ok != (err == nil) {
			t.Errorf("iat %v ahead: err=%v, want ok=%v", tc.ahead, err, tc.ok)
		}
	}
}

// TestEpochEdges covers the numbers at the ends of what a timestamp can
// be: zero, negative, the 32-bit signed overflow in 2038, the largest
// integer a float64 represents exactly, and past it.
func TestEpochEdges(t *testing.T) {
	p, s := timeProvider(t, 0)
	now := time.Now().Truncate(time.Second)
	cases := []struct {
		name string
		exp  any
		ok   bool
	}{
		{"zero", 0, false},
		{"negative", -1, false},
		{"just past now", now.Add(time.Minute).Unix(), true},
		{"the 2038 rollover", int64(2147483647), true},
		{"just past 2038", int64(2147483648), true},
		{"year 10000", int64(253402300799), true},
		{"largest exact float64 integer", int64(1) << 53, true},
		{"past exact float64", int64(1)<<53 + 1, true},
		{"int64 max", int64(math.MaxInt64), true},
		{"float", float64(now.Add(time.Minute).UnixNano()) / 1e9, true},
		{"string", fmt.Sprint(now.Add(time.Minute).Unix()), false},
		{"null", nil, false},
		{"bool", true, false},
		{"object", map[string]any{"at": 1}, false},
		{"array", []any{1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base(nil)
			claims["exp"] = tc.exp
			_, err := p.verify(s.sign(t, claims), now)
			if tc.ok != (err == nil) {
				t.Fatalf("exp=%v: err=%v, want ok=%v", tc.exp, err, tc.ok)
			}
		})
	}
}

// TestNonFiniteLifetimes is the NaN case for a clock comparison. NaN
// compares false against everything, so `now > exp` is false for a NaN
// exp: a token that never expires. The claim must be refused rather
// than believed.
func TestNonFiniteLifetimes(t *testing.T) {
	p, s := timeProvider(t, 0)
	now := time.Now()
	// JSON has no NaN or Infinity literal, so these arrive as the
	// spellings a hand-built encoder produces; each must fail to
	// decode or fail the claim check, never pass it.
	for _, raw := range []string{"NaN", "Infinity", "-Infinity", "1e400", "-1e400"} {
		claims := base(nil)
		delete(claims, "exp")
		token := s.signRaw(t, `{"iss":"https://issuer.test/","aud":"api","sub":"alice","exp":`+raw+`}`)
		if _, err := p.verify(token, now); err == nil {
			t.Errorf("exp=%s was accepted as a lifetime", raw)
		}
		_ = claims
	}
}

// TestMissingExpiry requires a token with no exp to be refused. An
// unbounded lifetime is the one a stolen token keeps forever.
func TestMissingExpiry(t *testing.T) {
	p, s := timeProvider(t, 0)
	claims := base(nil)
	delete(claims, "exp")
	if _, err := p.verify(s.sign(t, claims), time.Now()); err == nil {
		t.Fatal("a token with no exp was accepted")
	}
}

// TestZeroSkew pins the default-free case: with no skew configured, exp
// is exp. An operator who sets clock_skew to zero has said they run
// synchronised clocks.
func TestZeroSkew(t *testing.T) {
	p, s := timeProvider(t, 0)
	exp := time.Now().Truncate(time.Second).Add(time.Hour)
	token := s.sign(t, base(map[string]any{"exp": exp.Unix()}))
	if _, err := p.verify(token, exp); err != nil {
		t.Fatalf("refused exactly at exp with no skew: %v", err)
	}
	if _, err := p.verify(token, exp.Add(time.Second)); err == nil {
		t.Fatal("accepted a second past exp with no skew")
	}
}

// TestLargeSkew covers the other end: a generous skew keeps an expired
// token working for exactly that long and not a second more.
func TestLargeSkew(t *testing.T) {
	const skew = time.Hour
	p, s := timeProvider(t, skew)
	exp := time.Now().Truncate(time.Second).Add(-30 * time.Minute)
	token := s.sign(t, base(map[string]any{"exp": exp.Unix()}))
	if _, err := p.verify(token, time.Now()); err != nil {
		t.Fatalf("a token half an hour expired with an hour of skew: %v", err)
	}
	if _, err := p.verify(token, exp.Add(skew+time.Second)); err == nil {
		t.Fatal("the skew did not end")
	}
}

// TestVerificationIsDeterministic requires the same token and the same
// instant to give the same answer. Verification reads a shared key set
// and a shared configuration, and an answer that varied would be an
// answer nobody could reproduce from a log line.
func TestVerificationIsDeterministic(t *testing.T) {
	p, s := timeProvider(t, 30*time.Second)
	at := time.Now()
	token := s.sign(t, base(nil))
	first, firstErr := p.verify(token, at)
	for i := 0; i < 50; i++ {
		got, err := p.verify(token, at)
		if (err == nil) != (firstErr == nil) {
			t.Fatalf("run %d: %v then %v", i, firstErr, err)
		}
		if err == nil && fmt.Sprint(got["sub"]) != fmt.Sprint(first["sub"]) {
			t.Fatalf("run %d produced a different subject", i)
		}
	}
}

// TestClaimsAreNotShared requires two verifications of one token to
// hand out maps the caller can modify independently. A filter writes
// forwarded headers from these, and a shared map would leak one
// request's claims into another's.
func TestClaimsAreNotShared(t *testing.T) {
	p, s := timeProvider(t, 30*time.Second)
	token := s.sign(t, base(nil))
	a, err := p.verify(token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a["sub"] = "mallory"
	b, err := p.verify(token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(b["sub"]) != "alice" {
		t.Fatalf("a second verification saw the first one's edit: %v", b["sub"])
	}
}

// TestMalformedTokens covers the shapes that are not a token, each of
// which arrives on the Authorization header of an unauthenticated
// request.
func TestMalformedTokens(t *testing.T) {
	p, s := timeProvider(t, 0)
	good := s.sign(t, base(nil))
	parts := strings.Split(good, ".")
	bad := []string{
		"", ".", "..", "a.b", "a.b.c.d", good + ".", "." + good,
		parts[0] + "." + parts[1], parts[0] + ".." + parts[2],
		"!!!." + parts[1] + "." + parts[2],
		parts[0] + ".!!!." + parts[2],
		parts[0] + "." + parts[1] + ".!!!",
		strings.ToUpper(parts[0]) + "." + parts[1] + "." + parts[2],
		good + "\n",
		" " + good,
		strings.Repeat("a", MaxTokenBytes+1),
		"eyJhbGciOiJub25lIn0." + parts[1] + ".", // alg none with an empty signature
	}
	for i, token := range bad {
		if _, err := p.verify(token, time.Now()); err == nil {
			t.Errorf("case %d accepted: %.60q", i, token)
		}
	}
	// The unmodified token still verifies, so the cases above failed
	// for their own reasons.
	if _, err := p.verify(good, time.Now()); err != nil {
		t.Fatalf("the control token: %v", err)
	}
}

// TestDenyCategories requires each way a token can be wrong to reach
// the security log as its own category. "401" tells an operator
// nothing; "expired", "issuer" and "unknown_key" are three different
// incidents with three different answers.
func TestDenyCategories(t *testing.T) {
	rs, _, es, _ := keys(t)
	dir := t.TempDir()
	p := provider(t, config.JWTProvider{
		Audiences: []string{"api"}, JWKSFile: writeJWKS(t, dir, rs),
		Algorithms: []string{"RS256"}, ClockSkew: config.Duration(time.Second),
		RequiredClaims: []string{"scope"},
	})
	f := p.Filter(true)
	if f.Name() != "jwt:p" {
		t.Fatalf("filter name %q", f.Name())
	}
	other := signer{"RS256", "other-kid", rs.key}

	cases := []struct {
		name   string
		claims map[string]any
		s      signer
		want   string
	}{
		{"expired", map[string]any{"exp": time.Now().Add(-time.Hour).Unix(), "scope": "x"}, rs, "expired"},
		{"not yet valid", map[string]any{"nbf": time.Now().Add(time.Hour).Unix(), "scope": "x"}, rs, "not_yet_valid"},
		{"issuer", map[string]any{"iss": "https://elsewhere.test/", "scope": "x"}, rs, "issuer"},
		{"audience", map[string]any{"aud": "another-api", "scope": "x"}, rs, "audience"},
		{"algorithm", map[string]any{"scope": "x"}, es, "algorithm"},
		{"unknown key", map[string]any{"scope": "x"}, other, "unknown_key"},
		{"missing claim", map[string]any{}, rs, "claim"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.s.sign(t, base(tc.claims))
			r := newRequest(token)
			in := f.Begin(t.Context(), &filter.Info{})
			v := in.Request(r)
			if !v.Deny || v.Status != http.StatusUnauthorized {
				t.Fatalf("verdict %+v", v)
			}
			if v.Detail != tc.want {
				t.Fatalf("category %q, want %q", v.Detail, tc.want)
			}
			if !strings.Contains(v.Headers["WWW-Authenticate"], "invalid_token") {
				t.Fatalf("challenge %q", v.Headers["WWW-Authenticate"])
			}
			// The response phase never has an opinion.
			if rv := in.Response(&http.Response{Header: http.Header{}}); rv.Deny {
				t.Fatal("the response phase denied")
			}
		})
	}

	// A signature over different bytes is its own category.
	good := rs.sign(t, base(map[string]any{"scope": "x"}))
	parts := strings.Split(good, ".")
	forged := parts[0] + "." + b64u([]byte(`{"iss":"https://issuer.test/","aud":"api","sub":"mallory","scope":"admin","exp":99999999999}`)) + "." + parts[2]
	in := f.Begin(t.Context(), &filter.Info{})
	if v := in.Request(newRequest(forged)); v.Detail != "signature" {
		t.Fatalf("a re-signed payload gave %q", v.Detail)
	}
	// And a token that is not a token at all.
	in = f.Begin(t.Context(), &filter.Info{})
	if v := in.Request(newRequest("not-a-token")); v.Detail != "malformed" {
		t.Fatalf("garbage gave %q", v.Detail)
	}
	// A request with no token at all on a required route.
	in = f.Begin(t.Context(), &filter.Info{})
	if v := in.Request(httptest.NewRequest("GET", "http://a/x", nil)); v.Detail != "missing" {
		t.Fatalf("no token gave %q", v.Detail)
	}
	// The good token passes and logs its provider.
	in = f.Begin(t.Context(), &filter.Info{})
	if v := in.Request(newRequest(good)); v.Deny {
		t.Fatalf("the control token was denied: %+v", v)
	}
	if attrs := fmt.Sprint(in.End()); !strings.Contains(attrs, "jwt_provider") {
		t.Fatalf("attributes %s", attrs)
	}
}

// newRequest is a GET carrying a bearer token.
func newRequest(token string) *http.Request {
	r := httptest.NewRequest("GET", "http://a/x", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// TestTokenSources covers the three places a token may come from and
// the stripping that keeps it out of the upstream request.
func TestTokenSources(t *testing.T) {
	rs, _, _, _ := keys(t)
	dir := t.TempDir()
	jwks := writeJWKS(t, dir, rs)
	token := rs.sign(t, base(nil))

	for _, tc := range []struct {
		source string
		set    func(*http.Request)
		gone   func(*http.Request) bool
	}{
		{"bearer",
			func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
			func(r *http.Request) bool { return r.Header.Get("Authorization") == "" }},
		{"header:X-Token",
			func(r *http.Request) { r.Header.Set("X-Token", token) },
			func(r *http.Request) bool { return r.Header.Get("X-Token") == "" }},
		{"cookie:session",
			func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "other", Value: "keep"})
				r.AddCookie(&http.Cookie{Name: "session", Value: token})
			},
			func(r *http.Request) bool {
				return !strings.Contains(r.Header.Get("Cookie"), token) &&
					strings.Contains(r.Header.Get("Cookie"), "other=keep")
			}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			strip := true
			p := provider(t, config.JWTProvider{
				Audiences: []string{"api"}, JWKSFile: jwks, Algorithms: []string{"RS256"},
				Source: tc.source, StripToken: &strip,
				ForwardClaims: map[string]string{"X-User": "sub"},
			})
			f := p.Filter(true)
			r := httptest.NewRequest("GET", "http://a/x", nil)
			// A client supplied copy of the forwarded header is never
			// trusted, token or no token.
			r.Header.Set("X-User", "root")
			tc.set(r)
			if v := f.Begin(t.Context(), &filter.Info{}).Request(r); v.Deny {
				t.Fatalf("denied: %+v", v)
			}
			if got := r.Header.Get("X-User"); got != "alice" {
				t.Fatalf("forwarded identity is %q", got)
			}
			if !tc.gone(r) {
				t.Fatalf("the token reached the upstream: %v", r.Header)
			}

			// Absent on an optional route, the request continues with
			// the client's header removed rather than honoured.
			optional := p.Filter(false)
			r2 := httptest.NewRequest("GET", "http://a/x", nil)
			r2.Header.Set("X-User", "root")
			if v := optional.Begin(t.Context(), &filter.Info{}).Request(r2); v.Deny {
				t.Fatalf("an optional route denied a request with no token: %+v", v)
			}
			if r2.Header.Get("X-User") != "" {
				t.Fatalf("a client supplied identity header survived: %q", r2.Header.Get("X-User"))
			}
		})
	}
}

// TestKeysUnavailable covers a provider whose key set never loaded: the
// answer is 503 with a Retry-After, not 401. The client's token may be
// perfectly good, and telling them it is invalid sends them to re-
// authenticate against a provider that is not the problem.
func TestKeysUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	p := provider(t, config.JWTProvider{
		Audiences: []string{"api"}, JWKSURL: srv.URL, Algorithms: []string{"RS256"},
	})
	rs, _, _, _ := keys(t)
	f := p.Filter(true)
	// A well-formed token, so the verdict comes from the missing key
	// set rather than from the shape of the token.
	v := f.Begin(t.Context(), &filter.Info{}).Request(newRequest(rs.sign(t, base(nil))))
	if !v.Deny || v.Status != http.StatusServiceUnavailable || v.Detail != "keys_unavailable" {
		t.Fatalf("verdict %+v", v)
	}
	if v.Headers["Retry-After"] == "" {
		t.Fatal("no Retry-After on an unavailable key set")
	}
}

// TestJWKSKeyRejections covers the key sets a provider must not load a
// key from. Each of these is a key an attacker would like accepted: a
// small RSA modulus is forgeable, an exponent of 1 makes every
// signature valid, and a point off the curve is not a key at all.
func TestJWKSKeyRejections(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	big2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name string
		key  map[string]any
	}{
		{"rsa 1024", map[string]any{"kty": "RSA", "kid": "a", "n": b64u(small.N.Bytes()), "e": b64u(big.NewInt(65537).Bytes())}},
		{"rsa exponent 1", map[string]any{"kty": "RSA", "kid": "a", "n": b64u(big2048.N.Bytes()), "e": b64u(big.NewInt(1).Bytes())}},
		{"rsa exponent 0", map[string]any{"kty": "RSA", "kid": "a", "n": b64u(big2048.N.Bytes()), "e": b64u(big.NewInt(0).Bytes())}},
		{"rsa no modulus", map[string]any{"kty": "RSA", "kid": "a", "e": b64u(big.NewInt(65537).Bytes())}},
		{"rsa bad base64", map[string]any{"kty": "RSA", "kid": "a", "n": "!!!", "e": b64u(big.NewInt(65537).Bytes())}},
		{"ec off curve", map[string]any{"kty": "EC", "kid": "a", "crv": "P-256",
			"x": b64u(ec.X.FillBytes(make([]byte, 32))), "y": b64u(make([]byte, 32))}},
		{"ec unknown curve", map[string]any{"kty": "EC", "kid": "a", "crv": "P-192", "x": b64u(make([]byte, 24)), "y": b64u(make([]byte, 24))}},
		{"ec no coordinates", map[string]any{"kty": "EC", "kid": "a", "crv": "P-256"}},
		{"okp wrong curve", map[string]any{"kty": "OKP", "kid": "a", "crv": "X25519", "x": b64u(edk.Public().(ed25519.PublicKey))}},
		{"okp short key", map[string]any{"kty": "OKP", "kid": "a", "crv": "Ed25519", "x": b64u([]byte("short"))}},
		{"unknown type", map[string]any{"kty": "AES", "kid": "a", "k": b64u([]byte("secret"))}},
		{"encryption key", map[string]any{"kty": "RSA", "kid": "a", "use": "enc", "n": b64u(big2048.N.Bytes()), "e": b64u(big.NewInt(65537).Bytes())}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, _ := json.Marshal(map[string]any{"keys": []map[string]any{tc.key}})
			ks, err := parseJWKS(doc)
			if err != nil {
				return // refusing the whole document is also correct
			}
			if len(ks.all) != 0 {
				t.Fatalf("a %s was loaded as a signing key", tc.name)
			}
		})
	}

	// A good key in the same document is still loaded: one bad entry
	// does not take the provider down.
	good := map[string]any{"kty": "RSA", "kid": "good", "n": b64u(big2048.N.Bytes()), "e": b64u(big.NewInt(65537).Bytes())}
	doc, _ := json.Marshal(map[string]any{"keys": []map[string]any{cases[0].key, good}})
	ks, err := parseJWKS(doc)
	if err != nil || len(ks.all) != 1 || ks.all[0].kid != "good" {
		t.Fatalf("one bad key took the set down: %v %v", ks, err)
	}
}

// TestJWKSDocumentRejections covers the document itself rather than the
// keys in it.
func TestJWKSDocumentRejections(t *testing.T) {
	for _, doc := range []string{"", "{", "null", "[]", `{"keys":"none"}`, `{"keys":{}}`} {
		if _, err := parseJWKS([]byte(doc)); err == nil && doc != "null" {
			t.Errorf("parseJWKS(%q) was accepted", doc)
		}
	}
	// An empty set parses and holds nothing: a provider between
	// rotations is not a parse error.
	ks, err := parseJWKS([]byte(`{"keys":[]}`))
	if err != nil || len(ks.all) != 0 {
		t.Fatalf("an empty key set: %v %v", ks, err)
	}
	// Over the size ceiling.
	big := `{"keys":[` + strings.Repeat(`{"kty":"oct"},`, 100000) + `{"kty":"oct"}]}`
	if len(big) <= MaxJWKSBytes {
		t.Skipf("the padding document is only %d bytes", len(big))
	}
	if _, err := parseJWKS([]byte(big)); err == nil {
		t.Fatal("a key set over the ceiling was parsed")
	}
}

// TestKeySetIsBounded requires a key set with thousands of keys to stop
// at the cap. Every key in it is tried when a token carries no kid, so
// an unbounded set is work an unauthenticated request can ask for.
func TestKeySetIsBounded(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	entry := map[string]any{"kty": "RSA", "n": b64u(k.N.Bytes()), "e": b64u(big.NewInt(65537).Bytes())}
	keys := make([]map[string]any, 0, 1000)
	for i := 0; i < 1000; i++ {
		e := map[string]any{}
		for kk, vv := range entry {
			e[kk] = vv
		}
		e["kid"] = fmt.Sprintf("k%d", i)
		keys = append(keys, e)
	}
	doc, _ := json.Marshal(map[string]any{"keys": keys})
	ks, err := parseJWKS(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks.all) > 256 {
		t.Fatalf("the key set holds %d keys", len(ks.all))
	}
}

// TestProviderAccessors covers the small methods the management views
// and the filter name read.
func TestProviderAccessors(t *testing.T) {
	rs, _, _, _ := keys(t)
	dir := t.TempDir()
	p := provider(t, config.JWTProvider{
		Name: "idp", Audiences: []string{"api"}, JWKSFile: writeJWKS(t, dir, rs),
		Algorithms: []string{"RS256"},
	})
	if p.Name() != "idp" {
		t.Fatalf("Name %q", p.Name())
	}
	if p.Config().Issuer != "https://issuer.test/" {
		t.Fatalf("Config %+v", p.Config())
	}
	if p.KeyCount() != 1 {
		t.Fatalf("KeyCount %d", p.KeyCount())
	}
	calls, errs, hits, cached := p.IntrospectionStats()
	if calls|errs|hits != 0 || cached != 0 {
		t.Fatalf("introspection stats on a provider that does not introspect: %d %d %d %d", calls, errs, hits, cached)
	}
	// Start and Stop are the refresh loop's lifecycle; starting a
	// file-backed provider and stopping it must not block or panic.
	p.Start()
	p.Stop()
	p.Stop()
}

// TestIntrospectorConstruction covers the ways an introspection
// configuration can be wrong at load, which is where an operator wants
// to hear about it rather than on the first request.
func TestIntrospectorConstruction(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := config.TokenIntrospection{URL: "https://as.test/introspect", ClientID: "rp",
		ClientSecretFile: secret, Timeout: config.Duration(time.Second)}

	if _, err := newIntrospector(base); err != nil {
		t.Fatalf("a good configuration: %v", err)
	}
	missing := base
	missing.ClientSecretFile = filepath.Join(dir, "absent")
	if _, err := newIntrospector(missing); err == nil {
		t.Fatal("a missing client secret was accepted")
	}
	badCA := base
	badCA.CAFile = notPEM
	if _, err := newIntrospector(badCA); err == nil {
		t.Fatal("a ca_file with no certificates was accepted")
	}
	absentCA := base
	absentCA.CAFile = filepath.Join(dir, "absent.pem")
	if _, err := newIntrospector(absentCA); err == nil {
		t.Fatal("a missing ca_file was accepted")
	}
}

// TestIntrospectionResponses covers what the authorization server can
// answer. An endpoint that is confused must never produce an
// authenticated request: the failures are 503 to the client, not a
// pass.
func TestIntrospectionResponses(t *testing.T) {
	var body atomic.Value
	body.Store(`{"active":true,"sub":"alice","aud":"api","iss":"https://as.test","exp":9999999999}`)
	var status atomic.Int64
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if c := status.Load(); c != 200 {
			w.WriteHeader(int(c))
			return
		}
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()

	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(config.JWTProvider{
		Name: "as", Issuer: "https://as.test", Audiences: []string{"api"},
		ClockSkew: config.Duration(30 * time.Second), Source: "bearer",
		Introspection: &config.TokenIntrospection{URL: srv.URL, ClientID: "rp",
			ClientSecretFile: secret, Timeout: config.Duration(2 * time.Second)},
	}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)

	if _, err := p.Verify("opaque-1"); err != nil {
		t.Fatalf("an active token: %v", err)
	}

	cases := []struct {
		name   string
		body   string
		status int64
		want   error
	}{
		{"inactive", `{"active":false}`, 200, ErrInactive},
		{"no active field", `{"sub":"alice"}`, 200, ErrInactive},
		{"not json", `<html>error</html>`, 200, ErrIntrospection},
		{"empty body", ``, 200, ErrIntrospection},
		{"json null", `null`, 200, ErrIntrospection},
		{"json array", `["alice"]`, 200, ErrIntrospection},
		{"server error", `{"active":true}`, 500, ErrIntrospection},
		{"unauthorized", `{"active":true}`, 401, ErrIntrospection},
		{"wrong issuer", `{"active":true,"sub":"a","aud":"api","iss":"https://elsewhere.test","exp":9999999999}`, 200, ErrIssuer},
		{"wrong audience", `{"active":true,"sub":"a","aud":"other","iss":"https://as.test","exp":9999999999}`, 200, ErrAudience},
		{"expired", `{"active":true,"sub":"a","aud":"api","iss":"https://as.test","exp":1}`, 200, ErrExpired},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body.Store(tc.body)
			status.Store(tc.status)
			_, err := p.Verify(fmt.Sprintf("opaque-case-%d", i))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestIntrospectionIsBounded requires the in-flight limit to hold: the
// endpoint is a third party on the request path, and an unbounded fan
// out would turn a burst of unauthenticated requests into a burst
// against somebody else's server, with this process holding every
// goroutine while it waits.
func TestIntrospectionIsBounded(t *testing.T) {
	release := make(chan struct{})
	var inflight, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		inflight.Add(-1)
		_, _ = io.WriteString(w, `{"active":true,"sub":"a","aud":"api","iss":"https://as.test","exp":9999999999}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(config.JWTProvider{
		Name: "as", Issuer: "https://as.test", Audiences: []string{"api"},
		ClockSkew: config.Duration(30 * time.Second), Source: "bearer",
		Introspection: &config.TokenIntrospection{URL: srv.URL, ClientID: "rp",
			ClientSecretFile: secret, Timeout: config.Duration(10 * time.Second)},
	}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)

	done := make(chan struct{})
	for i := 0; i < 64; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			_, _ = p.Verify(fmt.Sprintf("opaque-%d", i))
		}(i)
	}
	// Let them pile up, then let the endpoint answer.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && peak.Load() < int64(maxIntrospectionInflight) {
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	for i := 0; i < 64; i++ {
		<-done
	}
	if got := peak.Load(); got > int64(maxIntrospectionInflight) {
		t.Fatalf("%d calls were in flight at once, the bound is %d", got, maxIntrospectionInflight)
	}
}
