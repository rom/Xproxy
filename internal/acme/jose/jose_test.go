package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// This package is the signature on every request the ACME client makes
// and the key authorisation a certificate authority checks. A forgery
// here is a certificate somebody else can get for a name they do not
// own, so the tests are about what must not verify.

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignAndVerify(t *testing.T) {
	k := key(t)
	payload := []byte(`{"termsOfServiceAgreed":true}`)
	raw, err := Sign(k, "", "nonce-1", "https://ca.example/new-account", payload)
	if err != nil {
		t.Fatal(err)
	}
	header, got, err := Verify(raw, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload %q", got)
	}
	if header["alg"] != "ES256" || header["nonce"] != "nonce-1" || header["url"] != "https://ca.example/new-account" {
		t.Fatalf("header %v", header)
	}
	// Without a key id the public key travels with the request; with one
	// it does not, because the account URL already names the key.
	if _, ok := header["jwk"]; !ok {
		t.Error("the first request carries no key")
	}
	if _, ok := header["kid"]; ok {
		t.Error("the first request carries a key id")
	}
	raw, err = Sign(k, "https://ca.example/acct/1", "nonce-2", "https://ca.example/order", payload)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err = Verify(raw, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if header["kid"] != "https://ca.example/acct/1" {
		t.Errorf("kid %v", header["kid"])
	}
	if _, ok := header["jwk"]; ok {
		t.Error("a request with a key id still carries the key")
	}
	// A POST-as-GET carries no payload at all, which is an empty string
	// rather than a missing member.
	raw, err = Sign(k, "https://ca.example/acct/1", "nonce-3", "https://ca.example/order/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env["payload"] != "" {
		t.Errorf("an empty payload became %q", env["payload"])
	}
	if _, body, err := Verify(raw, &k.PublicKey); err != nil || len(body) != 0 {
		t.Errorf("POST-as-GET: %q %v", body, err)
	}
	// Every field of the envelope is base64url without padding.
	for name, v := range env {
		if strings.ContainsAny(v, "+/=") {
			t.Errorf("%s is not base64url: %q", name, v)
		}
	}
}

func TestVerifyRejections(t *testing.T) {
	k, other := key(t), key(t)
	payload := []byte(`{"a":1}`)
	raw, err := Sign(k, "kid", "nonce", "https://ca.example/x", payload)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	rebuild := func(f func(map[string]string)) []byte {
		m := map[string]string{}
		for k, v := range env {
			m[k] = v
		}
		f(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	flip := func(s string) string {
		b := []byte(s)
		i := len(b) / 2
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	cases := map[string][]byte{
		"empty":                               nil,
		"not json":                            []byte("<html>"),
		"a json array":                        []byte("[1,2,3]"),
		"an empty object":                     []byte("{}"),
		"no signature":                        rebuild(func(m map[string]string) { delete(m, "signature") }),
		"no protected header":                 rebuild(func(m map[string]string) { delete(m, "protected") }),
		"a tampered payload":                  rebuild(func(m map[string]string) { m["payload"] = B64([]byte(`{"a":2}`)) }),
		"a tampered header":                   rebuild(func(m map[string]string) { m["protected"] = B64([]byte(`{"alg":"none"}`)) }),
		"a flipped signature":                 rebuild(func(m map[string]string) { m["signature"] = flip(m["signature"]) }),
		"a truncated signature":               rebuild(func(m map[string]string) { m["signature"] = m["signature"][:40] }),
		"an empty signature":                  rebuild(func(m map[string]string) { m["signature"] = "" }),
		"a zero signature":                    rebuild(func(m map[string]string) { m["signature"] = B64(make([]byte, 64)) }),
		"a longer signature":                  rebuild(func(m map[string]string) { m["signature"] = B64(make([]byte, 65)) }),
		"signature not base64":                rebuild(func(m map[string]string) { m["signature"] = "!!!!" }),
		"protected not base64":                rebuild(func(m map[string]string) { m["protected"] = "!!!!" }),
		"payload not base64":                  rebuild(func(m map[string]string) { m["payload"] = "!!!!" }),
		"a protected header that is not json": rebuild(func(m map[string]string) { m["protected"] = B64([]byte("not json")) }),
		"a protected header that is a string": rebuild(func(m map[string]string) { m["protected"] = B64([]byte(`"a string"`)) }),
		"padded base64":                       rebuild(func(m map[string]string) { m["signature"] += "==" }),
	}
	for name, b := range cases {
		if h, p, err := Verify(b, &k.PublicKey); err == nil {
			t.Errorf("%s verified: header %v payload %q", name, h, p)
		}
	}
	// Another account's key does not verify this request.
	if _, _, err := Verify(raw, &other.PublicKey); err == nil {
		t.Error("another key verified the request")
	}
	// A signature is bound to its own protected header and payload: two
	// valid envelopes cannot exchange parts.
	raw2, err := Sign(k, "kid", "nonce", "https://ca.example/y", payload)
	if err != nil {
		t.Fatal(err)
	}
	var env2 map[string]string
	if err := json.Unmarshal(raw2, &env2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(rebuild(func(m map[string]string) { m["signature"] = env2["signature"] }), &k.PublicKey); err == nil {
		t.Error("the other request's signature verified this one")
	}
	if _, _, err := Verify(rebuild(func(m map[string]string) { m["protected"] = env2["protected"] }), &k.PublicKey); err == nil {
		t.Error("the other request's header verified with this signature")
	}
}

func TestThumbprintAndKeyAuthorization(t *testing.T) {
	k := key(t)
	tp := Thumbprint(&k.PublicKey)
	// The thumbprint is a SHA-256 in base64url: 43 characters, no
	// padding, no characters that need escaping in a URL or a file name.
	if len(tp) != 43 {
		t.Fatalf("thumbprint %q is %d characters", tp, len(tp))
	}
	if strings.ContainsAny(tp, "+/=.") {
		t.Errorf("thumbprint %q is not base64url", tp)
	}
	if tp != Thumbprint(&k.PublicKey) {
		t.Error("the thumbprint is not stable")
	}
	if tp == Thumbprint(&key(t).PublicKey) {
		t.Error("two keys share a thumbprint")
	}
	// It is the hash of the RFC 7638 form: the four required members, in
	// lexicographic order, with no whitespace. Recomputed here rather
	// than taken from the code under test.
	j := JWK(&k.PublicKey)
	want := B64(func() []byte {
		s := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + j["x"] + `","y":"` + j["y"] + `"}`))
		return s[:]
	}())
	if tp != want {
		t.Errorf("thumbprint %q want %q", tp, want)
	}
	// A key authorisation is token.thumbprint, which is what the CA
	// fetches and compares.
	ka := KeyAuthorization("tok-en", &k.PublicKey)
	if ka != "tok-en."+tp {
		t.Errorf("key authorisation %q", ka)
	}
	if n := strings.Count(ka, "."); n != 1 {
		t.Errorf("key authorisation has %d dots: %q", n, ka)
	}
}

func TestJWKCoordinatesAreFixedWidth(t *testing.T) {
	// A coordinate shorter than 32 bytes must be left-padded, or this
	// implementation's thumbprint differs from every other one for the
	// same key. Generated keys rarely have a short coordinate, so the
	// padding is checked over many keys and then forced with a crafted
	// one.
	for i := 0; i < 50; i++ {
		k := key(t)
		j := JWK(&k.PublicKey)
		for _, m := range []string{"x", "y"} {
			b, err := base64.RawURLEncoding.DecodeString(j[m])
			if err != nil {
				t.Fatalf("%s is not base64url: %v", m, err)
			}
			if len(b) != 32 {
				t.Fatalf("%s is %d bytes", m, len(b))
			}
		}
		if j["crv"] != "P-256" || j["kty"] != "EC" {
			t.Fatalf("jwk %v", j)
		}
		if len(j) != 4 {
			t.Fatalf("the jwk carries %d members: %v", len(j), j)
		}
	}
	// A public key whose X is small still renders as 32 bytes.
	small := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)}
	j := JWK(small)
	b, err := base64.RawURLEncoding.DecodeString(j["x"])
	if err != nil || len(b) != 32 || b[31] != 1 {
		t.Fatalf("a small coordinate rendered as %x (%v)", b, err)
	}
}

func TestPublicKeyFromJWK(t *testing.T) {
	k := key(t)
	j := JWK(&k.PublicKey)
	m := map[string]any{"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]}
	pub, err := PublicKeyFromJWK(m)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(k.X) != 0 || pub.Y.Cmp(k.Y) != 0 {
		t.Fatal("the key did not round trip")
	}
	with := func(f func(map[string]any)) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			out[k] = v
		}
		f(out)
		return out
	}
	bad := map[string]map[string]any{
		"empty":                    {},
		"no x":                     with(func(o map[string]any) { delete(o, "x") }),
		"no y":                     with(func(o map[string]any) { delete(o, "y") }),
		"x is a number":            with(func(o map[string]any) { o["x"] = 1.0 }),
		"y is an object":           with(func(o map[string]any) { o["y"] = map[string]any{} }),
		"x is not base64":          with(func(o map[string]any) { o["x"] = "!!!!" }),
		"y is not base64":          with(func(o map[string]any) { o["y"] = "!!!!" }),
		"x is padded":              with(func(o map[string]any) { o["x"] = j["x"] + "==" }),
		"coordinates swapped":      with(func(o map[string]any) { o["x"], o["y"] = j["y"], j["x"] }),
		"a point not on the curve": with(func(o map[string]any) { o["x"] = B64(make([]byte, 32)) }),
		"the point at infinity":    with(func(o map[string]any) { o["x"], o["y"] = B64(make([]byte, 32)), B64(make([]byte, 32)) }),
		"oversize coordinates":     with(func(o map[string]any) { o["x"], o["y"] = B64(make([]byte, 1024)), B64(make([]byte, 1024)) }),
	}
	for name, in := range bad {
		if pub, err := PublicKeyFromJWK(in); err == nil {
			t.Errorf("%s was accepted: %v", name, pub)
		}
	}
	// A key parsed out of a JWK verifies what the private key signed,
	// which is the path a CA takes for a new account.
	raw, err := Sign(k, "", "nonce", "https://ca.example/new-account", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := Verify(raw, pub)
	if err != nil {
		t.Fatal(err)
	}
	embedded, ok := header["jwk"].(map[string]any)
	if !ok {
		t.Fatal("the embedded key is not an object")
	}
	fromHeader, err := PublicKeyFromJWK(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if !fromHeader.Equal(&k.PublicKey) {
		t.Fatal("the embedded key is not the signing key")
	}
}

func TestB64(t *testing.T) {
	for _, b := range [][]byte{nil, {}, {0}, {0xff}, {0xfb, 0xff, 0xfe}, make([]byte, 64)} {
		s := B64(b)
		if strings.ContainsAny(s, "+/=") {
			t.Errorf("B64(%x) = %q is not base64url", b, s)
		}
		back, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || string(back) != string(b) {
			t.Errorf("B64(%x) did not round trip: %q %v", b, s, err)
		}
	}
	// The constants the challenge paths are built from.
	if !strings.HasPrefix(HTTP01Path, "/.well-known/") || !strings.HasSuffix(HTTP01Path, "/") {
		t.Errorf("HTTP01Path %q", HTTP01Path)
	}
	if ALPNProto != "acme-tls/1" {
		t.Errorf("ALPNProto %q", ALPNProto)
	}
}
