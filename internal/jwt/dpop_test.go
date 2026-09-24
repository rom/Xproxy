package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

// proofKey is a client's DPoP key pair with the two things a proof needs
// from it: the public JWK to embed, and its thumbprint for the token.
type proofKey struct {
	s signer
}

func newProofKey(t *testing.T) proofKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return proofKey{s: signer{alg: "ES256", key: k}}
}

// publicJWK is the key as a proof carries it: public members only, and no
// kid, because a proof identifies its key by value.
func (p proofKey) publicJWK() map[string]any {
	j := p.s.jwk()
	delete(j, "kid")
	delete(j, "use")
	return j
}

// jkt is the RFC 7638 thumbprint the authorization server would put in
// the token's cnf claim.
func (p proofKey) jkt(t *testing.T) string {
	t.Helper()
	j := p.publicJWK()
	canon := `{"crv":"` + j["crv"].(string) + `","kty":"EC","x":"` + j["x"].(string) + `","y":"` + j["y"].(string) + `"}`
	sum := sha256.Sum256([]byte(canon))
	return b64u(sum[:])
}

// proof signs a DPoP proof with whatever header and claims a case needs.
func (p proofKey) proof(t *testing.T, hdr, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": p.s.alg, "typ": "dpop+jwt", "jwk": p.publicJWK()}
	for k, v := range hdr {
		if v == nil {
			delete(h, k)
			continue
		}
		h[k] = v
	}
	c := map[string]any{}
	for k, v := range claims {
		if v == nil {
			continue
		}
		c[k] = v
	}
	hb, _ := json.Marshal(h)
	pb, _ := json.Marshal(c)
	signed := b64u(hb) + "." + b64u(pb)
	digest := sha256.Sum256([]byte(signed))
	k := p.s.key.(*ecdsa.PrivateKey)
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return signed + "." + b64u(sig)
}

// ath is the access token hash a proof must carry beside a bound token.
func ath(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64u(sum[:])
}

// dpopProvider is a provider whose tokens are ES256 and whose DPoP policy
// is the one a case wants.
func dpopProvider(t *testing.T, mode string) (*Provider, signer) {
	t.Helper()
	dir := t.TempDir()
	_, _, es, _ := keys(t)
	p := provider(t, config.JWTProvider{
		Audiences:  []string{"api"},
		Algorithms: []string{"ES256"},
		JWKSFile:   writeJWKS(t, dir, es),
		DPoP:       &config.DPoP{Mode: mode},
	})
	return p, es
}

// run puts one request through the filter.
func run(t *testing.T, p *Provider, method, target, token, proof string) filter.Verdict {
	t.Helper()
	r, _ := http.NewRequest(method, target, nil)
	if token != "" {
		r.Header.Set("Authorization", "DPoP "+token)
	}
	if proof != "" {
		r.Header.Set("DPoP", proof)
	}
	return p.Filter(true).Begin(t.Context(), nil).Request(r)
}

// A bearer token is a password: whoever holds it is whoever it says. DPoP
// removes that, and the step that removes it is the binding -- the key
// that signed the proof must be the key the authorization server named in
// the token. Everything else in the proof is worthless without it, because
// anybody can generate a key and sign with it.
func TestAStolenBoundTokenIsUselessWithoutTheKey(t *testing.T) {
	p, es := dpopProvider(t, "allow")
	mine, theirs := newProofKey(t), newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": mine.jkt(t)}}))
	now := time.Now().Unix()
	claims := map[string]any{"jti": "1", "htm": "GET", "htu": "http://api.test/orders", "iat": now, "ath": ath(token)}

	// The client that holds the key.
	if v := run(t, p, "GET", "http://api.test/orders", token, mine.proof(t, nil, claims)); v.Deny {
		t.Fatalf("the bound client was refused: %+v", v)
	}
	// Somebody who stole the token and signed with a key of their own.
	claims["jti"] = "2"
	v := run(t, p, "GET", "http://api.test/orders", token, theirs.proof(t, nil, claims))
	if !v.Deny || v.Detail != "dpop_binding" {
		t.Fatalf("a proof signed by another key: %+v, want dpop_binding", v)
	}
	// And somebody who stole the token and sent it as a bearer token,
	// which is the replay the whole mechanism exists to stop.
	v = run(t, p, "GET", "http://api.test/orders", token, "")
	if !v.Deny || v.Detail != "dpop_missing" {
		t.Fatalf("a bound token with no proof: %+v, want dpop_missing", v)
	}
	if v.Headers["WWW-Authenticate"] == "" || !strings.HasPrefix(v.Headers["WWW-Authenticate"], "DPoP ") {
		t.Fatalf("challenge %q, want a DPoP challenge", v.Headers["WWW-Authenticate"])
	}
}

// A proof is made for one request. Moving it to another method, another
// path or another host must not work, or a captured GET becomes a DELETE.
func TestAProofDoesNotFitAnotherRequest(t *testing.T) {
	p, es := dpopProvider(t, "allow")
	k := newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	now := time.Now().Unix()
	base := map[string]any{"htm": "GET", "htu": "http://api.test/orders", "iat": now, "ath": ath(token)}
	with := func(jti string, over map[string]any) string {
		c := map[string]any{"jti": jti}
		for kk, vv := range base {
			c[kk] = vv
		}
		for kk, vv := range over {
			c[kk] = vv
		}
		return k.proof(t, nil, c)
	}
	// The request the proof was made for.
	if v := run(t, p, "GET", "http://api.test/orders", token, with("a", nil)); v.Deny {
		t.Fatalf("the matching request was refused: %+v", v)
	}
	for _, tc := range []struct {
		name, method, target string
		over                 map[string]any
	}{
		{"another method", "DELETE", "http://api.test/orders", nil},
		{"another path", "GET", "http://api.test/admin", nil},
		{"another host", "GET", "http://other.test/orders", nil},
		{"another scheme in htu", "GET", "http://api.test/orders", map[string]any{"htu": "https://api.test/orders"}},
		{"a lower case method", "GET", "http://api.test/orders", map[string]any{"htm": "get"}},
		{"no htu at all", "GET", "http://api.test/orders", map[string]any{"htu": nil}},
		{"no htm at all", "GET", "http://api.test/orders", map[string]any{"htm": nil}},
		{"no jti", "GET", "http://api.test/orders", map[string]any{"jti": nil}},
		{"no iat", "GET", "http://api.test/orders", map[string]any{"iat": nil}},
		{"an old proof", "GET", "http://api.test/orders", map[string]any{"iat": now - 3600}},
		{"a proof from the future", "GET", "http://api.test/orders", map[string]any{"iat": now + 3600}},
		{"another token's hash", "GET", "http://api.test/orders", map[string]any{"ath": ath("somebody else's token")}},
		{"no ath", "GET", "http://api.test/orders", map[string]any{"ath": nil}},
	} {
		c := map[string]any{"jti": tc.name}
		for kk, vv := range base {
			c[kk] = vv
		}
		for kk, vv := range tc.over {
			c[kk] = vv
		}
		if vv, ok := tc.over["jti"]; ok && vv == nil {
			delete(c, "jti")
		}
		v := run(t, p, tc.method, tc.target, token, k.proof(t, nil, c))
		if !v.Deny || v.Detail != "dpop_proof" {
			t.Errorf("%s: %+v, want dpop_proof", tc.name, v)
		}
	}
	// The query string is deliberately not compared: a client signs the
	// path, and the query is not what a replay changes.
	if v := run(t, p, "GET", "http://api.test/orders?page=2", token, with("q", nil)); v.Deny {
		t.Fatalf("a query string broke the htu comparison: %+v", v)
	}
}

// Replay is what the jti is for: the same proof twice is once.
func TestTheSameProofTwiceIsOnce(t *testing.T) {
	p, es := dpopProvider(t, "allow")
	k := newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	proof := k.proof(t, nil, map[string]any{
		"jti": "only-once", "htm": "GET", "htu": "http://api.test/orders",
		"iat": time.Now().Unix(), "ath": ath(token)})
	if v := run(t, p, "GET", "http://api.test/orders", token, proof); v.Deny {
		t.Fatalf("the first use was refused: %+v", v)
	}
	v := run(t, p, "GET", "http://api.test/orders", token, proof)
	if !v.Deny || v.Detail != "dpop_replay" {
		t.Fatalf("the second use: %+v, want dpop_replay", v)
	}
	// A fresh jti works, so this is replay protection and not a
	// one-request-per-token bound.
	fresh := k.proof(t, nil, map[string]any{
		"jti": "another", "htm": "GET", "htu": "http://api.test/orders",
		"iat": time.Now().Unix(), "ath": ath(token)})
	if v := run(t, p, "GET", "http://api.test/orders", token, fresh); v.Deny {
		t.Fatalf("a fresh proof was refused after a replay: %+v", v)
	}
}

// A proof refused for another reason must not spend its jti: otherwise a
// client that gets the clock wrong once cannot retry with the same proof
// after fixing nothing, and an attacker can burn a victim's identifiers.
func TestARefusedProofDoesNotSpendItsIdentifier(t *testing.T) {
	p, es := dpopProvider(t, "allow")
	k, other := newProofKey(t), newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	claims := map[string]any{"jti": "shared", "htm": "GET", "htu": "http://api.test/orders",
		"iat": time.Now().Unix(), "ath": ath(token)}
	// Somebody else's key: refused on the binding, before the jti is spent.
	if v := run(t, p, "GET", "http://api.test/orders", token, other.proof(t, nil, claims)); v.Detail != "dpop_binding" {
		t.Fatalf("expected a binding refusal, got %+v", v)
	}
	// The real client's proof with the same identifier still works.
	if v := run(t, p, "GET", "http://api.test/orders", token, k.proof(t, nil, claims)); v.Deny {
		t.Fatalf("the identifier was spent by a refused proof: %+v", v)
	}
}

// The header of a proof is as much of the proof as its claims: a type that
// is not dpop+jwt lets another JWT the client holds be presented as one, a
// symmetric algorithm is a signature the verifier could have written, and
// a key with private material in it is a client that has sent its secret.
func TestTheProofHeaderIsPartOfTheProof(t *testing.T) {
	p, es := dpopProvider(t, "allow")
	k := newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	claims := func(jti string) map[string]any {
		return map[string]any{"jti": jti, "htm": "GET", "htu": "http://api.test/orders",
			"iat": time.Now().Unix(), "ath": ath(token)}
	}
	private := k.publicJWK()
	private["d"] = b64u([]byte("0123456789012345678901234567890a"))
	for _, tc := range []struct {
		name string
		hdr  map[string]any
	}{
		{"typ JWT", map[string]any{"typ": "JWT"}},
		{"no typ", map[string]any{"typ": nil}},
		{"no jwk", map[string]any{"jwk": nil}},
		{"alg none", map[string]any{"alg": "none"}},
		{"alg HS256", map[string]any{"alg": "HS256"}},
		{"alg RS256 not in the list", map[string]any{"alg": "RS256"}},
		{"a private key in the header", map[string]any{"jwk": private}},
	} {
		v := run(t, p, "GET", "http://api.test/orders", token, k.proof(t, tc.hdr, claims(tc.name)))
		if !v.Deny || v.Detail != "dpop_proof" {
			t.Errorf("%s: %+v, want dpop_proof", tc.name, v)
		}
	}
	// And typ is compared case-insensitively, because the media type is.
	if v := run(t, p, "GET", "http://api.test/orders", token, k.proof(t, map[string]any{"typ": "DPoP+JWT"}, claims("case"))); v.Deny {
		t.Fatalf("a differently cased typ was refused: %+v", v)
	}
}

// Structural nonsense is refused rather than guessed at.
func TestAProofThatIsNotAJWTIsRefused(t *testing.T) {
	p, es := dpopProvider(t, "allow")
	k := newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	good := k.proof(t, nil, map[string]any{"jti": "x", "htm": "GET", "htu": "http://api.test/orders",
		"iat": time.Now().Unix(), "ath": ath(token)})
	parts := strings.Split(good, ".")
	for _, tc := range []struct{ name, proof string }{
		{"empty", " "},
		{"two parts", parts[0] + "." + parts[1]},
		{"four parts", good + ".x"},
		{"header not base64", "!!!." + parts[1] + "." + parts[2]},
		{"header not json", b64u([]byte("not json")) + "." + parts[1] + "." + parts[2]},
		{"claims not base64", parts[0] + ".!!!." + parts[2]},
		{"claims not json", parts[0] + "." + b64u([]byte("not json")) + "." + parts[2]},
		{"signature not base64", parts[0] + "." + parts[1] + ".!!!"},
		{"signature of nothing", parts[0] + "." + parts[1] + "." + b64u([]byte("no"))},
		{"a huge proof", strings.Repeat("a", maxProofBytes+1)},
	} {
		v := run(t, p, "GET", "http://api.test/orders", token, tc.proof)
		if !v.Deny || v.Detail != "dpop_proof" {
			t.Errorf("%s: %+v, want dpop_proof", tc.name, v)
		}
	}
}

// allow leaves an ordinary bearer token alone: a token nobody constrained
// is not one this mechanism protects, and refusing it would make turning
// DPoP on a migration rather than a setting.
func TestAllowDoesNotRefuseAnUnboundToken(t *testing.T) {
	p, es := dpopProvider(t, "allow")
	token := es.sign(t, base(nil))
	if v := run(t, p, "GET", "http://api.test/orders", token, ""); v.Deny {
		t.Fatalf("an unbound token was refused under allow: %+v", v)
	}
	// require says only constrained tokens are accepted here.
	q, es2 := dpopProvider(t, "require")
	v := run(t, q, "GET", "http://api.test/orders", es2.sign(t, base(nil)), "")
	if !v.Deny || v.Detail != "dpop_unbound" {
		t.Fatalf("require accepted an unbound token: %+v", v)
	}
	// And a constrained one with its proof still works under require.
	k := newProofKey(t)
	bound := es2.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	proof := k.proof(t, nil, map[string]any{"jti": "r", "htm": "GET", "htu": "http://api.test/orders",
		"iat": time.Now().Unix(), "ath": ath(bound)})
	if v := run(t, q, "GET", "http://api.test/orders", bound, proof); v.Deny {
		t.Fatalf("require refused a bound token with its proof: %+v", v)
	}
}

// off is off: nothing is verified and nothing is refused, which is what
// makes the setting safe to leave alone.
func TestOffVerifiesNothing(t *testing.T) {
	p, es := dpopProvider(t, "off")
	k := newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	// A bound token with no proof, which allow would refuse.
	r, _ := http.NewRequest("GET", "http://api.test/orders", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if v := p.Filter(true).Begin(t.Context(), nil).Request(r); v.Deny {
		t.Fatalf("off refused a request: %+v", v)
	}
	// And the DPoP authorization scheme is not read when DPoP is off, so
	// such a request has no token at all rather than an unchecked one.
	v := run(t, p, "GET", "http://api.test/orders", token, "")
	if !v.Deny || v.Detail != "missing" {
		t.Fatalf("the DPoP scheme was read with dpop off: %+v", v)
	}
}

// The proof belongs to this hop. Forwarding it invites the backend to
// verify it against its own URI, which will not match, and leaves a signed
// statement about this request in somebody else's log.
func TestTheProofDoesNotReachTheBackend(t *testing.T) {
	p, es := dpopProvider(t, "allow")
	k := newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	proof := k.proof(t, nil, map[string]any{"jti": "fwd", "htm": "GET", "htu": "http://api.test/orders",
		"iat": time.Now().Unix(), "ath": ath(token)})
	r, _ := http.NewRequest("GET", "http://api.test/orders", nil)
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", proof)
	if v := p.Filter(true).Begin(t.Context(), nil).Request(r); v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	if r.Header.Get("DPoP") != "" {
		t.Error("the proof was forwarded to the backend")
	}
}

// The thumbprint is the whole specification of RFC 7638: the member set
// and their order. Two implementations that disagree about either compute
// different thumbprints and no token ever verifies.
func TestTheThumbprintIsRFC7638(t *testing.T) {
	// The example key and thumbprint from RFC 7638 section 3.1.
	k := &jwk{Kty: "RSA",
		N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E: "AQAB"}
	got, err := thumbprint(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %q, want the value RFC 7638 prints", got)
	}
	// An incomplete key has no thumbprint rather than a thumbprint of the
	// empty string, which would be one every incomplete key shares.
	for _, bad := range []*jwk{
		{Kty: "RSA", N: "x"}, {Kty: "RSA", E: "x"},
		{Kty: "EC", Crv: "P-256", X: "x"}, {Kty: "EC", X: "x", Y: "y"},
		{Kty: "OKP", Crv: "Ed25519"}, {Kty: "oct", K: "x"},
	} {
		if _, err := thumbprint(bad); err == nil {
			t.Errorf("%+v got a thumbprint", bad)
		}
	}
}

// The replay table is bounded, because the identifiers come from clients.
// Over the bound it drops entries rather than growing, and it keeps
// admitting new ones -- a table that refused everything once full would be
// a denial of service a client could trigger.
func TestTheReplayTableIsBoundedAndKeepsWorking(t *testing.T) {
	c := newReplayCache(100)
	now := time.Now()
	for i := 0; i < 500; i++ {
		if !c.admit(string(rune(i))+"x", now.Add(time.Minute)) {
			t.Fatalf("entry %d was refused as a replay", i)
		}
		if c.Len() > 100 {
			t.Fatalf("table grew to %d, want at most 100", c.Len())
		}
	}
	// And within the bound it still catches a replay.
	if !c.admit("fresh", now.Add(time.Minute)) {
		t.Fatal("a new identifier was refused")
	}
	if c.admit("fresh", now.Add(time.Minute)) {
		t.Fatal("a replay was admitted")
	}
}

// external_url is the answer behind another proxy, and the reason the
// scheme is never taken from a header: a client that can set
// X-Forwarded-Proto could otherwise choose which URI its proof must match.
func TestExternalURLDecidesTheAuthorityTheProofMustMatch(t *testing.T) {
	dir := t.TempDir()
	_, _, es, _ := keys(t)
	p := provider(t, config.JWTProvider{
		Audiences:  []string{"api"},
		Algorithms: []string{"ES256"},
		JWKSFile:   writeJWKS(t, dir, es),
		DPoP:       &config.DPoP{Mode: "allow", ExternalURL: "https://public.example/"},
	})
	k := newProofKey(t)
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": k.jkt(t)}}))
	claims := func(jti, htu string) map[string]any {
		return map[string]any{"jti": jti, "htm": "GET", "htu": htu, "iat": time.Now().Unix(), "ath": ath(token)}
	}
	// The client signed the URI it used, which is the public one.
	if v := run(t, p, "GET", "http://internal.local/orders", token, k.proof(t, nil, claims("a", "https://public.example/orders"))); v.Deny {
		t.Fatalf("the public URI was refused: %+v", v)
	}
	// The internal URI this process actually saw is not what the client
	// signed, and a client claiming it is not believed.
	v := run(t, p, "GET", "http://internal.local/orders", token, k.proof(t, nil, claims("b", "http://internal.local/orders")))
	if !v.Deny || v.Detail != "dpop_proof" {
		t.Fatalf("the internal URI was accepted: %+v", v)
	}
	// A header cannot move the authority.
	r, _ := http.NewRequest("GET", "http://internal.local/orders", nil)
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("DPoP", k.proof(t, nil, claims("c", "http://internal.local/orders")))
	if v := p.Filter(true).Begin(t.Context(), nil).Request(r); !v.Deny {
		t.Fatal("X-Forwarded-Proto chose the URI the proof had to match")
	}
	// And a default port written out is the same authority.
	if v := run(t, p, "GET", "http://internal.local/orders", token, k.proof(t, nil, claims("d", "https://public.example:443/orders"))); v.Deny {
		t.Fatalf("an explicit default port was refused: %+v", v)
	}
}

// A symmetric algorithm in the policy is a policy that verifies proofs the
// verifier could have written itself. It is refused at load, where an
// operator sees it.
func TestASymmetricAlgorithmIsNotAProof(t *testing.T) {
	dir := t.TempDir()
	_, _, es, _ := keys(t)
	_, err := NewProvider(config.JWTProvider{
		Name: "p", Issuer: "https://issuer.test/", Audiences: []string{"api"},
		Algorithms: []string{"ES256"}, JWKSFile: writeJWKS(t, dir, es),
		DPoP: &config.DPoP{Mode: "allow", Algorithms: []string{"HS256"}},
	}, nolog)
	if err == nil || !strings.Contains(err.Error(), "asymmetric") {
		t.Fatalf("error %v, want one about an asymmetric algorithm", err)
	}
}
