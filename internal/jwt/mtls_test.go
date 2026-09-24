package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

// clientCert is a client certificate and the thumbprint an authorization
// server would record for it.
type clientCert struct {
	cert *x509.Certificate
}

func newClientCert(t *testing.T, cn string) clientCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return clientCert{cert: cert}
}

// thumb is cnf["x5t#S256"]: the base64url SHA-256 of the DER.
func (c clientCert) thumb() string { return certThumbprint(c.cert.Raw) }

// header is the certificate as RFC 9440 carries it.
func (c clientCert) header() string {
	return ":" + base64.StdEncoding.EncodeToString(c.cert.Raw) + ":"
}

// certProvider is a provider whose tokens are ES256 and whose certificate
// binding is the one a case wants.
func certProvider(t *testing.T, mode string, forwarded bool) (*Provider, signer) {
	t.Helper()
	dir := t.TempDir()
	_, _, es, _ := keys(t)
	p := provider(t, config.JWTProvider{
		Audiences:          []string{"api"},
		Algorithms:         []string{"ES256"},
		JWKSFile:           writeJWKS(t, dir, es),
		CertificateBinding: &config.CertificateBinding{Mode: mode, TrustForwardedHeader: forwarded},
	})
	return p, es
}

// present puts one request through the filter with a client certificate
// on the connection, a forwarded one in the header, or neither.
func present(t *testing.T, p *Provider, token string, onConnection *clientCert, forwarded *clientCert, trustedPeer bool) filter.Verdict {
	t.Helper()
	r, _ := http.NewRequest(http.MethodGet, "https://api.test/orders", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if onConnection != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{onConnection.cert}}
	}
	if forwarded != nil {
		r.Header.Set("Client-Cert", forwarded.header())
	}
	return p.Filter(true).Begin(t.Context(), &filter.Info{TrustedPeer: trustedPeer}).Request(r)
}

func boundTo(t *testing.T, es signer, c clientCert) string {
	t.Helper()
	return es.sign(t, base(map[string]any{"cnf": map[string]any{"x5t#S256": c.thumb()}}))
}

// The point of RFC 8705: the token is only usable on the connection whose
// certificate it names. A token lifted out of a log is worth nothing
// anywhere else, and that is the only claim being made here.
func TestAStolenBoundTokenIsUselessOnAnotherConnection(t *testing.T) {
	p, es := certProvider(t, "allow", false)
	mine, theirs := newClientCert(t, "client"), newClientCert(t, "thief")
	token := boundTo(t, es, mine)

	if v := present(t, p, token, &mine, nil, false); v.Deny {
		t.Fatalf("the bound client was refused: %+v", v)
	}
	v := present(t, p, token, &theirs, nil, false)
	if !v.Deny || v.Detail != "cert_binding" {
		t.Fatalf("a bound token on another certificate: %+v, want cert_binding", v)
	}
	// And presented with no certificate at all, which is what a token
	// stolen out of a log arrives as.
	v = present(t, p, token, nil, nil, false)
	if !v.Deny || v.Detail != "cert_missing" {
		t.Fatalf("a bound token with no certificate: %+v, want cert_missing", v)
	}
	if got := v.Headers["WWW-Authenticate"]; !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("challenge %q", got)
	}
}

// allow leaves an ordinary bearer token alone, which is what makes it
// safe to turn on before every client is issuing bound tokens.
func TestAllowDoesNotRefuseATokenWithNoCertificateBinding(t *testing.T) {
	p, es := certProvider(t, "allow", false)
	token := es.sign(t, base(nil))
	if v := present(t, p, token, nil, nil, false); v.Deny {
		t.Fatalf("an unbound token under allow: %+v", v)
	}
	// Even with a certificate on the connection: a token that names none
	// is not bound to the one that happens to be there.
	c := newClientCert(t, "client")
	if v := present(t, p, token, &c, nil, false); v.Deny {
		t.Fatalf("an unbound token with a certificate present: %+v", v)
	}
}

// require is the stronger setting: on this route a token that is not
// bound at all is not accepted, because an unbound token is the bearer
// token the binding exists to replace.
func TestRequireRefusesATokenThatIsNotBound(t *testing.T) {
	p, es := certProvider(t, "require", false)
	c := newClientCert(t, "client")
	v := present(t, p, es.sign(t, base(nil)), &c, nil, false)
	if !v.Deny || v.Detail != "cert_unbound" {
		t.Fatalf("an unbound token under require: %+v, want cert_unbound", v)
	}
	if v := present(t, p, boundTo(t, es, c), &c, nil, false); v.Deny {
		t.Fatalf("a bound token under require: %+v", v)
	}
}

func TestOffComparesNothing(t *testing.T) {
	p, es := certProvider(t, "off", false)
	mine, theirs := newClientCert(t, "client"), newClientCert(t, "thief")
	if v := present(t, p, boundTo(t, es, mine), &theirs, nil, false); v.Deny {
		t.Fatalf("with the binding off: %+v", v)
	}
}

// Where TLS is terminated in front, the certificate arrives in a header --
// and a header is only the balancer's word for it. A client that could set
// it would choose which certificate its own token is checked against,
// which is the whole of the check, so it counts only from a peer inside
// trusted_proxies.
func TestAForwardedCertificateCountsOnlyFromATrustedPeer(t *testing.T) {
	p, es := certProvider(t, "allow", true)
	mine := newClientCert(t, "client")
	token := boundTo(t, es, mine)

	if v := present(t, p, token, nil, &mine, true); v.Deny {
		t.Fatalf("a certificate forwarded by a trusted peer: %+v", v)
	}
	v := present(t, p, token, nil, &mine, false)
	if !v.Deny || v.Detail != "cert_missing" {
		t.Fatalf("a certificate forwarded by anybody: %+v, want cert_missing", v)
	}
	// And with the header not trusted by configuration at all, a trusted
	// peer's header is still not read.
	q, es2 := certProvider(t, "allow", false)
	mine2 := newClientCert(t, "client")
	v = present(t, q, boundTo(t, es2, mine2), nil, &mine2, true)
	if !v.Deny || v.Detail != "cert_missing" {
		t.Fatalf("a forwarded certificate without trust_forwarded_header: %+v", v)
	}
}

// A certificate larger than a handshake would have carried is refused
// before it is decoded, which is the only way the bound can be tested:
// this one is a real certificate, and it would otherwise match.
func TestAForwardedCertificateOverTheBoundIsRefused(t *testing.T) {
	p, es := certProvider(t, "allow", true)
	big := newBigClientCert(t)
	if len(big.header()) <= maxCertHeader {
		t.Fatalf("the fixture header is only %d bytes", len(big.header()))
	}
	if _, err := x509.ParseCertificate(big.cert.Raw); err != nil {
		t.Fatalf("the fixture is not a certificate: %v", err)
	}
	v := present(t, p, boundTo(t, es, big), nil, &big, true)
	if !v.Deny || v.Detail != "cert_missing" {
		t.Fatalf("an oversize forwarded certificate: %+v, want cert_missing", v)
	}
}

// newBigClientCert is a valid certificate past the header bound: an
// extension carrying twenty kilobytes, which is how a real one gets that
// large (a long SAN list, an embedded SCT, a stapled response).
func newBigClientCert(t *testing.T) clientCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "large"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: make([]byte, 20<<10)}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return clientCert{cert: cert}
}

// The connection's own certificate is the one that counts. A client that
// sends a Client-Cert header of its own cannot talk the check out of
// looking at the handshake.
func TestTheConnectionsCertificateWinsOverAHeader(t *testing.T) {
	p, es := certProvider(t, "allow", true)
	mine, theirs := newClientCert(t, "client"), newClientCert(t, "thief")
	// A thief with a token bound to somebody else's certificate, its
	// header naming that certificate, on its own connection.
	v := present(t, p, boundTo(t, es, mine), &theirs, &mine, true)
	if !v.Deny || v.Detail != "cert_binding" {
		t.Fatalf("a header naming the certificate the token wants: %+v, want cert_binding", v)
	}
}

func TestAForwardedHeaderThatIsNotACertificateIsNoCertificate(t *testing.T) {
	p, es := certProvider(t, "allow", true)
	mine := newClientCert(t, "client")
	token := boundTo(t, es, mine)
	for _, tc := range []struct{ name, value string }{
		{"empty", ""},
		{"no colons", base64.StdEncoding.EncodeToString(mine.cert.Raw)},
		{"not base64", ":!!!!:"},
		{"not a certificate", ":" + base64.StdEncoding.EncodeToString([]byte("hello")) + ":"},
		{"only colons", "::"},
		{"over the bound", ":" + strings.Repeat("A", maxCertHeader) + ":"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "https://api.test/orders", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			if tc.value != "" {
				r.Header.Set("Client-Cert", tc.value)
			}
			v := p.Filter(true).Begin(t.Context(), &filter.Info{TrustedPeer: true}).Request(r)
			if !v.Deny || v.Detail != "cert_missing" {
				t.Fatalf("%s: %+v, want cert_missing", tc.name, v)
			}
		})
	}
}

// The thumbprint is the SHA-256 of the DER, base64url without padding
// (RFC 8705 section 3.1). A token from a server that pads it is the same
// token, and refusing it would be indistinguishable from an attack in the
// log.
func TestThePaddedThumbprintIsTheSameThumbprint(t *testing.T) {
	p, es := certProvider(t, "allow", false)
	c := newClientCert(t, "client")
	padded := c.thumb()
	for len(padded)%4 != 0 {
		padded += "="
	}
	if padded == c.thumb() {
		t.Skip("this certificate's thumbprint needs no padding")
	}
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"x5t#S256": padded}}))
	if v := present(t, p, token, &c, nil, false); v.Deny {
		t.Fatalf("a padded thumbprint: %+v", v)
	}
}

func TestTheThumbprintIsTheSHA256OfTheDER(t *testing.T) {
	c := newClientCert(t, "client")
	got := certThumbprint(c.cert.Raw)
	// Computed the other way round: the specification's words rather than
	// this package's helper.
	digest := sha256.Sum256(c.cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if got != want {
		t.Errorf("thumbprint %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "=+/") {
		t.Errorf("thumbprint %q is not unpadded base64url", got)
	}
}

// A binding and a proof can both be on, and a token that carries both
// must satisfy both: two controls where either alone would have let the
// other's failure through.
func TestATokenBoundBothWaysMustSatisfyBoth(t *testing.T) {
	dir := t.TempDir()
	_, _, es, _ := keys(t)
	p := provider(t, config.JWTProvider{
		Audiences: []string{"api"}, Algorithms: []string{"ES256"},
		JWKSFile:           writeJWKS(t, dir, es),
		DPoP:               &config.DPoP{Mode: "allow"},
		CertificateBinding: &config.CertificateBinding{Mode: "allow"},
	})
	key := newProofKey(t)
	mine, theirs := newClientCert(t, "client"), newClientCert(t, "thief")
	token := es.sign(t, base(map[string]any{"cnf": map[string]any{"jkt": key.jkt(t), "x5t#S256": mine.thumb()}}))
	now := time.Now().Unix()
	claims := func(jti string) map[string]any {
		return map[string]any{"jti": jti, "htm": "GET", "htu": "https://api.test/orders", "iat": now, "ath": ath(token)}
	}
	send := func(jti string, c *clientCert, proof string) filter.Verdict {
		r, _ := http.NewRequest(http.MethodGet, "https://api.test/orders", nil)
		r.Header.Set("Authorization", "DPoP "+token)
		if proof != "" {
			r.Header.Set("DPoP", proof)
		}
		if c != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.cert}}
		}
		return p.Filter(true).Begin(t.Context(), &filter.Info{}).Request(r)
	}
	if v := send("1", &mine, key.proof(t, nil, claims("1"))); v.Deny {
		t.Fatalf("both satisfied: %+v", v)
	}
	if v := send("2", &theirs, key.proof(t, nil, claims("2"))); !v.Deny || v.Detail != "cert_binding" {
		t.Fatalf("the right key on the wrong connection: %+v, want cert_binding", v)
	}
	if v := send("3", &mine, ""); !v.Deny || v.Detail != "dpop_missing" {
		t.Fatalf("the right connection with no proof: %+v, want dpop_missing", v)
	}
}

// The binding is checked against claims this proxy verified. cnf out of an
// unverified token is a value whoever presented it chose, so a token with
// a broken signature must be refused as a signature and never reach the
// comparison.
func TestTheBindingIsCheckedOnVerifiedClaims(t *testing.T) {
	p, es := certProvider(t, "require", false)
	c := newClientCert(t, "client")
	token := boundTo(t, es, c)
	tampered := token[:len(token)-4] + "AAAA"
	v := present(t, p, tampered, &c, nil, false)
	if !v.Deny || v.Detail != "signature" {
		t.Fatalf("a tampered token: %+v, want signature", v)
	}
}

func TestTheThumbprintIsRecordedForTheLog(t *testing.T) {
	p, es := certProvider(t, "allow", false)
	c := newClientCert(t, "client")
	r, _ := http.NewRequest(http.MethodGet, "https://api.test/orders", nil)
	r.Header.Set("Authorization", "Bearer "+boundTo(t, es, c))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.cert}}
	in := p.Filter(true).Begin(t.Context(), &filter.Info{})
	if v := in.Request(r); v.Deny {
		t.Fatalf("refused: %+v", v)
	}
	var found string
	attrs := in.End()
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == "cert_thumbprint" {
			found, _ = attrs[i+1].(string)
		}
	}
	if found != c.thumb() {
		t.Errorf("the access log records %q, want %q", found, c.thumb())
	}
}
