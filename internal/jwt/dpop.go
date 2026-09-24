package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Demonstrating proof of possession, RFC 9449.
//
// A bearer token is a password: whoever holds it is whoever it says. That
// is the whole of its security model, and it is why a token stolen from a
// log, a browser's storage, a proxy's cache or a crash dump is as good as
// the original. Nothing about the request says it came from the client the
// token was issued to.
//
// DPoP adds the one thing missing. The client keeps a key pair, the
// authorization server records the public key's thumbprint in the token
// (`cnf.jkt`), and every request carries a small JWT -- the proof --
// signed with the private key over *this* method, *this* URI and *this*
// moment. A stolen token without the key produces no proof, and a proof
// captured from one request does not fit another.
//
// What this checks, in order, because each step is only meaningful once
// the one before it holds:
//
//  1. The proof is a JWT with typ "dpop+jwt" and an asymmetric algorithm
//     from the allow list. Nothing symmetric, and no "none": a proof the
//     client and the server could both have written proves nothing.
//  2. Its signature verifies under the key embedded in its own header.
//     That alone proves nothing at all -- anybody can generate a key and
//     sign with it -- which is why step 5 exists.
//  3. htm and htu match the request being made. This is what stops a
//     proof captured from a GET being replayed on a DELETE.
//  4. iat is recent, and the jti has not been seen before. Together they
//     bound replay to a window and then remove it.
//  5. The thumbprint of the embedded key equals the access token's
//     cnf.jkt. This is the step that matters: it is what ties the key that
//     signed the proof to the key the authorization server bound the token
//     to. Without it the proof is a signature over a request by somebody
//     who has the token, which is exactly the person a bearer token
//     already trusts.
//  6. ath equals the hash of the access token, so a proof cannot be moved
//     between two tokens the same client holds.

// DPoP errors, each with its own name so an operator can tell a client
// bug from an attack.
var (
	// ErrDPoPMissing is a sender-constrained token presented with no proof.
	ErrDPoPMissing = errors.New("jwt: no DPoP proof")
	// ErrDPoPProof is a proof that does not hold up.
	ErrDPoPProof = errors.New("jwt: bad DPoP proof")
	// ErrDPoPBinding is a proof signed by a key the token is not bound to.
	ErrDPoPBinding = errors.New("jwt: DPoP key is not the token's")
	// ErrDPoPReplay is a proof whose jti has been seen.
	ErrDPoPReplay = errors.New("jwt: DPoP proof replayed")
	// ErrDPoPUnbound is an access token with no cnf.jkt where one is
	// required.
	ErrDPoPUnbound = errors.New("jwt: access token is not sender constrained")
)

// maxProofBytes bounds one proof. A DPoP proof is a header, four short
// claims and a signature; anything larger is not one.
const maxProofBytes = 4096

// dpopModes.
const (
	dpopOff     = "off"
	dpopAllow   = "allow"
	dpopRequire = "require"
)

// dpop is a provider's compiled proof-of-possession policy.
type dpop struct {
	mode     string
	algs     map[string]bool
	algList  string // the algs parameter of the challenge
	maxAge   time.Duration
	skew     time.Duration
	external *url.URL
	seen     *replayCache
}

func newDPoP(c *config.DPoP, skew time.Duration) (*dpop, error) {
	if c == nil || c.Mode == "" || c.Mode == dpopOff {
		return &dpop{mode: dpopOff}, nil
	}
	d := &dpop{mode: c.Mode, algs: map[string]bool{}, maxAge: c.MaxAge.D(), skew: skew}
	if d.maxAge <= 0 {
		d.maxAge = time.Minute
	}
	list := c.Algorithms
	if len(list) == 0 {
		// The asymmetric algorithms a client library actually offers. RSA
		// PKCS#1 v1.5 is left out of the default: a proof is signed fresh
		// on every request, so there is no reason to keep the older
		// padding alive for it.
		list = []string{"ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
	}
	for _, a := range list {
		if !asymmetric(a) {
			return nil, fmt.Errorf("dpop.algorithms: %q is not an asymmetric algorithm", a)
		}
		d.algs[a] = true
	}
	d.algList = strings.Join(list, " ")
	if c.ExternalURL != "" {
		u, err := url.Parse(c.ExternalURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, errors.New("dpop.external_url: must be an absolute URL")
		}
		d.external = u
	}
	entries := c.ReplayEntries
	if entries <= 0 {
		entries = 65536
	}
	d.seen = newReplayCache(entries)
	return d, nil
}

// asymmetric reports an algorithm whose signature only the holder of a
// private key can produce. A proof signed with HMAC is one the verifier
// could have written itself, which proves nothing about the client.
func asymmetric(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		return true
	}
	return false
}

func (d *dpop) on() bool { return d != nil && d.mode != dpopOff && d.mode != "" }

// proofHeader is the JOSE header of a proof: the algorithm, the type and
// the public key the client is proving it holds.
type proofHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	JWK *jwk   `json:"jwk"`
}

// proofClaims are the four RFC 9449 claims plus the access token hash.
type proofClaims struct {
	JTI string  `json:"jti"`
	HTM string  `json:"htm"`
	HTU string  `json:"htu"`
	IAT float64 `json:"iat"`
	ATH string  `json:"ath"`
	// Nonce is read so a future server-provided nonce can be required;
	// it is not enforced here, and a client that sends one is not
	// refused for it.
	Nonce string `json:"nonce"`
}

// check verifies the proof on r against the access token's own binding.
//
// tokenClaims are the claims of an access token this proxy has already
// verified. Reading cnf.jkt from an unverified token would be worthless:
// an attacker would simply write their own thumbprint into it.
func (d *dpop) check(r *http.Request, token string, tokenClaims Claims, now time.Time) (thumb string, err error) {
	jkt := confirmationKey(tokenClaims)
	proof := r.Header.Get("DPoP")
	switch {
	case !d.on():
		return "", nil
	case jkt == "" && d.mode == dpopRequire:
		// A token nobody constrained is a bearer token, and this route
		// was configured to accept only constrained ones.
		return "", ErrDPoPUnbound
	case jkt == "" && proof == "":
		// Nothing was bound and nothing was claimed: an ordinary bearer
		// token, which allow does not refuse.
		return "", nil
	case proof == "":
		// The token says it is bound to a key. Accepting it without the
		// proof would be accepting the stolen copy.
		return "", ErrDPoPMissing
	}
	hdr, claims, err := parseProof(proof, d)
	if err != nil {
		return "", err
	}
	if err := d.checkClaims(r, claims, now); err != nil {
		return "", err
	}
	thumb, err = thumbprint(hdr.JWK)
	if err != nil {
		return "", ErrDPoPProof
	}
	// The step the rest exists for: the key that signed this proof must
	// be the key the authorization server bound the token to.
	if jkt != "" && thumb != jkt {
		return "", ErrDPoPBinding
	}
	// And the proof names the token it accompanies, so one cannot be
	// moved to another token the same client holds.
	if err := checkATH(claims.ATH, token, jkt != ""); err != nil {
		return "", err
	}
	// The jti is spent last, once everything else holds: a proof refused
	// for another reason must not consume the identifier a correct retry
	// would use.
	if !d.seen.admit(thumb+"\x00"+claims.JTI, now.Add(d.maxAge+d.skew)) {
		return "", ErrDPoPReplay
	}
	return thumb, nil
}

// parseProof reads and verifies one proof JWT under the key inside it.
func parseProof(proof string, d *dpop) (proofHeader, proofClaims, error) {
	var hdr proofHeader
	var claims proofClaims
	if len(proof) > maxProofBytes {
		return hdr, claims, ErrDPoPProof
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return hdr, claims, ErrDPoPProof
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(raw, &hdr) != nil {
		return hdr, claims, ErrDPoPProof
	}
	// The type is part of the proof's meaning: without it a JWT minted
	// for something else -- an id token, an assertion the client already
	// holds -- could be presented as a proof.
	if !strings.EqualFold(hdr.Typ, "dpop+jwt") || hdr.JWK == nil {
		return hdr, claims, ErrDPoPProof
	}
	if !d.algs[hdr.Alg] {
		return hdr, claims, ErrDPoPProof
	}
	// A private key in the header would mean the client sent its secret;
	// it is also how a careless implementation is invited to use it.
	if hdr.JWK.private() {
		return hdr, claims, ErrDPoPProof
	}
	pub, err := hdr.JWK.publicKey()
	if err != nil {
		return hdr, claims, ErrDPoPProof
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return hdr, claims, ErrDPoPProof
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return hdr, claims, ErrDPoPProof
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return hdr, claims, ErrDPoPProof
	}
	signed := []byte(parts[0] + "." + parts[1])
	if err := verifyWith(hdr.Alg, pub, signed, sig); err != nil {
		return hdr, claims, ErrDPoPProof
	}
	return hdr, claims, nil
}

// checkClaims holds the proof to the request it was made for.
func (d *dpop) checkClaims(r *http.Request, c proofClaims, now time.Time) error {
	if c.JTI == "" || len(c.JTI) > 256 {
		return ErrDPoPProof
	}
	// The method is compared exactly: HTTP methods are case-sensitive, so
	// "get" is not GET and a proof that spells it differently was not
	// made for this request.
	if c.HTM != r.Method {
		return ErrDPoPProof
	}
	if !d.htuMatches(r, c.HTU) {
		return ErrDPoPProof
	}
	if c.IAT == 0 {
		return ErrDPoPProof
	}
	iat := time.Unix(int64(c.IAT), 0)
	if now.Sub(iat) > d.maxAge+d.skew || iat.Sub(now) > d.skew {
		return ErrDPoPProof
	}
	return nil
}

// htuMatches compares the proof's htu with the URI the client asked for.
//
// Query and fragment are excluded, as RFC 9449 section 4.3 says: a client
// that signed the path is not expected to re-sign it for every query, and
// the query is not what a replay changes.
//
// The authority is the awkward part behind another proxy: this process
// sees its own scheme and whatever Host it was handed. external_url is
// how an operator says what the client sees, and without it the scheme
// comes from the connection -- never from a header, because a client that
// can set X-Forwarded-Proto could otherwise choose which URI its proof
// has to match.
func (d *dpop) htuMatches(r *http.Request, htu string) bool {
	if htu == "" {
		return false
	}
	u, err := url.Parse(htu)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	scheme, host := "http", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	if d.external != nil {
		scheme, host = d.external.Scheme, d.external.Host
	}
	if !strings.EqualFold(u.Scheme, scheme) || !sameAuthority(u.Host, host, scheme) {
		return false
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	want := r.URL.Path
	if want == "" {
		want = "/"
	}
	return path == want
}

// sameAuthority compares hosts, ignoring case and a default port written
// out in one of them.
func sameAuthority(a, b, scheme string) bool {
	return strings.EqualFold(trimDefaultPort(a, scheme), trimDefaultPort(b, scheme))
}

func trimDefaultPort(host, scheme string) string {
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		return strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

// checkATH holds the proof to the access token it came with.
func checkATH(ath, token string, bound bool) error {
	if ath == "" {
		// RFC 9449 requires ath whenever an access token is presented.
		// Demanding it only for a bound token keeps an unbound one, which
		// this policy is not protecting anyway, from being refused for a
		// claim it had no reason to send.
		if bound {
			return ErrDPoPProof
		}
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ath {
		return ErrDPoPProof
	}
	return nil
}

// confirmationKey reads cnf.jkt out of an access token's claims.
func confirmationKey(c Claims) string {
	cnf, _ := c["cnf"].(map[string]any)
	if cnf == nil {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

// thumbprint is the RFC 7638 JWK thumbprint: SHA-256 over the canonical
// JSON of the key's required members, in lexicographic order, with no
// whitespace. The order and the member set are the whole specification --
// two implementations that disagree about either compute different
// thumbprints and no token ever verifies.
func thumbprint(k *jwk) (string, error) {
	var canon string
	switch k.Kty {
	case "RSA":
		if k.E == "" || k.N == "" {
			return "", errors.New("incomplete RSA key")
		}
		canon = `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	case "EC":
		if k.Crv == "" || k.X == "" || k.Y == "" {
			return "", errors.New("incomplete EC key")
		}
		canon = `{"crv":"` + k.Crv + `","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	case "OKP":
		if k.Crv == "" || k.X == "" {
			return "", errors.New("incomplete OKP key")
		}
		canon = `{"crv":"` + k.Crv + `","kty":"OKP","x":"` + k.X + `"}`
	default:
		return "", errors.New("unsupported key type")
	}
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// replayCache remembers the proof identifiers spent inside their window.
//
// It is bounded, and the bound is a decision rather than an accident: the
// identifiers come from clients, so an unbounded table is a request away
// from being the whole of memory. Over the bound the oldest half goes,
// which loses replay protection for the proofs whose windows were closing
// anyway rather than for the ones just issued.
type replayCache struct {
	mu   sync.Mutex
	max  int
	seen map[string]time.Time
}

func newReplayCache(max int) *replayCache {
	return &replayCache{max: max, seen: make(map[string]time.Time, min(max, 1024))}
}

// admit records an identifier and reports whether it was new.
func (c *replayCache) admit(id string, until time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[id]; ok && exp.After(until.Add(-24*time.Hour)) {
		return false
	}
	if len(c.seen) >= c.max {
		c.evict(until)
	}
	c.seen[id] = until
	return true
}

// evict drops what has expired, and if that was not enough, the half of
// the table whose windows close first.
func (c *replayCache) evict(now time.Time) {
	for id, exp := range c.seen {
		if !exp.After(now) {
			delete(c.seen, id)
		}
	}
	if len(c.seen) < c.max {
		return
	}
	target := c.max / 2
	for id := range c.seen {
		if len(c.seen) <= target {
			return
		}
		delete(c.seen, id)
	}
}

// Len is the number of identifiers held, for the status view.
func (c *replayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
