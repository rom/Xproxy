package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// MaxTokenBytes bounds a token.
const MaxTokenBytes = 8192

// Claims is the decoded payload.
type Claims map[string]any

// Verification errors. The category is what reaches logs; the client only
// sees 401.
var (
	ErrMalformed   = errors.New("malformed token")
	ErrAlgorithm   = errors.New("algorithm not allowed")
	ErrNoKey       = errors.New("no key for token")
	ErrSignature   = errors.New("bad signature")
	ErrExpired     = errors.New("token expired")
	ErrNotYetValid = errors.New("token not yet valid")
	ErrIssuer      = errors.New("issuer mismatch")
	ErrAudience    = errors.New("audience mismatch")
	ErrClaim       = errors.New("required claim missing")
	ErrKeysUnavail = errors.New("verification keys unavailable")
)

// Provider verifies tokens of one issuer.
type Provider struct {
	cfg     config.JWTProvider
	log     *slog.Logger
	allowed map[string]bool
	keys    atomic.Pointer[keySet]
	secret  []byte
	fetch   *fetcher
	intro   *introspector // nil without introspection

	mu           sync.Mutex
	lastOnDemand time.Time
	stop         chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	now          func() time.Time

	// counters
	Verified, Rejected, Refreshes, RefreshErrors atomic.Uint64
}

// NewProvider loads keys and secrets. A JWKS URL is fetched once with a
// short timeout; failure is logged and retried in the background, and
// tokens are rejected with ErrKeysUnavail until keys arrive.
func NewProvider(cfg config.JWTProvider, log *slog.Logger) (*Provider, error) {
	p := &Provider{cfg: cfg, log: log.With("component", "jwt", "provider", cfg.Name), allowed: map[string]bool{}, stop: make(chan struct{}), now: time.Now}
	for _, a := range cfg.Algorithms {
		p.allowed[a] = true
	}
	if cfg.HMACSecretFile != "" {
		b, err := os.ReadFile(cfg.HMACSecretFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, fmt.Errorf("jwt provider %s: %w", cfg.Name, err)
		}
		b = []byte(strings.TrimSpace(string(b)))
		if len(b) < 32 {
			return nil, fmt.Errorf("jwt provider %s: hmac secret shorter than 32 bytes", cfg.Name)
		}
		p.secret = b
	}
	if cfg.JWKSFile != "" {
		data, err := os.ReadFile(cfg.JWKSFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, fmt.Errorf("jwt provider %s: %w", cfg.Name, err)
		}
		ks, err := parseJWKS(data)
		if err != nil {
			return nil, fmt.Errorf("jwt provider %s: %w", cfg.Name, err)
		}
		p.keys.Store(ks)
	}
	if cfg.JWKSURL != "" {
		f, err := newFetcher(cfg.JWKSURL, cfg.JWKSCAFile)
		if err != nil {
			return nil, fmt.Errorf("jwt provider %s: %w", cfg.Name, err)
		}
		p.fetch = f
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		p.refresh(ctx)
		cancel()
	}
	if cfg.Introspection != nil {
		in, err := newIntrospector(*cfg.Introspection)
		if err != nil {
			return nil, fmt.Errorf("jwt provider %s: introspection: %w", cfg.Name, err)
		}
		p.intro = in
	}
	if p.keys.Load() == nil && p.secret == nil && p.fetch == nil && p.intro == nil {
		return nil, fmt.Errorf("jwt provider %s: no keys", cfg.Name)
	}
	if len(cfg.Audiences) == 0 {
		// RFC 8725 §3.8: without an audience check any token the issuer
		// minted for another relying party is accepted here.
		p.log.Warn("jwt provider accepts tokens of any audience; set audiences to the values this proxy is issued for")
	}
	return p, nil
}

// Introspects reports whether token goes to the introspection endpoint:
// every token of a provider without keys or with always, else only one
// that is not a compact JWS.
func (p *Provider) Introspects(token string) bool {
	if p.intro == nil {
		return false
	}
	return p.intro.cfg.Always || !looksLikeJWS(token) || (p.keys.Load() == nil && p.secret == nil && p.fetch == nil)
}

// IntrospectionStats returns calls, errors, cache hits and cached
// entries (zeros without introspection).
func (p *Provider) IntrospectionStats() (calls, errs, hits uint64, cached int) {
	if p.intro == nil {
		return 0, 0, 0, 0
	}
	return p.intro.Calls.Load(), p.intro.Errors.Load(), p.intro.Hits.Load(), p.intro.cacheLen()
}

// Start begins periodic JWKS refresh.
func (p *Provider) Start() {
	if p.fetch == nil {
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(p.cfg.JWKSRefresh.D())
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				p.refresh(ctx)
				cancel()
			}
		}
	}()
}

// Stop ends background refresh. It is safe to call more than once and
// from several goroutines (a discovery swap and a filter close can race).
func (p *Provider) Stop() {
	p.stopOnce.Do(func() { close(p.stop) })
	p.wg.Wait()
}

// Name returns the provider name.
func (p *Provider) Name() string { return p.cfg.Name }

// Config returns the provider configuration.
func (p *Provider) Config() *config.JWTProvider { return &p.cfg }

// KeyCount returns the number of loaded asymmetric keys.
func (p *Provider) KeyCount() int {
	if ks := p.keys.Load(); ks != nil {
		return len(ks.all)
	}
	return 0
}

func (p *Provider) refresh(ctx context.Context) {
	ks, err := p.fetch.fetch(ctx)
	if err != nil {
		p.RefreshErrors.Add(1)
		p.log.Warn("jwks refresh failed", "url", p.cfg.JWKSURL, "err", err.Error())
		return
	}
	// A key set that suddenly turns empty is more likely an IdP problem
	// than a rotation to nothing: keep the previous keys.
	if len(ks.all) == 0 && p.keys.Load() != nil {
		p.log.Warn("jwks refresh returned no keys; keeping previous set")
		return
	}
	p.keys.Store(ks)
	p.Refreshes.Add(1)
	p.log.Info("jwks refreshed", "keys", len(ks.all))
}

// refreshOnDemand fetches at most once per minute when a token names an
// unknown key id (key rotation).
func (p *Provider) refreshOnDemand() {
	if p.fetch == nil {
		return
	}
	p.mu.Lock()
	if p.now().Sub(p.lastOnDemand) < time.Minute {
		p.mu.Unlock()
		return
	}
	p.lastOnDemand = p.now()
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.refresh(ctx)
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify checks a compact serialised token and returns its claims.
func (p *Provider) Verify(token string) (Claims, error) {
	var c Claims
	var err error
	if p.Introspects(token) {
		c, err = p.introspect(token, p.now())
	} else {
		c, err = p.verify(token, p.now())
	}
	if err != nil {
		p.Rejected.Add(1)
		return nil, err
	}
	p.Verified.Add(1)
	return c, nil
}

// introspect validates token at the endpoint and applies the provider's
// issuer, audience and required claim rules to what it says; exp is
// checked when present (an introspected token need not carry one).
func (p *Provider) introspect(token string, now time.Time) (Claims, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return nil, ErrMalformed
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.intro.cfg.Timeout.D())
	defer cancel()
	claims, err := p.intro.verify(ctx, token, now)
	if err != nil {
		return nil, err
	}
	skew := p.cfg.ClockSkew.D().Seconds()
	nowS := float64(now.Unix())
	if exp, ok := numeric(claims["exp"]); ok && nowS > exp+skew {
		return nil, ErrExpired
	}
	if nbf, ok := numeric(claims["nbf"]); ok && nowS+skew < nbf {
		return nil, ErrNotYetValid
	}
	if iss, ok := claims["iss"].(string); ok && iss != p.cfg.Issuer {
		return nil, ErrIssuer
	}
	if len(p.cfg.Audiences) > 0 {
		if _, has := claims["aud"]; has && !audienceMatches(claims["aud"], p.cfg.Audiences) {
			return nil, ErrAudience
		}
	}
	for _, name := range p.cfg.RequiredClaims {
		if _, ok := claims[name]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrClaim, name)
		}
	}
	return claims, nil
}

func (p *Provider) verify(token string, now time.Time) (Claims, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return nil, ErrMalformed
	}
	i1 := strings.IndexByte(token, '.')
	i2 := strings.LastIndexByte(token, '.')
	if i1 <= 0 || i2 <= i1+1 || i2 == len(token)-1 || strings.Count(token, ".") != 2 {
		return nil, ErrMalformed
	}
	hb, err := base64.RawURLEncoding.DecodeString(token[:i1])
	if err != nil {
		return nil, ErrMalformed
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg == "" {
		return nil, ErrMalformed
	}
	if !p.allowed[h.Alg] {
		return nil, fmt.Errorf("%w: %s", ErrAlgorithm, h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(token[i2+1:])
	if err != nil {
		return nil, ErrMalformed
	}
	signed := []byte(token[:i2])
	if err := p.checkSignature(h, signed, sig); err != nil {
		return nil, err
	}
	pb, err := base64.RawURLEncoding.DecodeString(token[i1+1 : i2])
	if err != nil {
		return nil, ErrMalformed
	}
	var claims Claims
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, ErrMalformed
	}
	if err := p.checkClaims(claims, now); err != nil {
		return nil, err
	}
	return claims, nil
}

func hashFor(alg string) (crypto.Hash, func() hash.Hash) {
	switch alg[len(alg)-3:] {
	case "384":
		return crypto.SHA384, sha512.New384
	case "512":
		return crypto.SHA512, sha512.New
	default:
		return crypto.SHA256, sha256.New
	}
}

func (p *Provider) checkSignature(h header, signed, sig []byte) error {
	if strings.HasPrefix(h.Alg, "HS") {
		if p.secret == nil {
			return ErrNoKey
		}
		_, newHash := hashFor(h.Alg)
		m := hmac.New(newHash, p.secret)
		m.Write(signed)
		if subtle.ConstantTimeCompare(m.Sum(nil), sig) != 1 {
			return ErrSignature
		}
		return nil
	}
	keys := p.candidates(h)
	if len(keys) == 0 {
		p.refreshOnDemand()
		keys = p.candidates(h)
	}
	if len(keys) == 0 {
		if p.keys.Load() == nil {
			return ErrKeysUnavail
		}
		return ErrNoKey
	}
	for _, k := range keys {
		if verifyWith(h.Alg, k.pub, signed, sig) == nil {
			return nil
		}
	}
	return ErrSignature
}

// candidates returns keys to try: those with the token's kid, or without
// a kid every key of the matching type (bounded).
func (p *Provider) candidates(h header) []*key {
	ks := p.keys.Load()
	if ks == nil {
		return nil
	}
	want := "RSA"
	switch {
	case strings.HasPrefix(h.Alg, "ES"):
		want = "EC"
	case h.Alg == "EdDSA":
		want = "OKP"
	}
	var out []*key
	if h.Kid != "" {
		for _, k := range ks.byKID[h.Kid] {
			if k.kty == want && (k.alg == "" || k.alg == h.Alg) {
				out = append(out, k)
			}
		}
		return out
	}
	for _, k := range ks.all {
		if k.kty == want && (k.alg == "" || k.alg == h.Alg) {
			out = append(out, k)
			if len(out) == 8 {
				break
			}
		}
	}
	return out
}

func verifyWith(alg string, pub crypto.PublicKey, signed, sig []byte) error {
	ch, newHash := hashFor(alg)
	hh := newHash()
	hh.Write(signed)
	digest := hh.Sum(nil)
	switch {
	case strings.HasPrefix(alg, "RS"):
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrSignature
		}
		return rsa.VerifyPKCS1v15(k, ch, digest, sig)
	case strings.HasPrefix(alg, "PS"):
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrSignature
		}
		return rsa.VerifyPSS(k, ch, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case strings.HasPrefix(alg, "ES"):
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrSignature
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return ErrSignature
		}
		// The curve must match the algorithm, otherwise a P-256 key could
		// be used with ES512 and so on.
		if (alg == "ES256" && size != 32) || (alg == "ES384" && size != 48) || (alg == "ES512" && size != 66) {
			return ErrSignature
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, s) {
			return ErrSignature
		}
		return nil
	case alg == "EdDSA":
		k, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, signed, sig) {
			return ErrSignature
		}
		return nil
	}
	return ErrAlgorithm
}

func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	}
	return 0, false
}

func (p *Provider) checkClaims(c Claims, now time.Time) error {
	skew := p.cfg.ClockSkew.D().Seconds()
	nowS := float64(now.Unix())
	exp, ok := numeric(c["exp"])
	if !ok {
		return fmt.Errorf("%w: exp", ErrClaim)
	}
	if nowS > exp+skew {
		return ErrExpired
	}
	if nbf, ok := numeric(c["nbf"]); ok && nowS+skew < nbf {
		return ErrNotYetValid
	}
	if iat, ok := numeric(c["iat"]); ok && iat > nowS+skew+60 {
		return ErrNotYetValid
	}
	if iss, _ := c["iss"].(string); iss != p.cfg.Issuer {
		return ErrIssuer
	}
	if len(p.cfg.Audiences) > 0 {
		if !audienceMatches(c["aud"], p.cfg.Audiences) {
			return ErrAudience
		}
	}
	for _, name := range p.cfg.RequiredClaims {
		if _, ok := c[name]; !ok {
			return fmt.Errorf("%w: %s", ErrClaim, name)
		}
	}
	return nil
}

// CheckAuthorizedParty applies OpenID Connect Core 3.1.3.7 steps 4 and 5
// to an ID token verified for clientID: an aud with more than one entry
// must carry azp, and an azp present must equal clientID.
func CheckAuthorizedParty(c Claims, clientID string) error {
	azp, hasAzp := c["azp"].(string)
	if aud, ok := c["aud"].([]any); ok && len(aud) > 1 && !hasAzp {
		return fmt.Errorf("%w: azp missing for multi-audience token", ErrAudience)
	}
	if hasAzp && azp != clientID {
		return fmt.Errorf("%w: azp %q", ErrAudience, azp)
	}
	return nil
}

func audienceMatches(aud any, allowed []string) bool {
	switch a := aud.(type) {
	case string:
		for _, w := range allowed {
			if a == w {
				return true
			}
		}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				for _, w := range allowed {
					if s == w {
						return true
					}
				}
			}
		}
	}
	return false
}

// ClaimString renders a claim value for a header or a log line: strings
// as is, numbers and booleans formatted, string arrays comma joined,
// anything else as JSON. Control characters are removed and the result is
// capped at 1024 bytes.
func ClaimString(v any) string {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case json.Number:
		s = x.String()
	case bool:
		if x {
			s = "true"
		} else {
			s = "false"
		}
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if str, ok := e.(string); ok {
				parts = append(parts, str)
			} else {
				b, _ := json.Marshal(e)
				parts = append(parts, string(b))
			}
		}
		s = strings.Join(parts, ",")
	default:
		b, _ := json.Marshal(v)
		s = string(b)
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 1024 {
		s = s[:1024]
	}
	return s
}
