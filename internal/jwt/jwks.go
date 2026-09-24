// Package jwt validates JSON Web Tokens at the edge on the standard library
// only (docs/AMR.md, AMR-025): RSA (PKCS#1 v1.5 and PSS), ECDSA, Ed25519 and
// HMAC signatures, JSON Web Key Sets from a file or an HTTPS URL, and the
// standard time and audience claims. Algorithms are an explicit allow list
// per provider; "none" does not exist here.
package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

// MaxJWKSBytes bounds a key set document.
const MaxJWKSBytes = 1 << 20

// key is one verification key.
type key struct {
	kid string
	kty string // RSA, EC, OKP
	alg string // optional hint from the JWK
	pub crypto.PublicKey
}

// keySet is an immutable snapshot of a provider's keys.
type keySet struct {
	byKID    map[string][]*key
	all      []*key
	loadedAt time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	// The private members, read only so a key that carries one can be
	// refused. A public key set has none of them, and a DPoP proof that
	// embeds one is a client that has sent its secret to a server.
	D  string `json:"d"`
	P  string `json:"p"`
	Q  string `json:"q"`
	DP string `json:"dp"`
	DQ string `json:"dq"`
	QI string `json:"qi"`
	K  string `json:"k"`
}

// private reports a key carrying private material.
func (k jwk) private() bool {
	return k.D != "" || k.P != "" || k.Q != "" || k.DP != "" || k.DQ != "" || k.QI != "" || k.K != ""
}

// parseJWKS parses a JSON Web Key Set. Unsupported or malformed keys are
// skipped so one bad key does not disable a provider; symmetric keys are
// never taken from a key set.
func parseJWKS(data []byte) (*keySet, error) {
	if len(data) > MaxJWKSBytes {
		return nil, errors.New("key set too large")
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse key set: %w", err)
	}
	ks := &keySet{byKID: map[string][]*key{}, loadedAt: time.Now()}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		e := &key{kid: k.Kid, kty: k.Kty, alg: k.Alg, pub: pub}
		ks.all = append(ks.all, e)
		if k.Kid != "" {
			ks.byKID[k.Kid] = append(ks.byKID[k.Kid], e)
		}
		if len(ks.all) >= 256 {
			break
		}
	}
	return ks, nil
}

func b64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64(k.E)
		if err != nil {
			return nil, err
		}
		N := new(big.Int).SetBytes(n)
		E := new(big.Int).SetBytes(e)
		if N.BitLen() < 2048 || !E.IsInt64() || E.Int64() < 3 || E.Int64() > 1<<31 {
			return nil, errors.New("rsa key too small or bad exponent")
		}
		return &rsa.PublicKey{N: N, E: int(E.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported curve")
		}
		x, err := b64(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("point not on curve")
		}
		return pub, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, errors.New("unsupported OKP curve")
		}
		x, err := b64(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

// fetcher loads key sets from a URL with a pinned CA and bounded response.
type fetcher struct {
	url    string
	client *http.Client
}

func newFetcher(url, caFile string) (*fetcher, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, fmt.Errorf("jwks ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("jwks ca file contains no certificates")
		}
		tc.RootCAs = pool
	}
	return &fetcher{url: url, client: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tc,
			Proxy:                 nil,
			MaxIdleConns:          2,
			ResponseHeaderTimeout: 5 * time.Second,
			DisableCompression:    true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") },
	}}, nil
}

func (f *fetcher) fetch(ctx context.Context) (*keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xproxy-jwks/1")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	return parseJWKS(data)
}
