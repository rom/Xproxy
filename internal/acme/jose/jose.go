// Package jose holds the JWS (RFC 7515, ES256) and JWK (RFC 7517, RFC 7638)
// pieces of the ACME client, plus the challenge constants, in a leaf
// package so that the client and the test CA can share them.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// B64 is base64url without padding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwk renders an ECDSA P-256 public key as a JSON Web Key with members in
// the lexicographic order the thumbprint requires.
// JWK renders an ECDSA P-256 public key.
func JWK(pub *ecdsa.PublicKey) map[string]string {
	size := (pub.Curve.Params().BitSize + 7) / 8
	return map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   B64(pub.X.FillBytes(make([]byte, size))),
		"y":   B64(pub.Y.FillBytes(make([]byte, size))),
	}
}

// Thumbprint returns the RFC 7638 thumbprint of the key.
func Thumbprint(pub *ecdsa.PublicKey) string {
	j := JWK(pub)
	raw := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, j["crv"], j["kty"], j["x"], j["y"])
	sum := sha256.Sum256([]byte(raw))
	return B64(sum[:])
}

// KeyAuthorization builds token.thumbprint for a challenge.
func KeyAuthorization(token string, pub *ecdsa.PublicKey) string {
	return token + "." + Thumbprint(pub)
}

// Sign produces a flattened JWS with ES256. When kid is empty the
// public key is embedded (new account); otherwise the account URL is used.
func Sign(key *ecdsa.PrivateKey, kid, nonce, url string, payload []byte) ([]byte, error) {
	header := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	if kid == "" {
		header["jwk"] = JWK(&key.PublicKey)
	} else {
		header["kid"] = kid
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	protected := B64(hb)
	body := ""
	if payload != nil {
		body = B64(payload)
	}
	digest := sha256.Sum256([]byte(protected + "." + body))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return json.Marshal(map[string]string{"protected": protected, "payload": body, "signature": B64(sig)})
}

// Verify checks a flattened JWS signed with ES256 and returns the
// decoded protected header and payload. Used by the test CA and available
// for tooling.
func Verify(raw []byte, pub *ecdsa.PublicKey) (header map[string]any, payload []byte, err error) {
	var env struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, err
	}
	hb, err := base64.RawURLEncoding.DecodeString(env.Protected)
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != 64 {
		return nil, nil, fmt.Errorf("bad signature")
	}
	digest := sha256.Sum256([]byte(env.Protected + "." + env.Payload))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, nil, fmt.Errorf("signature verification failed")
	}
	payload, err = base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

// PublicKeyFromJWK parses an embedded EC P-256 JWK.
func PublicKeyFromJWK(j map[string]any) (*ecdsa.PublicKey, error) {
	x, _ := j["x"].(string)
	y, _ := j["y"].(string)
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !pub.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("point not on curve")
	}
	return pub, nil
}

var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)

// HTTP01Path is the prefix of http-01 challenge URLs.
const HTTP01Path = "/.well-known/acme-challenge/"

// ALPNProto is the tls-alpn-01 protocol name.
const ALPNProto = "acme-tls/1"
