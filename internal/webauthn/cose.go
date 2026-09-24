package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
)

// COSE keys, RFC 8152, as WebAuthn uses them.
//
// The label numbers are the specification's and are written out because a
// key read with the wrong label is a key that verifies nothing or, worse,
// verifies the wrong thing.
const (
	coseKty = 1  // key type
	coseAlg = 3  // algorithm
	coseCrv = -1 // EC2 and OKP: curve; RSA: modulus
	coseXE  = -2 // EC2 and OKP: x; RSA: exponent
	coseY   = -3 // EC2: y

	ktyOKP = 1
	ktyEC2 = 2
	ktyRSA = 3

	// The COSE algorithm identifiers a browser offers.
	algES256 = -7
	algES384 = -35
	algES512 = -36
	algEdDSA = -8
	algRS256 = -257
	algPS256 = -37
)

// ErrKey is a credential public key this package will not use.
var ErrKey = errors.New("webauthn: unusable credential key")

// credentialKey is a registered public key with the algorithm it signs
// with. The algorithm is kept beside the key because a key can be used
// with more than one, and accepting whichever the assertion claims would
// let an attacker pick the weakest.
type credentialKey struct {
	alg int64
	pub crypto.PublicKey
}

// parseCOSEKey reads a COSE_Key.
//
// Only the algorithms a browser actually offers are accepted, and only
// the curves that match them: a P-256 key used with ES512 is refused,
// because the two disagree about how long a signature is and a verifier
// that does not check ends up reading one as the other.
func parseCOSEKey(b []byte) (credentialKey, error) {
	v, n, err := decodeCBOR(b)
	if err != nil {
		return credentialKey{}, fmt.Errorf("%w: %w", ErrKey, err)
	}
	if n != len(b) {
		return credentialKey{}, fmt.Errorf("%w: %d bytes after the key", ErrKey, len(b)-n)
	}
	m, ok := cborMap(v)
	if !ok {
		return credentialKey{}, fmt.Errorf("%w: not a map", ErrKey)
	}
	kty, ok1 := cborInt(m[numKey(coseKty)])
	alg, ok2 := cborInt(m[numKey(coseAlg)])
	if !ok1 || !ok2 {
		return credentialKey{}, fmt.Errorf("%w: no kty or alg", ErrKey)
	}
	switch {
	case kty == ktyEC2 && (alg == algES256 || alg == algES384 || alg == algES512):
		crv, _ := cborInt(m[numKey(coseCrv)])
		x, okx := cborBytes(m[numKey(coseXE)])
		y, oky := cborBytes(m[numKey(coseY)])
		if !okx || !oky {
			return credentialKey{}, fmt.Errorf("%w: EC2 key without x or y", ErrKey)
		}
		curve, size, err := ecCurve(crv, alg)
		if err != nil {
			return credentialKey{}, err
		}
		if len(x) != size || len(y) != size {
			// The coordinates are fixed width for a curve. A short one is
			// a different number when read as big-endian bytes, which is
			// a different point.
			return credentialKey{}, fmt.Errorf("%w: coordinates are %d and %d bytes, want %d", ErrKey, len(x), len(y), size)
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return credentialKey{}, fmt.Errorf("%w: point is not on the curve", ErrKey)
		}
		return credentialKey{alg: alg, pub: pub}, nil
	case kty == ktyOKP && alg == algEdDSA:
		crv, _ := cborInt(m[numKey(coseCrv)])
		if crv != 6 { // Ed25519
			return credentialKey{}, fmt.Errorf("%w: OKP curve %d", ErrKey, crv)
		}
		x, ok := cborBytes(m[numKey(coseXE)])
		if !ok || len(x) != ed25519.PublicKeySize {
			return credentialKey{}, fmt.Errorf("%w: bad Ed25519 key", ErrKey)
		}
		return credentialKey{alg: alg, pub: ed25519.PublicKey(x)}, nil
	case kty == ktyRSA && (alg == algRS256 || alg == algPS256):
		n, okn := cborBytes(m[numKey(coseCrv)])
		e, oke := cborBytes(m[numKey(coseXE)])
		if !okn || !oke {
			return credentialKey{}, fmt.Errorf("%w: RSA key without n or e", ErrKey)
		}
		N := new(big.Int).SetBytes(n)
		E := new(big.Int).SetBytes(e)
		if N.BitLen() < 2048 {
			return credentialKey{}, fmt.Errorf("%w: RSA modulus of %d bits", ErrKey, N.BitLen())
		}
		if !E.IsInt64() || E.Int64() < 3 || E.Int64() > 1<<31 {
			return credentialKey{}, fmt.Errorf("%w: RSA exponent out of range", ErrKey)
		}
		return credentialKey{alg: alg, pub: &rsa.PublicKey{N: N, E: int(E.Int64())}}, nil
	}
	return credentialKey{}, fmt.Errorf("%w: kty %d with alg %d", ErrKey, kty, alg)
}

// ecCurve pairs a COSE curve with the algorithm that may use it.
func ecCurve(crv, alg int64) (elliptic.Curve, int, error) {
	switch {
	case crv == 1 && alg == algES256:
		return elliptic.P256(), 32, nil
	case crv == 2 && alg == algES384:
		return elliptic.P384(), 48, nil
	case crv == 3 && alg == algES512:
		return elliptic.P521(), 66, nil
	}
	return nil, 0, fmt.Errorf("%w: curve %d does not go with algorithm %d", ErrKey, crv, alg)
}

// hashFor is the digest an algorithm signs over.
func (k credentialKey) hashFor() crypto.Hash {
	switch k.alg {
	case algES384:
		return crypto.SHA384
	case algES512:
		return crypto.SHA512
	}
	return crypto.SHA256
}

// verify checks a signature over signed.
//
// ECDSA signatures arrive ASN.1 encoded here, unlike the fixed-width pair
// a JWS carries: WebAuthn says the signature is whatever the COSE
// algorithm defines, and for the EC algorithms that is a DER SEQUENCE.
func (k credentialKey) verify(signed, sig []byte) error {
	h := k.hashFor()
	hh := h.New()
	hh.Write(signed)
	digest := hh.Sum(nil)
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return ErrSignature
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signed, sig) {
			return ErrSignature
		}
		return nil
	case *rsa.PublicKey:
		if k.alg == algPS256 {
			if err := rsa.VerifyPSS(pub, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				return ErrSignature
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, h, digest, sig); err != nil {
			return ErrSignature
		}
		return nil
	}
	return ErrSignature
}
