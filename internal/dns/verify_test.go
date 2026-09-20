package dns

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // algorithms 5 and 7 are SHA-1 by definition
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
)

// The signature check is the whole of DNSSEC: everything above it is
// bookkeeping about which key signed what. These tests drive it
// directly, one algorithm at a time, with keys generated here — a
// signature that verifies when it should not is the failure that makes
// every other check pointless.

// rsaKeyRR encodes a public key in the RFC 3110 exponent/modulus form.
func rsaKeyRR(pub *rsa.PublicKey, longExponent bool) []byte {
	e := big.NewInt(int64(pub.E)).Bytes()
	var out []byte
	if longExponent || len(e) > 255 {
		out = append([]byte{0}, 0, 0)
		binary.BigEndian.PutUint16(out[1:], uint16(len(e))) //nolint:gosec // test sizes
	} else {
		out = []byte{byte(len(e))}
	}
	out = append(out, e...)
	return append(out, pub.N.Bytes()...)
}

// TestVerifySigRSA covers the three RSA algorithms and the ways an RSA
// key or signature can be wrong.
func TestVerifySigRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := &dnskey{pub: rsaKeyRR(&key.PublicKey, false)}
	data := []byte("the canonical rrset")
	for _, tc := range []struct {
		alg  uint8
		hash crypto.Hash
		sum  func([]byte) []byte
	}{
		{5, crypto.SHA1, func(b []byte) []byte { d := sha1.Sum(b); return d[:] }}, //nolint:gosec // by definition
		{7, crypto.SHA1, func(b []byte) []byte { d := sha1.Sum(b); return d[:] }}, //nolint:gosec // by definition
		{8, crypto.SHA256, func(b []byte) []byte { d := sha256.Sum256(b); return d[:] }},
		{10, crypto.SHA512, func(b []byte) []byte { d := sha512.Sum512(b); return d[:] }},
	} {
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, tc.hash, tc.sum(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := verifySig(k, tc.alg, data, sig); err != nil {
			t.Errorf("algorithm %d: a valid signature was refused: %v", tc.alg, err)
		}
		// The same signature over other data, and a signature with one
		// bit flipped.
		if err := verifySig(k, tc.alg, append(data, '!'), sig); err == nil {
			t.Errorf("algorithm %d: a signature verified over different data", tc.alg)
		}
		bad := append([]byte(nil), sig...)
		bad[len(bad)/2] ^= 0x01
		if err := verifySig(k, tc.alg, data, bad); err == nil {
			t.Errorf("algorithm %d: a flipped signature verified", tc.alg)
		}
		// Truncated and extended signatures.
		if err := verifySig(k, tc.alg, data, sig[:len(sig)-1]); err == nil {
			t.Errorf("algorithm %d: a truncated signature verified", tc.alg)
		}
		if err := verifySig(k, tc.alg, data, append(append([]byte(nil), sig...), 0)); err == nil {
			t.Errorf("algorithm %d: an extended signature verified", tc.alg)
		}
		if err := verifySig(k, tc.alg, data, nil); err == nil {
			t.Errorf("algorithm %d: an empty signature verified", tc.alg)
		}
		// A signature made under another algorithm's hash must not pass:
		// the algorithm in the RRSIG is part of what is signed.
		if tc.alg == 8 {
			sha1Sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, func() []byte { d := sha1.Sum(data); return d[:] }()) //nolint:gosec // deliberate
			if err != nil {
				t.Fatal(err)
			}
			if err := verifySig(k, 8, data, sha1Sig); err == nil {
				t.Error("a SHA-1 signature verified as SHA-256")
			}
		}
		// Another key of the same size does not verify it.
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifySig(&dnskey{pub: rsaKeyRR(&other.PublicKey, false)}, tc.alg, data, sig); err == nil {
			t.Errorf("algorithm %d: another key verified the signature", tc.alg)
		}
	}
	// The long exponent form of the same key works too.
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, func() []byte { d := sha256.Sum256(data); return d[:] }())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySig(&dnskey{pub: rsaKeyRR(&key.PublicKey, true)}, 8, data, sig); err != nil {
		t.Errorf("the long exponent form was refused: %v", err)
	}
}

// TestParseRSAKey covers the RFC 3110 encoding at its edges, where a
// key somebody published could be a way to reach the big integer code
// with something absurd.
func TestParseRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	good := rsaKeyRR(&key.PublicKey, false)
	pub, err := parseRSAKey(good)
	if err != nil {
		t.Fatal(err)
	}
	if pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		t.Fatal("the key did not round trip")
	}
	// Truncation at every length is refused, or at worst yields a key
	// that is not this one.
	for n := 0; n < len(good)-1; n++ {
		p, err := parseRSAKey(good[:n])
		if err == nil && p.N.Cmp(key.N) == 0 {
			t.Fatalf("a %d byte prefix parsed as the whole key", n)
		}
	}
	// A 512 bit modulus, built by hand: the standard library will not
	// generate a key that small any more, and the point is that the
	// parser refuses one somebody published.
	small := append([]byte{1, 3}, bytes.Repeat([]byte{0xff}, 64)...)
	big8192 := make([]byte, 1024)
	for i := range big8192 {
		big8192[i] = 0xff
	}
	bad := map[string][]byte{
		"empty":                           nil,
		"one byte":                        {1},
		"two bytes":                       {1, 3},
		"an exponent longer than the key": {200, 1, 2, 3},
		"a five byte exponent":            append([]byte{5, 1, 1, 1, 1, 1}, key.N.Bytes()...),
		"a zero length exponent":          append([]byte{0, 0, 0}, key.N.Bytes()...),
		"an exponent and no modulus":      {1, 3},
		"a 512 bit modulus":               small,
		"a modulus of 8192 bits":          append([]byte{1, 3}, append(big8192, big8192...)...),
		"a zero modulus":                  {1, 3, 0, 0, 0, 0},
	}
	for name, b := range bad {
		if p, err := parseRSAKey(b); err == nil {
			t.Errorf("%s was accepted as a key of %d bits", name, p.N.BitLen())
		}
	}
}

// TestVerifySigECDSA covers both curves, including the check that the
// point is on the curve at all.
func TestVerifySigECDSA(t *testing.T) {
	for _, tc := range []struct {
		alg   uint8
		curve elliptic.Curve
		size  int
		sum   func([]byte) []byte
	}{
		{13, elliptic.P256(), 32, func(b []byte) []byte { d := sha256.Sum256(b); return d[:] }},
		{14, elliptic.P384(), 48, func(b []byte) []byte { d := sha512.Sum384(b); return d[:] }},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub := append(leftPad(key.X.Bytes(), tc.size), leftPad(key.Y.Bytes(), tc.size)...)
		k := &dnskey{pub: pub}
		data := []byte("the canonical rrset")
		r, s, err := ecdsa.Sign(rand.Reader, key, tc.sum(data))
		if err != nil {
			t.Fatal(err)
		}
		sig := append(leftPad(r.Bytes(), tc.size), leftPad(s.Bytes(), tc.size)...)
		if err := verifySig(k, tc.alg, data, sig); err != nil {
			t.Errorf("algorithm %d: a valid signature was refused: %v", tc.alg, err)
		}
		if err := verifySig(k, tc.alg, append(data, '!'), sig); err == nil {
			t.Errorf("algorithm %d: a signature verified over different data", tc.alg)
		}
		// Sizes: the key and the signature are both fixed width, and a
		// wrong width must be refused rather than padded or truncated.
		for _, bad := range [][]byte{nil, sig[:tc.size], sig[:len(sig)-1], append(append([]byte(nil), sig...), 0)} {
			if err := verifySig(k, tc.alg, data, bad); err == nil {
				t.Errorf("algorithm %d: a %d byte signature verified", tc.alg, len(bad))
			}
		}
		for _, badKey := range [][]byte{nil, pub[:tc.size], pub[:len(pub)-1], append(append([]byte(nil), pub...), 0)} {
			if err := verifySig(&dnskey{pub: badKey}, tc.alg, data, sig); err == nil {
				t.Errorf("algorithm %d: a %d byte key verified", tc.alg, len(badKey))
			}
		}
		// A point that is not on the curve, and the point at infinity.
		offCurve := append([]byte(nil), pub...)
		offCurve[0] ^= 0x01
		if err := verifySig(&dnskey{pub: offCurve}, tc.alg, data, sig); err == nil {
			t.Errorf("algorithm %d: a key off the curve verified", tc.alg)
		}
		if err := verifySig(&dnskey{pub: make([]byte, 2*tc.size)}, tc.alg, data, sig); err == nil {
			t.Errorf("algorithm %d: the point at infinity verified", tc.alg)
		}
		// A zero signature, which is what a stripped signature looks like.
		if err := verifySig(k, tc.alg, data, make([]byte, 2*tc.size)); err == nil {
			t.Errorf("algorithm %d: a zero signature verified", tc.alg)
		}
		// The other curve's key is the wrong size for this algorithm.
		otherAlg := uint8(14)
		if tc.alg == 14 {
			otherAlg = 13
		}
		if err := verifySig(k, otherAlg, data, sig); err == nil {
			t.Errorf("a %d key verified under algorithm %d", tc.alg, otherAlg)
		}
	}
}

// TestVerifySigEd25519 covers the algorithm with no parameters to get
// wrong, which leaves the sizes.
func TestVerifySigEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("the canonical rrset")
	sig := ed25519.Sign(priv, data)
	k := &dnskey{pub: pub}
	if err := verifySig(k, 15, data, sig); err != nil {
		t.Fatalf("a valid signature was refused: %v", err)
	}
	if err := verifySig(k, 15, append(data, '!'), sig); err == nil {
		t.Error("a signature verified over different data")
	}
	for _, bad := range [][]byte{nil, sig[:32], sig[:len(sig)-1], append(append([]byte(nil), sig...), 0), make([]byte, 64)} {
		if err := verifySig(k, 15, data, bad); err == nil {
			t.Errorf("a %d byte signature verified", len(bad))
		}
	}
	for _, badKey := range [][]byte{nil, pub[:16], append(append([]byte(nil), pub...), 0), make([]byte, 32)} {
		if err := verifySig(&dnskey{pub: badKey}, 15, data, sig); err == nil {
			t.Errorf("a %d byte key verified", len(badKey))
		}
	}
}

// TestUnsupportedAlgorithms pins the algorithm list. An algorithm this
// resolver does not implement must be an error, never a pass: the
// classic downgrade is a zone signed with something the validator
// silently skips.
func TestUnsupportedAlgorithms(t *testing.T) {
	data := []byte("x")
	for alg := 0; alg < 256; alg++ {
		a := uint8(alg) //nolint:gosec // range is 0..255
		want := a == 5 || a == 7 || a == 8 || a == 10 || a == 13 || a == 14 || a == 15
		if supportedAlg(a) != want {
			t.Errorf("supportedAlg(%d) = %v", a, !want)
		}
		if want {
			continue
		}
		// An unsupported algorithm never verifies, whatever is handed to
		// it — including algorithm 0, and 253/254 (private use).
		if err := verifySig(&dnskey{pub: make([]byte, 64)}, a, data, make([]byte, 64)); err == nil {
			t.Errorf("algorithm %d verified a signature", a)
		} else if !strings.Contains(err.Error(), "not supported") {
			t.Errorf("algorithm %d: %v", a, err)
		}
	}
}

// TestMatchDS covers the DS digest comparison, which is what binds a
// child's key to its parent.
func TestMatchDS(t *testing.T) {
	z := newSignedZone(t, "example.com.")
	owner, err := packName(z.name)
	if err != nil {
		t.Fatal(err)
	}
	input := append(append([]byte{}, owner...), z.rr.Data...)
	sha256sum := sha256.Sum256(input)
	sha1sum := sha1.Sum(input) //nolint:gosec // digest type 1 is SHA-1
	sha384sum := sha512.Sum384(input)
	k, err := parseDNSKEY(z.rr)
	if err != nil {
		t.Fatal(err)
	}
	ks := &keySet{set: &RRset{Name: z.name, Type: TypeDNSKEY, RRs: []RR{z.rr}}, keys: []dnskey{k}}
	good := []dsRecord{
		{keyTag: z.tag, alg: 13, digestType: 2, digest: sha256sum[:]},
		{keyTag: z.tag, alg: 13, digestType: 1, digest: sha1sum[:]},
		{keyTag: z.tag, alg: 13, digestType: 4, digest: sha384sum[:]},
	}
	for _, d := range good {
		if len(matchDS(ks, []dsRecord{d})) != 1 {
			t.Errorf("digest type %d did not match", d.digestType)
		}
	}
	flipped := append([]byte(nil), sha256sum[:]...)
	flipped[0] ^= 0x01
	bad := []dsRecord{
		{keyTag: z.tag ^ 1, alg: 13, digestType: 2, digest: sha256sum[:]}, // another key tag
		{keyTag: z.tag, alg: 8, digestType: 2, digest: sha256sum[:]},      // another algorithm
		{keyTag: z.tag, alg: 13, digestType: 3, digest: sha256sum[:]},     // GOST, not supported
		{keyTag: z.tag, alg: 13, digestType: 0, digest: sha256sum[:]},     // reserved
		{keyTag: z.tag, alg: 13, digestType: 2, digest: flipped},          // one bit
		{keyTag: z.tag, alg: 13, digestType: 2, digest: sha256sum[:16]},   // truncated
		{keyTag: z.tag, alg: 13, digestType: 2, digest: nil},              // empty
		{keyTag: z.tag, alg: 13, digestType: 1, digest: sha256sum[:]},     // the wrong digest for the type
		{keyTag: z.tag, alg: 13, digestType: 2, digest: sha1sum[:]},       // and the other way round
	}
	for i, d := range bad {
		if n := len(matchDS(ks, []dsRecord{d})); n != 0 {
			t.Errorf("case %d matched %d keys: %+v", i, n, d)
		}
	}
	// No DS at all does not match, and a set with one good record among
	// many bad ones does.
	if len(matchDS(ks, nil)) != 0 {
		t.Error("an empty DS set matched")
	}
	if len(matchDS(ks, append(append([]dsRecord{}, bad...), good[0]))) != 1 {
		t.Error("a good record among bad ones did not match")
	}
	// The owner name is part of the digest, so the same key published
	// under another name does not match.
	other := &keySet{set: &RRset{Name: "other.com.", Type: TypeDNSKEY, RRs: []RR{z.rr}}, keys: []dnskey{k}}
	if len(matchDS(other, []dsRecord{good[0]})) != 0 {
		t.Error("the digest matched under another owner name")
	}
	// anySupportedDS follows the same algorithm and digest lists.
	if anySupportedDS(nil) {
		t.Error("an empty DS set counted as supported")
	}
	if anySupportedDS([]dsRecord{{alg: 12, digestType: 2}}) {
		t.Error("an unsupported algorithm counted as supported")
	}
	if anySupportedDS([]dsRecord{{alg: 13, digestType: 3}}) {
		t.Error("an unsupported digest type counted as supported")
	}
	if !anySupportedDS([]dsRecord{{alg: 12, digestType: 2}, {alg: 13, digestType: 2}}) {
		t.Error("a supported record among unsupported ones was missed")
	}
	// parseDSSet skips records too short to hold a header rather than
	// reading past them.
	set := &RRset{RRs: []RR{{Data: nil}, {Data: []byte{1, 2, 3, 4}}, {Data: append([]byte{0, 1, 13, 2}, sha256sum[:]...)}}}
	if got := parseDSSet(set); len(got) != 1 || got[0].digestType != 2 {
		t.Errorf("parseDSSet returned %+v", got)
	}
}

// TestParseDNSKEY covers the record the whole chain hangs from.
func TestParseDNSKEY(t *testing.T) {
	z := newSignedZone(t, "example.com.")
	k, err := parseDNSKEY(z.rr)
	if err != nil {
		t.Fatal(err)
	}
	if k.alg != 13 || k.tag != z.tag || len(k.pub) != 64 {
		t.Fatalf("parsed key: alg %d tag %d %d bytes", k.alg, k.tag, len(k.pub))
	}
	bad := map[string]RR{
		"empty":          {Name: z.name, Type: TypeDNSKEY, Data: nil},
		"three bytes":    {Name: z.name, Type: TypeDNSKEY, Data: []byte{1, 1, 3}},
		"no public key":  {Name: z.name, Type: TypeDNSKEY, Data: []byte{1, 1, 3, 13}},
		"wrong protocol": {Name: z.name, Type: TypeDNSKEY, Data: append([]byte{1, 1, 4, 13}, z.rr.Data[4:]...)},
	}
	for name, rr := range bad {
		if _, err := parseDNSKEY(rr); err == nil {
			t.Errorf("%s was parsed as a key", name)
		}
	}
	// The key tag is computed from the record, so a changed record is a
	// different key.
	other := z.rr
	other.Data = append([]byte(nil), z.rr.Data...)
	other.Data[10] ^= 0xff
	k2, err := parseDNSKEY(other)
	if err != nil {
		t.Fatal(err)
	}
	if k2.tag == k.tag {
		t.Error("a changed key kept its tag")
	}
}
