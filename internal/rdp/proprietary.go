package rdp

import (
	"crypto/md5" //nolint:gosec // the protocol specifies MD5
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
)

// The server's half of standard RDP security: the certificate a
// desktop presents, and the key exchange read from the other side.
//
// A client has no public key infrastructure to check a server
// certificate against -- the protocol never had one -- so what it
// checks instead is a signature made with one key: the Terminal
// Services signing key, whose private half Microsoft published in
// MS-RDPBCGR 5.3.3.1.1 and whose public half is built into every
// client. It is below, because a gateway that cannot sign with it
// cannot speak this protocol to a client at all.
//
// That is worth being plain about rather than burying: **this
// signature authenticates nothing**. Anybody can make it, which is
// what publishing a private key means, so a client that verifies it
// has learned only that the other end read the specification. The
// encryption it protects is RC4 under MD5 and SHA-1. Offering this to
// clients is for equipment that speaks nothing else, and the security
// of such a session rests on the network it runs over, not on this.

// TerminalServicesKey is the key of MS-RDPBCGR 5.3.3.1.1: the modulus,
// private exponent and public exponent Microsoft published so that
// implementations could sign proprietary certificates. The bytes are
// as the specification prints them, little-endian.
//
// Publishing a private key makes it not a key. It is here for exactly
// the reason it was published: without it this gateway cannot present
// a certificate an old client will accept.
var (
	tsModulus = []byte{
		0x3d, 0x3a, 0x5e, 0xbd, 0x72, 0x43, 0x3e, 0xc9,
		0x4d, 0xbb, 0xc1, 0x1e, 0x4a, 0xba, 0x5f, 0xcb,
		0x3e, 0x88, 0x20, 0x87, 0xef, 0xf5, 0xc1, 0xe2,
		0xd7, 0xb7, 0x6b, 0x9a, 0xf2, 0x52, 0x45, 0x95,
		0xce, 0x63, 0x65, 0x6b, 0x58, 0x3a, 0xfe, 0xef,
		0x7c, 0xe7, 0xbf, 0xfe, 0x3d, 0xf6, 0x5c, 0x7d,
		0x6c, 0x5e, 0x06, 0x09, 0x1a, 0xf5, 0x61, 0xbb,
		0x20, 0x93, 0x09, 0x5f, 0x05, 0x6d, 0xea, 0x87,
	}
	tsPrivateExponent = []byte{
		0x87, 0xa7, 0x19, 0x32, 0xda, 0x11, 0x87, 0x55,
		0x58, 0x00, 0x16, 0x16, 0x25, 0x65, 0x68, 0xf8,
		0x24, 0x3e, 0xe6, 0xfa, 0xe9, 0x67, 0x49, 0x94,
		0xcf, 0x92, 0xcc, 0x33, 0x99, 0xe8, 0x08, 0x60,
		0x17, 0x9a, 0x12, 0x9f, 0x24, 0xdd, 0xb1, 0x24,
		0x99, 0xc7, 0x3a, 0xb8, 0x0a, 0x7b, 0x0d, 0xdd,
		0x35, 0x07, 0x79, 0x17, 0x0b, 0x51, 0x9b, 0xb3,
		0xc7, 0x10, 0x01, 0x13, 0xe7, 0x3f, 0xf3, 0x5f,
	}
	tsPublicExponent = []byte{0x5b, 0x7b, 0x88, 0xc0}
)

// The certificate and key blob constants of MS-RDPBCGR 2.2.1.4.3.1.1
// and 2.2.1.4.3.1.1.1.
const (
	certChainVersion1 = 0x00000001
	signatureAlgRSA   = 0x00000001
	keyExchangeAlgRSA = 0x00000001
	blobRSAKey        = 0x0006
	blobRSASignature  = 0x0008
	// rsaPadding is the eight bytes that follow the modulus and the
	// signature, which is why a key length is the modulus plus eight.
	rsaPadding = 8
	// legacyKeyBits is the size the protocol's own certificates carry.
	// It is not a choice: a client expects it.
	legacyKeyBits = 512
)

// NewLegacyKey draws the key a legacy listener presents. It is five
// hundred and twelve bits because the protocol says so, which the
// standard library will not generate any more and is right not to --
// so the primes are drawn here instead. Anything a session protects
// with this key is protected for about as long as somebody cares to
// factor it.
func NewLegacyKey() (*rsa.PrivateKey, error) {
	e := big.NewInt(65537)
	one := big.NewInt(1)
	for attempt := 0; attempt < 32; attempt++ {
		p, err := rand.Prime(rand.Reader, legacyKeyBits/2)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(rand.Reader, legacyKeyBits/2)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != legacyKeyBits {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		return key, nil
	}
	return nil, fmt.Errorf("%w: no key could be drawn", ErrLegacy)
}

// EncodeRSAPublicKey renders a key as the blob a certificate carries
// (MS-RDPBCGR 2.2.1.4.3.1.1.1): everything little-endian, the modulus
// reversed, and eight bytes of padding behind it which the length
// fields account for.
func EncodeRSAPublicKey(pub *rsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.N == nil {
		return nil, fmt.Errorf("%w: no key to encode", ErrLegacy)
	}
	size := (pub.N.BitLen() + 7) / 8
	if size < 64 || size > 1024 || pub.E <= 0 {
		return nil, fmt.Errorf("%w: a key of %d bits with exponent %d", ErrLegacy, pub.N.BitLen(), pub.E)
	}
	out := append([]byte(nil), rsaMagic...)
	out = binary.LittleEndian.AppendUint32(out, uint32(size+rsaPadding)) //nolint:gosec // bounded above
	out = binary.LittleEndian.AppendUint32(out, uint32(size*8))          //nolint:gosec // bounded above
	out = binary.LittleEndian.AppendUint32(out, uint32(size-1))          //nolint:gosec // bounded above
	out = binary.LittleEndian.AppendUint32(out, uint32(pub.E))           //nolint:gosec // checked above
	out = append(out, reverse(leftPad(pub.N.Bytes(), size))...)
	return append(out, make([]byte, rsaPadding)...), nil
}

// ProprietaryCertificate builds the certificate a legacy client is
// given: the key, and a signature over the fields in front of it made
// with the published key.
func ProprietaryCertificate(pub *rsa.PublicKey) ([]byte, error) {
	blob, err := EncodeRSAPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if len(blob) > 0xFFFF {
		return nil, fmt.Errorf("%w: a key blob of %d bytes", ErrLegacy, len(blob))
	}
	signed := binary.LittleEndian.AppendUint32(nil, certChainVersion1)
	signed = binary.LittleEndian.AppendUint32(signed, signatureAlgRSA)
	signed = binary.LittleEndian.AppendUint32(signed, keyExchangeAlgRSA)
	signed = binary.LittleEndian.AppendUint16(signed, blobRSAKey)
	signed = binary.LittleEndian.AppendUint16(signed, uint16(len(blob))) //nolint:gosec // bounded above
	signed = append(signed, blob...)

	sig := SignProprietary(signed)
	out := append([]byte(nil), signed...)
	out = binary.LittleEndian.AppendUint16(out, blobRSASignature)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(sig)+rsaPadding)) //nolint:gosec // a fixed 64 byte signature
	out = append(out, sig...)
	return append(out, make([]byte, rsaPadding)...), nil
}

// SignProprietary signs the first six fields of a proprietary
// certificate with the published key, as MS-RDPBCGR 5.3.3.1.2 sets
// out: an MD5 over those fields, copied into the front of a sixty
// three byte array of ones that ends in a one, then read as a
// little-endian integer and raised to the private exponent.
func SignProprietary(fields []byte) []byte {
	sum := md5.Sum(fields) //nolint:gosec // the protocol specifies MD5
	m := new(big.Int).SetBytes(reverse(signaturePadding(sum[:])))
	n := new(big.Int).SetBytes(reverse(tsModulus))
	d := new(big.Int).SetBytes(reverse(tsPrivateExponent))
	s := new(big.Int).Exp(m, d, n)
	return reverse(leftPad(s.Bytes(), len(tsModulus)))
}

// signaturePadding builds the sixty three byte array the hash is
// signed inside. One byte short of the modulus, so the value is
// always less than it.
func signaturePadding(hash []byte) []byte {
	out := make([]byte, len(tsModulus)-1)
	for i := range out {
		out[i] = 0xFF
	}
	copy(out, hash)
	out[len(hash)] = 0x00
	out[len(out)-1] = 0x01
	return out
}

// VerifyProprietary checks a signature the way a client does, with the
// public half of the published key. Nothing in this gateway needs to
// -- a desktop's certificate is read rather than trusted -- but the
// tests do, because a signature that is wrong in a way only a client
// notices is the failure worth catching here.
func VerifyProprietary(fields, signature []byte) bool {
	if len(signature) < len(tsModulus) {
		return false
	}
	n := new(big.Int).SetBytes(reverse(tsModulus))
	e := new(big.Int).SetBytes(reverse(tsPublicExponent))
	s := new(big.Int).SetBytes(reverse(signature[:len(tsModulus)]))
	m := new(big.Int).Exp(s, e, n)
	got := reverse(leftPad(m.Bytes(), len(tsModulus)-1))
	sum := md5.Sum(fields) //nolint:gosec // the protocol specifies MD5
	want := signaturePadding(sum[:])
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ServerSecurityData renders the block a server puts in the conference
// response: what it will encrypt with, its random, and the
// certificate carrying the key the client's random travels under.
func ServerSecurityData(method, level uint32, random, certificate []byte) ([]byte, error) {
	if method != 0 && len(random) != RandomSize {
		return nil, fmt.Errorf("%w: a server random of %d bytes", ErrLegacy, len(random))
	}
	out := binary.LittleEndian.AppendUint32(nil, method)
	out = binary.LittleEndian.AppendUint32(out, level)
	if method == 0 && level == EncryptionLevelNone {
		// A server that encrypts nothing sends the two words and
		// stops; there is no random and no certificate to send.
		return out, nil
	}
	out = binary.LittleEndian.AppendUint32(out, uint32(len(random)))      //nolint:gosec // checked above
	out = binary.LittleEndian.AppendUint32(out, uint32(len(certificate))) //nolint:gosec // bounded by the caller
	out = append(out, random...)
	return append(out, certificate...), nil
}

// ParseClientSecurity reads what a client said it can encrypt with.
func ParseClientSecurity(b []byte) (methods uint32, err error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("%w: a client security block of %d bytes", ErrLegacy, len(b))
	}
	return binary.LittleEndian.Uint32(b[0:4]), nil
}

// StrongestMethod picks what a session will use out of what the client
// offered. Strongest first, and FIPS is not among them: it is 3DES
// with a different derivation and a different packet layout, so a
// server that claimed it would fail after the exchange rather than
// before it.
func StrongestMethod(offered uint32) (uint32, bool) {
	for _, m := range []uint32{Encryption128Bit, Encryption56Bit, Encryption40Bit} {
		if offered&m != 0 {
			return m, true
		}
	}
	return 0, false
}

// ParseSecurityExchange reads the packet a client sends with its
// random sealed under the server's key, and returns the sealed value.
func ParseSecurityExchange(payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("%w: a security exchange of %d bytes", ErrLegacy, len(payload))
	}
	n := int(binary.LittleEndian.Uint32(payload[0:4]))
	// The value is the key's size plus eight bytes of padding, and a
	// key is at most this package parses.
	if n < 8 || n > 1024+rsaPadding || 4+n > len(payload) {
		return nil, fmt.Errorf("%w: a sealed random of %d bytes with %d there", ErrLegacy, n, len(payload)-4)
	}
	return payload[4 : 4+n], nil
}

// OpenClientRandom is the server's half of the key exchange: the raw
// RSA the protocol uses, with no padding scheme to check and so
// nothing to check it against.
func OpenClientRandom(key *rsa.PrivateKey, sealed []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: no key to open with", ErrLegacy)
	}
	size := (key.N.BitLen() + 7) / 8
	if len(sealed) < size {
		return nil, fmt.Errorf("%w: a sealed random of %d bytes for a %d byte key", ErrLegacy, len(sealed), size)
	}
	// What follows the value is padding the client sends and nothing
	// reads.
	c := new(big.Int).SetBytes(reverse(sealed[:size]))
	if c.Cmp(key.N) >= 0 {
		return nil, fmt.Errorf("%w: a sealed value larger than the modulus", ErrLegacy)
	}
	m := new(big.Int).Exp(c, key.D, key.N)
	return reverse(leftPad(m.Bytes(), RandomSize)), nil
}
