package rdp

import (
	"bytes"
	"crypto/md5" //nolint:gosec // the protocol specifies MD5
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
)

// The published key has to be the published key. A private exponent
// that does not belong to the modulus produces a signature no client
// accepts, and nothing else in this package would notice: the failure
// appears only in front of a real client. So it is checked the way a
// client checks it, with the public half.
func TestThePublishedKeyIsConsistent(t *testing.T) {
	if len(tsModulus) != 64 || len(tsPrivateExponent) != 64 || len(tsPublicExponent) != 4 {
		t.Fatalf("lengths %d %d %d", len(tsModulus), len(tsPrivateExponent), len(tsPublicExponent))
	}
	n := new(big.Int).SetBytes(reverse(tsModulus))
	d := new(big.Int).SetBytes(reverse(tsPrivateExponent))
	e := new(big.Int).SetBytes(reverse(tsPublicExponent))
	if n.BitLen() != 512 {
		t.Fatalf("a modulus of %d bits", n.BitLen())
	}
	if e.Cmp(big.NewInt(0xc0887b5b)) != 0 {
		t.Fatalf("public exponent %#x", e)
	}
	// Signing and verifying has to be the identity, for values across
	// the range rather than one convenient one.
	for _, v := range []string{"1", "2", "65537",
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"3d3a5ebd72433ec94dbbc11e4aba5fcb3e882087eff5c1e2d7b76b9af2524594"} {
		m, ok := new(big.Int).SetString(v, 0)
		if !ok {
			m, _ = new(big.Int).SetString(v, 16)
		}
		if m.Cmp(n) >= 0 {
			continue
		}
		back := new(big.Int).Exp(new(big.Int).Exp(m, d, n), e, n)
		if back.Cmp(m) != 0 {
			t.Fatalf("%s did not survive signing and verifying", v)
		}
	}
}

// The padding is the specification's worked example, byte for byte:
// the hash printed in MS-RDPBCGR 5.3.3.1.2 in front of an array of
// ones that ends in a one.
func TestTheSignaturePaddingIsTheWorkedExample(t *testing.T) {
	hash := []byte{0xf5, 0xcc, 0x18, 0xee, 0x45, 0xe9, 0x4d, 0xa6,
		0x79, 0x02, 0xca, 0x76, 0x51, 0x33, 0xe1, 0x7f}
	want := append(append([]byte(nil), hash...), 0x00)
	for len(want) < 62 {
		want = append(want, 0xFF)
	}
	want = append(want, 0x01)
	got := signaturePadding(hash)
	if len(got) != 63 {
		t.Fatalf("a padded array of %d bytes", len(got))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("padding\n got %x\nwant %x", got, want)
	}
}

// A certificate this gateway makes verifies against the public half of
// the published key, which is the only check a client performs.
func TestACertificateVerifiesAsAClientWould(t *testing.T) {
	key, err := NewLegacyKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ProprietaryCertificate(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// The signed part is everything up to the signature blob type,
	// which is where a client stops hashing.
	blobLen := int(binary.LittleEndian.Uint16(cert[14:16]))
	signed := cert[:16+blobLen]
	sig := cert[16+blobLen+4:]
	if !VerifyProprietary(signed, sig) {
		t.Fatal("a client would refuse this certificate")
	}
	// And a certificate with one byte changed anywhere in the signed
	// part must not verify.
	for _, at := range []int{0, 4, 12, 16, 20, 40, len(signed) - 9} {
		tampered := append([]byte(nil), signed...)
		tampered[at] ^= 0x01
		if VerifyProprietary(tampered, sig) {
			t.Fatalf("a certificate with byte %d changed still verified", at)
		}
	}
	// The gateway reads its own certificate back the way a client does
	// and finds the key it put there.
	got, proprietary, err := parseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !proprietary || got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Fatalf("the key did not survive the certificate: %v %+v", proprietary, got)
	}
}

// The key blob's lengths are what the specification's example prints:
// the key length is the modulus plus eight, the bit length is the
// key's, and the data length is one less than the modulus.
func TestTheKeyBlobLengths(t *testing.T) {
	key, err := NewLegacyKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := EncodeRSAPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, rsaMagic) {
		t.Fatalf("magic %x", blob[:4])
	}
	if got := binary.LittleEndian.Uint32(blob[4:8]); got != 72 {
		t.Errorf("keylen %d, want 72", got)
	}
	if got := binary.LittleEndian.Uint32(blob[8:12]); got != 512 {
		t.Errorf("bitlen %d, want 512", got)
	}
	if got := binary.LittleEndian.Uint32(blob[12:16]); got != 63 {
		t.Errorf("datalen %d, want 63", got)
	}
	if got := binary.LittleEndian.Uint32(blob[16:20]); got != 65537 {
		t.Errorf("exponent %d, want 65537", got)
	}
	if len(blob) != 20+64+8 {
		t.Errorf("a blob of %d bytes", len(blob))
	}
	if _, err := EncodeRSAPublicKey(nil); !errors.Is(err, ErrLegacy) {
		t.Error("a nil key was encoded")
	}
}

// The key is the size the protocol carries, and it is a working key.
func TestTheLegacyKeyIsFiveHundredAndTwelveBits(t *testing.T) {
	for i := 0; i < 4; i++ {
		key, err := NewLegacyKey()
		if err != nil {
			t.Fatal(err)
		}
		if key.N.BitLen() != 512 {
			t.Fatalf("a key of %d bits", key.N.BitLen())
		}
		if len(key.Primes) != 2 || new(big.Int).Mul(key.Primes[0], key.Primes[1]).Cmp(key.N) != 0 {
			t.Fatal("the primes do not make the modulus")
		}
		// It has to open what it seals, which is the whole of what the
		// protocol asks of it.
		random, err := NewRandom()
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := SealClientRandom(&key.PublicKey, random)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenClientRandom(key, sealed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, random) {
			t.Fatalf("the random did not survive: %x want %x", got, random)
		}
	}
}

// Everything a client chooses about the exchange is checked before it
// is used: the length in front of the sealed value, and the value
// against the modulus.
func TestTheSecurityExchangeIsChecked(t *testing.T) {
	key, err := NewLegacyKey()
	if err != nil {
		t.Fatal(err)
	}
	random, _ := NewRandom()
	sealed, _ := SealClientRandom(&key.PublicKey, random)
	good := binary.LittleEndian.AppendUint32(nil, uint32(len(sealed)))
	good = append(good, sealed...)
	if got, err := ParseSecurityExchange(good); err != nil || !bytes.Equal(got, sealed) {
		t.Fatalf("a good exchange: %v", err)
	}
	cases := [][]byte{
		{},
		{0x01, 0x02},
		binary.LittleEndian.AppendUint32(nil, 0x1000),           // longer than what arrived
		binary.LittleEndian.AppendUint32(nil, 4),                // shorter than any key
		binary.LittleEndian.AppendUint32(nil, 0xFFFFFFFF),       // absurd
		append(binary.LittleEndian.AppendUint32(nil, 72), 0x00), // a length with nothing behind it
	}
	for i, c := range cases {
		if _, err := ParseSecurityExchange(c); !errors.Is(err, ErrLegacy) {
			t.Errorf("case %d was accepted", i)
		}
	}
	// A value at or past the modulus is refused rather than reduced.
	big := make([]byte, (key.N.BitLen()+7)/8)
	for i := range big {
		big[i] = 0xFF
	}
	if _, err := OpenClientRandom(key, big); !errors.Is(err, ErrLegacy) {
		t.Error("a value larger than the modulus was opened")
	}
	if _, err := OpenClientRandom(nil, sealed); !errors.Is(err, ErrLegacy) {
		t.Error("a random was opened with no key")
	}
	if _, err := OpenClientRandom(key, sealed[:8]); !errors.Is(err, ErrLegacy) {
		t.Error("a short sealed value was opened")
	}
}

func TestTheStrongestMethodIsChosen(t *testing.T) {
	for _, c := range []struct {
		offered uint32
		want    uint32
		ok      bool
	}{
		{Encryption128Bit | Encryption56Bit | Encryption40Bit, Encryption128Bit, true},
		{Encryption56Bit | Encryption40Bit, Encryption56Bit, true},
		{Encryption40Bit, Encryption40Bit, true},
		{EncryptionFIPS, 0, false},
		{0, 0, false},
	} {
		got, ok := StrongestMethod(c.offered)
		if got != c.want || ok != c.ok {
			t.Errorf("%#x gave %#x %v", c.offered, got, ok)
		}
	}
	if _, err := ParseClientSecurity([]byte{1, 2}); !errors.Is(err, ErrLegacy) {
		t.Error("a short client security block was accepted")
	}
	if got, err := ParseClientSecurity(EncodeClientSecurity(ClientMethods)); err != nil || got != ClientMethods {
		t.Errorf("round trip gave %#x (%v)", got, err)
	}
}

// The block a server sends parses as one, including the shape a server
// that encrypts nothing sends.
func TestServerSecurityDataRoundTrips(t *testing.T) {
	key, err := NewLegacyKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ProprietaryCertificate(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.Repeat([]byte{0x5A}, RandomSize)
	block, err := ServerSecurityData(Encryption128Bit, EncryptionLevelClientCompatible, random, cert)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseServerSecurity(block)
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != Encryption128Bit || got.Level != EncryptionLevelClientCompatible {
		t.Errorf("method %#x level %d", got.Method, got.Level)
	}
	if !bytes.Equal(got.Random, random) || got.PublicKey == nil || got.PublicKey.N.Cmp(key.N) != 0 {
		t.Error("the random or the key did not survive")
	}
	none, err := ServerSecurityData(0, EncryptionLevelNone, nil, nil)
	if err != nil || len(none) != 8 {
		t.Fatalf("a block promising nothing: %x (%v)", none, err)
	}
	if _, err := ServerSecurityData(Encryption128Bit, EncryptionLevelLow, []byte{1, 2}, cert); !errors.Is(err, ErrLegacy) {
		t.Error("a short random was accepted")
	}
}

// The hash is over the six fields in the order the specification names
// them, which is the one thing a client and a server have to agree on
// without being able to negotiate it.
func TestTheHashCoversTheSixFields(t *testing.T) {
	key, err := NewLegacyKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := EncodeRSAPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fields := binary.LittleEndian.AppendUint32(nil, certChainVersion1)
	fields = binary.LittleEndian.AppendUint32(fields, signatureAlgRSA)
	fields = binary.LittleEndian.AppendUint32(fields, keyExchangeAlgRSA)
	fields = binary.LittleEndian.AppendUint16(fields, blobRSAKey)
	fields = binary.LittleEndian.AppendUint16(fields, uint16(len(blob)))
	fields = append(fields, blob...)

	cert, err := ProprietaryCertificate(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(cert, fields) {
		t.Fatal("the certificate does not begin with the six fields")
	}
	sum := md5.Sum(fields) //nolint:gosec // the protocol specifies MD5
	if !bytes.Equal(signaturePadding(sum[:]), signaturePadding(sum[:])) {
		t.Fatal("unreachable")
	}
	if !VerifyProprietary(fields, cert[len(fields)+4:]) {
		t.Fatal("the signature does not cover exactly those fields")
	}
}
