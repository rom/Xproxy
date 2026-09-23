package rdp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
)

// buildRSABlob renders a public key the way the protocol's own
// certificate carries it.
func buildRSABlob(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	size := (pub.N.BitLen() + 7) / 8
	out := append([]byte(nil), rsaMagic...)
	out = binary.LittleEndian.AppendUint32(out, uint32(size+8)) // keylen
	out = binary.LittleEndian.AppendUint32(out, uint32(size*8)) // bitlen
	out = binary.LittleEndian.AppendUint32(out, uint32(size-8)) // datalen
	out = binary.LittleEndian.AppendUint32(out, uint32(pub.E))
	out = append(out, reverse(leftPad(pub.N.Bytes(), size))...)
	return append(out, make([]byte, 8)...)
}

// buildCertificate wraps the blob in a proprietary certificate.
func buildCertificate(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	blob := buildRSABlob(t, pub)
	out := binary.LittleEndian.AppendUint32(nil, 1)     // version
	out = binary.LittleEndian.AppendUint32(out, 1)      // signature algorithm
	out = binary.LittleEndian.AppendUint32(out, 1)      // key algorithm
	out = binary.LittleEndian.AppendUint16(out, 0x0006) // key blob type
	out = binary.LittleEndian.AppendUint16(out, uint16(len(blob)))
	out = append(out, blob...)
	out = binary.LittleEndian.AppendUint16(out, 0x0008) // signature blob type
	out = binary.LittleEndian.AppendUint16(out, 64)
	return append(out, make([]byte, 64)...)
}

// buildServerSecurity renders a desktop's security block.
func buildServerSecurity(t *testing.T, method, level uint32, random []byte, pub *rsa.PublicKey) []byte {
	t.Helper()
	cert := buildCertificate(t, pub)
	out := binary.LittleEndian.AppendUint32(nil, method)
	out = binary.LittleEndian.AppendUint32(out, level)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(random)))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(cert)))
	out = append(out, random...)
	return append(out, cert...)
}

// The desktop's block parses and its key comes back intact, which is
// what the client random travels under.
func TestServerSecurityParses(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.Repeat([]byte{0xA5}, RandomSize)
	got, err := ParseServerSecurity(buildServerSecurity(t, Encryption128Bit, EncryptionLevelLow, random, &key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != Encryption128Bit || got.Level != EncryptionLevelLow {
		t.Errorf("method %#x level %d", got.Method, got.Level)
	}
	if !bytes.Equal(got.Random, random) {
		t.Error("the server random did not survive")
	}
	if got.PublicKey == nil || got.PublicKey.N.Cmp(key.N) != 0 || got.PublicKey.E != key.E {
		t.Error("the key did not survive the certificate")
	}
	if !got.Proprietary {
		t.Error("a proprietary certificate was not recognised as one")
	}

	// A desktop on TLS says it encrypts nothing, and that parses too.
	none, err := ParseServerSecurity(EncodeServerSecurity(0, EncryptionLevelNone))
	if err != nil {
		t.Fatal(err)
	}
	if none.PublicKey != nil || none.Method != 0 {
		t.Errorf("a block promising nothing: %+v", none)
	}
}

// Every length in the block is the desktop's to choose.
func TestServerSecurityLengthsAreChecked(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	good := buildServerSecurity(t, Encryption128Bit, EncryptionLevelLow,
		bytes.Repeat([]byte{1}, RandomSize), &key.PublicKey)
	cases := []struct {
		name string
		make func() []byte
	}{
		{"shorter than its own header", func() []byte { return good[:6] }},
		{"a method with no body", func() []byte { return good[:12] }},
		{"a random of the wrong size", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[8:12], 64)
			return b
		}},
		{"a certificate past the block", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[12:16], 0x2000)
			return b
		}},
		{"a certificate over the bound", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[12:16], maxCertificate+1)
			return b
		}},
	}
	for _, c := range cases {
		if _, err := ParseServerSecurity(c.make()); !errors.Is(err, ErrLegacy) {
			t.Errorf("%s was accepted (%v)", c.name, err)
		}
	}
}

// A certificate chain is refused rather than walked: the protocol
// gives a client nothing to check one against.
func TestACertificateChainIsRefused(t *testing.T) {
	b := binary.LittleEndian.AppendUint32(nil, Encryption128Bit)
	b = binary.LittleEndian.AppendUint32(b, EncryptionLevelLow)
	b = binary.LittleEndian.AppendUint32(b, RandomSize)
	chain := binary.LittleEndian.AppendUint32(nil, 2) // an X.509 chain
	b = binary.LittleEndian.AppendUint32(b, uint32(len(chain)))
	b = append(b, bytes.Repeat([]byte{0}, RandomSize)...)
	b = append(b, chain...)
	if _, err := ParseServerSecurity(b); !errors.Is(err, ErrLegacy) {
		t.Error("a certificate chain was walked")
	}
}

// A key blob that is not one, or one with a size or exponent that
// cannot be right, is refused before any arithmetic is done on it.
func TestRSABlobsAreChecked(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	good := buildRSABlob(t, &key.PublicKey)
	cases := []struct {
		name string
		make func() []byte
	}{
		{"not a blob at all", func() []byte { return bytes.Repeat([]byte{0}, 40) }},
		{"a key of no bits", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[8:12], 0)
			return b
		}},
		{"a key of a million bits", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[8:12], 1<<20)
			return b
		}},
		{"an even exponent", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[16:20], 4)
			return b
		}},
		{"a modulus past the blob", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[8:12], 4096)
			return b
		}},
	}
	for _, c := range cases {
		if _, err := parseRSAPublicKey(c.make()); !errors.Is(err, ErrLegacy) {
			t.Errorf("%s was accepted (%v)", c.name, err)
		}
	}
}

// The random is sealed under the desktop's key in the raw form the
// protocol uses, and the desktop gets back what was sent.
func TestTheClientRandomIsSealedForTheDesktop(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	random, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealClientRandom(&key.PublicKey, random)
	if err != nil {
		t.Fatal(err)
	}
	size := (key.N.BitLen() + 7) / 8
	if len(sealed) != size+8 {
		t.Fatalf("%d bytes sealed for a %d byte key", len(sealed), size)
	}
	if bytes.Contains(sealed, random) {
		t.Error("the random went out in clear")
	}
	// What the desktop does with it: raw RSA, and the value is
	// little-endian both ways.
	c := new(big.Int).SetBytes(reverse(sealed[:size]))
	m := new(big.Int).Exp(c, key.D, key.N)
	if got := reverse(leftPad(m.Bytes(), RandomSize)); !bytes.Equal(got, random) {
		t.Errorf("the desktop would recover %x, want %x", got, random)
	}

	if _, err := SealClientRandom(nil, random); !errors.Is(err, ErrLegacy) {
		t.Error("a random was sealed under no key at all")
	}
	if _, err := SealClientRandom(&key.PublicKey, random[:8]); !errors.Is(err, ErrLegacy) {
		t.Error("a short random was sealed")
	}
}

// The two ends derive the same keys, each end's encrypt key being the
// other's decrypt key.
func TestBothEndsDeriveTheSameKeys(t *testing.T) {
	clientRandom := bytes.Repeat([]byte{0x11}, RandomSize)
	serverRandom := bytes.Repeat([]byte{0x22}, RandomSize)
	k, err := DeriveKeys(Encryption128Bit, clientRandom, serverRandom)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.MAC) != 16 || len(k.Encrypt) != 16 || len(k.Decrypt) != 16 {
		t.Fatalf("keys of %d, %d and %d bytes", len(k.MAC), len(k.Encrypt), len(k.Decrypt))
	}
	if bytes.Equal(k.Encrypt, k.Decrypt) {
		t.Error("the two directions got the same key")
	}
	if bytes.Equal(k.MAC, k.Encrypt) || bytes.Equal(k.MAC, k.Decrypt) {
		t.Error("the signing key is one of the encryption keys")
	}
	// Another pair of randoms is another set of keys.
	other, err := DeriveKeys(Encryption128Bit, clientRandom, bytes.Repeat([]byte{0x33}, RandomSize))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k.Encrypt, other.Encrypt) {
		t.Error("two sessions derived the same key")
	}

	// The weakened methods carry fewer bits, and say so in the first
	// bytes the way the protocol does.
	weak, err := DeriveKeys(Encryption40Bit, clientRandom, serverRandom)
	if err != nil {
		t.Fatal(err)
	}
	if len(weak.Encrypt) != 8 || weak.Encrypt[0] != 0xD1 || weak.Encrypt[1] != 0x26 {
		t.Errorf("a 40 bit key is %x", weak.Encrypt)
	}
	if _, err := DeriveKeys(EncryptionFIPS, clientRandom, serverRandom); !errors.Is(err, ErrLegacy) {
		t.Error("FIPS mode was accepted")
	}
	if _, err := DeriveKeys(0x99, clientRandom, serverRandom); !errors.Is(err, ErrLegacy) {
		t.Error("an encryption method that is not one was accepted")
	}
	if _, err := DeriveKeys(Encryption128Bit, clientRandom[:8], serverRandom); !errors.Is(err, ErrLegacy) {
		t.Error("a short random was accepted")
	}
}

// What one end encrypts the other decrypts, with the signature
// matching, across a key rollover.
func TestASessionSurvivesAKeyRollover(t *testing.T) {
	k, err := DeriveKeys(Encryption128Bit, bytes.Repeat([]byte{1}, RandomSize), bytes.Repeat([]byte{2}, RandomSize))
	if err != nil {
		t.Fatal(err)
	}
	out, err := NewCrypt(k, k.Encrypt, Encryption128Bit)
	if err != nil {
		t.Fatal(err)
	}
	// The far end reads with the key this end writes with.
	in, err := NewCrypt(k, k.Encrypt, Encryption128Bit)
	if err != nil {
		t.Fatal(err)
	}
	// Enough packets to cross the rollover twice.
	for i := 0; i < rekeyEvery*2+5; i++ {
		msg := []byte("a packet of the session")
		want := append([]byte(nil), msg...)
		sig := out.Sign(msg)
		if err := out.Apply(msg); err != nil {
			t.Fatal(err)
		}
		if i == 0 && bytes.Equal(msg, want) {
			t.Fatal("the packet was not encrypted")
		}
		if err := in.Apply(msg); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(msg, want) {
			t.Fatalf("packet %d came back as %q", i, msg)
		}
		if got := in.Sign(msg); !bytes.Equal(got, sig) {
			t.Fatalf("packet %d: the signature does not match", i)
		}
	}
	if out.count >= rekeyEvery {
		t.Errorf("the key did not roll over: %d packets on it", out.count)
	}
}

// A signature covers the packet, so a changed one does not match.
func TestTheSignatureCoversThePacket(t *testing.T) {
	k, err := DeriveKeys(Encryption128Bit, bytes.Repeat([]byte{1}, RandomSize), bytes.Repeat([]byte{2}, RandomSize))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCrypt(k, k.Encrypt, Encryption128Bit)
	if err != nil {
		t.Fatal(err)
	}
	sig := c.Sign([]byte("what the desktop showed"))
	if len(sig) != 8 {
		t.Fatalf("a signature of %d bytes", len(sig))
	}
	if other := c.Sign([]byte("what the desktop showee")); bytes.Equal(sig, other) {
		t.Error("two different packets signed the same")
	}
	if other := c.Sign([]byte("what the desktop showed ")); bytes.Equal(sig, other) {
		t.Error("a longer packet signed the same")
	}
}

// The packet that carries the sealed random is the shape the desktop
// expects.
func TestSecurityExchangeShape(t *testing.T) {
	sealed := bytes.Repeat([]byte{0xEE}, 264)
	pkt := SecurityExchange(sealed)
	head, rest, err := ParseSecurityHeader(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if head.Flags&SecExchangePkt == 0 {
		t.Errorf("flags %#x do not say it is an exchange", head.Flags)
	}
	if n := binary.LittleEndian.Uint32(rest[0:4]); int(n) != len(sealed) {
		t.Errorf("the length says %d for %d bytes", n, len(sealed))
	}
	if !bytes.Equal(rest[4:], sealed) {
		t.Error("the sealed random did not survive")
	}
}

// TestAPacketSurvivesTheRoundTrip: what one end seals the other opens,
// with the header's own flags kept and the encryption flag added.
func TestAPacketSurvivesTheRoundTrip(t *testing.T) {
	client, server := pair(t, Encryption128Bit)
	payload := []byte("the client info packet, or anything else")
	sealed, err := client.Seal(SecInfoPkt, payload)
	if err != nil {
		t.Fatal(err)
	}
	head, rest, err := ParseSecurityHeader(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if head.Flags != SecInfoPkt|SecEncrypt {
		t.Fatalf("flags %#x", head.Flags)
	}
	if bytes.Contains(sealed, payload) {
		t.Fatal("the payload travelled in clear inside the sealed packet")
	}
	plain, err := server.Open(rest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatalf("round trip gave %q", plain)
	}
}

// TestATamperedPacketIsRefused: the signature is what says the packet
// arrived as it left, and a gateway that shrugged at a bad one would
// be forwarding whatever somebody on the path put there.
func TestATamperedPacketIsRefused(t *testing.T) {
	for _, flip := range []int{0, 3, 8, 20} {
		client, server := pair(t, Encryption128Bit)
		sealed, err := client.Seal(0, []byte("0123456789abcdefghij"))
		if err != nil {
			t.Fatal(err)
		}
		_, rest, err := ParseSecurityHeader(sealed)
		if err != nil {
			t.Fatal(err)
		}
		if flip >= len(rest) {
			continue
		}
		rest[flip] ^= 0x01
		if _, err := server.Open(rest); err == nil {
			t.Fatalf("a packet with byte %d flipped was accepted", flip)
		}
	}
}

// TestAShortEncryptedPacketIsRefused: everything after the header is
// the peer's to choose, including its length.
func TestAShortEncryptedPacketIsRefused(t *testing.T) {
	_, server := pair(t, Encryption128Bit)
	for n := 0; n < 8; n++ {
		if _, err := server.Open(make([]byte, n)); err == nil {
			t.Fatalf("an encrypted payload of %d bytes was accepted", n)
		}
	}
}

// TestFastPathSurvivesTheRoundTrip: the other framing, where the
// header says whether the rest is encrypted and the length has to be
// rewritten because the signature changes the size.
func TestFastPathSurvivesTheRoundTrip(t *testing.T) {
	for _, size := range []int{1, 100, 118, 119, 120, 200, 4000} {
		client, server := pair(t, Encryption128Bit)
		body := bytes.Repeat([]byte{0xAB}, size)
		raw := fastPathUnit(body)
		if FastPathEncrypted(raw) {
			t.Fatal("a plain unit says it is encrypted")
		}
		sealed, err := client.FastPathSeal(raw)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if !FastPathEncrypted(sealed) {
			t.Fatalf("%d bytes: the sealed unit does not say so", size)
		}
		if n := fastPathLength(t, sealed); n != len(sealed) {
			t.Fatalf("%d bytes: the header says %d and the unit is %d", size, n, len(sealed))
		}
		back, err := server.FastPathOpen(sealed)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if FastPathEncrypted(back) {
			t.Fatalf("%d bytes: the opened unit still says it is encrypted", size)
		}
		if n := fastPathLength(t, back); n != len(back) {
			t.Fatalf("%d bytes: the opened header says %d and the unit is %d", size, n, len(back))
		}
		if _, got, err := splitFastPath(back); err != nil || !bytes.Equal(got, body) {
			t.Fatalf("%d bytes: round trip gave %x (%v)", size, got, err)
		}
	}
}

func TestFastPathRefusesWhatIsNotOne(t *testing.T) {
	client, _ := pair(t, Encryption128Bit)
	for _, raw := range [][]byte{{}, {0x00}, {0x00, 0x80}} {
		if _, err := client.FastPathSeal(raw); err == nil {
			t.Fatalf("a unit of %d bytes was sealed", len(raw))
		}
	}
	if FastPathEncrypted(nil) {
		t.Fatal("nothing says it is encrypted")
	}
}

// pair builds the two ends of a session, each with the other's view of
// the two keys.
func pair(t *testing.T, method uint32) (client, server *Crypt) {
	t.Helper()
	clientRandom, serverRandom := make([]byte, RandomSize), make([]byte, RandomSize)
	for i := range clientRandom {
		clientRandom[i], serverRandom[i] = byte(i), byte(255-i)
	}
	keys, err := DeriveKeys(method, clientRandom, serverRandom)
	if err != nil {
		t.Fatal(err)
	}
	if client, err = NewCrypt(keys, keys.Encrypt, method); err != nil {
		t.Fatal(err)
	}
	if server, err = NewCrypt(keys, keys.Encrypt, method); err != nil {
		t.Fatal(err)
	}
	return client, server
}

// fastPathUnit wraps a body in the framing, choosing the one or two
// byte length the way a peer would.
func fastPathUnit(body []byte) []byte {
	if n := len(body) + 2; n < 0x80 {
		return append([]byte{0x00, byte(n)}, body...)
	}
	n := len(body) + 3
	return append([]byte{0x00, byte(0x80 | n>>8), byte(n)}, body...)
}

func fastPathLength(t *testing.T, raw []byte) int {
	t.Helper()
	if len(raw) < 2 {
		t.Fatal("not a fast path unit")
	}
	if raw[1]&0x80 == 0 {
		return int(raw[1])
	}
	if len(raw) < 3 {
		t.Fatal("a two byte length with one byte there")
	}
	return int(raw[1]&0x7F)<<8 | int(raw[2])
}
