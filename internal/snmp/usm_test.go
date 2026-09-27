package snmp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:staticcheck,gosec // the protocol's own cipher, in a test of reading it
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"testing"
)

// The key derivation, against RFC 3414 Appendix A.3's own vectors.
//
// They are the only published check on this: the derivation is a megabyte of
// hashing followed by a localisation step, and an implementation that got
// either wrong would produce keys that agree with nothing. The same two
// vectors appear in every library that speaks this protocol, which is what
// makes them worth testing against rather than against ourselves.
func TestPasswordToKeyMatchesTheStandardsVectors(t *testing.T) {
	engine := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	for _, tc := range []struct {
		algo AuthAlgo
		want string
	}{
		{AuthMD5, "526f5eed9fcce26f8964c2930787d82b"},
		{AuthSHA1, "6695febc9288e36282235fc7151f128497b38f3f"},
	} {
		got := PasswordToKey(tc.algo, "maplesyrup", engine)
		if hex(got) != tc.want {
			t.Errorf("%s: %x, want %s", tc.algo, got, tc.want)
		}
		if len(got) != tc.algo.KeyLen() {
			t.Errorf("%s: a key of %d octets, and the hash is %d", tc.algo, len(got), tc.algo.KeyLen())
		}
	}
	// A key is localised to one engine: the same pass phrase on another
	// engine is another key, which is the whole point of the second step.
	other := PasswordToKey(AuthMD5, "maplesyrup", []byte{1, 2, 3})
	if bytes.Equal(other, PasswordToKey(AuthMD5, "maplesyrup", engine)) {
		t.Error("the same pass phrase produced the same key for two engines")
	}
	// And an empty pass phrase has no key rather than the hash of nothing.
	if k := PasswordToKey(AuthMD5, "", engine); k != nil {
		t.Errorf("an empty pass phrase produced %x", k)
	}
}

// The digest, end to end: a message signed with a key verifies, and the same
// message with one octet changed does not.
//
// The test signs the message itself, the way a manager does, which is also
// what checks the offset the parser reports: sign at the offset the parser
// found, and the verifier has to agree about where the field was.
func TestAnAuthenticatedMessageVerifies(t *testing.T) {
	for _, algo := range AuthAlgos {
		key := PasswordToKey(algo, "maplesyrup", []byte("engine-a"))
		raw := signedV3(t, algo, key, "poller", nil)
		m, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		if m.V3.AuthParamsAt == 0 {
			t.Fatalf("%s: the parser reported no digest offset", algo)
		}
		if err := Verify(m, key, algo); err != nil {
			t.Errorf("%s: an honest message did not verify: %v", algo, err)
		}
		// The wrong key.
		if err := Verify(m, PasswordToKey(algo, "other", []byte("engine-a")), algo); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: the wrong key verified: %v", algo, err)
		}
		// One octet of the message changed, in the part a relay reads for
		// policy: the user name. This is the forgery the digest exists to
		// stop, and the one a relay that only read the header would carry.
		tampered := make([]byte, len(raw))
		copy(tampered, raw)
		at := bytes.Index(tampered, []byte("poller"))
		if at < 0 {
			t.Fatalf("%s: the user name is not in the message", algo)
		}
		tampered[at] = 'P'
		bad, err := Parse(tampered)
		if err != nil {
			t.Fatalf("%s: the tampered message did not parse: %v", algo, err)
		}
		if err := Verify(bad, key, algo); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: a tampered message verified: %v", algo, err)
		}
		// And a digest of the wrong length is not a digest. The header is
		// rebuilt rather than mutated in place: m is a pointer and the cases
		// after this one would inherit the damage.
		short := &Message{Raw: m.Raw, Version: V3, V3: &V3Header{
			AuthParams:   m.V3.AuthParams[:len(m.V3.AuthParams)-1],
			AuthParamsAt: m.V3.AuthParamsAt,
		}}
		if err := Verify(short, key, algo); !errors.Is(err, ErrNoAuthParams) {
			t.Errorf("%s: a short digest was treated as one: %v", algo, err)
		}
	}
}

// The bounds Verify puts on a header it is handed.
//
// Verify is exported and the header it reads is a struct a caller can build,
// so the offset and the length in it are not necessarily the ones a parse
// produced. A digest that runs off the end of the message would be a slice
// out of range, which is why the offset is checked against the message rather
// than trusted: the check turns a panic into a refusal.
func TestVerifyRefusesAHeaderThatDoesNotFitItsMessage(t *testing.T) {
	key := PasswordToKey(AuthMD5, "maplesyrup", []byte("engine-a"))
	raw := signedV3(t, AuthMD5, key, "poller", nil)
	digest := make([]byte, 12)
	for _, tc := range []struct {
		what string
		at   int
	}{
		{"an offset past the end of the message", len(raw)},
		{"an offset whose digest runs off the end", len(raw) - 4},
		{"no offset at all", 0},
		{"a negative offset", -1},
	} {
		m := &Message{Raw: raw, Version: V3, V3: &V3Header{AuthParams: digest, AuthParamsAt: tc.at}}
		if err := Verify(m, key, AuthMD5); !errors.Is(err, ErrNoAuthParams) {
			t.Errorf("%s was read as a digest: %v", tc.what, err)
		}
	}
	// A message with no header at all, and an algorithm that is not one.
	if err := Verify(&Message{Raw: raw, Version: V3}, key, AuthMD5); !errors.Is(err, ErrAuth) {
		t.Error("a message with no version 3 header verified")
	}
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(m, key, AuthAlgo("md4")); !errors.Is(err, ErrAuth) {
		t.Error("an algorithm that does not exist verified")
	}
	if err := Verify(m, nil, AuthMD5); !errors.Is(err, ErrAuth) {
		t.Error("an empty key verified")
	}
}

// The privacy layer, both ciphers: a scoped PDU encrypted the way a manager
// encrypts it reads back as the PDU that went in.
func TestAnEncryptedScopedPDUReadsBack(t *testing.T) {
	for _, tc := range []struct {
		priv PrivAlgo
		auth AuthAlgo
	}{
		{PrivDES, AuthMD5},
		{PrivAES128, AuthMD5},
		{PrivAES192, AuthSHA256},
		{PrivAES256, AuthSHA256},
	} {
		authKey := PasswordToKey(tc.auth, "maplesyrup", []byte("engine-a"))
		privKey := PasswordToKey(tc.auth, "othersyrup", []byte("engine-a"))
		scoped := usmScoped(t, 4242, "1.3.6.1.2.1.1.1.0")
		ct := encrypt(t, tc.priv, privKey, scoped)
		raw := signedV3(t, tc.auth, authKey, "poller", ct)
		m, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.priv, err)
		}
		if !m.V3.ScopedPDUEncrypted || m.PDU != nil {
			t.Fatalf("%s: the parser read a PDU out of a privacy blob", tc.priv)
		}
		if err := Verify(m, authKey, tc.auth); err != nil {
			t.Fatalf("%s: %v", tc.priv, err)
		}
		plain, err := Decrypt(m, privKey, tc.priv)
		if err != nil {
			t.Fatalf("%s: %v", tc.priv, err)
		}
		s, err := ParseScoped(plain)
		if err != nil {
			t.Fatalf("%s: the decrypted scoped PDU did not parse: %v", tc.priv, err)
		}
		if s.PDU == nil || s.PDU.Type != GetRequest || s.PDU.RequestID != 4242 {
			t.Errorf("%s: read back %+v", tc.priv, s.PDU)
		}
		if len(s.PDU.VarBinds) != 1 || s.PDU.VarBinds[0].OID.String() != "1.3.6.1.2.1.1.1.0" {
			t.Errorf("%s: the bindings read back as %+v", tc.priv, s.PDU.VarBinds)
		}
		if s.ContextName != "" {
			t.Errorf("%s: the context name read back as %q", tc.priv, s.ContextName)
		}
		// The context engine id is the first field of the scoped PDU, which
		// is the part of it the initialisation vector decides: in a chaining
		// mode the vector affects the first block and nothing after it, so a
		// vector built wrongly shows up here and nowhere else.
		if string(s.ContextEngineID) != "engine-a" {
			t.Errorf("%s: the context engine id read back as %q", tc.priv, s.ContextEngineID)
		}
		// The wrong privacy key does not read back as a scoped PDU. It is
		// not guaranteed to fail to parse -- this is a cipher without
		// integrity, which is why the digest is what a relay trusts -- so
		// the assertion is that it does not come back as the same PDU.
		if wrong, err := Decrypt(m, PasswordToKey(tc.auth, "wrong", []byte("engine-a")), tc.priv); err == nil {
			if got, err := ParseScoped(wrong); err == nil && got.PDU != nil &&
				got.PDU.RequestID == 4242 && len(got.PDU.VarBinds) == 1 {
				t.Errorf("%s: the wrong key read back the same PDU", tc.priv)
			}
		}
	}
	// A key too short for the cipher is refused rather than padded: AES-256
	// on an MD5 key is sixteen octets where thirty-two are needed, and a
	// relay that padded it would be decrypting with a key nobody has.
	m, err := Parse(signedV3(t, AuthMD5, PasswordToKey(AuthMD5, "maplesyrup", []byte("engine-a")),
		"poller", bytes.Repeat([]byte{0}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(m, PasswordToKey(AuthMD5, "maplesyrup", []byte("engine-a")), PrivAES256); !errors.Is(err, ErrKeyLength) {
		t.Errorf("AES-256 on a 16-octet key: %v", err)
	}
}

// What a privacy blob has to look like before either cipher sees it.
//
// Both of these are lengths the ciphers cannot be handed: a salt that is not
// eight octets makes an initialisation vector of the wrong length, and a
// cipher-block chain that is not a whole number of blocks cannot be chained.
// Go's cipher package panics on either, so they are refusals here.
func TestDecryptRefusesLengthsTheCiphersCannotTake(t *testing.T) {
	key := PasswordToKey(AuthSHA256, "maplesyrup", []byte("engine-a"))
	header := func(salt, ct []byte) *Message {
		return &Message{Version: V3, V3: &V3Header{
			EngineBoots: 3, EngineTime: 12345,
			PrivParams: salt, Ciphertext: ct,
		}}
	}
	block := bytes.Repeat([]byte{0x11}, 32)
	for _, tc := range []struct {
		what string
		salt []byte
		priv PrivAlgo
		want error
	}{
		{"a salt of four octets, DES", bytes.Repeat([]byte{1}, 4), PrivDES, ErrPrivParams},
		{"a salt of four octets, AES", bytes.Repeat([]byte{1}, 4), PrivAES128, ErrPrivParams},
		{"a salt of sixteen octets, AES", bytes.Repeat([]byte{1}, 16), PrivAES128, ErrPrivParams},
		{"no salt at all", nil, PrivDES, ErrPrivParams},
	} {
		if _, err := Decrypt(header(tc.salt, block), key, tc.priv); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", tc.what, err)
		}
	}
	// A chain that stops mid-block. AES here is counter feedback, a stream
	// mode, so any length is decryptable and only DES refuses.
	if _, err := Decrypt(header(salt(), block[:7]), key, PrivDES); !errors.Is(err, ErrCiphertext) {
		t.Errorf("seven octets of DES ciphertext: %v", err)
	}
	if _, err := Decrypt(header(salt(), block[:7]), key, PrivAES128); err != nil {
		t.Errorf("seven octets of AES ciphertext: %v", err)
	}
	// And no ciphertext at all is not an authPriv message.
	if _, err := Decrypt(header(salt(), nil), key, PrivDES); !errors.Is(err, ErrCiphertext) {
		t.Errorf("an empty privacy blob: %v", err)
	}
	if _, err := Decrypt(nil, key, PrivDES); !errors.Is(err, ErrCiphertext) {
		t.Error("a nil message decrypted")
	}
	// A privacy protocol that is not one has no key length, so every key is
	// long enough for it; it must not fall through to a cipher.
	if _, err := Decrypt(header(salt(), block), key, PrivAlgo("rc4")); err == nil {
		t.Error("a privacy protocol that does not exist decrypted")
	}
}

// The names configuration accepts, and the lengths that go with them.
func TestTheAlgorithmNames(t *testing.T) {
	for _, s := range []string{"MD5", "sha-1", "SHA256", "sha-512"} {
		if _, ok := AuthAlgoOf(s); !ok {
			t.Errorf("%q is not read as an authentication protocol", s)
		}
	}
	if _, ok := AuthAlgoOf("sha3"); ok {
		t.Error("sha3 was read as an authentication protocol")
	}
	for _, s := range []string{"DES", "aes-128", "AES256"} {
		if _, ok := PrivAlgoOf(s); !ok {
			t.Errorf("%q is not read as a privacy protocol", s)
		}
	}
	if _, ok := PrivAlgoOf("3des"); ok {
		t.Error("3des was read as a privacy protocol")
	}
	// The digest lengths are the standards' own: 96 bits for RFC 3414's
	// two, and half the hash for each of RFC 7860's four.
	for algo, want := range map[AuthAlgo]int{
		AuthMD5: 12, AuthSHA1: 12, AuthSHA224: 16, AuthSHA256: 24, AuthSHA384: 32, AuthSHA512: 48,
	} {
		if got := algo.DigestLen(); got != want {
			t.Errorf("%s truncates to %d octets, want %d", algo, got, want)
		}
	}
}

// --- the builders, which are a manager's side of this protocol ---

// usmScoped is a scoped PDU with one GetRequest in it.
func usmScoped(t *testing.T, id int64, oid string) []byte {
	t.Helper()
	o, err := ParseOID(oid)
	if err != nil {
		t.Fatal(err)
	}
	pdu := encodeTLV(TagInteger, encodeInt(id))
	pdu = append(pdu, encodeTLV(TagInteger, encodeInt(0))...)
	pdu = append(pdu, encodeTLV(TagInteger, encodeInt(0))...)
	pdu = append(pdu, encodeTLV(TagSequence, Varbind(o, TagNull, nil))...)
	body := encodeTLV(TagOctetStr, []byte("engine-a"))
	body = append(body, encodeTLV(TagOctetStr, nil)...)
	body = append(body, encodeTLV(Tag(GetRequest), pdu)...)
	return encodeTLV(TagSequence, body)
}

// signedV3 builds a version 3 message and signs it the way a manager does:
// the digest field zeroed, the whole message hashed, the result written back.
// When ciphertext is given the message is authPriv and carries it.
func signedV3(t *testing.T, algo AuthAlgo, key []byte, user string, ciphertext []byte) []byte {
	t.Helper()
	flags := byte(0x05) // authNoPriv, reportable
	scoped := usmScoped(t, 4242, "1.3.6.1.2.1.1.1.0")
	if ciphertext != nil {
		flags = 0x07 // authPriv
		scoped = encodeTLV(TagOctetStr, ciphertext)
	}
	digest := make([]byte, algo.DigestLen())
	build := func(d []byte) []byte {
		usm := encodeTLV(TagOctetStr, []byte("engine-a"))
		usm = append(usm, encodeTLV(TagInteger, encodeInt(3))...)
		usm = append(usm, encodeTLV(TagInteger, encodeInt(12345))...)
		usm = append(usm, encodeTLV(TagOctetStr, []byte(user))...)
		usm = append(usm, encodeTLV(TagOctetStr, d)...)
		usm = append(usm, encodeTLV(TagOctetStr, salt())...)
		global := encodeTLV(TagInteger, encodeInt(7))
		global = append(global, encodeTLV(TagInteger, encodeInt(65507))...)
		global = append(global, encodeTLV(TagOctetStr, []byte{flags})...)
		global = append(global, encodeTLV(TagInteger, encodeInt(3))...)
		body := encodeTLV(TagInteger, encodeInt(int64(V3)))
		body = append(body, encodeTLV(TagSequence, global)...)
		body = append(body, encodeTLV(TagOctetStr, encodeTLV(TagSequence, usm))...)
		body = append(body, scoped...)
		return encodeTLV(TagSequence, body)
	}
	// Two passes: one to lay the message out with a zeroed digest, one to
	// write the digest of that layout back into the same place. The length
	// of the field does not change, so the second is the first with the
	// field filled in.
	zeroed := build(digest)
	mac := hmac.New(algo.newHash(), key)
	mac.Write(zeroed)
	sum := mac.Sum(nil)[:algo.DigestLen()]
	return build(sum)
}

// salt is the eight-octet privacy salt every authPriv message carries. Every
// octet differs from every other and none is zero, so a vector built without
// it, or with it in the wrong place, decrypts to something else -- a salt of
// mostly zeroes would let half the derivation be wrong unnoticed.
func salt() []byte { return []byte{0x9a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71} }

// encrypt is a manager's side of the privacy layer.
func encrypt(t *testing.T, p PrivAlgo, key, plain []byte) []byte {
	t.Helper()
	if len(key) < p.KeyLen() {
		t.Fatalf("%s needs %d key octets and the test key is %d", p, p.KeyLen(), len(key))
	}
	if p == PrivDES {
		block, err := des.NewCipher(key[:8]) //nolint:gosec // the protocol's own cipher
		if err != nil {
			t.Fatal(err)
		}
		iv := make([]byte, des.BlockSize)
		for i := range iv {
			iv[i] = key[8+i] ^ salt()[i]
		}
		// DES-CBC pads to the block size; the padding is not read back.
		padded := make([]byte, (len(plain)+7)/8*8)
		copy(padded, plain)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return out
	}
	block, err := aes.NewCipher(key[:p.KeyLen()])
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 0, 16)
	iv = binary.BigEndian.AppendUint32(iv, 3)
	iv = binary.BigEndian.AppendUint32(iv, 12345)
	iv = append(iv, salt()...)
	out := make([]byte, len(plain))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, plain) //nolint:staticcheck // RFC 3826 is CFB
	return out
}
