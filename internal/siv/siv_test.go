package siv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vectorer is the vector interface the package adds beyond cipher.AEAD, for the
// standard's own multi-string shape.
type vectorer interface {
	SealVector(dst, plaintext []byte, ad ...[]byte) []byte
	OpenVector(dst, ciphertext []byte, ad ...[]byte) ([]byte, error)
}

// RFC 5297 Appendix A.1: deterministic authenticated encryption, one
// associated-data string and no nonce.
//
// This is the vector that pins the whole construction -- CMAC, the subkeys, the
// doubling in the field, S2V's xorend, the two bits cleared before counter mode
// -- against a value somebody else published. A test that only round-tripped
// this package through itself would pass with any self-consistent mistake in
// any of them.
func TestRFC5297DeterministicVector(t *testing.T) {
	key := unhex(t, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ad := unhex(t, "101112131415161718191a1b1c1d1e1f2021222324252627")
	plain := unhex(t, "112233445566778899aabbccddee")
	want := unhex(t, "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")

	a, err := New(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := a.Seal(nil, nil, plain, ad)
	if !bytes.Equal(got, want) {
		t.Fatalf("Seal\n got %x\nwant %x", got, want)
	}
	back, err := a.Open(nil, nil, got, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("Open gave %x, wanted %x", back, plain)
	}
}

// RFC 5297 Appendix A.2: nonce-based, with *two* associated-data strings and a
// nonce, which is the order S2V takes them in and which a cipher.AEAD cannot
// express -- so this is the vector the exported vector form exists for.
func TestRFC5297NonceBasedVector(t *testing.T) {
	key := unhex(t, "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
	ad1 := unhex(t, "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100")
	ad2 := unhex(t, "102030405060708090a0")
	nonce := unhex(t, "09f911029d74e35bd84156c5635688c0")
	plain := unhex(t, "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553")
	want := unhex(t, "7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d")

	a, err := New(key, len(nonce))
	if err != nil {
		t.Fatal(err)
	}
	v, ok := a.(vectorer)
	if !ok {
		t.Fatal("the AEAD does not expose the vector form")
	}
	got := v.SealVector(nil, plain, ad1, ad2, nonce)
	if !bytes.Equal(got, want) {
		t.Fatalf("SealVector\n got %x\nwant %x", got, want)
	}
	back, err := v.OpenVector(nil, got, ad1, ad2, nonce)
	if err != nil {
		t.Fatalf("OpenVector: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("OpenVector gave %x, wanted %x", back, plain)
	}
	// And the AEAD form agrees with it when there is one associated-data
	// string, which is the shape NTS uses.
	one := a.Seal(nil, nonce, plain, ad1)
	if w := v.SealVector(nil, plain, ad1, nonce); !bytes.Equal(one, w) {
		t.Fatalf("the AEAD form and the vector form disagree:\n %x\n %x", one, w)
	}
}

// Any octet changed anywhere is a message that does not open: the tag is over
// the plaintext and every associated-data string, which is what a synthetic
// vector means.
func TestNothingOpensAfterAChange(t *testing.T) {
	key := unhex(t, "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
	nonce := unhex(t, "09f911029d74e35bd84156c5635688c0")
	ad := []byte("the associated data")
	plain := []byte("the time is what is being authenticated here")
	a, err := New(key, len(nonce))
	if err != nil {
		t.Fatal(err)
	}
	sealed := a.Seal(nil, nonce, plain, ad)
	for i := range sealed {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 1
		if _, err := a.Open(nil, nonce, bad, ad); err == nil {
			t.Fatalf("octet %d of the ciphertext changed and it still opened", i)
		}
	}
	for i := range ad {
		bad := append([]byte(nil), ad...)
		bad[i] ^= 1
		if _, err := a.Open(nil, nonce, sealed, bad); err == nil {
			t.Fatalf("octet %d of the associated data changed and it still opened", i)
		}
	}
	for i := range nonce {
		bad := append([]byte(nil), nonce...)
		bad[i] ^= 1
		if _, err := a.Open(nil, bad, sealed, ad); err == nil {
			t.Fatalf("octet %d of the nonce changed and it still opened", i)
		}
	}
}

// A repeated nonce is not catastrophic, which is the whole reason NTS asks for
// this mode. Two different messages under one nonce give two different
// ciphertexts, and the only thing an observer learns from two *identical*
// messages is that they were identical.
func TestARepeatedNonceIsNotCatastrophic(t *testing.T) {
	key := unhex(t, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	nonce := make([]byte, 16)
	a, err := New(key, len(nonce))
	if err != nil {
		t.Fatal(err)
	}
	first := a.Seal(nil, nonce, []byte("the first message"), nil)
	second := a.Seal(nil, nonce, []byte("the second messag"), nil)
	if bytes.Equal(first, second) {
		t.Fatal("two different messages under one nonce gave one ciphertext")
	}
	// The ciphertexts are the same length, so an ordinary stream cipher under a
	// repeated nonce would have leaked the exclusive-or of the plaintexts: the
	// two ciphertext bodies would differ exactly where the plaintexts do. Here
	// the initialisation vector differs, so they differ throughout.
	af, bf := first[TagSize:], second[TagSize:]
	same := 0
	for i := range af {
		if af[i] == bf[i] {
			same++
		}
	}
	if same > len(af)/2 {
		t.Errorf("%d of %d ciphertext octets match, which is a keystream reused", same, len(af))
	}
	// And an identical message does repeat, which is the property being given
	// up and is worth pinning so nobody thinks it is random.
	again := a.Seal(nil, nonce, []byte("the first message"), nil)
	if !bytes.Equal(first, again) {
		t.Error("the same message under the same nonce gave two ciphertexts, so this is not SIV")
	}
}

// The empty cases, which are where an off-by-one in the padding lives.
func TestTheEmptyCases(t *testing.T) {
	key := unhex(t, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	a, err := New(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	// An empty plaintext seals to the tag alone and opens back to nothing.
	sealed := a.Seal(nil, nil, nil, nil)
	if len(sealed) != TagSize {
		t.Fatalf("an empty message sealed to %d octets", len(sealed))
	}
	back, err := a.Open(nil, nil, sealed, nil)
	if err != nil {
		t.Fatalf("Open of an empty message: %v", err)
	}
	if len(back) != 0 {
		t.Fatalf("an empty message opened to %d octets", len(back))
	}
	// A ciphertext shorter than the tag is refused rather than read past.
	if _, err := a.Open(nil, nil, sealed[:TagSize-1], nil); err == nil {
		t.Error("a truncated message opened")
	}
	// An empty associated-data string is a value, not the absence of one: the
	// two must not give the same tag, or a message with an empty string in it
	// would authenticate as one with none.
	withEmpty := a.Seal(nil, nil, []byte("x"), []byte{})
	withNone := a.Seal(nil, nil, []byte("x"), nil)
	if bytes.Equal(withEmpty, withNone) {
		t.Error("an empty associated-data string and no string gave one tag")
	}
}

// The keys the standard has, and the ones it does not.
func TestTheKeyLengths(t *testing.T) {
	for _, n := range []int{32, 48, 64} {
		if _, err := New(make([]byte, n), 16); err != nil {
			t.Errorf("a %d octet key was refused: %v", n, err)
		}
	}
	for _, n := range []int{0, 16, 31, 33, 65} {
		if _, err := New(make([]byte, n), 16); err == nil {
			t.Errorf("a %d octet key was accepted", n)
		}
	}
	if _, err := New(make([]byte, 32), -1); err == nil {
		t.Error("a negative nonce size was accepted")
	}
	// The nonce length is the length the AEAD was built with, and a caller that
	// passes another gets an error rather than a tag over the wrong vector.
	a, err := New(make([]byte, 32), 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Open(nil, make([]byte, 8), make([]byte, 32), nil); err == nil {
		t.Error("Open accepted a nonce of the wrong length")
	}
	// New returns a cipher.AEAD, so this is the interface's own two questions.
	if a.NonceSize() != 16 || a.Overhead() != TagSize {
		t.Errorf("NonceSize %d Overhead %d", a.NonceSize(), a.Overhead())
	}
}
