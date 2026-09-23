package rfb

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A key round-trips through the encoding the protocol sends it in, and
// the two ends agree on what it was.
func TestRSAAESKeyRoundTrip(t *testing.T) {
	key := testKey(t, 2048)
	own, err := OwnRSAAESKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, pub, err := ReadRSAAESKey(bytes.NewReader(own.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Bits != 2048 || pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		t.Fatalf("read a different key: %d bits", got.Bits)
	}
	if !bytes.Equal(got.Encode(), own.Encode()) {
		t.Error("the transcript encoding is not stable across a round trip")
	}
}

// A peer cannot name a key size that is not worth doing arithmetic
// for, in either direction.
func TestRSAAESKeySizeIsBounded(t *testing.T) {
	small := testKey(t, 1024)
	if _, err := OwnRSAAESKey(&small.PublicKey); !errors.Is(err, ErrRSAAES) {
		t.Error("a 1024 bit key of our own was accepted")
	}
	for _, bits := range []uint32{0, 1, 1024, RSAAESMaxKeyBits + 8, 1 << 30} {
		head := []byte{byte(bits >> 24), byte(bits >> 16), byte(bits >> 8), byte(bits)}
		if _, _, err := ReadRSAAESKey(bytes.NewReader(append(head, make([]byte, 64)...))); err == nil {
			t.Errorf("a peer key of %d bits was accepted", bits)
		}
	}
	// A length that disagrees with the modulus it carries is refused,
	// which is what a key padded up to look bigger would be.
	key := testKey(t, 2048)
	own, _ := OwnRSAAESKey(&key.PublicKey)
	b := own.Encode()
	b[0], b[1], b[2], b[3] = 0, 0, 0x10, 0x08 // says 4104 bits
	if _, _, err := ReadRSAAESKey(bytes.NewReader(b)); err == nil {
		t.Error("a key whose length disagrees with its modulus was accepted")
	}
	// And an even exponent is not an RSA exponent.
	b = own.Encode()
	b[len(b)-1] = 0x04
	if _, _, err := ReadRSAAESKey(bytes.NewReader(b)); err == nil {
		t.Error("an even exponent was accepted")
	}
}

// The two directions get different keys, so a message cannot be
// replayed back the way it came.
func TestRSAAESSessionKeysDifferPerDirection(t *testing.T) {
	cr := bytes.Repeat([]byte{1}, 16)
	sr := bytes.Repeat([]byte{2}, 16)
	ck, sk := RSAAESSessionKeys(SecRSAAES, cr, sr)
	if len(ck) != 16 || len(sk) != 16 {
		t.Fatalf("keys of %d and %d bytes", len(ck), len(sk))
	}
	if bytes.Equal(ck, sk) {
		t.Error("both directions got the same key")
	}
	ck2, sk2 := RSAAESSessionKeys(SecRSAAES256, cr, sr)
	if len(ck2) != 32 || len(sk2) != 32 {
		t.Fatalf("256 bit keys of %d and %d bytes", len(ck2), len(sk2))
	}
	if bytes.HasPrefix(ck2, ck) {
		t.Error("the 256 bit key is the 128 bit one extended")
	}
}

// The transcript is over both keys in an order that differs per end,
// so one end's hash cannot be sent back as the other's.
func TestRSAAESTranscriptIsOrdered(t *testing.T) {
	a, _ := OwnRSAAESKey(&testKey(t, 2048).PublicKey)
	b, _ := OwnRSAAESKey(&testKey(t, 2048).PublicKey)
	if RSAAESTranscriptMatches(RSAAESTranscript(SecRSAAES, a, b), RSAAESTranscript(SecRSAAES, b, a)) {
		t.Error("the transcript is the same in both directions")
	}
	if !RSAAESTranscriptMatches(RSAAESTranscript(SecRSAAES, a, b), RSAAESTranscript(SecRSAAES, a, b)) {
		t.Error("the same transcript did not match itself")
	}
}

// The channel carries what was put into it, message by message, and
// the two ends stay in step because each counts its own nonce.
func TestAESConnCarriesAStream(t *testing.T) {
	ck := bytes.Repeat([]byte{9}, 16)
	sk := bytes.Repeat([]byte{4}, 16)
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	client, err := NewAESConn(c1, ck, sk)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewAESConn(c2, sk, ck)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))

	msgs := []string{"first", "second", strings.Repeat("x", 5000)}
	go func() {
		for _, m := range msgs {
			if _, err := client.Write([]byte(m)); err != nil {
				return
			}
		}
	}()
	for _, m := range msgs {
		got, err := server.ReadFull(len(m))
		if err != nil {
			t.Fatalf("%q: %v", m[:min(len(m), 12)], err)
		}
		if string(got) != m {
			t.Errorf("read %q", got[:min(len(got), 12)])
		}
	}
	// And the other direction, which uses the other key.
	go func() { _, _ = server.Write([]byte("back")) }()
	got, err := client.ReadFull(4)
	if err != nil || string(got) != "back" {
		t.Errorf("read %q (%v)", got, err)
	}
}

// A message somebody changed does not open, and the channel does not
// hand back plaintext it could not authenticate.
func TestAESConnRefusesAChangedMessage(t *testing.T) {
	ck := bytes.Repeat([]byte{9}, 16)
	sk := bytes.Repeat([]byte{4}, 16)
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	client, _ := NewAESConn(c1, ck, sk)
	// The server reads with the wrong key, which is what a message
	// that was tampered with looks like from the inside.
	server, _ := NewAESConn(c2, sk, bytes.Repeat([]byte{5}, 16))
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, _ = client.Write([]byte("what the desktop showed")) }()
	if _, err := server.ReadFull(23); !errors.Is(err, ErrRSAAES) {
		t.Errorf("a message that did not authenticate was handed over (%v)", err)
	}
}

// A framed length outside the bound is refused before anything is
// allocated for it.
func TestAESConnBoundsAFramedMessage(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	server, _ := NewAESConn(c2, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{1}, 16))
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, _ = c1.Write([]byte{0xff, 0xff}) }()
	if _, err := server.ReadFull(1); !errors.Is(err, ErrRSAAES) {
		t.Errorf("an oversize frame was accepted (%v)", err)
	}
}

// A random of the wrong size, or one that does not decrypt, is refused
// rather than turned into a key.
func TestRSAAESRandomIsChecked(t *testing.T) {
	key := testKey(t, 2048)
	random, err := RSAAESRandom(SecRSAAES)
	if err != nil {
		t.Fatal(err)
	}
	if len(random) != 16 {
		t.Fatalf("random of %d bytes", len(random))
	}
	sealed, err := SealRSAAESRandom(&key.PublicKey, random)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenRSAAESRandom(bytes.NewReader(sealed), key, SecRSAAES)
	if err != nil || !bytes.Equal(got, random) {
		t.Fatalf("opened %x (%v)", got, err)
	}
	// The same random read as a 256 bit type is the wrong size.
	if _, err := OpenRSAAESRandom(bytes.NewReader(sealed), key, SecRSAAES256); !errors.Is(err, ErrRSAAES) {
		t.Errorf("a short random was accepted for a 256 bit type (%v)", err)
	}
	// Ciphertext that is not ours does not decrypt.
	bad := append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 0xff
	if _, err := OpenRSAAESRandom(bytes.NewReader(bad), key, SecRSAAES); !errors.Is(err, ErrRSAAES) {
		t.Errorf("a random that did not decrypt was accepted (%v)", err)
	}
	// A length longer than the key can have produced is refused before
	// the body is read.
	if _, err := OpenRSAAESRandom(bytes.NewReader([]byte{0xff, 0xff}), key, SecRSAAES); !errors.Is(err, ErrRSAAES) {
		t.Errorf("an oversize random was accepted (%v)", err)
	}
}

func TestRSAAESCredentialRoundTrip(t *testing.T) {
	b, err := RSAAESCredential("alice", "492013")
	if err != nil {
		t.Fatal(err)
	}
	user, pass, err := ReadRSAAESCredential(bytes.NewReader(b))
	if err != nil || user != "alice" || pass != "492013" {
		t.Errorf("read %q and %q (%v)", user, pass, err)
	}
	if _, err := RSAAESCredential(strings.Repeat("a", 256), "x"); err == nil {
		t.Error("a credential over the one byte length was accepted")
	}
}

// The fingerprint is stable, names one key, and is compared the way an
// operator is likely to have copied it.
func TestRSAAESFingerprint(t *testing.T) {
	a, _ := OwnRSAAESKey(&testKey(t, 2048).PublicKey)
	b, _ := OwnRSAAESKey(&testKey(t, 2048).PublicKey)
	fa, fb := RSAAESFingerprint(a), RSAAESFingerprint(b)
	if fa == fb {
		t.Error("two keys have the same fingerprint")
	}
	if fa != RSAAESFingerprint(a) {
		t.Error("the fingerprint is not stable")
	}
	if !FingerprintMatches(strings.ToUpper(fa), fa) ||
		!FingerprintMatches(strings.ReplaceAll(fa, ":", ""), fa) {
		t.Error("a fingerprint copied without colons or in capitals did not match")
	}
	if FingerprintMatches(fb, fa) || FingerprintMatches("", fa) {
		t.Error("the wrong fingerprint matched")
	}
}

// Which of the three types leaves the session in clear is the thing
// about this family easiest to get wrong.
func TestOnlyTheNeTypeLeavesTheSessionInClear(t *testing.T) {
	if !RSAAESEncrypted(SecRSAAES) || !RSAAESEncrypted(SecRSAAES256) {
		t.Error("an encrypting type was read as one that is not")
	}
	if RSAAESEncrypted(SecRSAAESne) {
		t.Error("rsa-aes-ne was read as encrypting the session")
	}
	if RSAAESKeySize(SecRSAAES256) != 32 || RSAAESKeySize(SecRSAAES) != 16 {
		t.Error("the key sizes are not what the types say")
	}
}
