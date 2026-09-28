// Package siv implements AES-SIV-CMAC, the synthetic initialisation vector
// mode of RFC 5297, as a cipher.AEAD.
//
// It is here for one reason: NTS (RFC 8915 s5.1) requires
// AEAD_AES_SIV_CMAC_256 of every implementation, and Go's standard library has
// GCM and ChaCha20-Poly1305 but not SIV. Nothing else in this proxy should use
// it -- new code wants an AEAD from the standard library.
//
// SIV is worth understanding rather than treating as a black box, because its
// property is the one NTS needs. An ordinary AEAD is catastrophic if a nonce
// repeats: two messages under one nonce leak the exclusive-or of their
// plaintexts. SIV derives its initialisation vector from the message itself, so
// a repeated nonce costs only the observation that two messages were identical.
// NTS needs that because the cookie a client holds outlives the connection that
// issued it and a client cannot be trusted to keep a nonce counter across a
// reboot.
//
// The construction is fully specified, so this is a written-down thing being
// implemented rather than a cipher being guessed at, and the tests pin it
// against the vectors published in RFC 5297 Appendix A rather than against
// itself.
package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
)

// ErrOpen is a message that did not authenticate.
var ErrOpen = errors.New("siv: message authentication failed")

// TagSize is the synthetic initialisation vector's length, which is one block
// and is prepended to every ciphertext.
const TagSize = aes.BlockSize

// KeySize256 is the key length of AEAD_AES_SIV_CMAC_256: thirty-two octets,
// which SIV splits into two AES-128 keys rather than using as one AES-256 key.
// That surprises people, and it is what the standard says: the first half keys
// the authentication and the second half the encryption.
const KeySize256 = 32

type siv struct {
	// mac is keyed with the first half of the key, ctr with the second.
	mac, ctr  cipher.Block
	nonceSize int
}

// New returns AES-SIV-CMAC over a key of 32, 48 or 64 octets, with the given
// nonce size.
//
// The nonce is a separate argument only because cipher.AEAD has one. To SIV it
// is simply the last associated-data string (RFC 5297 s2.6), which is why a
// zero nonce size is allowed and gives the deterministic mode.
func New(key []byte, nonceSize int) (cipher.AEAD, error) {
	switch len(key) {
	case 32, 48, 64:
	default:
		return nil, fmt.Errorf("siv: key is %d octets, not 32, 48 or 64", len(key))
	}
	if nonceSize < 0 {
		return nil, errors.New("siv: negative nonce size")
	}
	half := len(key) / 2
	mac, err := aes.NewCipher(key[:half])
	if err != nil {
		return nil, err
	}
	ctr, err := aes.NewCipher(key[half:])
	if err != nil {
		return nil, err
	}
	return &siv{mac: mac, ctr: ctr, nonceSize: nonceSize}, nil
}

func (s *siv) NonceSize() int { return s.nonceSize }
func (s *siv) Overhead() int  { return TagSize }

// Seal encrypts, with the nonce as the last associated-data string.
func (s *siv) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != s.nonceSize {
		panic("siv: incorrect nonce length given to Seal")
	}
	return s.SealVector(dst, plaintext, vector(additionalData, nonce)...)
}

// Open decrypts, with the nonce as the last associated-data string.
func (s *siv) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != s.nonceSize {
		return nil, errors.New("siv: incorrect nonce length given to Open")
	}
	return s.OpenVector(dst, ciphertext, vector(additionalData, nonce)...)
}

// vector is the associated-data strings in the order S2V takes them: the
// caller's, then the nonce. A nil component is left out rather than passed as
// an empty string, because an empty string is a *value* to S2V -- CMAC of it is
// not CMAC of nothing -- so passing one where the caller gave none would
// compute a different tag.
func vector(ad, nonce []byte) [][]byte {
	out := make([][]byte, 0, 2)
	if ad != nil {
		out = append(out, ad)
	}
	if nonce != nil {
		out = append(out, nonce)
	}
	return out
}

// SealVector is RFC 5297's SIV-Encrypt: any number of associated-data strings,
// in order, and the plaintext last.
//
// It is exported because the standard's own interface is a vector and NTS is
// not the only caller shape: RFC 5297's test vectors have two associated-data
// strings and a nonce, which a cipher.AEAD cannot express.
func (s *siv) SealVector(dst, plaintext []byte, ad ...[]byte) []byte {
	v := s.s2v(append(ad, plaintext))
	ret, out := sliceForAppend(dst, TagSize+len(plaintext))
	copy(out, v)
	s.crypt(out[TagSize:], plaintext, v)
	return ret
}

// OpenVector is RFC 5297's SIV-Decrypt.
func (s *siv) OpenVector(dst, ciphertext []byte, ad ...[]byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}
	v, body := ciphertext[:TagSize], ciphertext[TagSize:]
	// Decrypted into a scratch buffer and only then compared: writing into the
	// caller's dst before the tag is checked would hand unauthenticated
	// plaintext to a caller that trusted the error.
	plain := make([]byte, len(body))
	s.crypt(plain, body, v)
	want := s.s2v(append(ad, plain))
	if subtle.ConstantTimeCompare(v, want) != 1 {
		return nil, ErrOpen
	}
	ret, out := sliceForAppend(dst, len(plain))
	copy(out, plain)
	return ret, nil
}

// crypt runs AES in counter mode with the initialisation vector derived from
// the synthetic one.
//
// The two cleared bits are RFC 5297 s2.5 and they are not decoration: they make
// room for the counter to be incremented without carrying into the top half of
// either 64-bit word, so that a long message's counter cannot collide with
// another message's. Clearing them loses two bits of the vector, which is the
// price the standard chose.
func (s *siv) crypt(dst, src, v []byte) {
	if len(src) == 0 {
		return
	}
	var q [TagSize]byte
	copy(q[:], v)
	q[8] &= 0x7f
	q[12] &= 0x7f
	cipher.NewCTR(s.ctr, q[:]).XORKeyStream(dst, src)
}

// s2v is RFC 5297 s2.4: the string-to-vector construction that turns a vector
// of strings into one block.
func (s *siv) s2v(strings [][]byte) []byte {
	if len(strings) == 0 {
		// S2V of the empty vector is CMAC of a block that is one, which is the
		// standard's own answer and not an arbitrary choice.
		one := make([]byte, TagSize)
		one[TagSize-1] = 1
		return s.cmac(one)
	}
	d := s.cmac(make([]byte, TagSize))
	for _, str := range strings[:len(strings)-1] {
		d = xor(double(d), s.cmac(str))
	}
	last := strings[len(strings)-1]
	var t []byte
	if len(last) >= TagSize {
		// xorend: the accumulated value goes into the final block of the last
		// string, so a long last string is not copied twice.
		t = make([]byte, len(last))
		copy(t, last)
		xorInto(t[len(t)-TagSize:], d)
	} else {
		t = xor(double(d), pad(last))
	}
	return s.cmac(t)
}

// cmac is CMAC as NIST SP 800-38B specifies it, over this instance's
// authentication key.
func (s *siv) cmac(msg []byte) []byte {
	k1, k2 := s.subkeys()
	n := (len(msg) + TagSize - 1) / TagSize
	whole := n > 0 && len(msg)%TagSize == 0
	if n == 0 {
		n = 1
	}
	var x [TagSize]byte
	for i := 0; i < n-1; i++ {
		xorInto(x[:], msg[i*TagSize:(i+1)*TagSize])
		s.mac.Encrypt(x[:], x[:])
	}
	var last [TagSize]byte
	if whole {
		copy(last[:], msg[(n-1)*TagSize:])
		xorInto(last[:], k1)
	} else {
		copy(last[:], pad(msg[(n-1)*TagSize:]))
		xorInto(last[:], k2)
	}
	xorInto(x[:], last[:])
	s.mac.Encrypt(x[:], x[:])
	out := make([]byte, TagSize)
	copy(out, x[:])
	return out
}

// subkeys are CMAC's K1 and K2: the encryption of a zero block, doubled once
// and twice in the field.
func (s *siv) subkeys() ([]byte, []byte) {
	l := make([]byte, TagSize)
	s.mac.Encrypt(l, l)
	k1 := double(l)
	return k1, double(k1)
}

// pad is the 10* padding of SP 800-38B: a one bit, then zeroes.
func pad(b []byte) []byte {
	out := make([]byte, TagSize)
	copy(out, b)
	if len(b) < TagSize {
		out[len(b)] = 0x80
	}
	return out
}

// double is multiplication by two in GF(2^128) with the polynomial the
// standards use, done without a branch on the high bit: a conditional
// subtraction of the reduction constant is a branch on key material.
func double(b []byte) []byte {
	out := make([]byte, TagSize)
	carry := byte(0)
	for i := TagSize - 1; i >= 0; i-- {
		out[i] = b[i]<<1 | carry
		carry = b[i] >> 7
	}
	// carry is now the bit shifted out of the top. 0x87 is the reduction.
	out[TagSize-1] ^= carry * 0x87
	return out
}

func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	copy(out, a)
	xorInto(out, b)
	return out
}

func xorInto(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	for i := 0; i < n; i++ {
		dst[i] ^= src[i]
	}
}

// sliceForAppend is the standard library's own idiom for an AEAD that appends.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
