// Package eax implements the EAX authenticated encryption mode over a
// block cipher, as a cipher.AEAD.
//
// It is here for one reason: RealVNC's RSA-AES security types protect
// their handshake and session with AES in EAX, and Go's standard
// library has GCM and ChaCha20-Poly1305 but not EAX. Nothing else in
// this proxy should use it -- new code wants an AEAD from the standard
// library.
//
// EAX is M. Bellare, P. Rogaway and D. Wagner, "The EAX Mode of
// Operation" (FSE 2004), built on OMAC, which is CMAC as NIST SP
// 800-38B specifies it. Both are fully written down, so this is a
// specified construction being implemented rather than a cipher being
// guessed at, and the tests pin it against the published vectors of
// both documents rather than against itself.
package eax

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
)

// TagSize is the authentication tag EAX produces: the block size of
// the cipher underneath it.
const TagSize = 16

// ErrOpen says a message did not authenticate. It carries nothing
// about why, because there is nothing safe to say.
var ErrOpen = errors.New("eax: message authentication failed")

type eax struct {
	block     cipher.Block
	nonceSize int
	tagSize   int
}

// New returns EAX over block, with nonces of nonceSize bytes and the
// full tag.
func New(block cipher.Block, nonceSize int) (cipher.AEAD, error) {
	if block.BlockSize() != TagSize {
		return nil, fmt.Errorf("eax: block size %d, want %d", block.BlockSize(), TagSize)
	}
	if nonceSize <= 0 {
		return nil, fmt.Errorf("eax: nonce size %d", nonceSize)
	}
	return &eax{block: block, nonceSize: nonceSize, tagSize: TagSize}, nil
}

func (e *eax) NonceSize() int { return e.nonceSize }
func (e *eax) Overhead() int  { return e.tagSize }

func (e *eax) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != e.nonceSize {
		panic("eax: incorrect nonce length given to EAX")
	}
	n := e.omac(0, nonce)
	h := e.omac(1, additionalData)

	ret, out := sliceForAppend(dst, len(plaintext)+e.tagSize)
	// CTR with the nonce's OMAC as the counter block, which is what
	// EAX uses in place of a separate initialisation vector.
	ctr := cipher.NewCTR(e.block, n)
	ctr.XORKeyStream(out[:len(plaintext)], plaintext)

	c := e.omac(2, out[:len(plaintext)])
	tag := out[len(plaintext):]
	for i := 0; i < e.tagSize; i++ {
		tag[i] = n[i] ^ h[i] ^ c[i]
	}
	return ret
}

func (e *eax) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != e.nonceSize {
		return nil, fmt.Errorf("eax: nonce of %d bytes, want %d", len(nonce), e.nonceSize)
	}
	if len(ciphertext) < e.tagSize {
		return nil, ErrOpen
	}
	body, want := ciphertext[:len(ciphertext)-e.tagSize], ciphertext[len(ciphertext)-e.tagSize:]

	n := e.omac(0, nonce)
	h := e.omac(1, additionalData)
	c := e.omac(2, body)
	var got [TagSize]byte
	for i := 0; i < e.tagSize; i++ {
		got[i] = n[i] ^ h[i] ^ c[i]
	}
	// The tag is checked before anything is decrypted, and in constant
	// time: a comparison that stops early tells an attacker how much
	// of a forged tag was right.
	if subtle.ConstantTimeCompare(got[:e.tagSize], want) != 1 {
		return nil, ErrOpen
	}
	ret, out := sliceForAppend(dst, len(body))
	cipher.NewCTR(e.block, n).XORKeyStream(out, body)
	return ret, nil
}

// omac is OMAC^t: CMAC over the block-sized big-endian encoding of t
// followed by the message. The three values of t are what keep the
// nonce, the header and the ciphertext from being confused for one
// another.
func (e *eax) omac(t byte, msg []byte) []byte {
	buf := make([]byte, TagSize, TagSize+len(msg))
	buf[TagSize-1] = t
	buf = append(buf, msg...)
	return e.cmac(buf)
}

// cmac is CMAC as NIST SP 800-38B specifies it.
func (e *eax) cmac(msg []byte) []byte {
	k1, k2 := e.subkeys()
	var last [TagSize]byte
	n := len(msg) / TagSize
	rest := len(msg) % TagSize
	if len(msg) > 0 && rest == 0 {
		// A whole number of blocks: the last one is used as it is,
		// masked with the first subkey.
		n--
		copy(last[:], msg[n*TagSize:])
		xorInto(last[:], k1)
	} else {
		// Otherwise it is padded with a one bit and zeroes, and masked
		// with the second. The two subkeys are what stop a padded
		// message colliding with an unpadded one.
		copy(last[:], msg[n*TagSize:])
		last[rest] = 0x80
		xorInto(last[:], k2)
	}
	var x [TagSize]byte
	for i := 0; i < n; i++ {
		xorInto(x[:], msg[i*TagSize:(i+1)*TagSize])
		e.block.Encrypt(x[:], x[:])
	}
	xorInto(x[:], last[:])
	out := make([]byte, TagSize)
	e.block.Encrypt(out, x[:])
	return out
}

// subkeys derives CMAC's two subkeys by doubling in GF(2^128).
func (e *eax) subkeys() ([]byte, []byte) {
	l := make([]byte, TagSize)
	e.block.Encrypt(l, l)
	k1 := double(l)
	return k1, double(k1)
}

// double is multiplication by x in GF(2^128) with the reduction
// polynomial of SP 800-38B.
func double(b []byte) []byte {
	out := make([]byte, len(b))
	var carry byte
	for i := len(b) - 1; i >= 0; i-- {
		out[i] = b[i]<<1 | carry
		carry = b[i] >> 7
	}
	// The shift out of the top bit is reduced by the polynomial
	// x^128 + x^7 + x^2 + x + 1.
	if b[0]&0x80 != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// sliceForAppend is the standard library's helper of the same name:
// it grows dst by n bytes and returns the whole slice and the tail to
// write into.
func sliceForAppend(dst []byte, n int) ([]byte, []byte) {
	if total := len(dst) + n; cap(dst) >= total {
		head := dst[:total]
		return head, head[len(dst):]
	}
	head := make([]byte, len(dst)+n)
	copy(head, dst)
	return head, head[len(dst):]
}
