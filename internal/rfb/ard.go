package rfb

import (
	"crypto/aes"
	"crypto/md5" //nolint:gosec // the protocol specifies MD5 for the key derivation
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// ARD is Apple Remote Desktop's security type 30: Diffie-Hellman over
// a prime the server chooses, MD5 of the shared secret as an AES-128
// key, and a fixed credential blob encrypted with it in ECB.
//
// Where this comes from. Apple publishes no specification. The
// exchange below is the one every public reimplementation agrees on.
// Interoperability with Apple's Screen Sharing is NOT verified by this
// repository's tests, and docs/CONFIG.md says so.
//
// What it is worth. Apple's own servers offer a 512 bit prime, which
// is inside reach of anyone willing to spend on it; the key is MD5 of
// the shared secret; and the credential is encrypted in ECB, which
// leaks where two blocks are equal. It is here so a Mac that offers
// nothing else can be reached through a gateway that records the
// session and holds the policy. It is not a way to keep the credential
// secret, and the configuration that turns it on says so.

const (
	// ARDCredentialField is each half of the credential blob.
	ARDCredentialField = 64
	// ARDCredentialSize is the blob that travels encrypted.
	ARDCredentialSize = 2 * ARDCredentialField
	// ARDMinPrimeBytes is the smallest prime this proxy will use: 512
	// bits, which is what Apple sends. Smaller is not an exchange.
	ARDMinPrimeBytes = 64
	// ARDMaxPrimeBytes bounds the arithmetic an unauthenticated peer
	// can ask for.
	ARDMaxPrimeBytes = 512
	// ardServerPrimeBits is what this proxy generates in the server
	// role. Larger than Apple's own, since the length is on the wire
	// and a client reads it; docs/CONFIG.md says so in case a client
	// turns out to assume 512.
	ardServerPrimeBits = 1024
)

// ErrARD says the other end's parameters are ones no shared secret
// should be derived from.
var ErrARD = errors.New("rfb: ard parameters are unusable")

// ARDParams are what a server sends: a generator, the prime's length,
// the prime, and the server's public value.
type ARDParams struct {
	Gen        uint16
	Prime, Pub []byte
}

// Encode renders them in the order the protocol sends them.
func (p ARDParams) Encode() []byte {
	out := binary.BigEndian.AppendUint16(nil, p.Gen)
	out = binary.BigEndian.AppendUint16(out, uint16(len(p.Prime))) //nolint:gosec // bounded at construction
	out = append(out, p.Prime...)
	return append(out, p.Pub...)
}

// ReadARDParams reads them, bounding the prime before it is allocated.
func ReadARDParams(r io.Reader) (ARDParams, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return ARDParams{}, err
	}
	p := ARDParams{Gen: binary.BigEndian.Uint16(head[0:2])}
	n := int(binary.BigEndian.Uint16(head[2:4]))
	if n < ARDMinPrimeBytes || n > ARDMaxPrimeBytes {
		return ARDParams{}, fmt.Errorf("%w: prime of %d bytes, want %d to %d", ErrARD, n, ARDMinPrimeBytes, ARDMaxPrimeBytes)
	}
	buf := make([]byte, 2*n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return ARDParams{}, err
	}
	p.Prime, p.Pub = buf[:n], buf[n:]
	if err := p.check(); err != nil {
		return ARDParams{}, err
	}
	return p, nil
}

// check refuses what makes the exchange no exchange: a generator or
// public value of 0 or 1, a public value at or above the prime, and an
// even prime.
func (p ARDParams) check() error {
	prime := new(big.Int).SetBytes(p.Prime)
	pub := new(big.Int).SetBytes(p.Pub)
	switch {
	case p.Gen < 2:
		return fmt.Errorf("%w: generator %d", ErrARD, p.Gen)
	case prime.BitLen() < ARDMinPrimeBytes*8:
		return fmt.Errorf("%w: the prime is %d bits", ErrARD, prime.BitLen())
	case prime.Bit(0) == 0:
		return fmt.Errorf("%w: the modulus is even", ErrARD)
	case pub.Cmp(big.NewInt(1)) <= 0 || pub.Cmp(prime) >= 0:
		return fmt.Errorf("%w: the peer's public value fixes the secret", ErrARD)
	}
	return nil
}

// NewARDParams generates a server's side and returns the parameters to
// send with the private value to keep.
func NewARDParams() (ARDParams, *big.Int, error) {
	prime, err := rand.Prime(rand.Reader, ardServerPrimeBits)
	if err != nil {
		return ARDParams{}, nil, err
	}
	p := ARDParams{Gen: 2, Prime: prime.Bytes()}
	priv, err := ardPrivate(prime)
	if err != nil {
		return ARDParams{}, nil, err
	}
	p.Pub = leftPad(new(big.Int).Exp(big.NewInt(2), priv, prime).Bytes(), len(p.Prime))
	if err := p.check(); err != nil {
		return ARDParams{}, nil, err
	}
	return p, priv, nil
}

// ARDPublic is this end's public value for a prime the other end
// chose, with the private value to keep.
func ARDPublic(p ARDParams) ([]byte, *big.Int, error) {
	if err := p.check(); err != nil {
		return nil, nil, err
	}
	prime := new(big.Int).SetBytes(p.Prime)
	priv, err := ardPrivate(prime)
	if err != nil {
		return nil, nil, err
	}
	pub := new(big.Int).Exp(big.NewInt(int64(p.Gen)), priv, prime)
	return leftPad(pub.Bytes(), len(p.Prime)), priv, nil
}

// ARDKey is the AES key both ends arrive at: MD5 of the shared secret,
// left-padded to the prime's width the way the peers compute it.
func ARDKey(peerPub, prime []byte, priv *big.Int) ([]byte, error) {
	m := new(big.Int).SetBytes(prime)
	pub := new(big.Int).SetBytes(peerPub)
	if pub.Cmp(big.NewInt(1)) <= 0 || pub.Cmp(m) >= 0 {
		return nil, fmt.Errorf("%w: the peer's public value fixes the secret", ErrARD)
	}
	secret := new(big.Int).Exp(pub, priv, m)
	if secret.Cmp(big.NewInt(1)) <= 0 {
		return nil, fmt.Errorf("%w: the shared secret is degenerate", ErrARD)
	}
	sum := md5.Sum(leftPad(secret.Bytes(), len(prime))) //nolint:gosec // the protocol specifies it
	return sum[:], nil
}

func ardPrivate(prime *big.Int) (*big.Int, error) {
	// A private exponent in [2, prime-2].
	max := new(big.Int).Sub(prime, big.NewInt(4))
	if max.Sign() <= 0 {
		return nil, fmt.Errorf("%w: the prime is too small", ErrARD)
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(2)), nil
}

// ARDSeal renders the encrypted credential: a username and a password
// in 64 bytes each, NUL-terminated with random padding behind, in AES
// ECB under the derived key. ECB is not a choice being made here; it
// is what the type does.
func ARDSeal(key []byte, user, pass string) ([]byte, error) {
	if len(user) >= ARDCredentialField || len(pass) >= ARDCredentialField {
		return nil, fmt.Errorf("%w: a credential field over %d bytes", ErrARD, ARDCredentialField-1)
	}
	blob := make([]byte, ARDCredentialSize)
	if _, err := rand.Read(blob); err != nil {
		return nil, err
	}
	copy(blob, user)
	blob[len(user)] = 0
	copy(blob[ARDCredentialField:], pass)
	blob[ARDCredentialField+len(pass)] = 0
	if err := ardECB(key, blob, true); err != nil {
		return nil, err
	}
	return blob, nil
}

// ReadARDCredential reads the blob and opens it.
func ReadARDCredential(r io.Reader, key []byte) (string, string, error) {
	blob := make([]byte, ARDCredentialSize)
	if _, err := io.ReadFull(r, blob); err != nil {
		return "", "", err
	}
	return ARDOpen(key, blob)
}

// ARDOpen decrypts a credential blob and trims each field at its NUL.
func ARDOpen(key, blob []byte) (string, string, error) {
	if len(blob) != ARDCredentialSize {
		return "", "", fmt.Errorf("%w: credential of %d bytes, want %d", ErrARD, len(blob), ARDCredentialSize)
	}
	out := append([]byte(nil), blob...)
	if err := ardECB(key, out, false); err != nil {
		return "", "", err
	}
	return trimNUL(out[:ARDCredentialField]), trimNUL(out[ARDCredentialField:]), nil
}

func ardECB(key, data []byte, encrypt bool) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	if len(data)%block.BlockSize() != 0 {
		return fmt.Errorf("%w: credential of %d bytes is not whole blocks", ErrARD, len(data))
	}
	for off := 0; off < len(data); off += block.BlockSize() {
		blk := data[off : off+block.BlockSize()]
		if encrypt {
			block.Encrypt(blk, blk)
		} else {
			block.Decrypt(blk, blk)
		}
	}
	return nil
}
