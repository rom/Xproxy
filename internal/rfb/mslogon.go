package rfb

import (
	"crypto/des" //nolint:gosec // the protocol specifies DES
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// MS-Logon II is UltraVNC's security type 113: a Diffie-Hellman
// exchange whose shared secret becomes a DES key, and a Windows
// username and password encrypted under it.
//
// Where this comes from. UltraVNC publishes no specification for it.
// What is here follows the shape of UltraVNC's own vncauth.cpp and
// DH.cpp -- the exchange below, the CBC construction with the key as
// its own initialisation vector, and the same bit-reversed DES key
// convention RFC 6143 section 7.2.2 uses. Public reimplementations
// agree on that shape, and the tests here pin it. Interoperability
// against a real UltraVNC server is NOT verified by this repository's
// tests, and that is said plainly in docs/CONFIG.md rather than left
// for an operator to discover.
//
// What it is worth. Diffie-Hellman over 64 bits is breakable by
// anyone who records the exchange -- the numbers are small enough to
// solve on a laptop -- and DES has been breakable for decades. So
// this protects a Windows credential with nothing. It exists here so
// that an estate whose desktops speak only this can be reached
// through a gateway that records the session and holds the policy,
// which is a better place to be than reaching them directly. It is
// not a way to keep the credential secret, and the configuration that
// turns it on says so.

const (
	// MSLogonDHSize is the width of every Diffie-Hellman value: 64
	// bits, which is the whole trouble with this type.
	MSLogonDHSize = 8
	// MSLogonUserSize and MSLogonPassSize are the fixed, NUL-padded
	// credential fields.
	MSLogonUserSize = 256
	MSLogonPassSize = 64
	// MSLogonCredentialSize is the two of them together, which is what
	// travels encrypted.
	MSLogonCredentialSize = MSLogonUserSize + MSLogonPassSize
)

// MSLogonParams are the three values a server sends: the generator,
// the modulus, and its own public value, each eight bytes big-endian.
type MSLogonParams struct{ Gen, Mod, Pub uint64 }

// Encode renders them in the order the protocol sends them.
func (p MSLogonParams) Encode() []byte {
	out := binary.BigEndian.AppendUint64(nil, p.Gen)
	out = binary.BigEndian.AppendUint64(out, p.Mod)
	return binary.BigEndian.AppendUint64(out, p.Pub)
}

// ReadMSLogonParams reads them.
func ReadMSLogonParams(r io.Reader) (MSLogonParams, error) {
	var b [3 * MSLogonDHSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return MSLogonParams{}, err
	}
	p := MSLogonParams{
		Gen: binary.BigEndian.Uint64(b[0:8]),
		Mod: binary.BigEndian.Uint64(b[8:16]),
		Pub: binary.BigEndian.Uint64(b[16:24]),
	}
	if err := p.check(); err != nil {
		return MSLogonParams{}, err
	}
	return p, nil
}

// ErrMSLogonParams says the other end's Diffie-Hellman parameters are
// ones no shared secret should be derived from.
var ErrMSLogonParams = errors.New("rfb: mslogon2 parameters are degenerate")

// check refuses the parameters that make the exchange meaningless
// whatever the arithmetic says. The modulus is already far too small
// to be safe -- that is the type -- but a modulus of 0 or 1, a
// generator of 0 or 1, or a public value of 0 or 1 gives a fixed
// shared secret that anybody can work out without breaking anything at
// all, and those are worth refusing on their own.
func (p MSLogonParams) check() error {
	if p.Mod < 3 || p.Gen < 2 || p.Gen >= p.Mod || p.Pub < 2 || p.Pub >= p.Mod {
		return fmt.Errorf("%w: gen %d mod %d pub %d", ErrMSLogonParams, p.Gen, p.Mod, p.Pub)
	}
	return nil
}

// NewMSLogonParams generates a server's side of the exchange and
// returns the parameters to send with the private value to keep.
func NewMSLogonParams() (MSLogonParams, uint64, error) {
	// A fresh 63 bit prime per session. It buys little against someone
	// who can solve a 64 bit discrete log, but a modulus that is not
	// reused at least costs them the work each time.
	mod, err := rand.Prime(rand.Reader, 63)
	if err != nil {
		return MSLogonParams{}, 0, err
	}
	m := mod.Uint64()
	priv, err := msLogonPrivate(m)
	if err != nil {
		return MSLogonParams{}, 0, err
	}
	p := MSLogonParams{Gen: 5, Mod: m}
	p.Pub = msLogonExp(p.Gen, priv, m)
	if err := p.check(); err != nil {
		return MSLogonParams{}, 0, err
	}
	return p, priv, nil
}

// MSLogonPublic is this end's public value for a modulus and generator
// the other end chose, with the private value to keep.
func MSLogonPublic(p MSLogonParams) (pub, priv uint64, err error) {
	if err := p.check(); err != nil {
		return 0, 0, err
	}
	priv, err = msLogonPrivate(p.Mod)
	if err != nil {
		return 0, 0, err
	}
	return msLogonExp(p.Gen, priv, p.Mod), priv, nil
}

// MSLogonShared is the secret both ends arrive at, and the DES key the
// credential is encrypted under.
func MSLogonShared(peerPub, priv, mod uint64) (uint64, error) {
	if mod < 3 || peerPub < 2 || peerPub >= mod {
		return 0, fmt.Errorf("%w: pub %d mod %d", ErrMSLogonParams, peerPub, mod)
	}
	s := msLogonExp(peerPub, priv, mod)
	if s < 2 {
		// A shared secret of 0 or 1 is a key of nothing at all.
		return 0, fmt.Errorf("%w: shared secret %d", ErrMSLogonParams, s)
	}
	return s, nil
}

// msLogonPrivate draws a private exponent in [2, mod-2].
func msLogonPrivate(mod uint64) (uint64, error) {
	if mod < 5 {
		return 0, fmt.Errorf("%w: mod %d", ErrMSLogonParams, mod)
	}
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(mod-4))
	if err != nil {
		return 0, err
	}
	return n.Uint64() + 2, nil
}

// msLogonExp is base^exp mod m, through math/big because the squaring
// of two 64 bit values does not fit in one.
func msLogonExp(base, exp, m uint64) uint64 {
	return new(big.Int).Exp(
		new(big.Int).SetUint64(base),
		new(big.Int).SetUint64(exp),
		new(big.Int).SetUint64(m)).Uint64()
}

// MSLogonSeal renders the encrypted credential: the username in 256
// NUL-padded bytes and the password in 64, encrypted under the shared
// secret.
func MSLogonSeal(shared uint64, user, pass string) ([]byte, error) {
	if len(user) >= MSLogonUserSize {
		return nil, fmt.Errorf("rfb: mslogon2 username of %d bytes, over the %d field", len(user), MSLogonUserSize)
	}
	if len(pass) >= MSLogonPassSize {
		return nil, fmt.Errorf("rfb: mslogon2 password of %d bytes, over the %d field", len(pass), MSLogonPassSize)
	}
	out := make([]byte, MSLogonCredentialSize)
	copy(out[:MSLogonUserSize], user)
	copy(out[MSLogonUserSize:], pass)
	// The two fields are separate messages, each chained from the key
	// rather than continuing from the one before.
	if err := msLogonCrypt(shared, out[:MSLogonUserSize], true); err != nil {
		return nil, err
	}
	if err := msLogonCrypt(shared, out[MSLogonUserSize:], true); err != nil {
		return nil, err
	}
	return out, nil
}

// ReadMSLogonCredential reads the encrypted credential and opens it.
func ReadMSLogonCredential(r io.Reader, shared uint64) (string, string, error) {
	b := make([]byte, MSLogonCredentialSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", "", err
	}
	return MSLogonOpen(shared, b)
}

// MSLogonOpen decrypts a credential and trims the padding.
func MSLogonOpen(shared uint64, b []byte) (string, string, error) {
	if len(b) != MSLogonCredentialSize {
		return "", "", fmt.Errorf("rfb: mslogon2 credential of %d bytes, want %d", len(b), MSLogonCredentialSize)
	}
	out := append([]byte(nil), b...)
	if err := msLogonCrypt(shared, out[:MSLogonUserSize], false); err != nil {
		return "", "", err
	}
	if err := msLogonCrypt(shared, out[MSLogonUserSize:], false); err != nil {
		return "", "", err
	}
	return trimNUL(out[:MSLogonUserSize]), trimNUL(out[MSLogonUserSize:]), nil
}

func trimNUL(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// msLogonCrypt is DES in CBC with the key as its own initialisation
// vector, which is what UltraVNC's vncEncryptBytes2 does. The key is
// the shared secret with each byte's bits reversed, the same
// convention RFC 6143 section 7.2.2 uses for vncauth.
func msLogonCrypt(shared uint64, data []byte, encrypt bool) error {
	if len(data)%des.BlockSize != 0 {
		return fmt.Errorf("rfb: mslogon2 field of %d bytes is not whole blocks", len(data))
	}
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], shared)
	for i := range key {
		key[i] = reverseBits(key[i])
	}
	block, err := des.NewCipher(key[:]) //nolint:gosec // the protocol specifies DES
	if err != nil {
		return err
	}
	prev := key
	for off := 0; off < len(data); off += des.BlockSize {
		blk := data[off : off+des.BlockSize]
		if encrypt {
			for i := range blk {
				blk[i] ^= prev[i]
			}
			block.Encrypt(blk, blk)
			copy(prev[:], blk)
		} else {
			var cipher [8]byte
			copy(cipher[:], blk)
			block.Decrypt(blk, blk)
			for i := range blk {
				blk[i] ^= prev[i]
			}
			prev = cipher
		}
	}
	return nil
}
