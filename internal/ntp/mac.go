package ntp

import (
	"crypto/aes"
	"crypto/md5"  //nolint:gosec // a legacy algorithm this package can verify and warns about
	"crypto/sha1" //nolint:gosec // the same
	"crypto/subtle"
	"errors"
	"fmt"
)

// Symmetric authentication, as it actually is.
//
// NTP's symmetric authentication is a shared key and a digest over the
// packet. RFC 8573 makes AES-CMAC the algorithm to use and says plainly
// why: the older construction is MD5 over the key followed by the
// packet, which is a length-extension shape with a broken hash inside
// it. So AES-CMAC is what this package computes, and the two legacy
// algorithms are verifiable only where a configuration says so in
// writing -- because a device from 2006 cannot be taught a new one, and
// pretending it can is how a plant ends up with no authentication at all
// rather than weak authentication somebody knows about.
//
// Autokey (RFC 5906) is not here and will not be: it is withdrawn, its
// own designers say not to use it, and its extension fields fall under
// the unknown-field policy like anything else this relay cannot reason
// about.

// Algorithm names a configuration may use.
const (
	AlgAESCMAC = "aes-cmac"
	AlgMD5     = "md5"
	AlgSHA1    = "sha1"
)

// Errors of authentication.
var (
	ErrNoKey       = errors.New("ntp: no key with that identifier")
	ErrAlgorithm   = errors.New("ntp: algorithm this build does not compute")
	ErrKeyLength   = errors.New("ntp: key length the algorithm does not take")
	ErrNoMAC       = errors.New("ntp: packet carries no MAC")
	ErrMACMismatch = errors.New("ntp: MAC does not verify")
)

// Key is one symmetric key: the identifier the packet carries, the
// algorithm, and the secret.
type Key struct {
	ID        uint32
	Algorithm string
	Secret    []byte
}

// Keys is a key set by identifier.
type Keys map[uint32]Key

// Compute returns the digest for a message under this key. The message
// is the packet's header and every extension field -- everything before
// the key identifier -- which is what the MAC covers.
func (k Key) Compute(msg []byte) ([]byte, error) {
	switch k.Algorithm {
	case AlgAESCMAC, "":
		switch len(k.Secret) {
		case 16, 24, 32:
		default:
			return nil, fmt.Errorf("%w: AES-CMAC takes 16, 24 or 32 octets, not %d", ErrKeyLength, len(k.Secret))
		}
		return cmacAES(k.Secret, msg)
	case AlgMD5:
		// The legacy construction: the key, then the packet, through
		// MD5. Not an HMAC, which is part of why RFC 8573 replaced it.
		h := md5.New() //nolint:gosec // verifying what a legacy device sends
		h.Write(k.Secret)
		h.Write(msg)
		return h.Sum(nil), nil
	case AlgSHA1:
		h := sha1.New() //nolint:gosec // the same
		h.Write(k.Secret)
		h.Write(msg)
		return h.Sum(nil), nil
	}
	return nil, fmt.Errorf("%w: %q", ErrAlgorithm, k.Algorithm)
}

// Verify checks a packet's MAC against a key set.
//
// The comparison is constant time, and the digest length is taken from
// what the key's algorithm produces rather than from the packet: a
// sender that truncated its digest to one octet would otherwise have a
// one-in-256 chance of being believed.
func (p *Packet) Verify(keys Keys) error {
	if !p.HasMAC {
		return ErrNoMAC
	}
	k, ok := keys[p.KeyID]
	if !ok {
		return fmt.Errorf("%w: %d", ErrNoKey, p.KeyID)
	}
	if p.MACStart < HeaderLen || p.MACStart > len(p.Raw) {
		return ErrMACMismatch
	}
	want, err := k.Compute(p.Raw[:p.MACStart])
	if err != nil {
		return err
	}
	if len(p.MAC) != len(want) {
		// A digest of the wrong length for the key's algorithm is not a
		// digest that failed; it is a different claim, and saying so is
		// how a configuration mistake reads as one.
		return fmt.Errorf("%w: %d octets of digest where %s produces %d",
			ErrMACMismatch, len(p.MAC), k.Algorithm, len(want))
	}
	if subtle.ConstantTimeCompare(p.MAC, want) != 1 {
		return ErrMACMismatch
	}
	return nil
}

// Sign appends a key identifier and MAC to a rendered packet, for the
// probes this relay sends to a server that requires authentication.
func (k Key) Sign(packet []byte) ([]byte, error) {
	mac, err := k.Compute(packet)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(packet)+4+len(mac))
	out = append(out, packet...)
	out = append(out, byte(k.ID>>24), byte(k.ID>>16), byte(k.ID>>8), byte(k.ID))
	return append(out, mac...), nil
}

// cmacAES is AES-CMAC (RFC 4493), which the standard library does not
// have. It is short, it is exactly specified, and it is tested against
// the RFC's own vectors -- including the subkeys, so a failure says
// which half is wrong.
func cmacAES(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	const bs = aes.BlockSize
	// The subkeys: L = E(K, 0), then two conditional shifts.
	var l [bs]byte
	block.Encrypt(l[:], l[:])
	k1 := shiftAndXor(l[:])
	k2 := shiftAndXor(k1)

	n := (len(msg) + bs - 1) / bs
	complete := len(msg) > 0 && len(msg)%bs == 0
	if n == 0 {
		n = 1
	}
	last := make([]byte, bs)
	copy(last, msg[(n-1)*bs:])
	if complete {
		xorInto(last, k1)
	} else {
		// The padding of the specification: a single one bit, then
		// zeros, then the second subkey.
		last[len(msg)-(n-1)*bs] = 0x80
		xorInto(last, k2)
	}
	var x [bs]byte
	for i := 0; i < n-1; i++ {
		xorInto(x[:], msg[i*bs:(i+1)*bs])
		block.Encrypt(x[:], x[:])
	}
	xorInto(x[:], last)
	out := make([]byte, bs)
	block.Encrypt(out, x[:])
	return out, nil
}

// shiftAndXor is the subkey derivation: a left shift by one bit, and the
// constant 0x87 exclusive-ored in when the top bit was set.
func shiftAndXor(in []byte) []byte {
	out := make([]byte, len(in))
	carry := byte(0)
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if in[0]&0x80 != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func xorInto(dst []byte, src []byte) {
	for i := 0; i < len(dst) && i < len(src); i++ {
		dst[i] ^= src[i]
	}
}
