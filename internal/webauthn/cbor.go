// Package webauthn verifies WebAuthn assertions at the edge on the
// standard library only: a minimal CBOR reader for the shapes the
// specification uses, COSE public keys, and the registration and
// authentication ceremonies of a second factor.
//
// Attestation statements are deliberately not verified. Attestation says
// which authenticator model produced a credential, which matters when a
// deployment allows only certain hardware; it says nothing about whether
// the person registering is the person the account belongs to. Here a
// credential is trusted because the registration was authenticated by a
// factor the user already had, not because a manufacturer signed for the
// device. That is the honest reading of a second factor, and the
// alternative -- a metadata service, a certificate chain per vendor and a
// revocation story -- is a different feature with a different name.
package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// The CBOR this reads is the subset RFC 8949 calls canonical and CTAP2
// requires: definite lengths, no tags, no floats in the places these
// structures use. Everything else is refused rather than interpreted,
// because every byte here came from a browser and an authenticator, and a
// decoder that guesses is a decoder an attacker steers.
const (
	// maxCBORDepth bounds nesting. An attestation object is three levels;
	// a COSE key is two.
	maxCBORDepth = 16
	// maxCBORItems bounds the members of one map or array.
	maxCBORItems = 1024
	// maxCBORBytes bounds one byte or text string.
	maxCBORBytes = 1 << 20
)

var (
	// ErrCBOR is a value this reader will not decode.
	ErrCBOR = errors.New("webauthn: bad CBOR")
	// ErrCBORShort is a value that ends before it should.
	ErrCBORShort = errors.New("webauthn: truncated CBOR")
)

// cborValue is a decoded item: uint64, int64, []byte, string,
// []cborValue, or map[cborKey]cborValue.
type cborValue any

// cborKey is a map key. CBOR allows any value as a key; the structures
// here use only integers and strings, and a key of another type is
// refused rather than stringified into something that might collide.
type cborKey struct {
	text  string
	num   int64
	isNum bool
}

func textKey(s string) cborKey { return cborKey{text: s} }
func numKey(n int64) cborKey   { return cborKey{num: n, isNum: true} }

// cborReader walks a byte slice.
type cborReader struct {
	b   []byte
	pos int
}

// decodeCBOR reads one item and returns it with the bytes after it, so a
// caller can tell a document with trailing data from a clean one.
func decodeCBOR(b []byte) (cborValue, int, error) {
	r := &cborReader{b: b}
	v, err := r.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, r.pos, nil
}

// head reads the initial byte and its argument.
func (r *cborReader) head() (major byte, arg uint64, err error) {
	if r.pos >= len(r.b) {
		return 0, 0, ErrCBORShort
	}
	ib := r.b[r.pos]
	r.pos++
	major = ib >> 5
	extra := ib & 0x1f
	switch {
	case extra < 24:
		return major, uint64(extra), nil
	case extra == 24:
		if r.pos+1 > len(r.b) {
			return 0, 0, ErrCBORShort
		}
		arg = uint64(r.b[r.pos])
		r.pos++
		return major, arg, nil
	case extra == 25:
		if r.pos+2 > len(r.b) {
			return 0, 0, ErrCBORShort
		}
		arg = uint64(binary.BigEndian.Uint16(r.b[r.pos:]))
		r.pos += 2
		return major, arg, nil
	case extra == 26:
		if r.pos+4 > len(r.b) {
			return 0, 0, ErrCBORShort
		}
		arg = uint64(binary.BigEndian.Uint32(r.b[r.pos:]))
		r.pos += 4
		return major, arg, nil
	case extra == 27:
		if r.pos+8 > len(r.b) {
			return 0, 0, ErrCBORShort
		}
		arg = binary.BigEndian.Uint64(r.b[r.pos:])
		r.pos += 8
		return major, arg, nil
	}
	// 28 to 30 are reserved; 31 is an indefinite length, which canonical
	// CBOR does not use and which a streaming decoder is where the
	// length-confusion bugs live.
	return 0, 0, fmt.Errorf("%w: additional information %d", ErrCBOR, extra)
}

// item reads one value.
func (r *cborReader) item(depth int) (cborValue, error) {
	if depth > maxCBORDepth {
		return nil, fmt.Errorf("%w: nested past %d", ErrCBOR, maxCBORDepth)
	}
	major, arg, err := r.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0: // unsigned
		return arg, nil
	case 1: // negative: -1 - arg
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: negative integer out of range", ErrCBOR)
		}
		return -1 - int64(arg), nil //nolint:gosec // bounded above
	case 2, 3: // byte and text strings
		if arg > maxCBORBytes {
			return nil, fmt.Errorf("%w: string of %d bytes", ErrCBOR, arg)
		}
		n := int(arg) //nolint:gosec // bounded above
		if r.pos+n > len(r.b) {
			return nil, ErrCBORShort
		}
		raw := r.b[r.pos : r.pos+n]
		r.pos += n
		if major == 2 {
			// Copied, so a decoded value does not alias the buffer a
			// caller may still be holding or reusing.
			out := make([]byte, n)
			copy(out, raw)
			return out, nil
		}
		return string(raw), nil
	case 4: // array
		if arg > maxCBORItems {
			return nil, fmt.Errorf("%w: array of %d items", ErrCBOR, arg)
		}
		// The capacity is what the remaining bytes could hold, not what
		// the header claims: the smallest item is one byte.
		out := make([]cborValue, 0, min(int(arg), len(r.b)-r.pos+1)) //nolint:gosec // bounded above
		for i := uint64(0); i < arg; i++ {
			v, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5: // map
		if arg > maxCBORItems {
			return nil, fmt.Errorf("%w: map of %d pairs", ErrCBOR, arg)
		}
		out := make(map[cborKey]cborValue, min(int(arg), 64)) //nolint:gosec // bounded above
		for i := uint64(0); i < arg; i++ {
			kv, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			k, err := keyOf(kv)
			if err != nil {
				return nil, err
			}
			if _, dup := out[k]; dup {
				// A duplicate key is a document two parsers read
				// differently, which is how one of them is made to see a
				// different key than the other.
				return nil, fmt.Errorf("%w: duplicate map key", ErrCBOR)
			}
			v, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 7:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, fmt.Errorf("%w: simple value %d", ErrCBOR, arg)
	}
	return nil, fmt.Errorf("%w: major type %d", ErrCBOR, major)
}

// keyOf turns a decoded value into a map key.
func keyOf(v cborValue) (cborKey, error) {
	switch k := v.(type) {
	case string:
		return textKey(k), nil
	case uint64:
		if k > math.MaxInt64 {
			return cborKey{}, fmt.Errorf("%w: map key out of range", ErrCBOR)
		}
		return numKey(int64(k)), nil //nolint:gosec // bounded above
	case int64:
		return numKey(k), nil
	}
	return cborKey{}, fmt.Errorf("%w: map key is not an integer or a string", ErrCBOR)
}

// cborMap reads a map out of a value.
func cborMap(v cborValue) (map[cborKey]cborValue, bool) {
	m, ok := v.(map[cborKey]cborValue)
	return m, ok
}

// cborBytes reads a byte string out of a value.
func cborBytes(v cborValue) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}

// cborText reads a text string out of a value.
func cborText(v cborValue) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// cborInt reads an integer of either sign out of a value.
func cborInt(v cborValue) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true //nolint:gosec // bounded above
	case int64:
		return n, true
	}
	return 0, false
}
