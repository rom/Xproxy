package webauthn

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The CBOR reader's edges, which are where a decoder is attacked.
//
// An attestation object arrives from a browser, so every length in it is
// somebody else's number. What matters is that a length past the end of
// the buffer is an error rather than a read past it, that an argument
// too large for int64 is refused rather than wrapped into a small one,
// and that the encodings this format allows but canonical CBOR does not
// -- indefinite lengths, reserved additional information -- are refused
// rather than guessed at.
func TestTheCBORReaderRefusesWhatItCannotRead(t *testing.T) {
	ff8 := bytes.Repeat([]byte{0xff}, 8)
	for _, tc := range []struct {
		name string
		in   []byte
		want error
		says string
	}{
		{"nothing at all", nil, ErrCBORShort, ""},
		{"a one-byte argument that is not there", []byte{0x18}, ErrCBORShort, ""},
		{"a two-byte argument that is not there", []byte{0x19, 0x01}, ErrCBORShort, ""},
		{"a four-byte argument that is not there", []byte{0x1a, 0x00, 0x00}, ErrCBORShort, ""},
		{"an eight-byte argument that is not there", []byte{0x1b, 0x00}, ErrCBORShort, ""},
		{"an indefinite length", []byte{0x5f}, ErrCBOR, "additional information 31"},
		{"reserved additional information", []byte{0x1c}, ErrCBOR, "additional information 28"},
		{"a negative integer past int64", append([]byte{0x3b}, ff8...), ErrCBOR, "negative integer out of range"},
		{"a map of more pairs than exist", append([]byte{0xbb}, ff8...), ErrCBOR, "map of"},
		{"a byte string longer than the buffer", []byte{0x45, 1, 2}, ErrCBORShort, ""},
		{"a simple value nothing defines", []byte{0xf7}, ErrCBOR, "simple value 23"},
		{"a tag, which this decoder has no use for", []byte{0xc0, 0x01}, ErrCBOR, "major type 6"},
		{"a map key that is neither a number nor a string", []byte{0xa1, 0xf5, 0x01}, ErrCBOR, "map key is not an integer or a string"},
		{"a map key past int64", append(append([]byte{0xa1, 0x1b}, ff8...), 0x01), ErrCBOR, "map key out of range"},
	} {
		_, _, err := decodeCBOR(tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
			continue
		}
		if tc.says != "" && !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: error %v, want it to mention %q", tc.name, err, tc.says)
		}
	}
}

// The three values that carry no payload, and the readers that say what
// a decoded value is not.
func TestTheCBORSimpleValuesAndTheReadersThatRefuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want cborValue
	}{
		{"false", []byte{0xf4}, false},
		{"true", []byte{0xf5}, true},
		{"null", []byte{0xf6}, nil},
		{"an eight-byte unsigned integer", append([]byte{0x1b, 0, 0, 0, 0, 0, 0, 0}, 0x07), uint64(7)},
	} {
		v, n, err := decodeCBOR(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if v != tc.want {
			t.Errorf("%s: decoded %#v, want %#v", tc.name, v, tc.want)
		}
		if n != len(tc.in) {
			t.Errorf("%s: read %d of %d bytes", tc.name, n, len(tc.in))
		}
	}
	// An unsigned integer too large for int64 is not an integer this
	// package will hand on, and nothing else is read as one either.
	big, _, err := decodeCBOR(append([]byte{0x1b}, bytes.Repeat([]byte{0xff}, 8)...))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cborInt(big); ok {
		t.Error("an unsigned integer past int64 read as an int64")
	}
	for _, v := range []cborValue{true, nil, "text"} {
		if _, ok := cborInt(v); ok {
			t.Errorf("%#v read as an integer", v)
		}
	}
	if _, ok := cborBytes(true); ok {
		t.Error("a boolean read as a byte string")
	}
	if _, ok := cborText(true); ok {
		t.Error("a boolean read as text")
	}
	if _, ok := cborMap(true); ok {
		t.Error("a boolean read as a map")
	}
}
