package amqpwire

import (
	"math"
	"strings"
	"testing"
)

// The signed integers of AMQP 1.0, at every width the protocol defines.
//
// A negative number arrives as two's complement, so reading one is a
// reinterpretation of the same octets rather than a conversion. Reading it as
// unsigned instead is the failure worth having a test for: a link credit of -1
// would read as 18446744073709551615, and a policy comparing a number against
// a bound would let it through as enormous rather than refusing it as
// nonsense. Every one of these readers was at 0 % before this.
func TestEverySignedWidthIsReadAsTwosComplement(t *testing.T) {
	for _, c := range []struct {
		name string
		enc  []byte
		want int64
	}{
		// byte (0x51), smallint (0x54), smalllong (0x55): one octet.
		{"byte zero", []byte{0x51, 0x00}, 0},
		{"byte one", []byte{0x51, 0x01}, 1},
		{"byte minus one", []byte{0x51, 0xff}, -1},
		{"byte most negative", []byte{0x51, 0x80}, math.MinInt8},
		{"byte most positive", []byte{0x51, 0x7f}, math.MaxInt8},
		{"smallint minus one", []byte{0x54, 0xff}, -1},
		{"smalllong minus one", []byte{0x55, 0xff}, -1},

		// short (0x61): two octets, big endian.
		{"short minus one", []byte{0x61, 0xff, 0xff}, -1},
		{"short most negative", []byte{0x61, 0x80, 0x00}, math.MinInt16},
		{"short most positive", []byte{0x61, 0x7f, 0xff}, math.MaxInt16},

		// int (0x71): four octets.
		{"int minus one", []byte{0x71, 0xff, 0xff, 0xff, 0xff}, -1},
		{"int most negative", []byte{0x71, 0x80, 0x00, 0x00, 0x00}, math.MinInt32},
		{"int most positive", []byte{0x71, 0x7f, 0xff, 0xff, 0xff}, math.MaxInt32},

		// long (0x81) and timestamp (0x83): eight octets.
		{"long minus one", []byte{0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, -1},
		{"long most negative", []byte{0x81, 0x80, 0, 0, 0, 0, 0, 0, 0}, math.MinInt64},
		{"long most positive", []byte{0x81, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxInt64},
		{"a timestamp before the epoch", []byte{0x83, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newTypeReader(c.enc).value(0)
			if v.Kind != KindInt {
				t.Fatalf("kind = %v, want KindInt", v.Kind)
			}
			if v.I != c.want {
				t.Errorf("I = %d, want %d", v.I, c.want)
			}
			// A signed value is not an unsigned one: Uint must refuse it
			// rather than hand back the reinterpreted octets, which is
			// exactly the confusion this type system exists to stop.
			if u, ok := v.Uint(); ok && c.want < 0 {
				t.Errorf("a negative value read as the unsigned %d", u)
			}
		})
	}
}

// The unsigned widths beside them, so the pairing is the test rather than an
// assumption: the same octets under a different constructor are a different
// number, and that is the whole of why the constructor is read first.
func TestTheSameOctetsUnderAnUnsignedConstructorAreADifferentNumber(t *testing.T) {
	for _, c := range []struct {
		name string
		enc  []byte
		want uint64
	}{
		{"ubyte", []byte{0x50, 0xff}, 255},
		{"smalluint", []byte{0x52, 0xff}, 255},
		{"smallulong", []byte{0x53, 0xff}, 255},
		{"ushort", []byte{0x60, 0xff, 0xff}, 65535},
		{"uint", []byte{0x70, 0xff, 0xff, 0xff, 0xff}, 4294967295},
		{"ulong", []byte{0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxUint64},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newTypeReader(c.enc).value(0)
			if v.Kind != KindUint {
				t.Fatalf("kind = %v, want KindUint", v.Kind)
			}
			got, ok := v.Uint()
			if !ok || got != c.want {
				t.Errorf("Uint = %d, %v, want %d", got, ok, c.want)
			}
		})
	}
}

// A constructor from a later version of the protocol is stepped over exactly,
// by the width its category implies, and reported as present.
//
// This is the forward-compatibility rule: a type added after this was written
// must not be mistaken for a field that is missing, and must not desynchronise
// everything after it in the list. fixedWidth is what makes that exact, and it
// was at 0 %.
func TestATypeFromALaterVersionIsSteppedOverExactly(t *testing.T) {
	for _, c := range []struct {
		name  string
		code  byte
		width int
	}{
		{"an empty category (0x4_)", 0x4f, 0},
		{"one octet (0x5_)", 0x5f, 1},
		{"two octets (0x6_)", 0x6f, 2},
		{"four octets (0x7_)", 0x7f, 4},
		{"eight octets (0x8_)", 0x8f, 8},
		{"sixteen octets, where a uuid goes (0x9_)", 0x9f, 16},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The unknown value, then a string after it. The string must
			// still be read, which is what says the step was exact.
			enc := append([]byte{c.code}, make([]byte, c.width)...)
			enc = append(enc, 0xa1, 0x02, 'o', 'k')
			tr := newTypeReader(enc)
			first := tr.value(0)
			if first.Kind != KindOther {
				t.Errorf("kind = %v, want KindOther", first.Kind)
			}
			if !first.Present() {
				t.Error("an unknown type read as absent, which a missing field also is")
			}
			if got := tr.value(0).Text(); got != "ok" {
				t.Errorf("the value after it read as %q: the step was %d octets wide", got, c.width)
			}
		})
	}

	// A category with no width at all is not stepped over by guesswork: it
	// comes back as present with nothing consumed, so the caller's own
	// length is what bounds it.
	v := newTypeReader([]byte{0xff}).value(0)
	if v.Kind != KindOther || !v.Present() {
		t.Errorf("a constructor in no category = %+v", v)
	}
}

// The reader reports the version in force, which is what decides the framing.
//
// A relay that read 0-9-1 frames with 1.0 offsets, or the other way round,
// would mis-split every frame on the connection -- so the version is asked for
// rather than assumed, and it starts Unknown so that a frame arriving before
// the header is refused rather than framed by a guess.
func TestTheReaderSaysWhichFramingIsInForce(t *testing.T) {
	r := NewReader(strings.NewReader(""), 0)
	if got := r.Version(); got != Unknown {
		t.Errorf("a fresh reader is at version %v, want Unknown", got)
	}
	for _, v := range []Version{V091, V10, Unknown} {
		r.SetVersion(v)
		if got := r.Version(); got != v {
			t.Errorf("after SetVersion(%v) the reader is at %v", v, got)
		}
	}
}
