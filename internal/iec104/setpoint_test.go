package iec104

import (
	"encoding/binary"
	"math"
	"testing"
)

// The three setpoint encodings, read as one number.
//
// They are not interchangeable and the difference is not cosmetic: the same two
// octets are a fraction of full scale in one and an engineering integer in the
// other, so a bound written against the wrong reading is a bound about nothing.
func TestSetpointValuesAreReadPerEncoding(t *testing.T) {
	f32 := func(v float32) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, math.Float32bits(v))
		return b
	}
	u16 := func(v uint16) []byte {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, v)
		return b
	}
	for _, tc := range []struct {
		name string
		typ  Type
		elem []byte
		want float64
		ok   bool
	}{
		// Normalised: the signed value over 2^15.
		{"normalised zero", CSeNA1, append(u16(0x0000), 0x00), 0, true},
		{"normalised +half", CSeNA1, append(u16(0x4000), 0x00), 0.5, true},
		{"normalised -one", CSeNA1, append(u16(0x8000), 0x00), -1, true},
		{"normalised near +one", CSeNA1, append(u16(0x7fff), 0x00), 32767.0 / 32768, true},

		// Scaled: the signed integer as it stands.
		{"scaled 100", CSeNB1, append(u16(100), 0x00), 100, true},
		{"scaled -1", CSeNB1, append(u16(0xffff), 0x00), -1, true},
		{"scaled min", CSeNB1, append(u16(0x8000), 0x00), -32768, true},
		{"scaled max", CSeNB1, append(u16(0x7fff), 0x00), 32767, true},

		// Short float.
		{"float 42.5", CSeNC1, append(f32(42.5), 0x00), 42.5, true},
		{"float -0.25", CSeNC1, append(f32(-0.25), 0x00), -0.25, true},

		// The timed forms carry the value in the same place.
		{"timed scaled", CSeTB1, append(append(u16(250), 0x00), 0, 0, 0, 0, 0, 0, 0), 250, true},
		{"timed float", CSeTC1, append(append(f32(1.5), 0x00), 0, 0, 0, 0, 0, 0, 0), 1.5, true},

		// And the types that carry no setpoint at all.
		{"single command", CScNA1, []byte{0x81}, 0, false},
		{"regulating step", CRcNA1, []byte{0x01}, 0, false},
		{"bitstring command", CBoNA1, []byte{1, 2, 3, 4}, 0, false},
		{"a measurement", MMeNB1, []byte{0x64, 0x00}, 0, false},
	} {
		body := append([]byte{0x0a, 0x00, 0x00}, tc.elem...)
		f, err := Parse(iframe(1, 1, asdu(tc.typ, 1, false, CauseActivation, 1, body...)...))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, ok := f.ASDU.Setpoint()
		if ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.ok)
			continue
		}
		if ok && math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: value = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A truncated element reports no value rather than reading past it. The parser
// bounds the element, so this is belt and braces -- but Setpoint is called with
// whatever Qualifier holds, and a caller that grew a new path into it should not
// be able to read off the end.
func TestSetpointOnAShortElementReportsNothing(t *testing.T) {
	for _, a := range []*ASDU{
		{Type: CSeNB1, Qualifier: nil},
		{Type: CSeNB1, Qualifier: []byte{0x01}},
		{Type: CSeNC1, Qualifier: []byte{0x01, 0x02, 0x03}},
		{Type: CSeNA1, Qualifier: []byte{}},
	} {
		if _, ok := a.Setpoint(); ok {
			t.Errorf("%v with %d qualifier octets reported a value", a.Type, len(a.Qualifier))
		}
	}
	var nilASDU *ASDU
	if _, ok := nilASDU.Setpoint(); ok {
		t.Error("a nil ASDU reported a setpoint")
	}
}

// Every type the encoding table names is a type that supports selection and has
// a qualifier after its value, and every setpoint type is in the table. Three
// tables about the same handful of type codes drift apart unless something holds
// them together.
func TestTheSetpointTableAgreesWithTheOthers(t *testing.T) {
	for i := 0; i < 256; i++ {
		ty := Type(i)
		kind, _ := SetpointEncoding(ty)
		if kind == NotASetpoint {
			continue
		}
		if !ty.SelectSupported() {
			t.Errorf("%v carries a setpoint but does not support selection", ty)
		}
		at, ok := qualifierOffset(ty)
		if !ok {
			t.Errorf("%v carries a setpoint but has no qualifier octet", ty)
			continue
		}
		// The qualifier sits after the value, which is what the value's width
		// says it should be.
		width := map[SetpointKind]int{Normalised: 2, Scaled: 2, ShortFloat: 4}[kind]
		if at != width {
			t.Errorf("%v: value is %d octets but the qualifier is at %d", ty, width, at)
		}
	}
}
