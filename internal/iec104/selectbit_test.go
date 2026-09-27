package iec104

import "testing"

// The select/execute bit is read from the octet that carries it, which is not
// always the first one in the information element.
//
// This was wrong, and wrong in the direction that matters. The parser read bit 8
// of the element's first byte for every command type. On a single, double or
// regulating step command that byte is the qualifier, so it was right. On a
// setpoint the element is the *value* first -- two octets of normalised or scaled
// value, four of short float -- and the qualifier of setpoint command after it.
// So the bit being read was bit 8 of the value's low byte:
//
//   - a direct execute whose low value byte had bit 8 set (128..255, 384..511,
//     and so on: half of all values) was read as a *selection*. A selection is
//     recorded and forwarded, and the station reads the real QOS, which says
//     execute -- so it executed a command the relay had written down as a mere
//     selection. That is select-before-execute bypassed on the kind that
//     advertises enforcing it.
//   - a genuine selection whose low value byte did not have the bit set was read
//     as an execute and refused as unselected, so two-step operation on small
//     setpoint values did not work either.
//
// Both halves are asserted here, per type, because the offsets differ.
func TestTheSelectBitIsReadFromTheQualifierOctet(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  Type
		elem []byte
		want bool
	}{
		// One qualifier octet, S/E in bit 8 of it.
		{"single command, execute", CScNA1, []byte{0x01}, false},
		{"single command, select", CScNA1, []byte{0x81}, true},
		{"double command, select", CDcNA1, []byte{0x82}, true},
		{"regulating step, execute", CRcNA1, []byte{0x01}, false},

		// Two octets of value, then the QOS. The value's low byte having bit 8
		// set is what used to be mistaken for a selection.
		{"scaled setpoint 0x0080, execute", CSeNB1, []byte{0x80, 0x00, 0x00}, false},
		{"scaled setpoint 0x0080, select", CSeNB1, []byte{0x80, 0x00, 0x80}, true},
		{"scaled setpoint 0x0001, execute", CSeNB1, []byte{0x01, 0x00, 0x00}, false},
		{"scaled setpoint 0x0001, select", CSeNB1, []byte{0x01, 0x00, 0x80}, true},
		{"normalised setpoint 0xff80, execute", CSeNA1, []byte{0x80, 0xff, 0x00}, false},
		{"normalised setpoint 0xff80, select", CSeNA1, []byte{0x80, 0xff, 0x80}, true},

		// Four octets of short float, then the QOS.
		{"float setpoint, execute", CSeNC1, []byte{0x80, 0x80, 0x80, 0x80, 0x00}, false},
		{"float setpoint, select", CSeNC1, []byte{0x80, 0x80, 0x80, 0x80, 0x80}, true},

		// The timed forms keep the qualifier in the same place, with the
		// CP56Time2a after it.
		{"timed single command, select", CScTA1, []byte{0x81, 0, 0, 0, 0, 0, 0, 0}, true},
		{"timed scaled setpoint, select", CSeTB1,
			[]byte{0x80, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0}, true},
		{"timed scaled setpoint, execute", CSeTB1,
			[]byte{0x80, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0}, false},

		// A 32-bit bitstring command has no qualifier octet, so no selection.
		// It reads as an execute, which is the direction that keeps it under the
		// rule rather than excused from it.
		{"bitstring command", CBoNA1, []byte{0xff, 0xff, 0xff, 0xff}, false},
	} {
		body := append([]byte{0x0a, 0x00, 0x00}, tc.elem...)
		f, err := Parse(iframe(1, 1, asdu(tc.typ, 1, false, CauseActivation, 1, body...)...))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := f.ASDU.Select; got != tc.want {
			t.Errorf("%s: Select = %v, want %v (element %v, qualifier at %d)",
				tc.name, got, tc.want, tc.elem, qualifierAt(tc.typ))
		}
	}
}

// Every type that says it supports selection has a qualifier octet to read the
// bit from, and every type that has one says it supports selection. The two
// tables are written apart and a type in one but not the other is a type whose
// select handling is decided by accident.
func TestSelectSupportAndTheQualifierOffsetAgree(t *testing.T) {
	for i := 0; i < 256; i++ {
		ty := Type(i)
		_, hasQualifier := qualifierOffset(ty)
		if ty.SelectSupported() != hasQualifier {
			t.Errorf("%v: SelectSupported %v but a qualifier offset %v",
				ty, ty.SelectSupported(), hasQualifier)
		}
		// And where there is one, it sits inside the element.
		if hasQualifier {
			size, known := objectSize(ty)
			if !known {
				t.Errorf("%v has a qualifier offset but no known element size", ty)
				continue
			}
			if at, _ := qualifierOffset(ty); at >= size {
				t.Errorf("%v: qualifier at %d in an element of %d", ty, at, size)
			}
		}
	}
}

func qualifierAt(t Type) int { at, _ := qualifierOffset(t); return at }
