package iec104

import (
	"testing"

	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/iec104"
)

// Which IEC 104 ASDUs are engineering, on its own.
//
// The line this draws is the one a control room cares about: a breaker being
// operated is the control centre's own work and the rules and the
// select-before-operate machinery are for it, while a reset, the clock and
// the parameters of a measured value change what the station *is*. The
// parameters are the case that makes this worth having: the deadband and the
// scaling are what a control centre sees its own telemetry through, so
// changing one changes what the operators are looking at without touching a
// single measurement.
func TestWhichASDUsAreEngineering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		a     *wire.ASDU
		want  engineering.Class
		point string
	}{
		{name: "a reset process command restarts the station",
			a:    &wire.ASDU{Type: wire.CRpNA1, Cause: wire.CauseActivation, Common: 1},
			want: engineering.ClassRestart, point: "station 1"},
		{name: "the clock is a setting",
			a:    &wire.ASDU{Type: wire.CCsNA1, Cause: wire.CauseActivation, Common: 2},
			want: engineering.ClassConfiguration, point: "station 2"},
		{name: "a parameter of a measured value is a setting",
			a: &wire.ASDU{Type: wire.PMeNB1, Cause: wire.CauseActivation, Common: 1,
				Addresses: []uint32{5001}},
			want: engineering.ClassConfiguration, point: "station 1 5001"},
		{name: "so is activating one",
			a: &wire.ASDU{Type: wire.PAcNA1, Cause: wire.CauseActivation, Common: 1,
				Addresses: []uint32{5001}},
			want: engineering.ClassConfiguration, point: "station 1 5001"},
		{name: "the file set moves an SCL or a firmware image",
			a: &wire.ASDU{Type: wire.FScNA1, Cause: wire.CauseActivation, Common: 1,
				Addresses: []uint32{7}},
			want: engineering.ClassFileTransfer, point: "station 1 7"},
		{name: "a deactivation of one is the same class",
			a:    &wire.ASDU{Type: wire.CRpNA1, Cause: wire.CauseDeactivation, Common: 1},
			want: engineering.ClassRestart, point: "station 1"},

		// And what is not.
		{name: "a single command is a breaker, not engineering",
			a: &wire.ASDU{Type: wire.CScNA1, Cause: wire.CauseActivation, Common: 1,
				Addresses: []uint32{4321}}},
		{name: "a setpoint is not either",
			a: &wire.ASDU{Type: wire.CSeNB1, Cause: wire.CauseActivation, Common: 1,
				Addresses: []uint32{5001}}},
		{name: "an interrogation asks and changes nothing",
			a: &wire.ASDU{Type: wire.CIcNA1, Cause: wire.CauseActivation, Common: 1}},
		// A station's own confirmation of a reset carries the same type
		// identification travelling the other way, and is not a new operation:
		// counting it would double every engineering act in the record.
		{name: "a confirmation of a reset is not a second reset",
			a: &wire.ASDU{Type: wire.CRpNA1, Cause: wire.CauseActCon, Common: 1}},
		{name: "nor is telemetry",
			a: &wire.ASDU{Type: wire.MMeNB1, Cause: wire.CauseSpontaneous, Common: 1}},
		{name: "no ASDU at all", a: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, ok := engineeringOf(tc.a)
			if tc.want == "" {
				if ok {
					t.Fatalf("reported as engineering: %+v", op)
				}
				return
			}
			if !ok {
				t.Fatal("not reported as engineering")
			}
			if op.Class != tc.want {
				t.Errorf("class %q, want %q", op.Class, tc.want)
			}
			if op.Point != tc.point {
				t.Errorf("point %q, want %q", op.Point, tc.point)
			}
			if op.Detail == "" {
				t.Error("the operation carries no detail, so the event would not say what happened")
			}
		})
	}
}
