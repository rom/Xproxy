package modbus

import (
	"testing"

	"github.com/rom/xproxy/internal/engineering"
)

// Which Modbus requests are engineering, on its own.
//
// On this protocol the function code is nearly useless for the question: a
// write to a holding register is the process being driven and a UMAS block
// download is a PLC being reprogrammed, and the specification has nothing to
// say about the second because UMAS is not in it. What separates them is the
// sub-function's effect, which is why that table exists -- and why this test
// is about the effect rather than about the code.
func TestWhichModbusRequestsAreEngineering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pdu   []byte
		want  engineering.Class
		point string
	}{
		{name: "a UMAS block upload carries a control program",
			pdu: umasUpload, want: engineering.ClassProgramDownload, point: "unit 1"},
		{name: "a UMAS stop moves the PLC out of run",
			pdu: umasStop, want: engineering.ClassModeChange, point: "unit 1"},
		{name: "so does a diagnostic restart of its communications",
			pdu: diagnose, want: engineering.ClassModeChange, point: "unit 1"},
		// Clearing the counters touches neither the process nor the program,
		// and it is how the record of something that did goes away.
		{name: "clearing the counters is a setting change",
			pdu:  []byte{8, 0x00, 0x0A, 0x00, 0x00},
			want: engineering.ClassConfiguration, point: "unit 1"},

		// And the ones that are not: the process being driven, and the
		// housekeeping a sub-protocol needs before it can do anything.
		{name: "a setpoint is the process, not the device",
			pdu: []byte{6, 0x01, 0x90, 0x00, 0x32}}, // write 50 to register 400
		{name: "a register read is not engineering",
			pdu: []byte{3, 0x00, 0x64, 0x00, 0x02}}, // read 2 registers at 100
		{name: "a UMAS variable read is not either", pdu: umasRead},
		{name: "a function code with no sub-function has no effect to read",
			pdu: []byte{17}}, // report server id
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, ok := engineeringOf(req(t, "10.0.0.9", "", 1, tc.pdu))
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
			// The detail names the sub-function, because "program_download"
			// on its own does not tell an engineer which block moved.
			if op.Detail == "" {
				t.Error("the operation carries no detail")
			}
		})
	}

	// A request the relay could not parse is not engineering: there is no
	// sub-function to read, and guessing from the octets would be deciding
	// about a frame nothing else in this listener decided about.
	if op, ok := engineeringOf(request{unit: 1}); ok {
		t.Errorf("a request with no PDU was reported as engineering: %+v", op)
	}
}
