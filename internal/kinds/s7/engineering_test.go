package s7

import (
	"testing"

	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/s7"
)

func TestS7CommPlusEngineeringClassification(t *testing.T) {
	tests := []struct {
		function uint16
		class    engineering.Class
	}{
		{wire.PlusBeginSequence, engineering.ClassProgramDownload},
		{wire.PlusEndSequence, engineering.ClassProgramDownload},
		{wire.PlusCreateObject, engineering.ClassConfiguration},
		{wire.PlusDeleteObject, engineering.ClassConfiguration},
		{wire.PlusInvoke, engineering.ClassMethodCall},
	}
	for _, test := range tests {
		pdu := &wire.PlusPDU{Type: wire.PlusData, Opcode: wire.PlusRequest,
			HasOpcode: true, Function: test.function, HasFunction: true}
		op, ok := plusEngineeringOf(pdu)
		if !ok || op.Class != test.class {
			t.Errorf("function %#x: operation = %+v, %v; want class %s", test.function, op, ok, test.class)
		}
	}

	read := &wire.PlusPDU{Function: wire.PlusGetMultiVariables, HasFunction: true}
	if op, ok := plusEngineeringOf(read); ok {
		t.Errorf("read classified as engineering: %+v", op)
	}
}
