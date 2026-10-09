package opcua

import (
	"testing"

	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/opcua"
)

// Which OPC UA service calls are engineering, on its own.
//
// Call is the one worth the most. On this protocol a method is whatever the
// server's author decided -- "LoadRecipe", "Reset", "StartBatch" -- so a
// method call is an operation whose meaning this relay cannot read and whose
// consequences are the vendor's; the honest thing is to name it, record which
// method it was, and let the grant say whether it was expected. The other
// half is the address space itself: adding a node, deleting a reference,
// rewriting history.
//
// A Write to a variable's value is not engineering -- that is an HMI moving a
// setpoint, which the node rules are for -- but a write to access_level is,
// because it changes what the *next* client may do.
func TestWhichServiceCallsAreEngineering(t *testing.T) {
	pump := NodeRef{Key: "ns=4;s=Line1/Pump1"}
	reset := NodeRef{Key: "ns=4;s=Line1/Pump1/Reset"}
	speed := NodeRef{Key: "ns=4;s=Line1/Pump1/Speed"}

	for _, tc := range []struct {
		name   string
		svc    wire.Service
		ops    []Operation
		want   engineering.Class
		point  string
		detail string
	}{
		{name: "a method call is an operation this relay cannot read",
			svc:   wire.SvcCall,
			ops:   []Operation{{Node: pump, Method: &reset}},
			want:  engineering.ClassMethodCall,
			point: "ns=4;s=Line1/Pump1", detail: "call ns=4;s=Line1/Pump1/Reset"},
		// A Call with no object decoded is still a method call: the class is
		// what the service is, and the detail falls back to the service name
		// rather than claiming a node nothing read.
		{name: "a method call naming nothing is still one",
			svc: wire.SvcCall, want: engineering.ClassMethodCall, detail: "call"},

		{name: "adding a node changes the address space",
			svc: wire.SvcAddNodes, ops: []Operation{{Node: pump}},
			want: engineering.ClassConfiguration, point: "ns=4;s=Line1/Pump1",
			detail: "add_nodes"},
		{name: "so does deleting one",
			svc: wire.SvcDeleteNodes, ops: []Operation{{Node: pump}},
			want: engineering.ClassConfiguration, point: "ns=4;s=Line1/Pump1",
			detail: "delete_nodes"},
		{name: "and a reference", svc: wire.SvcAddReferences,
			ops: []Operation{{Node: pump}}, want: engineering.ClassConfiguration,
			point: "ns=4;s=Line1/Pump1", detail: "add_references"},
		{name: "and removing one", svc: wire.SvcDeleteRefs,
			ops: []Operation{{Node: pump}}, want: engineering.ClassConfiguration,
			point: "ns=4;s=Line1/Pump1", detail: "delete_references"},
		// Rewriting history is the one that changes the record of what the
		// plant did rather than what it will do.
		{name: "rewriting history changes the record", svc: wire.SvcHistoryUpdate,
			ops: []Operation{{Node: pump}}, want: engineering.ClassConfiguration,
			point: "ns=4;s=Line1/Pump1", detail: "history_update"},
		{name: "a configuration service naming nothing still reports its class",
			svc: wire.SvcAddNodes, want: engineering.ClassConfiguration,
			detail: "add_nodes"},

		{name: "a write to access_level decides what the next client may do",
			svc:   wire.SvcWrite,
			ops:   []Operation{{Node: speed, Attr: wire.AttrAccessLevel, Write: true}},
			want:  engineering.ClassConfiguration,
			point: "ns=4;s=Line1/Pump1/Speed", detail: "write access_level"},
		// The first access_level in the request decides, so a write that mixes
		// a setpoint with a permission is not a setpoint.
		{name: "a setpoint beside a permission does not hide it",
			svc: wire.SvcWrite,
			ops: []Operation{
				{Node: speed, Attr: wire.AttrValue, Write: true},
				{Node: speed, Attr: wire.AttrAccessLevel, Write: true}},
			want:  engineering.ClassConfiguration,
			point: "ns=4;s=Line1/Pump1/Speed", detail: "write access_level"},

		// And what is not.
		{name: "a setpoint is the process", svc: wire.SvcWrite,
			ops: []Operation{{Node: speed, Attr: wire.AttrValue, Write: true}}},
		// A *read* of access_level is not engineering: asking who may do what
		// changes nothing, and reporting it would bury the writes.
		{name: "reading access_level changes nothing", svc: wire.SvcWrite,
			ops: []Operation{{Node: speed, Attr: wire.AttrAccessLevel}}},
		{name: "a read is not engineering", svc: wire.SvcRead,
			ops: []Operation{{Node: speed, Attr: wire.AttrValue}}},
		{name: "nor is browsing the address space", svc: wire.SvcBrowse},
		{name: "no call at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var call *wire.ServiceCall
			if tc.svc != 0 || tc.want != "" {
				call = &wire.ServiceCall{Service: tc.svc}
			}
			op, ok := engineeringOf(call, tc.ops)
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
			if op.Detail != tc.detail {
				t.Errorf("detail %q, want %q", op.Detail, tc.detail)
			}
		})
	}

	// A nil call is not engineering, which is the path a message the relay
	// could not decode takes.
	if op, ok := engineeringOf(nil, nil); ok {
		t.Errorf("a nil service call was reported as engineering: %+v", op)
	}
}
