package s7

import (
	"context"
	"net/netip"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/s7"
	"github.com/rom/xproxy/internal/textsafe"
)

// Engineering on S7comm, which is the protocol this whole idea is easiest to
// argue for: the operations an engineering station uses are *named* on the wire,
// and they are the operations a plant is compromised through.
//
//	download            control logic into the CPU        program_download
//	upload              control logic out of it           program_upload
//	stop, mode          run, program and stop             mode_change
//	control             warm restart, block insert        restart
//	time_write          the clock every batch record uses configuration
//	programmer          force a variable, set a breakpoint mode_change
//
// A read is not engineering, and neither is a write to a data block: an HMI
// writes setpoints all day and calling that an engineering operation would make
// the class useless. The line is "this changes what the machine *is*, not what
// it is doing".

// engineeringOf classifies one request, and says whether it is engineering at
// all.
func engineeringOf(pdu *wire.PDU) (engineering.Operation, bool) {
	if pdu == nil {
		return engineering.Operation{}, false
	}
	op, ok := pdu.Op()
	if !ok {
		return engineering.Operation{}, false
	}
	var class engineering.Class
	switch op {
	case wire.OpDownload:
		class = engineering.ClassProgramDownload
	case wire.OpUpload:
		class = engineering.ClassProgramUpload
	case wire.OpStop, wire.OpMode, wire.OpProgrammer:
		class = engineering.ClassModeChange
	case wire.OpControl:
		class = engineering.ClassRestart
	case wire.OpTimeWrite:
		class = engineering.ClassConfiguration
	default:
		return engineering.Operation{}, false
	}
	return engineering.Operation{Class: class, Detail: describe(pdu)}, true
}

// plusEngineeringOf classifies the administrative functions that remain
// visible outside S7comm-plus's encrypted payload. The function is necessarily
// less specific than classic S7comm: Invoke may contain a download or a mode
// change, but what the relay can prove from the wire is that a method ran.
func plusEngineeringOf(pdu *wire.PlusPDU) (engineering.Operation, bool) {
	if pdu == nil || !pdu.HasFunction {
		return engineering.Operation{}, false
	}
	var class engineering.Class
	switch pdu.Function {
	case wire.PlusBeginSequence, wire.PlusEndSequence:
		class = engineering.ClassProgramDownload
	case wire.PlusCreateObject, wire.PlusDeleteObject:
		class = engineering.ClassConfiguration
	case wire.PlusInvoke:
		class = engineering.ClassMethodCall
	default:
		return engineering.Operation{}, false
	}
	return engineering.Operation{Class: class, Detail: plusDetail(pdu)}, true
}

// decideEngineering reports one engineering operation and says whether to carry
// it: "" to go on, or the reason to refuse it.
func (t *server) decideEngineering(se *session, pdu *wire.PDU) string {
	if !t.engineering.On() {
		return ""
	}
	op, ok := engineeringOf(pdu)
	if !ok {
		return ""
	}
	return t.decideEngineeringOperation(se, op)
}

// decidePlusEngineering applies the same work-order guard to the separately
// parsed S7comm-plus path. Without this call an allowed administrative function
// would bypass both grant enforcement and the engineering audit trail.
func (t *server) decidePlusEngineering(se *session, pdu *wire.PlusPDU) string {
	if !t.engineering.On() {
		return ""
	}
	op, ok := plusEngineeringOf(pdu)
	if !ok {
		return ""
	}
	return t.decideEngineeringOperation(se, op)
}

func (t *server) decideEngineeringOperation(se *session, op engineering.Operation) string {
	s := se.sess()
	if s.Addressed {
		op.Point = wire.ResourceName(s.Resource)
	}
	// S7comm has no identity, so the subject is the address. That is the honest
	// answer and it is also the useful one: a grant for this protocol names
	// the engineering station's address, because that is what the plant has.
	subject := se.ip.String()
	return t.engineering.Decide(op, subject, t.sc.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(op engineering.Operation, grant *access.Grant, order *access.WorkOrder) {
				t.reportEngineering(se, op, grant, order)
			},
			Ungranted: func(op engineering.Operation, reason string, order *access.WorkOrder) {
				t.engineeringOutside(se.ip, reason, op, order)
			},
			Would: func(op engineering.Operation, reason string) {
				t.host.Counters().WouldRefuse("s7", reason)
				t.host.Shadow().Record("s7", t.name, reason, "engineering", op.String())
			},
			Refused: func(op engineering.Operation, reason string) {
				se.refusal()
				t.host.Counters().Refuse("s7", reason)
				t.alert(se.ip, reason, op.String())
			},
		})
}

// reportEngineering writes the operation down: its own security event, its
// counter, and a fact in the cross-listener window -- which the sibling daemons
// see, because "a bastion session, then a program download" is two processes.
func (t *server) reportEngineering(se *session, op engineering.Operation, grant *access.Grant, order *access.WorkOrder) {
	t.host.Counters().Engineering("s7", string(op.Class))
	t.host.ObserveFact(se.ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "s7", Listener: t.name,
		Identity: op.Subject, Detail: op.String(),
	})
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "s7",
		"class", string(op.Class), "operation", textsafe.Clip64(op.Detail)}
	if op.Point != "" {
		attrs = append(attrs, "resource", op.Point)
	}
	if grant != nil {
		// The grant this happened under and the reason it was approved for,
		// which is the line an audit is actually asking for.
		attrs = append(attrs, "grant", grant.ID, "grant_reason", grant.Reason)
	}
	// The work order on file for the device, and the tone that follows
	// from it. A work order is not an approval and permits nothing: it
	// says somebody was expecting work here, which is why the event is a
	// notice rather than a warning.
	attrs = append(attrs, "severity", engineering.Severity(order))
	if order != nil {
		t.host.Counters().EngineeringFiled("s7", string(op.Class))
		attrs = append(attrs, "work_order", order.Reference,
			"work_order_by", textsafe.Clip64(order.By))
	}
	t.host.Logs().SecurityEvent(context.Background(), "engineering",
		engineering.Reason(op.Class), attrs...)
}

// engineeringOutside records an operation that happened outside every approved
// window on a listener that does not require one.
//
// It counts EngineeringOutside rather than a refusal: the operation was
// carried. The event itself is unchanged -- same action, same reason -- so the
// behaviour packs and the ATT&CK mapping that read it are unaffected.
func (t *server) engineeringOutside(ip netip.Addr, reason string, op engineering.Operation, order *access.WorkOrder) {
	t.host.Counters().EngineeringOutside("s7", string(op.Class), reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "s7",
		"reason", reason, "class", string(op.Class),
		"operation", textsafe.Clip64(op.String())}
	// The tone follows the work order, the same way the report's does: an
	// operation somebody filed is a notice, one nobody filed is a warning.
	// Both are events, because the listener carried the operation either way.
	a = append(a, "severity", engineering.Severity(order))
	if order != nil {
		a = append(a, "work_order", order.Reference,
			"work_order_by", textsafe.Clip64(order.By))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "s7_"+reason, a...)
}
