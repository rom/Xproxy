package modbus

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/textsafe"
)

// Engineering on Modbus, which the protocol itself has no word for and the
// vendors' sub-protocols do.
//
// A holding register write is not engineering: that is a setpoint, and the value
// rules are what police it. What is engineering arrives inside the function codes
// that carry a sub-protocol -- UMAS in function 90 on a Modicon, the diagnostic
// sub-functions of function 8 -- and this relay already classifies those by
// *effect* rather than by number, because the number is a vendor's and the effect
// is a plant's:
//
//	program   a control program, in either direction   program_download / upload
//	control   stop, start, restart, listen-only        mode_change
//	clear     the diagnostic register and event log    configuration
//
// The direction of a program transfer is what the sub-function says, and where
// this relay cannot tell it reports a download: "something moved a program" is
// the fact, and the safer reading of an ambiguous one is the one that gets
// looked at.

// engineeringOf classifies one request.
func engineeringOf(req request) (engineering.Operation, bool) {
	if req.pdu == nil {
		return engineering.Operation{}, false
	}
	effect, ok := req.pdu.SubEffect()
	if !ok {
		return engineering.Operation{}, false
	}
	var class engineering.Class
	switch effect {
	case wire.SubProgram:
		class = engineering.ClassProgramDownload
	case wire.SubControl:
		class = engineering.ClassModeChange
	case wire.SubClear:
		class = engineering.ClassConfiguration
	default:
		return engineering.Operation{}, false
	}
	detail := fmt.Sprintf("%s %s", wire.FunctionName(req.pdu.Function), effect)
	if req.pdu.HasSubFunction {
		detail = fmt.Sprintf("%s sub-function %d (%s)",
			wire.FunctionName(req.pdu.Function), req.pdu.SubFunction, effect)
	}
	return engineering.Operation{Class: class, Detail: detail,
		Point: fmt.Sprintf("unit %d", req.unit)}, true
}

// decideEngineering reports one engineering operation and says whether to carry
// it.
func (t *server) decideEngineering(se *session, req request) string {
	if !t.engineering.On() {
		return ""
	}
	op, ok := engineeringOf(req)
	if !ok {
		return ""
	}
	// Modbus names nobody, so the work order names the engineering station's
	// address. That is what the plant has, and pretending otherwise would be
	// inventing an identity out of a socket.
	subject := se.ip.String()
	return t.engineering.Decide(op, subject, t.m.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(op engineering.Operation, grant *access.Grant) {
				t.reportEngineering(se, op, grant)
			},
			Ungranted: func(op engineering.Operation, reason string) {
				t.engineeringOutside(se.ip, reason, op)
			},
			Would: func(op engineering.Operation, reason string) {
				t.host.Counters().ModbusWouldDeny.Add(1)
				t.host.Counters().WouldRefuse("modbus", reason)
				t.host.Shadow().Record("modbus", t.cfg.Name, reason, "engineering", op.String())
			},
			Refused: func(op engineering.Operation, reason string) {
				se.denied.Add(1)
				t.host.Counters().ModbusDenied.Add(1)
				t.alert(se.ip, reason, op.String())
			},
		})
}

func (t *server) reportEngineering(se *session, op engineering.Operation, grant *access.Grant) {
	t.host.Counters().Engineering("modbus", string(op.Class))
	t.host.ObserveFact(se.ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "modbus", Listener: t.cfg.Name,
		Detail: op.String(),
	})
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "proto", "modbus",
		"class", string(op.Class), "operation", textsafe.Clip64(op.Detail)}
	if op.Point != "" {
		attrs = append(attrs, "device", op.Point)
	}
	if grant != nil {
		attrs = append(attrs, "grant", grant.ID, "work_order", textsafe.Clip64(grant.Reason))
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
func (t *server) engineeringOutside(ip netip.Addr, reason string, op engineering.Operation) {
	t.host.Counters().EngineeringOutside("modbus", string(op.Class), reason)
	if !t.m.Alerts() {
		return
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "modbus_"+reason,
		"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "modbus",
		"reason", reason, "class", string(op.Class),
		"operation", textsafe.Clip64(op.String()))
}
