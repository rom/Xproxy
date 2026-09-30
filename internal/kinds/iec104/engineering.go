package iec104

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/textsafe"
)

// Engineering on IEC 60870-5-104, where the type identification says which
// commands are a control room's work and which are a substation's:
//
//	C_RP_NA_1               reset process               restart
//	C_CS_NA_1               the clock                   configuration
//	P_ME_*, P_AC_NA_1       parameters of measured values and their activation
//	                                                    configuration
//	F_* (the file set)      SCL, disturbance records, firmware
//	                                                    file_transfer
//
// A single or double command is not engineering: that is a breaker being
// operated, and it is what the rules and the select-before-operate machinery are
// for. The parameters are, and they are the interesting case: a parameter of a
// measured value is the deadband and the scaling a control centre sees its own
// telemetry through, so changing one changes what the operators are looking at
// without touching a single measurement.

// engineeringOf classifies one ASDU from a controlling station.
func engineeringOf(a *wire.ASDU) (engineering.Operation, bool) {
	if a == nil || !a.Cause.Commanding() {
		return engineering.Operation{}, false
	}
	var class engineering.Class
	switch {
	case a.Type == wire.CRpNA1:
		class = engineering.ClassRestart
	case a.Type == wire.CCsNA1:
		class = engineering.ClassConfiguration
	case a.Type >= wire.PMeNA1 && a.Type <= wire.PAcNA1:
		class = engineering.ClassConfiguration
	case a.Type >= wire.FFrNA1 && a.Type <= wire.FScNB1:
		class = engineering.ClassFileTransfer
	default:
		return engineering.Operation{}, false
	}
	op := engineering.Operation{Class: class, Detail: a.Type.String(),
		Point: fmt.Sprintf("station %d", a.Common)}
	if len(a.Addresses) > 0 {
		op.Point = fmt.Sprintf("station %d %d", a.Common, a.Addresses[0])
	}
	return op, true
}

// decideEngineering reports one engineering operation and says whether to carry
// the frame.
func (se *session) decideEngineering(frame *wire.Frame) (string, bool) {
	t := se.t
	if !t.engineering.On() {
		return "", true
	}
	a := frame.ASDU
	op, ok := engineeringOf(a)
	if !ok {
		return "", true
	}
	// This protocol has no user either, so the work order names the control
	// centre's address.
	subject := se.ip.String()
	reason := t.engineering.Decide(op, subject, t.m.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(op engineering.Operation, grant *access.Grant) {
				t.reportEngineering(se, op, grant)
			},
			Ungranted: func(op engineering.Operation, reason string) {
				t.alert(se.ip, reason, op.String())
			},
			Would: func(op engineering.Operation, reason string) {
				t.host.Counters().IEC104WouldDeny.Add(1)
				t.host.Counters().WouldRefuse("iec104", reason)
				t.shadowed(reason, "engineering", a)
			},
			Refused: func(op engineering.Operation, reason string) {
				t.host.Counters().IEC104Denied.Add(1)
				se.denied.Add(1)
				t.alert(se.ip, reason, op.String())
			},
		})
	if reason == "" {
		return "", true
	}
	return "iec104_" + reason, false
}

func (t *server) reportEngineering(se *session, op engineering.Operation, grant *access.Grant) {
	t.host.Counters().Engineering("iec104", string(op.Class))
	t.host.ObserveFact(se.ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "iec104", Listener: t.cfg.Name,
		Detail: op.String(),
	})
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "proto", "iec104",
		"class", string(op.Class), "operation", textsafe.Clip64(op.Detail)}
	if op.Point != "" {
		attrs = append(attrs, "object", op.Point)
	}
	if grant != nil {
		attrs = append(attrs, "grant", grant.ID, "work_order", textsafe.Clip64(grant.Reason))
	}
	t.host.Logs().SecurityEvent(context.Background(), "engineering",
		engineering.Reason(op.Class), attrs...)
}
