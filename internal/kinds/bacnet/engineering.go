package bacnet

import (
	"context"
	"net/netip"

	"github.com/rom/xproxy/internal/access"
	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/textsafe"
)

// Engineering on BACnet, which is four of its confirmed services:
//
//	ReinitializeDevice           a controller restarted, warm or cold   restart
//	DeviceCommunicationControl   a controller told to stop talking      mode_change
//	AtomicWriteFile              a file into the device                 file_transfer
//	CreateObject, DeleteObject   the object model itself                configuration
//
// A WriteProperty to a present-value is not engineering: that is a setpoint or a
// command, which the rules are for. ReinitializeDevice and
// DeviceCommunicationControl are, and they are the two services on this protocol
// that a building's own tooling uses and an intruder uses for the same reason: a
// controller that has been told to stop communicating is a controller the head
// end cannot see, and the head end's operator finds out from the alarm that
// never arrives.

func engineeringOf(req request) (engineering.Operation, bool) {
	a := req.apdu
	if a == nil || !a.HasService || !a.Service.Confirmed {
		return engineering.Operation{}, false
	}
	var class engineering.Class
	switch a.Service.Choice {
	case wire.ReinitializeDevice:
		class = engineering.ClassRestart
	case wire.DeviceCommunicationControl:
		class = engineering.ClassModeChange
	case wire.AtomicWriteFile:
		class = engineering.ClassFileTransfer
	case wire.CreateObject, wire.DeleteObject:
		class = engineering.ClassConfiguration
	default:
		return engineering.Operation{}, false
	}
	op := engineering.Operation{Class: class, Detail: a.Service.Name()}
	if len(req.targets) > 0 && req.located {
		op.Point = req.targets[0].Object.String()
	}
	return op, true
}

// decideEngineering reports one engineering operation and says whether to carry
// the message.
func (t *server) decideEngineering(req request) string {
	if !t.engineering.On() {
		return ""
	}
	op, ok := engineeringOf(req)
	if !ok {
		return ""
	}
	subject := req.client.String()
	return t.engineering.Decide(op, subject, t.m.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(op engineering.Operation, grant *access.Grant) {
				t.reportEngineering(req.client, op, grant)
			},
			Ungranted: func(op engineering.Operation, reason string) {
				t.alertEngineering(req.client, reason, op)
			},
			Would: func(op engineering.Operation, reason string) {
				t.host.Counters().WouldRefuse("bacnet", reason)
				t.host.Shadow().Record("bacnet", t.name, reason, "engineering", op.String())
			},
			Refused: func(op engineering.Operation, reason string) {
				t.alertEngineering(req.client, reason, op)
			},
		})
}

func (t *server) reportEngineering(ip netip.Addr, op engineering.Operation, grant *access.Grant) {
	t.host.Counters().Engineering("bacnet", string(op.Class))
	t.host.ObserveFact(ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "bacnet", Listener: t.name,
		Detail: op.String(),
	})
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "bacnet",
		"class", string(op.Class), "operation", op.Detail}
	if op.Point != "" {
		attrs = append(attrs, "object", textsafe.Clip64(op.Point))
	}
	if grant != nil {
		attrs = append(attrs, "grant", grant.ID, "work_order", textsafe.Clip64(grant.Reason))
	}
	t.host.Logs().SecurityEvent(context.Background(), "engineering",
		engineering.Reason(op.Class), attrs...)
}

// alertEngineering is the event for an operation outside every approved window,
// refused or not. It does not reach the ban ladder: a building's own controllers
// are the clients here.
func (t *server) alertEngineering(ip netip.Addr, reason string, op engineering.Operation) {
	t.host.Counters().Refuse("bacnet", reason)
	if !t.alertOnDeny {
		return
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "bacnet_"+reason,
		"listener", t.name, "client_ip", ip.String(), "proto", "bacnet",
		"reason", reason, "class", string(op.Class),
		"operation", textsafe.Clip64(op.String()))
}
