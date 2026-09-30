package opcua

import (
	"context"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/textsafe"
)

// Engineering on OPC UA, where one service runs something and the rest read and
// write:
//
//	Call                        a method the object model exposes   method_call
//	AddNodes, DeleteNodes       the address space itself            configuration
//	AddReferences, DeleteRefs   the same                            configuration
//	HistoryUpdate               the record of what the plant did    configuration
//	a write to access_level     who may do what, afterwards         configuration
//
// A Write to a variable's `value` is not engineering: that is an HMI moving a
// setpoint, which the node rules are for. A write to `access_level` is, because
// it changes what the *next* client may do -- which is the same kind of change
// as adding a node, and the reason the attribute is a policy field in the first
// place.
//
// Call is the one worth the most here. On this protocol a method is whatever the
// server's author decided -- "LoadRecipe", "Reset", "StartBatch" -- so a method
// call is an operation whose meaning this relay cannot read and whose
// consequences are the vendor's. The honest thing is to name it, record which
// method it was, and let the grant say whether it was expected.

// engineeringOf classifies one service call.
func engineeringOf(call *wire.ServiceCall, ops []Operation) (engineering.Operation, bool) {
	if call == nil {
		return engineering.Operation{}, false
	}
	out := engineering.Operation{Detail: call.Service.String()}
	switch call.Service {
	case wire.SvcCall:
		out.Class = engineering.ClassMethodCall
		if len(ops) > 0 && ops[0].Method != nil {
			out.Detail = "call " + ops[0].Method.Key
			out.Point = ops[0].Node.Key
		}
		return out, true
	case wire.SvcAddNodes, wire.SvcDeleteNodes, wire.SvcAddReferences,
		wire.SvcDeleteRefs, wire.SvcHistoryUpdate:
		out.Class = engineering.ClassConfiguration
		if len(ops) > 0 {
			out.Point = ops[0].Node.Key
		}
		return out, true
	case wire.SvcWrite:
		for _, op := range ops {
			if op.Write && op.Attr == wire.AttrAccessLevel {
				out.Class = engineering.ClassConfiguration
				out.Detail = "write access_level"
				out.Point = op.Node.Key
				return out, true
			}
		}
	}
	return engineering.Operation{}, false
}

// engineeringCheck reports one engineering operation and, where the listener
// requires a grant it has not got, answers the client. done says the caller
// should return the two values with it.
func (t *server) engineeringCheck(c *conn, m *wire.Assembled, call *wire.ServiceCall, ops []Operation) (forward, fatal, done bool) {
	reason := t.decideEngineering(c, call, ops)
	if reason == "" {
		return false, false, false
	}
	f, fa := t.respond(c, m, Decision{Reason: reason, Rule: "engineering",
		Status: wire.StatusBadUserAccessDenied})
	return f, fa, true
}

// decideEngineering reports one engineering operation and says whether to carry
// it.
func (t *server) decideEngineering(c *conn, call *wire.ServiceCall, ops []Operation) string {
	if !t.engineering.On() {
		return ""
	}
	op, ok := engineeringOf(call, ops)
	if !ok {
		return ""
	}
	// This protocol has a user, so a grant can name a person.
	subject := c.sess().User
	if subject == "" {
		subject = c.ip.String()
	}
	op.Subject = subject
	return t.engineering.Decide(op, subject, t.oc.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(op engineering.Operation, grant *access.Grant, order *access.WorkOrder) {
				t.reportEngineering(c, op, grant, order)
			},
			Ungranted: func(op engineering.Operation, reason string, order *access.WorkOrder) {
				t.engineeringOutside(c, reason, op, order)
			},
			Would: func(op engineering.Operation, reason string) {
				t.host.Counters().WouldRefuse("opcua", reason)
				t.host.Shadow().Record("opcua", t.name, reason, "engineering", op.String())
			},
			Refused: func(op engineering.Operation, reason string) {
				c.refusal()
				t.host.Counters().Refuse("opcua", reason)
				t.alertEngineering(c, reason, op)
			},
		})
}

func (t *server) reportEngineering(c *conn, op engineering.Operation, grant *access.Grant, order *access.WorkOrder) {
	t.host.Counters().Engineering("opcua", string(op.Class))
	t.host.ObserveFact(c.ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "opcua", Listener: t.name,
		Identity: op.Subject, Detail: op.String(),
	})
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"class", string(op.Class), "operation", textsafe.Clip64(op.Detail)}
	if op.Point != "" {
		a = append(a, "node", textsafe.Clip64(op.Point))
	}
	if op.Subject != "" {
		a = append(a, "user", op.Subject)
	}
	if grant != nil {
		a = append(a, "grant", grant.ID, "grant_reason", textsafe.Clip64(grant.Reason))
	}
	// The work order on file for the device, and the tone that follows
	// from it. A work order is not an approval and permits nothing: it
	// says somebody was expecting work here, which is why the event is a
	// notice rather than a warning.
	a = append(a, "severity", engineering.Severity(order))
	if order != nil {
		t.host.Counters().EngineeringFiled("opcua", string(op.Class))
		a = append(a, "work_order", order.Reference,
			"work_order_by", textsafe.Clip64(order.By))
	}
	t.host.Logs().SecurityEvent(context.Background(), "engineering",
		engineering.Reason(op.Class), a...)
}

// alertEngineering is the event for an operation outside every approved window.
// It does not reach the ban ladder.
func (t *server) alertEngineering(c *conn, reason string, op engineering.Operation) {
	t.host.Counters().Refuse("opcua", reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"reason", reason, "class", string(op.Class),
		"operation", textsafe.Clip64(op.String())}
	if op.Subject != "" {
		a = append(a, "user", op.Subject)
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "opcua_"+reason, a...)
}

// engineeringOutside records an operation that happened outside every approved
// window on a listener that does not require one.
//
// It counts EngineeringOutside rather than a refusal: the operation was
// carried. The event itself is unchanged -- same action, same reason -- so the
// behaviour packs and the ATT&CK mapping that read it are unaffected.
func (t *server) engineeringOutside(c *conn, reason string, op engineering.Operation, order *access.WorkOrder) {
	t.host.Counters().EngineeringOutside("opcua", string(op.Class), reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"reason", reason, "class", string(op.Class),
		"operation", textsafe.Clip64(op.String())}
	if op.Subject != "" {
		a = append(a, "user", op.Subject)
	}
	// The tone follows the work order, the same way the report's does: an
	// operation somebody filed is a notice, one nobody filed is a warning.
	// Both are events, because the listener carried the operation either way.
	a = append(a, "severity", engineering.Severity(order))
	if order != nil {
		a = append(a, "work_order", order.Reference,
			"work_order_by", textsafe.Clip64(order.By))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "opcua_"+reason, a...)
}
