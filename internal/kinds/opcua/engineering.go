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
// method it was, and let the work order say whether it was expected.

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
// requires a work order it has not got, answers the client. done says the caller
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
	// This protocol has a user, so a work order can name a person.
	subject := c.sess().User
	if subject == "" {
		subject = c.ip.String()
	}
	op.Subject = subject
	return t.engineering.Decide(op, subject, t.oc.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(op engineering.Operation, grant *access.Grant) {
				t.reportEngineering(c, op, grant)
			},
			Ungranted: func(op engineering.Operation, reason string) {
				t.alertEngineering(c, reason, op)
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

func (t *server) reportEngineering(c *conn, op engineering.Operation, grant *access.Grant) {
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
		a = append(a, "grant", grant.ID, "work_order", textsafe.Clip64(grant.Reason))
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
