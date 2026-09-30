package opcua

import (
	"context"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on OPC UA: what this client has been doing, and when it
// stops.
//
// The models are internal/anomaly, shared with every other OT kind. The
// translation here:
//
//	symbol   the service -- "Read", "Write", "Call", "Browse" -- and, for a
//	         Call, the method with it, because "Call" says almost nothing and
//	         "Call ns=2;s=Recipe.Load" says what happened
//	device   the session's user, where the listener established one: on the one
//	         industrial protocol that brought its own identity, the identity is
//	         the more useful grouping than an address
//	point    the node identifier, `ns=2;s=Line1.Setpoint`
//	value    nothing. This relay reads a Write's nodes and attributes, not the
//	         variant a value arrives as -- an OPC UA value is typed data whose
//	         type is in the server's address space -- so the two value models
//	         are inert here and the other four carry the kind.

// anomalyEvent translates one service call.
func anomalyEvent(c *conn, call *wire.ServiceCall, ops []Operation, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: c.ip, Symbol: call.Service.String(), At: now}
	if s := c.sess(); s.User != "" {
		e.Device = s.User
	}
	if len(ops) == 0 {
		return e
	}
	op := ops[0]
	e.Write = op.Write
	e.Point = op.Node.Key
	if op.Method != nil {
		// A method call is what the object model exposes for the purpose, and
		// which one it is matters more than that a Call happened at all.
		e.Symbol += " " + op.Method.Key
	}
	return e
}

// anomalyCheck runs the models over one service call. done says the caller
// should return the two values with it: the models refused the call, the client
// has been answered, and nothing more is to be decided about it.
func (t *server) anomalyCheck(c *conn, m *wire.Assembled, call *wire.ServiceCall, ops []Operation) (forward, fatal, done bool) {
	if !t.anomaly.On() {
		return false, false, false
	}
	what := call.Service.String()
	reason := t.anomaly.Decide(anomalyEvent(c, call, ops, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(c, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("opcua", f.Reason)
			t.host.Shadow().Record("opcua", t.name, f.Reason, "anomaly", what)
		},
		Refused: func(anomaly.Finding) { c.refusal() },
	})
	if reason == "" {
		return false, false, false
	}
	f, fa := t.respond(c, m, Decision{Reason: reason, Rule: "anomaly",
		Status: wire.StatusBadUserAccessDenied})
	return f, fa, true
}

// alertAnomaly records a behavioural finding. It does not reach the ban ladder:
// the signal is novelty, and the first legitimate recipe change of the year is
// novel too.
func (t *server) alertAnomaly(c *conn, f anomaly.Finding) {
	t.host.Counters().Refuse("opcua", f.Reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"reason", f.Reason, "model", string(f.Model)}
	if f.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(f.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "opcua_"+f.Reason, a...)
}
