package mms

import (
	"context"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on IEC 61850 MMS: what this client has been doing, and
// when it stops.
//
// The models are internal/anomaly, shared with every other OT kind. On this
// protocol the object names carry the semantics, so the translation is the
// richest of any kind here:
//
//	symbol   the service and, where the name is in the 61850 form, the
//	         functional constraint with it -- "Write $CF$" is a configuration
//	         change and "Write $CO$" moves a breaker, and a model that called
//	         both "Write" would have thrown away what the protocol says
//	device   the logical device (the domain) the request addressed
//	point    the object name, `AA1J1Q01A1LD0/XCBR1$CO$Pos$Oper`
//	value    nothing. A relay that turned an MMS data value into a number
//	         would have to guess at the type from the SCL this listener does
//	         not have, so the two value models are inert here and the other
//	         four carry the kind.
//
// Read replies are not run through the models at all, for the same reason.

// anomalyEvent translates one confirmed request.
func anomalyEvent(c *conn, m *wire.Message, ops []Operation, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: c.ip, Symbol: m.Service.String(), At: now}
	if len(ops) == 0 {
		return e
	}
	op := ops[0]
	e.Write = op.Write
	e.Point = op.Name.Key()
	e.Device = op.Name.Domain
	if op.Name.Parsed && op.Name.FC != "" {
		// The functional constraint is what a write *is* on this protocol, so
		// it belongs in the symbol rather than only in the point: a client that
		// has always written $SP$ setpoints and now writes $CF$ configuration
		// has changed what it does, not only where.
		e.Symbol += " " + string(op.Name.FC)
	}
	return e
}

// decideAnomaly runs the models over one request and returns the reason to
// refuse it, or "" to carry it.
func (t *server) decideAnomaly(c *conn, m *wire.Message, ops []Operation) string {
	if !t.anomaly.On() {
		return ""
	}
	what := describe(ops)
	return t.anomaly.Decide(anomalyEvent(c, m, ops, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(c, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("mms", f.Reason)
			t.host.Shadow().Record("mms", t.name, f.Reason, "anomaly", what)
		},
		// No counting here: alertAnomaly has already counted this finding, and
		// a refusal counted twice is a refusal an operator cannot count.
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding. It does not reach the ban ladder:
// the signal is novelty, and the first legitimate setting change of the year is
// novel too -- banning a control centre for it would take the substation's own
// supervision away over a detection about it.
func (t *server) alertAnomaly(c *conn, f anomaly.Finding) {
	t.host.Counters().Refuse("mms", f.Reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"reason", f.Reason, "model", string(f.Model)}
	if f.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(f.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "mms_"+f.Reason, a...)
}
