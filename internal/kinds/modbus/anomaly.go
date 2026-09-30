package modbus

import (
	"fmt"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/modbus"
)

// Behavioural detection: what a master has been doing, and when it stops.
//
// The policy in policy.go answers "is this permitted", from rules somebody
// wrote down. This answers a different question -- "is this what this master
// has been doing" -- and answers it without anybody having written anything.
// On this protocol that is worth more than it would be almost anywhere else,
// because control traffic is repetitive in a way other traffic is not: a
// master's scan cycle is the same few function codes over the same few address
// ranges, every cycle, for years. "This client has never done this before" is a
// signal here where on a web front end it would be noise.
//
// The models themselves are internal/anomaly, shared with every other OT kind,
// because none of them is about Modbus. This file is the translation: what a
// symbol, a point and a value are on this protocol.
//
//	symbol   the function code's name -- "read holding registers", "write single coil"
//	point    unit and address, "unit 1 40100", which is what a value belongs to
//	block    unit and the written span, "unit 1 40100-40120", which is what
//	         novelty about writes is keyed on: a master writes the same spans
//	         every cycle, and keying on each address in a span would fill a
//	         bounded set with one recipe download
//	value    a written register, and -- because this relay decodes read replies
//	         -- the registers a device answered with, which is where "the process
//	         values look too clean" comes from
//
// # It alerts
//
// It does not refuse, unless somebody asks it to. A detector built on "I have not
// seen this before" refuses the first legitimate thing anybody does after a quiet
// year: the maintenance write, the commissioning of a new point, the operator who
// finally uses a function the master has always been allowed to use. So the
// default is a security event and a counter, `action: deny` exists because some
// plants want it, and the documentation says what it costs. The events do not
// reach the ban ladder either: banning a plant's master over a function code it
// had not used yet takes the process away from the control room, which is a worse
// outcome than the one being guarded against.

// event translates one request into the vocabulary the models share.
func anomalyEvent(req request, now time.Time) anomaly.Event {
	e := anomaly.Event{
		Actor:  req.client,
		Device: fmt.Sprintf("unit %d", req.unit),
		Symbol: wire.FunctionName(req.pdu.Function),
		At:     now,
	}
	base := int(req.pdu.Address)
	if req.pdu.Function == wire.FCReadWriteMultiple {
		base = int(req.pdu.WriteAddress)
	}
	e.Point = fmt.Sprintf("unit %d %d", req.unit, base)
	if lo, hi, ok := writeSpan(req.pdu); ok && hi >= 0 {
		e.Write = true
		e.Block = fmt.Sprintf("unit %d %s", req.unit, rangeText(lo, hi))
	}
	// A single register write is the one shape where the request carries a
	// value this relay can attribute to one point. A multi-register write is
	// a span, and a value history keyed on a span is a history of nothing;
	// the read replies below are where those points' values come from.
	if e.Write && len(req.pdu.Registers) == 1 {
		e.Value, e.HasValue = float64(req.pdu.Registers[0]), true
	}
	return e
}

// decideAnomaly runs the detector over one request and says whether to carry it.
//
// Every finding is alerted on, whatever the action, because an operator who set
// `action: deny` still wants the record and an operator who did not still wants
// the signal. Only the first finding refuses, and only when this listener is
// enforcing: in shadow mode or a learning run nothing is refused, which is the
// whole of what those modes mean.
func (t *server) decideAnomaly(se *session, frame *wire.Frame, pdu *wire.PDU, req request, enforcing bool) (string, bool) {
	if !t.anomaly.On() || req.pdu == nil {
		return "", true
	}
	reason := t.anomaly.Decide(anomalyEvent(req, time.Now()), enforcing, anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alert(se.ip, f.Reason, f.Detail) },
		Would: func(f anomaly.Finding) {
			// The detector would have refused. Saying so is what shadow mode is
			// for, and it goes in the same place the policy's would-be refusals
			// do so that one report answers "what would enforcing cost".
			t.host.Counters().ModbusWouldDeny.Add(1)
			t.host.Counters().WouldRefuse("modbus", f.Reason)
			t.host.Shadow().Record("modbus", t.cfg.Name, f.Reason, "anomaly",
				fmt.Sprintf("unit %d %s %s", frame.Unit, wire.FunctionName(pdu.Function), f.Detail))
		},
		Refused: func(f anomaly.Finding) {
			se.denied.Add(1)
			t.host.Counters().ModbusDenied.Add(1)
			t.audit(se, frame, pdu, Decision{Reason: f.Reason, Rule: "anomaly"}, "deny")
		},
	})
	return reason, reason == ""
}

// observeAnomalyReply records the values a device answered a read with.
//
// This is the half of the telemetry model a request cannot provide. A frozen or
// replayed *written* value says something about the master; a frozen or replayed
// *read* value says something about the plant, or about what the control room is
// being shown, which is the one this model is for.
func (t *server) observeAnomalyReply(se *session, req request, resp *wire.PDU, now time.Time) {
	if !t.anomaly.On() || req.pdu == nil || resp == nil || req.pdu.Writes() {
		return
	}
	base := int(req.pdu.Address)
	h := anomaly.Handler{Alert: func(f anomaly.Finding) { t.alert(se.ip, f.Reason, f.Detail) }}
	for i, v := range resp.Registers {
		t.anomaly.Values(anomaly.Event{
			Actor:    req.client,
			Device:   fmt.Sprintf("unit %d", req.unit),
			Point:    fmt.Sprintf("unit %d %d", req.unit, base+i),
			Value:    float64(v),
			HasValue: true,
			At:       now,
		}, h)
	}
}
