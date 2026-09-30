package iec104

import (
	"fmt"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/iec104"
)

// Behavioural detection on IEC 60870-5-104: what this controlling station has
// been doing, and when it stops.
//
// The models are internal/anomaly, shared with every other OT kind. What is
// specific to this protocol is the translation, and on a control centre's own
// protocol it is unusually direct:
//
//	symbol   the type identification -- "C_SC_NA_1", "M_ME_NC_1" -- which is
//	         exactly "what kind of thing was asked for"
//	device   the common address, which is the substation
//	point    common address and information object address, "station 1 4321"
//	value    a setpoint a control centre commanded, and every measured value a
//	         station reported, because this relay decodes the information
//	         elements in both directions already
//
// The rhythm is worth more here than almost anywhere else. A control centre
// polls a substation on a general interrogation cycle that does not change from
// one year to the next, and the telemetry a station sends back is a background
// rate. Both go through the models unchanged.
//
// Telemetry never refuses. A finding about a *reported* value is a finding
// about the substation's answer: by the time it has arrived there is nothing
// left to refuse, and refusing telemetry would take the control room's view
// away over a detection about that view.

// anomalyEvent translates one client ASDU into the models' terms.
func anomalyEvent(a *wire.ASDU, raw []byte, se *session, now time.Time) anomaly.Event {
	e := anomaly.Event{
		Actor:  se.ip,
		Device: fmt.Sprintf("station %d", a.Common),
		Symbol: a.Type.String(),
		At:     now,
	}
	// A command is a write; an interrogation or a read is not. The cause of
	// transmission is what says which, because the same type identification
	// carries a command and its confirmation.
	e.Write = (a.Type.Command() || a.Type.System()) && a.Cause.Commanding()
	els := a.Elements(raw)
	if len(els) > 0 {
		e.Point = fmt.Sprintf("station %d %d", a.Common, els[0].Address)
		if els[0].HasValue {
			e.Value, e.HasValue = els[0].Value, true
		}
	}
	if v, ok := a.Setpoint(); ok {
		e.Value, e.HasValue = v, true
	}
	return e
}

// decideAnomaly runs the models over one frame and says whether to carry it.
//
// A frame from the station runs only the two value models, through Values: a
// station's answer is not something the controlling station did, and counting it
// as a request would teach the cycle model a rhythm that is the sum of the
// commands and the telemetry.
func (se *session) decideAnomaly(frame *wire.Frame, fromClient bool) (string, bool) {
	t := se.t
	a := frame.ASDU
	if !t.anomaly.On() || a == nil {
		return "", true
	}
	now := time.Now()
	raw := frame.Raw[wire.APCILen:]
	h := anomaly.Handler{Alert: func(f anomaly.Finding) { t.alert(se.ip, f.Reason, f.Detail) }}
	if !fromClient {
		for _, el := range a.Elements(raw) {
			if !el.HasValue {
				continue
			}
			t.anomaly.Values(anomaly.Event{
				Actor:    se.ip,
				Device:   fmt.Sprintf("station %d", a.Common),
				Point:    fmt.Sprintf("station %d %d", a.Common, el.Address),
				Value:    el.Value,
				HasValue: true,
				At:       now,
			}, h)
		}
		return "", true
	}
	h.Would = func(f anomaly.Finding) {
		t.host.Counters().IEC104WouldDeny.Add(1)
		t.host.Counters().WouldRefuse("iec104", f.Reason)
		t.shadowed(f.Reason, "anomaly", a)
	}
	h.Refused = func(f anomaly.Finding) {
		t.host.Counters().IEC104Denied.Add(1)
		se.denied.Add(1)
	}
	if reason := t.anomaly.Decide(anomalyEvent(a, raw, se, now), t.enforcing(), h); reason != "" {
		return "iec104_" + reason, false
	}
	return "", true
}
