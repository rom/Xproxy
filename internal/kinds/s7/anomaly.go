package s7

import (
	"fmt"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/s7"
)

// Behavioural detection on S7comm: what this engineering station or HMI has
// been doing, and when it stops.
//
// The models are internal/anomaly, shared with every other OT kind. The
// translation on this protocol:
//
//	symbol   the operation -- "read variable", "download block", "userdata
//	         cpu functions" -- which on S7comm is also the engineering workflow
//	device   the rack and slot the session addressed, because one connection
//	         reaches one CPU
//	block    the area and data block a write touched, "DB 12 byte 100-119",
//	         which is what novelty about writes is keyed on: a station writes
//	         the same ranges every cycle
//	point    area, block and byte, "DB 12 byte 100"
//	value    nothing yet. This relay does not decode a controller's answer
//	         into numbers -- an S7 item is octets whose meaning is in the
//	         engineering project, not on the wire -- so the telemetry and
//	         correlation models have nothing to compare here and the other
//	         four carry the kind. Saying so is better than feeding them the
//	         first two octets of something and calling it a value.
//
// There is no protocol refusal for S7comm-plus (see plusRefusal), so a
// behavioural finding on a plus PDU alerts and the request goes on: the
// alternative is a silent drop for something that is, by construction, a
// guess about novelty.

// anomalyEvent translates one classic S7 request.
func anomalyEvent(se *session, pdu *wire.PDU, now time.Time) anomaly.Event {
	s := se.sess()
	e := anomaly.Event{
		Actor:  se.ip,
		Symbol: describe(pdu),
		At:     now,
	}
	if s.Addressed {
		e.Device = fmt.Sprintf("rack %d slot %d", s.Rack, s.Slot)
	}
	items, ok := pdu.Items()
	if !ok || len(items) == 0 {
		return e
	}
	it := items[0]
	if !it.Address {
		return e
	}
	e.Write = pdu.HasFunction && pdu.Function == wire.FnWriteVar
	area := wire.AreaName(it.Area)
	byteAddr := it.Bit / 8
	if it.DB != 0 {
		e.Point = fmt.Sprintf("%s %d byte %d", area, it.DB, byteAddr)
	} else {
		e.Point = fmt.Sprintf("%s byte %d", area, byteAddr)
	}
	if e.Write {
		// The whole span, so that a station writing the same range every
		// cycle is one point rather than one per byte.
		last := byteAddr
		if it.Count > 0 {
			last = byteAddr + uint32(it.Count) - 1
		}
		e.Block = fmt.Sprintf("%s-%d", e.Point, last)
	}
	return e
}

// decideAnomaly runs the models over one request and returns the reason to
// refuse it, or "" to carry it. The recording -- the alert, the counter, the
// shadow ledger -- happens here, so the caller only has to answer the client.
func (t *server) decideAnomaly(se *session, pdu *wire.PDU) string {
	if !t.anomaly.On() || pdu == nil {
		return ""
	}
	what := describe(pdu)
	return t.anomaly.Decide(anomalyEvent(se, pdu, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alert(se.ip, f.Reason, f.Detail) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("s7", f.Reason)
			t.host.Shadow().Record("s7", t.name, f.Reason, "anomaly", what)
		},
		Refused: func(anomaly.Finding) { se.refusal() },
	})
}
