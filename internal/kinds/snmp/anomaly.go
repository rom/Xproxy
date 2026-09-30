package snmp

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on SNMP: what this manager has been doing, and when it
// stops.
//
// The models are internal/anomaly, shared with every other OT kind. The
// translation here:
//
//	symbol   the PDU type -- "get", "get-next", "get-bulk", "set", "trap"
//	device   the credential the message carried: the community string for v1
//	         and v2c, the USM user for v3, the security name for the transport
//	         model. On this protocol the credential is what a poller *is*, and
//	         it is a better grouping than its address
//	point    the first binding's object identifier
//	value    nothing. A value's tag is read and not interpreted -- a policy
//	         about SNMP values would need a MIB per estate -- so the two value
//	         models are inert here and the other four carry the kind.
//
// A write is a SET, which on network and field equipment is a configuration
// change. The novelty model's write-point signal is therefore "this manager has
// never set that object", which is one of the more useful things a relay can say
// about an estate that manages its switches over SNMP.

// anomalyEvent translates one request.
func anomalyEvent(req request, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: req.client, At: now}
	m := req.msg
	if m == nil {
		return e
	}
	if c := req.credential(); c != "" {
		e.Device = c
	} else if req.name != "" {
		e.Device = req.name
	}
	if m.PDU == nil {
		return e
	}
	e.Symbol = m.PDU.Type.String()
	e.Write = m.PDU.Type.Writes()
	if len(m.PDU.VarBinds) > 0 {
		e.Point = m.PDU.VarBinds[0].OID.String()
	}
	return e
}

// decideAnomaly runs the models over one request and returns the reason to
// refuse it, or "" to carry it.
func (t *server) decideAnomaly(req request) string {
	if !t.anomaly.On() {
		return ""
	}
	detail := ""
	if req.msg != nil && req.msg.PDU != nil {
		detail = req.msg.PDU.Type.String()
	}
	return t.anomaly.Decide(anomalyEvent(req, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(req.client, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("snmp", f.Reason)
			t.host.Shadow().Record("snmp", t.cfg.Name, f.Reason, "anomaly", detail)
		},
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding. It does not reach the ban ladder:
// the estate's own network management station is the client here.
func (t *server) alertAnomaly(ip netip.Addr, f anomaly.Finding) {
	t.host.Counters().Refuse("snmp", f.Reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "snmp",
		"reason", f.Reason, "model", string(f.Model)}
	if f.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(f.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "snmp_"+f.Reason, a...)
}
