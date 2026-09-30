package bacnet

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on BACnet/IP: what this client has been doing, and when
// it stops.
//
// The models are internal/anomaly, shared with every other OT kind. On a
// building's protocol, which has no user and no session, the translation is:
//
//	symbol   the confirmed service -- "ReadProperty", "WriteProperty",
//	         "ReinitializeDevice" -- or the virtual link function for a message
//	         with no application layer
//	device   the object instance the request addressed, which on this protocol
//	         is the nearest thing to a device identity there is
//	point    the object and property, `analog-output,3.present-value`
//	value    nothing. A property value is tagged data whose type is the
//	         object's, and this relay does not decode it into a number, so the
//	         two value models are inert here and the other four carry the kind.
//
// The talkers model is worth more here than on almost any other kind: a
// building's device list is written once at commissioning and does not change
// for a decade, so a new address on the segment is a fact worth a line in a log.

// anomalyEvent translates one request.
func anomalyEvent(req request, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: req.client, At: now}
	a := req.apdu
	if a == nil || !a.HasService {
		e.Symbol = req.fn.String()
		return e
	}
	e.Symbol = a.Service.Name()
	e.Write = a.Service.Writes()
	if len(req.targets) == 0 || !req.located {
		return e
	}
	tg := req.targets[0]
	e.Device = tg.Object.String()
	e.Point = tg.Object.String()
	if tg.HasProperty {
		e.Point += "." + tg.Property.String()
	}
	return e
}

// decideAnomaly runs the models over one request and returns the reason to
// refuse it, or "" to carry it.
func (t *server) decideAnomaly(req request) string {
	if !t.anomaly.On() {
		return ""
	}
	subject := what(req.apdu, req.targets)
	return t.anomaly.Decide(anomalyEvent(req, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(req.client, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("bacnet", f.Reason)
			t.host.Shadow().Record("bacnet", t.name, f.Reason, "anomaly", subject)
		},
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding. It does not reach the ban ladder:
// a building's controllers are the clients here, and banning one over a service
// it had not used yet takes the plant away from whoever is on site.
func (t *server) alertAnomaly(ip netip.Addr, f anomaly.Finding) {
	t.host.Counters().Refuse("bacnet", f.Reason)
	if !t.alertOnDeny {
		return
	}
	a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "bacnet",
		"reason", f.Reason, "model", string(f.Model)}
	if f.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(f.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "bacnet_"+f.Reason, a...)
}
