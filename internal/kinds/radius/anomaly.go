package radius

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on RADIUS: what each piece of equipment has been
// doing, and when it stops.
//
// The models are internal/anomaly, shared with every other kind. The
// translation here is:
//
//	symbol   the packet code and the method -- "access-request/eap",
//	         "accounting-request" -- so a NAS that has only ever done
//	         802.1X with PEAP and starts sending PAP is a finding
//	device   the NAS identifier, which is this protocol's nearest thing to
//	         a device name
//	point    the realm, which is where a credential is being sent
//	value    nothing: there is no number in a RADIUS request worth
//	         modelling, so the two value models are inert here
//
// The talkers model earns its keep: an estate's RADIUS clients are a list
// written once and changed by a change request, so a new address
// authenticating against the directory is worth a line in a log whatever
// the address lists say.

// anomalyEvent translates one request.
func anomalyEvent(req Request, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: req.Client, At: now, Symbol: req.Code.String()}
	if req.AuthType != "" {
		e.Symbol += "/" + string(req.AuthType)
	}
	e.Device = req.NASID
	e.Point = req.Realm
	return e
}

// decideAnomaly runs the models over one request and returns the reason to
// refuse it, or "" to carry it.
func (t *server) decideAnomaly(req Request) string {
	if !t.anomaly.On() {
		return ""
	}
	subject := req.Code.String()
	if req.User != "" {
		subject += " " + req.User
	}
	return t.anomaly.Decide(anomalyEvent(req, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(req.Client, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("radius", f.Reason)
			t.host.Shadow().Record("radius", t.name, f.Reason, "anomaly", subject)
		},
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding. It does not reach the ban
// ladder: the clients here are the estate's own switches and concentrators,
// and banning one over a method it had not used yet takes a building's
// network authentication away.
func (t *server) alertAnomaly(ip netip.Addr, f anomaly.Finding) {
	t.host.Counters().Refuse("radius", f.Reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "radius",
		"reason", f.Reason, "model", string(f.Model)}
	if f.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(f.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "radius_"+f.Reason, a...)
}
