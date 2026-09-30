package coap

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on CoAP: what this device or client has been doing, and
// when it stops.
//
// The models are internal/anomaly, shared with every other OT kind. On a
// constrained device's protocol the translation is short, because the protocol
// is:
//
//	symbol   the method -- GET, PUT, POST, DELETE
//	device   the security name the session mapped to, where there is one: on
//	         this protocol an address is the weakest identity there is, and a
//	         pre-shared key identity is the strongest
//	point    the path, `/3303/0/5700`, which on an LwM2M device *is* the object
//	         model
//	value    nothing. A CoAP payload is CBOR, SenML, plain text or a vendor's
//	         own encoding, and this relay does not decode it into numbers, so
//	         the two value models are inert here and the other four carry the
//	         kind.
//
// A write is PUT, POST or DELETE. Novelty about writes is keyed on the path
// itself rather than on a coarser block, because a path is already the unit an
// operator reads and there is no span for it to be part of.

// anomalyEvent translates one request.
func anomalyEvent(req request, now time.Time) anomaly.Event {
	e := anomaly.Event{
		Actor:  req.from,
		Device: req.identity,
		Symbol: req.msg.Code.String(),
		Point:  req.msg.Path(),
		At:     now,
	}
	switch req.msg.Code {
	case wire.PUT, wire.POST, wire.DELETE:
		e.Write = true
	}
	return e
}

// decideAnomaly runs the models over one request and returns the reason to
// refuse it, or "" to carry it.
func (s *server) decideAnomaly(req request) string {
	if !s.anomaly.On() {
		return ""
	}
	path := req.msg.Path()
	return s.anomaly.Decide(anomalyEvent(req, time.Now()), s.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { s.alertAnomaly(req.from, f) },
		Would: func(f anomaly.Finding) {
			s.host.Counters().WouldRefuse("coap", f.Reason)
			s.host.Shadow().Record("coap", s.cfg.Name, f.Reason, "anomaly", path)
		},
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding. It does not reach the ban ladder:
// on a protocol whose clients are sensors, a device that has been quiet for a
// year and wakes up is novel too.
func (s *server) alertAnomaly(ip netip.Addr, f anomaly.Finding) {
	s.host.Counters().Refuse("coap", f.Reason)
	if !s.alerts() {
		return
	}
	a := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "proto", "coap",
		"reason", f.Reason, "model", string(f.Model)}
	if f.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(f.Detail))
	}
	s.host.Logs().SecurityEvent(context.Background(), "alert", "coap_"+f.Reason, a...)
}
