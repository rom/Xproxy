package kkdcp

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/kerberos"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on a KDC proxy.
//
// The models are internal/anomaly, shared with every other kind. The
// translation is:
//
//	actor    the client's address
//	symbol   the message type and the encryption type it asked for --
//	         "tgs-req/rc4-hmac" -- so a client that has only ever asked for
//	         aes256 tickets and starts asking for RC4 is a finding on the
//	         symbols model whether or not the encryption rules refuse it
//	device   the realm, which on a proxy serving a trust is more than one
//	point    the service principal: the thing an estate's own question is
//	         about ("who asked for a ticket to the database last night")
//	value    nothing. There is no number in a Kerberos request worth
//	         modelling, so the two value models are inert here.
//
// The rate model is the one that earns its keep beside the explicit
// distinct-service bound: that bound counts different names, and this one
// counts requests, so a client asking for the *same* service ticket four
// hundred times in a minute trips the second and not the first.

// anomalyEvent translates one request.
func anomalyEvent(req Request, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: req.Client, At: now, Symbol: req.Type.String()}
	if len(req.ETypes) > 0 {
		e.Symbol += "/" + req.ETypes[0].String()
	}
	e.Device = req.Realm
	e.Point = req.Service
	if e.Point == "" {
		e.Point = req.Principal
	}
	// A request that asks the KDC to issue something a service will act on is
	// the write-like half of this protocol: a TGS request for a service, and
	// a password change.
	e.Write = req.Type == wire.MsgTGSReq || req.Type == wire.MsgAPReq
	return e
}

// decideAnomaly runs the models over one request and returns the reason to
// refuse it, or "" to carry it.
func (t *server) decideAnomaly(req Request) string {
	if !t.anomaly.On() {
		return ""
	}
	subject := req.Type.String()
	if req.Service != "" {
		subject += " " + req.Service
	} else if req.Principal != "" {
		subject += " " + req.Principal
	}
	return t.anomaly.Decide(anomalyEvent(req, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(req.Client, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("kkdcp", f.Reason)
			t.host.Shadow().Record("kkdcp", t.name, f.Reason, "anomaly", subject)
		},
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding, and this is the one kind here
// where it reaches the ban ladder: the clients are not the estate's own
// equipment but whatever on the internet found the endpoint, and an address
// enumerating service tickets has nothing to lose by being banned.
func (t *server) alertAnomaly(ip netip.Addr, f anomaly.Finding) {
	t.host.Counters().Refuse("kkdcp", f.Reason)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "kkdcp_denied")
	}
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "kkdcp",
		"reason", f.Reason, "model", string(f.Model)}
	if f.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(f.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "kkdcp_"+f.Reason, a...)
}
