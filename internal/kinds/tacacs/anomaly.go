package tacacs

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on TACACS+, where the models have more to work with
// than on any other kind in this project: there is a named user, a named
// device and a command.
//
// The translation is:
//
//	actor    the device's address
//	symbol   the command, or the exchange where there is no command -- so a
//	         user who has only ever run `show ...` and suddenly runs
//	         `configure terminal` is a finding on the symbols model
//	device   the port and remote address the session came in on, which is
//	         how a login from a console differs from one over the network
//	point    the user name: the thing an estate's own question is about
//	         ("who logged in to the core routers last night")
//	value    nothing. There is no number in a device administration command
//	         worth modelling, so the two value models are inert here.
//
// The sequences model earns its keep: device administration has a shape --
// log in, `enable`, look, change, save -- and a session that does those in a
// different order, or skips the looking, is worth a line.

// anomalyEvent translates one request.
func anomalyEvent(req Request, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: req.Client, At: now, Symbol: req.Exchange.String()}
	if req.Command != "" {
		e.Symbol = req.Command
		// A command is a change when it is not a show: the models' Write
		// flag is what makes the write-rate model mean anything here, and
		// "not a show" is the only honest reading a relay has without a
		// per-platform command table.
		e.Write = !isRead(req.Command)
	}
	e.Device = req.Port
	if req.RemAddr != "" {
		e.Device += "@" + req.RemAddr
	}
	e.Point = req.User
	return e
}

// isRead reports whether a command only looks.
//
// It is a judgement and it is deliberately narrow: the four verbs every
// platform spells the same way. Anything else counts as a change, which is
// the safe direction -- a relay that guessed a vendor's read-only command
// wrongly would be under-counting changes, and the models would learn that a
// change is ordinary.
func isRead(cmd string) bool {
	switch firstWord(cmd) {
	case "show", "display", "dir", "more":
		return true
	}
	return false
}

func firstWord(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return s[:i]
		}
	}
	return s
}

// decideAnomaly runs the models over one request and returns the reason to
// refuse it, or "" to carry it.
func (t *server) decideAnomaly(req Request) string {
	if !t.anomaly.On() {
		return ""
	}
	subject := req.Exchange.String()
	if req.Command != "" {
		subject = req.Command
	}
	if req.User != "" {
		subject += " (" + req.User + ")"
	}
	return t.anomaly.Decide(anomalyEvent(req, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(req.Client, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("tacacs", f.Reason)
			t.host.Shadow().Record("tacacs", t.name, f.Reason, "anomaly", subject)
		},
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding. It does not reach the ban
// ladder: the clients here are the estate's own routers and switches, and
// banning one takes administrative access to it away from whoever is trying
// to fix it.
func (t *server) alertAnomaly(ip netip.Addr, f anomaly.Finding) {
	t.host.Counters().Refuse("tacacs", f.Reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "tacacs",
		"reason", f.Reason, "model", string(f.Model)}
	if f.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(f.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "tacacs_"+f.Reason, a...)
}
