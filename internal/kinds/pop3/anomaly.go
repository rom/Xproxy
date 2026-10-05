package pop3

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on POP3.
//
// The translation is:
//
//	actor    the client's address
//	symbol   the command, which on this protocol is a short list -- so the
//	         symbols model is mostly about a client that has only ever used
//	         UIDL, RETR and DELE suddenly using TOP across the mailbox
//	device   nothing: there is one mailbox, so there is nothing to name
//	point    the account name
//	value    the octets the retrieval carried, which is what makes the two
//	         value models worth having here: a client whose daily total has
//	         been a megabyte and is now four hundred is a finding before any
//	         configured bound is reached
//
// DELE and RSET are the writes.

// anomalyEvent translates one command.
func anomalyEvent(req Request, octets int64, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: req.Client, At: now, Point: req.User}
	if req.Command != nil {
		e.Symbol = req.Command.Name
		e.Write = req.Command.Writes()
	}
	if octets > 0 {
		e.Value, e.HasValue = float64(octets), true
	}
	return e
}

// decideAnomaly runs the models over one command and returns the reason to
// refuse it, or "" to carry it.
func (t *server) decideAnomaly(c *conn, req Request) string {
	if !t.anomaly.On() {
		return ""
	}
	subject := req.Command.Name
	if req.User != "" {
		subject += " (" + req.User + ")"
	}
	return t.anomaly.Decide(anomalyEvent(req, c.retrieved, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(c.ip, req, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("pop3", f.Reason)
			t.host.Shadow().Record("pop3", t.name, f.Reason, "anomaly", subject)
		},
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding. As on the imap kind it reaches
// the ban ladder: the clients are people's mail applications, and one whose
// behaviour has turned into mailbox collection is worth stopping.
func (t *server) alertAnomaly(ip netip.Addr, req Request, f anomaly.Finding) {
	t.host.Counters().Refuse("pop3", f.Reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "pop3",
			"reason", f.Reason, "model", string(f.Model)}
		if req.User != "" {
			a = append(a, "user", textsafe.Clip64(req.User))
		}
		if f.Detail != "" {
			a = append(a, "detail", textsafe.Clip64(f.Detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "alert", "pop3_"+f.Reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "pop3_anomaly")
	}
}
