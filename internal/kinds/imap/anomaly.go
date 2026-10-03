package imap

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/imap"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behavioural detection on IMAP, where the models have a question worth
// asking that no list can answer: this account has read its mail the same
// way every day for a year, and today it read all of it.
//
// The translation is:
//
//	actor    the client's address
//	symbol   the command, so an account that has only ever used FETCH,
//	         SELECT and IDLE and suddenly runs SEARCH across every mailbox
//	         is a finding on the symbols model
//	device   the mailbox, which is what a client's working set looks like:
//	         a mail client touches INBOX, Sent and a few folders, and a
//	         collection script touches all of them
//	point    the account name, which is what the estate's own question is
//	         about ("what did that mailbox do last night")
//	value    the number of messages the request named, which makes the two
//	         value models mean something here: the rate of change model
//	         sees a client's fetch volume, and a request for forty thousand
//	         messages from an account whose largest has been twelve is a
//	         finding before any bound is reached
//
// The write-rate model reads APPEND, COPY, MOVE and STORE as writes, which
// is how a mailbox being emptied into another one shows up.

// anomalyEvent translates one command.
func anomalyEvent(req Request, now time.Time) anomaly.Event {
	e := anomaly.Event{Actor: req.Client, At: now, Point: req.User}
	if req.Command != nil {
		e.Symbol = req.Command.Effective()
		e.Write = wire.Writes(req.Command)
	}
	if len(req.Mailboxes) > 0 {
		e.Device = req.Mailboxes[0]
	}
	if req.Messages > 0 {
		e.Value, e.HasValue = float64(req.Messages), true
	}
	return e
}

// decideAnomaly runs the models over one command and returns the reason to
// refuse it, or "" to carry it.
func (t *server) decideAnomaly(c *conn, req Request) string {
	if !t.anomaly.On() {
		return ""
	}
	subject := "imap"
	if req.Command != nil {
		subject = req.Command.Effective()
	}
	if req.User != "" {
		subject += " (" + req.User + ")"
	}
	return t.anomaly.Decide(anomalyEvent(req, time.Now()), t.enforcing(), anomaly.Handler{
		Alert: func(f anomaly.Finding) { t.alertAnomaly(c.ip, req, f) },
		Would: func(f anomaly.Finding) {
			t.host.Counters().WouldRefuse("imap", f.Reason)
			t.host.Shadow().Record("imap", t.name, f.Reason, "anomaly", subject)
		},
		Refused: func(anomaly.Finding) {},
	})
}

// alertAnomaly records a behavioural finding.
//
// Unlike the TACACS+ kind's, this one reaches the ban ladder. The clients
// here are people's mail applications rather than the estate's own routers,
// and a client whose behaviour has just changed into mailbox collection is
// one an estate wants stopped rather than noted -- the cost of being wrong
// is a mail client that reconnects, not an engineer locked out of a switch.
func (t *server) alertAnomaly(ip netip.Addr, req Request, f anomaly.Finding) {
	t.host.Counters().Refuse("imap", f.Reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "imap",
			"reason", f.Reason, "model", string(f.Model)}
		if req.User != "" {
			a = append(a, "user", textsafe.Clip64(req.User))
		}
		if f.Detail != "" {
			a = append(a, "detail", textsafe.Clip64(f.Detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "alert", "imap_"+f.Reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "imap_anomaly")
	}
}
