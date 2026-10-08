package mysql

import (
	"context"
	"strings"

	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a database.
//
// As on the postgres kind: the statement *kind* and the command name, never the
// statement text. A WHERE clause names the row and an INSERT carries the value,
// and a security log is read by more people than the database is.
//
// One record here has no equivalent on the other kinds: the capability strip. It
// is not a refusal -- nothing was denied and the connection went through -- so it
// is an `alert` rather than a `deny`, and it is worth a line because an operator
// debugging "why does LOAD DATA LOCAL not work any more" needs to find it.

// refused records a decision the policy refused.
func (t *server) refused(se *session, d Decision, what string) {
	if !t.enforcing() && !d.Hard {
		t.wouldRefuse(d, what)
		return
	}
	se.tap.Deny(d.Reason)
	c := t.host.Counters()
	c.Refuse("mysql", d.Reason)
	t.logOp(se, what, "deny")
	// The ban ladder hears about this before alert_on_deny can silence the
	// record below: turning the log down is not a decision to stop responding.
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "mysql_denied")
	}

	if !t.alerts() {
		return
	}
	s := se.sess()
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "mysql",
		"reason", d.Reason, "secure", s.Secure}
	if s.User != "" {
		attrs = append(attrs, "db_user", textsafe.Clip64(s.User))
	}
	if s.Database != "" {
		attrs = append(attrs, "database", textsafe.Clip64(s.Database))
	}
	if s.Program != "" {
		attrs = append(attrs, "program", textsafe.Clip64(s.Program))
	}
	if what != "" {
		attrs = append(attrs, "what", textsafe.Clip64(what))
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if len(d.Observed) > 0 {
		// The rules being tried on live traffic. They decided nothing -- the
		// rule above did, or the default -- and this is where an operator reads
		// what one of them would have covered.
		attrs = append(attrs, "observed", strings.Join(d.Observed, ","))
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(d.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "mysql_"+d.Reason, attrs...)
}

// wouldRefuse records a decision that is not being enforced, for a caller that
// has already decided it is not enforcing it: the listener's monitor mode above,
// or the estate's authorisation policy, which has a shadow switch of its own and
// must leave the same record on a listener that enforces.
//
// Counted only as a would-be refusal. The two tables are kept apart so that a
// status view cannot add them up, and a listener in shadow mode that reported
// refusals it had in fact forwarded would be the one way to defeat that: an
// operator reading the refusal count of a listener being trialled would see
// enforcement that is not happening.
func (t *server) wouldRefuse(d Decision, what string) {
	t.host.Counters().WouldRefuse("mysql", d.Reason)
	t.host.Shadow().Record("mysql", t.name, d.Reason, d.Rule, what)
}

// deny records a refusal that is not about something the policy read.
func (t *server) deny(se *session, reason, detail string) {
	ip := se.ip
	se.tap.Deny(reason)
	t.host.Counters().Refuse("mysql", reason)
	// The ban ladder hears about this before alert_on_deny can silence the
	// record below: turning the log down is not a decision to stop responding.
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "mysql_denied")
	}

	if !t.alerts() {
		return
	}
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "mysql",
		"reason", reason}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "mysql_"+reason, attrs...)
}

// overriddenCaps records that the client claimed a capability the greeting no
// longer offered, and that the relay cleared it from the login too.
//
// A separate line from strippedCaps, and a louder one, because the two mean
// different things: stripping is the relay editing an offer, while this is a
// client overriding the edit. No driver does that by accident -- it means
// something on the segment built its own handshake response -- so it reads as a
// deny-level event even though the connection is allowed to continue with the
// capability off.
func (t *server) overriddenCaps(se *session, cleared uint32) {
	// The ban ladder hears about this before alert_on_deny can silence the
	// record below: turning the log down is not a decision to stop responding.
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "mysql_capabilities_overridden")
	}

	if !t.alerts() {
		return
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "mysql_capabilities_overridden",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "mysql",
		"capabilities", strings.Join(wire.CapList(cleared), ","))
}

// strippedCaps records that the relay narrowed the server's greeting.
//
// alert rather than deny: nothing was refused, the connection went through, and
// the client simply never saw a capability offered. An operator looking for why
// LOAD DATA LOCAL stopped working finds this line.
func (t *server) strippedCaps(se *session, cleared uint32) {
	t.host.Logs().SecurityEvent(context.Background(), "alert", "mysql_capabilities_stripped",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "mysql",
		"capabilities", strings.Join(wire.CapList(cleared), ","))
}

// alerts says whether a refusal on this listener is worth a security event.
//
// The counters, the access line and the ban observation do not go through here:
// this is the record alone, which is what alert_on_deny is named for.
func (t *server) alerts() bool { return t.mc.AlertOnDeny == nil || *t.mc.AlertOnDeny }

// logOp writes the access line for one command or statement.
//
// A refusal is written either way -- it is rare, and it is the one line nobody
// would choose to lose -- and what was forwarded only when log_requests asks,
// because a busy database is a great many lines a second. Without it this relay's
// only record is of what it refused, which answers "what did we stop" and not
// "what did they run".
//
// It carries the command name or the statement kind and never the statement text,
// for the reason the refusal record gives above: the kind is what the policy
// decided about, and the text is the data.
func (t *server) logOp(se *session, what, action string) {
	if action == "allow" && !t.mc.LogRequests {
		return
	}
	s := se.sess()
	attrs := []any{"listener", t.name, "proto", "mysql", "client_ip", se.ip.String(),
		"secure", s.Secure, "action", action}
	if what != "" {
		attrs = append(attrs, "what", textsafe.Clip64(what))
	}
	if s.User != "" {
		attrs = append(attrs, "db_user", textsafe.Clip64(s.User))
	}
	if s.Database != "" {
		attrs = append(attrs, "database", textsafe.Clip64(s.Database))
	}
	if s.Program != "" {
		attrs = append(attrs, "program", textsafe.Clip64(s.Program))
	}
	t.host.Logs().Access.Info("mysql", attrs...)
}
