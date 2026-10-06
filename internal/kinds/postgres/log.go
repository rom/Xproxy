package postgres

import (
	"context"
	"strings"

	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a database.
//
// What is in them: which client, as which role, to which database, with which
// application name, over an encrypted connection or not, which statement *kind*
// and which leading keyword.
//
// What is deliberately not in them: the statement text. A log that carried
// statements would carry the contents of somebody's database -- a WHERE clause
// names the row, an INSERT carries the value -- and a security log is read by
// more people than the database is. The kind and the verb are what a policy
// decided on and what an operator needs to argue with the decision; the text is
// the data. The one exception is the leading keyword of a statement the
// classifier could not read, because "something unreadable was refused" with no
// hint of what is a line nobody can act on -- and it goes through textsafe,
// since a verb that came off the network is a verb that can contain an escape
// sequence.

// refused records a statement or a connection the policy refused.
func (t *server) refused(se *session, d Decision, what string) {
	if !t.enforcing() && !d.Hard {
		t.wouldRefuse(se, d, what)
		return
	}
	se.tap.Deny(d.Reason)
	c := t.host.Counters()
	c.Refuse("postgres", d.Reason)
	t.log(se, d, what, "deny")
	if !t.alerts() {
		return
	}
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "postgres",
		"reason", d.Reason, "secure", se.secure}
	if se.user != "" {
		attrs = append(attrs, "db_user", textsafe.Clip64(se.user))
	}
	if se.database != "" {
		attrs = append(attrs, "database", textsafe.Clip64(se.database))
	}
	if se.app != "" {
		attrs = append(attrs, "application", textsafe.Clip64(se.app))
	}
	if what != "" {
		attrs = append(attrs, "statement_kind", textsafe.Clip64(what))
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
	t.host.Logs().SecurityEvent(context.Background(), "deny", "postgres_"+d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "postgres_denied")
	}
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
func (t *server) wouldRefuse(se *session, d Decision, what string) {
	t.host.Counters().WouldRefuse("postgres", d.Reason)
	t.host.Shadow().Record("postgres", t.name, d.Reason, d.Rule, what)
	t.log(se, d, what, "would_deny")
}

// deny records a refusal that is not about a statement the policy read: a
// client that may not connect, a message the reader could not frame, a bound.
// None of these is ever shadowed, because each means the relay does not know
// what it would be forwarding.
func (t *server) deny(se *session, reason, detail string) {
	ip := se.ip
	se.tap.Deny(reason)
	c := t.host.Counters()
	c.Refuse("postgres", reason)
	if !t.alerts() {
		return
	}
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "postgres",
		"reason", reason}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "postgres_"+reason, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "postgres_denied")
	}
}

// log writes the access record.
func (t *server) log(se *session, d Decision, what, action string) {
	attrs := []any{"listener", t.name, "proto", "postgres",
		"client_ip", se.ip.String(), "secure", se.secure,
		"db_user", textsafe.Clip64(se.user), "database", textsafe.Clip64(se.database),
		"action", action}
	if se.app != "" {
		attrs = append(attrs, "application", textsafe.Clip64(se.app))
	}
	if what != "" {
		attrs = append(attrs, "statement", textsafe.Clip64(what))
	}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
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
	t.host.Logs().Access.Info("postgres", argsOf(attrs)...)
}

func argsOf(a []any) []any { return a }
