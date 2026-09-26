package mysql

import (
	"context"
	"net/netip"
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
	c := t.host.Counters()
	if !t.enforcing() && !d.Hard {
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up, and a listener in shadow mode
		// that reported refusals it had in fact forwarded would be the one way
		// to defeat that: an operator reading the refusal count of a listener
		// being trialled would see enforcement that is not happening.
		c.WouldRefuse("mysql", d.Reason)
		t.host.Shadow().Record("mysql", t.name, d.Reason, d.Rule, what)
		return
	}
	c.Refuse("mysql", d.Reason)
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
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(d.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "mysql_"+d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "mysql_denied")
	}
}

// deny records a refusal that is not about something the policy read.
func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("mysql", reason)
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "mysql",
		"reason", reason}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "mysql_"+reason, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "mysql_denied")
	}
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
