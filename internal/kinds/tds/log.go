package tds

import (
	"context"
	"net/netip"

	wire "github.com/rom/xproxy/internal/tdswire"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a database.
//
// As on the other two database kinds: the statement *kind* and the procedure
// name, never the statement text. A WHERE clause names the row and an INSERT
// carries the value, and a security log is read by more people than the database
// is.
//
// Two records here have no equivalent on the sibling kinds. The forced
// encryption is one, and it is the line an operator needs before they turn
// require_tls on rather than after: it names every client whose negotiation the
// relay raised, which is the set that will break if any of them cannot do TLS.
// The connection reset is the other.

// refused records a decision the policy refused.
func (t *server) refused(se *session, d Decision, what string) {
	c := t.host.Counters()
	if !t.enforcing() && !d.Hard {
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up, and a listener in shadow mode
		// that reported refusals it had in fact forwarded would be the one way
		// to defeat that: an operator reading the refusal count of a listener
		// being trialled would see enforcement that is not happening.
		c.WouldRefuse("tds", d.Reason)
		t.host.Shadow().Record("tds", t.name, d.Reason, d.Rule, what)
		return
	}
	c.Refuse("tds", d.Reason)
	s := se.sess()
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "tds",
		"reason", d.Reason, "secure", s.Secure}
	if s.User != "" {
		attrs = append(attrs, "db_user", textsafe.Clip64(s.User))
	}
	if s.Integrated {
		attrs = append(attrs, "integrated", true)
	}
	if s.Database != "" {
		attrs = append(attrs, "database", textsafe.Clip64(s.Database))
	}
	if s.App != "" {
		attrs = append(attrs, "app", textsafe.Clip64(s.App))
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
	t.host.Logs().SecurityEvent(context.Background(), "deny", "tds_"+d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "tds_denied")
	}
}

// deny records a refusal that is not about something the policy read.
func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("tds", reason)
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "tds",
		"reason", reason}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "tds_"+reason, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "tds_denied")
	}
}

// forcedEncryption records that the relay answered a client's PRELOGIN with a
// stronger value than it asked for.
//
// alert rather than deny: nothing was refused and the connection went through.
// It is worth a line because it is the one event that predicts a breakage --
// every client listed here is one that would have gone in the clear, and one
// that will fail if it turns out not to speak TLS at all.
func (t *server) forcedEncryption(se *session, asked byte) {
	t.host.Logs().SecurityEvent(context.Background(), "alert", "tds_encryption_forced",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "tds",
		"asked", wire.EncryptName(asked), "answered", wire.EncryptName(wire.EncryptReq))
}

// connectionReset records a message that asked for the session to be reset,
// which is a connection pool handing a pooled connection to a different caller.
//
// alert rather than deny: it is a legitimate and common thing to do. It is
// recorded because the batches before and after it may have come from different
// parts of an application under one login, and a reader reconstructing what
// happened needs the boundary.
func (t *server) connectionReset(se *session, n int) {
	t.host.Logs().SecurityEvent(context.Background(), "alert", "tds_connection_reset",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "tds",
		"db_user", textsafe.Clip64(se.sess().User), "resets", n)
}
