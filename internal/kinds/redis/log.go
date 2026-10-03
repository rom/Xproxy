package redis

import (
	"context"
	"net/netip"
	"strings"

	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a cache.
//
// The command name and the key, never the value. On this protocol that line is
// sharper than on the SQL ones: a Redis value is whatever an application put
// there, which on a cache is session tokens, password reset codes and personal
// data, and a relay that logged arguments would be the largest disclosure in the
// estate. The key is logged because a key prefix policy is decided on it and a
// refusal nobody can attribute to a key is a refusal nobody can act on.
//
// The unauthenticated command has a record of its own because it is the one that
// says an instance was reachable without a password -- which is the finding, not
// the refusal.

// refused records a decision the policy refused.
func (t *server) refused(se *session, d Decision, what string) {
	c := t.host.Counters()
	if !t.enforcing() && !d.Hard {
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up, and a listener in shadow mode
		// that reported refusals it had in fact forwarded would be the one way
		// to defeat that: an operator reading the refusal count of a listener
		// being trialled would see enforcement that is not happening.
		c.WouldRefuse("redis", d.Reason)
		t.host.Shadow().Record("redis", t.name, d.Reason, d.Rule, what)
		return
	}
	c.Refuse("redis", d.Reason)
	s := se.sess()
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "redis",
		"reason", d.Reason, "secure", s.Secure, "authed", s.Authed}
	if s.User != "" {
		attrs = append(attrs, "db_user", textsafe.Clip64(s.User))
	}
	if s.Database != 0 {
		attrs = append(attrs, "database", s.Database)
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
	t.host.Logs().SecurityEvent(context.Background(), "deny", "redis_"+d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "redis_denied")
	}
}

// deny records a refusal that is not about something the policy read.
func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("redis", reason)
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "redis",
		"reason", reason}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "redis_"+reason, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "redis_denied")
	}
}

// authFailure records a credential the server refused.
//
// alert rather than deny, because the relay refused nothing -- the server did. It
// is worth a line because it is the signal a password is being guessed, and
// because the ban list wants it: the account guard's ladder is built out of
// failures, and on this protocol a failure is an ordinary command's error reply
// that nothing else would notice.
func (t *server) authFailure(se *session, user string) {
	t.host.Logs().SecurityEvent(context.Background(), "alert", "redis_auth_failed",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "redis",
		"db_user", textsafe.Clip64(user), "secure", se.sess().Secure)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "redis_denied")
	}
}

// keyPositionUnknown records a command the relay would not check a prefix policy
// against.
//
// It is a refusal, so it goes through refused() -- but it is worth naming here
// because it is the one an operator will ask about, and the answer is specific: the
// command's keys are somewhere that depends on an option, so the relay does not
// know which argument to check, and checking the wrong one would be a prefix policy
// that passes what it was meant to stop.
func (t *server) keyPositionUnknown(se *session, cmd string) {
	t.host.Logs().SecurityEvent(context.Background(), "alert", "redis_key_position_unknown",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "redis",
		"command", textsafe.Clip64(cmd),
		"detail", "the keys of this command are at positions that depend on an option, "+
			"so a key prefix policy cannot be applied to it")
}
