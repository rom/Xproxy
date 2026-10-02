package imap

import (
	"context"
	"net/netip"
	"strings"

	wire "github.com/rom/xproxy/internal/imap"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after a mailbox compromise.
//
// The question is never "did somebody log in" -- the mail server knows that
// -- it is **how much left**. So the line that matters here is the one for a
// FETCH, SEARCH, COPY or MOVE, with the number of messages the request
// named: a client that asked for one message at nine in the morning and
// forty thousand at three in the afternoon is the whole finding, and nothing
// in the mail server's own log separates those two lines.
//
// Three things are never written.
//
// **A password.** It arrives in a LOGIN argument, in the base64 of a SASL
// exchange, or in a literal. The LOGIN line records that a password was sent
// and the user name beside it; the exchange's lines are forwarded without
// being parsed at all; a literal's octets are copied and never held.
//
// **A message.** An APPEND's literal is a message somebody is writing and a
// FETCH's response is one somebody is reading. Neither is logged: the size
// is, and the count is.
//
// **A search term.** `SEARCH TEXT "redundancy"` says what somebody is
// looking for in their own mail, which is not this relay's business to
// record. The command name goes in the line and the arguments do not.

// deny records a refusal made about a connection rather than a command.
func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("imap", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "imap",
			"reason", reason}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "imap_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "imap_denied")
	}
}

// denyConn is deny with the connection's identity attached, for the
// refusals that happen once a session is under way.
func (t *server) denyConn(c *conn, reason, detail string) {
	_, user, _ := c.snapshot()
	t.host.Counters().Refuse("imap", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "imap",
			"reason", reason}
		if user != "" {
			a = append(a, "user", textsafe.Clip64(user))
		}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "imap_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "imap_denied")
	}
}

// refused records a refusal the policy made about a command.
func (t *server) refused(c *conn, req *Request, d Decision) {
	attrs := t.attrs(c, req, d)
	if !t.enforcing() && !d.Hard {
		t.host.Counters().WouldRefuse("imap", d.Reason)
		t.host.Shadow().Record("imap", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("imap would refuse", attrs...)
		return
	}
	t.host.Counters().Refuse("imap", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "imap_"+d.Reason, attrs...)
	}
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "imap_denied")
	}
}

// refusedAnswer records a refusal made about the server's own response,
// which on this protocol is the PREAUTH greeting.
func (t *server) refusedAnswer(c *conn, r *wire.Response, d Decision) {
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "imap",
		"reason", d.Reason, "status", r.Status}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(d.Detail))
	}
	if !t.enforcing() && !d.Hard {
		t.host.Counters().WouldRefuse("imap", d.Reason)
		t.host.Shadow().Record("imap", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("imap would refuse a response", attrs...)
		return
	}
	t.host.Counters().Refuse("imap", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "imap_"+d.Reason, attrs...)
	}
}

func (t *server) attrs(c *conn, req *Request, d Decision) []any {
	out := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "imap",
		"reason", d.Reason}
	if req != nil {
		out = append(out, "state", req.State.String())
		if req.Command != nil {
			out = append(out, "command", req.Command.Effective(), "tag", textsafe.Clip64(req.Command.Tag))
		}
		if req.User != "" {
			out = append(out, "user", textsafe.Clip64(req.User))
		}
		if len(req.Mailboxes) > 0 {
			out = append(out, "mailbox", textsafe.Clip64(strings.Join(req.Mailboxes, ",")))
		}
		if req.Messages > 0 {
			out = append(out, "messages", req.Messages)
		}
		if req.Open {
			out = append(out, "open_set", true)
		}
		if req.Literal > 0 {
			out = append(out, "literal_bytes", req.Literal)
		}
	}
	if d.Detail != "" {
		out = append(out, "detail", textsafe.Clip64(d.Detail))
	}
	if d.Rule != "" {
		out = append(out, "rule", d.Rule)
	}
	return out
}

// logCommand writes the access line for one command.
func (t *server) logCommand(c *conn, req Request, d Decision) {
	collects := req.Command != nil && wire.Collects(req.Command)
	if !t.logCommands && (!collects || !t.logFetches) {
		return
	}
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "imap",
		"state", req.State.String(), "encrypted", req.Encrypted}
	if req.Command != nil {
		a = append(a, "command", req.Command.Effective())
		if req.Command.Name == "UID" {
			a = append(a, "uid", true)
		}
	}
	if req.User != "" {
		a = append(a, "user", textsafe.Clip64(req.User))
	}
	if len(req.Mailboxes) > 0 {
		a = append(a, "mailbox", textsafe.Clip64(strings.Join(req.Mailboxes, ",")))
	}
	if collects {
		// The number that answers "how much left".
		a = append(a, "messages", req.Messages, "open_set", req.Open)
	}
	if req.Literal > 0 {
		a = append(a, "literal_bytes", req.Literal)
	}
	if req.Command != nil && req.Command.Effective() == "LOGIN" && !req.Encrypted {
		// That a password travelled in the clear, not what it was.
		a = append(a, "plaintext_password", true)
	}
	if mech, ok := mechanismOf(req.Command); ok {
		a = append(a, "mechanism", mech)
	}
	if d.Rule != "" {
		a = append(a, "rule", d.Rule)
	}
	if !d.Allow {
		a = append(a, "refused", d.Reason)
	}
	t.host.Logs().Access.Info("imap command", a...)
}

// mechanismOf is the mechanism of an AUTHENTICATE, for the log line.
func mechanismOf(cmd *wire.Command) (string, bool) {
	if cmd == nil {
		return "", false
	}
	return wire.Mechanism(cmd)
}

// logAnswer writes the line for a tagged response: what the server said
// about the command this relay carried.
func (t *server) logAnswer(c *conn, r *wire.Response, name string) {
	if !t.logCommands {
		return
	}
	_, user, _ := c.snapshot()
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "imap",
		"status", r.Status}
	if name != "" {
		a = append(a, "command", name)
	}
	if user != "" {
		a = append(a, "user", textsafe.Clip64(user))
	}
	if r.Code != "" {
		a = append(a, "code", r.Code)
	}
	t.host.Logs().Access.Info("imap response", a...)
}

// authFailed counts a refused credential and lets the ban ladder see it.
//
// It is the one place on this kind where a failure that is not a policy
// refusal reaches the ladder: a mailbox is the one service on an estate
// whose password is worth guessing at scale, and the mail server's own
// lockout protects the account rather than the estate.
func (t *server) authFailed(c *conn, name string) {
	t.host.Counters().IMAPAuthFailures.Add(1)
	_, user, _ := c.snapshot()
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "imap",
			"reason", "auth_failed", "command", name}
		if user != "" {
			a = append(a, "user", textsafe.Clip64(user))
		}
		t.host.Logs().SecurityEvent(context.Background(), "alert", "imap_auth_failed", a...)
	}
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "imap_auth_failed")
	}
}
