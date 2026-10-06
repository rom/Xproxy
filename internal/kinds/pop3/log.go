package pop3

import (
	"context"
	"net/netip"

	wire "github.com/rom/xproxy/internal/pop3"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after a mailbox compromise, which on this
// protocol is a shorter list than on IMAP because the protocol is.
//
// The line that matters is the retrieval: RETR takes a whole message and TOP
// takes the start of one, and the octets they carried are the only measure
// this protocol offers of how much of a mailbox left. A client that took
// four messages every morning and took nine hundred this afternoon is the
// finding, and the mail server's own log says only that it logged in.
//
// Two things are never written: the password, which arrives on the line
// after USER and in the base64 of an AUTH exchange, and the message, whose
// octets are counted and copied and never held.

func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("pop3", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "pop3",
			"reason", reason}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "pop3_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "pop3_denied")
	}
}

// denyConn is deny with the connection's identity attached.
func (t *server) denyConn(c *conn, reason, detail string) {
	c.tap.Deny(reason)
	t.host.Counters().Refuse("pop3", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "pop3",
			"reason", reason}
		if c.user != "" {
			a = append(a, "user", textsafe.Clip64(c.user))
		}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "pop3_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "pop3_denied")
	}
}

// refused records a refusal the policy made about a command.
func (t *server) refused(c *conn, req *Request, d Decision) {
	attrs := t.attrs(c, req, d)
	if !t.enforcing() && !d.Hard {
		t.host.Counters().WouldRefuse("pop3", d.Reason)
		t.host.Shadow().Record("pop3", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("pop3 would refuse", attrs...)
		return
	}
	c.tap.Deny(d.Reason)
	t.host.Counters().Refuse("pop3", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "pop3_"+d.Reason, attrs...)
	}
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "pop3_denied")
	}
}

func (t *server) attrs(c *conn, req *Request, d Decision) []any {
	out := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "pop3",
		"reason", d.Reason, "state", c.state.String()}
	if req != nil && req.Command != nil {
		out = append(out, "command", req.Command.Name)
	}
	if c.user != "" {
		out = append(out, "user", textsafe.Clip64(c.user))
	}
	if c.retrieved > 0 {
		out = append(out, "retrieved_bytes", c.retrieved, "messages", c.messages)
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
	if !t.logCommands {
		return
	}
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "pop3",
		"state", req.State.String(), "encrypted", req.Encrypted,
		"command", req.Command.Name}
	if req.User != "" {
		a = append(a, "user", textsafe.Clip64(req.User))
	}
	if n, ok, err := req.Command.Message(); err == nil && ok {
		a = append(a, "message", n)
	}
	if mech, _, ok := req.Command.Mechanism(); ok {
		a = append(a, "mechanism", mech)
	}
	if (req.Command.Name == "PASS" || req.Command.Name == "USER") && !req.Encrypted {
		// That a password travelled in the clear, not what it was.
		a = append(a, "plaintext_password", true)
	}
	if d.Rule != "" {
		a = append(a, "rule", d.Rule)
	}
	if !d.Allow {
		a = append(a, "refused", d.Reason)
	}
	t.host.Logs().Access.Info("pop3 command", a...)
}

// logRetrieval writes the line that says how much left.
func (t *server) logRetrieval(c *conn, cmd *wire.Command, octets int64) {
	if !t.logRetrievals {
		return
	}
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "pop3",
		"command", cmd.Name, "octets", octets,
		"total_octets", c.retrieved, "total_messages", c.messages}
	if c.user != "" {
		a = append(a, "user", textsafe.Clip64(c.user))
	}
	if n, ok, err := cmd.Message(); err == nil && ok {
		a = append(a, "message", n)
	}
	t.host.Logs().Access.Info("pop3 retrieval", a...)
}

// authFailed counts a refused credential and lets the ban ladder see it.
//
// A POP3 password is the one credential on this protocol and there is
// nothing else to guess, so a run of failures from one address is the
// clearest signal this kind produces.
func (t *server) authFailed(c *conn, command string) {
	t.host.Counters().POP3AuthFailures.Add(1)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "pop3",
			"reason", "auth_failed", "command", command}
		if c.user != "" {
			a = append(a, "user", textsafe.Clip64(c.user))
		}
		t.host.Logs().SecurityEvent(context.Background(), "alert", "pop3_auth_failed", a...)
	}
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "pop3_auth_failed")
	}
}
