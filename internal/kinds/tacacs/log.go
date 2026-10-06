package tacacs

import (
	"context"
	"net/netip"
	"strings"

	wire "github.com/rom/xproxy/internal/tacacs"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a network's device
// administration.
//
// The accounting line is the one that matters most and it is written whether
// or not anything was refused: on a TACACS+ estate that record is "who ran
// what, on which device, at what privilege level", and having a copy of it
// here -- written by a different program, in a different place -- is worth
// the disk, because whoever has just got privileged access to the routers
// does not have this.
//
// Two things are never written.
//
// **A password or a typed answer.** An ASCII login's password is in a
// CONTINUE packet's user_msg and PAP's is in the START's data; the wire
// package keeps only their lengths, and there is no accessor that would
// return either. What reaches a log line is that one was sent.
//
// **An argument's value, except the ones a policy decided on.** The
// arguments' *names* go in the line, because a rule can be written about
// one. The values do not, except `cmd` and `cmd-arg` -- which are the
// command, and the whole point -- and `priv-lvl`, which is the grant.

func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("tacacs", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "tacacs",
			"reason", reason}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "tacacs_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "tacacs_denied")
	}
}

// refused records a refusal the policy made about a request.
func (t *server) refused(c *conn, req *Request, d Decision) {
	if !t.enforcing() && !d.Hard {
		t.host.Counters().WouldRefuse("tacacs", d.Reason)
		t.host.Shadow().Record("tacacs", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("tacacs would refuse", t.attrs(c, req, d)...)
		return
	}
	c.tap.Deny(d.Reason)
	t.host.Counters().Refuse("tacacs", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "tacacs_"+d.Reason,
			t.attrs(c, req, d)...)
	}
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "tacacs_denied")
	}
}

// refusedAnswer records a refusal the policy made about the server's reply:
// a privilege grant above the bound, or a redirect.
func (t *server) refusedAnswer(c *conn, s *sess, a Answer, d Decision) {
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "tacacs",
		"reason", d.Reason, "exchange", a.Exchange.String(), "status", a.Status}
	if s.user != "" {
		attrs = append(attrs, "user", textsafe.Clip64(s.user))
	}
	if a.HasPrivilege {
		attrs = append(attrs, "priv_lvl", a.Privilege)
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(d.Detail))
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if !t.enforcing() && !d.Hard {
		t.host.Counters().WouldRefuse("tacacs", d.Reason)
		t.host.Shadow().Record("tacacs", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("tacacs would refuse a reply", attrs...)
		return
	}
	c.tap.Deny(d.Reason)
	t.host.Counters().Refuse("tacacs", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "tacacs_"+d.Reason, attrs...)
	}
}

func (t *server) attrs(c *conn, req *Request, d Decision) []any {
	out := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "tacacs",
		"reason", d.Reason}
	if req != nil {
		out = append(out, "exchange", req.Exchange.String(), "session", req.Session)
		if req.User != "" {
			out = append(out, "user", textsafe.Clip64(req.User))
		}
		if req.Command != "" {
			out = append(out, "command", textsafe.Clip64(req.Command))
		}
		if req.Port != "" {
			out = append(out, "port", textsafe.Clip64(req.Port))
		}
		if req.RemAddr != "" {
			out = append(out, "rem_addr", textsafe.Clip64(req.RemAddr))
		}
		out = append(out, "priv_lvl", int(req.PrivLvl))
	}
	if d.Detail != "" {
		out = append(out, "detail", textsafe.Clip64(d.Detail))
	}
	if d.Rule != "" {
		out = append(out, "rule", d.Rule)
	}
	if len(d.Observed) > 0 {
		// The rules being tried on live traffic. They decided nothing -- the
		// rule above did -- and this line is what an operator reads to find
		// out what one of them would have covered.
		out = append(out, "observed", strings.Join(d.Observed, ","))
	}
	return out
}

// logRequest writes the access line for one request.
func (t *server) logRequest(req Request, d Decision) {
	if !t.logRequests {
		return
	}
	a := []any{"listener", t.name, "client_ip", req.Client.String(), "proto", "tacacs",
		"exchange", req.Exchange.String(), "session", req.Session, "seq", int(req.Seq),
		"priv_lvl", int(req.PrivLvl)}
	if req.User != "" {
		a = append(a, "user", textsafe.Clip64(req.User))
	}
	if req.Port != "" {
		a = append(a, "port", textsafe.Clip64(req.Port))
	}
	if req.RemAddr != "" {
		a = append(a, "rem_addr", textsafe.Clip64(req.RemAddr))
	}
	if req.Exchange == wire.TypeAuthen {
		a = append(a, "action", req.Action.String(), "authen_type", req.AuthenType.String(),
			"authen_service", req.Service.String())
		if req.AuthenType.Plaintext() {
			// That the credential travels in the body, not what it is.
			a = append(a, "plaintext_password", true)
		}
	}
	if req.Method != 0 {
		a = append(a, "authen_method", req.Method.String())
	}
	if req.ServiceArg != "" {
		a = append(a, "service", textsafe.Clip64(req.ServiceArg))
	}
	if req.Command != "" {
		a = append(a, "command", textsafe.Clip64(req.Command))
	}
	if names := req.Args.Names(); len(names) > 0 {
		a = append(a, "args", strings.Join(names, ","))
	}
	if d.Rule != "" {
		a = append(a, "rule", d.Rule)
	}
	t.host.Logs().Access.Info("tacacs request", a...)
}

// logAccounting writes the audit record: the line an estate is asked for
// when somebody wants to know who changed the router.
func (t *server) logAccounting(req Request, ac wire.AcctRequest) {
	if !t.logAcct {
		return
	}
	a := []any{"listener", t.name, "client_ip", req.Client.String(), "proto", "tacacs",
		"record", wire.AcctRecord(ac.Flags), "session", req.Session,
		"priv_lvl", int(ac.PrivLvl), "authen_method", ac.Method.String()}
	if ac.User != "" {
		a = append(a, "user", textsafe.Clip64(ac.User))
	}
	if ac.Port != "" {
		a = append(a, "port", textsafe.Clip64(ac.Port))
	}
	if ac.RemAddr != "" {
		a = append(a, "rem_addr", textsafe.Clip64(ac.RemAddr))
	}
	if req.ServiceArg != "" {
		a = append(a, "service", textsafe.Clip64(req.ServiceArg))
	}
	if req.Command != "" {
		a = append(a, "command", textsafe.Clip64(req.Command))
	}
	if id, ok := ac.Args.First("task_id"); ok {
		a = append(a, "task_id", textsafe.Clip64(id.Value))
	}
	if el, ok := ac.Args.First("elapsed_time"); ok {
		a = append(a, "elapsed_time", textsafe.Clip64(el.Value))
	}
	t.host.Logs().Access.Info("tacacs accounting", a...)
}

// logAnswer writes the line that says what the server granted, which is the
// other half of the record: a command authorised, and at what privilege.
func (t *server) logAnswer(c *conn, s *sess, a Answer) {
	if !t.logRequests {
		return
	}
	out := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "tacacs",
		"exchange", a.Exchange.String(), "session", s.id, "status", a.Status,
		"pass", a.Pass}
	if s.user != "" {
		out = append(out, "user", textsafe.Clip64(s.user))
	}
	if a.HasPrivilege {
		out = append(out, "priv_lvl", a.Privilege)
	}
	if s.rule != "" {
		out = append(out, "rule", s.rule)
	}
	t.host.Logs().Access.Info("tacacs reply", out...)
}
