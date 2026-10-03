package kkdcp

import (
	"context"
	"net/netip"
	"strings"

	wire "github.com/rom/xproxy/internal/kerberos"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on an estate's Kerberos.
//
// Every line names the realm, the client principal and -- on a TGS request --
// the service principal, because those three are what a policy is written
// about and what an investigation starts from. The encryption types are on
// the line too, which is unusual for a log and is the point of this listener:
// "this client asked for an RC4 ticket to MSSQLSvc/db at 03:14" is a sentence
// no other part of an estate can produce.
//
// Nothing cryptographic is ever written. The pre-authentication blob, the
// ticket and the reply's encrypted part are all opaque here and stay that
// way; what is logged about them is which *type* they are in, which is the
// field a policy decided on.

func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("kkdcp", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "kkdcp",
			"reason", reason}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "kkdcp_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "kkdcp_denied")
	}
}

// refused records a refusal the policy made about a request.
func (t *server) refused(req Request, d Decision) {
	if !t.enforcing() && !d.Hard {
		t.host.Counters().WouldRefuse("kkdcp", d.Reason)
		t.host.Shadow().Record("kkdcp", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("kkdcp would refuse", t.attrs(req, d)...)
		return
	}
	t.host.Counters().Refuse("kkdcp", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "kkdcp_"+d.Reason,
			t.attrs(req, d)...)
	}
	if bl := t.host.Bans(); bl != nil && req.Client.IsValid() {
		bl.Observe(req.Client, "kkdcp_denied")
	}
}

// refusedAnswer records a refusal the policy made about the KDC's reply: a
// pre-authentication exemption, or a ticket in a weak encryption type.
func (t *server) refusedAnswer(req Request, a Answer, d Decision) {
	attrs := append(t.attrs(req, d), "reply", a.Type.String())
	if a.HasTicketEType {
		attrs = append(attrs, "ticket_etype", a.TicketEType.String())
	}
	if !t.enforcing() && !d.Hard {
		t.host.Counters().WouldRefuse("kkdcp", d.Reason)
		t.host.Shadow().Record("kkdcp", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("kkdcp would refuse a reply", attrs...)
		return
	}
	t.host.Counters().Refuse("kkdcp", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "kkdcp_"+d.Reason, attrs...)
	}
	if bl := t.host.Bans(); bl != nil && req.Client.IsValid() {
		bl.Observe(req.Client, "kkdcp_denied")
	}
}

func (t *server) attrs(req Request, d Decision) []any {
	out := []any{"listener", t.name, "client_ip", req.Client.String(), "proto", "kkdcp",
		"reason", d.Reason, "message", req.Type.String()}
	if req.Realm != "" {
		out = append(out, "realm", textsafe.Clip64(req.Realm))
	}
	if req.TargetDomain != "" && req.TargetDomain != req.Realm {
		out = append(out, "target_domain", textsafe.Clip64(req.TargetDomain))
	}
	if req.Principal != "" {
		out = append(out, "principal", textsafe.Clip64(req.Principal))
	}
	if req.Service != "" {
		out = append(out, "service", textsafe.Clip64(req.Service))
	}
	if len(req.ETypes) > 0 {
		out = append(out, "etypes", etypeList(req.ETypes))
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
	a := []any{"listener", t.name, "client_ip", req.Client.String(), "proto", "kkdcp",
		"message", req.Type.String(), "realm", textsafe.Clip64(req.Realm)}
	if req.TargetDomain != "" {
		a = append(a, "target_domain", textsafe.Clip64(req.TargetDomain))
	}
	if req.Principal != "" {
		a = append(a, "principal", textsafe.Clip64(req.Principal))
	}
	if req.Service != "" {
		a = append(a, "service", textsafe.Clip64(req.Service))
	}
	if len(req.ETypes) > 0 {
		a = append(a, "etypes", etypeList(req.ETypes))
	}
	if opts := req.Options.Names(); len(opts) > 0 {
		a = append(a, "options", req.Options.String())
	}
	a = append(a, "preauth", req.Preauth)
	if req.S4U2Self {
		a = append(a, "s4u2self", true)
	}
	if req.S4U2Proxy {
		a = append(a, "s4u2proxy", true)
	}
	if req.HasLifetime {
		a = append(a, "lifetime", req.Lifetime.String())
	}
	if d.Rule != "" {
		a = append(a, "rule", d.Rule)
	}
	t.host.Logs().Access.Info("kkdcp request", a...)
}

// logAnswer writes the line for one reply, which is where the KDC's own
// choices appear: the encryption type the ticket left in, and the error code
// where it refused.
func (t *server) logAnswer(req Request, a Answer) {
	if !t.logRequests {
		return
	}
	out := []any{"listener", t.name, "client_ip", req.Client.String(), "proto", "kkdcp",
		"reply", a.Type.String(), "realm", textsafe.Clip64(req.Realm)}
	if req.Principal != "" {
		out = append(out, "principal", textsafe.Clip64(req.Principal))
	}
	if req.Service != "" {
		out = append(out, "service", textsafe.Clip64(req.Service))
	}
	if a.HasTicketEType {
		out = append(out, "ticket_etype", a.TicketEType.String(),
			"weak_ticket", a.TicketEType.Weak())
	}
	if a.IsError {
		out = append(out, "error", wire.ErrorName(a.ErrorCode))
	}
	if a.PreauthExempt {
		out = append(out, "preauth_exempt", true)
	}
	if a.Rule != "" {
		out = append(out, "rule", a.Rule)
	}
	t.host.Logs().Access.Info("kkdcp reply", out...)
}
