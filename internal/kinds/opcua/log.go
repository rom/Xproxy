package opcua

import (
	"context"
	"fmt"
	"time"

	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a plant.
//
// Every line names the channel's terms and the identity, because on this protocol
// those are the things a change record is about: which application, which user,
// which security policy and mode, which service, which nodes. Where a rule decided,
// its own comment goes in too — that is where an operator writes why the rule
// exists.
//
// What is never logged is a value. A Write's payload is a process value: a pressure,
// a temperature, a recipe parameter. Not secrets, but not something a relay should
// copy into a log file at poll rate either. The node and the attribute are logged,
// because those are what a policy is written about and a refusal nobody can
// attribute to a node is a refusal nobody can act on.
//
// A password is never logged either, and never held: the wire package keeps only
// its length, and what reaches here is whether one was sent and whether it was
// protected.
//
// Two records are not refusals and are the ones that matter most after an incident.
// A **ServiceFault from the server** is the server refusing something this relay
// allowed, which is where the two policies disagree. And an **activation** is the
// moment a session acquires a user, which is the line that ties everything after it
// to a person.

// now is the clock, indirected so a test can pin it.
var now = time.Now

// refused2 records a decision the policy refused.
//
// The name is deliberate and temporary-looking because it is not the refusal: the
// refusal is what refuseConn, refuseMessage and refused do with the decision. This
// only writes it down.
func (t *server) refused2(c *conn, d Decision, what string) {
	ct := t.host.Counters()
	if !t.enforcing() && !d.Hard {
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up: a listener being trialled that
		// reported refusals it had in fact forwarded would be the one way to
		// defeat the point of shadow mode.
		ct.WouldRefuse("opcua", d.Reason)
		t.host.Shadow().Record("opcua", t.name, d.Reason, d.Rule, what)
		return
	}
	c.tap.Deny(d.Reason)
	ct.Refuse("opcua", d.Reason)
	if !t.alerts() {
		return
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "opcua_"+d.Reason,
		t.attrs(c, d, what)...)
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "opcua_denied")
	}
}

// attrs builds the log attributes for one refusal.
func (t *server) attrs(c *conn, d Decision, what string) []any {
	s := c.sess()
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"reason", d.Reason}
	if s.Secured {
		a = append(a, "security_policy", s.Policy.Short(), "security_mode", s.Mode.String())
	}
	if s.ApplicationURI != "" {
		a = append(a, "application_uri", textsafe.Clip64(s.ApplicationURI))
	}
	if s.Activated {
		a = append(a, "token_kind", s.TokenKind.String())
		if s.User != "" {
			a = append(a, "user", textsafe.Clip64(s.User))
		}
	}
	if what != "" {
		a = append(a, "what", textsafe.Clip64(what))
	}
	if d.Detail != "" {
		a = append(a, "detail", textsafe.Clip64(d.Detail))
	}
	if d.Rule != "" {
		a = append(a, "rule", d.Rule)
	}
	if d.Comment != "" {
		a = append(a, "comment", textsafe.Clip64(d.Comment))
	}
	if d.Status != 0 {
		a = append(a, "status", wire.StatusName(d.Status))
	}
	return a
}

// deny records a refusal that is not about something the policy read.
func (t *server) deny(c *conn, reason, detail string) {
	ip := c.ip
	c.tap.Deny(reason)
	t.host.Counters().Refuse("opcua", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "opcua",
			"reason", reason}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "opcua_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "opcua_denied")
	}
}

func (t *server) alerts() bool { return t.oc.AlertOnDeny == nil || *t.oc.AlertOnDeny }

// logHello writes the transport handshake's own line: the sizes a client proposed,
// which are what a later refusal in the middle of a large request would be about.
func (t *server) logHello(c *conn, h *wire.HelloBody) {
	t.host.Logs().Access.Info("opcua hello", "listener", t.name,
		"client_ip", c.ip.String(), "proto", "opcua",
		"endpoint", textsafe.Clip64(h.EndpointURL), "sizes", describeSizes(h))
}

// logAck writes the sizes actually in force, which are the minimum of the two ends'
// proposals and therefore not what either of them asked for.
func (t *server) logAck(c *conn, a *wire.AcknowledgeBody) {
	if !t.oc.LogRequests {
		return
	}
	t.host.Logs().Access.Info("opcua acknowledge", "listener", t.name,
		"client_ip", c.ip.String(), "proto", "opcua",
		"receive_buffer", a.ReceiveBufferSize, "send_buffer", a.SendBufferSize,
		"max_message", a.MaxMessageSize, "max_chunks", a.MaxChunkCount)
}

// logChannel writes the channel's terms, which are the most consequential line this
// listener produces: they say how strong the cryptography is and whether anything
// after this point has a readable body at all.
func (t *server) logChannel(c *conn, h *wire.AsymmetricHeader, o *wire.OpenChannelRequest) {
	t.host.Logs().Access.Info("opcua secure channel", "listener", t.name,
		"client_ip", c.ip.String(), "proto", "opcua",
		"security_policy", h.Policy.Short(), "security_mode", o.Mode.String(),
		"request", o.Type.String(), "lifetime_ms", o.Lifetime,
		"deprecated", h.Policy.Deprecated(), "readable", o.Mode.Readable(),
		"certificate_octets", len(h.SenderCertificate))
}

// logActivation writes the line that ties everything after it to a person.
//
// It is written whether or not log_requests is on, because it is not a request
// line: it is the session acquiring an identity, which happens once and is what an
// incident is reconstructed from.
func (t *server) logActivation(c *conn, a *wire.ActivateSessionRequest) {
	s := c.sess()
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"token_kind", a.Kind.String(), "policy_id", textsafe.Clip64(a.PolicyID),
		"application_uri", textsafe.Clip64(s.ApplicationURI),
		"session_name", textsafe.Clip64(s.SessionName)}
	if a.User != "" {
		attrs = append(attrs, "user", textsafe.Clip64(a.User))
	}
	if a.PasswordLen > 0 {
		// The length and whether it was protected, never the value. A relay that
		// held a plant's passwords would be a relay worth attacking for them.
		attrs = append(attrs, "password_octets", a.PasswordLen,
			"password_protected", a.PasswordAlgorithm != "")
	}
	if s.Secured {
		attrs = append(attrs, "security_policy", s.Policy.Short(),
			"security_mode", s.Mode.String())
	}
	t.host.Logs().Access.Info("opcua session activated", attrs...)
}

// logRequest writes the access line for one service call.
func (t *server) logRequest(c *conn, call *wire.ServiceCall, extra []any) {
	s := c.sess()
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"service", call.Service.String(), "handle", call.Header.RequestHandle}
	if s.Activated && s.User != "" {
		attrs = append(attrs, "user", textsafe.Clip64(s.User))
	}
	if call.Header.AuditEntryID != "" {
		// The client's own audit identifier, which is how a plant ties this
		// relay's record to the client's.
		attrs = append(attrs, "audit_entry", textsafe.Clip64(call.Header.AuditEntryID))
	}
	attrs = append(attrs, extra...)
	t.host.Logs().Access.Info("opcua request", attrs...)
}

// logWrite writes the line for a Write, which is written whether or not
// log_requests is on.
//
// A write is what a plant's change record is about. The node and the attribute are
// named and the value is not, and the attribute is named for what it governs:
// "permission" on a write to an access level says, in the line itself, that this
// was a privilege change rather than a setpoint.
func (t *server) logWrite(c *conn, call *wire.ServiceCall, w *wire.WriteRequest) {
	s := c.sess()
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"service", call.Service.String(), "handle", call.Header.RequestHandle,
		"values", len(w.Values)}
	if s.Activated && s.User != "" {
		attrs = append(attrs, "user", textsafe.Clip64(s.User))
	}
	for i, v := range w.Values {
		if i >= 16 {
			// A Write of a thousand values is one line with sixteen of them and a
			// count, rather than a thousand lines or one unbounded one.
			attrs = append(attrs, "more", len(w.Values)-i)
			break
		}
		what := v.Attr.String()
		if v.Attr.Permission() {
			what += " (permission)"
		}
		attrs = append(attrs, "value", fmt.Sprintf("%s %s type=%s",
			v.Node.Key(), what, v.Value.Value.Type))
	}
	t.host.Logs().Access.Info("opcua write", attrs...)
}

// logMethod writes the line for a Call, which is also always written: a method is
// how a client makes a plant do something, and there is no attribute and no value
// to soften it.
func (t *server) logMethod(c *conn, call *wire.ServiceCall, k *wire.CallRequest) {
	s := c.sess()
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"service", call.Service.String(), "handle", call.Header.RequestHandle,
		"methods", len(k.Methods)}
	if s.Activated && s.User != "" {
		attrs = append(attrs, "user", textsafe.Clip64(s.User))
	}
	for i, m := range k.Methods {
		if i >= 16 {
			attrs = append(attrs, "more", len(k.Methods)-i)
			break
		}
		// The argument *count* and not the arguments. A method's arguments are
		// process values like any other, and a setpoint in a log line is a
		// setpoint in a log file.
		attrs = append(attrs, "method", fmt.Sprintf("%s on %s args=%d",
			m.Method.Key(), m.Object.Key(), len(m.Arguments)))
	}
	t.host.Logs().Access.Info("opcua call", attrs...)
}

// serverError records an ERR from the server: the one place a server's own words
// reach this relay's log.
func (t *server) serverError(c *conn, e *wire.ErrorBody) {
	t.host.Counters().OPCUAServerErrors.Add(1)
	t.host.Logs().Access.Info("opcua server error", "listener", t.name,
		"client_ip", c.ip.String(), "proto", "opcua",
		"status", wire.StatusName(e.Code),
		// The reason is a remote peer's unvalidated free text, which is why it is
		// clipped and escaped like any other.
		"reason", textsafe.Clip64(e.Reason))
}

// serverRefused records the server refusing something this relay allowed.
//
// It is the case where the two policies disagree, and on this protocol it usually
// means the server does not grant this user what the listener does. An operator
// needs to know which of the two to change, so the line names both the service and
// the identity.
func (t *server) serverRefused(c *conn, call *wire.ServiceCall, svc wire.Service, known bool) {
	s := c.sess()
	t.host.Counters().OPCUAServerFaults.Add(1)
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "opcua",
		"status", wire.StatusName(call.Response.ServiceResult),
		"handle", call.Response.RequestHandle}
	if known {
		attrs = append(attrs, "service", svc.String())
	}
	if s.Activated && s.User != "" {
		attrs = append(attrs, "user", textsafe.Clip64(s.User))
	}
	if s.ApplicationURI != "" {
		attrs = append(attrs, "application_uri", textsafe.Clip64(s.ApplicationURI))
	}
	if call.Response.ServiceResult == wire.StatusBadUserAccessDenied {
		// The server refused the identity. That is a client walking a server's
		// permissions, and it is worth a security event rather than an access
		// line.
		t.host.Logs().SecurityEvent(context.Background(), "alert",
			"opcua_server_denied_user", attrs...)
		if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
			bl.Observe(c.ip, "opcua_denied")
		}
		return
	}
	t.host.Logs().Access.Info("opcua server fault", attrs...)
}
