package amqp

import (
	"context"
	"net/netip"
	"strconv"

	wire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a message broker.
//
// The line every record carries is what an operation *named* and never what a
// message held. A broker's payload is whatever an application put there,
// which in an estate is orders, personal data and tokens, and a relay that
// logged bodies would be the largest disclosure in it. The exchange, the
// queue, the routing key and the link address are logged, because those are
// what a policy decides on and a refusal nobody can attribute to a name is a
// refusal nobody can act on.
//
// Three records here are not refusals, and they are the ones that matter most
// after an incident. The broker's own 403 is the broker refusing a permission
// this relay allowed -- which is the case where the two policies disagree,
// and the operator wants to know which. The credential the broker refused is
// the signal a password is being guessed. And a broker offering ANONYMOUS is
// a finding about the broker rather than about any client.

// refused records a decision the policy refused.
func (t *server) refused(se *session, d Decision, what string) {
	c := t.host.Counters()
	c.Refuse("amqp", d.Reason)
	if !t.enforcing() && !d.Hard {
		c.WouldRefuse("amqp", d.Reason)
		t.host.Shadow().Record("amqp", t.name, d.Reason, d.Rule, what)
		return
	}
	if !t.alerts() {
		return
	}
	s := se.sess()
	user, mech, vhost := se.identity()
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
		"version", s.Version.String(), "reason", d.Reason,
		"secure", s.Secure, "authed", s.Authed}
	if user != "" {
		attrs = append(attrs, "amqp_user", textsafe.Clip64(user))
	}
	if mech != "" {
		attrs = append(attrs, "mechanism", textsafe.Clip64(mech))
	}
	if vhost != "" {
		attrs = append(attrs, "vhost", textsafe.Clip64(vhost))
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
	t.host.Logs().SecurityEvent(context.Background(), "deny", "amqp_"+d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "amqp_denied")
	}
}

// deny records a refusal that is not about something the policy read.
func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("amqp", reason)
	if t.alerts() {
		attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "amqp",
			"reason", reason}
		if detail != "" {
			attrs = append(attrs, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "amqp_"+reason, attrs...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "amqp_denied")
	}
}

// alerts says whether a refusal writes a security event.
func (t *server) alerts() bool { return t.ac.AlertOnDeny == nil || *t.ac.AlertOnDeny }

// authenticated records that the broker accepted a credential, which is the
// line that says who this connection is for everything after it.
func (t *server) authenticated(se *session) {
	user, mech, vhost := se.identity()
	t.host.Logs().Access.Info("amqp authenticated",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
		"version", se.sess().Version.String(),
		"amqp_user", textsafe.Clip64(user), "mechanism", textsafe.Clip64(mech),
		"vhost", textsafe.Clip64(vhost))
}

// authFailed records a credential the broker refused.
//
// alert rather than deny, because this relay refused nothing -- the broker
// did. It is worth a line because it is the signal a password is being
// guessed, and because the ban list wants it: the ladder that answers a
// credential attack is built out of failures, and on this protocol a failure
// is a frame that nothing else would notice.
func (t *server) authFailed(se *session) {
	user, mech, _ := se.identity()
	t.host.Logs().SecurityEvent(context.Background(), "alert", "amqp_auth_failed",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
		"amqp_user", textsafe.Clip64(user), "mechanism", textsafe.Clip64(mech),
		"secure", se.sess().Secure)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "amqp_denied")
	}
}

// brokerMechanisms records an offer worth knowing about.
//
// ANONYMOUS is a login with no identity. A client that chooses it is refused
// by the mechanism policy; the *offer* is a finding about the broker, because
// anything that reaches it without going through this relay can use it.
func (t *server) brokerMechanisms(se *session, mechs []string) {
	for _, m := range mechs {
		if !equalFold(m, "ANONYMOUS") {
			continue
		}
		t.host.Logs().SecurityEvent(context.Background(), "alert", "amqp_anonymous_offered",
			"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
			"detail", "the broker offers the ANONYMOUS mechanism, so a connection that "+
				"reaches it without passing this listener can authenticate as nobody")
		return
	}
}

// brokerRefused records the broker's own refusal on 0-9-1.
//
// 403 is ACCESS_REFUSED: the broker's permissions refused something this
// relay allowed. That is the interesting case -- the two policies disagree,
// and an operator has to know which one to change -- so it gets an alert
// rather than an access line, and the ban list hears about it: a client
// walking a broker's permissions produces a run of them.
func (t *server) brokerRefused(se *session, code uint16, text string) {
	if code != 403 {
		// Every other close code is the ordinary end of a connection, or a
		// protocol error, which is worth an access line and nothing more.
		t.host.Logs().Access.Info("amqp closed",
			"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
			"code", int(code), "text", textsafe.Clip64(text))
		return
	}
	user, _, vhost := se.identity()
	t.host.Logs().SecurityEvent(context.Background(), "alert", "amqp_broker_refused",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
		"code", int(code), "text", textsafe.Clip64(text),
		"amqp_user", textsafe.Clip64(user), "vhost", textsafe.Clip64(vhost))
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "amqp_denied")
	}
}

// brokerError records a 1.0 error condition, which is that version's way of
// saying the same things.
func (t *server) brokerError(se *session, condition, description string) {
	if condition == "amqp:unauthorized-access" {
		user, _, vhost := se.identity()
		t.host.Logs().SecurityEvent(context.Background(), "alert", "amqp_broker_refused",
			"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
			"condition", textsafe.Clip64(condition),
			"text", textsafe.Clip64(description),
			"amqp_user", textsafe.Clip64(user), "vhost", textsafe.Clip64(vhost))
		if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
			bl.Observe(se.ip, "amqp_denied")
		}
		return
	}
	t.host.Logs().Access.Info("amqp closed",
		"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
		"condition", textsafe.Clip64(condition), "text", textsafe.Clip64(description))
}

// logMethod writes the access line for one 0-9-1 method, when the listener
// asks for them.
//
// What it names and never what it carries: the exchange, the queue and the
// routing key of the operation, which is what an audit of a broker is about.
func (t *server) logMethod(se *session, name string, m *wire.Method) {
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
		"method", name}
	user, _, vhost := se.identity()
	if user != "" {
		attrs = append(attrs, "amqp_user", textsafe.Clip64(user))
	}
	if vhost != "" {
		attrs = append(attrs, "vhost", textsafe.Clip64(vhost))
	}
	if targets, ok := m.Targets(); ok {
		for _, tg := range targets {
			attrs = append(attrs, tg.Kind, textsafe.Clip64(tg.Name))
		}
	}
	t.host.Logs().Access.Info("amqp method", attrs...)
}

// logPerformative is the same for AMQP 1.0, where the interesting one is the
// attach: it is the frame that says what a link will carry and which way.
func (t *server) logPerformative(se *session, name string, p *wire.Performative) {
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "amqp",
		"performative", name}
	user, _, vhost := se.identity()
	if user != "" {
		attrs = append(attrs, "amqp_user", textsafe.Clip64(user))
	}
	if vhost != "" {
		attrs = append(attrs, "vhost", textsafe.Clip64(vhost))
	}
	if lname, handle, role, source, target, ok := p.Attach(); ok {
		attrs = append(attrs, "link", textsafe.Clip64(lname),
			"handle", strconv.FormatUint(handle, 10), "role", role)
		if source != "" {
			attrs = append(attrs, "source", textsafe.Clip64(source))
		}
		if target != "" {
			attrs = append(attrs, "target", textsafe.Clip64(target))
		}
	}
	t.host.Logs().Access.Info("amqp performative", attrs...)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'a' && x <= 'z' {
			x -= 32
		}
		if y >= 'a' && y <= 'z' {
			y -= 32
		}
		if x != y {
			return false
		}
	}
	return true
}
