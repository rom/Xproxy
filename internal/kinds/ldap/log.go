package ldap

import (
	"context"
	"crypto/tls"
	"time"

	wire "github.com/rom/xproxy/internal/ldap"
)

// The records a directory front is asked for after an incident: who
// authenticated, from where, as whom, and whether it worked; what was changed;
// and what was refused.
//
// A password never appears in any of them. Neither does an assertion value: a
// filter's *shape* is logged and what it was looking for is not, because a
// search for a person's name is that person's business and a log of every one
// is a surveillance record the estate did not ask for.

// refused records a request the policy refused.
func (se *session) refused(m *wire.Message, d Decision) {
	if !se.t.enforcing() && !d.Hard {
		se.wouldRefuse(m, d)
		return
	}
	se.enforcedRefusal(m, d)
}

// wouldRefuse records a decision that is not being enforced, for a caller that
// has already decided it is not enforcing it: the listener's own monitor mode
// above, or the estate's authorisation policy, which has a shadow switch of its
// own and must leave the same record on a listener that enforces.
//
// Counted only as a would-be refusal. The two tables are kept apart so that a
// status view cannot add them up, and a listener in shadow mode that reported
// refusals it had in fact forwarded would be the one way to defeat that: an
// operator reading the refusal count of a listener being trialled would see
// enforcement that is not happening.
func (se *session) wouldRefuse(m *wire.Message, d Decision) {
	t := se.t
	c := t.host.Counters()
	c.LDAPWouldDeny.Add(1)
	c.WouldRefuse("ldap", d.Reason)
	t.host.Shadow().Record("ldap", t.cfg.Name, d.Reason, d.Rule, detailOf(m, d))
	t.logRequest(se, m, d, "would_deny")
}

// enforcedRefusal records a refusal that is being enforced.
func (se *session) enforcedRefusal(m *wire.Message, d Decision) {
	t := se.t
	c := t.host.Counters()
	c.Refuse("ldap", d.Reason)
	c.LDAPDenied.Add(1)
	se.mu.Lock()
	se.denied++
	bound, secure := se.boundName, se.secure
	se.mu.Unlock()
	t.logRequest(se, m, d, "deny")
	if !t.alerts() {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "proto", "ldap",
		"reason", d.Reason, "op", m.Op.String(), "tls", secure}
	if bound != "" {
		attrs = append(attrs, "bound_dn", bound)
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", d.Detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "ldap_denied")
	}
}

// deny records a refusal that is not about a request the policy read: a
// client that may not connect, a malformed message, a bound, a bind the
// directory itself refused. None of these is shadowed.
// deny records a refusal, and tells the capture the session was one.
//
// The capture asks about the refusal rather than how the session ended, which is
// why it is recorded here and not from the access log: a session that ran and then
// closed on a timeout did not get turned away, and a `denied: true` rule that
// matched it would select most of the traffic on the listener.
func (t *server) deny(se *session, what, detail string) {
	ip := se.ip
	se.tap.Deny(what)
	if !t.alerts() {
		return
	}
	name := what
	if len(name) < 5 || name[:5] != "ldap_" {
		name = "ldap_" + name
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "ldap"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", name, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "ldap_denied")
	}
}

// detailOf is one short line describing a request, for the shadow ledger's
// sample: the operation and the object, which is what an administrator can
// look up.
func detailOf(m *wire.Message, d Decision) string {
	out := m.Op.String()
	if d.Detail != "" {
		out += " " + d.Detail
	}
	return out
}

// logRequest writes the access line for one request.
//
// log_requests writes every one, which on a directory front is a great many.
// The defaults write the two that matter: a bind and its outcome, and
// anything that changed the directory or was refused.
func (t *server) logRequest(se *session, m *wire.Message, d Decision, decision string) {
	interesting := decision != "allow" || m.Op.Writes()
	if !t.m.LogRequests && (!t.logWrites() || !interesting) {
		return
	}
	// A bind gets its own line when its answer arrives, so it is not logged
	// twice here unless it was refused before reaching the directory.
	if m.Op == wire.OpBindRequest && decision == "allow" {
		return
	}
	se.mu.Lock()
	bound, secure := se.boundName, se.secure
	se.mu.Unlock()
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"op", m.Op.String(), "decision", decision, "tls", secure, "msgid", m.ID}
	if bound != "" {
		attrs = append(attrs, "bound_dn", bound)
	}
	if s := m.Search; s != nil {
		attrs = append(attrs, "base", s.BaseDN.String(), "scope", scopeName(s.Scope),
			"filter_terms", s.Filter.Terms, "filter_depth", s.Filter.Depth,
			"attributes", len(s.Attributes))
		if s.Filter.LeadingWildcard > 0 {
			attrs = append(attrs, "leading_wildcard", s.Filter.LeadingWildcard)
		}
	}
	if mod := m.Modify; mod != nil {
		attrs = append(attrs, "object", mod.ObjectDN.String(),
			"changed", len(mod.Attributes))
	} else if m.Target != "" {
		attrs = append(attrs, "object", m.TargetDN.String())
	}
	if e := m.Extended; e != nil {
		attrs = append(attrs, "oid", e.OID)
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
	}
	t.host.Logs().Access.Info("ldap", attrs...)
}

// logBind writes the line for a bind and what the directory said about it.
// This is the record an estate is actually asked for.
func (t *server) logBind(se *session, name string, method wire.Method, code wire.ResultCode) {
	if !t.logBinds() && !t.m.LogRequests {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"op", "bind", "method", method.String(), "tls", se.isSecure(),
		"result", code.String()}
	if name != "" {
		attrs = append(attrs, "bind_dn", name)
	}
	if code == wire.ResultSuccess {
		attrs = append(attrs, "decision", "allow")
	} else {
		attrs = append(attrs, "decision", "failed")
	}
	t.host.Logs().Access.Info("ldap bind", attrs...)
}

// stripped records that an answer had attributes removed from it. It is an
// access line rather than a security event: nobody did anything wrong, and
// the directory sent what it was asked for.
func (t *server) stripped(se *session, m *wire.Message, removed int) {
	if !t.m.LogRequests && !t.logWrites() {
		return
	}
	name := ""
	if m.Entry != nil {
		name = m.Entry.Name
	}
	t.host.Logs().Access.Info("ldap stripped", "listener", t.cfg.Name,
		"client_ip", se.ip.String(), "msgid", m.ID, "object", name,
		"attributes_removed", removed)
}

// logSession writes the line for one session: what it did, and why it ended.
func (t *server) logSession(se *session, start time.Time, reason string) {
	se.mu.Lock()
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "tls", se.secure,
		"requests", se.requests, "binds", se.binds, "bind_failures", se.failures,
		"denied", se.denied, "duration_ms", time.Since(start).Milliseconds()}
	if se.boundName != "" {
		attrs = append(attrs, "bound_dn", se.boundName)
	}
	se.mu.Unlock()
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	t.host.Logs().Access.Info("ldap session", attrs...)
}

func scopeName(scope int) string {
	switch scope {
	case wire.ScopeBase:
		return "base"
	case wire.ScopeOne:
		return "one"
	case wire.ScopeSub:
		return "sub"
	}
	return "scope(?)"
}

// handleStartTLS answers a StartTLS request on the client's side rather than
// forwarding it.
//
// It is handled here and not relayed because the connection to the directory
// may already be TLS, or may be plaintext by design: this is the secure
// upgrade, and the two legs are separate decisions. It reports whether the
// request was handled, and a reason when the session must end.
func (se *session) handleStartTLS(m *wire.Message) (string, bool) {
	t := se.t
	if m.Op != wire.OpExtendedRequest || m.Extended == nil || m.Extended.OID != wire.OIDStartTLS {
		return "", false
	}
	if t.m.TLSMode != "starttls" || t.tlsCfg == nil {
		// The listener has no TLS to offer. Saying so in the protocol's own
		// terms is better than forwarding the request to a directory whose
		// answer would then apply to the wrong leg of the connection.
		t.host.Counters().Refuse("ldap", "starttls_unavailable")
		_ = se.writeClient(wire.StartTLSResponse(m.ID, wire.ResultProtocolError,
			"this listener does not offer StartTLS"))
		return "", true
	}
	if se.isSecure() {
		// StartTLS inside TLS. RFC 4513 leaves it undefined and no client
		// needs it; refusing keeps the session's state something both ends
		// agree about.
		t.host.Counters().Refuse("ldap", "starttls_twice")
		t.deny(se, "ldap_starttls_twice", "")
		_ = se.writeClient(wire.StartTLSResponse(m.ID, wire.ResultOperationsError,
			"the connection is already protected"))
		return "", true
	}
	se.mu.Lock()
	outstanding := len(se.outstanding)
	se.mu.Unlock()
	if outstanding > 0 {
		// RFC 4511 §4.14.1: the client must have no outstanding operations.
		// A relay that upgraded anyway would be changing the transport under
		// answers already in flight.
		t.host.Counters().Refuse("ldap", "starttls_outstanding")
		t.deny(se, "ldap_starttls_outstanding", "")
		_ = se.writeClient(wire.StartTLSResponse(m.ID, wire.ResultOperationsError,
			"operations are outstanding"))
		return "", true
	}
	// The write, the handshake and the swap are one critical section: a
	// write from the directory's side in the middle of the handshake would
	// put plaintext inside a TLS record.
	se.cmu.Lock()
	if _, err := se.client.Write(wire.StartTLSResponse(m.ID, wire.ResultSuccess, "")); err != nil {
		se.cmu.Unlock()
		return "closed", true
	}
	// StartTLS is an in-band upgrade, so the capture pauses over the handshake and
	// picks the plaintext up again on the far side: the file then holds one
	// readable stream of the protocol rather than cleartext and then ciphertext.
	se.tap.Pause()
	tc := tls.Server(se.client, t.tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.HandshakeContext(context.Background()); err != nil {
		se.cmu.Unlock()
		t.host.Counters().Refuse("ldap", "tls_handshake")
		t.deny(se, "tls_handshake", err.Error())
		return "tls_handshake", true
	}
	_ = tc.SetDeadline(time.Time{})
	se.client = se.tap.Client(tc)
	se.cmu.Unlock()
	se.mu.Lock()
	// The identity does not survive the upgrade. RFC 4513 §5.1.7 says the
	// authentication state is discarded, and a relay that kept it would let
	// a client bind in the clear and then hide behind TLS with the identity
	// that bind gave it.
	se.bound, se.boundName, se.method = nil, "", wire.MethodAnonymous
	se.secure = true
	se.mu.Unlock()
	t.host.Counters().LDAPStartTLS.Add(1)
	return "", true
}
