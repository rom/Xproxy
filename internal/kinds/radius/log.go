package radius

import (
	"context"
	"net/netip"
	"strings"

	wire "github.com/rom/xproxy/internal/radius"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a network's
// authentication.
//
// Every line names the client address, the code and -- where the packet had
// one -- the user name and realm, because on this protocol those are what a
// policy is written about and what an investigation starts from. Two things
// are never written here.
//
// **A password, in any form.** The wire package keeps only the obfuscated
// attribute's length, and what reaches here is that a request carried one.
// A relay that logged the ciphertext would be logging something anybody
// with the secret can reverse, which is everybody who can read the switch's
// configuration.
//
// **The attributes' values.** The attribute *types* a packet carried are
// logged, because a rule can be written about one; the values are not,
// because they are a session's own data and a log at login rate is not the
// place for it. The two exceptions are the ones a policy decided on: the
// user name, and the privilege level a reply granted.

func (t *server) alerts() bool { return t.alertOnDeny }

// deny records a refusal that is not about something the policy read.
func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("radius", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "radius",
			"reason", reason}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "radius_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "radius_denied")
	}
}

// refused records a refusal the policy made about a request, with the
// identity on it.
func (t *server) refused(ip netip.Addr, p *wire.Packet, d Decision) {
	if !t.enforcing() && !d.Hard {
		t.host.Counters().WouldRefuse("radius", d.Reason)
		t.host.Shadow().Record("radius", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("radius would refuse", t.attrs(ip, p, d)...)
		return
	}
	t.host.Counters().Refuse("radius", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "radius_"+d.Reason,
			t.attrs(ip, p, d)...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "radius_denied")
	}
}

// refusedReply records a refusal the policy made about an answer. The
// client's address is on the line rather than the server's, because the
// grant was about that client and that is what somebody reading the record
// is looking for.
func (t *server) refusedReply(e *exchange, p *wire.Packet, d Decision) {
	if !t.enforcing() {
		t.host.Counters().WouldRefuse("radius", d.Reason)
		t.host.Shadow().Record("radius", t.name, d.Reason, d.Rule, d.Detail)
		t.host.Logs().Access.Info("radius would refuse a reply", t.replyAttrs(e, p, d)...)
		return
	}
	t.host.Counters().Refuse("radius", d.Reason)
	if t.alerts() {
		t.host.Logs().SecurityEvent(context.Background(), "deny", "radius_"+d.Reason,
			t.replyAttrs(e, p, d)...)
	}
}

func (t *server) attrs(ip netip.Addr, p *wire.Packet, d Decision) []any {
	out := []any{"listener", t.name, "client_ip", ip.String(), "proto", "radius",
		"reason", d.Reason}
	if p != nil {
		out = append(out, "code", p.Code.String(), "radius_id", int(p.ID))
		if u := p.UserName(); u != "" {
			local, realm := wire.Realm(u)
			out = append(out, "user", textsafe.Clip64(u), "local", textsafe.Clip64(local))
			if realm != "" {
				out = append(out, "realm", textsafe.Clip64(realm))
			}
		}
		out = append(out, "auth_type", string(p.AuthType()))
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

func (t *server) replyAttrs(e *exchange, p *wire.Packet, d Decision) []any {
	out := []any{"listener", t.name, "client_ip", e.client.String(), "proto", "radius",
		"reason", d.Reason, "code", p.Code.String(), "radius_id", int(e.clientID)}
	if e.user != "" {
		out = append(out, "user", textsafe.Clip64(e.user))
	}
	if n, ok := p.PrivilegeLevel(); ok {
		out = append(out, "priv_lvl", n)
	}
	if p.Administrative() {
		out = append(out, "service_type", "administrative")
	}
	if d.Detail != "" {
		out = append(out, "detail", textsafe.Clip64(d.Detail))
	}
	if d.Rule != "" {
		out = append(out, "rule", d.Rule)
	}
	return out
}

// logRequest writes the access line for one request.
func (t *server) logRequest(req Request, d Decision) {
	if !t.logRequests {
		return
	}
	a := []any{"listener", t.name, "client_ip", req.Client.String(), "proto", "radius",
		"code", req.Code.String(), "radius_id", int(req.ID),
		"auth_type", string(req.AuthType)}
	if req.User != "" {
		a = append(a, "user", textsafe.Clip64(req.User))
	}
	if req.Realm != "" {
		a = append(a, "realm", textsafe.Clip64(req.Realm))
	}
	if req.NASID != "" {
		a = append(a, "nas_identifier", textsafe.Clip64(req.NASID))
	}
	if req.HasEAP {
		a = append(a, "eap_type", req.EAPType.String())
		if len(req.EAPOffers) > 0 {
			a = append(a, "eap_offers", offers(req.EAPOffers))
		}
	}
	if req.Password {
		// That one was sent, not what it was. On this protocol that fact is
		// itself worth recording: it says the estate is still doing PAP.
		a = append(a, "plaintext_password", true)
	}
	if d.Rule != "" {
		a = append(a, "rule", d.Rule)
	}
	t.host.Logs().Access.Info("radius request", a...)
}

// logReply writes the access line for one answer, which is the line that
// says what was granted.
func (t *server) logReply(e *exchange, rep Reply) {
	if !t.logRequests {
		return
	}
	a := []any{"listener", t.name, "client_ip", e.client.String(), "proto", "radius",
		"code", rep.Code.String(), "radius_id", int(e.clientID)}
	if e.user != "" {
		a = append(a, "user", textsafe.Clip64(e.user))
	}
	if rep.HasPrivilege {
		a = append(a, "priv_lvl", rep.Privilege)
	}
	if rep.Administrative {
		a = append(a, "service_type", "administrative")
	}
	if e.rule != "" {
		a = append(a, "rule", e.rule)
	}
	t.host.Logs().Access.Info("radius reply", a...)
}

// offers renders a Nak's method list for a log line.
func offers(list []wire.EAPType) string {
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, e.String())
	}
	return strings.Join(parts, ",")
}
