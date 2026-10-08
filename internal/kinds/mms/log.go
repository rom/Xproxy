package mms

import (
	"context"
	"fmt"
	"strings"
	"time"

	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident in a substation.
//
// Every line names the calling identity and, where the request had one, the object
// and its functional constraint -- because on this protocol that is what a change
// record is about. "A Write happened" is not a record; "this AP-title wrote
// XCBR1$CO$Pos$Oper on AA1J1Q01A1LD0 at 03:14" is.
//
// Three things are never written here.
//
// **A value.** A Write's payload is a process value and a control's ctlVal is a
// breaker position. The object and the constraint are logged because those are what a
// policy is written about; the value is not, because a log at poll rate is not the
// place for a substation's data.
//
// **A password.** The wire package keeps only its length, and what reaches here is
// that one was sent and how long it was. A relay that logged the password would be
// the second place it leaks, which is the whole point of not holding it.
//
// **A whole object list.** A Read naming forty objects is logged as the first and a
// count, because a log line that is a list is a log line nobody reads.
//
// Two records are not refusals and are the ones that matter most afterwards. An
// **association** is where an identity enters, and an **IED error** is the device
// refusing something this relay allowed -- which is where the two policies disagree.

// now is the clock, indirected so a test can pin it.
var now = time.Now

func (t *server) alerts() bool { return t.mc.AlertOnDeny == nil || *t.mc.AlertOnDeny }

// deny records a refusal that is not about something the policy read.
func (t *server) deny(c *conn, reason, detail string) {
	ip := c.ip
	c.tap.Deny(reason)
	t.host.Counters().Refuse("mms", reason)
	if t.alerts() {
		a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "mms",
			"reason", reason}
		if detail != "" {
			a = append(a, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "mms_"+reason, a...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "mms_denied")
	}
}

// alertDeny records a refusal the policy made, with the identity on it.
func (t *server) alertDeny(c *conn, d Decision, what string) {
	// The ban ladder hears about this before alert_on_deny can silence the
	// record below: turning the log down is not a decision to stop responding.
	if bl := t.host.Bans(); bl != nil && c.ip.IsValid() {
		bl.Observe(c.ip, "mms_denied")
	}

	if !t.alerts() {
		return
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "mms_"+d.Reason,
		t.attrs(c, d, what)...)
}

// attrs builds the attributes for one refusal.
func (t *server) attrs(c *conn, d Decision, what string) []any {
	a := c.assoc()
	out := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"reason", d.Reason, "identity", a.Identity()}
	if a.HasQualifier {
		out = append(out, "ae_qualifier", a.AEQualifier)
	}
	if a.Auth != wire.AuthNone {
		out = append(out, "authentication", a.Auth.String())
	}
	if what != "" {
		out = append(out, "what", textsafe.Clip64(what))
	}
	if d.Detail != "" {
		out = append(out, "detail", textsafe.Clip64(d.Detail))
	}
	if d.Rule != "" {
		out = append(out, "rule", d.Rule)
	}
	if d.Comment != "" {
		out = append(out, "comment", textsafe.Clip64(d.Comment))
	}
	if d.ErrorClass != 0 {
		out = append(out, "mms_error", fmt.Sprintf("%d/%d", d.ErrorClass, d.ErrorCode))
	}
	return out
}

// logWouldRefuse records what a shadow or learning listener would have refused.
func (t *server) logWouldRefuse(c *conn, d Decision, what string) {
	t.host.Logs().Access.Info("mms would refuse", t.attrs(c, d, what)...)
}

// logTransport writes the transport connection's own line: the selectors, which are a
// convention on this protocol and therefore worth recording rather than deciding on.
func (t *server) logTransport(c *conn, cotp *wire.COTP) {
	t.host.Logs().Access.Info("mms transport", "listener", t.name,
		"client_ip", c.ip.String(), "proto", "mms",
		"pdu", wire.TypeName(cotp.Type),
		"called_selector", fmt.Sprintf("%x", cotp.Called),
		"calling_selector", fmt.Sprintf("%x", cotp.Calling),
		"tpdu_size", wire.TPDUBytes(cotp.TPDUSize))
}

// logAssociate writes the association request, which is where an identity enters.
// It is logged whatever log_requests says, because it is the line everything after
// it is attributed to.
func (t *server) logAssociate(c *conn, a *wire.Associate) {
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"ap_title", a.CallingAPTitle.String(),
		"called_ap_title", a.CalledAPTitle.String(),
		"authentication", a.Auth.String()}
	if a.HasCallingAEQualifier {
		attrs = append(attrs, "ae_qualifier", a.CallingAEQualifier)
	}
	if a.Auth != wire.AuthNone {
		// The length and not the value. See the note at the top of this file.
		attrs = append(attrs, "authentication_length", a.AuthLength)
	}
	if a.Mechanism != nil {
		attrs = append(attrs, "mechanism", a.Mechanism.String())
	}
	t.host.Logs().Access.Info("mms association", attrs...)
}

// logAssociateResult writes what the IED said about the association.
func (t *server) logAssociateResult(c *conn, a *wire.Associate) {
	if a.Tag != wire.AARE {
		return
	}
	t.host.Logs().Access.Info("mms association result", "listener", t.name,
		"client_ip", c.ip.String(), "proto", "mms",
		"identity", c.assoc().Identity(), "accepted", a.Accepted(),
		"result", a.Result)
}

// alertPlaintext is the finding an estate most often does not know it has: a password
// crossing this relay in the clear, whether or not the listener refuses it.
//
// It is a security event rather than an access line because it is about the estate's
// posture rather than about one request, and it names the length rather than the
// value.
func (t *server) alertPlaintext(c *conn, length int) {
	t.host.Logs().SecurityEvent(context.Background(), "finding", "mms_plaintext_password",
		"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"identity", c.assoc().Identity(), "length", length,
		"detail", "the ACSE authentication value is a cleartext password (IEC 61850-8-1); IEC 62351-4 replaces it")
}

// logRequest writes one request's line, where the listener asks for them -- except
// for the ones that are always written.
func (t *server) logRequest(c *conn, m *wire.Message, ops []Operation) {
	always := m.Service.Changes() || operatesAny(ops) ||
		m.Service.Class() == wire.ClassDomain
	if !always && !t.mc.LogRequests {
		return
	}
	a := c.assoc()
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"identity", a.Identity(), "service", m.Service.String(),
		"class", m.Service.Class().String(), "invoke", m.InvokeID}
	if m.Domain != "" {
		attrs = append(attrs, "domain", textsafe.Clip64(m.Domain))
	}
	if m.ListName != "" {
		attrs = append(attrs, "variable_list", textsafe.Clip64(m.ListName))
	}
	if m.FileName != "" {
		attrs = append(attrs, "file", textsafe.Clip64(m.FileName))
	}
	if len(ops) > 0 {
		attrs = append(attrs, "objects", len(ops),
			"first", textsafe.Clip64(ops[0].Name.Key()))
		if fcs := constraintsOf(ops); fcs != "" {
			attrs = append(attrs, "constraints", fcs)
		}
		if operatesAny(ops) {
			attrs = append(attrs, "operates", true)
		}
	}
	if m.Values > 0 {
		// How many values, never what they were.
		attrs = append(attrs, "values", m.Values)
	}
	t.host.Logs().Access.Info("mms request", attrs...)
}

// logObserved writes the line an observe rule exists for: it matched and decided
// nothing, which is how a rule is tried on live traffic.
func (t *server) logObserved(c *conn, r *rule, svc wire.Service, ops []Operation) {
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"identity", c.assoc().Identity(), "rule", r.Name(),
		"service", svc.String()}
	if len(ops) > 0 {
		attrs = append(attrs, "first", textsafe.Clip64(ops[0].Name.Key()))
	}
	if r.Comment() != "" {
		attrs = append(attrs, "comment", textsafe.Clip64(r.Comment()))
	}
	t.host.Logs().Access.Info("mms observed", attrs...)
}

// logSelected writes the line a select-before-operate estate wants: the IED
// confirmed a selection, and this association may now operate that object until the
// selection expires.
func (t *server) logSelected(c *conn, key string) {
	t.host.Counters().MMSSelections.Add(1)
	t.host.Logs().Access.Info("mms selected", "listener", t.name,
		"client_ip", c.ip.String(), "proto", "mms",
		"identity", c.assoc().Identity(), "object", textsafe.Clip64(key),
		"until", now().Add(t.policy.SelectTimeout()).UTC().Format(time.RFC3339))
}

// serverError records a read error on the IED's side, which is the relay losing the
// device rather than a client misbehaving.
func (t *server) serverError(c *conn, err error) {
	t.host.Logs().Error.Warn("mms ied read failed", "listener", t.name,
		"client_ip", c.ip.String(), "error", textsafe.Clip64(err.Error()))
}

// serverRefused records the IED refusing something this relay allowed. It is not a
// refusal by this listener and is deliberately not counted as one -- but it is the
// line that says the two policies disagree, and which way.
func (t *server) serverRefused(c *conn, svc wire.Service, m *wire.Message) {
	attrs := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"identity", c.assoc().Identity(), "invoke", m.InvokeID,
		"pdu", m.PDU.String()}
	if svc.Known() {
		attrs = append(attrs, "service", svc.String())
	}
	if m.HasError {
		attrs = append(attrs, "mms_error", fmt.Sprintf("%d/%d", m.ErrorClass, m.ErrorCode))
	}
	t.host.Logs().Access.Info("mms ied refused", attrs...)
}

// operatesAny says one of the operations operates the plant.
func operatesAny(ops []Operation) bool {
	for _, op := range ops {
		if op.Write && op.Name.Operates() {
			return true
		}
	}
	return false
}

// constraintsOf is the set of functional constraints a request touched, sorted, for
// one log field rather than one per object.
func constraintsOf(ops []Operation) string {
	seen := map[string]bool{}
	out := make([]string, 0, 8)
	for _, op := range ops {
		if !op.Name.Parsed || seen[string(op.Name.FC)] {
			continue
		}
		seen[string(op.Name.FC)] = true
		out = append(out, string(op.Name.FC))
		if len(out) >= 8 {
			break
		}
	}
	sortStrings(out)
	return strings.Join(out, ",")
}

// sortStrings is an insertion sort, which is the right one for a list of at most
// eight two-letter strings and avoids pulling in sort for it.
func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
