package snmp

import (
	"context"
	"net/netip"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/textsafe"
)

// Engineering on SNMP, which is one operation: a SET.
//
// On network and field equipment an SNMP write is a configuration change -- a
// port disabled, a VLAN moved, a trap destination pointed somewhere else -- and
// that is the whole of what this protocol changes. A GET is not engineering
// however deep it walks, and a GETBULK of the whole tree is a different problem
// (an amplifier, and the behavioural models' business).
//
// So the class is `configuration`, the point is the first binding's object
// identifier, and the subject is the credential rather than the address, because
// on this protocol the community string or the USM user is what a management
// station *is*. A work order for "reconfigure the substation switches on
// Tuesday" names that credential.
func engineeringOf(req request) (engineering.Operation, bool) {
	m := req.msg
	if m == nil || m.PDU == nil || !m.PDU.Type.Writes() {
		return engineering.Operation{}, false
	}
	op := engineering.Operation{Class: engineering.ClassConfiguration,
		Detail: m.PDU.Type.String(), Subject: req.credential()}
	if len(m.PDU.VarBinds) > 0 {
		op.Point = m.PDU.VarBinds[0].OID.String()
	}
	return op, true
}

// decideEngineering reports one engineering operation and says whether to carry
// the message.
func (t *server) decideEngineering(req request) string {
	if !t.engineering.On() {
		return ""
	}
	op, ok := engineeringOf(req)
	if !ok {
		return ""
	}
	subject := op.Subject
	if subject == "" {
		subject = req.client.String()
	}
	return t.engineering.Decide(op, subject, t.m.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(op engineering.Operation, grant *access.Grant) {
				t.reportEngineering(req.client, op, grant)
			},
			Ungranted: func(op engineering.Operation, reason string) {
				t.alertEngineering(req.client, reason, op)
			},
			Would: func(op engineering.Operation, reason string) {
				t.host.Counters().WouldRefuse("snmp", reason)
				t.host.Shadow().Record("snmp", t.cfg.Name, reason, "engineering", op.String())
			},
			Refused: func(op engineering.Operation, reason string) {
				t.alertEngineering(req.client, reason, op)
			},
		})
}

func (t *server) reportEngineering(ip netip.Addr, op engineering.Operation, grant *access.Grant) {
	t.host.Counters().Engineering("snmp", string(op.Class))
	t.host.ObserveFact(ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "snmp", Listener: t.cfg.Name,
		Identity: op.Subject, Detail: op.String(),
	})
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "snmp",
		"class", string(op.Class), "operation", op.Detail}
	if op.Point != "" {
		attrs = append(attrs, "oid", textsafe.Clip64(op.Point))
	}
	if op.Subject != "" {
		attrs = append(attrs, "credential", textsafe.Clip64(op.Subject))
	}
	if grant != nil {
		attrs = append(attrs, "grant", grant.ID, "work_order", textsafe.Clip64(grant.Reason))
	}
	t.host.Logs().SecurityEvent(context.Background(), "engineering",
		engineering.Reason(op.Class), attrs...)
}

// alertEngineering is the event for a configuration change outside every
// approved window. It does not reach the ban ladder: the estate's own management
// station is the client here.
func (t *server) alertEngineering(ip netip.Addr, reason string, op engineering.Operation) {
	t.host.Counters().Refuse("snmp", reason)
	if !t.alerts() {
		return
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "snmp_"+reason,
		"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "snmp",
		"reason", reason, "class", string(op.Class),
		"operation", textsafe.Clip64(op.String()))
}
