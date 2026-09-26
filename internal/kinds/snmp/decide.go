package snmp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/assets"
	wire "github.com/rom/xproxy/internal/snmp"
)

// What a decision does: the counters, the logs, and the rewrites.

// errSealed is a message whose payload this relay cannot read, where the
// thing being asked of it needs the payload. It is not a malformed message
// and not a refused one: it is a v3 message encrypted to a key the relay
// does not hold, which is the security model working.
var errSealed = errors.New("snmp: the scoped payload is encrypted")

// errUnanswerable is a version 3 request whose downgrade would leave no way
// to give the manager an answer it would accept.
var errUnanswerable = errors.New("snmp: a v3 request cannot be downgraded, because its answer would have to be authenticated")

// count records what the message was. Reads are the poll, writes are the
// changes, notifications are the alarms -- three numbers an operator can
// read a network's SNMP traffic off, where one "messages" count says
// nothing.
func (t *server) count(m *wire.Message) {
	c := t.host.Counters()
	if m.PDU == nil {
		return
	}
	switch {
	case m.PDU.Type.Writes():
		c.SNMPWrites.Add(1)
	case m.PDU.Type.Notification():
		c.SNMPTraps.Add(1)
	case m.PDU.Type.Reads():
		c.SNMPReads.Add(1)
	}
}

// refused records a message the policy refused.
//
// In shadow mode it records the refusal that did not happen and writes no
// security event: an event saying "deny" about traffic that was forwarded
// would be a false record, and the shadow ledger is the place that says
// what enforcing would have cost.
func (t *server) refused(ip netip.Addr, m *wire.Message, d Decision) {
	c := t.host.Counters()
	if !t.enforcing() {
		c.SNMPWouldDeny.Add(1)
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up, and a listener in shadow mode
		// that reported refusals it had in fact forwarded would be the one way
		// to defeat that: an operator reading the refusal count of a listener
		// being trialled would see enforcement that is not happening.
		c.WouldRefuse("snmp", d.Reason)
		t.host.Shadow().Record("snmp", t.cfg.Name, d.Reason, d.Rule, detailOf(m, d))
		t.access(ip, m, d, "would_deny", "")
		return
	}
	c.Refuse("snmp", d.Reason)
	c.SNMPDenied.Add(1)
	t.access(ip, m, d, "deny", "")
	if !t.alerts() {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "snmp",
		"reason", d.Reason, "version", m.Version.String()}
	if m.PDU != nil {
		attrs = append(attrs, "pdu", m.PDU.Type.String())
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", d.Detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "snmp_denied")
	}
}

// deny records a refusal that is not about a message the policy read: a
// client that may not send, a malformed datagram, a bound. None of these is
// shadowed -- a relay whose bounds were in shadow mode would be a relay
// with no bounds.
func (t *server) deny(ip netip.Addr, what, detail string) {
	if !t.alerts() {
		return
	}
	name := what
	if len(name) < 5 || name[:5] != "snmp_" {
		name = "snmp_" + name
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "snmp"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", name, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "snmp_denied")
	}
}

// detailOf is one short line describing a message, for the shadow ledger's
// sample. It names the operation and the first object, which is what makes
// a ledger entry answerable: "set 1.3.6.1.2.1.1.5.0" is something an
// engineer can look up, and "snmp_rule" is not.
func detailOf(m *wire.Message, d Decision) string {
	out := m.Version.String()
	if m.PDU != nil {
		out += " " + m.PDU.Type.String()
	}
	if d.Detail != "" {
		out += " " + d.Detail
	}
	return out
}

// access writes the access line for one message.
//
// log_messages writes every message, which on this protocol is a lot: a
// poller asks the same questions every thirty seconds. log_writes -- the
// default -- writes what was *changed* and what was refused, and leaves the
// polling alone, because what was changed through this relay is the record
// an estate is asked for after an incident.
func (t *server) access(ip netip.Addr, m *wire.Message, d Decision, decision, from string) {
	writes := t.m.LogWrites == nil || *t.m.LogWrites
	interesting := decision != "allow" || (m.PDU != nil && m.PDU.Type.Writes())
	if !t.m.LogMessages && (!writes || !interesting) {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(),
		"version", m.Version.String(), "decision", decision}
	if from != "" {
		attrs = append(attrs, "from", from)
	}
	if m.PDU != nil {
		attrs = append(attrs, "pdu", m.PDU.Type.String(), "bindings", len(m.PDU.VarBinds))
		if oid := firstOID(m.PDU); oid != "" {
			attrs = append(attrs, "oid", oid)
		}
		if m.PDU.Type == wire.GetBulkRequest {
			attrs = append(attrs, "repetitions", m.PDU.MaxRepetitions)
		}
	}
	if m.Version == wire.V3 && m.V3 != nil {
		attrs = append(attrs, "user", m.V3.User, "level", m.V3.Level.String())
		if m.V3.ContextName != "" {
			attrs = append(attrs, "context", m.V3.ContextName)
		}
	}
	// The community string is never logged. It is a credential, and an
	// access log that printed every one would be a list of the estate's
	// passwords with a timestamp beside each.
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Reason != "" && decision == "allow" {
		// The one allow that carries a reason: an encrypted v3 payload the
		// relay decided about without reading.
		attrs = append(attrs, "reason", d.Reason)
	}
	t.host.Logs().Access.Info("snmp", attrs...)
}

// logMessage writes the access line for a message that was allowed.
func (t *server) logMessage(ip netip.Addr, m *wire.Message, d Decision, from string) {
	t.access(ip, m, d, "allow", from)
}

// observeManager tells the estate's inventory about the thing polling.
//
// A monitoring system asks; that is what separates it from the equipment it
// monitors. The object identifiers it asked for are recorded because the shape
// of a poll says what kind of monitoring it is.
func (t *server) observeManager(ip netip.Addr, m *wire.Message) {
	t.host.ObserveAsset(assets.Observation{Listener: t.cfg.Name, Proto: "snmp",
		Addr: ip, Server: false, OIDs: oidsOf(m)})
}

// observeAgent tells the inventory about the equipment that answered.
//
// What it does *not* record is the agent's own description. sysDescr
// (1.3.6.1.2.1.1.1) is the one string in an estate that usually names a device's
// model and firmware, and a relay does see it go past -- but this package's
// reader keeps a varbind's name, type and extent and deliberately not its
// value, because a policy about values would need a MIB per estate. Changing a
// parser on the data path so that an inventory can read one string would be
// paying for a convenience in the place where the cost lands hardest, so the
// object identifiers are recorded and the values are left alone.
func (t *server) observeAgent(ip netip.Addr, m *wire.Message) {
	t.host.ObserveAsset(assets.Observation{Listener: t.cfg.Name, Proto: "snmp",
		Addr: ip, Server: true, OIDs: oidsOf(m)})
}

// oidsOf is the object identifiers a message named, bounded: the shape of a
// poll says what kind of monitoring it is, and the first few say it as well as
// all of them.
func oidsOf(m *wire.Message) []string {
	if m.PDU == nil {
		return nil
	}
	out := make([]string, 0, 8)
	for _, vb := range m.PDU.VarBinds {
		if len(out) >= 8 {
			break
		}
		out = append(out, vb.OID.String())
	}
	return out
}

// logSession writes the line for one stream session.
func (t *server) logSession(ip netip.Addr, start time.Time, secure bool, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "tls", secure,
		"duration_ms", time.Since(start).Milliseconds()}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	t.host.Logs().Access.Info("snmp session", attrs...)
}

// lowerRepetitions bounds a GETBULK's repetition count.
//
// The count is *lowered* rather than the request refused: a poller asking
// for more than it should get still gets an answer, which is what keeps
// this bound deployable in an estate whose pollers nobody can reconfigure,
// and the amplification is gone either way.
//
// The second return says the request must be refused instead, which
// happens for exactly one shape: an authenticated version 3 GETBULK past
// the bound. Its digest covers the whole message, this relay has no key to
// compute a new one with, and forwarding it unchanged would leave the bound
// unenforced. Refusing is the only answer that is neither a forged message
// nor an unbounded one.
func (t *server) lowerRepetitions(m *wire.Message, d Decision) (out []byte, lowered, refuse bool) {
	if m.PDU == nil || m.PDU.Type != wire.GetBulkRequest {
		return nil, false, false
	}
	max := t.policy.MaxRepetitions(request{msg: m}, d.Rule)
	if max <= 0 || m.PDU.MaxRepetitions <= int64(max) {
		return nil, false, false
	}
	if m.Version == wire.V3 {
		// Every version 3 message, whatever its level. An authenticated one
		// carries a digest over the whole message and this relay holds no
		// key to compute a new one with; a noAuthNoPriv one is signed by
		// nothing, but its scoped PDU sits inside a header with its own
		// lengths and security parameters, and rebuilding that is forging a
		// v3 message rather than relaying one. Either way the honest answer
		// is to refuse, because forwarding it unchanged would leave the
		// amplification bound unenforced.
		return nil, false, true
	}
	rewritten, err := wire.WithMaxRepetitions(m.PDU.Raw, int64(max))
	if err != nil {
		return nil, false, true
	}
	full, err := wire.Envelope(m.Version, m.Community, rewritten)
	if err != nil {
		return nil, false, true
	}
	return full, true, false
}

// applyUpgrade rewrites the envelope of a message being forwarded in a
// different version from the one it arrived in.
//
// This is the secure upgrade, and it only runs downwards. Producing v3 is
// refused at load: there is no user, no engine and no key with which to
// authenticate a v3 message that arrived as v2c, and producing one would be
// inventing an authentication that did not happen.
//
// Downgrading a v3 *request* is refused here for the mirror-image reason.
// The agent's answer would come back as v2c, and giving it to a v3 manager
// means rebuilding it as v3 -- which needs the user's key, which this relay
// does not hold. A relay that sent the v2c answer on would be a relay whose
// managers time out; one that claimed to have authenticated it would be
// lying. A v3 *notification* downgrades cleanly, because nothing comes
// back, and that is the case worth having: a modern device sending v3 traps
// to a collector that only understands v2c.
func (t *server) applyUpgrade(cur []byte, m *wire.Message) ([]byte, bool, error) {
	if t.upgrade < 0 || m.Version == t.upgrade {
		return cur, false, nil
	}
	if m.PDU == nil {
		// An encrypted v3 payload. There is no PDU to put in a v2c
		// envelope, and there will not be one without the key.
		return cur, false, errSealed
	}
	if m.Version == wire.V3 && !m.PDU.Type.Notification() {
		return cur, false, errUnanswerable
	}
	community := t.m.UpstreamCommunity
	if community == "" {
		community = m.Community
	}
	out, err := wire.Envelope(t.upgrade, community, m.PDU.Raw)
	if err != nil {
		return cur, false, err
	}
	return out, true, nil
}

// restore rebuilds a response in the version its request arrived in, which
// is the other half of the downgrade: the agent answered in the version the
// relay asked in, and the manager is owed the version it spoke.
//
// It is only ever v1 and v2c. Neither has any integrity to invalidate, so
// rewriting the envelope of one into the other is a relay's own statement
// and nothing is being forged. A v3 response is never restored, because a
// v3 request is never downgraded.
func (t *server) restore(raw []byte, m *wire.Message, e *exchange) ([]byte, bool) {
	if e == nil || m.PDU == nil || m.Version == e.version {
		return raw, false
	}
	if m.Version == wire.V3 || e.version == wire.V3 {
		return raw, false
	}
	out, err := wire.Envelope(e.version, e.community, m.PDU.Raw)
	if err != nil {
		return raw, false
	}
	return out, true
}

// answerRefusal sends the refusal on a datagram listener.
func (t *server) answerRefusal(m *wire.Message, to net.Addr) {
	if t.m.DenyResponse == "drop" || t.m.DenyResponse == "close" {
		// close has no meaning on a datagram: there is nothing to close,
		// and validation says so. Here it reads as drop.
		return
	}
	if answer := wire.Refusal(m); answer != nil {
		_, _ = t.pc.WriteTo(answer, to)
	}
}

// refusalFor is the refusal to send on a stream listener.
func refusalFor(m *wire.Message) []byte { return wire.Refusal(m) }
