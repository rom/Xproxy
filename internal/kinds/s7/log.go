package s7

import (
	"context"
	"fmt"
	"net/netip"

	wire "github.com/rom/xproxy/internal/s7"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident on a plant.
//
// Every line names the controller and the operation, because those are what a
// plant's change record is about: which CPU, which rack and slot, which
// operation, and -- where a rule decided -- the rule's own comment, which is
// where an operator writes why the rule exists.
//
// What is never logged is a value. A write's payload is a process value, and
// on a plant those are pressures, temperatures and recipe parameters: not
// secrets, but not something a relay should be copying into a log file at
// poll rate either. The *address* is logged, because an address is what a
// policy is written about and a refusal nobody can attribute to a byte range
// is a refusal nobody can act on.
//
// One record here is not a refusal and is the one that matters most after an
// incident: an *access fault* from the PLC itself. That is the controller
// refusing something this relay allowed, which on this protocol almost always
// means the CPU is password-protected and the client has not supplied one. It
// is the case where the two policies disagree, and an operator needs to know
// which one to change.

// refused records a decision the policy refused.
func (t *server) refused(se *session, d Decision, what string) {
	c := t.host.Counters()
	c.Refuse("s7", d.Reason)
	if !t.enforcing() && !d.Hard {
		c.WouldRefuse("s7", d.Reason)
		t.host.Shadow().Record("s7", t.name, d.Reason, d.Rule, what)
		return
	}
	if !t.alerts() {
		return
	}
	s := se.sess()
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "s7",
		"reason", d.Reason}
	if s.Addressed {
		attrs = append(attrs, "rack", s.Rack, "slot", s.Slot,
			"resource", wire.ResourceName(s.Resource))
	}
	if what != "" {
		attrs = append(attrs, "what", textsafe.Clip64(what))
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(d.Detail))
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Comment != "" {
		attrs = append(attrs, "comment", textsafe.Clip64(d.Comment))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "s7_"+d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "s7_denied")
	}
}

// deny records a refusal that is not about something the policy read.
func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("s7", reason)
	if t.alerts() {
		attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "s7",
			"reason", reason}
		if detail != "" {
			attrs = append(attrs, "detail", textsafe.Clip64(detail))
		}
		t.host.Logs().SecurityEvent(context.Background(), "deny", "s7_"+reason, attrs...)
	}
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "s7_denied")
	}
}

// alerts says whether a refusal writes a security event.
func (t *server) alerts() bool { return t.sc.AlertOnDeny == nil || *t.sc.AlertOnDeny }

// plcRefused records the controller's own refusal.
func (t *server) plcRefused(se *session, pdu *wire.PDU) {
	s := se.sess()
	kind, name := "alert", "s7_plc_refused"
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "s7",
		"error_class", wire.ErrorClassName(pdu.ErrClass),
		"error_code", fmt.Sprintf("%#x", pdu.ErrCode),
		"function", pdu.FunctionName()}
	if s.Addressed {
		attrs = append(attrs, "rack", s.Rack, "slot", s.Slot)
	}
	if pdu.ErrClass != 0x87 {
		// Every other class is the ordinary business of a controller: an
		// object that does not exist, a resource that is busy. It is worth an
		// access line and nothing more.
		t.host.Logs().Access.Info("s7 error", attrs...)
		return
	}
	// An access fault: the CPU refused a permission. On this protocol that
	// usually means it is password-protected and the client has not supplied
	// one, which is a client walking a controller's protection level.
	t.host.Logs().SecurityEvent(context.Background(), kind, name, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "s7_denied")
	}
}

// logRequest writes the access line for one request, when the listener asks
// for them.
//
// The operation, the controller, and what the request named -- the area, the
// data block and the byte range for a read or a write, the service name for a
// control operation, the block for an upload or a download. Never a value.
func (t *server) logRequest(se *session, pdu *wire.PDU) {
	op, known := pdu.Op()
	if !known {
		return
	}
	s := se.sess()
	attrs := []any{"listener", t.name, "client_ip", se.ip.String(), "proto", "s7",
		"operation", string(op)}
	if s.Addressed {
		attrs = append(attrs, "rack", s.Rack, "slot", s.Slot)
	}
	if items, ok := pdu.Items(); ok {
		for _, it := range items {
			if !it.Address {
				attrs = append(attrs, "item", fmt.Sprintf("syntax %#x", it.Syntax))
				continue
			}
			where := wire.AreaName(it.Area)
			if it.Area == wire.AreaDB || it.Area == wire.AreaInstanceDB {
				where = fmt.Sprintf("%s%d", where, it.DB)
			}
			attrs = append(attrs, "item", fmt.Sprintf("%s %d.%d %s x%d",
				where, it.Byte(), it.BitOffset(), wire.TransportName(it.Transport), it.Count))
		}
	}
	if name, ok := pdu.Service(); ok {
		attrs = append(attrs, "service", textsafe.Clip64(name))
	}
	if kind, number, ok := pdu.Block(); ok {
		attrs = append(attrs, "block", fmt.Sprintf("%s%d", kind, number))
	}
	if u, ok := pdu.UserData(); ok {
		attrs = append(attrs, "function", u.Name())
	}
	t.host.Logs().Access.Info("s7 request", attrs...)
}
