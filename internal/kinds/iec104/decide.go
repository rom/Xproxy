package iec104

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
)

// decide is everything that happens to one frame between reading it and
// forwarding it. It returns the refusal reason and whether the frame may
// go on.
//
// The order is deliberate, and it is the same order as every other kind in
// this project: the integrity checks that are not policy come first, then
// the bounds, then the policy. A frame this could not read never reaches
// the policy at all -- the reader refused it -- and the numbering checks
// come before the rules because a replayed command is a replayed command
// whatever the rules say about its type.
func (se *session) decide(frame *wire.Frame, fromClient bool) (string, bool) {
	t := se.t
	switch frame.Format {
	case wire.FormatU:
		return se.decideControl(frame, fromClient)
	case wire.FormatS:
		// A supervisory acknowledgement carries a receive sequence number
		// and nothing else. It is still worth checking, because a station
		// that acknowledges frames nobody sent is either confused or
		// trying to open the sending window.
		return se.decideAck(frame, fromClient)
	}
	// An I frame. The numbering first, and the acknowledgement it carries
	// with it: on this protocol every I frame is also an acknowledgement.
	if reason, ok := se.decideSequence(frame, fromClient); !ok {
		return reason, false
	}
	if reason, ok := se.decideAck(frame, fromClient); !ok {
		return reason, false
	}
	a := frame.ASDU
	if a == nil {
		return "", true
	}
	se.t.observeFrame(se, a)
	command := a.Type.Command()
	system := a.Type.System()
	if command {
		t.host.Counters().IEC104Commands.Add(1)
		se.commands.Add(1)
	}
	if system {
		t.host.Counters().IEC104SystemCmds.Add(1)
	}
	// The rate limits, which are bounds rather than policy and are
	// therefore never shadowed: a relay that let a flood through because
	// its policy was in shadow mode would be a relay with no bound at all.
	if t.limiter != nil && !t.limiter.Allow(se.ip.String()) {
		t.host.Counters().IEC104RateLimited.Add(1)
		t.host.Counters().Refuse("iec104", "rate_limited")
		return "iec104_rate_limited", false
	}
	if t.cmdRate != nil && (command || system) && !t.cmdRate.Allow(se.ip.String()) {
		t.host.Counters().IEC104RateLimited.Add(1)
		t.host.Counters().Refuse("iec104", "command_rate_limited")
		t.deny(se.ip, "iec104_command_rate_limited", a.Type.String())
		return "iec104_command_rate_limited", false
	}
	// A station sending an activation to its own control centre is a
	// station behaving as a controlling station. It is not a thing the
	// standard has a shape for, and it is what a compromised substation
	// gateway pivoting upstream looks like.
	if !fromClient && a.Cause.Commanding() && (command || system) {
		t.host.Counters().Refuse("iec104", "station_command")
		t.deny(se.ip, "iec104_station_command", a.Type.String())
		if t.enforcing() {
			return "iec104_station_command", false
		}
		t.shadowed("iec104_station_command", "", a)
		return "", true
	}
	// Then the policy, which is the part shadow mode is about.
	d := t.policy.Decide(request{client: se.ip, frame: frame})
	// Learning records the frame and what the policy made of it, whether or not
	// the refusal is enforced: a learning run wants to know that the policy and
	// the traffic disagree, and which way.
	se.observeLearn(a, fromClient, d.Allow, time.Now())
	if !d.Allow {
		return se.policyRefused(frame, d)
	}
	// Then what the information element says: the quality a station attached to
	// a reading, the value it claims, and the timestamp a control centre put on
	// a command. It comes before the setpoint bound because a command whose
	// timestamp is an hour old is not a command whose value is worth arguing
	// about, and before the selection for the same reason a refused value does
	// not consume one.
	if reason, ok := se.decideElements(frame, fromClient); !ok {
		return reason, false
	}
	// Then the value a setpoint carries, which is the bound a rule about
	// type identifications cannot express: a rule says who may move this
	// point, and this says how far. It comes before the selection is
	// touched, so a refused value does not consume one.
	if reason, ok := se.decideSetpoint(frame); !ok {
		return reason, false
	}
	// And select-before-operate last, because it is about a command the
	// policy has already allowed: the question is not whether this client
	// may operate this point, but whether it said so twice.
	if reason, ok := se.decideSelect(frame); !ok {
		return reason, false
	}
	// The frame is going on, so what it says about the process is what the
	// relay knows about the process.
	t.observeSetpoint(a, fromClient)
	se.logFrame(frame, d, fromClient)
	return "", true
}

// decideSetpoint applies the value bounds to a setpoint command.
//
// Only a command from a controlling station is decided about. A station's
// own confirmation carries the same type and the same value, and refusing
// that would leave a control centre waiting for the answer to a command
// this relay already let through.
func (se *session) decideSetpoint(frame *wire.Frame) (string, bool) {
	t := se.t
	a := frame.ASDU
	if a == nil {
		return "", true
	}
	val, isSetpoint := a.Setpoint()
	if !isSetpoint {
		return "", true
	}
	t.host.Counters().IEC104Setpoints.Add(1)
	if !a.Cause.Commanding() {
		return "", true
	}
	d := t.policy.Setpoint(a)
	held, unknowns, _ := t.policy.state.Status()
	t.host.Counters().IEC104SetpointPoints.Store(int64(held))
	t.host.Counters().IEC104SetpointUnknown.Store(int64(unknowns)) //nolint:gosec // a count
	if d.Allow {
		return "", true
	}
	detail := setpointDetail(a, d.Rule, val)
	t.host.Counters().Refuse("iec104", trimReason(d.Reason))
	if t.alerts() {
		attrs := append(asduAttrs(a), "listener", t.cfg.Name, "client_ip", se.ip.String(),
			"proto", "iec104", "reason", d.Reason, "value", val, "bound", d.Rule)
		t.host.Logs().SecurityEvent(context.Background(), "deny", d.Reason, attrs...)
		if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
			bl.Observe(se.ip, "iec104_denied")
		}
	}
	if !t.enforcing() {
		t.host.Counters().IEC104WouldDeny.Add(1)
		t.host.Counters().WouldRefuse("iec104", d.Reason)
		if sh := t.host.Shadow(); sh != nil {
			sh.Record("iec104", t.cfg.Name, d.Reason, d.Rule, detail)
		}
		return "", true
	}
	t.host.Counters().IEC104Denied.Add(1)
	se.denied.Add(1)
	return d.Reason, false
}

// observeSetpoint records what a forwarded setpoint says the process now
// holds, which is what a delta bound is measured against. Which frames teach
// the relay what, and why, is setpointLearned.
func (t *server) observeSetpoint(a *wire.ASDU, fromClient bool) {
	// A listener with no bounds remembers nothing: there is no delta to
	// measure, so a table of values would be memory spent on a question
	// nobody asked.
	if a == nil || t.policy == nil || t.policy.state == nil || len(t.policy.setpoints) == 0 {
		return
	}
	switch setpointLearned(a, fromClient) {
	case learnValue:
		val, _ := a.Setpoint()
		t.policy.state.Observe(a, val)
	case learnForget:
		t.policy.state.Forget(a)
	}
}

// trimReason is the refusal-counter name for a reason: the counters are
// already per protocol, so they carry "setpoint_range" where the security
// log carries "iec104_setpoint_range".
func trimReason(reason string) string {
	const p = "iec104_"
	if hasPrefix(reason, p) {
		return reason[len(p):]
	}
	return reason
}

// policyRefused records a policy refusal and answers whether to enforce
// it, which is the one decision shadow mode changes.
func (se *session) policyRefused(frame *wire.Frame, d Decision) (string, bool) {
	t := se.t
	if !t.enforcing() {
		t.host.Counters().IEC104WouldDeny.Add(1)
		t.host.Counters().WouldRefuse("iec104", d.Reason)
		t.shadowed(d.Reason, d.Rule, frame.ASDU)
		return "", true
	}
	t.host.Counters().IEC104Denied.Add(1)
	se.denied.Add(1)
	t.refuse(se, frame, d)
	return d.Reason, false
}

// decideControl decides about a U-format frame.
func (se *session) decideControl(frame *wire.Frame, fromClient bool) (string, bool) {
	t := se.t
	d := t.policy.Control(frame.Control)
	if d.Allow {
		return "", true
	}
	if !fromClient {
		// A station's own confirmation is the answer to an activation this
		// relay already let through, and refusing it would leave the
		// control centre waiting for ever. Only a station *originating* a
		// control function is worth refusing, and the confirmations are
		// paired with their activations at load for exactly this reason.
		return "", true
	}
	if !t.enforcing() {
		t.host.Counters().IEC104WouldDeny.Add(1)
		t.host.Counters().WouldRefuse("iec104", d.Reason)
		t.shadowedControl(d.Reason, frame.Control)
		return "", true
	}
	t.host.Counters().IEC104Denied.Add(1)
	se.denied.Add(1)
	t.host.Counters().Refuse("iec104", d.Reason)
	t.deny(se.ip, "iec104_control", frame.Control.String())
	return d.Reason, false
}

// decideAck checks the receive sequence number a frame carried.
//
// It is called for supervisory frames, which carry nothing else, and for
// every I frame, because the standard lets an end piggyback its
// acknowledgement on any frame it sends and an end with data to send does
// exactly that. A relay that only read the supervisory ones would see the
// window fill up and refuse an ordinary afternoon's thirteenth command.
func (se *session) decideAck(frame *wire.Frame, fromClient bool) (string, bool) {
	t := se.t
	if t.m.MaxUnacknowledged != nil && !*t.m.MaxUnacknowledged {
		return "", true
	}
	end := &se.clientEnd
	if !fromClient {
		end = &se.stationEnd
	}
	if reason := end.acknowledged(frame.Recv); reason != "" {
		t.host.Counters().IEC104SeqGaps.Add(1)
		t.host.Counters().Refuse("iec104", "ack_ahead")
		t.deny(se.ip, "iec104_ack_ahead", "")
		if t.enforcing() {
			return reason, false
		}
	}
	return "", true
}

// decideSequence applies the numbering checks to an I frame.
func (se *session) decideSequence(frame *wire.Frame, fromClient bool) (string, bool) {
	t := se.t
	end := &se.clientEnd
	if !fromClient {
		end = &se.stationEnd
	}
	if t.m.CheckSequence != nil && !*t.m.CheckSequence {
		// Still recorded, because the relay's own numbering and its
		// acknowledgements are counted from what arrived.
		end.arrived(frame.Send, 0)
		return "", true
	}
	k := t.m.K
	if k == 0 {
		k = 12 // the standard's own default
	}
	if t.m.MaxUnacknowledged != nil && !*t.m.MaxUnacknowledged {
		k = 0
	}
	switch reason := end.arrived(frame.Send, k); reason {
	case "":
		return "", true
	case "iec104_window":
		t.host.Counters().IEC104WindowFull.Add(1)
		t.host.Counters().Refuse("iec104", "window")
		t.deny(se.ip, "iec104_window", "")
		if t.enforcing() {
			return reason, false
		}
		return "", true
	default:
		t.host.Counters().IEC104SeqGaps.Add(1)
		t.host.Counters().Refuse("iec104", "sequence")
		t.deny(se.ip, "iec104_sequence", "")
		if t.enforcing() {
			return reason, false
		}
		return "", true
	}
}

// decideSelect applies select-before-operate.
//
// A selection is recorded when one arrives, and consumed when the matching
// execute does. With require_select an execute that consumed nothing is
// refused: that is the check, and it is what turns a single injected
// command frame from an operation into a refusal.
func (se *session) decideSelect(frame *wire.Frame) (string, bool) {
	t := se.t
	a := frame.ASDU
	if a == nil || !a.Type.Command() || !a.Cause.Commanding() {
		return "", true
	}
	switch {
	case a.Cause == wire.CauseDeactivation:
		// The controlling station thinking better of it. The selection goes
		// whether or not it was the client that made it: a deactivation
		// naming a point this session did not select releases nothing.
		t.selects.Release(se.id, a)
		return "", true
	case a.Select:
		t.host.Counters().IEC104Selects.Add(1)
		if !t.selects.Select(se.id, a) {
			// The table is full, or the command names no point. Either way
			// the selection was not recorded, so an execute after it
			// cannot be matched -- and letting the execute through on a
			// selection that was never kept would be a bound that disabled
			// the check.
			t.host.Counters().Refuse("iec104", "select_unavailable")
			t.deny(se.ip, "iec104_select_unavailable", a.Type.String())
			if t.enforcing() && t.m.RequireSelect {
				return "iec104_select_unavailable", false
			}
			return "", true
		}
		held, _ := t.selects.Status()
		t.host.Counters().IEC104SelectsHeld.Store(int64(held))
		return "", true
	default:
		t.host.Counters().IEC104Executes.Add(1)
		selected := t.selects.Take(se.id, a)
		held, _ := t.selects.Status()
		t.host.Counters().IEC104SelectsHeld.Store(int64(held))
		if selected || !t.m.RequireSelect || !a.Type.SelectSupported() {
			// A type with no two-step form in the standard -- a 32-bit
			// bitstring output -- cannot be selected, so requiring a
			// selection for it would refuse every use of it for ever.
			return "", true
		}
		t.host.Counters().IEC104Unselected.Add(1)
		t.host.Counters().Refuse("iec104", "unselected")
		t.deny(se.ip, "iec104_unselected", detailOf(a))
		if !t.enforcing() {
			t.host.Counters().IEC104WouldDeny.Add(1)
			t.host.Counters().WouldRefuse("iec104", "iec104_unselected")
			t.shadowed("iec104_unselected", "", a)
			return "", true
		}
		t.host.Counters().IEC104Denied.Add(1)
		se.denied.Add(1)
		return "iec104_unselected", false
	}
}

// refuse records a frame the policy refused. The event carries what was
// asked for, because "a command was refused" is not an audit trail and
// "station 1, C_SC_NA_1 act on point 4321, rule breakers" is.
func (t *server) refuse(se *session, frame *wire.Frame, d Decision) {
	t.host.Counters().Refuse("iec104", d.Reason)
	if !t.alerts() {
		return
	}
	attrs := append(asduAttrs(frame.ASDU), "listener", t.cfg.Name,
		"client_ip", se.ip.String(), "proto", "iec104", "reason", d.Reason)
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "iec104_denied")
	}
}

// deny records a refusal that is not about an ASDU: a client that may not
// connect, a malformed frame, a bound.
func (t *server) deny(ip netip.Addr, what, detail string) {
	// Counted before the alert switch, because a listener with alerts off is one
	// that does not want the records and still wants the numbers. Every decision
	// about an ASDU is counted by reason; these were not, so an operator reading
	// this kind's refusals saw the protocol decisions and none of the ones made
	// before a controlling station had said anything at all.
	t.host.Counters().Refuse("iec104", what)
	if !t.alerts() {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "iec104"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	name := what
	if !hasPrefix(name, "iec104_") {
		name = "iec104_" + name
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", name, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "iec104_denied")
	}
}

// alert records something worth telling an operator about that is not a refusal:
// a quality bit the policy names, a reported value outside its bound on a
// listener that only watches.
//
// It does not reach the ban ladder, and that is the point. A substation reporting
// a substituted value is not an attacker -- it is usually an engineer with a
// hand-entered reading -- and a ban would take the control room's telemetry away
// over a data-quality problem. The event and the counter are what an operator
// acts on; the ban ladder is for a client doing something it may not do.
func (t *server) alert(ip netip.Addr, what, detail string) {
	t.host.Counters().Refuse("iec104", trimReason(what))
	if !t.alerts() {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "iec104"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	name := what
	if !hasPrefix(name, "iec104_") {
		name = "iec104_" + name
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", name, attrs...)
}

// shadowed records a refusal that did not happen, so that an operator can
// see what enforcing would have cost before they enforce.
func (t *server) shadowed(reason, rule string, a *wire.ASDU) {
	if sh := t.host.Shadow(); sh != nil {
		sh.Record("iec104", t.cfg.Name, reason, rule, detailOf(a))
	}
}

// shadowedControl is the same for a U-format frame, which has no ASDU.
func (t *server) shadowedControl(reason string, c wire.Control) {
	if sh := t.host.Shadow(); sh != nil {
		sh.Record("iec104", t.cfg.Name, reason, "", c.String())
	}
}

// logFrame writes the access line. On this protocol most traffic is
// telemetry, so log_commands (the default) writes the commands and leaves
// the measurements alone: a record of what was commanded is the thing a
// grid operator is asked for after an incident, and a line per measurement
// buries it.
func (se *session) logFrame(frame *wire.Frame, d Decision, fromClient bool) {
	t := se.t
	a := frame.ASDU
	commands := t.m.LogCommands == nil || *t.m.LogCommands
	interesting := a != nil && (a.Type.Command() || a.Type.System())
	if !t.m.LogFrames && (!commands || !interesting) {
		return
	}
	from := "client"
	if !fromClient {
		from = "station"
	}
	attrs := append(asduAttrs(a), "listener", t.cfg.Name, "client_ip", se.ip.String(),
		"tls", se.secure, "from", from, "decision", "allow")
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if frame.Format == wire.FormatI {
		attrs = append(attrs, "send", frame.Send, "recv", frame.Recv)
	}
	t.host.Logs().Access.Info("iec104", attrs...)
}

// asduAttrs are the fields that describe an ASDU in a log line: the ones a
// grid engineer reads off a substation point list.
func asduAttrs(a *wire.ASDU) []any {
	if a == nil {
		return nil
	}
	attrs := []any{"type", a.Type.String(), "cause", a.Cause.String(),
		"common", a.Common, "objects", a.Objects}
	if a.Originator != 0 {
		attrs = append(attrs, "originator", a.Originator)
	}
	if len(a.Addresses) > 0 {
		attrs = append(attrs, "address", a.Addresses[0])
	}
	if a.Type.Command() {
		attrs = append(attrs, "select", a.Select)
	}
	if a.Test {
		attrs = append(attrs, "test", true)
	}
	if a.Negative {
		attrs = append(attrs, "negative", true)
	}
	return attrs
}

// detailOf is one short line describing an ASDU, for a security event's
// detail field and for the shadow ledger's sample.
func detailOf(a *wire.ASDU) string {
	if a == nil {
		return ""
	}
	out := a.Type.String() + " " + a.Cause.String()
	out += " ca=" + itoa(int(a.Common))
	if len(a.Addresses) > 0 {
		out += " ioa=" + itoa(int(a.Addresses[0]))
	}
	if a.Type.Command() && a.Select {
		out += " select"
	}
	return out
}

// log writes the session line: one per connection, with what it carried.
func (t *server) log(se *session, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "tls", se.secure,
		"commands", se.commands.Load(), "denied", se.denied.Load(),
		"duration_ms", time.Since(start).Milliseconds()}
	if se.ep != nil {
		attrs = append(attrs, "station", se.ep.Address)
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	t.host.Logs().Access.Info("iec104 session", attrs...)
}

// alerts says whether a refusal writes a security event.
func (t *server) alerts() bool { return t.m.AlertOnDeny == nil || *t.m.AlertOnDeny }

// hasPrefix without a strings import in this file.
func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// itoa formats a small non-negative number.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 && i > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// unused keeps the binary import honest if a later change drops its use.
var _ = binary.LittleEndian

// answerNegative refuses an activation the way the standard says a station
// does: the same ASDU returned with the negative-confirm bit set and the
// cause changed to a confirmation.
//
// It is the one place this relay writes a frame of its own rather than
// forwarding one, and it does so by copying the octets it read and changing
// two: the cause octet's low six bits and its negative bit. Re-encoding the
// ASDU from the parsed fields would risk a frame the control centre reads
// differently from the one it sent.
//
// A frame that is not an activation gets no answer. There is nothing to
// negatively confirm about a measurement, and inventing a confirmation for
// one would put an ASDU on the wire that no station would ever send.
func (se *session) answerNegative(frame *wire.Frame, fromClient bool) {
	a := frame.ASDU
	if a == nil || !a.Cause.Commanding() {
		return
	}
	to := &se.clientEnd
	if !fromClient {
		to = &se.stationEnd
	}
	out := make([]byte, len(frame.Raw))
	copy(out, frame.Raw)
	// The cause octet is the third of the ASDU, which starts after the
	// APCI. Keep its test bit, set negative, and make the cause the
	// confirmation of whatever was asked.
	i := wire.APCILen + 2
	if i >= len(out) {
		return
	}
	confirm := byte(wire.CauseActCon)
	if a.Cause == wire.CauseDeactivation {
		confirm = byte(wire.CauseDeactCon)
	}
	out[i] = confirm | 0x40 | (out[i] & 0x80)
	// The sequence numbers are this relay's own, and have to be: a frame
	// it writes is a frame the end reading it counts, and an end that was
	// handed the numbers of the frame it just sent closes the association
	// (apci.go).
	if err := to.writeI(out); err != nil {
		se.closed.Store(true)
	}
}
