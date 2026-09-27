package s7

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/s7"
)

// S7comm-plus on this listener.
//
// An estate that has bought a Siemens controller since about 2012 has an
// S7-1200 or an S7-1500, and TIA Portal talks to it in S7comm-plus: the same
// TPKT and COTP stack, a protocol identifier of 0x72 instead of 0x32, and a
// different protocol above. A relay that read only 0x32 was not a relay in
// front of that controller -- it ended the connection on the first PDU, which
// is the wrong answer twice over: the engineering station gets a dropped
// socket with no reason in it, and an operator reading the refusal counters
// sees a transport error rather than a policy.
//
// **The policy is smaller than the classic one, and honestly so.** Classic
// S7comm says on the wire which area, which data block and which bytes a
// request names. S7comm-plus does not: the session is integrity-protected and
// the object and variable addressing is encrypted under a key the two ends
// derive, so a relay sees the outer framing and nothing under it. What is left
// is the function code -- read, write, method call, program change -- and that
// is what this decides about. Claiming more would be claiming to read what no
// relay in the middle can see.
//
// **An unnamed function fails closed.** The function table is read from the
// wire rather than from a specification Siemens does not publish, so it can be
// incomplete. A function this relay cannot name is the `unknown` class, and
// `default_action` decides it -- deny unless an operator says otherwise. That
// is the property that makes a reverse-engineered table safe to police with:
// being wrong costs a refusal, not a silent pass.

// The modes.
const (
	// plusRefuse lets no S7comm-plus through. It is the default, because it
	// is what an s7 listener written before this section existed meant.
	plusRefuse = "refuse"
	// plusPolicy decides each PDU by the lists.
	plusPolicy = "policy"
	// plusPassthrough forwards every S7comm-plus PDU.
	plusPassthrough = "passthrough"
)

// plusModes is the enum, for the policy and the load check to share.
var plusModes = map[string]bool{plusRefuse: true, plusPolicy: true, plusPassthrough: true}

// commPlus is the compiled S7comm-plus policy.
type commPlus struct {
	mode string
	// allowFn and denyFn are by function code, which is checked before the
	// classes: an engineer who disagrees with this relay's idea of what a
	// function does says so by naming the function.
	allowFn, denyFn map[uint16]bool
	// allowCl and denyCl are by class.
	allowCl, denyCl map[wire.PlusClass]bool
	allowByDef      bool
	// readOnly is the listener's own switch, which applies here too and
	// cannot be widened by a list: a read-only listener that TIA Portal
	// could write through is not a read-only listener.
	readOnly bool
}

// compilePlus builds it. A listener with no section gets the refusing mode,
// so the behaviour of every configuration written before this existed is
// unchanged except that the refusal is now named.
func compilePlus(c *config.S7Listener) (*commPlus, error) {
	p := &commPlus{mode: plusRefuse, readOnly: c.ReadOnly}
	cp := c.CommPlus
	if cp == nil {
		return p, nil
	}
	if cp.Mode != "" {
		if !plusModes[cp.Mode] {
			return nil, fmt.Errorf("s7comm_plus.mode: %q is not refuse, policy or passthrough", cp.Mode)
		}
		p.mode = cp.Mode
	}
	switch cp.DefaultAction {
	case "", "deny":
	case "allow":
		p.allowByDef = true
	default:
		return nil, fmt.Errorf("s7comm_plus.default_action: %q is not allow or deny", cp.DefaultAction)
	}
	var err error
	if p.allowFn, err = plusFunctionSet("s7comm_plus.functions", cp.Functions); err != nil {
		return nil, err
	}
	if p.denyFn, err = plusFunctionSet("s7comm_plus.deny_functions", cp.DenyFunctions); err != nil {
		return nil, err
	}
	if p.allowCl, err = plusClassSet("s7comm_plus.classes", cp.Classes); err != nil {
		return nil, err
	}
	if p.denyCl, err = plusClassSet("s7comm_plus.deny_classes", cp.DenyClasses); err != nil {
		return nil, err
	}
	// Lists on a listener that refuses everything are a policy nobody will
	// ever read, and almost always a mode somebody forgot to set.
	if p.mode != plusPolicy && (len(p.allowFn)+len(p.denyFn)+len(p.allowCl)+len(p.denyCl)) > 0 {
		return nil, fmt.Errorf("s7comm_plus: functions and classes are only read in mode: policy, and this listener is mode: %s", p.mode)
	}
	return p, nil
}

// plusFunctionSet reads a list of function codes by name or by number.
//
// A number is allowed because the table is read from the wire: an estate that
// finds a function this relay cannot name should be able to write a rule about
// it the same day rather than waiting for the table to grow.
func plusFunctionSet(field string, in []string) (map[uint16]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[uint16]bool, len(in))
	for _, s := range in {
		name := strings.TrimSpace(s)
		if f, ok := wire.PlusFunctionOf(name); ok {
			out[f] = true
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(name, "0x"), "0X"), 16, 16)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a function name or a 16-bit hex code", field, s)
		}
		out[uint16(n)] = true
	}
	return out, nil
}

func plusClassSet(field string, in []string) (map[wire.PlusClass]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[wire.PlusClass]bool, len(in))
	for _, s := range in {
		c, ok := wire.PlusClassNamed(strings.TrimSpace(s))
		if !ok {
			return nil, fmt.Errorf("%s: %q is not read, write, admin or unknown", field, s)
		}
		out[c] = true
	}
	return out, nil
}

// Enabled says whether any S7comm-plus reaches the controller at all, which
// is what the relay checks before it bothers parsing one.
func (p *commPlus) Enabled() bool { return p != nil && p.mode != plusRefuse }

// Plus decides about one S7comm-plus PDU from the client.
//
// The order is the same as everywhere else in this kind: the refusals that
// are not policy first, then the deny lists, then read_only, then the allow
// lists, then the default. A response or a notification travelling up from
// the controller is not decided here at all -- it is the answer to a request
// this relay already allowed.
func (p *commPlus) Plus(pdu *wire.PlusPDU) Decision {
	if p == nil || p.mode == plusRefuse {
		// Hard, because refusing the variant is not a policy a trial should
		// carry: an estate that has not decided about S7comm-plus has not
		// asked for it to reach the controller while it thinks about it.
		return hard("s7comm_plus_refused", plusDetail(pdu))
	}
	if p.mode == plusPassthrough {
		return allowed()
	}
	name, _ := pdu.FunctionName()
	class := pdu.Class()
	if !pdu.HasFunction && class != wire.PlusOpaque {
		// A keepalive carries no function: it changes nothing on the
		// controller and a link needs it, so it goes on the strength of the
		// mode alone.
		//
		// The opaque class is deliberately *not* covered by that. A
		// firmware-1.5 data PDU also has no function code here, but for the
		// opposite reason -- there is one and this relay cannot locate it --
		// so carrying it because the field came back empty would be carrying
		// every operation on a current S7-1500 unexamined. It goes to the
		// lists below, where an operator has to name it.
		return allowed()
	}
	detail := plusDetail(pdu)
	if p.denyFn[pdu.Function] || p.denyCl[class] {
		return Decision{Reason: "s7comm_plus_denied", Detail: detail}
	}
	if p.readOnly && class != wire.PlusRead {
		// Every class but read is refused, and that deliberately includes
		// unknown: on a read-only listener a function this relay cannot name
		// is exactly the one it must not forward.
		return hard("read_only", detail)
	}
	if p.allowFn[pdu.Function] {
		return allowed()
	}
	if p.allowCl[class] {
		return allowed()
	}
	if p.allowByDef {
		return allowed()
	}
	_ = name
	return Decision{Reason: "s7comm_plus_not_allowed", Detail: detail}
}

// plusDetail describes a PDU for a refusal: the function by name where this
// relay has one and by number where it does not, with the class, because a
// refusal an engineer cannot look up is one they cannot act on.
func plusDetail(pdu *wire.PlusPDU) string {
	if pdu == nil {
		return ""
	}
	out := pdu.TypeName()
	if op := pdu.OpcodeName(); op != "" {
		out += " " + op
	}
	if name, _ := pdu.FunctionName(); name != "" {
		out += " " + name + " (" + string(pdu.Class()) + ")"
	}
	return out
}
