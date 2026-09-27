package s7

import (
	"encoding/binary"
	"testing"

	wire "github.com/rom/xproxy/internal/s7"
)

// S7comm-plus through the whole relay.
//
// The reason this matters more than a parser test: before this existed, the
// relay ended the connection on the first S7comm-plus PDU. Not refused it --
// ended it, with no answer and nothing in the counters an operator would read
// as a policy. So every controller an estate has bought since about 2012 could
// not be put behind this relay at all, and the failure looked like a network
// fault. The first test here is that defect, written down.

// plusFrame builds a TPKT/COTP frame carrying one S7comm-plus PDU: the header,
// then an opcode, two octets the protocol holds at zero, and a function code.
func plusFrame(opcode uint8, function uint16) []byte {
	data := []byte{opcode, 0x00, 0x00}
	data = binary.BigEndian.AppendUint16(data, function)
	return plusRaw(wire.PlusData, data)
}

// plusRaw builds one with a PDU type and data of the caller's choosing, for
// the cases that are not a well-formed request.
func plusRaw(pduType uint8, data []byte) []byte {
	body := []byte{wire.PlusProtocolID, pduType}
	body = binary.BigEndian.AppendUint16(body, uint16(len(data)))
	body = append(body, data...)
	return tpkt(append([]byte{0x02, 0xf0, 0x80}, body...))
}

// The defect: an S7-1500 client's first request killed the connection.
//
// It is refused now, and the refusal is a *policy* -- named, counted, and
// leaving the session up -- rather than a socket that closed. The default is
// still that no S7comm-plus reaches the controller, because that is what an s7
// listener written before this section existed meant.
func TestS7CommPlusIsRefusedByDefaultAndSaysSo(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	cl.write(plusFrame(wire.PlusRequest, wire.PlusGetMultiVariables))
	// The refusal leaves the connection up: the client can still do the work
	// it came to do over classic S7comm, which is what an estate running both
	// an HMI and TIA Portal against one CPU needs.
	cl.allowed(readJob(7, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	if !p.got("read") {
		t.Error("the classic read after the S7comm-plus refusal never arrived")
	}
	if p.got("plus get_multi_variables") {
		t.Error("a refused S7comm-plus request reached the controller")
	}
	if n := s.Stats().Refusals["s7"]["s7comm_plus_refused"]; n < 1 {
		t.Errorf("the refusal was not counted as a policy: %v", s.Stats().Refusals["s7"])
	}
}

// mode: policy is what makes an S7-1500 usable: the reads an HMI makes go, and
// the operations that change the program do not.
func TestS7CommPlusPolicyAllowsReadsAndRefusesTheRest(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: policy\n"+
		"          classes: [read]\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	// A read: through, and the controller answers it.
	cl.write(plusFrame(wire.PlusRequest, wire.PlusGetMultiVariables))
	if f, err := cl.r.Next(); err != nil {
		t.Fatalf("the allowed read got no answer: %v (%v)", err, f)
	}
	if !p.got("plus get_multi_variables") {
		t.Fatalf("the allowed read never reached the controller: %v", p.saws())
	}

	// A write, and a program change: neither goes.
	for _, c := range []struct {
		what string
		fn   uint16
	}{
		{"set_multi_variables", wire.PlusSetMultiVariables},
		{"create_object", wire.PlusCreateObject},
		{"invoke", wire.PlusInvoke},
		{"delete_object", wire.PlusDeleteObject},
	} {
		cl.write(plusFrame(wire.PlusRequest, c.fn))
		if p.got("plus " + c.what) {
			t.Errorf("%s reached the controller", c.what)
		}
	}
	waitFor(t, func() bool { return s.Stats().Refusals["s7"]["s7comm_plus_not_allowed"] >= 4 })
}

// The property that makes a table read off the wire safe to police with: a
// function this relay cannot name is refused, not forwarded. Siemens publishes
// no specification, so the table will be incomplete -- and being incomplete
// must cost a refusal rather than a silent pass.
func TestAnUnnamedS7CommPlusFunctionFailsClosed(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: policy\n"+
		"          classes: [read, write, admin]\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	// A function code in none of the four classes this relay knows. Every
	// class it does know is allowed above, so only the unknown one is left --
	// and it is refused.
	cl.write(plusFrame(wire.PlusRequest, 0x7777))
	if p.got("plus function_0x7777") {
		t.Error("a function this relay cannot name was forwarded to the controller")
	}
	waitFor(t, func() bool { return s.Stats().Refusals["s7"]["s7comm_plus_not_allowed"] >= 1 })

	// And an estate that has decided about it can say so, which is the point
	// of `unknown` being a class rather than a hidden default.
	p2 := startPLC(t, &fakePLC{})
	_, addr2 := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: policy\n"+
		"          classes: [unknown]\n", p2.addr())
	cl2 := dial(t, addr2)
	cl2.connect(wire.ResourceOP, 0, 2)
	cl2.write(plusFrame(wire.PlusRequest, 0x7777))
	if _, err := cl2.r.Next(); err != nil {
		t.Fatalf("the allowed unknown function got no answer: %v", err)
	}
	if !p2.got("plus function_0x7777") {
		t.Errorf("naming the unknown class did not let it through: %v", p2.saws())
	}
}

// read_only holds over S7comm-plus too, and no list can widen it. A read-only
// listener that TIA Portal could write through would not be one.
func TestReadOnlyHoldsOverS7CommPlus(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+
		"        read_only: true\n"+
		"        s7comm_plus:\n"+
		"          mode: policy\n"+
		"          classes: [read, write, admin, unknown]\n"+
		"          default_action: allow\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	cl.write(plusFrame(wire.PlusRequest, wire.PlusSetMultiVariables))
	if p.got("plus set_multi_variables") {
		t.Error("a write reached a read-only listener's controller")
	}
	// And the unknown class is refused on a read-only listener whatever the
	// lists say, because a function the relay cannot name is exactly the one
	// it must not carry there.
	cl.write(plusFrame(wire.PlusRequest, 0x7777))
	if p.got("plus function_0x7777") {
		t.Error("an unnamed function reached a read-only listener's controller")
	}
	waitFor(t, func() bool { return s.Stats().Refusals["s7"]["read_only"] >= 2 })
	// The reads it exists for still work.
	cl.write(plusFrame(wire.PlusRequest, wire.PlusExplore))
	if _, err := cl.r.Next(); err != nil {
		t.Fatalf("a read on a read-only listener was refused: %v", err)
	}
}

// passthrough is the escape hatch, and it has to actually pass through:
// an estate that must have TIA Portal working today should get that, with the
// frame bounds and rate limits still in force.
func TestPassthroughCarriesEveryS7CommPlusPDU(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: passthrough\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	for _, fn := range []uint16{wire.PlusInvoke, wire.PlusCreateObject, 0x7777} {
		cl.write(plusFrame(wire.PlusRequest, fn))
		if _, err := cl.r.Next(); err != nil {
			t.Fatalf("passthrough did not carry %#x: %v", fn, err)
		}
	}
}

// A PDU the relay could not read ends the connection, which is the same answer
// classic S7comm gets and for the same reason: forwarding what it cannot
// decide about would hand the controller octets with no policy applied.
func TestAnUnreadableS7CommPlusPDUEndsTheConnection(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: passthrough\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	// A declared data length longer than the octets that arrived. This is the
	// check that makes the rest of the parser safe to rely on: the length is
	// the one header field the frame itself can contradict.
	cl.write(tpkt([]byte{0x02, 0xf0, 0x80, wire.PlusProtocolID, wire.PlusData, 0x00, 0x40, 0x31}))
	if _, err := cl.r.Next(); err == nil {
		t.Error("the connection carried on after a PDU that did not add up")
	}
	if p.got("plus ") {
		t.Error("an unreadable PDU reached the controller")
	}
}

// A keepalive and the connect PDU carry no function code. They change nothing
// on the controller and the session cannot start without the connect, so in
// policy mode they go on the strength of the mode -- a listener that refused
// them would be a listener no S7-1500 could open a session through.
func TestTheS7CommPlusPDUsWithNoFunctionAreCarried(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: policy\n"+
		"          classes: [read]\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	cl.write(plusRaw(wire.PlusKeepalive, nil))
	cl.write(plusRaw(wire.PlusConnect, []byte{0x00}))
	// They have to *arrive*, not merely fail to end the session. A refused
	// S7comm-plus request is dropped rather than fatal, so a test that only
	// checked that the connection survived could not tell a carried keepalive
	// from a swallowed one -- and a swallowed connect is a session no S7-1500
	// can open.
	cl.write(plusFrame(wire.PlusRequest, wire.PlusExplore))
	if _, err := cl.r.Next(); err != nil {
		t.Fatalf("the session did not survive a keepalive and a connect: %v", err)
	}
	if n := p.count("plus "); n != 2 {
		t.Errorf("the controller saw %d of the two PDUs with no function: %v", n, p.saws())
	}
	if !p.got("plus explore") {
		t.Errorf("the controller saw %v", p.saws())
	}
	if n := s.Stats().Refusals["s7"]["s7comm_plus_not_allowed"]; n != 0 {
		t.Errorf("a keepalive or a connect was refused as an operation (%d refusals)", n)
	}
}

// The deny list wins over the allow list, which is the property an estate
// relies on when it allows a class and carves one function out of it.
func TestAnS7CommPlusDenyListBeatsTheAllowList(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: policy\n"+
		"          classes: [read, write, admin]\n"+
		"          deny_functions: [invoke]\n"+
		"          deny_classes: [write]\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	// Allowed by its class, denied by name.
	cl.write(plusFrame(wire.PlusRequest, wire.PlusInvoke))
	if p.got("plus invoke") {
		t.Error("a denied function reached the controller")
	}
	// Allowed by its class and denied by the class deny list.
	cl.write(plusFrame(wire.PlusRequest, wire.PlusSetVariable))
	if p.got("plus set_variable") {
		t.Error("a denied class reached the controller")
	}
	// And what neither list denies still goes.
	cl.write(plusFrame(wire.PlusRequest, wire.PlusCreateObject))
	if _, err := cl.r.Next(); err != nil {
		t.Fatalf("an allowed admin function was refused: %v", err)
	}
	waitFor(t, func() bool { return s.Stats().Refusals["s7"]["s7comm_plus_denied"] >= 2 })
}

// A client that answers is not a client. A response or a notification arriving
// from the client's side is the controller's to send, and forwarding one would
// be forwarding a message this relay has no policy for.
func TestAnS7CommPlusAnswerFromTheClientEndsTheConnection(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: passthrough\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	cl.write(plusFrame(wire.PlusResponse, wire.PlusGetMultiVariables))
	if _, err := cl.r.Next(); err == nil {
		t.Error("the connection carried on after the client sent a response")
	}
	if p.got("plus get_multi_variables") {
		t.Error("a client's response reached the controller")
	}
	waitFor(t, func() bool { return s.Stats().Refusals["s7"]["unexpected_message"] >= 1 })
}

// deny_response close is available for an estate that would rather a refused
// S7comm-plus request ended the session than vanished, which matters because
// there is no refusal to write in this protocol.
func TestDenyResponseCloseEndsAnS7CommPlusSession(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+
		"        deny_response: close\n"+
		"        s7comm_plus:\n"+
		"          mode: policy\n"+
		"          classes: [read]\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	cl.write(plusFrame(wire.PlusRequest, wire.PlusInvoke))
	if _, err := cl.r.Next(); err == nil {
		t.Error("deny_response close left the session up")
	}
	if p.got("plus invoke") {
		t.Error("the refused request reached the controller")
	}
}

// Shadow mode is a trial, and it has to carry S7comm-plus like everything else
// -- except the refusals marked hard, which are not policy: refusing the
// variant outright, and read_only.
func TestAnS7CommPlusPolicyInShadowModeRecordsWithoutRefusing(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+
		"        s7comm_plus:\n"+
		"          mode: policy\n"+
		"          classes: [read]\n"+
		"      policy: {mode: shadow}\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	cl.write(plusFrame(wire.PlusRequest, wire.PlusInvoke))
	if _, err := cl.r.Next(); err != nil {
		t.Fatalf("a shadowed refusal did not carry the request: %v", err)
	}
	if !p.got("plus invoke") {
		t.Fatalf("a shadowed request never reached the controller: %v", p.saws())
	}
	waitFor(t, func() bool { return s.Stats().WouldRefusals["s7"]["s7comm_plus_not_allowed"] >= 1 })
	if n := s.Stats().Refusals["s7"]["s7comm_plus_not_allowed"]; n != 0 {
		t.Errorf("a shadowed listener counted %d real refusals", n)
	}
}
