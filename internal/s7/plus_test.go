package s7

import (
	"encoding/binary"
	"testing"
)

// build makes an S7comm-plus PDU with a header the caller controls, so a test
// can lie about the length on purpose.
func plusBuild(pduType uint8, declared int, data []byte) []byte {
	b := []byte{PlusProtocolID, pduType}
	b = binary.BigEndian.AppendUint16(b, uint16(declared)) //nolint:gosec // a test's own number
	return append(b, data...)
}

func plusRequest(fn uint16) []byte {
	d := []byte{PlusRequest, 0x00, 0x00}
	d = binary.BigEndian.AppendUint16(d, fn)
	return plusBuild(PlusData, len(d), d)
}

// One octet is what tells the two protocols apart, and everything downstream
// depends on getting that right: a classic PDU read as plus, or the reverse,
// would be a policy applied from the wrong vocabulary.
func TestTheTwoProtocolsAreToldApartByOneOctet(t *testing.T) {
	t.Parallel()
	if !IsPlus([]byte{PlusProtocolID, PlusData, 0, 0}) {
		t.Error("an S7comm-plus PDU was not recognised")
	}
	for what, b := range map[string][]byte{
		"classic S7comm": {ProtocolID, 0x01, 0, 0},
		"empty":          {},
		"something else": {0x03, 0x00},
	} {
		if IsPlus(b) {
			t.Errorf("%s was read as S7comm-plus", what)
		}
	}
}

func TestARequestIsReadAsFarAsThePolicyNeeds(t *testing.T) {
	t.Parallel()
	p, err := ParsePlus(plusRequest(PlusGetMultiVariables))
	if err != nil {
		t.Fatalf("ParsePlus: %v", err)
	}
	if p.Type != PlusData || p.TypeName() != "data" {
		t.Errorf("type %#x (%s)", p.Type, p.TypeName())
	}
	if !p.HasOpcode || p.Opcode != PlusRequest || p.OpcodeName() != "request" {
		t.Errorf("opcode %#x (%s)", p.Opcode, p.OpcodeName())
	}
	if !p.HasFunction || p.Function != PlusGetMultiVariables {
		t.Errorf("function %#x", p.Function)
	}
	if name, known := p.FunctionName(); name != "get_multi_variables" || !known {
		t.Errorf("name %q known %v", name, known)
	}
	if p.Class() != PlusRead {
		t.Errorf("class %q", p.Class())
	}
	if p.IsAnswer() {
		t.Error("a request read as an answer")
	}
}

// The declared length is the one header field the frame itself can contradict,
// which is what makes the rest of the parse safe to rely on: a header this
// package has misread shows up as a frame that does not add up, rather than as
// a policy decided on a misread field.
func TestALengthThatDoesNotAgreeWithTheFrameIsRefused(t *testing.T) {
	t.Parallel()
	for what, b := range map[string][]byte{
		"a length past the frame":     plusBuild(PlusData, 64, []byte{PlusRequest}),
		"a header on its own":         {PlusProtocolID, PlusData, 0x00},
		"nothing":                     {},
		"the wrong protocol":          {ProtocolID, 0x01, 0x00, 0x00},
		"a request with no function":  plusBuild(PlusData, 3, []byte{PlusRequest, 0, 0}),
		"a response with no function": plusBuild(PlusData, 4, []byte{PlusResponse, 0, 0, 0}),
	} {
		if _, err := ParsePlus(b); err == nil {
			t.Errorf("%s parsed", what)
		}
	}
	// A length *shorter* than what arrived is not an error: the octets after
	// the data are the trailer, which carries nothing a policy is about.
	d := []byte{PlusRequest, 0, 0, 0x04, 0xBB}
	withTrailer := append(plusBuild(PlusData, len(d), d), PlusProtocolID, 0x01, 0x00, 0x00)
	p, err := ParsePlus(withTrailer)
	if err != nil {
		t.Fatalf("a PDU with a trailer was refused: %v", err)
	}
	if p.Function != PlusExplore {
		t.Errorf("the trailer moved the function: %#x", p.Function)
	}
}

// A PDU with no function code is not a PDU with function zero, and the two
// must not look the same to a policy: one is a keepalive, the other would be a
// decision made up.
func TestThePDUsThatCarryNoFunction(t *testing.T) {
	t.Parallel()
	for what, b := range map[string][]byte{
		"a keepalive":        {PlusProtocolID, PlusKeepalive, 0x07, 0x00},
		"a notification":     plusBuild(PlusData, 1, []byte{PlusNotification}),
		"an empty data part": plusBuild(PlusData, 0, nil),
	} {
		p, err := ParsePlus(b)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if p.HasFunction {
			t.Errorf("%s was given a function code", what)
		}
		if p.Class() != PlusUnknown {
			t.Errorf("%s got class %q, want unknown", what, p.Class())
		}
		if name, known := p.FunctionName(); name != "" || known {
			t.Errorf("%s named a function %q", what, name)
		}
	}
	// A connect PDU is not one of them: the session setup carries a request
	// with a function code in the same place a data PDU does, so a connect
	// whose data part is too short to hold one is malformed rather than a
	// connect with nothing to decide.
	if _, err := ParsePlus(plusBuild(PlusConnect, 1, []byte{0x00})); err == nil {
		t.Error("a connect PDU too short for its function code parsed")
	}
	full := []byte{PlusRequest, 0x00, 0x00, 0x04, 0xCA} // create_object, the session setup
	c, err := ParsePlus(plusBuild(PlusConnect, len(full), full))
	if err != nil {
		t.Fatalf("a connect PDU carrying its request was refused: %v", err)
	}
	if !c.HasFunction || c.Function != PlusCreateObject {
		t.Errorf("the connect PDU's function was not read: %+v", c)
	}
}

// Only what is positively an answer is an answer. A connect PDU's data starts
// with a different structure in the same position, so "not a request" is true
// of several PDUs a client legitimately sends -- and a relay that refused all
// of them would be one no S7-1500 could open a session through.
func TestOnlyAResponseOrANotificationIsAnAnswer(t *testing.T) {
	t.Parallel()
	for what, c := range map[string]struct {
		b    []byte
		want bool
	}{
		"a request":      {plusRequest(PlusExplore), false},
		"a response":     {plusBuild(PlusData, 5, []byte{PlusResponse, 0, 0, 0x04, 0xBB}), true},
		"a notification": {plusBuild(PlusData, 1, []byte{PlusNotification}), true},
		"a keepalive":    {[]byte{PlusProtocolID, PlusKeepalive, 0x07, 0x00}, false},
		"a connect":      {plusBuild(PlusConnect, 5, []byte{PlusRequest, 0, 0, 0x04, 0xCA}), false},
	} {
		p, err := ParsePlus(c.b)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if got := p.IsAnswer(); got != c.want {
			t.Errorf("%s: IsAnswer %v, want %v", what, got, c.want)
		}
	}
}

// A function this package cannot name says so, carrying the number, because a
// refusal an engineer cannot look up is one they cannot act on -- and on a
// protocol read from the wire the numbers that turn up in the field are how
// the table gets longer.
func TestAnUnnamedFunctionCarriesItsNumber(t *testing.T) {
	t.Parallel()
	name, known := PlusFunctionName(0x7777)
	if known {
		t.Error("an invented function code was recognised")
	}
	if name != "function_0x7777" {
		t.Errorf("name %q", name)
	}
	if PlusClassOf(0x7777) != PlusUnknown {
		t.Errorf("class %q", PlusClassOf(0x7777))
	}
	// And a name round-trips, so a rule written with the name this package
	// prints in a log matches the function that log line was about.
	for f := range plusFunctionNames {
		n, known := PlusFunctionName(f)
		if !known {
			t.Errorf("%#x is in the table and not known", f)
		}
		if got, ok := PlusFunctionOf(n); !ok || got != f {
			t.Errorf("%q round-tripped to %#x (%v)", n, got, ok)
		}
	}
}

// Every named function has a class, and every class is one of the three the
// configuration accepts. A function in the table with no class would be an
// operation that silently became `unknown`, which is the one classification an
// operator has to opt into.
func TestEveryNamedFunctionHasARealClass(t *testing.T) {
	t.Parallel()
	for f, name := range plusFunctionNames {
		switch c := PlusClassOf(f); c {
		case PlusRead, PlusWrite, PlusAdmin:
		default:
			t.Errorf("%s (%#x) has class %q", name, f, c)
		}
	}
	for _, c := range []string{"read", "write", "admin", "unknown"} {
		if _, ok := PlusClassNamed(c); !ok {
			t.Errorf("%q is not a class the configuration accepts", c)
		}
	}
	if _, ok := PlusClassNamed("program"); ok {
		t.Error("an invented class was accepted")
	}
}

// The classification is a judgement rather than something the protocol states,
// so it is written down where a reviewer can disagree with it. The two that
// matter: a download and a mode change on this family are Invoke calls, and
// creating or deleting an object is a program change -- neither is a read.
func TestTheClassificationSaysWhatItMeans(t *testing.T) {
	t.Parallel()
	for f, want := range map[uint16]PlusClass{
		PlusExplore:           PlusRead,
		PlusGetLink:           PlusRead,
		PlusGetMultiVariables: PlusRead,
		PlusGetVarSubStreamed: PlusRead,
		PlusSetVariable:       PlusWrite,
		PlusSetMultiVariables: PlusWrite,
		PlusCreateObject:      PlusAdmin,
		PlusDeleteObject:      PlusAdmin,
		PlusInvoke:            PlusAdmin,
		PlusBeginSequence:     PlusAdmin,
		PlusEndSequence:       PlusAdmin,
	} {
		if got := PlusClassOf(f); got != want {
			name, _ := PlusFunctionName(f)
			t.Errorf("%s: class %q, want %q", name, got, want)
		}
	}
}

// The three things reading the dissector's own source corrected, each of which
// was a defect in this package rather than a gap.

// A keepalive has no length field. Its two octets after the PDU type are a
// sequence number and a reserved octet, so reading them as a data length made a
// keepalive with a large sequence number look like a PDU that overran its
// frame -- and an overrun is refused, so an idle link was dropped.
func TestAKeepaliveHasNoLengthField(t *testing.T) {
	t.Parallel()
	for _, seq := range []byte{0x00, 0x01, 0x40, 0x7f, 0xff} {
		b := []byte{PlusProtocolID, PlusKeepalive, seq, 0x00}
		p, err := ParsePlus(b)
		if err != nil {
			t.Fatalf("a keepalive with sequence %#x was refused: %v", seq, err)
		}
		if p.HasOpcode || p.HasFunction || p.DataLen != 0 {
			t.Errorf("sequence %#x: %+v", seq, p)
		}
		if p.Class() != PlusUnknown {
			t.Errorf("sequence %#x: class %q", seq, p.Class())
		}
	}
}

// A function code is read for every opcode but the notification, which is what
// the protocol does. Reading it only for the two opcodes this package first
// knew about left a hole one octet wide: opcode 0x02 is a second response the
// V13 HMI uses, and a client that set it carried a function code past a policy
// that never looked at one.
func TestEveryOpcodeButANotificationCarriesAFunction(t *testing.T) {
	t.Parallel()
	for _, op := range []uint8{PlusRequest, PlusResponse, PlusResponse2, 0x77} {
		d := []byte{op, 0x00, 0x00, 0x05, 0x6B} // invoke
		p, err := ParsePlus(plusBuild(PlusData, len(d), d))
		if err != nil {
			t.Fatalf("opcode %#x: %v", op, err)
		}
		if !p.HasFunction || p.Function != PlusInvoke {
			t.Errorf("opcode %#x did not carry its function: %+v", op, p)
		}
		if p.Class() != PlusAdmin {
			t.Errorf("opcode %#x: class %q, want admin", op, p.Class())
		}
	}
	// The notification is the exception, and its data part has another shape.
	d := []byte{PlusNotification, 0x00, 0x00, 0x05, 0x6B}
	p, err := ParsePlus(plusBuild(PlusData, len(d), d))
	if err != nil {
		t.Fatal(err)
	}
	if p.HasFunction {
		t.Errorf("a notification was given a function code: %+v", p)
	}
}

// A second response opcode is still a response, so a client sending one is a
// client answering -- which it has no business doing.
func TestTheSecondResponseOpcodeIsAnAnswer(t *testing.T) {
	t.Parallel()
	d := []byte{PlusResponse2, 0x00, 0x00, 0x05, 0x4C}
	p, err := ParsePlus(plusBuild(PlusData, len(d), d))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsAnswer() {
		t.Error("opcode 0x02 was not read as an answer")
	}
}

// Firmware 1.5 moved a variable-length integrity block to the front of the data
// part, so the opcode is not at a fixed offset there. This package says it
// cannot locate the function rather than reading one out of a digest, and the
// PDU gets a class of its own so an operator answers the question knowingly.
func TestAFirmware15DataPDUIsOpaqueRatherThanGuessedAt(t *testing.T) {
	t.Parallel()
	// The octets that would be an opcode and a function if the integrity
	// block were not in front of them.
	d := []byte{PlusRequest, 0x00, 0x00, 0x05, 0x6B, 0x20}
	p, err := ParsePlus(plusBuild(PlusDataFW15, len(d), d))
	if err != nil {
		t.Fatalf("a firmware 1.5 data PDU was refused: %v", err)
	}
	if p.HasOpcode || p.HasFunction {
		t.Errorf("the integrity block was read as an opcode and a function: %+v", p)
	}
	if p.Class() != PlusOpaque {
		t.Errorf("class %q, want opaque", p.Class())
	}
	if _, ok := PlusClassNamed("opaque"); !ok {
		t.Error("opaque is not a class the configuration accepts")
	}
	// And it is a different answer from unknown, because it asks the operator
	// a different question.
	if PlusOpaque == PlusUnknown {
		t.Error("opaque and unknown are the same class")
	}
}
