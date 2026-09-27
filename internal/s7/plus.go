package s7

import (
	"encoding/binary"
	"fmt"
)

// S7comm-plus: the protocol an S7-1200 or S7-1500 speaks to TIA Portal.
//
// It rides the same TPKT and COTP stack as classic S7comm and is a different
// protocol above them, announced by a protocol identifier of 0x72 where
// classic S7comm uses 0x32. An estate that has bought a controller since
// about 2012 is speaking it, so a relay in front of one that understood only
// 0x32 would not be a relay in front of that controller at all.
//
// **What can be read, and what cannot.** Less than in classic S7comm, and
// the difference is not this package's to fix. From firmware 4 onward the
// session is integrity-protected and the interesting parts of a request are
// encrypted under a key the two ends derive; a relay in the middle sees the
// outer framing and no more. So this reads the outer framing -- the PDU
// type, the opcode, and the function code of a request or response -- and
// stops. The object identifiers, the variable addresses and the values are
// opaque, and a relay that claimed to police them would be claiming to read
// something it cannot see.
//
// **Where the field values come from.** Siemens publishes no specification
// for either S7comm or S7comm-plus. The classic protocol above is read the
// way Wireshark's dissector and the open libraries read it; the same is true
// here, and the function codes below are the ones that public reverse
// engineering agrees on. That is a weaker footing than an RFC, and the
// design accounts for it in one specific way: **a function this package
// cannot name is reported as unnamed rather than guessed at**, and the
// listener kind decides an unnamed function by its default action. So a
// function code that is wrong or missing from the table below fails closed
// -- it does not become an operation the relay silently permits.
//
// Nothing here is parsed past what a policy is written about, which is the
// same rule the classic PDU follows. In particular the sequence number is
// *not* read: its offset differs between the opcodes and nothing in a policy
// needs it, so reading it would be a field this package could misread for no
// gain.

// PlusProtocolID is the first octet of an S7comm-plus PDU.
const PlusProtocolID = 0x72

// PlusHeaderLen is the fixed header: the protocol identifier, the PDU type
// and a two-octet length covering the data that follows it.
const PlusHeaderLen = 4

// The PDU types: the second octet.
const (
	// PlusConnect is the opening PDU of a session.
	PlusConnect uint8 = 0x01
	// PlusData carries a request, a response or a notification.
	PlusData uint8 = 0x02
	// PlusDataFW15 is the same thing as spoken by firmware 1.5.
	PlusDataFW15 uint8 = 0x03
	// PlusKeepalive carries nothing.
	PlusKeepalive uint8 = 0xFF
)

func plusTypeName(t uint8) string {
	switch t {
	case PlusConnect:
		return "connect"
	case PlusData:
		return "data"
	case PlusDataFW15:
		return "data_fw1.5"
	case PlusKeepalive:
		return "keepalive"
	}
	return fmt.Sprintf("type_%#x", t)
}

// The opcodes: the first octet of the data part.
const (
	PlusRequest      uint8 = 0x31
	PlusResponse     uint8 = 0x32
	PlusNotification uint8 = 0x33
	// PlusResponse2 is a second response opcode, which the HMI of TIA Portal
	// V13 uses for cyclic data. It is a response like 0x32 and carries a
	// function code in the same place, and a relay that knew only the other
	// three would have had a hole exactly one octet wide: a client that set
	// this opcode carried a function code past a policy that never read one.
	PlusResponse2 uint8 = 0x02
)

func plusOpcodeName(o uint8) string {
	switch o {
	case PlusRequest:
		return "request"
	case PlusResponse:
		return "response"
	case PlusResponse2:
		return "response2"
	case PlusNotification:
		return "notification"
	}
	return fmt.Sprintf("opcode_%#x", o)
}

// plusCarriesFunction says whether an opcode is followed by two reserved
// octets and a function code.
//
// Every opcode but the notification is: a notification is the controller
// reporting against a subscription and its data part has a different shape.
// This is deliberately "everything except" rather than a list of the three
// that do, because that is how the protocol behaves -- an opcode this package
// has never seen still has a function code where the others keep theirs, and
// a relay that read one only for the opcodes it recognised would let an
// unrecognised opcode carry an operation past the policy.
func plusCarriesFunction(o uint8) bool { return o != PlusNotification }

// The function codes of a request or a response.
//
// These are what a policy on this protocol is written about, because they are
// the only thing in it a relay can still see. The names are the ones public
// reverse engineering uses, so that a rule reads the same way as the capture
// an engineer is looking at.
const (
	PlusExplore           uint16 = 0x04BB
	PlusCreateObject      uint16 = 0x04CA
	PlusDeleteObject      uint16 = 0x04D4
	PlusSetVariable       uint16 = 0x04F2
	PlusGetLink           uint16 = 0x0524
	PlusSetMultiVariables uint16 = 0x0542
	PlusGetMultiVariables uint16 = 0x054C
	PlusBeginSequence     uint16 = 0x0556
	PlusEndSequence       uint16 = 0x0560
	PlusInvoke            uint16 = 0x056B
	PlusGetVarSubStreamed uint16 = 0x0586
)

var plusFunctionNames = map[uint16]string{
	PlusExplore:           "explore",
	PlusCreateObject:      "create_object",
	PlusDeleteObject:      "delete_object",
	PlusSetVariable:       "set_variable",
	PlusGetLink:           "get_link",
	PlusSetMultiVariables: "set_multi_variables",
	PlusGetMultiVariables: "get_multi_variables",
	PlusBeginSequence:     "begin_sequence",
	PlusEndSequence:       "end_sequence",
	PlusInvoke:            "invoke",
	PlusGetVarSubStreamed: "get_var_sub_streamed",
}

// PlusFunctionName names a function code, or says it has no name here.
//
// The unnamed form carries the number, because a refusal an engineer cannot
// look up is a refusal they cannot act on -- and on a protocol read from the
// wire rather than from a specification, the numbers that turn up in the
// field are how the table gets longer.
func PlusFunctionName(f uint16) (string, bool) {
	if n, ok := plusFunctionNames[f]; ok {
		return n, true
	}
	return fmt.Sprintf("function_%#04x", f), false
}

// PlusFunctionOf reads a function code by name or by number, for a rule.
func PlusFunctionOf(s string) (uint16, bool) {
	for f, n := range plusFunctionNames {
		if n == s {
			return f, true
		}
	}
	return 0, false
}

// PlusClass is what a function does, in the three words a plant policy is
// written in.
//
// The mapping is a judgement rather than something the protocol states, so
// every function can also be named on its own in a rule, and this is what a
// rule that names none of them falls back to. An engineer who disagrees with
// one of these can say so in a rule; an engineer who cannot see the mapping
// at all would be trusting it blind.
type PlusClass string

// The three classes, and the one that means "this relay does not know".
const (
	// PlusRead browses or reads: the operations an HMI and a historian make.
	PlusRead PlusClass = "read"
	// PlusWrite changes a value.
	PlusWrite PlusClass = "write"
	// PlusAdmin changes the program or the controller: creating and deleting
	// objects, calling a method, and the sequences a download runs inside.
	// On this protocol family a download and a mode change are Invoke calls,
	// which is why Invoke is here and not with the reads.
	PlusAdmin PlusClass = "admin"
	// PlusUnknown is a function this package cannot name. It is a class of
	// its own rather than a default, because "the relay does not know what
	// this is" is a different fact from "the relay knows it is a read", and
	// an operator should be able to write a rule about it.
	PlusUnknown PlusClass = "unknown"
	// PlusOpaque is a PDU whose function code this relay cannot *locate*,
	// rather than one it cannot name: a firmware-1.5 data PDU, where an
	// integrity block of variable length sits in front of the opcode. It is
	// separate from unknown because the two ask an operator a different
	// question -- unknown is "allow an operation I cannot name", opaque is
	// "allow a PDU I cannot inspect at all" -- and an S7-1500 on current
	// firmware sends the second constantly, so an estate that wants those
	// controllers working has to answer it knowingly.
	PlusOpaque PlusClass = "opaque"
)

var plusClasses = map[uint16]PlusClass{
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
}

// PlusClassOf says what a function does.
func PlusClassOf(f uint16) PlusClass {
	if c, ok := plusClasses[f]; ok {
		return c
	}
	return PlusUnknown
}

// PlusClassOf a name, for a rule.
func PlusClassNamed(s string) (PlusClass, bool) {
	switch PlusClass(s) {
	case PlusRead, PlusWrite, PlusAdmin, PlusUnknown, PlusOpaque:
		return PlusClass(s), true
	}
	return "", false
}

// PlusPDU is an S7comm-plus PDU, read as far as a policy needs.
type PlusPDU struct {
	// Type is the PDU type octet.
	Type uint8
	// DataLen is the length the header declared, which this package has
	// already checked against the octets that arrived.
	DataLen int
	// Opcode is the first octet of the data part, and HasOpcode says the data
	// part was long enough to have one.
	//
	// On a data PDU that octet *is* the opcode. On a connect PDU it is the
	// start of a different structure that happens to sit in the same place, so
	// only the three values this package names are ever acted on: reading
	// meaning into the others would be reading meaning into a field that is
	// not there. A keepalive has no data part at all.
	Opcode    uint8
	HasOpcode bool
	// Function is the function code of a request or a response, and
	// HasFunction says one was there to read.
	Function    uint16
	HasFunction bool
}

// IsPlus says whether a COTP data PDU carries S7comm-plus rather than
// classic S7comm, which is one octet's worth of question and the reason a
// relay can tell the two apart before it tries to parse either.
func IsPlus(b []byte) bool { return len(b) > 0 && b[0] == PlusProtocolID }

// ParsePlus reads an S7comm-plus PDU.
//
// The declared length is checked against what arrived, and that check is what
// makes the rest of this safe to rely on: the length is the one field in the
// header that the frame itself can contradict, so a header this package has
// misread shows up here as a frame that does not add up rather than as a
// policy decided on a misread field. A PDU whose length overruns the frame is
// refused; the trailing octets after the data are the trailer, which carries
// nothing a policy is about.
func ParsePlus(b []byte) (*PlusPDU, error) {
	if len(b) < PlusHeaderLen {
		return nil, fmt.Errorf("an S7comm-plus header of %d octets is shorter than its own fields", len(b))
	}
	if b[0] != PlusProtocolID {
		return nil, fmt.Errorf("not an S7comm-plus PDU: the protocol identifier is %#x", b[0])
	}
	p := &PlusPDU{Type: b[1]}
	if p.Type == PlusKeepalive {
		// A keepalive has no length field at all: it is four octets, and the
		// two after the PDU type are a sequence number and a reserved octet
		// rather than a length. Reading them as a length made a keepalive
		// whose sequence number happened to be large look like a PDU that
		// overran its frame -- which a relay refuses, so a link that was
		// merely idle was dropped.
		return p, nil
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if PlusHeaderLen+n > len(b) {
		return nil, fmt.Errorf("an S7comm-plus data length of %d runs past the %d octets that arrived", n, len(b)-PlusHeaderLen)
	}
	p.DataLen = n
	if p.Type == PlusDataFW15 {
		// Firmware 1.5 and above moved the integrity block from the end of
		// the data part to the front of it, and that block begins with a
		// variable-length integer -- so the opcode is not at a fixed offset
		// here and this package does not guess where it is. The PDU is
		// reported with no opcode and no function, which makes it the
		// Opaque class, and the listener decides it explicitly. Reading a
		// function code out of a digest would be worse than admitting the
		// offset is unknown.
		return p, nil
	}
	data := b[PlusHeaderLen : PlusHeaderLen+n]
	if len(data) == 0 {
		return p, nil
	}
	p.Opcode, p.HasOpcode = data[0], true
	// The function code follows the opcode and two octets the protocol holds
	// at zero.
	if !plusCarriesFunction(p.Opcode) {
		return p, nil
	}
	if len(data) < 5 {
		// The opcode said there is a function and the data is too short to
		// hold one. That is a PDU this package cannot read rather than one
		// with no function, and the two must not look the same to a policy.
		return nil, fmt.Errorf("an S7comm-plus %s of %d octets is too short to carry a function code",
			plusOpcodeName(p.Opcode), len(data))
	}
	p.Function = binary.BigEndian.Uint16(data[3:5])
	p.HasFunction = true
	return p, nil
}

// TypeName names the PDU type.
func (p *PlusPDU) TypeName() string {
	if p == nil {
		return ""
	}
	return plusTypeName(p.Type)
}

// OpcodeName names the opcode, or "" when there was none.
func (p *PlusPDU) OpcodeName() string {
	if p == nil || !p.HasOpcode {
		return ""
	}
	return plusOpcodeName(p.Opcode)
}

// FunctionName names the function, or "" when there was none. The second
// result says whether this package recognised it.
func (p *PlusPDU) FunctionName() (string, bool) {
	if p == nil || !p.HasFunction {
		return "", false
	}
	return PlusFunctionName(p.Function)
}

// Class is what this PDU does. A PDU with no function code is Unknown: a
// keepalive changes nothing, but so does a policy that guessed.
func (p *PlusPDU) Class() PlusClass {
	if p == nil {
		return PlusUnknown
	}
	if p.Type == PlusDataFW15 {
		return PlusOpaque
	}
	if !p.HasFunction {
		return PlusUnknown
	}
	return PlusClassOf(p.Function)
}

// IsAnswer says whether this PDU is one only a controller sends: a response,
// or a notification against a subscription.
//
// It is deliberately a test for the two opcodes that *are* answers rather than
// for "not a request". A connect PDU's data begins with a different structure
// in the same position, and a keepalive has no data at all, so "the first octet
// is not 0x31" is true of several PDUs a client legitimately sends -- a relay
// that refused all of them would be a relay no S7-1500 could open a session
// through. Only what can be positively identified as an answer is treated as
// one.
func (p *PlusPDU) IsAnswer() bool {
	if p == nil || !p.HasOpcode {
		return false
	}
	return p.Opcode == PlusResponse || p.Opcode == PlusResponse2 || p.Opcode == PlusNotification
}
