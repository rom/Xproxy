// Package iec104 reads IEC 60870-5-104, the telecontrol protocol that
// runs electricity transmission and distribution.
//
// It is the grid's Modbus: a controlling station (the SCADA master) and a
// controlled station (a substation gateway or an RTU) exchange application
// service data units over a plain TCP connection on port 2404, with no
// authentication, no integrity and no confidentiality anywhere in the
// standard. IEC 62351-3 adds TLS around it and almost nothing deployed
// uses it, because the controlled stations are substation equipment with
// twenty-year service lives.
//
// What the protocol *does* have is structure, and the structure is what a
// relay can enforce:
//
//   - Every APDU begins with 0x68 and a length, so the framing is
//     unambiguous -- unlike Modbus over a terminal server.
//   - A frame is one of three formats. **I** carries data and is
//     sequence-numbered in both directions. **S** acknowledges received
//     I frames and carries nothing. **U** is an unnumbered control
//     function: start, stop, or test the data transfer.
//   - An I frame's ASDU says what it is in a fixed header: a *type
//     identification* (measurement, command, file transfer...), a *cause
//     of transmission* (spontaneous, request, activation...), and a
//     *common address* naming the station.
//   - The commands -- single, double, regulating step, setpoint, and the
//     two that reset or reboot equipment -- are a small, numbered,
//     enumerable set. A relay can allow the ones a control centre has any
//     business sending and refuse the rest, which is a thing no substation
//     gateway does.
//   - The dangerous commands have a two-step form: *select* (activation
//     with the S/E bit set) then *execute*. The standard describes it; the
//     equipment mostly does not enforce it. A relay can.
//
// This package reads. The policy lives in the listener kind.
package iec104

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// Start is the first octet of every APDU.
const Start = 0x68

// The fixed sizes of the protocol.
const (
	// APCILen is the application protocol control information: the start
	// octet, the length, and four control octets.
	APCILen = 6
	// MaxLength is the largest value the length octet can carry, and so
	// the largest APDU body. It is one octet, so an APDU is at most 255
	// octets of body -- which is why this protocol needs no bound of its
	// own beyond reading the field.
	MaxLength = 255
	// MinLength is the smallest body: the four control octets of an S or
	// U frame.
	MinLength = 4
	// ASDUHeaderLen is the type identification, the variable structure
	// qualifier, the cause of transmission with its originator address,
	// and the two-octet common address.
	ASDUHeaderLen = 6
	// MaxSeq is the sequence number space: twelve bits, wrapping.
	MaxSeq = 1 << 15
)

// Format is which of the three APDU formats a frame is.
type Format int

// The three formats.
const (
	// FormatI carries an ASDU and is numbered in both directions.
	FormatI Format = iota
	// FormatS acknowledges received I frames.
	FormatS
	// FormatU is an unnumbered control function.
	FormatU
)

// String names a format the way the standard does.
func (f Format) String() string {
	switch f {
	case FormatS:
		return "S"
	case FormatU:
		return "U"
	}
	return "I"
}

// The U-format control functions, as the bit pairs of the first control
// octet. They come in confirmed pairs: a station sends the activation and
// its peer answers the confirmation.
type Control byte

// The six control functions.
const (
	StartDTAct Control = 0x07
	StartDTCon Control = 0x0b
	StopDTAct  Control = 0x13
	StopDTCon  Control = 0x23
	TestFRAct  Control = 0x43
	TestFRCon  Control = 0x83
)

// String names a control function.
func (c Control) String() string {
	switch c {
	case StartDTAct:
		return "STARTDT_act"
	case StartDTCon:
		return "STARTDT_con"
	case StopDTAct:
		return "STOPDT_act"
	case StopDTCon:
		return "STOPDT_con"
	case TestFRAct:
		return "TESTFR_act"
	case TestFRCon:
		return "TESTFR_con"
	}
	return fmt.Sprintf("U(%#02x)", byte(c))
}

// ControlOf reads a control function name as the configuration spells it.
func ControlOf(s string) (Control, bool) {
	switch s {
	case "STARTDT_act", "startdt_act":
		return StartDTAct, true
	case "STARTDT_con", "startdt_con":
		return StartDTCon, true
	case "STOPDT_act", "stopdt_act":
		return StopDTAct, true
	case "STOPDT_con", "stopdt_con":
		return StopDTCon, true
	case "TESTFR_act", "testfr_act":
		return TestFRAct, true
	case "TESTFR_con", "testfr_con":
		return TestFRCon, true
	}
	return 0, false
}

// Errors this package returns. Each names a way a frame is not one,
// because a relay that forwarded a frame it could not read would be
// forwarding what it could not decide about -- and the station behind it
// will read those octets somehow.
var (
	// ErrStart is a first octet that is not 0x68. On this protocol that
	// means the stream is not synchronised, and a reader that hunted for
	// the next start octet would hand the station a frame beginning in
	// the middle of the last one.
	ErrStart = errors.New("iec104: not a start octet")
	// ErrLength is a length octet outside the four-to-253 range the
	// formats allow.
	ErrLength = errors.New("iec104: bad apdu length")
	// ErrShortASDU is an I frame whose body cannot hold an ASDU header.
	ErrShortASDU = errors.New("iec104: apdu too short for an asdu header")
	// ErrObjects is a variable structure qualifier that does not agree
	// with the octets that follow it.
	ErrObjects = errors.New("iec104: object count does not match the asdu")
)

// Frame is one APDU: its format, whatever the format carries, and the
// octets it arrived in.
type Frame struct {
	Format Format
	// Send and Recv are the sequence numbers of an I frame; Recv alone
	// for an S frame. They are the values, already shifted out of the
	// control octets.
	Send, Recv uint16
	// Control is the function of a U frame.
	Control Control
	// ASDU is the parsed application service data unit of an I frame.
	ASDU *ASDU
	// Raw is the whole APDU, start octet included. A relay forwards
	// these octets rather than re-encoding: re-encoding is how a relay
	// and a station come to disagree about what was said.
	Raw []byte
}

// ASDU is the application service data unit of an I frame, parsed as far
// as policy needs and no further.
//
// The header is read here, and with it the addresses and the two octets a
// command carries. The information *elements* -- a value, its quality
// descriptor, its time tag -- are read on demand by Elements, because most
// frames are telemetry and most listeners have nothing to ask about them.
//
// Nothing is ever re-encoded. Every frame is forwarded as the octets that
// arrived: decoding a hundred-odd types into a second implementation of the
// standard and writing them back out is how a relay and a station come to
// disagree about a reading nobody can trace. Elements reads; it does not
// rewrite.
type ASDU struct {
	// Type is the type identification: what this ASDU is.
	Type Type
	// Objects is the number of information objects (or, for a sequence,
	// the number of elements).
	Objects int
	// Sequence says the addresses are implied by the first one rather
	// than carried per object.
	Sequence bool
	// Cause is the cause of transmission, without its two flag bits.
	Cause Cause
	// Negative and Test are the two flags that share the cause octet.
	Negative, Test bool
	// Originator is the originator address: which controlling station,
	// where a controlled station talks to several.
	Originator byte
	// Common is the common address of the ASDU: which station.
	Common uint16
	// Addresses are the information object addresses, in order. For a
	// sequence only the first is carried on the wire and this holds
	// that one.
	Addresses []uint32
	// Select is true when the first command object has its select
	// bit set: the first half of select-before-operate.
	Select bool
	// Qualifier is the command's qualifier octets as they arrived, for
	// the value bounds a policy may set. Empty for a type that carries
	// no command.
	Qualifier []byte
}

// Reader reads APDUs from a stream.
type Reader struct {
	r   io.Reader
	buf []byte
}

// NewReader reads frames from one side of a connection.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r, buf: make([]byte, 0, APCILen+MaxLength)}
}

// ReadFrame reads one APDU.
//
// A frame that cannot be read is an error and not a resynchronisation: on
// a protocol whose framing is a start octet and a length, a reader that
// hunted for the next 0x68 would find one inside a measurement's payload
// as often as at a frame boundary.
func (rd *Reader) ReadFrame() (*Frame, error) {
	var head [2]byte
	if _, err := io.ReadFull(rd.r, head[:]); err != nil {
		return nil, err
	}
	if head[0] != Start {
		return nil, ErrStart
	}
	length := int(head[1])
	if length < MinLength || length > MaxLength-2 {
		return nil, ErrLength
	}
	raw := make([]byte, 2+length)
	raw[0], raw[1] = head[0], head[1]
	if _, err := io.ReadFull(rd.r, raw[2:]); err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse reads an APDU that is already in memory.
func Parse(raw []byte) (*Frame, error) {
	if len(raw) < APCILen || raw[0] != Start {
		return nil, ErrStart
	}
	if int(raw[1]) != len(raw)-2 {
		return nil, ErrLength
	}
	f := &Frame{Raw: raw}
	c1 := raw[2]
	switch {
	case c1&1 == 0:
		// An I frame: the send sequence number is the first two control
		// octets with the low bit dropped, the receive sequence number
		// the other two.
		f.Format = FormatI
		f.Send = binary.LittleEndian.Uint16(raw[2:4]) >> 1
		f.Recv = binary.LittleEndian.Uint16(raw[4:6]) >> 1
		a, err := ParseASDU(raw[APCILen:])
		if err != nil {
			return nil, err
		}
		f.ASDU = a
	case c1&3 == 1:
		f.Format = FormatS
		f.Recv = binary.LittleEndian.Uint16(raw[4:6]) >> 1
	default:
		f.Format = FormatU
		// The control function is the top six bits of the first octet
		// with its two low bits; the standard defines one bit pair set
		// at a time, and anything else is not a function this knows.
		f.Control = Control(c1)
	}
	if f.Format != FormatI && len(raw) != APCILen {
		// S and U frames carry nothing. A length that says otherwise is
		// either a frame this cannot read or a station trying to slip an
		// ASDU past a check that only looks at I frames.
		return nil, ErrLength
	}
	return f, nil
}

// ParseASDU reads the application service data unit of an I frame.
func ParseASDU(b []byte) (*ASDU, error) {
	if len(b) < ASDUHeaderLen {
		return nil, ErrShortASDU
	}
	a := &ASDU{
		Type:       Type(b[0]),
		Objects:    int(b[1] & 0x7f),
		Sequence:   b[1]&0x80 != 0,
		Cause:      Cause(b[2] & 0x3f),
		Negative:   b[2]&0x40 != 0,
		Test:       b[2]&0x80 != 0,
		Originator: b[3],
		Common:     binary.LittleEndian.Uint16(b[4:6]),
	}
	body := b[ASDUHeaderLen:]
	// The information object size is what the type identification says,
	// and a type this does not know is forwarded with its addresses
	// unread rather than guessed at: the number is what a policy about
	// types needs, and inventing a size would misreport an address.
	size, known := objectSize(a.Type)
	if !known {
		return a, nil
	}
	if a.Objects == 0 {
		// The qualifier says no objects. Some implementations send this
		// for an interrogation; it is not a frame to reject, and there
		// is nothing to read.
		return a, nil
	}
	if a.Sequence {
		// A sequence carries one address and then the elements.
		if len(body) < 3+size*a.Objects {
			return nil, ErrObjects
		}
		a.Addresses = []uint32{addr3(body)}
		if elem := body[3 : 3+size]; commandType(a.Type) {
			a.Qualifier = elem
			a.Select = selectBit(a.Type, elem)
		}
		return a, nil
	}
	if len(body) < (3+size)*a.Objects {
		return nil, ErrObjects
	}
	a.Addresses = make([]uint32, 0, a.Objects)
	for i := 0; i < a.Objects; i++ {
		at := body[i*(3+size):]
		a.Addresses = append(a.Addresses, addr3(at))
		if i == 0 && commandType(a.Type) {
			a.Qualifier = at[3 : 3+size]
			a.Select = selectBit(a.Type, a.Qualifier)
		}
	}
	return a, nil
}

// selectBit reads the select/execute bit out of a command's information
// element, from wherever that type keeps its qualifier octet.
//
// A type with no qualifier reads as an execute rather than a selection, which is
// the safe direction: an execute is what needs a prior selection, so a type that
// cannot be selected is held to the rule rather than excused from it.
func selectBit(t Type, elem []byte) bool {
	at, ok := qualifierOffset(t)
	if !ok || at >= len(elem) {
		return false
	}
	return elem[at]&0x80 != 0
}

// signed16 reads the two octets of a normalised or scaled setpoint value as
// what the standard says they are: one signed 16-bit integer, little endian.
//
// The conversion is the decoding rather than a narrowing that could lose
// something: all 65536 bit patterns are valid values, and the ones above
// 0x7fff are the negative half of the range.
func signed16(b []byte) int16 {
	return int16(binary.LittleEndian.Uint16(b)) //nolint:gosec // the standard's own signed encoding
}

// addr3 reads a three-octet information object address, little endian as
// everything in this protocol is.
func addr3(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

// Setpoint reads the value a setpoint command carries, as a float64 whatever
// the encoding on the wire was, and says whether there was one to read.
//
// One number for three encodings is deliberate: a policy about a setpoint is a
// statement about the process ("the pressure setpoint is between 0 and 40"), and
// an operator should not have to write it three times because the substation
// sends a scaled integer on one point and a short float on another. What the
// number *means* still differs -- a normalised value is a fraction of a full
// scale configured in the device, which this relay cannot see -- and the
// reference says so where a bound is configured.
//
// It reads from the same element the qualifier came from, so it is available
// wherever Select is.
func (a *ASDU) Setpoint() (float64, bool) {
	if a == nil {
		return 0, false
	}
	kind, at := SetpointEncoding(a.Type)
	if kind == NotASetpoint {
		return 0, false
	}
	e := a.Qualifier
	switch kind {
	case Normalised:
		if len(e) < at+2 {
			return 0, false
		}
		// The fraction, as the standard defines it: the signed 16-bit value
		// over 2^15, so 0x8000 is exactly -1 and 0x7fff is one step short
		// of +1. Reading the two octets as signed is the decoding, not a
		// lossy narrowing: every one of the 65536 values means something,
		// and the half above 0x7fff means a negative setpoint.
		return float64(signed16(e[at:])) / 32768, true
	case Scaled:
		if len(e) < at+2 {
			return 0, false
		}
		return float64(signed16(e[at:])), true
	case ShortFloat:
		if len(e) < at+4 {
			return 0, false
		}
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(e[at:]))), true
	}
	return 0, false
}
