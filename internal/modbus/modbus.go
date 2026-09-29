// Package modbus reads Modbus the way a relay has to read it: every
// frame, in both directions, as the thing it actually is.
//
// Modbus has no authentication, no integrity and no notion of a session.
// A frame says which device it is for (the unit identifier), what to do
// (the function code) and where (the address and quantity), and the
// device does it. That is the whole protocol, which is why it is still
// running plants built before the word "firewall" meant anything -- and
// why the only place a policy can exist is between the master and the
// slave, reading the frames.
//
// So this package parses rather than pattern-matches. A relay that
// looked for "function code 6" in a byte stream would be fooled by the
// same byte inside a register value, and a relay that forwarded what it
// could not parse would be forwarding what it could not decide about.
// Every frame is read whole, and a frame that does not parse is a frame
// the relay refuses -- because the slave behind it will read those bytes
// somehow, and "somehow" is the attack.
//
// What is implemented: the public function codes of the Modbus
// Application Protocol v1.1b3, the MBAP framing of Modbus/TCP, the RTU
// and ASCII framings as they are tunnelled over TCP, and the exception
// responses. Serial line electrical framing is not here, because a relay
// on a serial line is a different device; what arrives here is a stream
// or a datagram.
package modbus

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The MBAP header of Modbus/TCP: transaction identifier, protocol
// identifier, length, unit identifier (MODBUS Messaging on TCP/IP
// Implementation Guide v1.0b section 4.1).
const (
	// HeaderLen is the MBAP header: 2 transaction, 2 protocol, 2
	// length, 1 unit.
	HeaderLen = 7
	// ProtocolID is the only protocol identifier Modbus/TCP defines.
	ProtocolID = 0
	// MaxPDU is the largest PDU the specification allows: 253 bytes,
	// which is the 256-byte serial frame less address and CRC.
	MaxPDU = 253
	// MaxADU is an MBAP frame at its largest: the header plus the
	// longest PDU. Nothing legitimate is over it, and a length field
	// claiming more is a sender testing the reader.
	MaxADU = HeaderLen + MaxPDU
	// MinPDU is a PDU carrying nothing but a function code.
	MinPDU = 1
)

// Public function codes (MODBUS Application Protocol v1.1b3 section 6).
const (
	FCReadCoils              byte = 1
	FCReadDiscreteInputs     byte = 2
	FCReadHoldingRegisters   byte = 3
	FCReadInputRegisters     byte = 4
	FCWriteSingleCoil        byte = 5
	FCWriteSingleRegister    byte = 6
	FCReadExceptionStatus    byte = 7
	FCDiagnostic             byte = 8
	FCGetCommEventCounter    byte = 11
	FCGetCommEventLog        byte = 12
	FCWriteMultipleCoils     byte = 15
	FCWriteMultipleRegisters byte = 16
	FCReportServerID         byte = 17
	FCReadFileRecord         byte = 20
	FCWriteFileRecord        byte = 21
	FCMaskWriteRegister      byte = 22
	FCReadWriteMultiple      byte = 23
	FCReadFIFOQueue          byte = 24
	FCEncapsulatedInterface  byte = 43
)

// ExceptionBit marks a response as an exception: the function code is
// echoed with its high bit set (section 7).
const ExceptionBit byte = 0x80

// Exception codes (section 7).
const (
	ExIllegalFunction    byte = 0x01
	ExIllegalAddress     byte = 0x02
	ExIllegalValue       byte = 0x03
	ExServerFailure      byte = 0x04
	ExAcknowledge        byte = 0x05
	ExServerBusy         byte = 0x06
	ExMemoryParity       byte = 0x08
	ExGatewayPathUnavail byte = 0x0A
	ExGatewayNoResponse  byte = 0x0B
)

// Quantity bounds from the specification. They are the reason a relay
// can refuse a request without asking the device: a read of 2001 coils
// is not a request the protocol has.
const (
	MaxReadCoils      = 2000
	MaxReadRegisters  = 125
	MaxWriteCoils     = 1968
	MaxWriteRegisters = 123
	MaxRWWriteRegs    = 121
	MaxFIFOCount      = 31
)

// Access is what a function code does to the device: the distinction a
// read-only policy is made of.
type Access string

const (
	// AccessRead reads process data and changes nothing.
	AccessRead Access = "read"
	// AccessWrite changes process data: a coil, a register, a file
	// record, or the read half of a read/write in one frame.
	AccessWrite Access = "write"
	// AccessDiagnostic is the diagnostic and counter function codes.
	// They read nothing of the process and can still restart a
	// communications link or clear a counter an operator is watching.
	AccessDiagnostic Access = "diagnostic"
	// AccessIdentify reports what the device is: the server identity
	// and the device identification of the encapsulated interface.
	AccessIdentify Access = "identify"
	// AccessVendor is a function code the specification leaves to the
	// vendor. Nothing here knows what it does, which is the point of
	// saying so.
	AccessVendor Access = "vendor"
)

// Table is what this package knows about one function code.
type Table struct {
	Name   string
	Access Access
	// ReadOnlySafe says the code may pass a read-only policy.
	ReadOnlySafe bool
}

// functions is the public function code table. A code absent from it is
// either reserved or vendor defined, and the relay says which.
var functions = map[byte]Table{
	FCReadCoils:              {"read_coils", AccessRead, true},
	FCReadDiscreteInputs:     {"read_discrete_inputs", AccessRead, true},
	FCReadHoldingRegisters:   {"read_holding_registers", AccessRead, true},
	FCReadInputRegisters:     {"read_input_registers", AccessRead, true},
	FCWriteSingleCoil:        {"write_single_coil", AccessWrite, false},
	FCWriteSingleRegister:    {"write_single_register", AccessWrite, false},
	FCReadExceptionStatus:    {"read_exception_status", AccessRead, true},
	FCDiagnostic:             {"diagnostic", AccessDiagnostic, false},
	FCGetCommEventCounter:    {"get_comm_event_counter", AccessDiagnostic, true},
	FCGetCommEventLog:        {"get_comm_event_log", AccessDiagnostic, true},
	FCWriteMultipleCoils:     {"write_multiple_coils", AccessWrite, false},
	FCWriteMultipleRegisters: {"write_multiple_registers", AccessWrite, false},
	FCReportServerID:         {"report_server_id", AccessIdentify, true},
	FCReadFileRecord:         {"read_file_record", AccessRead, true},
	FCWriteFileRecord:        {"write_file_record", AccessWrite, false},
	FCMaskWriteRegister:      {"mask_write_register", AccessWrite, false},
	FCReadWriteMultiple:      {"read_write_multiple_registers", AccessWrite, false},
	FCReadFIFOQueue:          {"read_fifo_queue", AccessRead, true},
	FCEncapsulatedInterface:  {"encapsulated_interface", AccessIdentify, true},
	// Not in the specification, and in the table anyway: see FCUMAS. It
	// is named so a policy can be written about it and marked vendor so
	// nothing here pretends to know what one of its commands means.
	FCUMAS: {"umas", AccessVendor, false},
}

// userDefined are the two ranges the specification reserves for a
// vendor (section 5): 65 to 72 and 100 to 110. A frame carrying one is
// not malformed, and nothing here can say what it does.
func userDefined(fc byte) bool {
	return (fc >= 65 && fc <= 72) || (fc >= 100 && fc <= 110)
}

// FunctionName is the name of a function code, for logs and policy.
func FunctionName(fc byte) string {
	if t, ok := functions[fc&^ExceptionBit]; ok {
		return t.Name
	}
	if userDefined(fc &^ ExceptionBit) {
		return fmt.Sprintf("vendor_%d", fc&^ExceptionBit)
	}
	return fmt.Sprintf("function_%d", fc&^ExceptionBit)
}

// FunctionCode reads a function code written as a number or as one of
// the names above, which is how a policy names one.
func FunctionCode(s string) (byte, bool) {
	for fc, t := range functions {
		if t.Name == s {
			return fc, true
		}
	}
	return 0, false
}

// AccessOf is what a function code does, and whether the code is one
// this package knows.
func AccessOf(fc byte) (Access, bool) {
	if t, ok := functions[fc]; ok {
		return t.Access, true
	}
	if userDefined(fc) {
		return AccessVendor, true
	}
	return AccessVendor, false
}

// ReadOnlySafe says whether a function code may pass a read-only
// policy. A code this package does not know never does: a relay that
// let an unknown code through a read-only rule would be promising
// something it cannot check.
func ReadOnlySafe(fc byte) bool {
	t, ok := functions[fc]
	return ok && t.ReadOnlySafe
}

// Errors a parse can return. They are distinguished because the relay
// answers them differently: a frame it cannot read at all ends the
// connection, while a request that is well formed and out of bounds is
// answered with an exception the master understands.
var (
	// ErrShort is a PDU that ends before its own fields do.
	ErrShort = errors.New("modbus: truncated pdu")
	// ErrBounds is a field outside what the specification allows: a
	// quantity of zero, a count that does not match the data.
	ErrBounds = errors.New("modbus: field out of range")
	// ErrUnknownFunction is a function code this package does not
	// parse.
	ErrUnknownFunction = errors.New("modbus: unknown function code")
)

// PDU is a parsed protocol data unit.
//
// The fields that are set depend on the function code, and Access says
// which reading applies. Everything a policy decides on is here rather
// than in the bytes, so a rule is written about a quantity and an
// address instead of about an offset into a buffer.
type PDU struct {
	// Function is the function code with the exception bit removed;
	// Exception is the code an exception response carries.
	Function  byte
	Access    Access
	Known     bool
	Exception byte
	// IsException marks an exception response.
	IsException bool
	// Address and Quantity are the range a read or a write names.
	// HasRange says the function code has one at all: a diagnostic or
	// an identification request does not.
	Address, Quantity uint16
	HasRange          bool
	// SubFunction is the second code a function code carries where it
	// has one: the diagnostic sub-function (code 8), the MEI type of an
	// encapsulated request (code 43) or the UMAS command (code 90). See
	// subfunction.go for what each one means, and SubEffect for what it
	// does to the device.
	SubFunction    uint16
	HasSubFunction bool
	// Session is the UMAS session byte, the pairing key an engineering
	// station is given when it takes a PLC's reservation. It is here
	// because it has to be read to find the command behind it, and it is
	// worth a log line: a station sending commands under a session
	// nobody issued is a station that guessed.
	Session    byte
	HasSession bool
	// Registers are the 16-bit values a write carries, in order, and
	// Coils the bits. Both are empty on a read request.
	Registers []uint16
	Coils     []bool
	// WriteAddress and WriteQuantity are the write half of function
	// code 23, whose read half is in Address and Quantity.
	WriteAddress, WriteQuantity uint16
	// ByteCount is the declared data length where the function code
	// has one.
	ByteCount int
	// Records are the file records of codes 20 and 21.
	Records []FileRecord
	// Identity is what a device answered about itself: function code 43,
	// MEI type 14, the one place in this protocol where a device names its
	// vendor, product and firmware revision. It is set on a response and
	// nowhere else, and nil everywhere else -- including on a CANopen answer,
	// which shares the function code and is a tunnel rather than a statement.
	Identity *DeviceIdentity
}

// FileRecord is one sub-request of a file record read or write.
type FileRecord struct {
	ReferenceType byte
	File          uint16
	Record        uint16
	Length        uint16
	// Values are the register values a write record carries.
	Values []uint16
}

// Last is the last address a range covers, and whether the range stays
// inside the 16-bit address space. A request whose range wraps past
// 65535 is not a request the protocol has, and a relay that let it
// through would be letting a range policy be walked around.
func (p *PDU) Last() (uint16, bool) {
	if !p.HasRange {
		return 0, true
	}
	end := uint32(p.Address) + uint32(p.Quantity) - 1
	if p.Quantity == 0 || end > 0xFFFF {
		return 0, false
	}
	return uint16(end), true
}

// WriteLast is the same for the write half of function code 23.
func (p *PDU) WriteLast() (uint16, bool) {
	if p.Function != FCReadWriteMultiple {
		return 0, true
	}
	end := uint32(p.WriteAddress) + uint32(p.WriteQuantity) - 1
	if p.WriteQuantity == 0 || end > 0xFFFF {
		return 0, false
	}
	return uint16(end), true
}

// SafeUnderReadOnly says whether this request changes nothing a
// read-only listener is there to protect.
//
// It reads the parsed request rather than the function code alone,
// because one function code can be two things: an encapsulated
// interface request is identification when its MEI type is 14 and a
// CANopen tunnel when it is 13, and a tunnel carries whatever the
// tunnelled protocol carries.
func (p *PDU) SafeUnderReadOnly() bool {
	return ReadOnlySafe(p.Function) && p.Access != AccessVendor
}

// Writes says whether this request changes anything on the device.
func (p *PDU) Writes() bool {
	if p.Access == AccessWrite || p.Access == AccessDiagnostic && p.Function == FCDiagnostic {
		return true
	}
	// UMAS is a protocol inside a function code, and most of what it
	// carries is a change: stop the PLC, download a block, write a
	// variable. The commands this package reads as pure reads are still
	// not reads a relay can vouch for -- what these codes mean is
	// published research and not a specification -- so the frame counts
	// as a write and a read-only listener refuses the lot.
	return p.Function == FCUMAS
}

// ParseRequest reads a request PDU: the function code and the fields
// that code defines, checked against the specification's own bounds.
//
// It is strict on purpose. Every bound here is one the device would
// have to check itself, and the ones that get forgotten in firmware are
// exactly these: a byte count that does not match the data, a quantity
// of zero, a range that wraps.
func ParseRequest(pdu []byte) (*PDU, error) {
	if len(pdu) < MinPDU {
		return nil, ErrShort
	}
	if len(pdu) > MaxPDU {
		return nil, ErrBounds
	}
	fc := pdu[0]
	if fc&ExceptionBit != 0 {
		// A request never carries the exception bit: that is a response
		// arriving where a request was expected.
		return nil, ErrBounds
	}
	access, known := AccessOf(fc)
	p := &PDU{Function: fc, Access: access, Known: known}
	data := pdu[1:]
	switch fc {
	case FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters, FCReadInputRegisters:
		if len(data) != 4 {
			return nil, ErrShort
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity = binary.BigEndian.Uint16(data[2:])
		p.HasRange = true
		limit := MaxReadCoils
		if fc == FCReadHoldingRegisters || fc == FCReadInputRegisters {
			limit = MaxReadRegisters
		}
		if p.Quantity < 1 || int(p.Quantity) > limit {
			return nil, ErrBounds
		}
	case FCWriteSingleCoil:
		if len(data) != 4 {
			return nil, ErrShort
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity, p.HasRange = 1, true
		v := binary.BigEndian.Uint16(data[2:])
		// The specification allows exactly two values here (section
		// 6.5): 0xFF00 on, 0x0000 off. Anything else is a device's
		// guess, and two devices guess differently.
		switch v {
		case 0xFF00:
			p.Coils = []bool{true}
		case 0x0000:
			p.Coils = []bool{false}
		default:
			return nil, ErrBounds
		}
		p.Registers = []uint16{v}
	case FCWriteSingleRegister:
		if len(data) != 4 {
			return nil, ErrShort
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity, p.HasRange = 1, true
		p.Registers = []uint16{binary.BigEndian.Uint16(data[2:])}
	case FCReadExceptionStatus, FCGetCommEventCounter, FCGetCommEventLog, FCReportServerID:
		if len(data) != 0 {
			return nil, ErrBounds
		}
	case FCDiagnostic:
		// A diagnostic is a sub-function and one data word, and nothing
		// else: four bytes (section 6.8). A frame with a trailing byte
		// past them is a frame two readers would disagree about, and
		// this is the function code that restarts a device.
		if len(data) != 4 {
			return nil, ErrBounds
		}
		p.SubFunction = binary.BigEndian.Uint16(data)
		p.HasSubFunction = true
		p.ByteCount = 2
		p.Registers = []uint16{binary.BigEndian.Uint16(data[2:])}
	case FCWriteMultipleCoils:
		if len(data) < 5 {
			return nil, ErrShort
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity = binary.BigEndian.Uint16(data[2:])
		p.HasRange = true
		p.ByteCount = int(data[4])
		if p.Quantity < 1 || int(p.Quantity) > MaxWriteCoils {
			return nil, ErrBounds
		}
		// The byte count has to be the bytes the quantity needs, and
		// the data has to be that many. Both are checked because a
		// device that trusts either one alone reads somebody else's
		// memory.
		if want := (int(p.Quantity) + 7) / 8; p.ByteCount != want || len(data) != 5+want {
			return nil, ErrBounds
		}
		p.Coils = decodeCoils(data[5:], int(p.Quantity))
	case FCWriteMultipleRegisters:
		if len(data) < 5 {
			return nil, ErrShort
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity = binary.BigEndian.Uint16(data[2:])
		p.HasRange = true
		p.ByteCount = int(data[4])
		if p.Quantity < 1 || int(p.Quantity) > MaxWriteRegisters {
			return nil, ErrBounds
		}
		if want := int(p.Quantity) * 2; p.ByteCount != want || len(data) != 5+want {
			return nil, ErrBounds
		}
		p.Registers = decodeRegisters(data[5:])
	case FCMaskWriteRegister:
		if len(data) != 6 {
			return nil, ErrShort
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity, p.HasRange = 1, true
		p.Registers = []uint16{binary.BigEndian.Uint16(data[2:]), binary.BigEndian.Uint16(data[4:])}
	case FCReadWriteMultiple:
		if len(data) < 9 {
			return nil, ErrShort
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity = binary.BigEndian.Uint16(data[2:])
		p.HasRange = true
		p.WriteAddress = binary.BigEndian.Uint16(data[4:])
		p.WriteQuantity = binary.BigEndian.Uint16(data[6:])
		p.ByteCount = int(data[8])
		if p.Quantity < 1 || int(p.Quantity) > MaxReadRegisters {
			return nil, ErrBounds
		}
		if p.WriteQuantity < 1 || int(p.WriteQuantity) > MaxRWWriteRegs {
			return nil, ErrBounds
		}
		if want := int(p.WriteQuantity) * 2; p.ByteCount != want || len(data) != 9+want {
			return nil, ErrBounds
		}
		p.Registers = decodeRegisters(data[9:])
	case FCReadFIFOQueue:
		if len(data) != 2 {
			return nil, ErrShort
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity, p.HasRange = 1, true
	case FCReadFileRecord:
		if len(data) < 1 {
			return nil, ErrShort
		}
		n := int(data[0])
		if n < 7 || n > 245 || len(data) != 1+n || n%7 != 0 {
			return nil, ErrBounds
		}
		for i := 1; i+6 < len(data); i += 7 {
			r := FileRecord{ReferenceType: data[i],
				File:   binary.BigEndian.Uint16(data[i+1:]),
				Record: binary.BigEndian.Uint16(data[i+3:]),
				Length: binary.BigEndian.Uint16(data[i+5:])}
			if r.ReferenceType != 6 || r.Record > 0x270F || r.Length < 1 {
				return nil, ErrBounds
			}
			p.Records = append(p.Records, r)
		}
		p.ByteCount = n
	case FCWriteFileRecord:
		if len(data) < 1 {
			return nil, ErrShort
		}
		n := int(data[0])
		if n < 9 || n > 251 || len(data) != 1+n {
			return nil, ErrBounds
		}
		i := 1
		for i < len(data) {
			if i+7 > len(data) {
				return nil, ErrShort
			}
			r := FileRecord{ReferenceType: data[i],
				File:   binary.BigEndian.Uint16(data[i+1:]),
				Record: binary.BigEndian.Uint16(data[i+3:]),
				Length: binary.BigEndian.Uint16(data[i+5:])}
			if r.ReferenceType != 6 || r.Record > 0x270F || r.Length < 1 {
				return nil, ErrBounds
			}
			i += 7
			if i+int(r.Length)*2 > len(data) {
				return nil, ErrShort
			}
			r.Values = decodeRegisters(data[i : i+int(r.Length)*2])
			i += int(r.Length) * 2
			p.Records = append(p.Records, r)
		}
		p.ByteCount = n
	case FCEncapsulatedInterface:
		if len(data) < 1 {
			return nil, ErrShort
		}
		p.SubFunction = uint16(data[0])
		p.HasSubFunction = true
		// The specification defines two MEI types and no others. Type
		// 14 is Read Device Identification, which is an identification
		// request of exactly three bytes: the type, the identification
		// code and the object id. Type 13 is CANopen, which is a tunnel
		// carrying whatever CANopen carries -- and the distinction
		// matters to a read-only policy, because one of them asks a
		// question and the other one is a second protocol.
		switch data[0] {
		case 13:
			p.Access = AccessVendor
		case 14:
			if len(data) != 3 {
				return nil, ErrBounds
			}
			if data[1] < 1 || data[1] > 4 {
				return nil, ErrBounds
			}
		default:
			return nil, ErrBounds
		}
		p.ByteCount = len(data) - 1
	case FCUMAS:
		// A session byte and then a command of UMAS's own, before
		// whatever that command carries: 5A <session> <command> ...
		// Nothing below the command is parsed, because nothing here
		// knows the shape of a UMAS payload and a bound invented for one
		// would be a bound a policy could be walked around. What is
		// parsed is what a policy decides on: which command, from whom.
		if len(data) < 2 {
			return nil, ErrShort
		}
		p.Session, p.HasSession = data[0], true
		p.SubFunction, p.HasSubFunction = uint16(data[1]), true
		p.ByteCount = len(data) - 2
	default:
		if !known {
			return nil, ErrUnknownFunction
		}
		p.ByteCount = len(data)
	}
	// A range that runs past the end of the address space is not a
	// range the protocol has, and it is the shape a range policy is
	// walked around with: a rule comparing 0..999 against a request
	// that starts at 65535 and asks for two has nothing to compare.
	// Refusing it here is what lets every later stage assume a parsed
	// request has an end.
	if _, ok := p.Last(); !ok {
		return nil, ErrBounds
	}
	if _, ok := p.WriteLast(); !ok {
		return nil, ErrBounds
	}
	return p, nil
}

// ParseResponse reads a response PDU. req is the request it answers,
// which is what makes a response readable at all: the wire form of a
// read response says how many bytes follow and not what they are, so
// the quantity comes from the request.
func ParseResponse(pdu []byte, req *PDU) (*PDU, error) {
	if len(pdu) < MinPDU {
		return nil, ErrShort
	}
	if len(pdu) > MaxPDU {
		return nil, ErrBounds
	}
	fc := pdu[0]
	if fc&ExceptionBit != 0 {
		if len(pdu) != 2 {
			return nil, ErrBounds
		}
		base := fc &^ ExceptionBit
		access, known := AccessOf(base)
		return &PDU{Function: base, Access: access, Known: known,
			IsException: true, Exception: pdu[1]}, nil
	}
	access, known := AccessOf(fc)
	p := &PDU{Function: fc, Access: access, Known: known}
	data := pdu[1:]
	switch fc {
	case FCReadCoils, FCReadDiscreteInputs:
		if len(data) < 1 {
			return nil, ErrShort
		}
		p.ByteCount = int(data[0])
		if len(data) != 1+p.ByteCount {
			return nil, ErrBounds
		}
		want := int(req.Quantity)
		if req.Quantity == 0 || (want+7)/8 != p.ByteCount {
			return nil, ErrBounds
		}
		p.Coils = decodeCoils(data[1:], want)
		p.Address, p.Quantity, p.HasRange = req.Address, req.Quantity, true
	case FCReadHoldingRegisters, FCReadInputRegisters:
		if len(data) < 1 {
			return nil, ErrShort
		}
		p.ByteCount = int(data[0])
		if len(data) != 1+p.ByteCount || p.ByteCount%2 != 0 {
			return nil, ErrBounds
		}
		if int(req.Quantity)*2 != p.ByteCount {
			return nil, ErrBounds
		}
		p.Registers = decodeRegisters(data[1:])
		p.Address, p.Quantity, p.HasRange = req.Address, req.Quantity, true
	case FCReadWriteMultiple:
		if len(data) < 1 {
			return nil, ErrShort
		}
		p.ByteCount = int(data[0])
		if len(data) != 1+p.ByteCount || p.ByteCount%2 != 0 || int(req.Quantity)*2 != p.ByteCount {
			return nil, ErrBounds
		}
		p.Registers = decodeRegisters(data[1:])
		p.Address, p.Quantity, p.HasRange = req.Address, req.Quantity, true
	case FCWriteSingleCoil, FCWriteSingleRegister:
		// The response echoes the request.
		if len(data) != 4 {
			return nil, ErrBounds
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity, p.HasRange = 1, true
		p.Registers = []uint16{binary.BigEndian.Uint16(data[2:])}
	case FCWriteMultipleCoils, FCWriteMultipleRegisters:
		if len(data) != 4 {
			return nil, ErrBounds
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity = binary.BigEndian.Uint16(data[2:])
		p.HasRange = true
	case FCMaskWriteRegister:
		if len(data) != 6 {
			return nil, ErrBounds
		}
		p.Address = binary.BigEndian.Uint16(data)
		p.Quantity, p.HasRange = 1, true
	case FCReadExceptionStatus:
		if len(data) != 1 {
			return nil, ErrBounds
		}
		p.ByteCount = 1
	case FCDiagnostic:
		// The echo of the request: the same four bytes.
		if len(data) != 4 {
			return nil, ErrBounds
		}
		p.SubFunction = binary.BigEndian.Uint16(data)
		p.HasSubFunction = true
		p.ByteCount = 2
	case FCReadFIFOQueue:
		if len(data) < 4 {
			return nil, ErrShort
		}
		byteCount := int(binary.BigEndian.Uint16(data))
		count := int(binary.BigEndian.Uint16(data[2:]))
		if count > MaxFIFOCount || byteCount != count*2+2 || len(data) != 2+byteCount {
			return nil, ErrBounds
		}
		p.ByteCount = byteCount
		p.Registers = decodeRegisters(data[4:])
	case FCEncapsulatedInterface:
		// The one variable shape below that this does read into fields: MEI
		// type 14 is a device naming itself, and that is the whole of what a
		// relay can learn about what it is in front of without asking a
		// question of its own. A CANopen answer (type 13) stays opaque, and so
		// does an identification response whose object list disagrees with its
		// own length fields -- which is a malformed response rather than a
		// device to read strings out of.
		p.ByteCount = len(data)
		id, err := parseIdentity(data)
		if err != nil {
			return nil, err
		}
		p.Identity = id
	case FCReadFileRecord, FCWriteFileRecord, FCReportServerID,
		FCGetCommEventCounter, FCGetCommEventLog, FCUMAS:
		// Variable shapes whose own length fields are checked by the
		// framing. There is nothing a policy decides on inside them,
		// and inventing a structure here would be inventing a bound
		// the specification does not have. The UMAS reply is here for
		// the same reason twice over: its shape is not published at
		// all, and the decision was made about the request.
		p.ByteCount = len(data)
	default:
		if !known {
			return nil, ErrUnknownFunction
		}
		p.ByteCount = len(data)
	}
	return p, nil
}

func decodeRegisters(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:])) //nolint:gosec // i+1 < len(b) is the loop's condition
	}
	return out
}

func decodeCoils(b []byte, n int) []bool {
	out := make([]bool, 0, n)
	for i := 0; i < n; i++ {
		byteIdx, bit := i/8, i%8
		if byteIdx >= len(b) {
			break
		}
		out = append(out, b[byteIdx]&(1<<bit) != 0)
	}
	return out
}

// ExceptionPDU builds an exception response for a function code, which
// is how the relay refuses a request without ending the connection: the
// master reads it as the device's own refusal and carries on.
func ExceptionPDU(fc, code byte) []byte {
	return []byte{fc | ExceptionBit, code}
}

// ExceptionName is the name of an exception code, for logs.
func ExceptionName(code byte) string {
	switch code {
	case ExIllegalFunction:
		return "illegal_function"
	case ExIllegalAddress:
		return "illegal_data_address"
	case ExIllegalValue:
		return "illegal_data_value"
	case ExServerFailure:
		return "server_device_failure"
	case ExAcknowledge:
		return "acknowledge"
	case ExServerBusy:
		return "server_device_busy"
	case ExMemoryParity:
		return "memory_parity_error"
	case ExGatewayPathUnavail:
		return "gateway_path_unavailable"
	case ExGatewayNoResponse:
		return "gateway_target_no_response"
	}
	return fmt.Sprintf("exception_%d", code)
}
