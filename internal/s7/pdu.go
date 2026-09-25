package s7

import (
	"encoding/binary"
	"fmt"
)

// The S7 PDU, which is the layer the policy is written about.
//
// It has no public specification. What is here is the protocol as deployed
// equipment speaks it -- the same reading Wireshark's dissector and the
// open libraries make -- and where this package cannot name something it
// says so rather than guessing, because a relay that guessed would be
// deciding a policy on a field it had misread.
//
// The header is a protocol identifier, a message type, a reference the
// answer echoes, and the lengths of the two halves that follow: the
// parameters, which say what the operation *is*, and the data, which is
// what it carries. An acknowledgement adds two octets of error, which is
// the PLC's own account of why it refused something and worth reading for
// that alone.

// ProtocolID is the first octet of every S7 PDU.
const ProtocolID = 0x32

// ROSCTR is the message type: what kind of thing this PDU is.
type ROSCTR uint8

// The message types.
const (
	// Job is a request from the client.
	Job ROSCTR = 0x01
	// Ack is an acknowledgement with no data, which the families in the
	// field rarely send.
	Ack ROSCTR = 0x02
	// AckData is an acknowledgement with data: the answer to a job, and
	// the two error octets.
	AckData ROSCTR = 0x03
	// Userdata is the second protocol inside the first: the diagnostic,
	// block, clock, security and programmer functions, each named by a
	// function group and a subfunction rather than by a function code.
	Userdata ROSCTR = 0x07
)

func (r ROSCTR) String() string {
	switch r {
	case Job:
		return "job"
	case Ack:
		return "ack"
	case AckData:
		return "ack_data"
	case Userdata:
		return "userdata"
	}
	return fmt.Sprintf("%#x", uint8(r))
}

// The function codes of a job (the parameter's first octet).
const (
	FnCPUServices     uint8 = 0x00
	FnSetupComm       uint8 = 0xF0
	FnReadVar         uint8 = 0x04
	FnWriteVar        uint8 = 0x05
	FnRequestDownload uint8 = 0x1A
	FnDownloadBlock   uint8 = 0x1B
	FnDownloadEnded   uint8 = 0x1C
	FnStartUpload     uint8 = 0x1D
	FnUpload          uint8 = 0x1E
	FnEndUpload       uint8 = 0x1F
	FnPLCControl      uint8 = 0x28
	FnPLCStop         uint8 = 0x29
)

var functionNames = map[uint8]string{
	FnCPUServices:     "cpu_services",
	FnSetupComm:       "setup_communication",
	FnReadVar:         "read_var",
	FnWriteVar:        "write_var",
	FnRequestDownload: "request_download",
	FnDownloadBlock:   "download_block",
	FnDownloadEnded:   "download_ended",
	FnStartUpload:     "start_upload",
	FnUpload:          "upload",
	FnEndUpload:       "end_upload",
	FnPLCControl:      "plc_control",
	FnPLCStop:         "plc_stop",
}

// PDU is one S7 message.
type PDU struct {
	Type   ROSCTR
	PDURef uint16
	// Param and Data are the two halves the header's lengths describe.
	Param, Data []byte
	// ErrClass and ErrCode are an acknowledgement's error octets, and
	// HasError says they were there -- an error class of zero means no
	// error, which is not the same as a PDU that carries none.
	ErrClass, ErrCode uint8
	HasError          bool
	// Function is the parameter's first octet on a job or an
	// acknowledgement to one. HasFunction says the parameter was long
	// enough to have one.
	Function    uint8
	HasFunction bool
}

// ParseS7 reads an S7 PDU out of a COTP data PDU's user data.
//
// The two lengths are from the network, so both are checked against what
// actually arrived. A PDU whose parameter length reaches past the frame is
// refused rather than clipped: the parameters are what say what the
// operation is, and half of them is not a shorter operation.
func ParseS7(b []byte) (*PDU, error) {
	if len(b) < 10 {
		return nil, fmt.Errorf("an S7 header of %d octets is shorter than its own fields", len(b))
	}
	if b[0] != ProtocolID {
		return nil, fmt.Errorf("not an S7 PDU: the protocol identifier is %#x", b[0])
	}
	p := &PDU{Type: ROSCTR(b[1]), PDURef: binary.BigEndian.Uint16(b[4:6])}
	plen := int(binary.BigEndian.Uint16(b[6:8]))
	dlen := int(binary.BigEndian.Uint16(b[8:10]))
	off := 10
	if p.Type == AckData || p.Type == Ack {
		// The error class and code sit between the header and the
		// parameters on an acknowledgement.
		if len(b) < 12 {
			return nil, fmt.Errorf("an acknowledgement of %d octets has no error field", len(b))
		}
		p.ErrClass, p.ErrCode = b[10], b[11]
		p.HasError = true
		off = 12
	}
	if plen < 0 || dlen < 0 || off+plen+dlen > len(b) {
		return nil, fmt.Errorf("an S7 PDU says %d parameter and %d data octets, and carries %d",
			plen, dlen, len(b)-off)
	}
	p.Param = b[off : off+plen]
	p.Data = b[off+plen : off+plen+dlen]
	if len(p.Param) > 0 {
		p.Function, p.HasFunction = p.Param[0], true
	}
	return p, nil
}

// FunctionName names a job's function, or gives its number.
func (p *PDU) FunctionName() string {
	if !p.HasFunction {
		return "none"
	}
	if n, ok := functionNames[p.Function]; ok {
		return n
	}
	return fmt.Sprintf("%#x", p.Function)
}

// KnownFunction says whether the function code is one this package names.
func (p *PDU) KnownFunction() bool {
	_, ok := functionNames[p.Function]
	return p.HasFunction && ok
}

// FunctionNames is every function name this package knows, for the
// configuration to validate a policy's spelling against.
func FunctionNames() []string {
	out := make([]string, 0, len(functionNames))
	for _, n := range functionNames {
		out = append(out, n)
	}
	return out
}

// Setup reads a setup-communication job or its answer: the two
// "maximum amount of queued calls" fields and the PDU length the two sides
// are agreeing on.
//
// The PDU length is the one a relay cares about. It is what bounds every
// read and write that follows, it is negotiated rather than fixed, and a
// listener that reads frames up to a bound of its own has to know the
// number the two sides settled on -- or refuse it.
func (p *PDU) Setup() (calling, called, pduLength uint16, ok bool) {
	if !p.HasFunction || p.Function != FnSetupComm || len(p.Param) < 8 {
		return 0, 0, 0, false
	}
	return binary.BigEndian.Uint16(p.Param[2:4]),
		binary.BigEndian.Uint16(p.Param[4:6]),
		binary.BigEndian.Uint16(p.Param[6:8]), true
}

// Service reads the service name of a PLC control or stop job.
//
// This is the field that says which control operation it is, and the names
// are Siemens' own: `P_PROGRAM` is a warm restart or a stop, `_INSE` and
// `_DELE` insert and delete a block, `_GARB` compresses the memory, and
// `_MODU` is a memory card operation. They are the difference between "the
// CPU was restarted" and "a block was deleted", so a relay that only saw
// "plc_control" would be refusing or allowing both together.
func (p *PDU) Service() (string, bool) {
	if !p.HasFunction {
		return "", false
	}
	switch p.Function {
	case FnPLCStop:
		// function, five reserved octets, a length octet, then the name.
		if len(p.Param) < 7 {
			return "", false
		}
		n := int(p.Param[6])
		if 7+n > len(p.Param) {
			return "", false
		}
		return string(p.Param[7 : 7+n]), true
	case FnPLCControl:
		// function, seven reserved octets, a two-octet parameter block
		// length, that block, a length octet, then the name.
		if len(p.Param) < 10 {
			return "", false
		}
		blk := int(binary.BigEndian.Uint16(p.Param[8:10]))
		at := 10 + blk
		if at >= len(p.Param) {
			return "", false
		}
		n := int(p.Param[at])
		if at+1+n > len(p.Param) {
			return "", false
		}
		return string(p.Param[at+1 : at+1+n]), true
	}
	return "", false
}

// Block reads the block a download or upload job names, as the eight
// characters the protocol puts it in: a block type and a number, written
// `_0800010A` for a data block. The number is decimal text, which is how
// the protocol writes it, and the type is one character.
//
// A relay reads it because "a program was downloaded" and "this data block
// was downloaded" are different events, and because an allow list of block
// types is a real policy: a listener may let an engineering station upload
// (read) blocks and never download (write) one.
func (p *PDU) Block() (kind string, number int, ok bool) {
	if !p.HasFunction {
		return "", 0, false
	}
	switch p.Function {
	case FnRequestDownload, FnStartUpload:
	default:
		return "", 0, false
	}
	// The filename is the last nine octets of the parameter on both: a
	// length octet is not used, the field is fixed at nine characters of
	// the form `_0800010A`.
	if len(p.Param) < 9 {
		return "", 0, false
	}
	name := p.Param[len(p.Param)-9:]
	if name[0] != '_' {
		return "", 0, false
	}
	// name[1:3] is the block type as two hexadecimal digits of an ASCII
	// code point, name[3:8] the number in decimal, name[8] the
	// destination.
	var num int
	for _, c := range name[3:8] {
		if c < '0' || c > '9' {
			return "", 0, false
		}
		num = num*10 + int(c-'0')
	}
	return blockKind(name[1:3]), num, true
}

// blockKind names a block type from the two hexadecimal digits the
// protocol writes it as.
func blockKind(b []byte) string {
	switch string(b) {
	case "08":
		return "db"
	case "0A":
		return "sdb"
	case "0B":
		return "fc"
	case "0C":
		return "sfc"
	case "0E":
		return "fb"
	case "0F":
		return "sfb"
	}
	return string(b)
}

// The error classes an acknowledgement carries. They are the PLC's own
// account of why it refused something, and the two that matter to a relay
// are the access fault -- which is what a protected CPU answers a client
// that has not supplied its password -- and the resource error, which is
// what one answers when it is out of connections.
var errorClasses = map[uint8]string{
	0x00: "no_error",
	0x81: "application_relationship",
	0x82: "object_definition",
	0x83: "no_resources",
	0x84: "service_processing",
	0x85: "supplies",
	0x87: "access_fault",
}

// ErrorClassName names an error class.
func ErrorClassName(c uint8) string {
	if n, ok := errorClasses[c]; ok {
		return n
	}
	return fmt.Sprintf("%#x", c)
}
