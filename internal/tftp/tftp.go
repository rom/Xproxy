// Package tftp reads the Trivial File Transfer Protocol (RFC 1350) and its
// option extension (RFC 2347 to 2349, RFC 7440).
//
// TFTP is the protocol that moves firmware onto switches, configurations off
// them, boot images to machines that have no operating system yet and
// provisioning files to telephones. It has **no authentication of any kind**:
// no user, no password, no token, no transport security, and no extension
// that adds one. A request is a filename and a mode, and a server that
// receives one answers it.
//
// That makes a relay in front of it unusually load-bearing, and it makes the
// three things below the whole of what such a relay can do.
//
// **The filename is the only thing a policy has.** There is no identity, so
// the decision is about the address it came from and the path it asked for --
// and a path is exactly where this protocol has been exploited for forty
// years. `../../etc/shadow`, an absolute path, a backslash on a server that
// runs on Windows, a NUL in the middle: each of them has worked somewhere.
// So a filename is read as a path and classified, and a relay refuses the
// classes rather than matching strings.
//
// **A write is not a read.** Most TFTP in an estate is a read: a switch
// pulling firmware, a machine pulling a boot image. A *write* is a device
// putting a file onto the server, which is how a configuration leaves an
// estate and how firmware arrives in it. The two are separate decisions and
// the default for the second is no.
//
// **It is an amplifier.** A twenty-octet read request yields a whole file to
// whatever address the datagram claimed to come from -- and RFC 7440's window
// size multiplies it, because a window of sixty-four is sixty-four data
// packets per acknowledgement. So the transfer's size, its block size and its
// window are all bounded, and the bounds are the relay's rather than the
// client's, because the client's are a request.
//
// What this package does not do is interpret a transfer's contents. What is
// in a firmware image is the estate's business; that the image is one the
// policy allows, of a size the policy allows, to a path the policy allows, is
// the relay's.
package tftp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Op is a TFTP opcode.
type Op uint16

// The five opcodes of RFC 1350 and the sixth of RFC 2347.
const (
	OpRead  Op = 1
	OpWrite Op = 2
	OpData  Op = 3
	OpAck   Op = 4
	OpError Op = 5
	// OpOAck is the option acknowledgement: the server's answer to a
	// request that carried options, naming the ones it accepted. A relay
	// reads it because the accepted block size and window size are the
	// bounds the rest of the transfer runs under.
	OpOAck Op = 6
)

var opNames = map[Op]string{
	OpRead: "read", OpWrite: "write", OpData: "data",
	OpAck: "ack", OpError: "error", OpOAck: "oack",
}

func (o Op) String() string {
	if n, ok := opNames[o]; ok {
		return n
	}
	return fmt.Sprintf("op(%d)", uint16(o))
}

// Known says whether this is an opcode the standards define.
func (o Op) Known() bool { _, ok := opNames[o]; return ok }

// Request says whether this opcode begins a transfer.
func (o Op) Request() bool { return o == OpRead || o == OpWrite }

// OpOf names an opcode the way a rule is written.
func OpOf(s string) (Op, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "read", "rrq", "get":
		return OpRead, true
	case "write", "wrq", "put":
		return OpWrite, true
	case "data":
		return OpData, true
	case "ack":
		return OpAck, true
	case "error":
		return OpError, true
	case "oack":
		return OpOAck, true
	}
	return 0, false
}

// The transfer modes of RFC 1350.
const (
	// ModeOctet is a byte-for-byte transfer, which is what everything
	// actually uses.
	ModeOctet = "octet"
	// ModeNetASCII translates line endings, which matters for a
	// configuration file moved between systems.
	ModeNetASCII = "netascii"
	// ModeMail is obsolete: RFC 1350 removed it, and it asked a server to
	// deliver the file as mail to the user named in the filename field. A
	// server that still implements it is a mail injection vector reachable
	// with one unauthenticated datagram.
	ModeMail = "mail"
)

// Error codes (RFC 1350 §5, RFC 2347 §2).
const (
	ErrNotDefined      uint16 = 0
	ErrFileNotFound    uint16 = 1
	ErrAccessViolation uint16 = 2
	ErrDiskFull        uint16 = 3
	ErrIllegalOp       uint16 = 4
	ErrUnknownTID      uint16 = 5
	ErrFileExists      uint16 = 6
	ErrNoSuchUser      uint16 = 7
	// ErrOptionRefused is RFC 2347's code for a request whose options the
	// server will not accept, which is what a relay sends when a bound
	// refuses one.
	ErrOptionRefused uint16 = 8
)

var errorNames = map[uint16]string{
	ErrNotDefined: "notDefined", ErrFileNotFound: "fileNotFound",
	ErrAccessViolation: "accessViolation", ErrDiskFull: "diskFull",
	ErrIllegalOp: "illegalOperation", ErrUnknownTID: "unknownTransferID",
	ErrFileExists: "fileAlreadyExists", ErrNoSuchUser: "noSuchUser",
	ErrOptionRefused: "optionRefused",
}

// ErrorName names an error code, for a log line an operator reads.
func ErrorName(code uint16) string {
	if n, ok := errorNames[code]; ok {
		return n
	}
	return fmt.Sprintf("error(%d)", code)
}

// The option names the extensions define. A relay reads these four because
// each of them is a bound; any other option is carried or refused by name
// rather than understood.
const (
	// OptBlockSize is RFC 2348. The standard allows 8 to 65464, and a large
	// value fragments at the IP layer -- which is a lever rather than a
	// feature.
	OptBlockSize = "blksize"
	// OptTimeout is RFC 2349, in seconds, 1 to 255.
	OptTimeout = "timeout"
	// OptTransferSize is RFC 2349: on a read the server fills it in, and on
	// a write the *client* declares how large the file it is about to send
	// is -- which is a bound a relay can hold it to before the first octet
	// arrives.
	OptTransferSize = "tsize"
	// OptWindowSize is RFC 7440: how many data packets may be sent before
	// one acknowledgement. It is this protocol's amplification factor.
	OptWindowSize = "windowsize"
)

// The bounds the standards themselves set, which are the outer edge of
// anything a listener may configure.
const (
	// MinBlockSize and MaxBlockSize are RFC 2348's range.
	MinBlockSize = 8
	MaxBlockSize = 65464
	// DefaultBlockSize is RFC 1350's, and what a transfer that negotiated
	// nothing uses. It is also how the end of a transfer is recognised: a
	// data packet shorter than the block size is the last one.
	DefaultBlockSize = 512
	// MaxWindowSize is RFC 7440's.
	MaxWindowSize = 65535
	// MaxPacket is the largest datagram any of this produces: a data packet
	// with the largest block size, its opcode and its block number.
	MaxPacket = MaxBlockSize + 4
	// MaxFilename bounds the filename field. The standard sets none; a name
	// longer than this is a name nobody meant.
	MaxFilename = 1024
	// MaxOptions bounds how many options one request may carry.
	MaxOptions = 16
)

// Errors a reader returns.
var (
	// ErrTruncated is a packet that ended inside itself.
	ErrTruncated = errors.New("tftp: truncated packet")
	// ErrOpcode is an opcode the standards do not define.
	ErrOpcode = errors.New("tftp: unknown opcode")
	// ErrShape is a packet whose fields are not the ones that opcode has.
	ErrShape = errors.New("tftp: not the shape of that packet")
	// ErrUnterminated is a string field with no terminating zero, which is
	// the shape a filename runs past its own field in.
	ErrUnterminated = errors.New("tftp: unterminated string field")
	// ErrCount is more of something than a bound allows.
	ErrCount = errors.New("tftp: too many elements")
)

// Request is a parsed read or write request.
type Request struct {
	// Filename as it arrived, unmodified. What it *means* is Path's
	// business.
	Filename string
	// Mode is octet, netascii or mail, folded to lower case: RFC 1350 says
	// the mode is case-insensitive, and a server that compared it exactly
	// would refuse a client that wrote OCTET.
	Mode string
	// Options are the extension options, by name, in the order they
	// arrived. Order is kept because RFC 2347 requires an option
	// acknowledgement to answer in the request's order.
	Options []Option
}

// Option is one extension option.
type Option struct {
	Name, Value string
}

// Get returns an option's value.
func (r *Request) Get(name string) (string, bool) {
	for _, o := range r.Options {
		if o.Name == name {
			return o.Value, true
		}
	}
	return "", false
}

// Number reads an option as a non-negative number, and says whether it was
// present and well formed. An option whose value is not a number is not an
// option this relay will carry: the server would read it somehow.
func (r *Request) Number(name string) (int, bool, error) {
	v, ok := r.Get(name)
	if !ok {
		return 0, false, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, true, fmt.Errorf("%w: option %s is %q", ErrShape, name, v)
	}
	return n, true, nil
}

// Data is a parsed data packet.
type Data struct {
	Block uint16
	// Length is the payload's extent. The payload itself is forwarded and
	// not kept: what is inside a firmware image is the estate's business.
	Length int
}

// Packet is one parsed TFTP packet.
type Packet struct {
	Op Op
	// Raw is the packet as it arrived, which is what a relay forwards when
	// it forwards something unchanged.
	Raw []byte

	Request *Request
	Data    *Data
	// Ack is the block number acknowledged, for OpAck.
	Ack uint16
	// ErrorCode and ErrorMessage are the fields of an error packet.
	ErrorCode    uint16
	ErrorMessage string
	// OAck are the options a server accepted, for OpOAck.
	OAck []Option
}

// Parse reads one TFTP packet.
func Parse(raw []byte) (*Packet, error) {
	if len(raw) < 2 {
		return nil, ErrTruncated
	}
	if len(raw) > MaxPacket {
		return nil, fmt.Errorf("%w: %d octets", ErrTruncated, len(raw))
	}
	p := &Packet{Op: Op(binary.BigEndian.Uint16(raw[:2])), Raw: raw}
	if !p.Op.Known() {
		return nil, fmt.Errorf("%w: %d", ErrOpcode, uint16(p.Op))
	}
	body := raw[2:]
	switch p.Op {
	case OpRead, OpWrite:
		req, err := parseRequest(body)
		if err != nil {
			return nil, err
		}
		p.Request = req
	case OpData:
		if len(body) < 2 {
			return nil, fmt.Errorf("%w: a data packet with no block number", ErrShape)
		}
		p.Data = &Data{Block: binary.BigEndian.Uint16(body[:2]), Length: len(body) - 2}
	case OpAck:
		if len(body) != 2 {
			// An acknowledgement is exactly two octets. One that carries
			// more is one a server may read differently from this relay,
			// and a relay that forwarded it would be forwarding two
			// readings.
			return nil, fmt.Errorf("%w: an acknowledgement of %d octets", ErrShape, len(body))
		}
		p.Ack = binary.BigEndian.Uint16(body)
	case OpError:
		if len(body) < 2 {
			return nil, fmt.Errorf("%w: an error packet with no code", ErrShape)
		}
		p.ErrorCode = binary.BigEndian.Uint16(body[:2])
		msg, rest, err := cstring(body[2:])
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("%w: %d octets after an error message", ErrShape, len(rest))
		}
		p.ErrorMessage = msg
	case OpOAck:
		opts, err := parseOptions(body)
		if err != nil {
			return nil, err
		}
		p.OAck = opts
	}
	return p, nil
}

// parseRequest reads the filename, the mode and the options.
func parseRequest(body []byte) (*Request, error) {
	name, rest, err := cstring(body)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("%w: a request with no filename", ErrShape)
	}
	if len(name) > MaxFilename {
		return nil, fmt.Errorf("%w: a filename of %d octets", ErrCount, len(name))
	}
	mode, rest, err := cstring(rest)
	if err != nil {
		return nil, err
	}
	if mode == "" {
		return nil, fmt.Errorf("%w: a request with no mode", ErrShape)
	}
	opts, err := parseOptions(rest)
	if err != nil {
		return nil, err
	}
	// RFC 1350 §5: the mode is case-insensitive. A relay that compared it
	// exactly would refuse the client that wrote OCTET, and a policy that
	// refused "mail" exactly would miss the one that wrote Mail.
	return &Request{Filename: name, Mode: strings.ToLower(mode), Options: opts}, nil
}

// parseOptions reads a sequence of zero-terminated name and value pairs.
func parseOptions(body []byte) ([]Option, error) {
	var out []Option
	for len(body) > 0 {
		if len(out) >= MaxOptions {
			return nil, fmt.Errorf("%w: more than %d options", ErrCount, MaxOptions)
		}
		name, rest, err := cstring(body)
		if err != nil {
			return nil, err
		}
		value, rest, err := cstring(rest)
		if err != nil {
			return nil, err
		}
		if name == "" {
			return nil, fmt.Errorf("%w: an option with no name", ErrShape)
		}
		// RFC 2347 makes option names case-insensitive too.
		out = append(out, Option{Name: strings.ToLower(name), Value: value})
		body = rest
	}
	return out, nil
}

// cstring reads a zero-terminated string and returns what follows it.
//
// A field with no terminator is refused rather than read to the end of the
// packet, because "to the end of the packet" is one reading and a server's
// own parser may take another -- and a filename that runs past its field is
// exactly where the two readings differ.
func cstring(b []byte) (string, []byte, error) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], nil
		}
	}
	return "", nil, ErrUnterminated
}
