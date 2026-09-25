// Package amqpwire reads AMQP off the wire: the two versions that share a
// port and a name and nothing else.
//
// **AMQP 0-9-1** is what RabbitMQ speaks and what almost every message
// broker deployment in the field means by AMQP. It is a frame protocol
// with a class-and-method catalogue: every operation -- declaring an
// exchange, binding a queue, publishing, consuming, deleting -- is a
// method frame with a class identifier, a method identifier and typed
// arguments.
//
// **AMQP 1.0** (ISO/IEC 19464) is a different protocol that kept the
// name. There are no classes and no methods: there are nine
// performatives, a self-describing type system underneath them, and the
// thing being authorised is the *address* a link attaches to.
//
// A relay in front of a broker has to read both, because a client picks
// the version in its first eight octets and the same port serves either.
//
// What this package is for is deciding, so it reads three things and
// refuses to guess about any of them.
//
// **The frame, exactly.** A 0-9-1 frame carries its own length and ends
// with octet 206; a 1.0 frame's length includes its header and its data
// offset says where the body starts. Both are bounded here before
// anything is allocated, because the length is the attacker's field: the
// declared size is read from the network and a reader that trusted it
// would allocate whatever a first packet asked for.
//
// **The identity, and never the secret.** The SASL exchange carries the
// mechanism and, for PLAIN, the authorisation identity and the password
// in one binary field separated by zero octets. The username is what a
// policy decides on and what a log line needs; the password is read past
// and never returned, because a relay that held one would be a careless
// log line away from the estate's broker credentials.
//
// **What the operation names.** An exchange, a queue, a routing key, a
// link address. These are the nouns a policy is written about, and the
// package says which ones a method names *and whether it knows* -- a
// method whose arguments it cannot lay out returns `known` false rather
// than a plausible-looking name, so a policy can refuse it instead of
// checking a list against the wrong field.
//
// Nothing here writes a frame. The relay forwards the octets it read, so
// every frame carries its own bytes: a proxy that re-rendered a frame
// would be a second implementation of the encoder, and the case where its
// output differs from its input is exactly the case an attacker is
// looking for.
package amqpwire

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The frame types of AMQP 0-9-1 (§2.3) and the octet that ends every one
// of them.
const (
	FrameMethod    uint8 = 1
	FrameHeader    uint8 = 2
	FrameBody      uint8 = 3
	FrameHeartbeat uint8 = 8
	FrameEnd       uint8 = 0xCE
)

// The frame types of AMQP 1.0 (§2.3.1): the protocol's own frames, and
// the SASL layer's.
const (
	FrameAMQP uint8 = 0
	FrameSASL uint8 = 1
)

// The smallest frame each version allows a peer to be held to, and the
// bound this package applies when a caller names none.
//
// The minimums are the protocols' own (0-9-1 §4.2.3 and 1.0 §2.4.1).
// They matter to a relay because `frame_max` is negotiated: a listener
// that bounded frames below the minimum would be refusing a client for
// obeying the specification.
const (
	MinFrameMax091  = 4096
	MinFrameMax10   = 512
	DefaultMaxFrame = 128 << 10
)

// Version is which protocol a connection turned out to be speaking.
type Version int

const (
	// Unknown is a connection whose header has not been read yet, or one
	// whose header named a version this package does not read.
	Unknown Version = iota
	// V091 is AMQP 0-9-1.
	V091
	// V10 is AMQP 1.0, including its SASL and TLS layers -- the framing
	// is the same and only the header's protocol identifier differs.
	V10
	// Legacy is AMQP 0-8 or 0-9: the same framing as 0-9-1 with a
	// smaller method catalogue. It is read as far as its header, so a
	// listener can refuse it by name rather than as gibberish.
	Legacy
)

func (v Version) String() string {
	switch v {
	case V091:
		return "0-9-1"
	case V10:
		return "1.0"
	case Legacy:
		return "0-8"
	}
	return "unknown"
}

// Header is the eight octets a connection opens with: the literal "AMQP",
// a protocol identifier and a version.
//
// The identifier is what makes 1.0 different from every other protocol
// here: 0 is AMQP itself, 2 is "start TLS now" and 3 is "the SASL layer
// first", and a connection can send two headers in a row -- SASL, then
// AMQP -- on the same socket.
type Header struct {
	ID                     uint8
	Major, Minor, Revision uint8
	raw                    [8]byte
}

// The protocol identifiers of AMQP 1.0 §2.2.
const (
	ProtoAMQP uint8 = 0
	ProtoTLS  uint8 = 2
	ProtoSASL uint8 = 3
)

// HeaderSize is the length of a protocol header.
const HeaderSize = 8

var literal = [4]byte{'A', 'M', 'Q', 'P'}

// ParseHeader reads the eight octets of a protocol header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) != HeaderSize {
		return Header{}, fmt.Errorf("a protocol header is %d octets, not %d", HeaderSize, len(b))
	}
	if b[0] != literal[0] || b[1] != literal[1] || b[2] != literal[2] || b[3] != literal[3] {
		return Header{}, errors.New("not an AMQP connection: the header does not begin with AMQP")
	}
	h := Header{ID: b[4], Major: b[5], Minor: b[6], Revision: b[7]}
	copy(h.raw[:], b)
	return h, nil
}

// Bytes is the header as it arrived, for forwarding unchanged.
func (h Header) Bytes() []byte { b := h.raw; return b[:] }

// Version says which protocol the header asked for.
func (h Header) Version() Version {
	switch {
	// 1.0 is version 1.0.0 under one of three protocol identifiers: the
	// protocol itself, its TLS layer and its SASL layer. The identifier is
	// part of the check because 0-9's header is also major 1 minor 0 --
	// with the version the other way round and a protocol class where 1.0
	// puts its identifier.
	case (h.ID == ProtoAMQP || h.ID == ProtoTLS || h.ID == ProtoSASL) &&
		h.Major == 1 && h.Minor == 0 && h.Revision == 0:
		return V10
	case h.ID == 0 && h.Major == 0 && h.Minor == 9 && h.Revision == 1:
		return V091
	// The two headers before 0-9-1, which put a protocol class and
	// instance where it puts zeroes and then the version the other way
	// round: 1.1.8.0 is 0-8 and 1.1.0.9 is 0-9. They are read as legacy
	// because the framing is the same one, so a listener can refuse them
	// by name -- or answer them, which is what a broker does.
	case h.ID == 1 && h.Major == 1 && h.Minor == 8 && h.Revision == 0:
		return Legacy
	case h.ID == 1 && h.Major == 1 && h.Minor == 0 && h.Revision == 9:
		return Legacy
	}
	return Unknown
}

// Layer says what a 1.0 header asked to speak: AMQP, TLS or SASL. It is
// meaningless before 1.0, where the field is reserved.
func (h Header) Layer() uint8 { return h.ID }

func (h Header) String() string {
	v := h.Version()
	if v == V10 {
		switch h.ID {
		case ProtoTLS:
			return "1.0 tls"
		case ProtoSASL:
			return "1.0 sasl"
		}
		return "1.0"
	}
	if v == Unknown {
		return fmt.Sprintf("unknown (%d.%d.%d.%d)", h.ID, h.Major, h.Minor, h.Revision)
	}
	return v.String()
}

// Frame is one frame, with the octets it arrived as.
type Frame struct {
	Version Version
	// Type is a frame type of the version: method, header, body or
	// heartbeat on 0-9-1; AMQP or SASL on 1.0.
	Type    uint8
	Channel uint16
	// Payload is the part a method or a performative is read from: on
	// 0-9-1 the octets between the size and the frame-end, on 1.0 the
	// body after the extended header.
	Payload []byte
	// Raw is the whole frame as it arrived. It is what the relay
	// forwards: this package never renders a frame back.
	Raw []byte
}

// Heartbeat says whether this frame is a keepalive and nothing else. The
// two versions spell it differently -- 0-9-1 has a frame type for it, 1.0
// sends a frame with no body at all -- which is exactly the kind of
// difference a caller should not have to remember.
func (f *Frame) Heartbeat() bool {
	if f.Version == V10 {
		return f.Type == FrameAMQP && len(f.Payload) == 0
	}
	return f.Type == FrameHeartbeat
}

// KnownType says whether the frame type is one the version defines.
//
// An unknown type is not read further and not made sense of; it is
// reported so a policy can refuse the connection. A broker's own
// behaviour here varies, and "whatever the broker does with a frame type
// that does not exist" is not a property a relay should be passing
// through.
func (f *Frame) KnownType() bool {
	if f.Version == V10 {
		return f.Type == FrameAMQP || f.Type == FrameSASL
	}
	switch f.Type {
	case FrameMethod, FrameHeader, FrameBody, FrameHeartbeat:
		return true
	}
	return false
}

// Reader reads protocol headers and frames off one connection.
//
// It is version-aware because the framing is: the caller reads the header
// first, which sets the version, and a 1.0 connection that switches from
// its SASL layer to AMQP itself reads a second header on the same reader.
type Reader struct {
	br  *bufio.Reader
	v   Version
	max int
}

// NewReader wraps a connection. max bounds one frame, including its own
// header, and a value below the protocol minimum is raised to it: a
// listener must not refuse a peer for sending the smallest frame the
// specification allows.
func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 {
		max = DefaultMaxFrame
	}
	if max < MinFrameMax091 {
		max = MinFrameMax091
	}
	return &Reader{br: bufio.NewReaderSize(r, 16<<10), max: max}
}

// Version is the version in force.
func (r *Reader) Version() Version { return r.v }

// SetVersion forces the framing, for a caller that learned the version
// some other way.
func (r *Reader) SetVersion(v Version) { r.v = v }

// Max is the frame bound in force.
func (r *Reader) Max() int { return r.max }

// Header reads a protocol header and puts its version in force.
//
// A header whose version this package does not read is returned with the
// version Unknown rather than as an error: the whole point of reading it
// is to be able to refuse it by name.
func (r *Reader) Header() (Header, error) {
	var b [HeaderSize]byte
	if _, err := io.ReadFull(r.br, b[:]); err != nil {
		return Header{}, err
	}
	h, err := ParseHeader(b[:])
	if err != nil {
		return Header{}, err
	}
	r.v = h.Version()
	return h, nil
}

// NextOrHeader reads whatever comes next: a frame, or a protocol header.
//
// A connection can send a header in the middle of its stream, and on AMQP 1.0
// it must: a successful SASL exchange ends with both peers starting again with
// a fresh header (§5.3.2), and a peer that refuses the version it was sent
// answers with one of its own before closing (§2.2 and 0-9-1 §4.2.2). A reader
// that assumed a frame there would read eight octets of header as a frame
// header and lose the stream.
//
// One peeked octet tells them apart, and it is unambiguous in both framings: a
// header begins with the literal `A`, a 0-9-1 frame begins with a frame type
// (1, 2, 3 or 8), and a 1.0 frame begins with the most significant octet of a
// size this reader bounds far below `A`'s value -- so a frame claiming
// 0x41000000 octets is refused for its size either way.
func (r *Reader) NextOrHeader() (*Frame, *Header, error) {
	b, err := r.br.Peek(1)
	if err != nil {
		return nil, nil, err
	}
	if b[0] == literal[0] {
		h, err := r.Header()
		if err != nil {
			return nil, nil, err
		}
		return nil, &h, nil
	}
	f, err := r.Next()
	return f, nil, err
}

// Next reads one frame.
func (r *Reader) Next() (*Frame, error) {
	switch r.v {
	case V10:
		return r.next10()
	case V091, Legacy:
		return r.next091()
	}
	return nil, errors.New("the protocol version is not known yet")
}

// next091 reads a 0-9-1 frame: type, channel, size, payload, frame-end.
func (r *Reader) next091() (*Frame, error) {
	var h [7]byte
	if _, err := io.ReadFull(r.br, h[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(h[3:7])
	// The bound before the allocation. The size is four octets from the
	// network, so a reader that made room for it first would let a
	// twelve-octet packet ask for four gigabytes.
	if int64(size)+8 > int64(r.max) {
		return nil, fmt.Errorf("a frame of %d octets is over the %d this listener allows", size+8, r.max)
	}
	raw := make([]byte, 7+int(size)+1)
	copy(raw, h[:])
	if _, err := io.ReadFull(r.br, raw[7:]); err != nil {
		return nil, err
	}
	if raw[len(raw)-1] != FrameEnd {
		// The frame-end octet is the protocol's own check that the size
		// it was told is the size it got. A mismatch means the stream is
		// no longer framed, and every octet after it is the sender's
		// choice of what this relay reads as a method.
		return nil, fmt.Errorf("a frame of %d octets did not end with %#x", size, FrameEnd)
	}
	return &Frame{Version: r.v, Type: h[0], Channel: binary.BigEndian.Uint16(h[1:3]),
		Payload: raw[7 : 7+int(size)], Raw: raw}, nil
}

// next10 reads a 1.0 frame: a size that includes the header, a data
// offset that says where the body starts, a type and a channel.
func (r *Reader) next10() (*Frame, error) {
	var h [8]byte
	if _, err := io.ReadFull(r.br, h[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(h[0:4])
	if size < 8 {
		return nil, fmt.Errorf("a frame of %d octets is smaller than its own header", size)
	}
	if int64(size) > int64(r.max) {
		return nil, fmt.Errorf("a frame of %d octets is over the %d this listener allows", size, r.max)
	}
	doff := int(h[4])
	if doff < 2 {
		// The data offset is in four-octet words and counts from the
		// start of the frame, so anything below two puts the body inside
		// the header it is described by.
		return nil, fmt.Errorf("a data offset of %d words is inside the frame header", doff)
	}
	if doff*4 > int(size) {
		return nil, fmt.Errorf("a data offset of %d words is past the end of a %d octet frame", doff, size)
	}
	raw := make([]byte, int(size))
	copy(raw, h[:])
	if _, err := io.ReadFull(r.br, raw[8:]); err != nil {
		return nil, err
	}
	return &Frame{Version: V10, Type: h[5], Channel: binary.BigEndian.Uint16(h[6:8]),
		Payload: raw[doff*4:], Raw: raw}, nil
}
