// Package opcua reads OPC UA as far as a relay in front of an industrial plant
// needs to: the UA TCP transport of IEC 62541-6, the secure channel it carries,
// and — where the channel's own security leaves the body readable — the service
// request inside.
//
// OPC UA is what the last fifteen years of industrial automation standardised on.
// A modern PLC, a historian, a SCADA client, an MES and a cloud gateway all speak
// it, and unlike the protocols it replaced it was designed with security in it
// rather than bolted beside it: certificates on both ends, a signed and encrypted
// channel, a session with a user identity. That changes what a relay in front of it
// is for, and this package is shaped by three consequences.
//
// **The interesting decisions are in the handshake, not the payload.** Before any
// service call there is a Hello that negotiates buffer sizes, an OpenSecureChannel
// that names a security policy and carries both certificates, and a
// CreateSession/ActivateSession pair that names a user. Those are the fields an
// estate has opinions about — which policies are acceptable, whose certificate,
// which user — and they are in the clear by construction, because they are how the
// two ends agree on what to encrypt. So a relay can enforce a great deal without
// reading a single service call.
//
// **How much of the body is readable is a property of the channel, not of the
// relay.** MessageSecurityMode has three values and they mean three different jobs
// for a reader. With None everything is plaintext. With **Sign** the body is signed
// and *not* encrypted, so a relay can read every node id and method argument — and
// must not change one, because the signature is over what the client sent. With
// SignAndEncrypt the body is ciphertext and a relay can see only the channel and
// the sizes. This package reports which case it is in rather than guessing, and the
// listener's policy is written in terms of it.
//
// **A chunk is not a message.** A service call larger than the negotiated buffer
// arrives as several chunks with the same request identifier, and the body only
// means anything once they are joined. A reader that decided about the first chunk
// would be deciding about a fragment, and one that joined them without bounds would
// let a peer name a total it never has to send. So chunk assembly is here, bounded,
// with the abort chunk type honoured.
//
// What this package does not do is decrypt. A relay that terminated the secure
// channel would be a man in the middle of the one industrial protocol that was
// designed to notice, and it would hold the plant's private key to do it. Where the
// body is encrypted this package says so and reads the envelope.
package opcua

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The bounds. Every one is a refusal rather than a truncation, and every one is
// about a number a peer chose.
const (
	// HeaderLen is the fixed part of every UA TCP message: three octets of type,
	// one of chunk type, and the size.
	HeaderLen = 8
	// MinMessageSize is the smallest legal MessageSize: the header alone.
	MinMessageSize = HeaderLen
	// MaxMessageSize is what this package will read in one chunk. IEC 62541-6
	// s7.1 makes 8192 the smallest buffer a peer may negotiate, and real
	// deployments use 64 kibibytes; this is generous enough for any of them and
	// small enough that a parse is cheap.
	MaxMessageSize = 1 << 20
	// MaxChunks bounds an assembled message's chunk count, and MaxAssembled its
	// total. The two together are what stop a peer describing a transfer it
	// never has to finish.
	MaxChunks    = 64
	MaxAssembled = 8 << 20
	// MaxString is the longest string or byte string this package will read. A
	// certificate is a few kilobytes and an endpoint URL is a few hundred
	// octets, so anything past this is a length field being used as an
	// allocation request.
	MaxString = 64 << 10
	// MaxArray bounds the elements in an array a request carries: the nodes to
	// read, the values to write, the methods to call. A request naming ten
	// thousand nodes is one request and ten thousand operations.
	MaxArray = 1024
	// MaxNamespaces bounds the namespace index a node id may name.
	MaxNamespaces = 1 << 16
)

// The errors, each naming the layer that refused.
var (
	// ErrShort is a message shorter than the fields it claims.
	ErrShort = errors.New("opcua: truncated")
	// ErrTooLong is a length past a bound.
	ErrTooLong = errors.New("opcua: past the bound")
	// ErrMessageType is a message type this package does not read.
	ErrMessageType = errors.New("opcua: message type")
	// ErrChunkType is a chunk type that is not final, intermediate or abort.
	ErrChunkType = errors.New("opcua: chunk type")
	// ErrSize is a MessageSize that does not agree with the octets.
	ErrSize = errors.New("opcua: message size")
	// ErrEncoding is a value encoded in a way the standard does not define.
	ErrEncoding = errors.New("opcua: encoding")
	// ErrOpaque is a body this relay cannot read because the channel encrypted
	// it. It is not a malformed message: it is a message that is doing what it
	// was configured to do.
	ErrOpaque = errors.New("opcua: the body is encrypted")
)

// MessageType is the three-octet tag every UA TCP message starts with.
//
// It is kept as the octets rather than mapped to an integer, because that is what
// a capture shows and what an error should name.
type MessageType [3]byte

// The types of IEC 62541-6 s7.1.2.
var (
	// Hello opens a connection and proposes the buffer sizes.
	Hello = MessageType{'H', 'E', 'L'}
	// Acknowledge answers it with the sizes the server will use, which are the
	// smaller of the two ends' proposals.
	Acknowledge = MessageType{'A', 'C', 'K'}
	// Error ends the connection with a status code and a reason.
	Error = MessageType{'E', 'R', 'R'}
	// ReverseHello is the server connecting outward to a client, for the case
	// where the client is the one behind the firewall.
	ReverseHello = MessageType{'R', 'H', 'E'}
	// OpenSecureChannel carries the security policy and both certificates.
	OpenSecureChannel = MessageType{'O', 'P', 'N'}
	// CloseSecureChannel ends it.
	CloseSecureChannel = MessageType{'C', 'L', 'O'}
	// Message is every service call and every response.
	Message = MessageType{'M', 'S', 'G'}
)

func (t MessageType) String() string { return string(t[:]) }

// Known says the type is one this package reads.
func (t MessageType) Known() bool {
	switch t {
	case Hello, Acknowledge, Error, ReverseHello,
		OpenSecureChannel, CloseSecureChannel, Message:
		return true
	}
	return false
}

// Handshake says the type belongs to the transport's own opening exchange, before
// any secure channel exists.
func (t MessageType) Handshake() bool {
	switch t {
	case Hello, Acknowledge, Error, ReverseHello:
		return true
	}
	return false
}

// Secured says the type carries a secure channel header.
func (t MessageType) Secured() bool {
	switch t {
	case OpenSecureChannel, CloseSecureChannel, Message:
		return true
	}
	return false
}

// TypeOf reads a type's name back, for a configuration file.
func TypeOf(name string) (MessageType, bool) {
	switch name {
	case "hello", "HEL":
		return Hello, true
	case "acknowledge", "ACK":
		return Acknowledge, true
	case "error", "ERR":
		return Error, true
	case "reverse_hello", "RHE":
		return ReverseHello, true
	case "open_secure_channel", "OPN":
		return OpenSecureChannel, true
	case "close_secure_channel", "CLO":
		return CloseSecureChannel, true
	case "message", "MSG":
		return Message, true
	}
	return MessageType{}, false
}

// ChunkType is the fourth octet: whether this chunk finishes the message,
// continues it, or abandons it.
type ChunkType byte

const (
	// Final is the last (or only) chunk of a message.
	Final ChunkType = 'F'
	// Intermediate says more chunks follow with the same request identifier.
	Intermediate ChunkType = 'C'
	// Abort abandons a partly sent message and carries a status code and reason
	// instead of the rest of the body. Honouring it is what stops a peer
	// accumulating a message it has already given up on.
	Abort ChunkType = 'A'
)

func (c ChunkType) String() string {
	switch c {
	case Final:
		return "final"
	case Intermediate:
		return "intermediate"
	case Abort:
		return "abort"
	}
	return fmt.Sprintf("chunk(%q)", byte(c))
}

// Known says the chunk type is one of the three the standard defines.
func (c ChunkType) Known() bool {
	return c == Final || c == Intermediate || c == Abort
}

// Chunk is one UA TCP message off the wire, framed but not yet interpreted.
type Chunk struct {
	Type  MessageType
	Chunk ChunkType
	// Body is everything after the eight-octet header.
	Body []byte
	// Raw is the chunk as it arrived, header included.
	Raw []byte
}

// PeekSize reads the MessageSize from a header without consuming anything, which
// is what a reader needs to know how much to read.
//
// It is separate from Parse because a stream reader has to learn the length before
// it has the message, and because the length is the first thing a peer controls:
// checking it here means one bound in one place rather than a bound at every call
// site that happened to remember.
func PeekSize(header []byte) (int, error) {
	if len(header) < HeaderLen {
		return 0, fmt.Errorf("%w: a header of %d octets", ErrShort, len(header))
	}
	n := binary.LittleEndian.Uint32(header[4:8])
	if n < MinMessageSize {
		return 0, fmt.Errorf("%w: %d octets, less than a header", ErrSize, n)
	}
	if n > MaxMessageSize {
		return 0, fmt.Errorf("%w: a message of %d octets", ErrTooLong, n)
	}
	return int(n), nil
}

// ParseChunk frames one message. raw must be exactly the message: the caller read
// its length from PeekSize.
func ParseChunk(raw []byte) (*Chunk, error) {
	n, err := PeekSize(raw)
	if err != nil {
		return nil, err
	}
	if len(raw) != n {
		// The declared size and the octets disagree. Refused rather than
		// trusting either: a reader that took the shorter would leave the rest
		// to be read as the start of the next message, which is how one peer's
		// message becomes two different messages to two readers.
		return nil, fmt.Errorf("%w: %d octets declared, %d given", ErrSize, n, len(raw))
	}
	c := &Chunk{
		Type:  MessageType{raw[0], raw[1], raw[2]},
		Chunk: ChunkType(raw[3]),
		Body:  raw[HeaderLen:],
		Raw:   raw,
	}
	if !c.Type.Known() {
		return nil, fmt.Errorf("%w: %q", ErrMessageType, c.Type)
	}
	if !c.Chunk.Known() {
		return nil, fmt.Errorf("%w: %q", ErrChunkType, byte(c.Chunk))
	}
	// The handshake messages are never chunked: there is no request identifier
	// to join them by, so a non-final one is a message nobody could reassemble.
	if c.Type.Handshake() && c.Chunk != Final {
		return nil, fmt.Errorf("%w: %s is %s", ErrChunkType, c.Type, c.Chunk)
	}
	return c, nil
}

// reader is a cursor over a message body, with every read bounded.
//
// The whole point of the type is that a caller cannot forget a length check: there
// is no way to read a field except through a method that checks first, and the
// first failure sticks so a caller that ignores one error does not then act on a
// zero value as though it were data.
type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, args...)
	}
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.i+n > len(r.b) {
		r.fail("%w: %d octets wanted, %d left", ErrShort, n, len(r.b)-r.i)
		return false
	}
	return true
}

func (r *reader) byte() byte {
	if !r.need(1) {
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

func (r *reader) uint16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b[r.i:])
	r.i += 2
	return v
}

func (r *reader) uint32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.i:])
	r.i += 4
	return v
}

func (r *reader) int32() int32 {
	return int32(r.uint32()) //nolint:gosec // the wire form is two's complement
}

func (r *reader) uint64() uint64 {
	if !r.need(8) {
		return 0
	}
	v := binary.LittleEndian.Uint64(r.b[r.i:])
	r.i += 8
	return v
}

func (r *reader) int64() int64 {
	return int64(r.uint64()) //nolint:gosec // the wire form is two's complement
}

func (r *reader) bytes(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v
}

// length reads the Int32 that precedes a string, a byte string or an array.
//
// Minus one is the null value and every other negative number is a length nobody
// defined, which is refused rather than clamped to zero: a reader that treated -2
// as empty would agree with nothing else about where the next field starts.
func (r *reader) length(what string, max int) (int, bool) {
	n := r.int32()
	if r.err != nil {
		return 0, false
	}
	switch {
	case n == -1:
		return 0, false // null, and not an error
	case n < -1:
		r.fail("%w: a %s of length %d", ErrEncoding, what, n)
		return 0, false
	case int(n) > max:
		r.fail("%w: a %s of %d", ErrTooLong, what, n)
		return 0, false
	}
	return int(n), true
}

// str reads a String: a length and then UTF-8 octets. The octets are not validated
// as UTF-8 here, because a caller that is about to log one needs to know it was not
// rather than be handed a replacement.
func (r *reader) str() string {
	n, ok := r.length("string", MaxString)
	if !ok {
		return ""
	}
	return string(r.bytes(n))
}

// byteString reads a ByteString, which is the same encoding as a String and a
// different meaning: it is a certificate, a thumbprint or an opaque token.
func (r *reader) byteString() []byte {
	n, ok := r.length("byte string", MaxString)
	if !ok {
		return nil
	}
	return r.bytes(n)
}

// arrayLen reads the Int32 that precedes an array.
func (r *reader) arrayLen(what string) int {
	n, ok := r.length(what, MaxArray)
	if !ok {
		return 0
	}
	return n
}

func (r *reader) done() error { return r.err }

// left says how many octets have not been read, which is what tells a caller
// whether a message carried more than the fields it names.
func (r *reader) left() int { return len(r.b) - r.i }
