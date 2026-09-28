// Package coap reads the Constrained Application Protocol of RFC 7252: the
// message layer, the option layer above it and the request a relay in front of a
// constrained network needs to see, whether the datagram arrived in the clear or
// out of a DTLS session.
//
// CoAP is REST for devices too small to run TLS comfortably. A sensor, a valve, a
// street light, a smart meter, a LwM2M-managed handset: the thing on the other
// end has a method, a path, a content format and a payload, exactly as an HTTP
// resource does, in a protocol that fits in a few hundred octets over UDP. What
// makes it worth a relay of its own rather than treating the datagram as opaque
// is that the path is *right there* in the message and says what is about to
// happen: a PUT to /3311/0/5850 turns a light on, and it is one option away from
// a GET of the same resource.
//
// Four things about the protocol decide what a relay in front of it can be.
//
// **The commonest deployment has no security at all.** RFC 7252 s9 defines DTLS
// with pre-shared keys, raw public keys or certificates, and it also defines
// NoSec, which is "no DTLS", and NoSec is what most of the field runs: a device
// with sixty kilobytes of flash and a coin cell is a device whose vendor shipped
// it without a handshake. In NoSec there is no identity whatsoever -- not a weak
// one, none -- so a policy has the source address, the method, the path and the
// payload, and this package's job is to deliver the middle three honestly or say
// it could not.
//
// **It is a reflection amplifier by construction.** A four-octet GET over UDP
// can return a kilobyte, and /.well-known/core (RFC 6690) is a resource whose
// whole purpose is to return a list of every other resource -- the largest answer
// on the device, from the smallest request, at an address the sender chose.
// Block-wise transfer (RFC 7959) then lets a client ask for that answer in pieces
// and declare how large the whole of it will be. So the size of an answer
// relative to the question it answers is a number worth bounding, and this
// package exposes the block and size options rather than leaving them inside an
// opaque value.
//
// **A server can be told to fetch.** Proxy-Uri and Proxy-Scheme (s5.10.2) turn
// the thing at the other end into a forward proxy: "get this URI for me, and send
// me what it says". On a constrained network that is an open relay, an
// amplification stage and a way to reach the things the network was segmented to
// protect, all in one option, and it is why those two options are called out
// separately here rather than counted among the rest.
//
// **The standard says what a proxy must do with an option it does not know**, and
// it is one of the few protocols that does. An option number's own low bits carry
// its class (s5.4.6): odd is Critical, bit one is UnSafe to forward. An
// unrecognised Critical option in a request is 4.02 Bad Option; an unrecognised
// UnSafe option must not be forwarded at all, and a proxy answers 5.02 Bad
// Gateway rather than passing it on. That rule is a gift to a relay, because it
// means "I do not understand this" has a defined and safe answer instead of a
// judgement call, so the predicates are part of this package rather than
// something a caller works out from a table.
//
// What this package does not do is decide. Whether a PUT to a given path is
// something this estate permits is the policy's business; that the message is a
// PUT, to that path, with that content format, carrying that many octets, and
// that nothing in it was read past the end of what a peer sent, is this
// package's.
package coap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The bounds. Each is a refusal rather than a truncation: a message this package
// cannot read completely is one a caller must not act on half of.
const (
	// HeaderLen is the fixed header: version, type and token length in one
	// octet, the code, and the message identifier.
	HeaderLen = 4
	// PayloadMarker separates the options from the payload. A marker with
	// nothing after it is a message format error (RFC 7252 s3.1), because a
	// zero-length payload is expressed by leaving the marker out.
	PayloadMarker = 0xFF
	// Version is the only version there is. RFC 7252 s3 says a message of any
	// other version is silently ignored, which is what a refusal here becomes.
	Version = 1
	// MaxToken is the token length RFC 7252 allows. See ErrToken for why 9 to
	// 15 are refused rather than read as RFC 8974 extended tokens.
	MaxToken = 8
	// MaxMessage is what this package will read at all. RFC 7252 s4.6 puts a
	// sensible message at 1152 octets so that it fits an IPv6 datagram with
	// headroom, and that is the listener's default bound; this one is the
	// structural limit, generous enough for a hop whose MTU is known to be
	// larger and small enough that a parse is cheap.
	MaxMessage = 8192
	// MaxOptions bounds the options in one message. A message made of
	// thousands of empty options is a parse nobody asked for.
	MaxOptions = 64
	// MaxOptionLen is the longest option value RFC 7252 defines, which is
	// Proxy-Uri at 1034 octets. Each option's own range is checked as well;
	// this is the bound that stops a length field asking for a large
	// allocation before anything has looked at which option it is.
	MaxOptionLen = 1034
	// MaxPathSegments and MaxQueryParts bound the repeated options that make
	// up a URI. A path of ten thousand segments is not a path.
	MaxPathSegments = 32
	MaxQueryParts   = 32
)

// The errors. Each names the layer that refused, so a listener can count "a
// message that is not CoAP" apart from "a CoAP message whose options do not add
// up", which are different events with different people behind them.
var (
	// ErrShort is a message shorter than the fields it claims.
	ErrShort = errors.New("coap: truncated")
	// ErrTooLong is a message, an option or a token past a bound.
	ErrTooLong = errors.New("coap: past the bound")
	// ErrVersion is a version this package does not read.
	ErrVersion = errors.New("coap: version")
	// ErrToken is a token length RFC 7252 reserves.
	ErrToken = errors.New("coap: token length")
	// ErrOption is an option whose encoding or length is not what the standard
	// says it is.
	ErrOption = errors.New("coap: option")
	// ErrPayload is a payload marker with no payload after it.
	ErrPayload = errors.New("coap: payload marker")
	// ErrEmpty is an empty message (code 0.00) carrying something, which
	// RFC 7252 s4.1 makes a format error: an empty message is a bare
	// acknowledgement or a reset and has no token, options or payload.
	ErrEmpty = errors.New("coap: empty message is not empty")
)

// Type is the message type of RFC 7252 s3, which is the reliability layer rather
// than anything about the request inside.
type Type uint8

const (
	// Confirmable asks to be acknowledged and is retransmitted until it is.
	Confirmable Type = 0
	// NonConfirmable is sent once and not acknowledged. It is what a sensor
	// reporting into a lossy network sends, and it is also what an attacker
	// sends when it does not care whether anything came back -- including to a
	// multicast group.
	NonConfirmable Type = 1
	// Acknowledgement acknowledges a Confirmable message, and carries the
	// response with it when the response was ready in time (a piggybacked
	// response).
	Acknowledgement Type = 2
	// Reset says the message could not be processed: it is the answer to a
	// message whose format was wrong, and the answer a host gives to a
	// notification it no longer wants.
	Reset Type = 3
)

func (t Type) String() string {
	switch t {
	case Confirmable:
		return "con"
	case NonConfirmable:
		return "non"
	case Acknowledgement:
		return "ack"
	case Reset:
		return "rst"
	}
	return fmt.Sprintf("type(%d)", uint8(t))
}

// TypeOf reads a type's name back, for a configuration file.
func TypeOf(name string) (Type, bool) {
	switch name {
	case "con", "confirmable":
		return Confirmable, true
	case "non", "non_confirmable":
		return NonConfirmable, true
	case "ack", "acknowledgement":
		return Acknowledgement, true
	case "rst", "reset":
		return Reset, true
	}
	return 0, false
}

// Message is one CoAP message, parsed.
type Message struct {
	Type Type
	// Code is the method in a request and the result in a response. 0.00 is
	// the empty message, which is neither.
	Code Code
	// MessageID pairs an acknowledgement with what it acknowledges, and is the
	// duplicate-detection key. It is not the request/response pairing: that is
	// the token, because a separate response arrives in a message of its own
	// with its own identifier.
	MessageID uint16
	// Token pairs a response with its request, and is the only thing that
	// does. Up to eight octets, chosen by the client.
	Token []byte
	// Options are in the order they arrived, which is also ascending number
	// order because the encoding is a delta. A repeated option appears once
	// per instance.
	Options []Option
	// Payload is what came after the marker, empty when there was no marker.
	Payload []byte
	// Raw is the message as it arrived.
	Raw []byte
}

// Parse reads one datagram.
func Parse(raw []byte) (*Message, error) {
	if len(raw) > MaxMessage {
		return nil, fmt.Errorf("%w: %d octets", ErrTooLong, len(raw))
	}
	if len(raw) < HeaderLen {
		return nil, fmt.Errorf("%w: %d octets, less than a header", ErrShort, len(raw))
	}
	if v := raw[0] >> 6; v != Version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, v)
	}
	tkl := int(raw[0] & 0x0f)
	if tkl > MaxToken {
		// RFC 7252 s3 reserves 9 to 15 and makes a message using them a format
		// error. They are refused rather than read as the extended token
		// lengths of RFC 8974, which reuses 13 and 14 as "one or two more
		// octets of length follow", because the two readings disagree about
		// where the options start. A relay that guessed would be deciding
		// about one message while the server acted on another, which is the
		// class of bug nobody finds.
		return nil, fmt.Errorf("%w: %d", ErrToken, tkl)
	}
	m := &Message{
		Type:      Type(raw[0] >> 4 & 0x03),
		Code:      Code(raw[1]),
		MessageID: binary.BigEndian.Uint16(raw[2:4]),
		Raw:       raw,
	}
	rest := raw[HeaderLen:]
	if len(rest) < tkl {
		return nil, fmt.Errorf("%w: a token of %d octets in %d", ErrShort, tkl, len(rest))
	}
	m.Token = rest[:tkl]
	rest = rest[tkl:]
	opts, payload, err := parseOptions(rest)
	if err != nil {
		return nil, err
	}
	m.Options, m.Payload = opts, payload
	if m.Code.IsEmpty() {
		// RFC 7252 s4.1: an empty message has no token, no options and no
		// payload. One that carries any of them is a format error -- and worth
		// refusing rather than ignoring the extra, because an empty message is
		// how a hop says "I could not read that", and one with a payload
		// smuggled onto it is two different messages depending on who reads it.
		if tkl != 0 || len(opts) != 0 || len(payload) != 0 {
			return nil, fmt.Errorf("%w: token %d, %d options, %d octets of payload",
				ErrEmpty, tkl, len(opts), len(payload))
		}
	}
	return m, nil
}

// parseOptions walks the delta-encoded options and returns the payload after
// them.
//
// The encoding is why this is a loop rather than a table read: an option's number
// is the previous number plus a delta, so an option cannot be skipped and the
// options cannot be read out of order. Everything after a length nobody checked
// would be read at the wrong offset, which is the one mistake in a CoAP parser
// that turns a path policy into a decision about a different path than the server
// will act on.
func parseOptions(b []byte) ([]Option, []byte, error) {
	var (
		out    []Option
		number uint32
	)
	for len(b) > 0 {
		if b[0] == PayloadMarker {
			if len(b) == 1 {
				// RFC 7252 s3.1: the marker is followed by a payload of at
				// least one octet, because no payload is expressed by leaving
				// the marker out.
				return nil, nil, fmt.Errorf("%w: nothing after it", ErrPayload)
			}
			return out, b[1:], nil
		}
		if len(out) >= MaxOptions {
			return nil, nil, fmt.Errorf("%w: more than %d options", ErrTooLong, MaxOptions)
		}
		first := b[0]
		b = b[1:]
		// The delta's extension octets come before the length's, so they are
		// read in that order and the slice moves between them.
		delta, n, err := extend(first>>4, b, "delta")
		if err != nil {
			return nil, nil, err
		}
		b = b[n:]
		length, n, err := extend(first&0x0f, b, "length")
		if err != nil {
			return nil, nil, err
		}
		b = b[n:]
		if length > MaxOptionLen {
			return nil, nil, fmt.Errorf("%w: a value of %d octets", ErrTooLong, length)
		}
		// Safe as an int: the bound above holds length at or below MaxOptionLen.
		if int(length) > len(b) {
			return nil, nil, fmt.Errorf("%w: an option of %d octets in %d",
				ErrShort, length, len(b))
		}
		number += delta
		if number > 0xffff {
			// The registry is sixteen bits wide, and the deltas accumulate, so
			// a chain of large ones runs off the end of it. A number nobody can
			// name is not an option this relay can have a policy about.
			return nil, nil, fmt.Errorf("%w: number %d", ErrOption, number)
		}
		out = append(out, Option{Number: uint16(number), Value: b[:length]})
		b = b[length:]
	}
	return out, nil, nil
}

// extend reads a nibble and the extension octets RFC 7252 s3.1 defines for it:
// 13 means one more octet plus thirteen, 14 means two more plus two hundred and
// sixty-nine, and 15 is reserved.
func extend(nibble uint8, b []byte, what string) (uint32, int, error) {
	switch nibble {
	case 13:
		if len(b) < 1 {
			return 0, 0, fmt.Errorf("%w: an extended %s with no octet after it", ErrShort, what)
		}
		return uint32(b[0]) + 13, 1, nil
	case 14:
		if len(b) < 2 {
			return 0, 0, fmt.Errorf("%w: an extended %s with %d octets after it", ErrShort, what, len(b))
		}
		return uint32(binary.BigEndian.Uint16(b[:2])) + 269, 2, nil
	case 15:
		// Reserved, and a message using it is a format error. The all-ones
		// first octet is the payload marker and was taken before this.
		return 0, 0, fmt.Errorf("%w: a reserved %s nibble", ErrOption, what)
	}
	return uint32(nibble), 0, nil
}
