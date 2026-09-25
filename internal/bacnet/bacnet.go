// Package bacnet reads BACnet/IP: the virtual link layer of ASHRAE 135
// Annex J, the network layer under it and the application layer inside
// that, as far as a relay in front of a building needs to read them.
//
// BACnet is what runs the building. Air handling, chillers, boilers, fan
// coils, lighting, lifts, access control, smoke control, pressurisation
// in an operating theatre: the controllers that hold those setpoints
// speak this protocol, and a great many of them have been in a ceiling
// void since before the estate had a security team.
//
// Three things about the protocol decide what a relay in front of it can
// be, and they are the reasons this package is shaped the way it is.
//
// **There is no identity.** Plain BACnet has no user, no session and no
// authentication. Clause 24's authenticate service was withdrawn, and
// the Network Security of clause 24 (Challenge-Request, Security-Payload,
// key distribution) is implemented by almost nothing in the field. A
// device answers whoever asks. So a policy has three things to work
// with: the address a datagram came from, the service it asks for, and
// the object and property it names -- and this package's job is to
// deliver the last two honestly or say it could not.
//
// **Writing is a service, not a mode.** readProperty and writeProperty
// are different service choices in the same request shape, so the
// difference between reading a zone temperature and setting it is one
// octet. reinitializeDevice restarts a controller and
// deviceCommunicationControl tells it to stop talking for a while --
// both are ordinary confirmed requests, both take an optional password
// that is sent in the clear and that most devices leave unset. So the
// service choice is the first decision, and the dangerous services are
// named rather than inferred.
//
// **It is broadcast, and it amplifies.** Who-Is is a broadcast that every
// device answers with an I-Am; a BBMD (a BACnet Broadcast Management
// Device) forwards broadcasts between subnets, and its foreign-device
// registration lets a host ask to be sent every broadcast on a network it
// is not on. Forwarded-NPDU carries the address the message came from
// inside the payload, where a sender chooses it. Those three together
// are a reflection amplifier with a directory service attached, which is
// why the BBMD management functions are separated out here rather than
// left as just more function codes.
//
// What this package does not do is interpret an encoded value. Whether
// 21.5 is a reasonable setpoint for a room is the estate's business; that
// the request is a write, to that object, of that property, from that
// address, is the relay's.
package bacnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"
)

// Port is the BACnet/IP port, 0xBAC0. Annex J assigns 47808 and the
// fifteen above it to the fifteen further networks a host can serve.
const Port = 47808

// MaxMessage is the largest BACnet/IP message Annex J allows: an NPDU of
// 1497 octets, which with the four-octet virtual link header is what
// fits an Ethernet frame without fragmenting. A datagram longer than
// this is not a message this protocol can carry, whatever it declares.
const MaxMessage = 1497

// The errors this package returns. They are wrapped, so a caller
// separates "this is not BACnet at all" from "this is BACnet and it is
// broken", which are different events: the first is a stray datagram on
// a well-known port and the second is a peer worth naming.
var (
	// ErrNotBACnet is a datagram whose first octet is not 0x81. Nothing
	// of this protocol is in it.
	ErrNotBACnet = errors.New("not a BACnet/IP message")
	// ErrTruncated is a message that ends inside a field.
	ErrTruncated = errors.New("truncated")
	// ErrMalformed is a message whose fields contradict each other or
	// the standard: a declared length that is not the datagram's, a
	// reserved bit that is set, a version that is not 1.
	ErrMalformed = errors.New("malformed")
	// ErrUnsupported is a shape this package will not read: a function
	// code the standard does not define, or a security wrapper whose
	// contents it cannot see.
	ErrUnsupported = errors.New("unsupported")
)

// Function is a BVLC function code: what the virtual link layer is being
// asked to do with the message.
type Function uint8

// The BVLC functions of Annex J, and the one clause 24 adds.
const (
	FuncResult                Function = 0x00
	FuncWriteBDT              Function = 0x01
	FuncReadBDT               Function = 0x02
	FuncReadBDTAck            Function = 0x03
	FuncForwardedNPDU         Function = 0x04
	FuncRegisterForeignDevice Function = 0x05
	FuncReadFDT               Function = 0x06
	FuncReadFDTAck            Function = 0x07
	FuncDeleteFDTEntry        Function = 0x08
	FuncDistributeBroadcast   Function = 0x09
	FuncOriginalUnicast       Function = 0x0A
	FuncOriginalBroadcast     Function = 0x0B
	FuncSecureBVLL            Function = 0x0C
)

var functionNames = map[Function]string{
	FuncResult:                "bvlc-result",
	FuncWriteBDT:              "write-broadcast-distribution-table",
	FuncReadBDT:               "read-broadcast-distribution-table",
	FuncReadBDTAck:            "read-broadcast-distribution-table-ack",
	FuncForwardedNPDU:         "forwarded-npdu",
	FuncRegisterForeignDevice: "register-foreign-device",
	FuncReadFDT:               "read-foreign-device-table",
	FuncReadFDTAck:            "read-foreign-device-table-ack",
	FuncDeleteFDTEntry:        "delete-foreign-device-table-entry",
	FuncDistributeBroadcast:   "distribute-broadcast-to-network",
	FuncOriginalUnicast:       "original-unicast-npdu",
	FuncOriginalBroadcast:     "original-broadcast-npdu",
	FuncSecureBVLL:            "secure-bvll",
}

// String names the function for a log line and a policy rule. An
// undefined code is rendered with its number rather than as a name this
// standard does not have.
func (f Function) String() string {
	if s, ok := functionNames[f]; ok {
		return s
	}
	return fmt.Sprintf("function-0x%02x", uint8(f))
}

// Known reports whether the standard defines this function code.
func (f Function) Known() bool { _, ok := functionNames[f]; return ok }

// CarriesNPDU reports whether the payload is a network layer message
// this package can read further into. The other functions are the
// virtual link layer talking about itself.
func (f Function) CarriesNPDU() bool {
	switch f {
	case FuncForwardedNPDU, FuncDistributeBroadcast, FuncOriginalUnicast, FuncOriginalBroadcast:
		return true
	}
	return false
}

// Broadcast reports whether the function asks for the message to reach
// every device rather than one: directly on the local subnet, or through
// every BBMD in the distribution table.
func (f Function) Broadcast() bool {
	switch f {
	case FuncOriginalBroadcast, FuncDistributeBroadcast, FuncForwardedNPDU:
		return true
	}
	return false
}

// LinkRequest reports whether the function is a request the virtual link
// layer answers: one of the table reads or writes, or a foreign device
// registration.
//
// It matters to a relay because the link layer has no identifier to pair
// an answer by. A relay that forwards one of these has to expect exactly
// one answer back -- a BVLC-Result or a table acknowledgement -- and a
// relay that expected none would forward the question and drop the reply.
func (f Function) LinkRequest() bool {
	switch f {
	case FuncWriteBDT, FuncReadBDT, FuncRegisterForeignDevice, FuncReadFDT, FuncDeleteFDTEntry:
		return true
	}
	return false
}

// BBMD reports whether the function manages a broadcast management
// device: its distribution table, or the foreign devices registered with
// it.
//
// These are separated out because they are the protocol's own
// administration and because two of them are the whole of a known attack.
// Register-Foreign-Device asks a BBMD to send the registering address
// every broadcast on the network for the next few minutes, from an
// unauthenticated datagram; Read-Broadcast-Distribution-Table hands back
// the map of the estate's BACnet routing to whoever asks. Neither has any
// business crossing a relay from a client network.
func (f Function) BBMD() bool {
	switch f {
	case FuncWriteBDT, FuncReadBDT, FuncReadBDTAck,
		FuncRegisterForeignDevice, FuncReadFDT, FuncReadFDTAck, FuncDeleteFDTEntry:
		return true
	}
	return false
}

// BVLC is a parsed virtual link layer message.
type BVLC struct {
	Function Function
	// Origin is the originating device's B/IP address, which only a
	// Forwarded-NPDU carries -- inside the payload, where whoever sent
	// the datagram chose it. HasOrigin says whether it is there at all;
	// that it is true says nothing about whether it is true.
	Origin    netip.AddrPort
	HasOrigin bool
	// Payload is what follows the header and, for a Forwarded-NPDU, the
	// originating address: the NPDU when the function carries one, and
	// the function's own fields otherwise.
	Payload []byte
}

const bvlcHeader = 4

// ParseBVLC reads the virtual link layer.
//
// The declared length must be the datagram's length exactly. A message
// that declares less leaves octets after it that no BACnet device will
// read and that an inspecting relay would therefore not be inspecting --
// which is a way to carry something past this relay to a device that
// reads further. A message that declares more is truncated. Either way
// the length field and the datagram disagree, and a relay that resolved
// the disagreement by trusting one of them would be choosing which of
// the two readings to forward.
func ParseBVLC(b []byte) (BVLC, error) {
	if len(b) == 0 {
		return BVLC{}, fmt.Errorf("%w: an empty datagram", ErrTruncated)
	}
	if b[0] != 0x81 {
		return BVLC{}, fmt.Errorf("%w: type 0x%02x", ErrNotBACnet, b[0])
	}
	if len(b) < bvlcHeader {
		return BVLC{}, fmt.Errorf("%w: %d octets, and the link header is %d", ErrTruncated, len(b), bvlcHeader)
	}
	if len(b) > MaxMessage {
		return BVLC{}, fmt.Errorf("%w: %d octets, and Annex J allows %d", ErrMalformed, len(b), MaxMessage)
	}
	declared := int(binary.BigEndian.Uint16(b[2:4]))
	switch {
	case declared < bvlcHeader:
		return BVLC{}, fmt.Errorf("%w: a declared length of %d, which does not cover the header", ErrMalformed, declared)
	case declared > len(b):
		return BVLC{}, fmt.Errorf("%w: %d octets declared and %d arrived", ErrTruncated, declared, len(b))
	case declared < len(b):
		return BVLC{}, fmt.Errorf("%w: %d octets declared and %d arrived, so %d would go unread",
			ErrMalformed, declared, len(b), len(b)-declared)
	}
	v := BVLC{Function: Function(b[1]), Payload: b[bvlcHeader:declared]}
	if !v.Function.Known() {
		return v, fmt.Errorf("%w: %s", ErrUnsupported, v.Function)
	}
	if v.Function == FuncForwardedNPDU {
		if len(v.Payload) < 6 {
			return v, fmt.Errorf("%w: a forwarded-npdu without its originating address", ErrTruncated)
		}
		v.Origin = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{v.Payload[0], v.Payload[1], v.Payload[2], v.Payload[3]}),
			binary.BigEndian.Uint16(v.Payload[4:6]))
		v.HasOrigin = true
		v.Payload = v.Payload[6:]
	}
	return v, nil
}

// The NPCI control octet's bits (clause 6.2.2).
const (
	npciNetworkMessage = 0x80
	npciReservedHigh   = 0x40
	npciHasDest        = 0x20
	npciReservedLow    = 0x10
	npciHasSource      = 0x08
	npciExpectingReply = 0x04
	npciPriority       = 0x03
)

// NPDU is a parsed network layer header and what it carries.
type NPDU struct {
	// Version is always 1; a message that says otherwise is refused
	// rather than read as if it were version 1.
	Version uint8
	// DNET, DLEN and DADR are the destination: which BACnet network, and
	// which device on it. HasDest says whether the message carries them
	// at all -- without them it is for the network it arrived on.
	DNET    uint16
	DADR    []byte
	HasDest bool
	// SNET and SADR are the source, filled in by the router that
	// forwarded the message.
	SNET      uint16
	SADR      []byte
	HasSource bool
	// Hop is the hop count, present only alongside a destination. A
	// router decrements it, so it is the only thing that stops a routing
	// loop in a misconfigured estate.
	Hop uint8
	// Priority is the network priority: 0 normal, 1 urgent, 2 critical
	// equipment, 3 life safety. It decides what a congested router
	// drops, so a client that sends everything as life safety is
	// claiming a queue it has not earned.
	Priority uint8
	// ExpectingReply is the bit that says a reply is expected. It is
	// what turns a broadcast into an amplifier.
	ExpectingReply bool
	// NetworkMessage says the payload is the network layer's own message
	// rather than an application PDU. MessageType names it, and VendorID
	// is present for the proprietary range.
	NetworkMessage bool
	MessageType    NetworkMessageType
	VendorID       uint16
	HasVendor      bool
	// APDU is the application layer message, for an NPDU that carries
	// one. It is empty for a network layer message.
	APDU []byte
}

// BroadcastDest reports whether the destination is every device on the
// destination network: a destination network with a zero-length address,
// which clause 6.2.2 defines as a broadcast there.
func (n NPDU) BroadcastDest() bool { return n.HasDest && len(n.DADR) == 0 }

// ParseNPDU reads the network layer.
//
// The reserved bits are checked. They are reserved and zero in every
// version of the standard, and a sender that sets one is either not
// speaking this protocol or is aiming at a parser that ignores them --
// and a relay whose reading of a message differs from the device's is a
// relay that can be talked past.
func ParseNPDU(b []byte) (NPDU, error) {
	if len(b) < 2 {
		return NPDU{}, fmt.Errorf("%w: %d octets, and the network header is 2", ErrTruncated, len(b))
	}
	n := NPDU{Version: b[0]}
	if n.Version != 1 {
		return n, fmt.Errorf("%w: network layer version %d, and the standard has only 1", ErrMalformed, n.Version)
	}
	c := b[1]
	if c&(npciReservedHigh|npciReservedLow) != 0 {
		return n, fmt.Errorf("%w: reserved bits set in the control octet (0x%02x)", ErrMalformed, c)
	}
	n.Priority = c & npciPriority
	n.ExpectingReply = c&npciExpectingReply != 0
	n.NetworkMessage = c&npciNetworkMessage != 0
	at := 2
	take := func(k int, what string) ([]byte, error) {
		if at+k > len(b) {
			return nil, fmt.Errorf("%w: %s needs %d octets and %d are left", ErrTruncated, what, k, len(b)-at)
		}
		out := b[at : at+k]
		at += k
		return out, nil
	}
	if c&npciHasDest != 0 {
		h, err := take(3, "the destination")
		if err != nil {
			return n, err
		}
		n.HasDest, n.DNET = true, binary.BigEndian.Uint16(h[0:2])
		if n.DADR, err = take(int(h[2]), "the destination address"); err != nil {
			return n, err
		}
	}
	if c&npciHasSource != 0 {
		h, err := take(3, "the source")
		if err != nil {
			return n, err
		}
		n.HasSource, n.SNET = true, binary.BigEndian.Uint16(h[0:2])
		// A source address of zero length is not a source. Clause 6.2.2
		// gives SLEN no broadcast meaning -- a message comes from one
		// device -- so a zero here is a field that was written to be
		// skipped rather than read.
		if h[2] == 0 {
			return n, fmt.Errorf("%w: a source network with a zero-length address", ErrMalformed)
		}
		if n.SADR, err = take(int(h[2]), "the source address"); err != nil {
			return n, err
		}
	}
	if n.HasDest {
		h, err := take(1, "the hop count")
		if err != nil {
			return n, err
		}
		n.Hop = h[0]
	}
	if !n.NetworkMessage {
		n.APDU = b[at:]
		if len(n.APDU) == 0 {
			return n, fmt.Errorf("%w: a network header with no application message after it", ErrTruncated)
		}
		return n, nil
	}
	h, err := take(1, "the network message type")
	if err != nil {
		return n, err
	}
	n.MessageType = NetworkMessageType(h[0])
	if n.MessageType.Proprietary() {
		v, err := take(2, "the vendor identifier")
		if err != nil {
			return n, err
		}
		n.VendorID, n.HasVendor = binary.BigEndian.Uint16(v), true
	}
	return n, nil
}

// Clip cuts a string from a message to a bounded length on a rune
// boundary, so a name out of a device cannot make a log line as long as
// the attacker likes and cannot end it half way through a character.
func Clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "..."
}
