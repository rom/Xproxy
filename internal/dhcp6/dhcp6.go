// Package dhcp6 reads DHCPv6 (RFC 8415) and its options.
//
// DHCPv6 is how an IPv6 machine learns what its network is, and like its
// predecessor it is a protocol where *answering* is the attack. But it is not
// the same protocol: the packet format, the message types, the relay mechanism
// and the identity of a client are all different, and reading it as if it were
// DHCPv4 would be worse than not reading it at all. Four differences matter to
// a relay, and they are why this package exists rather than an extension of the
// DHCPv4 one.
//
// **A client is a DUID, not a hardware address.** RFC 8415 s11 identifies a
// client by a DHCP Unique Identifier it chooses for itself and keeps across
// reboots and across interfaces. Nothing authenticates it. It is variable
// length, so it is also a length field an attacker picks -- and because the
// common forms (DUID-LLT and DUID-LL) carry a MAC address inside them, it is
// what lets an inventory recognise the same device as its DHCPv4 self.
//
// **Prefix delegation has no DHCPv4 equivalent.** An IA_PD (option 25) asks for
// a whole prefix and a reply delegates one. A rogue reply can hand a host a
// prefix it will route; a rogue request can ask a real server for one, and a
// server that grants it has given a segment away. Neither has an analogue in
// the v4 protocol, and neither is visible to anything that only counts
// addresses.
//
// **The relay mechanism is a nested message, not a field.** A relay wraps the
// client's message in a RELAY-FORW carrying the link and peer addresses and the
// original inside a Relay-Message option, and a server answers with a
// RELAY-REPL wrapped the same way. So the interesting message is at the bottom
// of a chain, the chain has a depth an attacker chooses, and the relay's own
// options -- Interface-ID (18), Remote-ID (37), Subscriber-ID (38) -- sit in the
// outer message where a client has no business putting them.
//
// **The dangerous options are different and there are more of them.** DNS
// servers (23) and the domain search list (24) are the obvious pair. Beyond
// them: the boot file URL (59) and its parameters (60) are what a machine boots,
// which is RFC 5970's whole purpose; the captive portal URL (103, RFC 8910) is a
// URL a client will open; the S46 transition options (94 to 97) put a host's
// *IPv4* traffic through a border relay of the sender's choosing, which is a
// takeover of a protocol this message is not even about; and the Server Unicast
// option (12) tells a client to stop talking to the relay and address the server
// directly, which is how a server turns off every policy a relay has.
//
// The parser reads all of it, bounded, and says what it found rather than
// deciding: the deciding belongs to a listener with a configuration.
package dhcp6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// MessageType is the first octet: what the message is for.
type MessageType uint8

// The message types of RFC 8415 s7.3 and RFC 5007.
const (
	Solicit            MessageType = 1
	Advertise          MessageType = 2
	Request            MessageType = 3
	Confirm            MessageType = 4
	Renew              MessageType = 5
	Rebind             MessageType = 6
	Reply              MessageType = 7
	Release            MessageType = 8
	Decline            MessageType = 9
	Reconfigure        MessageType = 10
	InformationRequest MessageType = 11
	RelayForward       MessageType = 12
	RelayReply         MessageType = 13
	// The lease query family of RFC 5007, whose intended user is a relay
	// agent and whose intended purpose is an inventory -- which is also what
	// makes it worth refusing from anywhere else.
	LeaseQuery      MessageType = 14
	LeaseQueryReply MessageType = 15
	LeaseQueryDone  MessageType = 16
	LeaseQueryData  MessageType = 17
)

var typeNames = map[MessageType]string{
	Solicit: "solicit", Advertise: "advertise", Request: "request",
	Confirm: "confirm", Renew: "renew", Rebind: "rebind", Reply: "reply",
	Release: "release", Decline: "decline", Reconfigure: "reconfigure",
	InformationRequest: "information_request",
	RelayForward:       "relay_forward", RelayReply: "relay_reply",
	LeaseQuery: "leasequery", LeaseQueryReply: "leasequery_reply",
	LeaseQueryDone: "leasequery_done", LeaseQueryData: "leasequery_data",
}

func (t MessageType) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("type(%d)", uint8(t))
}

// Known says whether this is a type this package understands. A type it does
// not is not forwarded on a guess: a relay cannot decide about a message whose
// meaning is not defined.
func (t MessageType) Known() bool { _, ok := typeNames[t]; return ok }

// TypeOf reads a message type by the name a configuration uses.
func TypeOf(s string) (MessageType, bool) {
	for t, name := range typeNames {
		if name == s {
			return t, true
		}
	}
	return 0, false
}

// FromClient says whether a client sends this type.
func (t MessageType) FromClient() bool {
	switch t {
	case Solicit, Request, Confirm, Renew, Rebind, Release, Decline, InformationRequest:
		return true
	case LeaseQuery:
		// A LEASEQUERY travels towards a server, from what RFC 5007 s4.1 calls a
		// requestor. It is nobody's ordinary client, but the direction is the
		// client's direction, and getting that wrong would put a misleading
		// reason on the refusal: an estate reading
		// "a server's message on the client side" would go looking for a rogue
		// server, when what arrived was somebody asking for an inventory of
		// every lease in the estate.
		return true
	}
	return false
}

// FromServer says whether a server sends this type.
func (t MessageType) FromServer() bool {
	switch t {
	case Advertise, Reply, Reconfigure, LeaseQueryReply, LeaseQueryDone, LeaseQueryData:
		return true
	}
	return false
}

// IsRelay says whether this type is a relay's own wrapper.
func (t MessageType) IsRelay() bool { return t == RelayForward || t == RelayReply }

// Assigns says whether this type can hand a client an address or a prefix,
// which is the half of the protocol that configures a machine.
func (t MessageType) Assigns() bool { return t == Advertise || t == Reply }

// The shapes and bounds of a message.
const (
	// HeaderLen is a client or server message's header: the type and the
	// three octets of transaction identifier.
	HeaderLen = 4
	// RelayHeaderLen is a relay message's: the type, the hop count and the two
	// sixteen-octet addresses.
	RelayHeaderLen = 34
	// OptionHeaderLen is an option's code and length.
	OptionHeaderLen = 4
	// MaxMessage bounds what this package will read at all. A DHCPv6 message
	// has no fixed maximum in the standard, and a relay chain grows one, so
	// the bound is here and a listener bounds it tighter still.
	MaxMessage = 8192
	// MaxOptions bounds the options in one message, because a message made of
	// four thousand empty options costs more to read than to send.
	MaxOptions = 64
	// MaxNesting bounds the relay chain. RFC 8415 s19.1.1 caps the hop count
	// at 32, so a chain deeper than that is not a topology; a listener bounds
	// it to what its own estate has.
	MaxNesting = 32
	// MaxHopCount is that cap.
	MaxHopCount = 32
	// MaxDUID is the longest DUID RFC 8415 s11.1 allows: 128 octets.
	MaxDUID = 128
	// TransactionIDLen is the three octets of RFC 8415 s8.
	TransactionIDLen = 3
)

// Errors this package returns. They are distinguished because a relay reports
// them differently: a truncated message is a sender that cannot speak the
// protocol, a bound reached is a sender spending this relay's time, and a relay
// chain that does not hold together is a topology nobody meant.
var (
	// ErrShort is a message that ends inside a header or an option.
	ErrShort = errors.New("dhcp6: message is too short")
	// ErrTooLong is a message or an option past its bound.
	ErrTooLong = errors.New("dhcp6: past the bound")
	// ErrOption is an option whose length does not fit what is there.
	ErrOption = errors.New("dhcp6: malformed option")
	// ErrRelay is a relay message that does not hold together: no
	// Relay-Message option, a chain deeper than the bound, or a hop count
	// past the standard's own.
	ErrRelay = errors.New("dhcp6: malformed relay message")
	// ErrDUID is a DHCP Unique Identifier this package cannot read.
	ErrDUID = errors.New("dhcp6: malformed DUID")
)

// Option is one option: a code, and the value between the header and the next
// option.
type Option struct {
	Code  uint16
	Value []byte
}

// Message is a parsed DHCPv6 message.
type Message struct {
	Type MessageType
	// TransactionID is the client's three octets, in the low 24 bits. It is
	// the only thing tying an answer to a question, and it is visible to
	// everyone on the segment -- which is why it proves nothing.
	TransactionID uint32

	// HopCount, LinkAddress and PeerAddress are a relay message's header. The
	// link address is the segment the client is on as the relay reports it,
	// and the peer address is where the relay got the message from.
	HopCount    uint8
	LinkAddress netip.Addr
	PeerAddress netip.Addr

	// Options are this message's own options, in the order they arrived.
	Options []Option
	// Inner is the message carried in a relay message's Relay-Message option.
	Inner *Message
	// Depth is how many relay messages enclose this one: zero for a message
	// that arrived from a client or a server directly.
	Depth int
	// Raw is this message's own octets as they arrived. A relay forwards a
	// re-encoding rather than these -- it is adding its own wrapper -- but the
	// original is what a decision is made about and what a log line describes.
	Raw []byte
}

// Parse reads a message and, for a relay message, the chain inside it.
//
// The chain is read iteratively and bounded twice: by the nesting bound and by
// the standard's own hop count. A relay that recursed on a sender's say-so would
// be a relay whose stack depth is an attacker's choice.
func Parse(raw []byte) (*Message, error) {
	if len(raw) > MaxMessage {
		return nil, fmt.Errorf("%w: %d octets", ErrTooLong, len(raw))
	}
	m, err := parseOne(raw)
	if err != nil {
		return nil, err
	}
	// The chain. Each relay message carries the next one whole in its
	// Relay-Message option, so following it is following a length a sender
	// wrote -- bounded here rather than trusted.
	outer := m
	for depth := 1; outer.Type.IsRelay(); depth++ {
		if depth > MaxNesting {
			return nil, fmt.Errorf("%w: more than %d relay messages", ErrRelay, MaxNesting)
		}
		body, ok := outer.Get(OptionRelayMsg)
		if !ok {
			return nil, fmt.Errorf("%w: a %s with no relay message inside it", ErrRelay, outer.Type)
		}
		inner, err := parseOne(body)
		if err != nil {
			return nil, err
		}
		inner.Depth = depth
		outer.Inner = inner
		outer = inner
	}
	return m, nil
}

// parseOne reads one message without following the chain.
func parseOne(raw []byte) (*Message, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("%w: empty", ErrShort)
	}
	m := &Message{Type: MessageType(raw[0]), Raw: raw}
	var rest []byte
	if m.Type.IsRelay() {
		if len(raw) < RelayHeaderLen {
			return nil, fmt.Errorf("%w: a relay message of %d octets", ErrShort, len(raw))
		}
		m.HopCount = raw[1]
		if m.HopCount > MaxHopCount {
			return nil, fmt.Errorf("%w: hop count %d, past the %d of RFC 8415", ErrRelay, m.HopCount, MaxHopCount)
		}
		m.LinkAddress = addr16(raw[2:18])
		m.PeerAddress = addr16(raw[18:34])
		rest = raw[RelayHeaderLen:]
	} else {
		if len(raw) < HeaderLen {
			return nil, fmt.Errorf("%w: a message of %d octets", ErrShort, len(raw))
		}
		m.TransactionID = uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		rest = raw[HeaderLen:]
	}
	opts, err := parseOptions(rest)
	if err != nil {
		return nil, err
	}
	m.Options = opts
	return m, nil
}

// parseOptions reads a sequence of options.
//
// The length in each header is the sender's claim about where the next one
// starts, and it is the claim a reader that trusted it would walk off the end
// of. Every option is checked against what is actually there.
func parseOptions(b []byte) ([]Option, error) {
	out := make([]Option, 0, 8)
	for len(b) > 0 {
		if len(out) >= MaxOptions {
			return nil, fmt.Errorf("%w: more than %d options", ErrTooLong, MaxOptions)
		}
		if len(b) < OptionHeaderLen {
			return nil, fmt.Errorf("%w: %d octets where an option header belongs", ErrOption, len(b))
		}
		code := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < OptionHeaderLen+n {
			return nil, fmt.Errorf("%w: option %d says %d octets with %d left",
				ErrOption, code, n, len(b)-OptionHeaderLen)
		}
		out = append(out, Option{Code: code, Value: b[OptionHeaderLen : OptionHeaderLen+n]})
		b = b[OptionHeaderLen+n:]
	}
	return out, nil
}

func addr16(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a)
}

// Get returns the first value of an option.
//
// First rather than joined: DHCPv6 has no equivalent of RFC 3396's splitting, so
// an option appearing twice is a message two readers could disagree about --
// see Repeated, which is how a policy can refuse one rather than guess.
func (m *Message) Get(code uint16) ([]byte, bool) {
	for _, o := range m.Options {
		if o.Code == code {
			return o.Value, true
		}
	}
	return nil, false
}

// All returns every value of an option, for the codes that legitimately repeat:
// a message may carry several IA_NA or IA_PD options, one per identity
// association.
func (m *Message) All(code uint16) [][]byte {
	out := make([][]byte, 0, 2)
	for _, o := range m.Options {
		if o.Code == code {
			out = append(out, o.Value)
		}
	}
	return out
}

// Has says whether an option is present.
func (m *Message) Has(code uint16) bool { _, ok := m.Get(code); return ok }

// Codes lists the option codes present, in order and with repeats.
func (m *Message) Codes() []uint16 {
	out := make([]uint16, 0, len(m.Options))
	for _, o := range m.Options {
		out = append(out, o.Code)
	}
	return out
}

// Repeated lists the option codes that appear more than once and are not ones
// that may.
//
// It matters because two implementations will read such a message differently --
// one taking the first value and one the last -- and a relay that decided about
// the first while the server acted on the last would be the reason nobody could
// find the bug.
func (m *Message) Repeated() []uint16 {
	seen := map[uint16]int{}
	for _, o := range m.Options {
		seen[o.Code]++
	}
	out := make([]uint16, 0, 2)
	for _, o := range m.Options {
		if seen[o.Code] > 1 && !MayRepeat(o.Code) {
			seen[o.Code] = 0
			out = append(out, o.Code)
		}
	}
	return out
}

// Innermost is the message at the bottom of the relay chain: the client's own,
// or the server's answer to it. It is what a policy decides about.
func (m *Message) Innermost() *Message {
	for m.Inner != nil {
		m = m.Inner
	}
	return m
}

// Chain is every message from the outside in, which is what a log line
// describing a relayed exchange needs.
func (m *Message) Chain() []*Message {
	out := make([]*Message, 0, 4)
	for p := m; p != nil; p = p.Inner {
		out = append(out, p)
	}
	return out
}

// ClientDUID is the client identifier of the innermost message.
func (m *Message) ClientDUID() (DUID, bool) {
	v, ok := m.Innermost().Get(OptionClientID)
	if !ok {
		return DUID{}, false
	}
	d, err := ParseDUID(v)
	if err != nil {
		return DUID{}, false
	}
	return d, true
}

// ServerDUID is the server identifier of the innermost message.
func (m *Message) ServerDUID() (DUID, bool) {
	v, ok := m.Innermost().Get(OptionServerID)
	if !ok {
		return DUID{}, false
	}
	d, err := ParseDUID(v)
	if err != nil {
		return DUID{}, false
	}
	return d, true
}
