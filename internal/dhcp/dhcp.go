// Package dhcp reads the Dynamic Host Configuration Protocol (RFC 2131) and
// its options (RFC 2132, RFC 3046, RFC 3396, RFC 3442).
//
// DHCP is how a machine learns what its network is, and that makes it the one
// protocol where answering a question is the attack. A client broadcasts "who
// will configure me", and whatever answers first tells it its address, its
// **default route**, its **DNS servers**, its **proxy** (option 252) and, on a
// machine that boots from the network, the **file it boots** (options 66 and
// 67). There is no authentication in any of it: the exchange is a transaction
// identifier and a hardware address, both of which are in the request anybody
// on the segment can see.
//
// Three shapes of that matter, and they are why this package reads the whole
// message rather than forwarding it.
//
// **An answer from the wrong server is the whole attack.** Every switch vendor
// calls the countermeasure DHCP snooping and implements it as a trusted port;
// a relay can do the same thing by address, and it can do the part a switch
// cannot: read what the answer *says*.
//
// **The options a server sends are a configuration, not data.** Option 121 and
// its Microsoft twin 249 are classless static routes -- a route injection in a
// broadcast reply. Option 252 is the WPAD URL, which is a proxy. Options 66,
// 67 and 43 point a machine at what it boots. Each is a legitimate option some
// estates need and a takeover in the others, so each is a decision.
//
// **A message's options are not where a naive reader looks for them.** Two
// features of RFC 2132 and RFC 3396 make the same message say different things
// to different parsers, which is exactly the shape a relay exists to remove:
// option 52 (**option overload**) says the `sname` and `file` fields carry
// options too, and RFC 3396 says an option appearing **more than once** is one
// option whose value is the concatenation. A reader that missed either would be
// deciding about a message the server reads differently -- so this one reads
// both, and says so in the parsed result.
//
// What this package does not do is DHCPv6 (RFC 8415). That is a different
// packet format with different message types, a different relay mechanism and
// its own options; reading it as if it were this one would be worse than not
// reading it at all, and pretending one implementation covers both is the kind
// of claim a security tool should not make.
package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Op is the BOOTP operation: a request from a client, a reply from a server.
type Op uint8

// The two operations of RFC 951, which RFC 2131 keeps.
const (
	BootRequest Op = 1
	BootReply   Op = 2
)

func (o Op) String() string {
	switch o {
	case BootRequest:
		return "request"
	case BootReply:
		return "reply"
	}
	return fmt.Sprintf("op(%d)", uint8(o))
}

// MessageType is option 53's value: what the message is for.
type MessageType uint8

// The message types of RFC 2131 §3, RFC 3203 and RFC 4388.
const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	Ack      MessageType = 5
	Nak      MessageType = 6
	Release  MessageType = 7
	Inform   MessageType = 8
	// ForceRenew is RFC 3203: a server telling a client to renew now. It is
	// a message *to* a client that is not an answer to anything, which is why
	// it is worth being able to name in a policy.
	ForceRenew MessageType = 9
	// The lease query family of RFC 4388, which asks a server what it knows
	// about a lease. A relay agent is its intended user and an inventory is
	// its intended purpose, which is also what makes it worth refusing from
	// anywhere else.
	LeaseQuery       MessageType = 10
	LeaseUnassigned  MessageType = 11
	LeaseUnknown     MessageType = 12
	LeaseActive      MessageType = 13
	BulkLeaseQuery   MessageType = 14
	LeaseQueryDone   MessageType = 15
	ActiveLeaseQuery MessageType = 16
	LeaseQueryStatus MessageType = 17
	DHCPTLS          MessageType = 18
)

var typeNames = map[MessageType]string{
	Discover: "discover", Offer: "offer", Request: "request", Decline: "decline",
	Ack: "ack", Nak: "nak", Release: "release", Inform: "inform",
	ForceRenew: "force_renew", LeaseQuery: "lease_query",
	LeaseUnassigned: "lease_unassigned", LeaseUnknown: "lease_unknown",
	LeaseActive: "lease_active", BulkLeaseQuery: "bulk_lease_query",
	LeaseQueryDone: "lease_query_done", ActiveLeaseQuery: "active_lease_query",
	LeaseQueryStatus: "lease_query_status", DHCPTLS: "dhcp_tls",
}

func (t MessageType) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type(%d)", uint8(t))
}

// Known says whether this is a message type a standard defines.
func (t MessageType) Known() bool { _, ok := typeNames[t]; return ok }

// FromClient says whether a message type is one a client sends. It is read
// from the type rather than from the direction the datagram came from, because
// those two disagreeing is itself the finding: a DHCPOFFER arriving from the
// client side is somebody answering on the segment.
func (t MessageType) FromClient() bool {
	switch t {
	case Discover, Request, Decline, Release, Inform, LeaseQuery,
		BulkLeaseQuery, ActiveLeaseQuery:
		return true
	}
	return false
}

// FromServer says whether a message type is one a server sends.
func (t MessageType) FromServer() bool {
	switch t {
	case Offer, Ack, Nak, ForceRenew, LeaseUnassigned, LeaseUnknown,
		LeaseActive, LeaseQueryDone, LeaseQueryStatus:
		return true
	}
	return false
}

// Assigns says whether a message type hands a client its configuration. These
// are the ones whose *contents* are worth a policy: an OFFER and an ACK carry
// the address, the route, the resolvers and the boot file.
func (t MessageType) Assigns() bool { return t == Offer || t == Ack }

// TypeOf names a message type the way a rule is written.
func TypeOf(s string) (MessageType, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "dhcp")
	for t, n := range typeNames {
		if n == s || strings.ReplaceAll(n, "_", "") == s {
			return t, true
		}
	}
	return 0, false
}

// The hardware address types of RFC 1700 that appear in practice.
const (
	HTypeEthernet uint8 = 1
	HTypeIEEE802  uint8 = 6
	// HTypeInfiniband is 32, whose addresses are 20 octets -- which is why
	// hlen is read rather than assumed to be six.
	HTypeInfiniband uint8 = 32
)

// The fixed sizes of RFC 2131 §2.
const (
	// FixedLen is the BOOTP header before the options: 236 octets.
	FixedLen = 236
	// CookieLen is the four octets of the magic cookie that say the options
	// that follow are DHCP's rather than BOOTP's vendor field.
	CookieLen = 4
	// MinPacket is a message with a cookie and nothing else.
	MinPacket = FixedLen + CookieLen
	// MaxHWLen is the chaddr field's extent. An hlen larger than this is a
	// message claiming a hardware address longer than the field holding it.
	MaxHWLen = 16
	// MaxPacket is the largest message this package reads. RFC 2131 requires
	// a client to accept 576 and lets a server send more when the client's
	// option 57 says it can; 4096 is past anything an estate produces and
	// short of anything worth reassembling.
	MaxPacket = 4096
	// MaxOptions bounds how many options one message may carry, before the
	// RFC 3396 concatenation.
	MaxOptions = 128
	// MaxNameLen bounds the sname and file fields, which are 64 and 128
	// octets in the header.
	MaxSNameLen = 64
	MaxFileLen  = 128
)

// Cookie is the magic cookie of RFC 2132 §3: 99.130.83.99.
var Cookie = [4]byte{99, 130, 83, 99}

// Errors a reader returns.
var (
	// ErrTruncated is a message shorter than the fixed header, or one that
	// ended inside an option.
	ErrTruncated = errors.New("dhcp: truncated message")
	// ErrCookie is a message whose options are not DHCP's.
	ErrCookie = errors.New("dhcp: not the DHCP magic cookie")
	// ErrShape is a field that is not the shape that field has.
	ErrShape = errors.New("dhcp: not the shape of that field")
	// ErrCount is more of something than a bound allows.
	ErrCount = errors.New("dhcp: too many elements")
	// ErrNoType is a message with no option 53. Every DHCP message has one;
	// a message without is BOOTP, and this relay does not speak for BOOTP.
	ErrNoType = errors.New("dhcp: no message type")
)

// Message is one parsed DHCP message.
type Message struct {
	Op    Op
	HType uint8
	HLen  uint8
	Hops  uint8
	XID   uint32
	Secs  uint16
	Flags uint16

	// The four addresses of §2, in the order the header has them: the
	// client's own, the one being offered, the server's, and the relay
	// agent's.
	CIAddr, YIAddr, SIAddr, GIAddr netip.Addr

	// CHAddr is the client hardware address, hlen octets of it. The rest of
	// the field is not kept: it is padding, and a relay that compared the
	// padding would be comparing whatever a client left there.
	CHAddr []byte

	// SName and File are the header's two string fields, empty when option
	// overload moved options into them.
	SName, File string

	// Type is option 53's value.
	Type MessageType

	// Options are the options, in the order they first appeared, with the
	// multiple appearances of one code already joined per RFC 3396.
	Options []Option

	// Overload is option 52's value: which header fields carried options.
	// It is kept because it is a thing a relay may legitimately refuse --
	// a message whose options are hidden in the boot filename field is one
	// almost nothing in an estate sends.
	Overload uint8

	// Raw is the message as it arrived.
	Raw []byte
}

// Option is one option, joined across its appearances.
type Option struct {
	Code  uint8
	Value []byte
	// Split says the option arrived as more than one instance and was joined
	// per RFC 3396. It is recorded because a message that used the encoding
	// is a message two parsers may read differently, and an operator looking
	// at a refusal is owed that.
	Split bool
	// Where says which parts of the message carried it: the options field,
	// the file field, the sname field, or several.
	Where Where
}

// Where says which part of a message an option came from.
type Where uint8

// The three places options can be, per RFC 2132 §9.3.
const (
	InOptions Where = 1 << 0
	InFile    Where = 1 << 1
	InSName   Where = 1 << 2
)

func (w Where) String() string {
	var parts []string
	if w&InOptions != 0 {
		parts = append(parts, "options")
	}
	if w&InFile != 0 {
		parts = append(parts, "file")
	}
	if w&InSName != 0 {
		parts = append(parts, "sname")
	}
	if len(parts) == 0 {
		return "nowhere"
	}
	return strings.Join(parts, "+")
}

// Parse reads one DHCP message.
//
// Everything is read: the header, the options, the options hidden in the
// header's own string fields by option 52, and the several instances of one
// option that RFC 3396 says are one. A relay that read less would be deciding
// about a different message from the one the server reads.
func Parse(raw []byte) (*Message, error) {
	if len(raw) < MinPacket {
		return nil, fmt.Errorf("%w: %d octets, less than %d", ErrTruncated, len(raw), MinPacket)
	}
	if len(raw) > MaxPacket {
		return nil, fmt.Errorf("%w: %d octets", ErrCount, len(raw))
	}
	if [4]byte(raw[FixedLen:FixedLen+CookieLen]) != Cookie {
		return nil, ErrCookie
	}
	m := &Message{
		Op:    Op(raw[0]),
		HType: raw[1],
		HLen:  raw[2],
		Hops:  raw[3],
		XID:   binary.BigEndian.Uint32(raw[4:8]),
		Secs:  binary.BigEndian.Uint16(raw[8:10]),
		Flags: binary.BigEndian.Uint16(raw[10:12]),
		Raw:   raw,
	}
	if m.Op != BootRequest && m.Op != BootReply {
		return nil, fmt.Errorf("%w: op %d", ErrShape, raw[0])
	}
	if m.HLen > MaxHWLen {
		// A hardware address longer than the field that holds it. One
		// reader would take sixteen octets and another would read past
		// them, and the address is what a lease is keyed on.
		return nil, fmt.Errorf("%w: hlen %d", ErrShape, m.HLen)
	}
	m.CIAddr = addr4(raw[12:16])
	m.YIAddr = addr4(raw[16:20])
	m.SIAddr = addr4(raw[20:24])
	m.GIAddr = addr4(raw[24:28])
	m.CHAddr = append([]byte(nil), raw[28:28+m.HLen]...)

	// The options field first, because option 52 is in it and says whether
	// the two string fields are options or strings.
	opts := newOptions()
	if err := opts.read(raw[FixedLen+CookieLen:], InOptions); err != nil {
		return nil, err
	}
	if v, ok := opts.first(OptOverload); ok && len(v) == 1 {
		m.Overload = v[0]
	}
	file, sname := raw[108:108+MaxFileLen], raw[44:44+MaxSNameLen]
	// RFC 2132 §9.3: 1 means the file field holds options, 2 the sname
	// field, 3 both. The order is the standard's: file, then sname.
	if m.Overload&1 != 0 {
		if err := opts.read(file, InFile); err != nil {
			return nil, err
		}
	} else {
		m.File = cstr(file)
	}
	if m.Overload&2 != 0 {
		if err := opts.read(sname, InSName); err != nil {
			return nil, err
		}
	} else {
		m.SName = cstr(sname)
	}
	m.Options = opts.joined()
	v, ok := opts.first(OptMessageType)
	if !ok || len(v) != 1 {
		return nil, ErrNoType
	}
	if v[0] == 0 {
		// Option 53 present, one octet long, and zero. No standard defines a
		// message type of zero: it is the absent value wearing a length, and
		// what a server does with it is the server's own business -- one will
		// find no case and drop it, another will fall through. A relay cannot
		// decide about a message whose *type* the two ends may read
		// differently, so this is refused rather than carried with a type a
		// rule could not name.
		//
		// A non-zero type nobody has defined is a different matter and is
		// carried: it is refusable by the policy's own type list, which is
		// where a type added by a later RFC belongs rather than in a code
		// change here.
		return nil, fmt.Errorf("%w: option 53 is zero", ErrNoType)
	}
	m.Type = MessageType(v[0])
	return m, nil
}

// addr4 reads one of the header's four addresses. The unspecified address is
// 0.0.0.0, which is a real value here -- a client that has no address yet
// sends it -- so it is kept rather than turned into an invalid address.
func addr4(b []byte) netip.Addr {
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
}

// cstr reads one of the header's fixed string fields, which is NUL-padded and
// need not be NUL-terminated when it is full.
func cstr(b []byte) string {
	if i := indexZero(b); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// options collects option instances in the order their codes first appeared,
// so that RFC 3396's concatenation and RFC 2132's overload can both be applied
// without losing the order a relay has to write back.
type options struct {
	order []uint8
	parts map[uint8][][]byte
	where map[uint8]Where
	count int
}

func newOptions() *options {
	return &options{parts: map[uint8][][]byte{}, where: map[uint8]Where{}}
}

// read reads a sequence of code/length/value options.
//
// Pad (0) and End (255) have no length octet, which is the one irregularity in
// the encoding. Everything after End in the same field is padding by
// definition and is not read: a field that carried more would be a field two
// parsers disagree about.
func (o *options) read(b []byte, w Where) error {
	for i := 0; i < len(b); {
		code := b[i]
		switch code {
		case OptPad:
			i++
			continue
		case OptEnd:
			return nil
		}
		if i+1 >= len(b) {
			return fmt.Errorf("%w: option %d has no length", ErrTruncated, code)
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			return fmt.Errorf("%w: option %d claims %d octets", ErrTruncated, code, n)
		}
		o.count++
		if o.count > MaxOptions {
			return fmt.Errorf("%w: more than %d options", ErrCount, MaxOptions)
		}
		if _, seen := o.parts[code]; !seen {
			o.order = append(o.order, code)
		}
		o.parts[code] = append(o.parts[code], b[i+2:i+2+n])
		o.where[code] |= w
		i += 2 + n
	}
	return nil
}

// first is one option's first instance, for the two options that have to be
// read before the rest can be: the message type and the overload.
func (o *options) first(code uint8) ([]byte, bool) {
	p := o.parts[code]
	if len(p) == 0 {
		return nil, false
	}
	return p[0], true
}

// joined applies RFC 3396: several instances of one option are one option
// whose value is their concatenation, in the order they appeared.
func (o *options) joined() []Option {
	out := make([]Option, 0, len(o.order))
	for _, code := range o.order {
		parts := o.parts[code]
		opt := Option{Code: code, Where: o.where[code], Split: len(parts) > 1}
		if len(parts) == 1 {
			opt.Value = append([]byte(nil), parts[0]...)
		} else {
			for _, p := range parts {
				opt.Value = append(opt.Value, p...)
			}
		}
		out = append(out, opt)
	}
	return out
}

// Get returns an option's joined value.
func (m *Message) Get(code uint8) ([]byte, bool) {
	for _, o := range m.Options {
		if o.Code == code {
			return o.Value, true
		}
	}
	return nil, false
}

// Has says whether an option is present at all, which for several of them is
// the whole of what matters.
func (m *Message) Has(code uint8) bool { _, ok := m.Get(code); return ok }

// Codes are the option codes the message carries, in order.
func (m *Message) Codes() []uint8 {
	out := make([]uint8, 0, len(m.Options))
	for _, o := range m.Options {
		out = append(out, o.Code)
	}
	return out
}

// Hidden says whether any option arrived somewhere other than the options
// field, or arrived split across instances. Both are encodings a server reads
// and a careless reader does not, which is why a listener can refuse them.
func (m *Message) Hidden() bool {
	for _, o := range m.Options {
		if o.Split || o.Where&^InOptions != 0 {
			return true
		}
	}
	return false
}

// Broadcast says whether the client asked for the reply to be broadcast,
// which is the flags field's top bit (RFC 2131 §2, figure 2).
func (m *Message) Broadcast() bool { return m.Flags&0x8000 != 0 }

// Relayed says whether a relay agent has already handled this message.
func (m *Message) Relayed() bool { return m.GIAddr.IsValid() && !m.GIAddr.IsUnspecified() }
