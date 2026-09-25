package dhcp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// The writing half. A relay agent does not merely forward: RFC 2131 §4.1.1
// requires it to fill in giaddr and increment hops, and RFC 3046 requires it to
// add its own agent information and to strip what a client claimed. So a
// message leaves this relay re-encoded from what was read, which is also what
// makes an option policy possible: an option that was removed is a message that
// no longer carries it, not a message with a note attached.

// Encode writes a message back out.
//
// The options are written in the order they were read, which matters more than
// it looks: a server that answers in the request's order is the normal case,
// and an operator comparing a capture with a log should see the same sequence
// in both. The header's string fields are written as strings; option overload
// is not produced, because a relay that hid options in the boot filename field
// would be making its own output harder to read than its input.
func Encode(m *Message) ([]byte, error) {
	if m.Op != BootRequest && m.Op != BootReply {
		return nil, fmt.Errorf("%w: op %d", ErrShape, uint8(m.Op))
	}
	if len(m.CHAddr) > MaxHWLen {
		return nil, fmt.Errorf("%w: a hardware address of %d octets", ErrShape, len(m.CHAddr))
	}
	hlen := uint8(len(m.CHAddr)) //nolint:gosec // bounded by MaxHWLen one line above
	if len(m.SName) > MaxSNameLen || len(m.File) > MaxFileLen {
		return nil, fmt.Errorf("%w: sname or file longer than its field", ErrCount)
	}
	out := make([]byte, FixedLen+CookieLen, 576)
	out[0] = uint8(m.Op)
	out[1] = m.HType
	out[2] = hlen
	out[3] = m.Hops
	binary.BigEndian.PutUint32(out[4:8], m.XID)
	binary.BigEndian.PutUint16(out[8:10], m.Secs)
	binary.BigEndian.PutUint16(out[10:12], m.Flags)
	put4(out[12:16], m.CIAddr)
	put4(out[16:20], m.YIAddr)
	put4(out[20:24], m.SIAddr)
	put4(out[24:28], m.GIAddr)
	copy(out[28:28+MaxHWLen], m.CHAddr)
	copy(out[44:44+MaxSNameLen], m.SName)
	copy(out[108:108+MaxFileLen], m.File)
	copy(out[FixedLen:FixedLen+CookieLen], Cookie[:])

	// The message type goes first whatever order it was read in. RFC 2131
	// §3 does not require it, but every implementation looks for it early and
	// a relay whose own output buried it would be inviting the difference in
	// readings that this package exists to remove.
	if m.Type != 0 {
		out = append(out, OptMessageType, 1, uint8(m.Type))
	}
	for _, o := range m.Options {
		switch o.Code {
		case OptMessageType, OptPad, OptEnd, OptOverload:
			// The type is already written; the padding and the terminator are
			// framing rather than options; and the overload is a statement
			// about an encoding this encoder does not produce.
			continue
		}
		written, err := appendOption(out, o.Code, o.Value)
		if err != nil {
			return nil, err
		}
		out = written
	}
	out = append(out, OptEnd)
	// RFC 2131 §2: a message is padded to the 300-octet BOOTP minimum,
	// because there are BOOTP relay agents and clients that drop anything
	// shorter, and an estate with one of those in it is exactly the kind of
	// estate this relay is deployed into.
	for len(out) < 300 {
		out = append(out, OptPad)
	}
	if len(out) > MaxPacket {
		return nil, fmt.Errorf("%w: %d octets", ErrCount, len(out))
	}
	return out, nil
}

// appendOption writes one option, splitting it across instances when it is
// longer than a single length octet can describe.
//
// RFC 3396 is what makes that legal, and it is the same rule the reader
// applies in reverse: several instances of one code are one option. A relay
// that could read the encoding and not write it would be a relay that could
// not carry what it had just decided to allow.
func appendOption(out []byte, code uint8, value []byte) ([]byte, error) {
	switch code {
	case OptPad, OptEnd:
		return nil, fmt.Errorf("%w: option %d is framing, not an option", ErrShape, code)
	}
	if len(value) == 0 {
		// A zero-length option is legal and meaningful: option 55 with no
		// value is not, but several others are present-or-absent flags.
		return append(out, code, 0), nil
	}
	for len(value) > 0 {
		n := len(value)
		if n > 255 {
			n = 255
		}
		out = append(out, code, uint8(n)) //nolint:gosec // n is clamped to 255 above
		out = append(out, value[:n]...)
		value = value[n:]
	}
	return out, nil
}

// put4 writes one of the header's four addresses. An address that is not IPv4
// is written as 0.0.0.0 rather than refused, because the field is four octets
// and there is nothing else it could hold; the parser only ever produces IPv4
// addresses, so this is a guard against a caller's own mistake.
func put4(b []byte, a netip.Addr) {
	if !a.Is4() {
		return
	}
	v := a.As4()
	copy(b, v[:])
}

// Set replaces an option's value, or adds it when it is not there. The order is
// kept: an option that was present stays where it was.
func (m *Message) Set(code uint8, value []byte) {
	for i := range m.Options {
		if m.Options[i].Code == code {
			m.Options[i].Value = append([]byte(nil), value...)
			m.Options[i].Split = false
			return
		}
	}
	m.Options = append(m.Options, Option{Code: code,
		Value: append([]byte(nil), value...), Where: InOptions})
}

// Remove takes an option out and says whether it was there. This is how an
// option policy is applied: the message that leaves does not carry the option,
// rather than carrying it with a note.
func (m *Message) Remove(code uint8) bool {
	for i := range m.Options {
		if m.Options[i].Code == code {
			m.Options = append(m.Options[:i], m.Options[i+1:]...)
			return true
		}
	}
	return false
}

// Clone copies a message deeply enough to rewrite: the option values and the
// hardware address are copied, so a rewritten message cannot change the one it
// came from. A relay holds the original for its log while it edits the copy.
func (m *Message) Clone() *Message {
	c := *m
	c.CHAddr = append([]byte(nil), m.CHAddr...)
	c.Options = make([]Option, len(m.Options))
	for i, o := range m.Options {
		c.Options[i] = o
		c.Options[i].Value = append([]byte(nil), o.Value...)
	}
	c.Raw = nil
	return &c
}

// AgentInfo builds an RFC 3046 option 82 from a circuit identifier and a remote
// identifier, either of which may be empty.
//
// The relay adds this and the client never does: the option exists so that a
// server can tell *which* segment a request came from, and a value a client
// supplied would be a client telling the server which segment to believe it is
// on.
func AgentInfo(circuit, remote string) ([]byte, error) {
	out := make([]byte, 0, 8+len(circuit)+len(remote))
	for _, sub := range []struct {
		code uint8
		val  string
	}{{1, circuit}, {2, remote}} {
		if sub.val == "" {
			continue
		}
		if len(sub.val) > 255 {
			return nil, fmt.Errorf("%w: a suboption of %d octets", ErrCount, len(sub.val))
		}
		out = append(out, sub.code, uint8(len(sub.val))) //nolint:gosec // bounded two lines above
		out = append(out, sub.val...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: an agent option with no suboptions", ErrShape)
	}
	return out, nil
}

// SubOption is one suboption inside option 82.
type SubOption struct {
	Code  uint8
	Value []byte
}

// SubOptions reads option 82's contents. It is read rather than carried
// blindly because a relay that inserts the option has to be able to see that
// one is already there, and because the two suboptions an operator cares about
// -- the circuit and the remote identifier -- are what a server's own logs key
// on.
func SubOptions(v []byte) ([]SubOption, error) {
	var out []SubOption
	for i := 0; i < len(v); {
		if i+1 >= len(v) {
			return nil, fmt.Errorf("%w: a suboption with no length", ErrTruncated)
		}
		n := int(v[i+1])
		if i+2+n > len(v) {
			return nil, fmt.Errorf("%w: a suboption claiming %d octets", ErrTruncated, n)
		}
		out = append(out, SubOption{Code: v[i], Value: v[i+2 : i+2+n]})
		i += 2 + n
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no suboptions", ErrShape)
	}
	return out, nil
}
