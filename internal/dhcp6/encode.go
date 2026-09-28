package dhcp6

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Rendering a message, for the messages a relay makes rather than forwards.
//
// A relay agent does not forward the octets it received: it wraps them, and on
// the way back it unwraps them. So encoding is not an optional half of this
// package the way it is for a protocol a relay passes through -- it is how a
// RELAY-FORW is built and how the client's own message is recovered from a
// RELAY-REPL.

// Encode renders a message.
//
// A relay message's inner message is encoded from Inner when there is one, so a
// caller that edited the inside does not have to rebuild the Relay-Message
// option by hand. A message with neither an Inner nor a Relay-Message option is
// refused rather than sent: a relay message with nothing inside is a message no
// server can answer.
func Encode(m *Message) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nothing to encode", ErrShort)
	}
	out := make([]byte, 0, 256)
	if m.Type.IsRelay() {
		if m.HopCount > MaxHopCount {
			return nil, fmt.Errorf("%w: hop count %d", ErrRelay, m.HopCount)
		}
		out = append(out, byte(m.Type), m.HopCount)
		out = appendAddr(out, m.LinkAddress)
		out = appendAddr(out, m.PeerAddress)
	} else {
		if m.TransactionID > 0xffffff {
			return nil, fmt.Errorf("%w: a transaction identifier of %d does not fit three octets",
				ErrOption, m.TransactionID)
		}
		out = append(out, byte(m.Type),
			byte(m.TransactionID>>16), byte(m.TransactionID>>8), byte(m.TransactionID))
	}
	inner := []byte(nil)
	if m.Inner != nil {
		b, err := Encode(m.Inner)
		if err != nil {
			return nil, err
		}
		inner = b
	}
	wrote := false
	for _, o := range m.Options {
		value := o.Value
		if o.Code == OptionRelayMsg && inner != nil {
			value, wrote = inner, true
		}
		var err error
		if out, err = appendOption(out, o.Code, value); err != nil {
			return nil, err
		}
	}
	if inner != nil && !wrote {
		var err error
		if out, err = appendOption(out, OptionRelayMsg, inner); err != nil {
			return nil, err
		}
	}
	if m.Type.IsRelay() && inner == nil && !m.Has(OptionRelayMsg) {
		return nil, fmt.Errorf("%w: a %s with nothing inside it", ErrRelay, m.Type)
	}
	if len(out) > MaxMessage {
		return nil, fmt.Errorf("%w: %d octets", ErrTooLong, len(out))
	}
	return out, nil
}

func appendOption(out []byte, code uint16, value []byte) ([]byte, error) {
	if len(value) > 0xffff {
		return nil, fmt.Errorf("%w: option %d is %d octets", ErrTooLong, code, len(value))
	}
	out = binary.BigEndian.AppendUint16(out, code)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value))) //nolint:gosec // bounded above
	return append(out, value...), nil
}

// appendAddr writes sixteen octets. An address that is not a v6 one is written
// as the unspecified address rather than as whatever its four octets are: a
// relay's link address field is sixteen octets and a v4 address there would be
// fifteen octets of somebody else's address.
func appendAddr(out []byte, a netip.Addr) []byte {
	if !a.Is6() {
		return append(out, make([]byte, 16)...)
	}
	b := a.As16()
	return append(out, b[:]...)
}

// Set replaces an option's value, or adds it when it is not there.
//
// It replaces the first and removes any later copies, so a message this relay
// edited cannot come out with two of an option that may not repeat -- which is
// the ambiguity Repeated exists to report.
func (m *Message) Set(code uint16, value []byte) {
	out := make([]Option, 0, len(m.Options)+1)
	done := false
	for _, o := range m.Options {
		switch {
		case o.Code != code:
			out = append(out, o)
		case !done:
			out = append(out, Option{Code: code, Value: value})
			done = true
		}
	}
	if !done {
		out = append(out, Option{Code: code, Value: value})
	}
	m.Options = out
}

// Remove drops every copy of an option and says whether there was one.
func (m *Message) Remove(code uint16) bool {
	out := make([]Option, 0, len(m.Options))
	found := false
	for _, o := range m.Options {
		if o.Code == code {
			found = true
			continue
		}
		out = append(out, o)
	}
	m.Options = out
	return found
}

// Clone is a deep copy, so that editing a message for forwarding does not edit
// the one a decision was made about or the one a log line will describe.
func (m *Message) Clone() *Message {
	if m == nil {
		return nil
	}
	c := *m
	c.Options = make([]Option, len(m.Options))
	for i, o := range m.Options {
		c.Options[i] = Option{Code: o.Code, Value: append([]byte(nil), o.Value...)}
	}
	c.Raw = append([]byte(nil), m.Raw...)
	c.Inner = m.Inner.Clone()
	return &c
}

// Wrap builds the RELAY-FORW a relay sends towards a server.
//
// link is the segment the client is on and peer is where this relay received the
// message from: RFC 8415 s19.1.1 says both are the relay's own statement, which
// is the whole reason a client's own Interface-ID or Remote-ID has to be
// stripped before this.
//
// The hop count is the inner message's plus one when the inner message is itself
// a relay message, and zero otherwise, which is how the chain's depth stays the
// standard's rather than a sender's.
func Wrap(inner *Message, link, peer netip.Addr, opts ...Option) (*Message, error) {
	if inner == nil {
		return nil, fmt.Errorf("%w: nothing to relay", ErrRelay)
	}
	hops := uint8(0)
	if inner.Type.IsRelay() {
		if inner.HopCount >= MaxHopCount {
			return nil, fmt.Errorf("%w: hop count %d is already at the bound", ErrRelay, inner.HopCount)
		}
		hops = inner.HopCount + 1
	}
	m := &Message{Type: RelayForward, HopCount: hops, LinkAddress: link, PeerAddress: peer,
		Inner: inner.Clone()}
	m.Options = append(m.Options, Option{Code: OptionRelayMsg})
	m.Options = append(m.Options, opts...)
	return m, nil
}

// Unwrap is the message a RELAY-REPL carries, which is what goes back to the
// client. A reply that is not a relay message is returned as it is, because a
// server answering an unrelayed request answers the client directly.
func Unwrap(m *Message) (*Message, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nothing to unwrap", ErrRelay)
	}
	if !m.Type.IsRelay() {
		return m, nil
	}
	if m.Inner == nil {
		return nil, fmt.Errorf("%w: a %s with nothing inside it", ErrRelay, m.Type)
	}
	return m.Inner, nil
}
