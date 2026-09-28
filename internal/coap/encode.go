package coap

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// Encode writes a message back to the wire.
//
// A relay encodes for two reasons: to forward a message it has taken an option
// out of, and to answer one itself. The second is the more important -- the
// standard gives a proxy defined answers for the messages it refuses (4.02 for an
// unrecognised critical option, 5.02 for an unrecognised unsafe one), and
// answering is better than dropping, because a device that got an answer stops
// retransmitting and a device that got silence does not.
func Encode(m *Message) ([]byte, error) {
	if len(m.Token) > MaxToken {
		return nil, fmt.Errorf("%w: a token of %d octets", ErrToken, len(m.Token))
	}
	if m.Code.IsEmpty() && (len(m.Token) != 0 || len(m.Options) != 0 || len(m.Payload) != 0) {
		return nil, fmt.Errorf("%w: refusing to write one", ErrEmpty)
	}
	out := make([]byte, 0, HeaderLen+len(m.Token)+len(m.Payload)+32)
	out = append(out, Version<<6|byte(m.Type&0x03)<<4|byte(len(m.Token)))
	out = append(out, byte(m.Code))
	out = binary.BigEndian.AppendUint16(out, m.MessageID)
	out = append(out, m.Token...)

	// The options are delta-encoded, so they have to go out in ascending number
	// order whatever order they are held in. The sort is stable because the
	// instances of a repeated option are the path and the query, and their order
	// is their meaning: sorting "sensors" before "temperature" unstably would be
	// reordering the path.
	opts := make([]Option, len(m.Options))
	copy(opts, m.Options)
	sort.SliceStable(opts, func(i, j int) bool { return opts[i].Number < opts[j].Number })

	var last uint16
	for _, o := range opts {
		if len(o.Value) > MaxOptionLen {
			return nil, fmt.Errorf("%w: %s of %d octets", ErrTooLong,
				OptionName(o.Number), len(o.Value))
		}
		// Ascending after the sort, so the delta is never negative.
		delta := int(o.Number) - int(last)
		last = o.Number
		dn, dext := nibble(delta)
		ln, lext := nibble(len(o.Value))
		out = append(out, dn<<4|ln)
		out = append(out, dext...)
		out = append(out, lext...)
		out = append(out, o.Value...)
	}
	if len(m.Payload) > 0 {
		out = append(out, PayloadMarker)
		out = append(out, m.Payload...)
	}
	if len(out) > MaxMessage {
		return nil, fmt.Errorf("%w: %d octets", ErrTooLong, len(out))
	}
	return out, nil
}

// nibble splits a value into the nibble and the extension octets of RFC 7252
// s3.1.
// The caller has already bounded v: an option number is sixteen bits and a value
// is at most MaxOptionLen octets, so neither the byte nor the uint16 below can
// lose anything.
func nibble(v int) (uint8, []byte) {
	switch {
	case v < 13:
		return uint8(v), nil //nolint:gosec // below thirteen
	case v < 269:
		return 13, []byte{byte(v - 13)}
	}
	return 14, binary.BigEndian.AppendUint16(nil, uint16(v-269)) //nolint:gosec // bounded above
}

// Clone copies a message deeply enough to edit: the options and the payload are
// fresh, so removing an option from the copy leaves the original as it arrived.
// Raw is carried over rather than copied, because it is the message that arrived
// and editing the copy does not change that.
func (m *Message) Clone() *Message {
	out := *m
	out.Token = append([]byte(nil), m.Token...)
	out.Options = make([]Option, len(m.Options))
	for i, o := range m.Options {
		out.Options[i] = Option{Number: o.Number, Value: append([]byte(nil), o.Value...)}
	}
	out.Payload = append([]byte(nil), m.Payload...)
	return &out
}

// Set replaces every instance of an option with one.
func (m *Message) Set(n uint16, v []byte) {
	m.Remove(n)
	m.Options = append(m.Options, Option{Number: n, Value: v})
}

// Add appends an instance, which is how a repeated option is built.
func (m *Message) Add(n uint16, v []byte) {
	m.Options = append(m.Options, Option{Number: n, Value: v})
}

// Remove takes out every instance of an option and says how many went.
func (m *Message) Remove(n uint16) int {
	kept := m.Options[:0]
	gone := 0
	for _, o := range m.Options {
		if o.Number == n {
			gone++
			continue
		}
		kept = append(kept, o)
	}
	m.Options = kept
	return gone
}

// Answer builds the response a relay sends itself, rather than forwarding the
// request and letting the far end decide.
//
// The type is what RFC 7252 s5.2 requires for the request's own type: a
// Confirmable request is answered by an Acknowledgement carrying the response --
// piggybacked, with the request's own message identifier, so it also acknowledges
// it -- and a Non-confirmable request by a Non-confirmable response with an
// identifier of its own. The token is the request's, because the token is the only
// thing that pairs the two, and a response with the wrong token is not an answer
// to this client at all.
func Answer(req *Message, code Code, mid uint16) *Message {
	out := &Message{Code: code, Token: append([]byte(nil), req.Token...)}
	if req.Type == Confirmable {
		out.Type, out.MessageID = Acknowledgement, req.MessageID
		return out
	}
	out.Type, out.MessageID = NonConfirmable, mid
	return out
}

// ResetFor builds the empty Reset that answers a message a hop could not process
// at all: a format error, or a notification nobody wants any more.
//
// It carries no token, because an empty message carries nothing (RFC 7252 s4.1).
// That is also why it is the right answer to a message whose token could not be
// read: there is nothing to echo back and nothing that pretends there was.
func ResetFor(mid uint16) *Message {
	return &Message{Type: Reset, Code: Empty, MessageID: mid}
}

// AckFor builds the bare acknowledgement that says "received, answer to follow",
// which is what a relay sends when it is about to take longer than the far end's
// retransmission timer.
func AckFor(mid uint16) *Message {
	return &Message{Type: Acknowledgement, Code: Empty, MessageID: mid}
}
