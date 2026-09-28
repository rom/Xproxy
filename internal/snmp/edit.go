package snmp

import (
	"encoding/binary"
	"fmt"
)

// Rewriting a message.
//
// A relay that changes a message has to re-encode it, and this relay makes
// exactly three changes. It lowers a GETBULK's repetition count, because
// that count is the amplification factor of the best-known attack on this
// protocol. It rebuilds the envelope of a request whose version is being
// downgraded, which is how a manager speaks v3 with authentication to the
// relay and the relay speaks v2c to a switch whose firmware has nothing
// else. And it answers a refusal the way an agent would, so the manager
// sees an error rather than a timeout.
//
// All three keep the variable bindings exactly as they arrived. What was
// asked for is not the relay's to edit -- only how much of it may come
// back, and in whose name it is asked.
//
// None of them can be applied to an *authenticated* version 3 message.
// msgAuthenticationParameters is a digest over the whole message and this
// relay holds no key, so any edit would produce a message the agent then
// rejects -- and an edit that silently produced an unauthenticated message
// would be worse. Rebuilding a v1 or v2c envelope around the PDU is a
// different act and is allowed: the digest is discarded along with the
// envelope it belonged to, and what leaves here is honestly a message this
// relay sent, in a credential this relay holds.

// The error statuses a refusal is reported in.
const (
	// StatusNoSuchName is version 1's way of saying an object is not in
	// this community's view, which is the nearest thing v1 has to a
	// refusal.
	StatusNoSuchName = 2
	// StatusNoAccess is version 2c's and version 3's, added precisely so
	// that "you may not" stopped having to be spelled as "no such
	// object".
	StatusNoAccess = 6
	// StatusTooBig is what an agent answers when the response would not
	// fit: the manager is expected to ask for less, which is what every
	// manager does.
	StatusTooBig = 1
)

// encodeTLV encodes one element: a tag, a length in the shortest form that holds
// it, and the contents.
func encodeTLV(tag Tag, body []byte) []byte {
	n := len(body)
	out := make([]byte, 0, n+6)
	out = append(out, byte(tag))
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	case n <= 0xffff:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// encodeInt encodes an INTEGER: two's complement, big endian, in the fewest
// octets that hold the value with its sign. Writing more octets than that
// is legal BER and is not what an agent sees from any other manager, so a
// rewritten field that looked different from an untouched one would be a
// fingerprint of this relay for no gain.
func encodeInt(v int64) []byte {
	var b [8]byte
	// The two's-complement octets of v, which is what BER writes. The
	// conversion is the reinterpretation, not a range change: a negative v
	// is meant to come out as its high-bit-set octets.
	binary.BigEndian.PutUint64(b[:], uint64(v)) //nolint:gosec // two's complement is the point
	i := 0
	for i < 7 {
		// A leading octet goes only when the next one still carries the
		// sign: dropping 0x00 before an octet with its high bit set would
		// turn a positive number negative.
		if b[i] == 0x00 && b[i+1]&0x80 == 0 {
			i++
			continue
		}
		if b[i] == 0xff && b[i+1]&0x80 != 0 {
			i++
			continue
		}
		break
	}
	out := make([]byte, 8-i)
	copy(out, b[i:])
	return out
}

// Envelope builds a version 1 or 2c message around a PDU element.
//
// It is the secure downgrade in one function: the PDU is whatever arrived,
// the version and the community string are this relay's, and the manager
// never needs to know the second.
func Envelope(v Version, community string, pdu []byte) ([]byte, error) {
	if v != V1 && v != V2c {
		return nil, fmt.Errorf("%w: a community envelope is v1 or v2c, not %s", ErrVersion, v)
	}
	if len(community) > MaxCommunity {
		return nil, ErrCommunity
	}
	if len(pdu) == 0 {
		return nil, ErrTruncated
	}
	body := make([]byte, 0, len(pdu)+len(community)+16)
	body = append(body, encodeTLV(TagInteger, encodeInt(int64(v)))...)
	body = append(body, encodeTLV(TagOctetStr, []byte(community))...)
	body = append(body, pdu...)
	out := encodeTLV(TagSequence, body)
	if len(out) > MaxMessage {
		return nil, ErrTruncated
	}
	return out, nil
}

// WithMaxRepetitions rebuilds a GETBULK PDU element with its
// max-repetitions field replaced, leaving the request identifier, the
// non-repeaters count and the bindings as they were.
func WithMaxRepetitions(pdu []byte, n int64) ([]byte, error) {
	if n < 0 {
		return nil, ErrIntegerRange
	}
	top := &reader{b: pdu}
	e, err := top.next()
	if err != nil {
		return nil, err
	}
	if !top.empty() {
		return nil, ErrTrailing
	}
	if PDUType(e.tag) != GetBulkRequest {
		return nil, fmt.Errorf("%w: max-repetitions belongs to a GETBULK, not %#02x", ErrTag, byte(e.tag))
	}
	in, err := top.sub(e)
	if err != nil {
		return nil, err
	}
	id, err := in.expect(TagInteger)
	if err != nil {
		return nil, err
	}
	nonRep, err := in.expect(TagInteger)
	if err != nil {
		return nil, err
	}
	if _, err := in.expect(TagInteger); err != nil {
		// The count being replaced. It is read rather than skipped so that
		// a PDU whose third field is not an INTEGER is refused here and
		// not silently rebuilt into something else.
		return nil, err
	}
	binds, err := in.expect(TagSequence)
	if err != nil {
		return nil, err
	}
	if !in.empty() {
		return nil, ErrTrailing
	}
	body := make([]byte, 0, len(e.body)+4)
	body = append(body, id.raw...)
	body = append(body, nonRep.raw...)
	body = append(body, encodeTLV(TagInteger, encodeInt(n))...)
	body = append(body, binds.raw...)
	return encodeTLV(e.tag, body), nil
}

// Refusal builds the answer an agent sends to a request it will not serve:
// a Response PDU carrying an error status, echoing the bindings that were
// asked for. Every manager already knows how to display that, which is why
// a relay's refusal is better sent than dropped -- a dropped request is a
// timeout, and a timeout is indistinguishable from a device that died.
//
// It returns nil where there is no answer to send: a version 3 message,
// whose response would have to carry a digest this relay cannot compute; a
// notification, which nobody is waiting on; and a response, which is not a
// request.
func Refusal(m *Message) []byte {
	if m == nil || m.PDU == nil {
		return nil
	}
	if m.Version == V3 && !m.IsTSM() {
		// A USM refusal would have to be signed with the manager's own key,
		// which this relay does not hold as that manager. The transport
		// security model is the exception and not a loophole: its messages
		// carry no digest at all, so a response is authenticated by the
		// session it is written into. See refusalTSM.
		return nil
	}
	switch p := m.PDU; {
	case p.Type.Notification(), p.Type == Response, p.Type == ReportPDU:
		return nil
	}
	status, index := int64(StatusNoAccess), int64(0)
	if m.Version == V1 {
		// Version 1 has no noAccess, and noSuchName is what its agents
		// answer for an object outside the community's view. It is the
		// same statement in the only vocabulary a v1 manager has.
		status = StatusNoSuchName
		if len(m.PDU.VarBinds) > 0 {
			index = 1
		}
	}
	binds := m.PDU.Bindings
	if len(binds) == 0 {
		binds = encodeTLV(TagSequence, nil)
	}
	body := make([]byte, 0, len(binds)+16)
	body = append(body, encodeTLV(TagInteger, encodeInt(m.PDU.RequestID))...)
	body = append(body, encodeTLV(TagInteger, encodeInt(status))...)
	body = append(body, encodeTLV(TagInteger, encodeInt(index))...)
	body = append(body, binds...)
	pdu := encodeTLV(Tag(Response), body)
	if m.IsTSM() {
		return refusalTSM(m, pdu)
	}
	out, err := Envelope(m.Version, m.Community, pdu)
	if err != nil {
		return nil
	}
	return out
}

// refusalTSM wraps a refusal for a message under the transport security
// model.
//
// The context is echoed rather than chosen: a manager that named an engine and
// a context is owed an answer about that engine and that context, and an agent
// answers with the ones it was asked about. The message identifier is echoed
// for the reason every response echoes it -- it is what the manager's stack
// pairs the answer with -- and the level is the one the message arrived at,
// which is the transport's and not this relay's to raise or lower.
func refusalTSM(m *Message, pdu []byte) []byte {
	scoped, err := ScopedPDU(m.V3.ContextEngineID, m.V3.ContextName, pdu)
	if err != nil {
		return nil
	}
	out, err := BuildTSM(TSMBuild{
		MessageID: m.V3.MessageID, MaxSize: m.V3.MaxSize, Level: m.V3.Level,
		Scoped: scoped,
	})
	if err != nil {
		return nil
	}
	return out
}
