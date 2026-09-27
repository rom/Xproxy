package snmp

import "fmt"

// Building an answer, for a listener that answers as an agent that is not
// there.
//
// The rest of this package reads: it parses what arrived and rewrites an
// envelope. This file is the one place that *builds* a response with values
// in it, which is what a fabricated agent needs and what nothing else here
// has needed.
//
// The encoding is BER, written the way an agent writes it -- the shortest
// length form, the shortest integer, and no octet more than the value needs
// -- because a response whose encoding differs from every other agent's is a
// fingerprint of this proxy for no gain.

// EncodeOID encodes an object identifier.
//
// The first two subidentifiers are one octet group, 40*first + second, which
// is X.690's own rule and the reason an OID cannot begin with anything but
// 0, 1 or 2. Every subidentifier after them is base 128, high bit set on all
// but the last octet.
func EncodeOID(o OID) []byte {
	if len(o) < 2 {
		// An OID of fewer than two arcs has no first octet group. Nothing
		// here builds one, and a caller that did would be building a name
		// no agent could answer for.
		return nil
	}
	out := make([]byte, 0, len(o)+4)
	out = appendBase128(out, o[0]*40+o[1])
	for _, sub := range o[2:] {
		out = appendBase128(out, sub)
	}
	return out
}

// appendBase128 writes one subidentifier, seven bits per octet, most
// significant first, with the continuation bit set on all but the last.
func appendBase128(dst []byte, v uint32) []byte {
	if v < 0x80 {
		return append(dst, byte(v))
	}
	var b [5]byte
	i := len(b)
	i--
	b[i] = byte(v & 0x7f)
	for v >>= 7; v > 0; v >>= 7 {
		i--
		b[i] = byte(v&0x7f) | 0x80
	}
	return append(dst, b[i:]...)
}

// Varbind builds one variable binding: a name and a value.
func Varbind(oid OID, tag Tag, value []byte) []byte {
	body := encodeTLV(TagOID, EncodeOID(oid))
	body = append(body, encodeTLV(tag, value)...)
	return encodeTLV(TagSequence, body)
}

// NullValue is the value of a binding in a request, and of one an agent
// answers with nothing.
func NullValue() []byte { return nil }

// Int, Counter, Gauge and Ticks are the numeric values an agent answers
// with. They are separate because the tag is part of the answer: a manager
// that asked for a counter and was handed an integer has been told the
// object is a different object.
func Int(v int64) []byte      { return encodeInt(v) }
func Counter(v uint32) []byte { return encodeUint(uint64(v)) }
func Gauge(v uint32) []byte   { return encodeUint(uint64(v)) }
func Ticks(v uint32) []byte   { return encodeUint(uint64(v)) }

// Counter64 is the 64-bit counter version 2c added for interfaces fast
// enough to wrap a 32-bit one inside a polling interval.
func Counter64(v uint64) []byte { return encodeUint(v) }

// encodeUint encodes an unsigned value the way BER does: the fewest octets
// that hold it, with a leading zero where the top bit would otherwise make
// it negative. Counter32, Gauge32 and TimeTicks are unsigned, and an agent
// that wrote 0xFFFFFFFF as five octets is what every agent does.
func encodeUint(v uint64) []byte {
	var b [9]byte
	for i := range 8 {
		b[8-i] = byte(v >> (8 * i))
	}
	i := 1
	for i < 8 && b[i] == 0 {
		i++
	}
	if b[i]&0x80 != 0 {
		i--
	}
	out := make([]byte, 9-i)
	copy(out, b[i:])
	return out
}

// Answer builds a response to a request: the same request identifier, no
// error, and the bindings given.
func Answer(m *Message, binds [][]byte) ([]byte, error) {
	return answer(m, 0, 0, binds)
}

// AnswerError builds a response carrying an error status and the index of
// the binding it is about, which is how an agent says an object is not one
// it has.
func AnswerError(m *Message, status, index int64) ([]byte, error) {
	if m == nil || m.PDU == nil {
		return nil, fmt.Errorf("%w: no request to answer", ErrTruncated)
	}
	// The bindings come back as they arrived, which is what an agent does:
	// a manager pairs the answer with its request by them.
	return answerRaw(m, status, index, m.PDU.Bindings)
}

func answer(m *Message, status, index int64, binds [][]byte) ([]byte, error) {
	body := make([]byte, 0, 64)
	for _, b := range binds {
		body = append(body, b...)
	}
	return answerRaw(m, status, index, encodeTLV(TagSequence, body))
}

// answerRaw assembles the response PDU around a variable-binding sequence
// that is already encoded.
func answerRaw(m *Message, status, index int64, bindings []byte) ([]byte, error) {
	if m == nil || m.PDU == nil {
		return nil, fmt.Errorf("%w: no request to answer", ErrTruncated)
	}
	if len(bindings) == 0 {
		bindings = encodeTLV(TagSequence, nil)
	}
	body := make([]byte, 0, len(bindings)+16)
	body = append(body, encodeTLV(TagInteger, encodeInt(m.PDU.RequestID))...)
	body = append(body, encodeTLV(TagInteger, encodeInt(status))...)
	body = append(body, encodeTLV(TagInteger, encodeInt(index))...)
	body = append(body, bindings...)
	return Envelope(m.Version, m.Community, encodeTLV(Tag(Response), body))
}
