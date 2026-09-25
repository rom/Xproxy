package snmp

import (
	wire "github.com/rom/xproxy/internal/snmp"
)

// The builders. Every test message is assembled from these rather than from
// a captured hexdump, so a test says what shape it is about; and they are a
// second, independent encoder from the one in the wire package, which is
// what makes a round trip through this relay worth asserting.

func tlv(t wire.Tag, body ...byte) []byte {
	out := []byte{byte(t)}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}

func integer(v int64) []byte {
	if v == 0 {
		return tlv(wire.TagInteger, 0)
	}
	var b []byte
	neg := v < 0
	for v != 0 && v != -1 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	if len(b) == 0 || (!neg && b[0]&0x80 != 0) {
		b = append([]byte{0}, b...)
	}
	return tlv(wire.TagInteger, b...)
}

func octets(t wire.Tag, s string) []byte { return tlv(t, []byte(s)...) }

// oid encodes an object identifier, packing the first two sub-identifiers
// the way BER does and writing the rest base-128.
func oid(vals ...uint32) []byte {
	body := base128(vals[0]*40 + vals[1])
	for _, v := range vals[2:] {
		body = append(body, base128(v)...)
	}
	return tlv(wire.TagOID, body...)
}

func base128(v uint32) []byte {
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0x7f)}, out...)
		v >>= 7
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func varbind(name, value []byte) []byte {
	return tlv(wire.TagSequence, join(name, value)...)
}

func pduOf(t wire.Tag, reqID, a, c int64, binds ...[]byte) []byte {
	return tlv(t, join(integer(reqID), integer(a), integer(c),
		tlv(wire.TagSequence, join(binds...)...))...)
}

// get is a GetRequest for one object.
func get(reqID int64, o ...uint32) []byte {
	return pduOf(wire.TagGetRequest, reqID, 0, 0, varbind(oid(o...), tlv(wire.TagNull)))
}

// set is a SetRequest writing a string to one object, which is the operation
// a read-only listener exists to refuse.
func set(reqID int64, value string, o ...uint32) []byte {
	return pduOf(wire.TagSetRequest, reqID, 0, 0,
		varbind(oid(o...), octets(wire.TagOctetStr, value)))
}

// bulk is a GETBULK, whose repetition count is this protocol's
// amplification factor.
func bulk(reqID, reps int64, o ...uint32) []byte {
	return pduOf(wire.TagGetBulkRequest, reqID, 0, reps, varbind(oid(o...), tlv(wire.TagNull)))
}

// trap is a version 2 notification.
func trap(reqID int64, o ...uint32) []byte {
	return pduOf(wire.TagTrapV2, reqID, 0, 0,
		varbind(oid(1, 3, 6, 1, 2, 1, 1, 3, 0), tlv(wire.TagTimeTicks, 0, 0, 0x30, 0x39)),
		varbind(oid(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), oid(o...)))
}

// response answers a request, with a value of the requested size so a test
// can make an answer disproportionate to the question that asked for it.
func response(reqID int64, size int, o ...uint32) []byte {
	value := make([]byte, size)
	for i := range value {
		value[i] = 'x'
	}
	return pduOf(wire.TagResponse, reqID, 0, 0,
		varbind(oid(o...), tlv(wire.TagOctetStr, value...)))
}

func v1msg(community string, p []byte) []byte {
	return tlv(wire.TagSequence, join(integer(int64(wire.V1)), octets(wire.TagOctetStr, community), p)...)
}

func v2c(community string, p []byte) []byte {
	return tlv(wire.TagSequence, join(integer(int64(wire.V2c)), octets(wire.TagOctetStr, community), p)...)
}

// v3 builds a version 3 message. flags is the msgFlags octet: bit 0
// authentication, bit 1 privacy, bit 2 reportable.
func v3(flags byte, user string, contextName string, p []byte) []byte {
	usm := tlv(wire.TagOctetStr, tlv(wire.TagSequence, join(
		octets(wire.TagOctetStr, "engine-a"),
		integer(3), integer(12345),
		octets(wire.TagOctetStr, user),
		octets(wire.TagOctetStr, "0123456789ab"),
		octets(wire.TagOctetStr, ""),
	)...)...)
	global := tlv(wire.TagSequence, join(
		integer(7), integer(65507), tlv(wire.TagOctetStr, flags), integer(3),
	)...)
	scoped := tlv(wire.TagSequence, join(
		octets(wire.TagOctetStr, "engine-a"), octets(wire.TagOctetStr, contextName), p,
	)...)
	if flags&0x03 == 0x03 {
		// authPriv, and only authPriv: the scoped PDU is an OCTET STRING of
		// ciphertext, which is the shape a relay can read the header of and
		// nothing else. Privacy without authentication is not a level the
		// standard defines, so a message claiming it carries a plain scoped
		// PDU like any other -- and the policy refuses it by level.
		scoped = octets(wire.TagOctetStr, "this is not really encrypted")
	}
	return tlv(wire.TagSequence, join(integer(int64(wire.V3)), global, usm, scoped)...)
}

// parse is the wire parser, as the relay calls it, so a test that builds a
// bad message finds out here rather than three assertions later.
func parse(raw []byte) *wire.Message {
	m, err := wire.Parse(raw)
	if err != nil {
		panic("the test built a message that does not parse: " + err.Error())
	}
	return m
}
