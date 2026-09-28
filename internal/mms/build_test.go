package mms

import "encoding/binary"

// A builder, so the tests read as the protocol rather than as hexadecimal.
//
// It renders BER because the tests have to: this package never encodes a frame, so
// nothing in it can be used to produce one, and a test that pasted captured octets
// would be a test nobody can change when a case is added.

// tlv renders one element with a definite length, in the high-tag-number form where
// the number needs it -- which MMS's file and domain services do, since their tags
// run past 30.
func tlv(class byte, cons bool, tag uint32, body ...[]byte) []byte {
	var b []byte
	for _, p := range body {
		b = append(b, p...)
	}
	first := class
	if cons {
		first |= Constructed
	}
	var id []byte
	if tag < 0x1F {
		id = []byte{first | byte(tag)}
	} else {
		id = append([]byte{first | 0x1F}, base128(uint64(tag))...)
	}
	id = append(id, berLen(len(b))...)
	return append(id, b...)
}

// berLen renders a length in the shortest definite form, which is what a compliant
// encoder does and what these tests assert against.
func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
}

// ctx renders a constructed context tag, ctxp a primitive one.
func ctx(tag uint32, body ...[]byte) []byte {
	return tlv(ClassContext, true, tag, body...)
}

func ctxp(tag uint32, body []byte) []byte { return tlv(ClassContext, false, tag, body) }

// app renders an [APPLICATION n] constructed tag.
func app(tag uint32, body ...[]byte) []byte {
	return tlv(ClassApplication, true, tag, body...)
}

func seq(body ...[]byte) []byte { return tlv(ClassUniversal, true, TagSequence, body...) }
func set(body ...[]byte) []byte { return tlv(ClassUniversal, true, TagSet, body...) }

// univ renders a primitive universal element.
func univ(tag uint32, body []byte) []byte { return tlv(ClassUniversal, false, tag, body) }

// integer renders an INTEGER in the shortest two's complement form.
func integer(v int64) []byte {
	if v == 0 {
		return univ(TagInteger, []byte{0})
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
	if neg && b[0]&0x80 == 0 {
		b = append([]byte{0xFF}, b...)
	}
	return univ(TagInteger, b)
}

func visible(s string) []byte { return univ(TagVisibleStr, []byte(s)) }

// oid renders an OBJECT IDENTIFIER from its arcs.
func oid(arcs ...uint64) []byte {
	if len(arcs) < 2 {
		panic("an object identifier has at least two arcs")
	}
	b := []byte{byte(arcs[0]*40 + arcs[1])}
	for _, a := range arcs[2:] {
		b = append(b, base128(a)...)
	}
	return univ(TagOID, b)
}

func base128(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0x7F)}, out...)
		v >>= 7
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

// tpkt wraps a body in a TPKT header.
func tpkt(body []byte) []byte {
	out := []byte{TPKTVersion, 0, 0, 0}
	binary.BigEndian.PutUint16(out[2:], uint16(len(body)+TPKTHeader))
	return append(out, body...)
}

// cotpData wraps a payload in a COTP data PDU.
func cotpData(payload []byte) []byte {
	return append([]byte{0x02, DT, 0x80}, payload...)
}

// sessionData wraps a payload in the canonical give-tokens plus data-transfer pair.
func sessionData(payload []byte) []byte {
	return append([]byte{SPDUGiveTokens, 0, SPDUDataTransfer, 0}, payload...)
}

// pdv wraps an encoded APDU as one presentation data value on a context.
func pdv(context uint64, apdu []byte) []byte {
	return app(1, seq(integer(int64(context)), ctx(0, apdu)))
}

// objectName renders a domain-specific ObjectName.
func objectName(domain, item string) []byte {
	return ctx(1, seq(visible(domain), visible(item)))
}

// vmdName renders a vmd-specific ObjectName.
func vmdName(item string) []byte { return ctxp(0, []byte(item)) }

// readRequest renders a confirmed Read of the given names.
func readRequest(invoke int64, names ...[]byte) []byte {
	vars := make([][]byte, 0, len(names))
	for _, n := range names {
		vars = append(vars, seq(ctx(0, n)))
	}
	return ctx(uint32(ConfirmedRequest),
		integer(invoke),
		ctx(uint32(SvcRead), ctx(1, ctx(0, vars...))))
}

// writeRequest renders a confirmed Write of one name and one value.
func writeRequest(invoke int64, name []byte) []byte {
	return ctx(uint32(ConfirmedRequest),
		integer(invoke),
		ctx(uint32(SvcWrite),
			ctx(0, seq(ctx(0, name))),
			ctx(0, ctxp(5, []byte{0x01}))))
}
