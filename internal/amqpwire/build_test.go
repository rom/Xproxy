package amqpwire

import "encoding/binary"

// The builders the tests are written with.
//
// They exist so a test reads as the frame it is about -- `frame091(FrameMethod,
// 1, method(ClassQueue, 40, short(0), shortstr("q"), bits(true)))` -- rather
// than as a table of octets nobody will check again. They are deliberately
// willing to build a malformed frame: half of what is tested here is what
// this package does with one.

func be16b(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32b(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func be64b(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// The 0-9-1 argument forms.

func octet(v uint8) []byte  { return []byte{v} }
func short(v uint16) []byte { return be16b(v) }
func long(v uint32) []byte  { return be32b(v) }
func longlong(v uint64) []byte {
	return be64b(v)
}

func shortstr(s string) []byte { return append([]byte{uint8(len(s))}, s...) }
func longstr(b []byte) []byte  { return append(be32b(uint32(len(b))), b...) }

// bits packs booleans the way the protocol does: one octet, least
// significant first.
func bits(vs ...bool) []byte {
	var b uint8
	for i, v := range vs {
		if v {
			b |= 1 << uint(i%8)
		}
	}
	return []byte{b}
}

// table builds a field table out of already-encoded entries.
func table(entries ...[]byte) []byte { return longstr(join(entries...)) }

// entryS is a table entry whose value is a long string.
func entryS(name, value string) []byte {
	return join(shortstr(name), []byte{'S'}, longstr([]byte(value)))
}

// entryI is a table entry whose value is a 32-bit integer, which is what a
// bound like x-max-length is written as.
func entryI(name string, v uint32) []byte {
	return join(shortstr(name), []byte{'I'}, be32b(v))
}

// entryUnknown is a table entry with a type code nothing defines, which is
// the case a reader must refuse rather than skip.
func entryUnknown(name string) []byte {
	return join(shortstr(name), []byte{'Z'}, []byte{0})
}

// entryTable nests a table inside one.
func entryTable(name string, inner ...[]byte) []byte {
	return join(shortstr(name), []byte{'F'}, table(inner...))
}

func method(class, id uint16, args ...[]byte) []byte {
	return join(be16b(class), be16b(id), join(args...))
}

func frame091(typ uint8, channel uint16, payload []byte) []byte {
	return join([]byte{typ}, be16b(channel), be32b(uint32(len(payload))), payload, []byte{FrameEnd})
}

// contentHeader builds a content header frame's payload: the class, a
// weight, the body size, the property flags and the properties those flags
// name.
func contentHeader(class uint16, bodySize uint64, flags uint16, props ...[]byte) []byte {
	return join(be16b(class), be16b(0), be64b(bodySize), be16b(flags), join(props...))
}

func header091() []byte { return []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1} }
func header10(id uint8) []byte {
	return []byte{'A', 'M', 'Q', 'P', id, 1, 0, 0}
}

// The 1.0 type forms.

func null10() []byte { return []byte{0x40} }
func bool10(v bool) []byte {
	if v {
		return []byte{0x41}
	}
	return []byte{0x42}
}
func uint10(v uint32) []byte   { return join([]byte{0x70}, be32b(v)) }
func smalluint(v uint8) []byte { return []byte{0x52, v} }
func str10(s string) []byte    { return join([]byte{0xa1, uint8(len(s))}, []byte(s)) }
func sym10(s string) []byte    { return join([]byte{0xa3, uint8(len(s))}, []byte(s)) }
func bin10(b []byte) []byte    { return join([]byte{0xa0, uint8(len(b))}, b) }

// list10 is a list8: a size, a count and the elements.
func list10(items ...[]byte) []byte {
	body := join(items...)
	return join([]byte{0xc0, uint8(len(body) + 1), uint8(len(items))}, body)
}

// bigList10 is a list32, for the lists that do not fit in a one-octet
// size.
func bigList10(items ...[][]byte) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, join(it...)...)
	}
	return join([]byte{0xd0}, be32b(uint32(len(body)+4)), be32b(uint32(len(items))), body)
}

// array10 is an array8: one constructor for every element.
func array10(ctor byte, items ...[]byte) []byte {
	body := join(items...)
	return join([]byte{0xe0, uint8(len(body) + 2), uint8(len(items)), ctor}, body)
}

// described10 wraps a body in a descriptor written as a small unsigned
// long, which is how a performative arrives.
func described10(code uint8, body []byte) []byte {
	return join([]byte{0x00, 0x53, code}, body)
}

// perf10 builds a performative: a descriptor and a field list.
func perf10(code uint8, fields ...[]byte) []byte {
	return described10(code, list10(fields...))
}

// source10 and target10 build the described source and target of an attach.
func source10(address string, dynamic bool) []byte {
	return described10(0x28, list10(str10(address), null10(), null10(), null10(), bool10(dynamic)))
}

func target10(address string, dynamic bool) []byte {
	return described10(0x29, list10(str10(address), null10(), null10(), null10(), bool10(dynamic)))
}

// frame10 builds a 1.0 frame: a size that includes the header, a data
// offset of two words, a type and a channel.
func frame10(typ uint8, channel uint16, body []byte) []byte {
	size := uint32(8 + len(body))
	return join(be32b(size), []byte{2, typ}, be16b(channel), body)
}
