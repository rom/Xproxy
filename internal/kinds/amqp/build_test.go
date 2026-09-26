package amqp

import (
	"encoding/binary"
	"testing"

	wire "github.com/rom/xproxy/internal/amqpwire"
)

// The frames the tests are written with.
//
// A test about a policy should read as the operation it is about --
// `meth(t, ClassQueue, 40, u16(0), sstr("work"), bitsOf(false, false, false))`
// is a queue.delete -- rather than as a table of octets nobody will check
// again. The builders are deliberately willing to produce a malformed frame,
// because half of what is tested here is what the relay does with one.

func u16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func u32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func u64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// The 0-9-1 argument forms.

func sstr(s string) []byte { return append([]byte{uint8(len(s))}, s...) }
func lstr(b []byte) []byte { return append(u32(uint32(len(b))), b...) }

func bitsOf(vs ...bool) []byte {
	var b uint8
	for i, v := range vs {
		if v {
			b |= 1 << uint(i%8)
		}
	}
	return []byte{b}
}

func emptyTable() []byte           { return u32(0) }
func tbl(entries ...[]byte) []byte { return lstr(cat(entries...)) }

// entryStr is a table entry whose value is a long string, which is what the
// two arguments that name an exchange are.
func entryStr(name, value string) []byte {
	return cat(sstr(name), []byte{'S'}, lstr([]byte(value)))
}

// methodPayload is a class, a method and its arguments.
func methodPayload(class, id uint16, args ...[]byte) []byte {
	return cat(u16(class), u16(id), cat(args...))
}

// contentHeaderPayload is a content header frame's payload: the class, a
// weight, the declared body size, the property flags and the properties.
func contentHeaderPayload(bodySize uint64, flags uint16, props ...[]byte) []byte {
	return cat(u16(wire.ClassBasic), u16(0), u64(bodySize), u16(flags), cat(props...))
}

// The 1.0 type forms. The kind's own encoders cover the ones a refusal needs;
// these are the rest.

func null10() []byte { return []byte{0x40} }
func bool10(v bool) []byte {
	if v {
		return []byte{0x41}
	}
	return []byte{0x42}
}
func u10(v uint32) []byte   { return cat([]byte{0x70}, u32(v)) }
func s10(s string) []byte   { return appendString(nil, s) }
func sym10(s string) []byte { return appendSymbol(nil, s) }
func bin10(b []byte) []byte {
	return cat([]byte{0xa0, uint8(len(b))}, b)
}

// l10 is a list of already-encoded values.
func l10(items ...[]byte) []byte { return list8(cat(items...), len(items)) }

// perfBody is a performative: a descriptor and a field list.
func perfBody(code uint8, fields ...[]byte) []byte {
	return described(code, l10(fields...))
}

// perf parses what perfBody builds, which is how a policy test names a
// performative.
func perf(t *testing.T, code uint8, fields ...[]byte) *wire.Performative {
	t.Helper()
	p, err := wire.ParsePerformative(perfBody(code, fields...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// src10 and tgt10 are the described source and target of an attach, which is
// where a link's address lives.
func src10(address string, dynamic bool) []byte {
	return described(0x28, l10(s10(address), null10(), null10(), null10(), bool10(dynamic)))
}

func tgt10(address string, dynamic bool) []byte {
	return described(0x29, l10(s10(address), null10(), null10(), null10(), bool10(dynamic)))
}
