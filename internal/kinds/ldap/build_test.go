package ldap

import (
	wire "github.com/rom/xproxy/internal/ldap"
)

// The builders. Test messages are assembled from the exported wire package's
// own encoder where it has one, and from BER by hand where it does not --
// which is most of it, because a relay's tests are about the requests clients
// send and a relay never sends those.

// ber is a minimal encoder for the shapes these tests need. It is a second
// encoder from the one the wire package uses to *re*build an entry, which is
// the pair that has to agree.
func ber(id byte, body ...byte) []byte {
	out := []byte{id}
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

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

const (
	tagBool   = 0x01
	tagInt    = 0x02
	tagOctets = 0x04
	tagEnum   = 0x0a
	tagSeq    = 0x30
	tagSet    = 0x31
	appCons   = 0x60 // application, constructed
	appPrim   = 0x40 // application, primitive
	ctxCons   = 0xa0 // context, constructed
	ctxPrim   = 0x80 // context, primitive
)

func integer(v int) []byte {
	if v == 0 {
		return ber(tagInt, 0)
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return ber(tagInt, b...)
}

func enumerated(v int) []byte { out := integer(v); out[0] = tagEnum; return out }
func octets(s string) []byte  { return ber(tagOctets, []byte(s)...) }
func boolean(b bool) []byte {
	if b {
		return ber(tagBool, 0xff)
	}
	return ber(tagBool, 0x00)
}
func seq(parts ...[]byte) []byte   { return ber(tagSeq, cat(parts...)...) }
func setOf(parts ...[]byte) []byte { return ber(tagSet, cat(parts...)...) }
func appC(tag byte, parts ...[]byte) []byte {
	return ber(appCons|tag, cat(parts...)...)
}
func appP(tag byte, data string) []byte { return ber(appPrim|tag, []byte(data)...) }
func ctxC(tag byte, parts ...[]byte) []byte {
	return ber(ctxCons|tag, cat(parts...)...)
}
func ctxP(tag byte, data string) []byte { return ber(ctxPrim|tag, []byte(data)...) }

// msg wraps an operation in an LDAPMessage.
func msg(id int, op []byte, controls ...[]byte) []byte {
	parts := [][]byte{integer(id), op}
	if len(controls) > 0 {
		parts = append(parts, ctxC(0, controls...))
	}
	return seq(parts...)
}

// bind is a simple bind: the operation every application performs, and the
// three different security statements its two string fields can make.
func bind(id int, name, password string) []byte {
	return msg(id, appC(0, integer(3), octets(name), ctxP(0, password)))
}

func bindVersion(id, version int, name, password string) []byte {
	return msg(id, appC(0, integer(version), octets(name), ctxP(0, password)))
}

func saslBind(id int, mechanism, credential string) []byte {
	return msg(id, appC(0, integer(3), octets(""),
		ctxC(3, octets(mechanism), octets(credential))))
}

// search builds a SearchRequest with the eight fields it has.
func search(id int, base string, scope int, filter []byte, attrs ...string) []byte {
	list := [][]byte{}
	for _, a := range attrs {
		list = append(list, octets(a))
	}
	return msg(id, appC(3, octets(base), enumerated(scope), enumerated(0),
		integer(0), integer(0), boolean(false), filter, seq(list...)))
}

func present(attr string) []byte         { return ctxP(7, attr) }
func equality(attr, value string) []byte { return ctxC(3, octets(attr), octets(value)) }
func and(parts ...[]byte) []byte         { return ctxC(0, parts...) }
func or(parts ...[]byte) []byte          { return ctxC(1, parts...) }
func not(part []byte) []byte             { return ctxC(2, part) }
func substr(attr string, parts ...[]byte) []byte {
	return ctxC(4, octets(attr), seq(parts...))
}
func initialPart(s string) []byte { return ctxP(0, s) }
func finalPart(s string) []byte   { return ctxP(2, s) }

func modify(id int, object string, changes ...[]byte) []byte {
	return msg(id, appC(6, octets(object), seq(changes...)))
}

func change(op int, attr string, values ...string) []byte {
	vals := [][]byte{}
	for _, v := range values {
		vals = append(vals, octets(v))
	}
	return seq(enumerated(op), seq(octets(attr), setOf(vals...)))
}

func add(id int, object string) []byte { return msg(id, appC(8, octets(object), seq())) }
func del(id int, object string) []byte { return msg(id, appP(10, object)) }
func compare(id int, object, attr, value string) []byte {
	return msg(id, appC(14, octets(object), seq(octets(attr), octets(value))))
}
func extended(id int, oid string) []byte { return msg(id, appC(23, ctxP(0, oid))) }
func unbind(id int) []byte               { return msg(id, ber(appPrim|2)) }

// entry is a SearchResultEntry with values, which is what a directory sends
// and what the relay has to rewrite.
func entry(id int, name string, attrs ...string) []byte {
	list := [][]byte{}
	for _, a := range attrs {
		list = append(list, seq(octets(a), setOf(octets("value-of-"+a))))
	}
	return msg(id, appC(4, octets(name), seq(list...)))
}

func searchDone(id int, code wire.ResultCode) []byte {
	return msg(id, appC(5, enumerated(int(code)), octets(""), octets("")))
}

func bindResult(id int, code wire.ResultCode) []byte {
	return msg(id, appC(1, enumerated(int(code)), octets(""), octets("")))
}

func parseMsg(raw []byte) *wire.Message {
	m, err := wire.Parse(raw)
	if err != nil {
		panic("the test built a message that does not parse: " + err.Error())
	}
	return m
}
