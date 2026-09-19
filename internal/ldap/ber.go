package ldap

import (
	"errors"
	"fmt"
)

// A minimal BER encoder and decoder covering the subset of LDAP (RFC 4511)
// this package speaks: bind and search. It is deliberately small; only the
// tags and forms those operations use are supported.

// BER classes.
const (
	classUniversal   = 0x00
	classApplication = 0x40
	classContext     = 0x80
)

// constructed is the bit that marks a constructed (nested) value.
const constructed = 0x20

// Universal tags.
const (
	tagBoolean  = 0x01
	tagInteger  = 0x02
	tagOctetStr = 0x04
	tagEnum     = 0x0a
	tagSequence = 0x10
	tagSet      = 0x11
)

// packet is one BER TLV: a leaf carries bytes, a constructed node carries
// children. class/tag identify it; encoding recomputes the identifier and
// length.
type packet struct {
	class byte
	tag   byte
	// constructed reports a nested value; kids is then the content.
	cons bool
	data []byte
	kids []*packet
}

func leaf(class, tag byte, data []byte) *packet {
	return &packet{class: class, tag: tag, data: data}
}

func node(class, tag byte, kids ...*packet) *packet {
	return &packet{class: class, tag: tag, cons: true, kids: kids}
}

func (p *packet) add(k *packet) { p.kids = append(p.kids, k) }

// encode appends the TLV encoding of p to out.
func (p *packet) encode(out []byte) []byte {
	id := p.class | p.tag
	if p.cons {
		id |= constructed
	}
	out = append(out, id)
	var body []byte
	if p.cons {
		for _, k := range p.kids {
			body = k.encode(body)
		}
	} else {
		body = p.data
	}
	out = appendLength(out, len(body))
	return append(out, body...)
}

func appendLength(out []byte, n int) []byte {
	if n < 0x80 {
		return append(out, byte(n))
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n)
		n >>= 8
	}
	out = append(out, byte(0x80|(len(buf)-i)))
	return append(out, buf[i:]...)
}

// integer builds a universal INTEGER holding a non-negative value that fits
// the LDAP fields this package sets (versions, limits, message IDs).
func integer(v int) *packet {
	if v == 0 {
		return leaf(classUniversal, tagInteger, []byte{0})
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	// A leading bit set would read as negative; prepend a zero.
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return leaf(classUniversal, tagInteger, b)
}

func enumerated(v int) *packet { p := integer(v); p.tag = tagEnum; return p }

func str(s string) *packet { return leaf(classUniversal, tagOctetStr, []byte(s)) }

func boolean(b bool) *packet {
	v := byte(0)
	if b {
		v = 0xff
	}
	return leaf(classUniversal, tagBoolean, []byte{v})
}

// parse reads one TLV from b and returns it with the number of bytes consumed.
func parse(b []byte) (*packet, int, error) {
	if len(b) < 2 {
		return nil, 0, errors.New("ber: short packet")
	}
	id := b[0]
	p := &packet{class: id & 0xc0, tag: id & 0x1f, cons: id&constructed != 0}
	if p.tag == 0x1f {
		return nil, 0, errors.New("ber: high-tag-number form unsupported")
	}
	n, hdr, err := readLength(b[1:])
	if err != nil {
		return nil, 0, err
	}
	start := 1 + hdr
	end := start + n
	if n < 0 || end > len(b) {
		return nil, 0, errors.New("ber: length exceeds buffer")
	}
	body := b[start:end]
	if p.cons {
		for len(body) > 0 {
			kid, used, err := parse(body)
			if err != nil {
				return nil, 0, err
			}
			p.kids = append(p.kids, kid)
			body = body[used:]
		}
	} else {
		p.data = body
	}
	return p, end, nil
}

// readLength reads a definite-form length; it returns the length and the
// number of header bytes it used. Indefinite form is rejected.
func readLength(b []byte) (length, hdr int, err error) {
	if len(b) == 0 {
		return 0, 0, errors.New("ber: missing length")
	}
	first := b[0]
	if first < 0x80 {
		return int(first), 1, nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return 0, 0, errors.New("ber: indefinite length unsupported")
	}
	if count > 4 || 1+count > len(b) {
		return 0, 0, errors.New("ber: bad long-form length")
	}
	n := 0
	for i := 0; i < count; i++ {
		n = n<<8 | int(b[1+i])
	}
	if n < 0 {
		return 0, 0, errors.New("ber: length overflow")
	}
	return n, 1 + count, nil
}

// intValue reads a non-negative integer/enumerated value.
func (p *packet) intValue() (int, error) {
	if len(p.data) == 0 || len(p.data) > 4 {
		return 0, fmt.Errorf("ber: bad integer of %d bytes", len(p.data))
	}
	n := 0
	for _, c := range p.data {
		n = n<<8 | int(c)
	}
	return n, nil
}
