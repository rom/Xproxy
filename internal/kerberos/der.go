package kerberos

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// A bounded DER reader, because everything in this package arrives from a
// peer and all of it is DER.
//
// DER is BER with the ambiguity removed: definite lengths only, the
// shortest length encoding, and one way to write each value. That makes a
// reader for it simpler than the BER reader internal/mms needs, and it
// makes two refusals here correct rather than merely cautious. An
// indefinite length is not DER, so it is refused instead of scanned for an
// end-of-contents marker the peer places. A non-minimal length is not DER
// either, and accepting one would mean two readers could disagree about
// where a field ends -- which on a protocol where a relay and a KDC both
// read the same octets is the whole class of bug worth avoiding.
//
// The bounds are the same three every nested encoding needs: a length is
// never trusted past the slice it is in, depth is counted, and a sequence's
// children are counted. A Kerberos AS-REQ is six levels deep and carries a
// handful of pre-authentication elements; nothing legitimate is near these
// numbers.

const (
	// maxDepth bounds nesting. A TGS-REQ carrying a PA-TGS-REQ with a
	// ticket inside it is about eight levels.
	maxDepth = 24
	// maxElements bounds one sequence's children: the longest list in a
	// KDC request is the encryption type list, which is a dozen.
	maxElements = 256
	// maxInteger bounds the octets an INTEGER may occupy. Everything this
	// package reads is an Int32 or a UInt32.
	maxInteger = 5
	// maxString bounds a KerberosString: a realm or one component of a
	// principal name. RFC 4120 sets no limit; the longest real one is a
	// service principal name with a fully qualified host in it.
	maxString = 1024
)

// DER classes and the constructed bit.
const (
	classUniversal   byte = 0x00
	classApplication byte = 0x40
	classContext     byte = 0x80
	constructed      byte = 0x20
)

// The universal tags this package reads.
const (
	tagInteger      uint32 = 0x02
	tagBitString    uint32 = 0x03
	tagOctetString  uint32 = 0x04
	tagSequence     uint32 = 0x10
	tagGeneralStr   uint32 = 0x1B
	tagGeneralTime  uint32 = 0x18
	tagUTF8Str      uint32 = 0x0C
	tagPrintableStr uint32 = 0x13
	tagIA5Str       uint32 = 0x16
	tagVisibleStr   uint32 = 0x1A
)

// Errors the reader returns. They are values so a kind's refusal reason
// can be a stable string rather than an error's text.
var (
	ErrShort      = errors.New("kerberos: encoding ends inside an element")
	ErrIndefinite = errors.New("kerberos: indefinite length is not DER")
	ErrNonMinimal = errors.New("kerberos: length is not in the shortest form DER requires")
	ErrDepth      = errors.New("kerberos: nested deeper than this reader will follow")
	ErrElements   = errors.New("kerberos: more elements than this reader will read")
	ErrTag        = errors.New("kerberos: element is not the tag that must be here")
	ErrInteger    = errors.New("kerberos: integer is wider than the standard's Int32")
	ErrString     = errors.New("kerberos: string is longer than this reader will read")
	ErrText       = errors.New("kerberos: string carries control characters")
	ErrTime       = errors.New("kerberos: time is not a KerberosTime")
	ErrTrailing   = errors.New("kerberos: octets after the outermost element")
)

// element is one TLV. Data aliases the caller's buffer, which is the
// buffer a relay is about to forward; nothing here writes to it.
type element struct {
	class byte
	tag   uint32
	cons  bool
	data  []byte
}

// is says the element carries this class and tag.
func (e element) is(tag uint32) bool { return e.class == classUniversal && e.tag == tag }

// ctx says the element is a context tag with this number, which is how
// every field of every Kerberos structure is encoded.
func (e element) ctx(tag uint32) bool { return e.class == classContext && e.tag == tag }

// isString says the element carries one of the universal string tags a
// KerberosString is written with.
func (e element) isString() bool {
	if e.class != classUniversal {
		return false
	}
	switch e.tag {
	case tagGeneralStr, tagIA5Str, tagUTF8Str, tagPrintableStr, tagVisibleStr:
		return true
	}
	return false
}

// der walks one level.
type der struct {
	b     []byte
	depth int
	read  int
	// ctxSeen is the set of context tags already read at this level, so a
	// structure carrying one of its fields twice is refused rather than
	// resolved. See next below for why that is a security property and not
	// tidiness.
	ctxSeen uint64
}

func newDER(b []byte) *der { return &der{b: b} }

// empty says there is nothing left at this level.
func (r *der) empty() bool { return len(r.b) == 0 }

// next reads one element.
func (r *der) next() (element, error) {
	if r.read >= maxElements {
		return element{}, ErrElements
	}
	if len(r.b) < 2 {
		return element{}, fmt.Errorf("%w: %d octets where a tag and a length must be",
			ErrShort, len(r.b))
	}
	id := r.b[0]
	tag := uint32(id & 0x1f)
	at := 1
	if tag == 0x1f {
		// The high-tag-number form. Kerberos uses it for nothing -- its
		// highest application tag is 30 -- so a tag arriving in it is
		// either a different protocol or somebody encoding a low tag the
		// long way to get two readers to disagree. Refused.
		return element{}, fmt.Errorf("%w: high-tag-number form", ErrTag)
	}
	n, hdr, err := derLength(r.b[at:])
	if err != nil {
		return element{}, err
	}
	at += hdr
	if n > len(r.b)-at {
		return element{}, fmt.Errorf("%w: element says %d octets, %d are left",
			ErrShort, n, len(r.b)-at)
	}
	// class holds the two class bits only; the constructed bit is cons, so
	// a comparison against a class never has to mask it out.
	e := element{class: id & 0xc0, tag: tag, cons: id&constructed != 0, data: r.b[at : at+n]}
	if e.class == classContext {
		// A field twice in one structure is refused, and this is the other
		// half of the promise the comment at the top of this file makes.
		// Every Kerberos field is an explicit context tag and every field
		// loop in message.go is a switch over them, so a repeated tag would
		// be resolved rather than rejected: the last occurrence overwrites
		// the realm, the sname, the cname or the options, and the etype list
		// concatenates. A KDC's decoder resolves it its own way -- the first
		// occurrence, or an error -- and the two readings are then a request
		// the policy allowed for one realm and the KDC acted on for another,
		// with the audit record wrong in the same direction as the decision.
		// There is no Kerberos structure that uses one context tag twice, so
		// nothing legitimate is refused here.
		if e.tag < 64 && r.ctxSeen&(1<<e.tag) != 0 {
			return element{}, fmt.Errorf("%w: context tag [%d] twice in one structure", ErrTag, e.tag)
		}
		r.ctxSeen |= 1 << e.tag
	}
	r.b = r.b[at+n:]
	r.read++
	return e, nil
}

// derLength reads a definite length in the shortest form.
func derLength(b []byte) (n, hdr int, err error) {
	if len(b) == 0 {
		return 0, 0, ErrShort
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	if b[0] == 0x80 {
		return 0, 0, ErrIndefinite
	}
	count := int(b[0] & 0x7f)
	if count > 4 {
		// Four octets is 4 GiB. A length wider than that is not a length
		// in any message this reader will ever be handed, and reading it
		// into an int is where a 32-bit build overflows.
		return 0, 0, fmt.Errorf("%w: %d length octets", ErrShort, count)
	}
	if len(b) < 1+count {
		return 0, 0, ErrShort
	}
	if b[1] == 0 {
		return 0, 0, ErrNonMinimal
	}
	v := 0
	for _, c := range b[1 : 1+count] {
		v = v<<8 | int(c)
	}
	if v < 0x80 || (count > 1 && v < 1<<(8*(count-1))) {
		return 0, 0, ErrNonMinimal
	}
	return v, 1 + count, nil
}

// inner descends into a constructed element, counting the depth.
func (r *der) inner(e element) (*der, error) {
	if r.depth+1 >= maxDepth {
		return nil, ErrDepth
	}
	return &der{b: e.data, depth: r.depth + 1}, nil
}

// sequence descends into a SEQUENCE.
func (r *der) sequence(e element) (*der, error) {
	if !e.cons {
		return nil, fmt.Errorf("%w: not a constructed element", ErrTag)
	}
	return r.inner(e)
}

// only descends into a context tag that wraps exactly one element and
// returns that element, which is the shape of every field in a Kerberos
// structure: [n] EXPLICIT whatever.
func (r *der) only(e element) (element, *der, error) {
	if !e.cons {
		// An explicit tag is constructed by definition: the value is inside
		// it as its own TLV. A primitive context tag whose content happens to
		// parse as one is a second spelling of the field, and a reader that
		// took it would accept an encoding a KDC rejects.
		return element{}, nil, fmt.Errorf("%w: explicit tag is not constructed", ErrTag)
	}
	in, err := r.inner(e)
	if err != nil {
		return element{}, nil, err
	}
	inner, err := in.next()
	if err != nil {
		return element{}, nil, err
	}
	if !in.empty() {
		// A context tag holding two elements is not an explicit tag
		// around one value. Reading the first and ignoring the rest is
		// how a reader comes to decide about a different value than the
		// server does.
		return element{}, nil, fmt.Errorf("%w: context tag holds more than one element", ErrTag)
	}
	return inner, in, nil
}

// derInteger reads an INTEGER as RFC 4120's Int32, which is what every
// numeric field of a Kerberos message is: a message type, an encryption
// type, a pre-authentication type, an error code, a nonce.
//
// Returning int32 rather than a wider integer is deliberate. Every caller
// turns the number into a type of that width, and a reader that handed
// back an int64 would make each of those a narrowing conversion whose
// safety the next reader has to re-derive.
func derInteger(e element) (int32, error) {
	if !e.is(tagInteger) {
		return 0, fmt.Errorf("%w: not an INTEGER", ErrTag)
	}
	b := e.data
	if len(b) == 0 || len(b) > maxInteger {
		return 0, ErrInteger
	}
	if len(b) > 1 && (b[0] == 0 && b[1] < 0x80 || b[0] == 0xff && b[1] >= 0x80) {
		// A leading octet that adds no information is not DER, and a
		// reader that accepted it would accept two encodings of one
		// number -- which is a second spelling of every value a rule is
		// written about.
		return 0, ErrNonMinimal
	}
	v := int64(int8(b[0]))
	for _, c := range b[1:] {
		v = v<<8 | int64(c)
	}
	// maxInteger admits five octets, because that is the longest DER
	// encoding of a value a peer might send; a value that does not fit in
	// an Int32 is one the standard does not define a field for.
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, ErrInteger
	}
	return int32(v), nil
}

// derString reads a KerberosString, which RFC 4120 §5.2.1 constrains to
// IA5String and which the installed base encodes as GeneralString.
//
// Control characters are refused rather than cleaned. A realm or a
// principal name with a newline in it is a second line in a log file, and
// one with an escape sequence is a terminal doing what the sequence says
// when an operator reads the record back.
func derString(e element) (string, error) {
	// The class is not enough on its own: every universal tag shares it, so a
	// realm encoded under the INTEGER or OCTET STRING tag would be read here
	// as text while a KDC reads it as the type it claims to be. The set below
	// is the string types a KerberosString arrives as -- GeneralString from
	// the installed base, and the others from implementations that took
	// RFC 4120 §5.2.1's IA5String constraint literally or went to UTF-8.
	if !e.isString() {
		return "", fmt.Errorf("%w: not a string", ErrTag)
	}
	if len(e.data) > maxString {
		return "", ErrString
	}
	for _, c := range e.data {
		if c < 0x20 || c == 0x7f {
			return "", ErrText
		}
	}
	return string(e.data), nil
}

// derTime reads a KerberosTime: a GeneralizedTime in UTC with no
// fractional seconds, which is what RFC 4120 §5.2.3 requires.
func derTime(e element) (time.Time, error) {
	if !e.is(tagGeneralTime) {
		return time.Time{}, fmt.Errorf("%w: not a GeneralizedTime", ErrTag)
	}
	t, err := time.Parse("20060102150405Z", string(e.data))
	if err != nil {
		return time.Time{}, ErrTime
	}
	return t, nil
}

// derBits reads a BIT STRING's first four octets as a big-endian word,
// which is how KDCOptions and APOptions are encoded.
//
// The unused-bits octet must be zero: both are 32-bit flag fields with no
// partial octet, and a non-zero count would mean a reader and a KDC
// disagree about the low bits of the options -- the bits that say renew,
// validate and enc-tkt-in-skey.
func derBits(e element) (uint32, error) {
	if !e.is(tagBitString) {
		return 0, fmt.Errorf("%w: not a BIT STRING", ErrTag)
	}
	if len(e.data) < 1 || e.data[0] != 0 {
		return 0, fmt.Errorf("%w: %d unused bits", ErrTag, firstOr(e.data, 0xff))
	}
	b := e.data[1:]
	var v uint32
	for i := 0; i < 4; i++ {
		v <<= 8
		if i < len(b) {
			v |= uint32(b[i])
		}
	}
	return v, nil
}

func firstOr(b []byte, or byte) byte {
	if len(b) == 0 {
		return or
	}
	return b[0]
}
