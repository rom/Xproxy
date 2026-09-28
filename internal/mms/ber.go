package mms

import (
	"fmt"
	"math"
)

// A bounded BER reader, because every layer above COTP here is BER and all of it
// arrives from a peer.
//
// The bounds are the point. BER is a self-describing nested encoding with a length
// field at every level, which makes it the classic shape for two attacks: a length
// that says more than the buffer holds, and a nesting depth that turns a few
// hundred octets into a recursion as deep as the reader will follow. So this reader
// refuses a length past its own slice rather than trusting it, counts depth, and
// has no recursion the caller does not ask for one level at a time.
//
// Indefinite lengths are refused outright. They are legal BER and IEC 61850 does
// not use them; accepting them would mean scanning for an end-of-contents marker
// that a peer chooses where to put, which is a second length field under another
// name.
//
// The high-tag-number form, on the other hand, has to be supported: MMS numbers its
// confirmed services up to 77 and the low form stops at 30, so every file and domain
// service arrives in it. It is bounded instead — a tag number is at most two
// continuation octets, which is 16383 and four times the highest number any of these
// protocols defines.
const (
	// MaxDepth bounds nesting. An MMS Read of a structured data object is five or
	// six levels; past a dozen it is not a substation's traffic.
	MaxDepth = 24
	// MaxElements bounds one sequence's children, which is what stops a
	// GetNameList response with a million entries becoming a million allocations.
	MaxElements = 4096
	// MaxIdentifier bounds an object or domain name. IEC 61850-7-2 allows 64 and
	// the estate uses far less.
	MaxIdentifier = 256
	// MaxOIDArcs bounds an object identifier. An AP-title is four to eight arcs.
	MaxOIDArcs = 32
	// MaxTag bounds a tag number in the high form. The highest these protocols
	// define is MMS's fileDirectory at 77.
	MaxTag = 16383
)

// BER classes and the constructed bit.
const (
	ClassUniversal   byte = 0x00
	ClassApplication byte = 0x40
	ClassContext     byte = 0x80
	ClassPrivate     byte = 0xC0
	Constructed      byte = 0x20
)

// The universal tags this package reads.
const (
	TagBoolean    uint32 = 0x01
	TagInteger    uint32 = 0x02
	TagBitString  uint32 = 0x03
	TagOctetStr   uint32 = 0x04
	TagNull       uint32 = 0x05
	TagOID        uint32 = 0x06
	TagUTF8       uint32 = 0x0C
	TagSequence   uint32 = 0x10
	TagSet        uint32 = 0x11
	TagVisibleStr uint32 = 0x1A
	TagGeneralStr uint32 = 0x1B
	TagBMPStr     uint32 = 0x1E
)

// Element is one TLV. Data is the contents, not a copy: it aliases the buffer the
// caller handed in, which is the buffer the relay is about to forward. Nothing here
// writes to it.
type Element struct {
	Class byte
	// Tag is the tag number. It is wider than an octet because the high form
	// carries numbers that do not fit in one, and a reader that narrowed it would
	// fold two different tags into one.
	Tag  uint32
	Cons bool
	Data []byte
}

// Is says the element carries this class and tag.
func (e Element) Is(class byte, tag uint32) bool { return e.Class == class && e.Tag == tag }

// Context says the element is a context-specific tag with this number, which is how
// every CHOICE in MMS and ACSE is encoded.
func (e Element) Context(tag uint32) bool { return e.Class == ClassContext && e.Tag == tag }

// BER walks one level of a BER encoding.
type BER struct {
	b     []byte
	depth int
}

// NewBER reads the top level of b.
func NewBER(b []byte) *BER { return &BER{b: b} }

// Empty says there is nothing left at this level.
func (r *BER) Empty() bool { return len(r.b) == 0 }

// Rest is what has not been read, for a caller that wants the remaining octets as
// they arrived.
func (r *BER) Rest() []byte { return r.b }

// Next reads one element.
func (r *BER) Next() (Element, error) {
	if len(r.b) < 2 {
		return Element{}, fmt.Errorf("%w: %d octets left where a tag and length must be",
			ErrShort, len(r.b))
	}
	id := r.b[0]
	tag := uint32(id & 0x1F)
	idLen := 1
	if tag == 0x1F {
		var err error
		if tag, idLen, err = highTag(r.b); err != nil {
			return Element{}, err
		}
	}
	n, hdr, err := berLength(r.b[idLen:])
	if err != nil {
		return Element{}, err
	}
	end := idLen + hdr + n
	if end > len(r.b) || end < 0 {
		return Element{}, fmt.Errorf("%w: element says %d octets, %d are left",
			ErrShort, n, len(r.b)-idLen-hdr)
	}
	e := Element{
		Class: id & 0xC0,
		Tag:   tag,
		Cons:  id&Constructed != 0,
		Data:  r.b[idLen+hdr : end],
	}
	r.b = r.b[end:]
	return e, nil
}

// highTag reads the high-tag-number form: base-128 octets with a continuation bit,
// following an identifier whose low five bits are all set. It returns the number and
// how many octets the whole identifier took.
//
// The bound is two continuation octets. The alternative is a tag number a peer can
// make as long as it likes, which is a length field under another name -- and no tag
// in these protocols needs more.
func highTag(b []byte) (uint32, int, error) {
	var v uint32
	for i := 1; i < len(b); i++ {
		if i > 3 {
			return 0, 0, fmt.Errorf("%w: a tag number in more than %d octets", ErrSize, 3)
		}
		v = v<<7 | uint32(b[i]&0x7F)
		if v > MaxTag {
			return 0, 0, fmt.Errorf("%w: tag number %d", ErrSize, v)
		}
		if b[i]&0x80 == 0 {
			if v < 0x1F {
				// The low form could have carried it. A peer that used the long
				// form anyway has sent two encodings of one tag, which is how a
				// rule matching on a tag gets bypassed.
				return 0, 0, fmt.Errorf("%w: tag %d in the high form", ErrEncoding, v)
			}
			return v, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: a tag number that never ends", ErrEncoding)
}

// Sub reads inside a constructed element, one level deeper.
func (r *BER) Sub(e Element) (*BER, error) {
	if !e.Cons {
		return nil, fmt.Errorf("%w: a primitive element has nothing inside it", ErrEncoding)
	}
	if r.depth+1 > MaxDepth {
		return nil, fmt.Errorf("%w: nested past %d levels", ErrEncoding, MaxDepth)
	}
	return &BER{b: e.Data, depth: r.depth + 1}, nil
}

// berLength reads a length. It returns the length, how many octets described it,
// and an error for the forms this package refuses.
func berLength(b []byte) (n, hdr int, err error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("%w: no length octet", ErrShort)
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	count := int(b[0] & 0x7F)
	if count == 0 {
		// The indefinite form. Legal BER, unused by IEC 61850, and a second
		// length field under another name if it were accepted: the reader would
		// then be scanning for an end-of-contents marker a peer places where it
		// likes.
		return 0, 0, fmt.Errorf("%w: indefinite length", ErrEncoding)
	}
	if count > 4 {
		// Four octets is 4 GiB. A longer length is not a length a substation
		// sends, and reading it into an int would be reading a number this
		// program cannot hold on a 32-bit build.
		return 0, 0, fmt.Errorf("%w: length in %d octets", ErrSize, count)
	}
	if len(b) < 1+count {
		return 0, 0, fmt.Errorf("%w: %d length octets, %d available",
			ErrShort, count, len(b)-1)
	}
	var v uint64
	for _, c := range b[1 : 1+count] {
		v = v<<8 | uint64(c)
	}
	if v > math.MaxInt32 {
		return 0, 0, fmt.Errorf("%w: length %d", ErrSize, v)
	}
	return int(v), 1 + count, nil
}

// Int reads an INTEGER, which BER encodes as a signed big-endian two's complement
// number of as many octets as it takes.
//
// A value wider than eight octets is refused rather than truncated. Nothing in
// these protocols needs one, and silently keeping the low bits of a length or an
// invoke identifier is how a bound gets bypassed.
func Int(e Element) (int64, error) {
	if len(e.Data) == 0 {
		return 0, fmt.Errorf("%w: an empty INTEGER", ErrEncoding)
	}
	if len(e.Data) > 8 {
		return 0, fmt.Errorf("%w: INTEGER in %d octets", ErrSize, len(e.Data))
	}
	v := int64(0)
	if e.Data[0]&0x80 != 0 {
		v = -1
	}
	for _, c := range e.Data {
		v = v<<8 | int64(c)
	}
	return v, nil
}

// Uint reads an INTEGER that must not be negative, which is every length, count and
// identifier in these layers.
func Uint(e Element) (uint64, error) {
	v, err := Int(e)
	if err != nil {
		return 0, err
	}
	if v < 0 {
		return 0, fmt.Errorf("%w: a negative value where a count belongs: %d", ErrEncoding, v)
	}
	return uint64(v), nil
}

// Bool reads a BOOLEAN. BER says any non-zero octet is true.
func Bool(e Element) (bool, error) {
	if len(e.Data) != 1 {
		return false, fmt.Errorf("%w: BOOLEAN in %d octets", ErrEncoding, len(e.Data))
	}
	return e.Data[0] != 0, nil
}
