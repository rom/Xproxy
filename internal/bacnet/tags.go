package bacnet

import (
	"encoding/binary"
	"fmt"
)

// The application tag numbers of clause 20.2.1.4. Only the ones this
// package reads are named.
const (
	tagBoolean    uint32 = 1
	tagUnsigned   uint32 = 2
	tagEnumerated uint32 = 9
	tagObjectID   uint32 = 12
)

// extendedTag is the tag number that means "the real number is in the
// next octet".
const extendedTag uint32 = 15

// tag is one BACnet tag and the primitive value under it. A constructed
// value is two tags -- an opening and a closing -- with anything between
// them, so Opening and Closing are how a walk knows to descend or stop.
type tag struct {
	Number  uint32
	Context bool
	Opening bool
	Closing bool
	// Data is the primitive value's octets, aliasing the message.
	Data []byte
	// Boolean is an application Boolean's value, which lives in the
	// length field rather than in any octets of its own.
	Boolean bool
}

// reader walks the tags of an encoded parameter list.
type reader struct {
	b  []byte
	at int
}

// done reports whether the reader has consumed everything.
func (r *reader) done() bool { return r.at >= len(r.b) }

// next reads one tag and its primitive value, leaving the reader after
// it. It does not descend into a constructed value: a caller that reads
// an opening tag either descends itself or calls skip.
func (r *reader) next() (tag, error) {
	if r.done() {
		return tag{}, fmt.Errorf("%w: a tag past the end of %d octets", ErrTruncated, len(r.b))
	}
	head := r.b[r.at]
	r.at++
	t := tag{Number: uint32(head >> 4), Context: head&0x08 != 0}
	lvt := head & 0x07
	if t.Number == extendedTag {
		if r.done() {
			return t, fmt.Errorf("%w: an extended tag number with no octet after it", ErrTruncated)
		}
		t.Number = uint32(r.b[r.at])
		r.at++
		if t.Number < extendedTag {
			// The extended form is for numbers the short form cannot
			// hold. A number under fifteen written the long way is two
			// encodings of one tag, and the two are what a device and a
			// relay can disagree about.
			return t, fmt.Errorf("%w: tag number %d written in the extended form", ErrMalformed, t.Number)
		}
	}
	switch lvt {
	case 6:
		if !t.Context {
			return t, fmt.Errorf("%w: an opening marker on an application tag (%d)", ErrMalformed, t.Number)
		}
		t.Opening = true
		return t, nil
	case 7:
		if !t.Context {
			return t, fmt.Errorf("%w: a closing marker on an application tag (%d)", ErrMalformed, t.Number)
		}
		t.Closing = true
		return t, nil
	}
	if !t.Context && t.Number == tagBoolean {
		// An application Boolean carries its value in the length field
		// and has no octets of its own (clause 20.2.3).
		if lvt > 1 {
			return t, fmt.Errorf("%w: a boolean with a length of %d", ErrMalformed, lvt)
		}
		t.Boolean = lvt == 1
		return t, nil
	}
	// The length is held in an int throughout, bounded against the
	// message before it is ever converted: no encoded length this
	// protocol can carry is larger than a message it can carry, so a
	// declared length past MaxMessage is refused where it is read rather
	// than after arithmetic on it.
	n := int(lvt)
	if lvt == 5 {
		// The extended length form. A small length written this way is
		// accepted rather than refused: unlike a tag number, there is no
		// second reading of it -- both a device and this relay see the
		// same value -- so refusing would turn a clumsy encoder into a
		// building with no heating.
		if r.done() {
			return t, fmt.Errorf("%w: an extended length with no octet after it", ErrTruncated)
		}
		first := r.b[r.at]
		r.at++
		switch {
		case first < 254:
			n = int(first)
		case first == 254:
			if r.at+2 > len(r.b) {
				return t, fmt.Errorf("%w: a two-octet length with %d octets left", ErrTruncated, len(r.b)-r.at)
			}
			n = int(binary.BigEndian.Uint16(r.b[r.at : r.at+2]))
			r.at += 2
		default:
			if r.at+4 > len(r.b) {
				return t, fmt.Errorf("%w: a four-octet length with %d octets left", ErrTruncated, len(r.b)-r.at)
			}
			v := binary.BigEndian.Uint32(r.b[r.at : r.at+4])
			if v > MaxMessage {
				return t, fmt.Errorf("%w: a value of %d octets, and Annex J's largest message is %d",
					ErrMalformed, v, MaxMessage)
			}
			n = int(uint16(v))
			r.at += 4
		}
	}
	if n > len(r.b)-r.at {
		return t, fmt.Errorf("%w: a value of %d octets with %d left", ErrTruncated, n, len(r.b)-r.at)
	}
	t.Data = r.b[r.at : r.at+n]
	r.at += n
	return t, nil
}

// skip advances past the constructed value an opening tag has just
// begun, counting the markers rather than matching their numbers: the
// same number nests inside itself in more than one service, so matching
// numbers would stop at the wrong place.
func (r *reader) skip() error {
	for depth := 1; depth > 0; {
		t, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case t.Opening:
			depth++
		case t.Closing:
			depth--
		}
	}
	return nil
}

// uint reads a tag's value as an unsigned integer. BACnet encodes one in
// as few octets as it needs, so anything up to four is a number and
// anything longer is not one this relay will read: a property identifier
// is twenty-two bits and a process identifier is thirty-two.
func (t tag) uint() (uint32, bool) {
	if len(t.Data) == 0 || len(t.Data) > 4 {
		return 0, false
	}
	var v uint32
	for _, c := range t.Data {
		v = v<<8 | uint32(c)
	}
	return v, true
}

// property reads a tag's value as a property identifier, refusing one
// that does not fit the twenty-two bits the standard gives it. Four
// octets of anything decode to a number; only some of those numbers are
// property identifiers, and reporting one of the others as a property
// would put a value in a log line and a policy decision that no device
// could have meant.
func (t tag) property() (PropertyID, bool) {
	v, ok := t.uint()
	if !ok || PropertyID(v) > maxProperty {
		return 0, false
	}
	return PropertyID(v), true
}
