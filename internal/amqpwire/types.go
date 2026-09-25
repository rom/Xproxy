package amqpwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// The AMQP 1.0 type system, read far enough to decide and no further.
//
// Every value is a constructor octet and then its data, and the
// constructor's high nibble says how wide the data is: 0x4 is nothing,
// 0x5 one octet, 0x6 two, 0x7 four, 0x8 eight, 0x9 sixteen, 0xA a
// one-octet length, 0xB a four-octet length, 0xC and 0xD a size and a
// count, 0xE and 0xF the same for an array. That regularity is what makes
// a bounded reader possible: a value this package has no use for can still
// be stepped over exactly, so an unknown field in the middle of a
// performative does not cost the fields after it.
//
// Three bounds are not optional, because every length and count in here
// comes off the network.
//
// **Depth**, because a list may hold a list. Without a bound, a few dozen
// octets describe a structure deep enough to end the process in the reader
// rather than in the policy.
//
// **A value budget**, because a compound's count is four octets and its
// contents need not be there. A reader that trusted the count would
// allocate for it; this one appends what it actually finds and stops when
// the budget is spent.
//
// **The size against what is left**, on every single container, because
// the alternative is reading one frame's octets as another's.

const (
	// maxValueDepth is how deeply values may nest.
	maxValueDepth = 16
	// maxValues is how many values one frame may decode into. A
	// performative is a list of about a dozen fields, a few of which are
	// maps; a thousand is beyond anything a broker or client sends and far
	// below anything that costs this process a moment.
	maxValues = 1024
)

var (
	errValueDepth  = errors.New("the value is nested deeper than this relay reads")
	errValueBudget = errors.New("the frame describes more values than this relay reads")
	errValueShort  = errors.New("a value runs past the end of the frame")
)

// ValueKind is what a decoded value turned out to be.
type ValueKind int

// The kinds. Anything this package does not need to tell apart -- the
// floats, the decimals, the timestamps, a uuid -- is Other: stepped over
// exactly, and reported as present.
const (
	KindNull ValueKind = iota
	KindBool
	KindUint
	KindInt
	KindString
	KindSymbol
	KindBinary
	KindList
	KindMap
	KindArray
	KindDescribed
	KindOther
)

// Value is one decoded value.
type Value struct {
	Kind ValueKind
	// Str holds a string or a symbol.
	Str string
	// U holds any unsigned integer, and a boolean as 0 or 1.
	U uint64
	// I holds a signed integer.
	I int64
	// Bin holds binary data, which is where a SASL response arrives.
	Bin []byte
	// Items holds the elements of a list, map or array. A map's keys and
	// values alternate, which is how the protocol puts them on the wire.
	Items []Value
	// Descriptor is the code of a described value, when the descriptor is
	// a number -- which is how the performatives and the standard types
	// are written. DescriptorName holds it when it is a symbol instead.
	Descriptor     uint64
	DescriptorName string
	// Described is what a described value describes.
	Described []Value
}

// Bool reads a value as a boolean, false when it is not one.
func (v Value) Bool() bool { return v.Kind == KindBool && v.U != 0 }

// Text reads a value as a string or symbol, empty when it is neither.
func (v Value) Text() string {
	if v.Kind == KindString || v.Kind == KindSymbol {
		return v.Str
	}
	return ""
}

// Uint reads a value as an unsigned integer, with a second return for
// whether it was one -- because 0 and absent are different answers about
// `max-frame-size`.
func (v Value) Uint() (uint64, bool) {
	if v.Kind == KindUint {
		return v.U, true
	}
	return 0, false
}

// Present says whether a field was there at all. A performative's trailing
// fields are often null, and null is not zero: an `idle-time-out` of null
// means the peer did not ask for one, and a relay that read it as zero
// would report a heartbeat interval nobody chose.
func (v Value) Present() bool { return v.Kind != KindNull }

// tr reads values out of one frame body.
type tr struct {
	b      []byte
	i      int
	budget int
	err    error
}

func newTypeReader(b []byte) *tr { return &tr{b: b, budget: maxValues} }

func (t *tr) fail(err error) {
	if t.err == nil {
		t.err = err
	}
}

func (t *tr) take(n int) []byte {
	if t.err != nil {
		return nil
	}
	if n < 0 || t.i+n > len(t.b) {
		t.fail(errValueShort)
		return nil
	}
	b := t.b[t.i : t.i+n]
	t.i += n
	return b
}

// value reads one value, constructor and all.
func (t *tr) value(depth int) Value {
	c := t.take(1)
	if t.err != nil {
		return Value{}
	}
	return t.valueWith(c[0], depth)
}

// valueWith reads the data of a value whose constructor is already known,
// which is also how an array's elements arrive: one constructor for all of
// them.
func (t *tr) valueWith(c byte, depth int) Value {
	if depth > maxValueDepth {
		t.fail(errValueDepth)
		return Value{}
	}
	if t.budget <= 0 {
		t.fail(errValueBudget)
		return Value{}
	}
	t.budget--

	switch c {
	case 0x00: // a described value: a descriptor and then the thing itself
		d := t.value(depth + 1)
		body := t.value(depth + 1)
		if t.err != nil {
			return Value{}
		}
		v := Value{Kind: KindDescribed, Described: []Value{body}}
		if d.Kind == KindUint {
			v.Descriptor = d.U
		} else {
			v.DescriptorName = d.Text()
		}
		return v
	case 0x40:
		return Value{Kind: KindNull}
	case 0x41:
		return Value{Kind: KindBool, U: 1}
	case 0x42:
		return Value{Kind: KindBool}
	case 0x43:
		return Value{Kind: KindUint}
	case 0x44:
		return Value{Kind: KindUint}
	case 0x56: // boolean in one octet
		b := t.take(1)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindBool, U: uint64(b[0] & 1)}
	case 0x50, 0x52, 0x53: // ubyte, smalluint, smallulong
		b := t.take(1)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindUint, U: uint64(b[0])}
	case 0x51, 0x54, 0x55: // byte, smallint, smalllong
		b := t.take(1)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindInt, I: signed8(b[0])}
	case 0x60: // ushort
		b := t.take(2)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindUint, U: uint64(binary.BigEndian.Uint16(b))}
	case 0x61: // short
		b := t.take(2)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindInt, I: signed16(binary.BigEndian.Uint16(b))}
	case 0x70: // uint
		b := t.take(4)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindUint, U: uint64(binary.BigEndian.Uint32(b))}
	case 0x71: // int
		b := t.take(4)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindInt, I: signed32(binary.BigEndian.Uint32(b))}
	case 0x80: // ulong
		b := t.take(8)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindUint, U: binary.BigEndian.Uint64(b)}
	case 0x81, 0x83: // long, timestamp
		b := t.take(8)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindInt, I: signed64(binary.BigEndian.Uint64(b))}
	case 0xa0, 0xb0: // binary
		b := t.variable(c)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindBinary, Bin: b}
	case 0xa1, 0xb1: // utf-8 string
		b := t.variable(c)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindString, Str: string(b)}
	case 0xa3, 0xb3: // symbol, which is ascii by definition
		b := t.variable(c)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindSymbol, Str: string(b)}
	case 0x45: // an empty list
		return Value{Kind: KindList}
	case 0xc0, 0xd0: // list
		items := t.compound(c, depth)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindList, Items: items}
	case 0xc1, 0xd1: // map
		items := t.compound(c, depth)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindMap, Items: items}
	case 0xe0, 0xf0: // array
		items := t.array(c, depth)
		if t.err != nil {
			return Value{}
		}
		return Value{Kind: KindArray, Items: items}
	}

	// Everything else is stepped over by the width its constructor's high
	// nibble declares. This is where the floats, the decimals and the
	// uuids go, and where a type added to the protocol after this was
	// written will go: skipped exactly, reported as present, and not
	// mistaken for a field that is missing.
	n, ok := fixedWidth(c)
	if !ok {
		return Value{Kind: KindOther, U: uint64(c)}
	}
	t.take(n)
	if t.err != nil {
		return Value{}
	}
	return Value{Kind: KindOther, U: uint64(c)}
}

// The signed forms. A negative number arrives as two's complement, so
// reading one is a reinterpretation of the same octets rather than a
// conversion that could overflow: the value is already in range for the
// width it came in.
func signed8(v uint8) int64   { return int64(int8(v)) }  //nolint:gosec // two's complement, same width
func signed16(v uint16) int64 { return int64(int16(v)) } //nolint:gosec // two's complement, same width
func signed32(v uint32) int64 { return int64(int32(v)) } //nolint:gosec // two's complement, same width
func signed64(v uint64) int64 { return int64(v) }        //nolint:gosec // two's complement, same width

// fixedWidth is the data width a constructor's category implies.
func fixedWidth(c byte) (int, bool) {
	switch c >> 4 {
	case 0x4:
		return 0, true
	case 0x5:
		return 1, true
	case 0x6:
		return 2, true
	case 0x7:
		return 4, true
	case 0x8:
		return 8, true
	case 0x9:
		return 16, true
	}
	return 0, false
}

// variable reads a value whose length is one or four octets.
func (t *tr) variable(c byte) []byte {
	var n int
	if c>>4 == 0xa {
		b := t.take(1)
		if t.err != nil {
			return nil
		}
		n = int(b[0])
	} else {
		b := t.take(4)
		if t.err != nil {
			return nil
		}
		v := binary.BigEndian.Uint32(b)
		if v > math.MaxInt32 {
			t.fail(errValueShort)
			return nil
		}
		n = int(v)
	}
	return t.take(n)
}

// sizeAndCount reads a compound's size and count, and returns the body the
// size names.
//
// The size is checked against what is left before anything is read out of
// it, and the count is used as a stopping condition rather than as an
// allocation: a count of four billion in a twelve-octet frame is a thing
// senders send.
func (t *tr) sizeAndCount(c byte) (body []byte, count int) {
	wide := c>>4 == 0xd || c>>4 == 0xf
	var size, n uint32
	if wide {
		b := t.take(8)
		if t.err != nil {
			return nil, 0
		}
		size = binary.BigEndian.Uint32(b[0:4])
		n = binary.BigEndian.Uint32(b[4:8])
		if size < 4 {
			t.fail(errValueShort)
			return nil, 0
		}
		size -= 4 // the count is inside the size
	} else {
		b := t.take(2)
		if t.err != nil {
			return nil, 0
		}
		size = uint32(b[0])
		n = uint32(b[1])
		if size < 1 {
			t.fail(errValueShort)
			return nil, 0
		}
		size--
	}
	if size > math.MaxInt32 {
		t.fail(errValueShort)
		return nil, 0
	}
	body = t.take(int(size))
	if t.err != nil {
		return nil, 0
	}
	if n > maxValues {
		n = maxValues
	}
	return body, int(n)
}

// compound reads a list or a map: count values, each with its own
// constructor.
func (t *tr) compound(c byte, depth int) []Value {
	body, count := t.sizeAndCount(c)
	if t.err != nil {
		return nil
	}
	inner := &tr{b: body, budget: t.budget}
	out := make([]Value, 0, min(count, 32))
	for i := 0; i < count && inner.i < len(body); i++ {
		out = append(out, inner.value(depth+1))
		if inner.err != nil {
			t.fail(inner.err)
			return nil
		}
	}
	t.budget = inner.budget
	return out
}

// array reads an array: one constructor, then count values of it.
func (t *tr) array(c byte, depth int) []Value {
	body, count := t.sizeAndCount(c)
	if t.err != nil {
		return nil
	}
	if len(body) == 0 {
		return nil
	}
	inner := &tr{b: body[1:], budget: t.budget}
	ctor := body[0]
	out := make([]Value, 0, min(count, 32))
	for i := 0; i < count; i++ {
		v := inner.valueWith(ctor, depth+1)
		if inner.err != nil {
			t.fail(inner.err)
			return nil
		}
		out = append(out, v)
		// A zero-width constructor -- the array of nulls or booleans --
		// consumes nothing, so the loop has to be bounded by the count
		// rather than by the body running out.
		if inner.i >= len(inner.b) && i+1 < count {
			if w, ok := fixedWidth(ctor); !ok || w != 0 {
				break
			}
		}
	}
	t.budget = inner.budget
	return out
}

// field reads one field of a performative's field list by position,
// answering null for a field the sender left off the end -- which is how
// this protocol says "not set" for every trailing field.
func field(list []Value, i int) Value {
	if i < 0 || i >= len(list) {
		return Value{Kind: KindNull}
	}
	return list[i]
}

// describe renders a descriptor for a message, for the one case where a
// caller has to say what it could not read.
func describe(v Value) string {
	if v.DescriptorName != "" {
		return v.DescriptorName
	}
	return fmt.Sprintf("%#x", v.Descriptor)
}
