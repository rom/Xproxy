package snmp

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// The BER subset SNMP uses, read and written by hand.
//
// encoding/asn1 is not usable here for two reasons. SNMP defines
// application-specific and context-specific tags of its own -- Counter32,
// Gauge32, TimeTicks, Counter64, IpAddress, the three exception values, and
// a tag per PDU type -- which a struct-tag driven decoder cannot express.
// And a relay has to know *where a message ended*: it forwards the octets
// it read, so it needs the exact extent of every element rather than a
// decoded Go value.
//
// So this is a reader over a byte slice with one rule: every element's
// length is read from the encoding, checked against what remains, and
// nothing is ever guessed. In particular the indefinite-length form is
// refused rather than scanned for its terminator. SNMP does not use it, and
// a relay that accepted it would be deciding where a message ends by
// searching for two zero octets -- a decision the agent behind it would
// make differently.

// Tag is a BER identifier octet.
type Tag byte

// The universal tags SNMP uses.
const (
	TagInteger   Tag = 0x02
	TagOctetStr  Tag = 0x04
	TagNull      Tag = 0x05
	TagOID       Tag = 0x06
	TagSequence  Tag = 0x30
	TagIPAddress Tag = 0x40 // application 0, primitive
	TagCounter32 Tag = 0x41
	TagGauge32   Tag = 0x42 // also Unsigned32
	TagTimeTicks Tag = 0x43
	TagOpaque    Tag = 0x44
	TagCounter64 Tag = 0x46
	// The three exception values a response may carry instead of a value,
	// context-specific and primitive. They are not errors: an agent
	// answering a walk says end-of-MIB-view with one of them.
	TagNoSuchObject   Tag = 0x80
	TagNoSuchInstance Tag = 0x81
	TagEndOfMibView   Tag = 0x82
)

// The PDU tags: context-specific, constructed. The numbering is the
// protocol's own and is worth reading as a list, because a policy about
// what a manager may *do* is a policy about these eight values.
const (
	TagGetRequest     Tag = 0xa0
	TagGetNextRequest Tag = 0xa1
	TagResponse       Tag = 0xa2
	TagSetRequest     Tag = 0xa3
	TagTrapV1         Tag = 0xa4
	TagGetBulkRequest Tag = 0xa5
	TagInformRequest  Tag = 0xa6
	TagTrapV2         Tag = 0xa7
	TagReport         Tag = 0xa8
)

// MaxOIDLength bounds the sub-identifiers of one object identifier.
//
// RFC 2578 allows 128. A relay reads the OID to decide about it, so the
// bound is here rather than at the agent: an identifier of a hundred
// thousand sub-identifiers is a way to spend a relay's time, not a way to
// name an object.
const MaxOIDLength = 128

// MaxVarBinds bounds the variable bindings of one PDU. A GETBULK response
// is the one that grows, and max_repetitions is what bounds that; this is
// the bound on what arrives.
const MaxVarBinds = 2048

// MaxNesting bounds how deep this reader will descend. SNMP's own
// structure is three deep (message, PDU, varbind list, varbind), so
// anything past this is a message shaped to make a parser recurse.
const MaxNesting = 16

// Errors this package returns. Each names a way a message is not one,
// because a relay that forwarded what it could not read would be
// forwarding what it could not decide about -- and the agent behind it
// will read those octets somehow.
var (
	// ErrTruncated is an element whose length runs past what arrived.
	ErrTruncated = errors.New("snmp: element runs past the end of the message")
	// ErrIndefinite is the indefinite-length form, which SNMP does not use
	// and which a relay must not scan for a terminator.
	ErrIndefinite = errors.New("snmp: indefinite length")
	// ErrLongLength is a length field longer than a 32-bit count, which no
	// datagram can carry.
	ErrLongLength = errors.New("snmp: length field too long")
	// ErrTag is an element that is not the tag expected there.
	ErrTag = errors.New("snmp: unexpected tag")
	// ErrIntegerRange is an INTEGER outside what its field can hold.
	ErrIntegerRange = errors.New("snmp: integer out of range")
	// ErrOID is an object identifier that is not one.
	ErrOID = errors.New("snmp: malformed object identifier")
	// ErrTrailing is an element followed by octets that belong to nothing.
	ErrTrailing = errors.New("snmp: trailing octets")
	// ErrNesting is a message nested deeper than this reader descends.
	ErrNesting = errors.New("snmp: nested too deep")
	// ErrCount is more of something than the bound allows.
	ErrCount = errors.New("snmp: too many elements")
)

// reader reads BER elements from a slice.
type reader struct {
	b     []byte
	depth int
}

// element is one BER element: its tag, its contents, and the whole thing.
type element struct {
	tag Tag
	// body is the contents octets, without the tag and length.
	body []byte
	// raw is the element including its tag and length, which is what a
	// relay forwards when it forwards something unchanged.
	raw []byte
}

// next reads one element.
func (r *reader) next() (element, error) {
	if len(r.b) < 2 {
		return element{}, ErrTruncated
	}
	tag := Tag(r.b[0])
	n := int(r.b[1])
	at := 2
	switch {
	case n == 0x80:
		return element{}, ErrIndefinite
	case n > 0x80:
		// The long form: the low bits count the length octets.
		count := n & 0x7f
		if count > 4 {
			return element{}, ErrLongLength
		}
		if len(r.b) < 2+count {
			return element{}, ErrTruncated
		}
		n = 0
		for i := 0; i < count; i++ {
			n = n<<8 | int(r.b[2+i])
		}
		at = 2 + count
	}
	if n < 0 || len(r.b) < at+n {
		return element{}, ErrTruncated
	}
	e := element{tag: tag, body: r.b[at : at+n], raw: r.b[:at+n]}
	r.b = r.b[at+n:]
	return e, nil
}

// expect reads one element and checks its tag.
func (r *reader) expect(want Tag) (element, error) {
	e, err := r.next()
	if err != nil {
		return element{}, err
	}
	if e.tag != want {
		return element{}, fmt.Errorf("%w: %#02x where %#02x was expected", ErrTag, byte(e.tag), byte(want))
	}
	return e, nil
}

// sub returns a reader over an element's contents, one level deeper.
func (r *reader) sub(e element) (*reader, error) {
	if r.depth+1 > MaxNesting {
		return nil, ErrNesting
	}
	return &reader{b: e.body, depth: r.depth + 1}, nil
}

// empty says whether anything is left.
func (r *reader) empty() bool { return len(r.b) == 0 }

// readInt reads an INTEGER as an int64. BER integers are signed
// two's complement, big endian, in the fewest octets that hold the value.
func readInt(e element) (int64, error) {
	if len(e.body) == 0 || len(e.body) > 8 {
		return 0, ErrIntegerRange
	}
	v := int64(int8(e.body[0]))
	for _, c := range e.body[1:] {
		v = v<<8 | int64(c)
	}
	return v, nil
}

// readUint reads one of the unsigned application types (Counter32,
// Gauge32, TimeTicks, Counter64).
//
// These are unsigned on the wire but encoded as BER integers, so an agent
// writing a value with the high bit set emits a leading zero octet. An
// implementation that read them as signed would report a Counter32 past
// two billion as negative, which is how a counter that has simply grown
// becomes a policy decision.
func readUint(e element) (uint64, error) {
	b := e.body
	if len(b) == 0 || len(b) > 9 {
		return 0, ErrIntegerRange
	}
	if len(b) == 9 {
		if b[0] != 0 {
			return 0, ErrIntegerRange
		}
		b = b[1:]
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// OID is an object identifier: the name of one thing in a MIB.
//
// It is the field an SNMP policy is mostly written about, because it says
// *what* is being read or written. Keeping it as sub-identifiers rather
// than as a string is what makes a subtree test a prefix comparison
// instead of a string operation with a dot in it -- and 1.3.6.1.2.1 must
// not be a prefix of 1.3.6.1.2.11.
type OID []uint32

// String writes an OID the way every MIB browser and every operator does.
func (o OID) String() string {
	if len(o) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// Compare orders two object identifiers the way the protocol does:
// subidentifier by subidentifier, and a prefix before what extends it.
//
// It is what a walk is: GETNEXT answers with the least name greater than the
// one asked about, so an agent whose ordering disagreed with its manager's
// would either loop or skip -- and a manager whose walk loops is a manager
// that never finishes.
func Compare(a, b OID) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// Under says whether this OID is at or below a subtree.
//
// The comparison is per sub-identifier, which is the point: 1.3.6.1.2.11 is
// not under 1.3.6.1.2.1, although the string "1.3.6.1.2.1" is a prefix of
// the string "1.3.6.1.2.11". A policy written with string prefixes would
// allow a subtree nobody named.
func (o OID) Under(prefix OID) bool {
	if len(o) < len(prefix) {
		return false
	}
	for i, v := range prefix {
		if o[i] != v {
			return false
		}
	}
	return true
}

// Equal says whether two OIDs name the same object.
func (o OID) Equal(p OID) bool {
	if len(o) != len(p) {
		return false
	}
	for i, v := range o {
		if p[i] != v {
			return false
		}
	}
	return true
}

// ParseOID reads an OID the way an operator writes it, with or without a
// leading dot.
func ParseOID(s string) (OID, error) {
	text := strings.TrimSpace(s)
	text = strings.TrimPrefix(text, ".")
	if text == "" {
		return nil, fmt.Errorf("%w: empty", ErrOID)
	}
	parts := strings.Split(text, ".")
	if len(parts) > MaxOIDLength {
		return nil, fmt.Errorf("%w: %d sub-identifiers is past the bound of %d", ErrOID, len(parts), MaxOIDLength)
	}
	out := make(OID, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrOID, s)
		}
		out = append(out, uint32(v))
	}
	return out, nil
}

// readOID decodes an OBJECT IDENTIFIER.
//
// Every sub-identifier is base-128 with a continuation bit, and the *first*
// one encodes two: the value is 40*arc + second, where arc is 0, 1 or 2.
// That packing is the one place in BER where the encoding is not simply a
// sequence of values, and it is easy to get wrong in a way that matters: the
// packed value is a sub-identifier like any other, so it can span several
// octets. 2.999 packs to 1079 and takes two. A reader that treated the
// first *octet* as the packed value would read 2.999 as 2.56.55 -- a
// different object, under a different subtree, which is a way past a policy
// written about subtrees.
func readOID(e element) (OID, error) {
	if len(e.body) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrOID)
	}
	vals, err := base128Values(e.body)
	if err != nil {
		return nil, err
	}
	// The packed first value splits into the arc and the second
	// sub-identifier. An arc of 2 has no upper bound on its second value,
	// which is why the packed one can be large.
	first := vals[0]
	out := make(OID, 0, len(vals)+1)
	switch {
	case first < 40:
		out = append(out, 0, first)
	case first < 80:
		out = append(out, 1, first-40)
	default:
		out = append(out, 2, first-80)
	}
	out = append(out, vals[1:]...)
	if len(out) > MaxOIDLength {
		return nil, fmt.Errorf("%w: past the bound of %d sub-identifiers", ErrOID, MaxOIDLength)
	}
	return out, nil
}

// base128Values decodes the base-128 sub-identifiers of an OID's contents.
func base128Values(b []byte) ([]uint32, error) {
	out := make([]uint32, 0, 8)
	var v uint64
	var started bool
	for _, c := range b {
		if !started && c == 0x80 {
			// A leading continuation octet with no bits in it is a
			// non-minimal encoding: two different encodings of the same
			// identifier, which is how two implementations come to
			// disagree about whether an OID is inside a subtree.
			return nil, fmt.Errorf("%w: non-minimal sub-identifier", ErrOID)
		}
		started = true
		v = v<<7 | uint64(c&0x7f)
		if v > math.MaxUint32 {
			return nil, fmt.Errorf("%w: sub-identifier past 32 bits", ErrOID)
		}
		if c&0x80 == 0 {
			out = append(out, uint32(v))
			v, started = 0, false
			if len(out) > MaxOIDLength+1 {
				return nil, fmt.Errorf("%w: past the bound of %d sub-identifiers", ErrOID, MaxOIDLength)
			}
		}
	}
	if started {
		// The last octet had its continuation bit set, so the identifier
		// is unfinished.
		return nil, fmt.Errorf("%w: truncated sub-identifier", ErrOID)
	}
	return out, nil
}
