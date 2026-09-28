package mms

import (
	"fmt"
	"strings"
)

// ISO 8823 presentation, which is where the abstract syntax is named.
//
// This layer decides what the octets above it *are*. A connection presentation PDU
// carries a context definition list: a set of (identifier, abstract syntax) pairs
// the two ends agree on, and every data PDU after it names one of those identifiers
// rather than the syntax. So a relay that wants to know an MMS payload from an ACSE
// one has to read the list at association time and remember it — which is also how
// it knows that a payload arrived on a context the two ends never defined.
//
// That last case is worth naming rather than tolerating. A data PDU on an undefined
// context is either a stack this relay has not seen or a peer addressing a syntax
// the association did not agree to; neither is traffic a service rule can decide
// about, and forwarding it as though it were MMS would be forwarding something with
// no policy applied.

// The object identifiers this relay recognises.
//
// MMS has two: the abstract syntax of the protocol itself, and the application
// context IEC 61850-8-1 names in the association request.
var (
	// OIDACSE is the ACSE abstract syntax, 2.2.1.0.1.
	OIDACSE = OID{2, 2, 1, 0, 1}
	// OIDMMSAbstract is the MMS abstract syntax, 1.0.9506.2.1.
	OIDMMSAbstract = OID{1, 0, 9506, 2, 1}
	// OIDMMSTransfer is the MMS transfer syntax, 1.0.9506.2.3, which is what the
	// context definition list names as the transfer syntax for MMS.
	OIDMMSTransfer = OID{1, 0, 9506, 2, 3}
	// OIDBER is the basic encoding rules, 2.1.1, named as the transfer syntax of
	// every context here.
	OIDBER = OID{2, 1, 1}
)

// OID is an object identifier, as a slice of arcs.
type OID []uint64

// String renders it in dotted form.
func (o OID) String() string {
	if len(o) == 0 {
		return ""
	}
	var b strings.Builder
	for i, arc := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		fmt.Fprintf(&b, "%d", arc)
	}
	return b.String()
}

// Equal compares two identifiers.
func (o OID) Equal(p OID) bool {
	if len(o) != len(p) {
		return false
	}
	for i := range o {
		if o[i] != p[i] {
			return false
		}
	}
	return true
}

// ReadOID decodes an OBJECT IDENTIFIER.
//
// The first octet packs the first two arcs, and every arc after it is base-128 with
// a continuation bit. An arc is refused if its encoding does not terminate inside
// the element or if it needs more than 63 bits, because an identifier this program
// cannot hold is one it must not truncate into a different identifier.
func ReadOID(e Element) (OID, error) {
	b := e.Data
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: an empty object identifier", ErrEncoding)
	}
	out := make(OID, 0, 8)
	switch {
	case b[0] < 40:
		out = append(out, 0, uint64(b[0]))
	case b[0] < 80:
		out = append(out, 1, uint64(b[0])-40)
	default:
		out = append(out, 2, uint64(b[0])-80)
	}
	var v uint64
	var started bool
	for _, c := range b[1:] {
		if len(out) >= MaxOIDArcs {
			return nil, fmt.Errorf("%w: an object identifier of more than %d arcs",
				ErrSize, MaxOIDArcs)
		}
		if v>>57 != 0 {
			return nil, fmt.Errorf("%w: an object identifier arc wider than 64 bits", ErrSize)
		}
		v = v<<7 | uint64(c&0x7F)
		started = true
		if c&0x80 == 0 {
			out = append(out, v)
			v, started = 0, false
		}
	}
	if started {
		return nil, fmt.Errorf("%w: an object identifier arc that never ends", ErrEncoding)
	}
	return out, nil
}

// The presentation PDU tags (ISO 8823).
const (
	// tagCPType is the connect presentation PDU, a SET.
	tagCPType = TagSet
	// tagUserData is fully-encoded-data, [APPLICATION 1], which is both the
	// user-data of a CP and the whole of an ordinary data PDU.
	tagUserData uint32 = 1
)

// The context tags inside a CP's normal-mode-parameters.
const (
	cpContextList uint32 = 4
	cpUserData    uint32 = 6
	cpNormalMode  uint32 = 2
)

// Contexts is the presentation context definition list of an association: which
// identifier names which abstract syntax.
//
// It is a map rather than a slice because the point of it is the lookup a data PDU
// does, and it is bounded because the list arrives from a peer.
type Contexts map[uint64]OID

// MaxContexts bounds the list. IEC 61850 defines two: ACSE and MMS.
const MaxContexts = 16

// PDV is one presentation data value: which context it arrived on and the octets.
type PDV struct {
	Context uint64
	// Syntax is the abstract syntax the context names, or nil where the
	// association's list did not define this identifier.
	Syntax OID
	// Data is the encoded value, which for MMS is the MMS PDU and for ACSE the
	// APDU.
	Data []byte
}

// IsMMS says the value arrived on a context the association bound to MMS.
func (p PDV) IsMMS() bool {
	return p.Syntax.Equal(OIDMMSAbstract) || p.Syntax.Equal(OIDMMSTransfer)
}

// IsACSE says it arrived on the ACSE context.
func (p PDV) IsACSE() bool { return p.Syntax.Equal(OIDACSE) }

// ParseCP reads a connect (or accept) presentation PDU and returns the context
// definition list and the user data inside it.
//
// The mode selector and the selectors themselves are skipped: they are agreement
// between the two stacks. The list is not, because every data PDU after this one
// depends on it.
func ParseCP(b []byte) (Contexts, []byte, error) {
	top, err := NewBER(b).Next()
	if err != nil {
		return nil, nil, err
	}
	if !top.Is(ClassUniversal, tagCPType) || !top.Cons {
		return nil, nil, fmt.Errorf("%w: a presentation connect PDU is a SET, this is class %#02x tag %d",
			ErrEncoding, top.Class, top.Tag)
	}
	set, err := NewBER(b).Sub(top)
	if err != nil {
		return nil, nil, err
	}
	for !set.Empty() {
		e, err := set.Next()
		if err != nil {
			return nil, nil, err
		}
		if !e.Context(cpNormalMode) || !e.Cons {
			continue
		}
		params, err := set.Sub(e)
		if err != nil {
			return nil, nil, err
		}
		return normalMode(params)
	}
	// No normal-mode parameters. X.226 allows an X.410-1984 mode with none, which
	// nothing in a substation speaks; a relay that guessed at the payload's syntax
	// would be guessing at whether it is applying a policy.
	return nil, nil, fmt.Errorf("%w: a presentation connect with no normal-mode parameters",
		ErrOpaque)
}

func normalMode(r *BER) (Contexts, []byte, error) {
	ctx := Contexts{}
	var user []byte
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return nil, nil, err
		}
		switch {
		case e.Context(cpContextList) && e.Cons:
			if err := readContextList(r, e, ctx); err != nil {
				return nil, nil, err
			}
		case e.Class == ClassApplication && e.Tag == tagUserData && e.Cons:
			user = e.Data
		}
	}
	return ctx, user, nil
}

// readContextList reads the (identifier, abstract syntax) pairs.
func readContextList(parent *BER, e Element, into Contexts) error {
	list, err := parent.Sub(e)
	if err != nil {
		return err
	}
	for !list.Empty() {
		item, err := list.Next()
		if err != nil {
			return err
		}
		if !item.Cons {
			continue
		}
		if len(into) >= MaxContexts {
			return fmt.Errorf("%w: more than %d presentation contexts", ErrSize, MaxContexts)
		}
		fields, err := list.Sub(item)
		if err != nil {
			return err
		}
		var (
			id     uint64
			syntax OID
			haveID bool
		)
		for !fields.Empty() {
			f, err := fields.Next()
			if err != nil {
				return err
			}
			switch {
			case f.Is(ClassUniversal, TagInteger) && !haveID:
				v, err := Uint(f)
				if err != nil {
					return err
				}
				id, haveID = v, true
			case f.Is(ClassUniversal, TagOID) && syntax == nil:
				// The first identifier is the abstract syntax; the transfer
				// syntax list that may follow it is always BER here.
				syntax, err = ReadOID(f)
				if err != nil {
					return err
				}
			}
		}
		if haveID && syntax != nil {
			into[id] = syntax
		}
	}
	return nil
}

// MaxPDVs bounds the values in one data PDU. MMS sends one.
const MaxPDVs = 8

// ParsePDVs reads a presentation data PDU: fully-encoded-data, which is a sequence
// of presentation data values, each naming the context it belongs to.
//
// ctx may be nil, in which case every value comes back with no syntax — which is
// what happens on an association this relay did not see the start of, and is a fact
// the caller decides about rather than a parse error.
func ParsePDVs(b []byte, ctx Contexts) ([]PDV, error) {
	top, err := NewBER(b).Next()
	if err != nil {
		return nil, err
	}
	if top.Class != ClassApplication || top.Tag != tagUserData || !top.Cons {
		return nil, fmt.Errorf("%w: a presentation data PDU is [APPLICATION 1], this is class %#02x tag %d",
			ErrEncoding, top.Class, top.Tag)
	}
	seq, err := NewBER(b).Sub(top)
	if err != nil {
		return nil, err
	}
	var out []PDV
	for !seq.Empty() {
		item, err := seq.Next()
		if err != nil {
			return nil, err
		}
		if !item.Cons {
			continue
		}
		if len(out) >= MaxPDVs {
			return nil, fmt.Errorf("%w: more than %d data values in one PDU", ErrSize, MaxPDVs)
		}
		p, err := readPDV(seq, item, ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: a data PDU carrying no values", ErrShort)
	}
	return out, nil
}

func readPDV(parent *BER, item Element, ctx Contexts) (PDV, error) {
	fields, err := parent.Sub(item)
	if err != nil {
		return PDV{}, err
	}
	var p PDV
	for !fields.Empty() {
		f, err := fields.Next()
		if err != nil {
			return PDV{}, err
		}
		switch {
		case f.Is(ClassUniversal, TagInteger):
			v, err := Uint(f)
			if err != nil {
				return PDV{}, err
			}
			p.Context = v
		case f.Context(0) && f.Cons:
			// single-ASN1-type: the value is the encoded APDU itself.
			p.Data = f.Data
		case f.Context(1) && !f.Cons:
			// octet-aligned.
			p.Data = f.Data
		}
	}
	if p.Data == nil {
		return PDV{}, fmt.Errorf("%w: a data value with no contents", ErrShort)
	}
	if ctx != nil {
		p.Syntax = ctx[p.Context]
	}
	return p, nil
}
