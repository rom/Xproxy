package ldap

import (
	"bufio"
	"fmt"
	"io"
)

// Reading an LDAPMessage off a stream, and reading what it says.

// Reader reads length-delimited LDAPMessages from a stream.
//
// LDAP has no framing of its own: a message is a BER SEQUENCE and its own
// length field delimits it, exactly as in SNMP over TCP. The length is
// therefore chosen by whoever sent it, so this reader decides about the
// length *before* it reads the octets the length claims: reading them to
// find out what they asked for is the work a bound exists to avoid.
//
// There is no resynchronisation. A stream whose framing is wrong is a stream
// whose next octet is unknown, and guessing a message boundary nobody sent is
// how a check gets bypassed.
type Reader struct {
	r   *bufio.Reader
	max int
}

// NewReader wraps a stream, refusing any message longer than max octets.
func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 || max > MaxMessage {
		max = MaxMessage
	}
	size := max + 8
	if size > 1<<16 {
		// A buffer the size of the largest message a directory may send is
		// a megabyte per connection; the reader grows into it only as far
		// as a message actually goes.
		size = 1 << 16
	}
	return &Reader{r: bufio.NewReaderSize(r, size), max: max}
}

// Next reads one message whole, tag and length included, which is what a
// relay forwards when it forwards something unchanged.
func (rd *Reader) Next() ([]byte, error) {
	id, err := rd.r.ReadByte()
	if err != nil {
		return nil, err
	}
	// An LDAPMessage is a universal, constructed SEQUENCE: 0x30 and nothing
	// else. A client whose first octet is a letter is speaking HTTP at a
	// directory port, which is what a scanner does to everything it finds.
	if id != classUniversal|constructed|tagSequence {
		return nil, ErrFraming
	}
	first, err := rd.r.ReadByte()
	if err != nil {
		return nil, err
	}
	header := []byte{id, first}
	n := int(first)
	switch {
	case first == 0x80:
		// The indefinite length: legal BER, and it would make a message's
		// extent depend on finding an end-of-contents pair inside a value
		// this relay does not interpret.
		return nil, ErrFraming
	case first > 0x80:
		count := int(first & 0x7f)
		if count > 4 {
			return nil, ErrTooLong
		}
		octets := make([]byte, count)
		if _, err := io.ReadFull(rd.r, octets); err != nil {
			return nil, err
		}
		header = append(header, octets...)
		n = 0
		for _, c := range octets {
			n = n<<8 | int(c)
		}
		if n < 0 {
			return nil, ErrTooLong
		}
	}
	if len(header)+n > rd.max {
		return nil, ErrTooLong
	}
	out := make([]byte, len(header)+n)
	copy(out, header)
	if _, err := io.ReadFull(rd.r, out[len(header):]); err != nil {
		return nil, err
	}
	return out, nil
}

// MaxControls bounds the controls one message may carry. Each is an OID and
// an opaque value, and a client that attached a thousand would be making the
// relay the work.
const MaxControls = 32

// MaxAttributes bounds the attribute descriptions one request or entry may
// name.
const MaxAttributes = 1024

// Parse reads one LDAPMessage.
//
// Every operation is read to the depth a policy is written at and no
// further. Where a field is a credential its extent is read and its content
// is not, because a relay that held a directory password in a struct would
// be a relay that could log one.
func Parse(raw []byte) (*Message, error) {
	if len(raw) == 0 || len(raw) > MaxMessage {
		return nil, ErrTruncated
	}
	top, used, err := parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTruncated, err)
	}
	if used != len(raw) {
		// Octets after the message. On a stream that is a framing this
		// reader did not agree to, and forwarding it would be forwarding
		// two messages as one.
		return nil, fmt.Errorf("%w: %d octets after the message", ErrShape, len(raw)-used)
	}
	if top.class != classUniversal || top.tag != tagSequence || !top.cons {
		return nil, ErrFraming
	}
	if len(top.kids) < 2 {
		return nil, fmt.Errorf("%w: a message with %d fields", ErrShape, len(top.kids))
	}
	m := &Message{Raw: raw, pkt: top}
	if m.ID, err = top.kids[0].intValue(); err != nil {
		return nil, fmt.Errorf("%w: message id: %s", ErrShape, err)
	}
	body := top.kids[1]
	if body.class != classApplication {
		return nil, fmt.Errorf("%w: the operation is an application tag, not %#02x", ErrShape, body.class)
	}
	m.Op = Op(body.tag)
	if !m.Op.Known() {
		return nil, fmt.Errorf("%w: operation %d", ErrShape, body.tag)
	}
	if len(top.kids) > 2 {
		if m.Controls, err = readControls(top.kids[2]); err != nil {
			return nil, err
		}
	}
	if err := m.readOp(body); err != nil {
		return nil, err
	}
	return m, nil
}

// readOp fills in the operation's own fields.
func (m *Message) readOp(body *packet) error {
	switch m.Op {
	case OpBindRequest:
		return m.readBind(body)
	case OpSearchRequest:
		return m.readSearch(body)
	case OpSearchResultEntry:
		return m.readEntry(body)
	case OpModifyRequest:
		return m.readModify(body)
	case OpAddRequest, OpDelRequest, OpModifyDNRequest, OpCompareRequest:
		return m.readTarget(body)
	case OpAbandonRequest:
		n, err := body.intValue()
		if err != nil {
			return fmt.Errorf("%w: abandon: %s", ErrShape, err)
		}
		m.Abandon = n
		return nil
	case OpExtendedRequest, OpExtendedResponse:
		return m.readExtended(body)
	case OpUnbindRequest, OpSearchResultReference, OpIntermediateResponse:
		// Unbind carries nothing, a reference carries URIs the relay does
		// not follow, and an intermediate response belongs to whatever
		// extended operation asked for it.
		return nil
	default:
		// The remaining operations are all responses with the same three
		// leading fields.
		return m.readResult(body)
	}
}

// readBind reads a BindRequest, and decides which of the four things a
// simple bind can be this one is.
func (m *Message) readBind(body *packet) error {
	if len(body.kids) != 3 {
		return fmt.Errorf("%w: a bind with %d fields", ErrShape, len(body.kids))
	}
	b := &Bind{}
	var err error
	if b.Version, err = body.kids[0].intValue(); err != nil {
		return fmt.Errorf("%w: bind version: %s", ErrShape, err)
	}
	b.Name = string(body.kids[1].data)
	if b.DN, err = ParseDN(b.Name); err != nil {
		return fmt.Errorf("%w: bind name: %s", ErrShape, err)
	}
	auth := body.kids[2]
	if auth.class != classContext {
		return fmt.Errorf("%w: bind authentication is a context tag", ErrShape)
	}
	switch auth.tag {
	case 0: // simple
		b.PasswordLength = len(auth.data)
		switch {
		case b.Name == "" && b.PasswordLength == 0:
			b.Method = MethodAnonymous
		case b.PasswordLength == 0:
			// A name and no password. RFC 4513 calls this an unauthenticated
			// bind and says it is anonymous; the directory will very likely
			// answer success, and the application behind it will read that
			// success as "the password was right".
			b.Method = MethodUnauthenticated
		default:
			b.Method = MethodSimple
		}
	case 3: // sasl
		b.Method = MethodSASL
		if len(auth.kids) == 0 {
			return fmt.Errorf("%w: a SASL bind with no mechanism", ErrShape)
		}
		b.Mechanism = string(auth.kids[0].data)
		if len(auth.kids) > 1 {
			b.PasswordLength = len(auth.kids[1].data)
		}
	default:
		return fmt.Errorf("%w: bind authentication %#02x", ErrShape, auth.tag)
	}
	m.Bind = b
	return nil
}

// readSearch reads a SearchRequest: where it looks, how widely, how hard,
// and for what.
func (m *Message) readSearch(body *packet) error {
	if len(body.kids) != 8 {
		return fmt.Errorf("%w: a search with %d fields", ErrShape, len(body.kids))
	}
	s := &Search{}
	var err error
	s.Base = string(body.kids[0].data)
	if s.BaseDN, err = ParseDN(s.Base); err != nil {
		return fmt.Errorf("%w: search base: %s", ErrShape, err)
	}
	if s.Scope, err = body.kids[1].intValue(); err != nil {
		return fmt.Errorf("%w: search scope: %s", ErrShape, err)
	}
	if s.Scope < ScopeBase || s.Scope > ScopeSub {
		return fmt.Errorf("%w: search scope %d", ErrShape, s.Scope)
	}
	if s.DerefAliases, err = body.kids[2].intValue(); err != nil {
		return fmt.Errorf("%w: deref aliases: %s", ErrShape, err)
	}
	if s.SizeLimit, err = body.kids[3].intValue(); err != nil {
		return fmt.Errorf("%w: size limit: %s", ErrShape, err)
	}
	if s.TimeLimit, err = body.kids[4].intValue(); err != nil {
		return fmt.Errorf("%w: time limit: %s", ErrShape, err)
	}
	s.TypesOnly = len(body.kids[5].data) > 0 && body.kids[5].data[0] != 0
	if s.Filter, err = ReadFilter(body.kids[6]); err != nil {
		return err
	}
	if s.Attributes, err = readAttributes(body.kids[7]); err != nil {
		return err
	}
	m.Search = s
	return nil
}

// readEntry reads a SearchResultEntry down to its attribute names. The
// values are skipped deliberately: they are the estate's data, and reading
// them would make this a directory server with a second schema.
func (m *Message) readEntry(body *packet) error {
	if len(body.kids) != 2 {
		return fmt.Errorf("%w: an entry with %d fields", ErrShape, len(body.kids))
	}
	e := &ResultEntry{Name: string(body.kids[0].data)}
	for _, attr := range body.kids[1].kids {
		if len(e.Attributes) >= MaxAttributes {
			return fmt.Errorf("%w: more than %d attributes in an entry", ErrCount, MaxAttributes)
		}
		if len(attr.kids) == 0 {
			return fmt.Errorf("%w: an attribute with no description", ErrShape)
		}
		e.Attributes = append(e.Attributes, string(attr.kids[0].data))
	}
	m.Entry = e
	return nil
}

// readModify reads a ModifyRequest: which object, and which attributes are
// changed how. *What* they are changed to is not read.
func (m *Message) readModify(body *packet) error {
	if len(body.kids) != 2 {
		return fmt.Errorf("%w: a modify with %d fields", ErrShape, len(body.kids))
	}
	mod := &Modify{Object: string(body.kids[0].data)}
	var err error
	if mod.ObjectDN, err = ParseDN(mod.Object); err != nil {
		return fmt.Errorf("%w: modify object: %s", ErrShape, err)
	}
	for _, change := range body.kids[1].kids {
		if len(mod.Attributes) >= MaxAttributes {
			return fmt.Errorf("%w: more than %d changes in a modify", ErrCount, MaxAttributes)
		}
		if len(change.kids) != 2 {
			return fmt.Errorf("%w: a change with %d fields", ErrShape, len(change.kids))
		}
		op, err := change.kids[0].intValue()
		if err != nil {
			return fmt.Errorf("%w: change operation: %s", ErrShape, err)
		}
		if len(change.kids[1].kids) == 0 {
			return fmt.Errorf("%w: a change with no attribute", ErrShape)
		}
		mod.Operations = append(mod.Operations, op)
		mod.Attributes = append(mod.Attributes, string(change.kids[1].kids[0].data))
	}
	m.Modify = mod
	return nil
}

// readTarget reads the single distinguished name an add, delete, modifyDN or
// compare names.
func (m *Message) readTarget(body *packet) error {
	switch m.Op {
	case OpDelRequest:
		// A delete is the one operation whose whole body is the name, so
		// the name is a leaf rather than the first field of a sequence.
		m.Target = string(body.data)
	default:
		if len(body.kids) == 0 {
			return fmt.Errorf("%w: %s with no object", ErrShape, m.Op)
		}
		m.Target = string(body.kids[0].data)
	}
	dn, err := ParseDN(m.Target)
	if err != nil {
		return fmt.Errorf("%w: %s object: %s", ErrShape, m.Op, err)
	}
	m.TargetDN = dn
	return nil
}

// readExtended reads an extended operation's OID and the extent of its
// value.
func (m *Message) readExtended(body *packet) error {
	e := &Extended{}
	for _, kid := range body.kids {
		if kid.class != classContext {
			continue
		}
		switch {
		case kid.tag == 0 && m.Op == OpExtendedRequest:
			e.OID = string(kid.data)
		case kid.tag == 1 && m.Op == OpExtendedRequest:
			e.HasValue, e.ValueLength = true, len(kid.data)
		case kid.tag == 10:
			e.OID = string(kid.data)
		case kid.tag == 11:
			e.HasValue, e.ValueLength = true, len(kid.data)
		}
	}
	m.Extended = e
	if m.Op == OpExtendedResponse {
		// A response carries the result fields as well, which is how a
		// StartTLS refusal says why.
		return m.readResult(body)
	}
	if e.OID == "" {
		return fmt.Errorf("%w: an extended request with no operation name", ErrShape)
	}
	return nil
}

// readResult reads the three fields every LDAPResult begins with, and
// whether a referral followed them.
func (m *Message) readResult(body *packet) error {
	if len(body.kids) < 3 {
		return fmt.Errorf("%w: a result with %d fields", ErrShape, len(body.kids))
	}
	code, err := body.kids[0].intValue()
	if err != nil {
		return fmt.Errorf("%w: result code: %s", ErrShape, err)
	}
	r := &Result{Code: ResultCode(code),
		MatchedDN: string(body.kids[1].data), Message: string(body.kids[2].data)}
	for _, kid := range body.kids[3:] {
		if kid.class == classContext && kid.tag == 3 {
			r.Referral = true
		}
	}
	m.Result = r
	return nil
}

// readControls reads the control list attached to a message.
func readControls(p *packet) ([]Control, error) {
	if p.class != classContext || p.tag != 0 {
		return nil, fmt.Errorf("%w: the third field of a message is its controls", ErrShape)
	}
	out := make([]Control, 0, len(p.kids))
	for _, c := range p.kids {
		if len(out) >= MaxControls {
			return nil, fmt.Errorf("%w: more than %d controls", ErrCount, MaxControls)
		}
		if len(c.kids) == 0 {
			return nil, fmt.Errorf("%w: a control with no name", ErrShape)
		}
		ctrl := Control{OID: string(c.kids[0].data)}
		for _, kid := range c.kids[1:] {
			switch {
			case kid.class == classUniversal && kid.tag == tagBoolean:
				ctrl.Criticality = len(kid.data) > 0 && kid.data[0] != 0
			case kid.class == classUniversal && kid.tag == tagOctetStr:
				ctrl.ValueLength = len(kid.data)
			}
		}
		out = append(out, ctrl)
	}
	return out, nil
}

// readAttributes reads an attribute description list.
func readAttributes(p *packet) ([]string, error) {
	out := make([]string, 0, len(p.kids))
	for _, a := range p.kids {
		if len(out) >= MaxAttributes {
			return nil, fmt.Errorf("%w: more than %d attributes named", ErrCount, MaxAttributes)
		}
		out = append(out, string(a.data))
	}
	return out, nil
}
