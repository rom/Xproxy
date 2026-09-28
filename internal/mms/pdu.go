package mms

import "fmt"

// Reading an MMS PDU far enough to decide about it.
//
// Every confirmed request carries an invoke identifier and one service, and the
// services a policy is written about carry object names. This file reads the outer
// PDU and the bodies of the services a substation uses; a service whose body is not
// read is still named, because naming it is what lets a listener refuse it.

// MaxInvokeID bounds an invoke identifier. ISO 9506 types it Unsigned32, so a larger
// one is not a request any device sends -- and refusing it rather than keeping the low
// bits matters, because the low bits of an identifier name a *different* request and
// this relay matches answers to requests by it.
const MaxInvokeID = 0xFFFFFFFF

// MaxNames bounds the object names in one request. A Read of a whole logical device
// through a named variable list is one name; a Read that lists them is as many as
// the client chose to send, which is why there is a bound and why the listener has
// an operations bound of its own on top of it.
const MaxNames = 512

// Message is one MMS PDU, read as far as the policy needs.
type Message struct {
	PDU PDU
	// InvokeID is the request's identifier, which the response echoes. Zero with
	// HasInvokeID false for a PDU that carries none.
	InvokeID    uint64
	HasInvokeID bool
	// Service is the confirmed service, for a request or a response this relay
	// matched to its request.
	Service Service
	// HasService says a service was read: an initiate or a conclude carries none.
	HasService bool
	// Names are the object names the request addressed, in the order they arrived.
	Names []Name
	// NamesTruncated says there were more than MaxNames and the rest were not
	// read. A policy that allowed the request on the strength of the names it
	// could see would be allowing the ones it could not, so the caller refuses
	// rather than deciding.
	NamesTruncated bool
	// Domain is the domain a service that names one addressed: the scope of a
	// GetNameList, the domain of a download or a delete. It is separate from
	// Names because those services address a logical device rather than a data
	// object.
	Domain string
	// ListName is the named variable list a Read or Write went through, where it
	// did. A Read through a list names no data objects at all, which is a fact a
	// policy has to be able to see: the list decides what is read and the client
	// defined the list earlier.
	ListName string
	// FileName is the path a file service named, joined with slashes.
	FileName string
	// Values is how many data values a Write carried, which has to match the names
	// or the request is malformed.
	Values int
	// ErrorClass and ErrorCode are a confirmed-error's class and code.
	ErrorClass, ErrorCode int64
	HasError              bool
}

// ParsePDU reads one MMS PDU.
func ParsePDU(b []byte) (*Message, error) {
	top, err := NewBER(b).Next()
	if err != nil {
		return nil, err
	}
	if top.Class != ClassContext {
		return nil, fmt.Errorf("%w: an MMS PDU is a context tag, this is class %#02x",
			ErrEncoding, top.Class)
	}
	m := &Message{PDU: PDU(top.Tag)}
	if !top.Cons {
		// A primitive outer tag: only the conclude PDUs are encoded that way, and
		// only because their bodies are empty.
		return m, nil
	}
	body, err := NewBER(b).Sub(top)
	if err != nil {
		return nil, err
	}
	switch m.PDU {
	case ConfirmedRequest:
		return m, m.readConfirmedRequest(body)
	case ConfirmedResponse:
		return m, m.readInvokeOnly(body)
	case ConfirmedError:
		return m, m.readError(body)
	case Reject, CancelRequest, CancelResponse, CancelError:
		return m, m.readInvokeOnly(body)
	case Unconfirmed, InitiateRequest, InitiateResponse, InitiateError,
		ConcludeRequest, ConcludeResponse, ConcludeError:
		// Nothing in these is addressed at an object: an unconfirmed PDU is a
		// report the server sends, and the initiate PDUs are the negotiation.
		return m, nil
	}
	return nil, fmt.Errorf("%w: MMS PDU %d", ErrEncoding, top.Tag)
}

// readConfirmedRequest reads the invoke identifier and then the one service.
func (m *Message) readConfirmedRequest(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e.Is(ClassUniversal, TagInteger) && !m.HasInvokeID {
			v, err := invokeID(e)
			if err != nil {
				return err
			}
			m.InvokeID, m.HasInvokeID = v, true
			continue
		}
		if e.Class != ClassContext {
			continue
		}
		// The service is a context tag, and its number is the service. The
		// modifier list, which is also a context tag, is not a service -- but it
		// is [0] and so is `status`, and the two are told apart by position: the
		// modifiers precede the service. Nothing in IEC 61850 sends modifiers, so
		// the first context tag after the invoke identifier is the service.
		if e.Tag > 0xFF {
			// A context tag past an octet is not a service any edition of ISO 9506
			// defines, and Service is an octet: narrowing it would name a
			// different service in the log and the refusal.
			return fmt.Errorf("%w: a confirmed service tagged %d", ErrEncoding, e.Tag)
		}
		m.Service, m.HasService = Service(e.Tag), true
		return m.readBody(r, e)
	}
	return nil
}

// readInvokeOnly takes the invoke identifier and leaves the rest: a response is
// matched to its request by that identifier, and the request is what carried the
// names.
func (m *Message) readInvokeOnly(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e.Is(ClassUniversal, TagInteger) {
			v, err := invokeID(e)
			if err != nil {
				return err
			}
			m.InvokeID, m.HasInvokeID = v, true
			return nil
		}
	}
	return nil
}

func (m *Message) readError(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		switch {
		case e.Is(ClassUniversal, TagInteger) && !m.HasInvokeID:
			v, err := invokeID(e)
			if err != nil {
				return err
			}
			m.InvokeID, m.HasInvokeID = v, true
		case e.Context(0) && e.Cons:
			// serviceError: an errorClass choice and an optional code.
			inner, err := r.Sub(e)
			if err != nil {
				return err
			}
			for !inner.Empty() {
				f, err := inner.Next()
				if err != nil {
					return err
				}
				switch {
				case f.Context(0) && f.Cons:
					cls, err := inner.Sub(f)
					if err != nil {
						return err
					}
					if !cls.Empty() {
						c, err := cls.Next()
						if err != nil {
							return err
						}
						m.ErrorClass = int64(c.Tag)
						m.HasError = true
						if v, err := Int(c); err == nil {
							m.ErrorCode = v
						}
					}
				case f.Is(ClassUniversal, TagInteger):
					if v, err := Int(f); err == nil {
						m.ErrorCode = v
					}
				}
			}
		}
	}
	return nil
}

// readBody reads the services whose contents a policy is written about.
//
// A service not in this switch is named and its body left alone. That is deliberate
// and it is safe in one direction only: a listener that allows such a service allows
// everything it can carry, which is why the default action and the service list
// matter more here than on a protocol whose every body is read.
func (m *Message) readBody(parent *BER, e Element) error {
	if !e.Cons {
		return nil
	}
	body, err := parent.Sub(e)
	if err != nil {
		return err
	}
	switch m.Service {
	case SvcRead:
		return m.readAccessSpec(body, false)
	case SvcWrite:
		return m.readAccessSpec(body, true)
	case SvcGetVariableAccessAttributes, SvcDefineNamedVariable, SvcDeleteVariableAccess,
		SvcGetNamedVariableListAttrs, SvcDeleteNamedVariableList, SvcRename,
		SvcGetNamedTypeAttributes, SvcDeleteNamedType:
		return m.readNames(body)
	case SvcDefineNamedVariableList:
		return m.readDefineList(body)
	case SvcGetNameList:
		return m.readNameList(body)
	case SvcInitiateDownloadSequence, SvcTerminateDownloadSequence, SvcDeleteDomain,
		SvcGetDomainAttributes, SvcInitiateUploadSequence, SvcRequestDomainDownload,
		SvcRequestDomainUpload, SvcLoadDomainContent, SvcStoreDomainContent:
		return m.readDomain(body)
	case SvcFileOpen, SvcFileDelete, SvcFileDirectory, SvcObtainFile, SvcFileRename:
		return m.readFile(body)
	}
	return nil
}

// readAccessSpec reads a Read or a Write: a variable access specification, which is
// either a list of variables or the name of a variable list, and for a Write the
// values that follow.
func (m *Message) readAccessSpec(r *BER, write bool) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		switch {
		case e.Context(0) && e.Cons && write:
			// A Write's [0] is either the access specification's listOfVariable
			// arm or its own listOfData, depending on where in the sequence it
			// appears. The values come after the specification, so a [0] seen
			// before any name is the specification and one seen after it is the
			// data.
			if len(m.Names) == 0 && m.ListName == "" {
				if err := m.readVariableList(r, e); err != nil {
					return err
				}
				continue
			}
			m.Values = countChildren(r, e)
		case e.Context(0) && e.Cons:
			if err := m.readVariableList(r, e); err != nil {
				return err
			}
		case e.Context(1) && e.Cons:
			if err := m.readSpecChoice(r, e); err != nil {
				return err
			}
		}
	}
	return nil
}

// readSpecChoice reads the explicitly tagged VariableAccessSpecification of a Read,
// whose arms are the variable list and the variable list *name*.
func (m *Message) readSpecChoice(parent *BER, e Element) error {
	inner, err := parent.Sub(e)
	if err != nil {
		return err
	}
	if inner.Empty() {
		return nil
	}
	first, err := inner.Next()
	if err != nil {
		return err
	}
	switch {
	case first.Context(0) && first.Cons:
		return m.readVariableList(inner, first)
	case first.Context(1) && first.Cons, first.Context(2), first.Context(0) && !first.Cons:
		// variableListName: an ObjectName naming the list a Read goes through.
		n, err := readObjectName(inner, first)
		if err != nil {
			return err
		}
		m.ListName = n.Key()
		return nil
	}
	return nil
}

// readVariableList reads listOfVariable: a sequence of variable specifications, each
// of which names an object.
func (m *Message) readVariableList(parent *BER, e Element) error {
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
		if len(m.Names) >= MaxNames {
			m.NamesTruncated = true
			return nil
		}
		fields, err := list.Sub(item)
		if err != nil {
			return err
		}
		for !fields.Empty() {
			f, err := fields.Next()
			if err != nil {
				return err
			}
			// variableSpecification's `name` arm is [0], holding an ObjectName.
			if !f.Context(0) || !f.Cons {
				continue
			}
			spec, err := fields.Sub(f)
			if err != nil {
				return err
			}
			if spec.Empty() {
				continue
			}
			arm, err := spec.Next()
			if err != nil {
				return err
			}
			n, err := readObjectName(spec, arm)
			if err != nil {
				return err
			}
			m.Names = append(m.Names, n)
		}
	}
	return nil
}

// readNames reads a service whose whole body is one object name.
func (m *Message) readNames(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e.Class != ClassContext {
			continue
		}
		n, err := readObjectName(r, e)
		if err != nil {
			return err
		}
		if n.Item != "" || n.Domain != "" {
			m.Names = append(m.Names, n)
			return nil
		}
	}
	return nil
}

// readDefineList reads DefineNamedVariableList: the list's own name, then the
// variables going into it. Both matter: the name is what a later Read will address,
// and the members are what that Read will actually reach.
func (m *Message) readDefineList(r *BER) error {
	first := true
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e.Class != ClassContext {
			continue
		}
		if first {
			n, err := readObjectName(r, e)
			if err != nil {
				return err
			}
			m.ListName = n.Key()
			first = false
			continue
		}
		if e.Cons {
			if err := m.readVariableList(r, e); err != nil {
				return err
			}
		}
	}
	return nil
}

// readNameList reads GetNameList's object scope, which is the domain a client is
// enumerating. A GetNameList with a vmd-specific scope is asking the device for
// every logical device it has, which is the request a stranger sends first.
func (m *Message) readNameList(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if !e.Context(1) {
			continue
		}
		if !e.Cons {
			return nil
		}
		scope, err := r.Sub(e)
		if err != nil {
			return err
		}
		for !scope.Empty() {
			f, err := scope.Next()
			if err != nil {
				return err
			}
			if f.Context(1) {
				// domainSpecific.
				m.Domain = identifier(f)
				return nil
			}
		}
		return nil
	}
	return nil
}

// readDomain reads a service whose body names a domain: a download, an upload, a
// delete, an attribute read.
func (m *Message) readDomain(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		switch {
		case e.Is(ClassUniversal, TagVisibleStr), e.Is(ClassUniversal, TagGeneralStr),
			e.Is(ClassUniversal, TagUTF8):
			m.Domain = identifier(e)
			return nil
		case e.Context(0) && !e.Cons, e.Context(1) && !e.Cons:
			m.Domain = identifier(e)
			return nil
		}
	}
	return nil
}

// readFile reads a file service's name, which is a sequence of path components. They
// are joined with slashes because that is the form a policy pattern is written in
// and the form an operator reads.
//
// Only string-typed elements are taken as components. A file service's body also
// carries integers -- a position, a length -- and a reader that took whatever element
// came next would turn the octets of an INTEGER into a path, which is a path no rule
// was written about and one the caller would then decide about as though it were real.
func (m *Message) readFile(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if !e.Cons {
			if s := stringComponent(e); s != "" && m.FileName == "" {
				m.FileName = s
			}
			continue
		}
		parts, err := r.Sub(e)
		if err != nil {
			return err
		}
		var joined string
		for n := 0; !parts.Empty(); n++ {
			if n >= MaxElements {
				return fmt.Errorf("%w: a file name of more than %d components",
					ErrSize, MaxElements)
			}
			p, err := parts.Next()
			if err != nil {
				return err
			}
			s := stringComponent(p)
			if s == "" {
				continue
			}
			if joined != "" {
				joined += "/"
			}
			joined += s
			if len(joined) > MaxIdentifier {
				return fmt.Errorf("%w: a file name longer than %d octets",
					ErrSize, MaxIdentifier)
			}
		}
		if joined != "" {
			m.FileName = joined
			return nil
		}
	}
	return nil
}

// readObjectName reads an ObjectName: the choice of vmd-specific, domain-specific
// and aa-specific.
func readObjectName(parent *BER, e Element) (Name, error) {
	if !e.Context(1) {
		// vmd-specific [0] and aa-specific [2] are both an Identifier, encoded
		// implicitly, so the octets are the name.
		kind := NameVMD
		if e.Tag == 2 {
			kind = NameAA
		}
		return Name{Kind: kind, Item: identifier(e)}, nil
	}
	if !e.Cons {
		return Name{}, fmt.Errorf("%w: a domain-specific name with no sequence", ErrEncoding)
	}
	// Inside [1] is the SEQUENCE of the two identifiers -- except on the stacks
	// that tag the sequence implicitly and put the identifiers directly under [1].
	// Both are read: refusing one of them would refuse half the estate. The peek is
	// on a reader of its own so that failing to find the wrapper costs nothing.
	fields, err := parent.Sub(e)
	if err != nil {
		return Name{}, err
	}
	if peek, err := NewBER(e.Data).Next(); err == nil &&
		peek.Is(ClassUniversal, TagSequence) && peek.Cons {
		if fields, err = fields.Sub(peek); err != nil {
			return Name{}, err
		}
	}
	n := Name{Kind: NameDomain}
	for i := 0; !fields.Empty(); i++ {
		f, err := fields.Next()
		if err != nil {
			return Name{}, err
		}
		switch i {
		case 0:
			n.Domain = identifier(f)
		case 1:
			item := identifier(f)
			parsed := ParseItem(item)
			parsed.Kind, parsed.Domain = NameDomain, n.Domain
			return parsed, nil
		}
	}
	return n, nil
}

// identifier reads an MMS Identifier: a visible string, bounded.
//
// An identifier longer than the bound comes back empty rather than truncated. A
// truncated name would be a *different* name, and a policy matching a different name
// is worse than one that refuses to match at all: the caller sees an empty name and
// refuses it.
func identifier(e Element) string {
	if len(e.Data) == 0 || len(e.Data) > MaxIdentifier {
		return ""
	}
	return string(e.Data)
}

// invokeID reads an invoke identifier, bounded to the Unsigned32 the standard types
// it as.
func invokeID(e Element) (uint64, error) {
	v, err := Uint(e)
	if err != nil {
		return 0, err
	}
	if v > MaxInvokeID {
		return 0, fmt.Errorf("%w: invoke identifier %d, past the Unsigned32 the standard defines",
			ErrSize, v)
	}
	return v, nil
}

// stringComponent is an identifier, but only where the element is one of the string
// types. See the note on readFile.
func stringComponent(e Element) string {
	switch e.Tag {
	case TagVisibleStr, TagGeneralStr, TagUTF8, TagOctetStr:
		return identifier(e)
	}
	return ""
}

// countChildren counts the elements inside a constructed element without keeping
// them, which is how a Write's values are counted without reading process data.
func countChildren(parent *BER, e Element) int {
	sub, err := parent.Sub(e)
	if err != nil {
		return 0
	}
	n := 0
	for !sub.Empty() && n < MaxElements {
		if _, err := sub.Next(); err != nil {
			return n
		}
		n++
	}
	return n
}
