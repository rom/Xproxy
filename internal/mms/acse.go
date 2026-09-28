package mms

import "fmt"

// ACSE (ISO 8650 / X.227), the first layer here with an identity in it.
//
// The association request names who is calling, in three ways that are worth telling
// apart:
//
// The **AP-title** is an object identifier, and on IEC 61850 it is what an SCL file
// configured: the closest this protocol comes to a name for the calling application.
// It is not a credential — nothing proves it — but it is the field a policy is
// written about, exactly as a Modbus unit identifier is.
//
// The **AE-qualifier** is an integer distinguishing application entities inside one
// application, which in a substation usually separates a control-centre client from
// an engineering one.
//
// And the **authentication value** is, where an estate configured one at all, a
// **password in the clear**. IEC 61850-8-1 specifies the charstring form and IEC
// 62351-4 exists to replace it. A relay in front of this protocol can see it
// crossing, and the useful thing to do about it is to refuse the association rather
// than to forward a credential that anybody on the path has now read. That is why
// this parser reads the *presence* and the length of the value and never keeps the
// value itself: a relay that logged the password would be the second place it leaks.

// The ACSE APDU tags, which are [APPLICATION n] (X.227 §8).
const (
	AARQ uint32 = 0 // associate request
	AARE uint32 = 1 // associate response
	RLRQ uint32 = 2 // release request
	RLRE uint32 = 3 // release response
	ABRT uint32 = 4 // abort
)

// APDUName names an APDU for a log line.
func APDUName(tag uint32) string {
	switch tag {
	case AARQ:
		return "associate_request"
	case AARE:
		return "associate_response"
	case RLRQ:
		return "release_request"
	case RLRE:
		return "release_response"
	case ABRT:
		return "abort"
	}
	return fmt.Sprintf("acse(%d)", tag)
}

// The field tags of an AARQ (X.227 §8.2).
const (
	aarqAppContext    uint32 = 1
	aarqCalledAPTitle uint32 = 2
	aarqCalledAEQual  uint32 = 3
	aarqCallingAPName uint32 = 6
	aarqCallingAEQual uint32 = 7
	aarqRequirements  uint32 = 10
	aarqMechanism     uint32 = 11
	aarqAuthValue     uint32 = 12
	aarqUserInfo      uint32 = 30
)

// The field tags of an AARE.
const (
	aareAppContext   uint32 = 1
	aareResult       uint32 = 2
	aareDiagnostic   uint32 = 3
	aareRespAPTitle  uint32 = 4
	aareRespAEQual   uint32 = 5
	aareRequirements uint32 = 8
	aareUserInfo     uint32 = 30
)

// AuthKind says what form an authentication value took, which decides what a policy
// can say about it.
type AuthKind uint8

const (
	// AuthNone is an association that carried no authentication value.
	AuthNone AuthKind = iota
	// AuthPassword is the charstring form: a password, in the clear, on the wire.
	AuthPassword
	// AuthBitString and AuthExternal are the other two forms the choice allows.
	// Neither appears in IEC 61850-8-1, and neither is a credential this relay
	// can say anything about beyond that it was there.
	AuthBitString
	AuthExternal
	// AuthOther is the fourth arm, added by later editions.
	AuthOther
)

// String names the form.
func (a AuthKind) String() string {
	switch a {
	case AuthNone:
		return "none"
	case AuthPassword:
		return "password"
	case AuthBitString:
		return "bitstring"
	case AuthExternal:
		return "external"
	case AuthOther:
		return "other"
	}
	return fmt.Sprintf("auth(%d)", uint8(a))
}

// Associate is what an AARQ or AARE said.
type Associate struct {
	// Tag is which APDU it was.
	Tag uint32
	// Context is the application context name, which IEC 61850-8-1 fixes.
	Context OID
	// CallingAPTitle and CalledAPTitle are the object identifiers naming the two
	// application processes, where the peers sent them.
	CallingAPTitle, CalledAPTitle OID
	// CallingAEQualifier and CalledAEQualifier are the integer qualifiers, and
	// HasCallingAEQualifier says whether one arrived, because zero is a value a
	// substation uses.
	CallingAEQualifier, CalledAEQualifier       int64
	HasCallingAEQualifier, HasCalledAEQualifier bool
	// Mechanism is the authentication mechanism's identifier, where one was named.
	Mechanism OID
	// Auth is which form of authentication value arrived, and AuthLength how long
	// it was. The value itself is deliberately not kept: on the charstring form it
	// is a password, and a relay that held it would be the second place it leaks.
	Auth       AuthKind
	AuthLength int
	// Result is an AARE's result: 0 accepted, 1 rejected-permanent, 2
	// rejected-transient. HasResult says one arrived.
	Result    int64
	HasResult bool
	// UserInfo is the association-information, which is where the MMS initiate PDU
	// travels.
	UserInfo []byte
}

// Accepted says an AARE accepted the association.
func (a *Associate) Accepted() bool { return a.HasResult && a.Result == 0 }

// ParseAssociate reads an ACSE APDU.
//
// The caller has already decided this payload is on the ACSE presentation context;
// what comes back says which APDU it was and what it named.
func ParseAssociate(b []byte) (*Associate, error) {
	top, err := NewBER(b).Next()
	if err != nil {
		return nil, err
	}
	if top.Class != ClassApplication || !top.Cons {
		return nil, fmt.Errorf("%w: an ACSE APDU is [APPLICATION n] constructed, this is class %#02x",
			ErrEncoding, top.Class)
	}
	a := &Associate{Tag: top.Tag}
	fields, err := NewBER(b).Sub(top)
	if err != nil {
		return nil, err
	}
	switch a.Tag {
	case AARQ:
		return a, a.readRequest(fields)
	case AARE:
		return a, a.readResponse(fields)
	case RLRQ, RLRE, ABRT:
		// Nothing in these is worth a policy: a release is a release, and an abort
		// carries a source and a diagnostic the two stacks agreed on.
		return a, nil
	}
	return nil, fmt.Errorf("%w: ACSE APDU %d", ErrEncoding, a.Tag)
}

func (a *Associate) readRequest(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e.Class != ClassContext {
			continue
		}
		switch e.Tag {
		case aarqAppContext:
			if a.Context, err = innerOID(r, e); err != nil {
				return err
			}
		case aarqCalledAPTitle:
			if a.CalledAPTitle, err = innerOID(r, e); err != nil {
				return err
			}
		case aarqCallingAPName:
			if a.CallingAPTitle, err = innerOID(r, e); err != nil {
				return err
			}
		case aarqCalledAEQual:
			if a.CalledAEQualifier, a.HasCalledAEQualifier, err = innerInt(r, e); err != nil {
				return err
			}
		case aarqCallingAEQual:
			if a.CallingAEQualifier, a.HasCallingAEQualifier, err = innerInt(r, e); err != nil {
				return err
			}
		case aarqMechanism:
			// The mechanism name is implicitly tagged, so the identifier's octets
			// are the element's own contents.
			if a.Mechanism, err = ReadOID(e); err != nil {
				return err
			}
		case aarqAuthValue:
			if err := a.readAuth(r, e); err != nil {
				return err
			}
		case aarqUserInfo:
			a.UserInfo = associationInformation(r, e)
		}
	}
	return nil
}

func (a *Associate) readResponse(r *BER) error {
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e.Class != ClassContext {
			continue
		}
		switch e.Tag {
		case aareAppContext:
			if a.Context, err = innerOID(r, e); err != nil {
				return err
			}
		case aareResult:
			if a.Result, a.HasResult, err = innerInt(r, e); err != nil {
				return err
			}
		case aareRespAPTitle:
			if a.CalledAPTitle, err = innerOID(r, e); err != nil {
				return err
			}
		case aareRespAEQual:
			if a.CalledAEQualifier, a.HasCalledAEQualifier, err = innerInt(r, e); err != nil {
				return err
			}
		case aareUserInfo:
			a.UserInfo = associationInformation(r, e)
		}
	}
	return nil
}

// readAuth records which form the authentication value took and how long it was,
// and nothing else. See the note on Associate.Auth.
func (a *Associate) readAuth(parent *BER, e Element) error {
	if !e.Cons {
		// An implicitly tagged value, which some stacks send: the contents are
		// the charstring.
		a.Auth, a.AuthLength = AuthPassword, len(e.Data)
		return nil
	}
	inner, err := parent.Sub(e)
	if err != nil {
		return err
	}
	if inner.Empty() {
		a.Auth = AuthNone
		return nil
	}
	v, err := inner.Next()
	if err != nil {
		return err
	}
	a.AuthLength = len(v.Data)
	switch {
	case v.Context(0) || v.Is(ClassUniversal, TagGeneralStr) || v.Is(ClassUniversal, TagVisibleStr):
		a.Auth = AuthPassword
	case v.Context(1):
		a.Auth = AuthBitString
	case v.Context(2):
		a.Auth = AuthExternal
	default:
		a.Auth = AuthOther
	}
	return nil
}

// innerOID reads an explicitly tagged object identifier: a constructed context tag
// wrapping the identifier. Where the tag is primitive the octets are the identifier
// itself, which is the implicit form some stacks use.
func innerOID(parent *BER, e Element) (OID, error) {
	if !e.Cons {
		return ReadOID(e)
	}
	inner, err := parent.Sub(e)
	if err != nil {
		return nil, err
	}
	for !inner.Empty() {
		v, err := inner.Next()
		if err != nil {
			return nil, err
		}
		if v.Is(ClassUniversal, TagOID) {
			return ReadOID(v)
		}
	}
	// A title in the directory-name form rather than the identifier form. IEC
	// 61850 uses identifiers; a name is carried as absent rather than guessed at.
	return nil, nil
}

// innerInt reads an explicitly tagged INTEGER the same way.
func innerInt(parent *BER, e Element) (int64, bool, error) {
	if !e.Cons {
		v, err := Int(e)
		return v, err == nil, err
	}
	inner, err := parent.Sub(e)
	if err != nil {
		return 0, false, err
	}
	for !inner.Empty() {
		v, err := inner.Next()
		if err != nil {
			return 0, false, err
		}
		if v.Is(ClassUniversal, TagInteger) {
			n, err := Int(v)
			return n, err == nil, err
		}
	}
	return 0, false, nil
}

// associationInformation unwraps the user-information, which is an EXTERNAL whose
// single-ASN1-type arm holds the MMS initiate PDU.
//
// A shape this function does not recognise yields no octets rather than an error:
// the association still happened, and the caller decides whether an association
// whose initiate it could not read is one to forward.
func associationInformation(parent *BER, e Element) []byte {
	if !e.Cons {
		return nil
	}
	seq, err := parent.Sub(e)
	if err != nil {
		return nil
	}
	for !seq.Empty() {
		ext, err := seq.Next()
		if err != nil {
			return nil
		}
		if !ext.Cons {
			continue
		}
		inner, err := seq.Sub(ext)
		if err != nil {
			return nil
		}
		for !inner.Empty() {
			v, err := inner.Next()
			if err != nil {
				return nil
			}
			// single-ASN1-type [0] holds the PDU; octet-aligned [1] holds its
			// octets. Either way what is wanted is the contents.
			if v.Context(0) || v.Context(1) {
				return v.Data
			}
		}
	}
	return nil
}
