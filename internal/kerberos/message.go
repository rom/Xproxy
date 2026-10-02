package kerberos

import (
	"errors"
	"fmt"
	"time"
)

// Reading a Kerberos message as far as a proxy can read it.
//
// Every message is [APPLICATION n] SEQUENCE, and every field inside is an
// explicitly tagged context element -- so the parse is a walk over
// numbered fields, and a field this package does not read is skipped
// rather than refused. That last part is deliberate: Microsoft adds
// pre-authentication types and padata that RFC 4120 does not describe, and
// a reader that refused an unknown field would refuse most of the real
// traffic in an AD estate. Unknown *structure* is refused; unknown
// *content* is counted and skipped.
//
// What is read is the set of fields a policy can be written about, and
// nothing else. There is no attempt to read inside an encrypted part, a
// ticket, or a FAST armour, because there is no key here and never will
// be.

// Message is one Kerberos message, read as far as its plaintext goes.
type Message struct {
	Type MsgType
	// PVNO is the protocol version, which is 5 in everything. It is the
	// standard's Int32, as every numeric field of a message is.
	PVNO int32

	// Realm is the realm the message is about: req-body's realm in a
	// request, crealm in a reply, and the error's realm field.
	Realm string
	// Client is cname, which an AS-REQ always carries and a TGS-REQ
	// usually does not -- in a TGS exchange the client is named by the
	// ticket, which is encrypted.
	Client    Principal
	HasClient bool
	// Server is sname: the service the ticket is for. In an AS-REQ it is
	// the realm's krbtgt; in a TGS-REQ it is the service being reached,
	// and it is the single most useful field on this protocol.
	Server    Principal
	HasServer bool

	// Options is kdc-options in a request.
	Options Options
	// ETypes are the encryption types the client will accept, in the
	// client's own order of preference -- which is what makes a request
	// listing only RC4 a different thing from one listing RC4 last.
	ETypes []EType
	// PAData are the pre-authentication types present, in order.
	PAData []PAType
	// ForUser is the principal a PA-FOR-USER names: the user an S4U2Self
	// request is asking to impersonate.
	ForUser    Principal
	HasForUser bool

	// From, Till and RTime are the request's requested validity. Till is
	// mandatory in a request; the other two are not.
	From, Till, RTime          time.Time
	HasFrom, HasTill, HasRTime bool
	// Nonce is the request's nonce, which pairs a reply to a request --
	// and which a relay reads because it is the only in-message link
	// between the two.
	Nonce uint32
	// Addresses is how many host addresses a request pinned itself to,
	// and AdditionalTickets how many tickets it carried. An additional
	// ticket with the constrained-delegation option is S4U2Proxy.
	Addresses         int
	AdditionalTickets int

	// EncPartEType is the type the KDC actually encrypted a reply's
	// enc-part in, which is the answer to "did the request's weak etype
	// get used". TicketEType is the same for the ticket itself, which is
	// the one Kerberoasting cares about: the ticket is encrypted in the
	// *service* account's key.
	EncPartEType, TicketEType       EType
	HasEncPartEType, HasTicketEType bool

	// ErrorCode and ErrorText are a KRB-ERROR's.
	ErrorCode int32
	ErrorText string

	// Unknown counts the fields this reader skipped, which belongs in a
	// log line on a protocol that gets extended by one vendor: a message
	// with eleven unread fields is worth knowing about even when every
	// field this package does read was fine.
	Unknown int
}

// Message errors.
var (
	ErrNotMessage   = errors.New("kerberos: not an application-tagged message")
	ErrUnknownType  = errors.New("kerberos: message type this reader does not read")
	ErrTypeMismatch = errors.New("kerberos: application tag and msg-type disagree")
	ErrPVNO         = errors.New("kerberos: protocol version is not 5")
	ErrNoRealm      = errors.New("kerberos: message carries no realm")
	ErrNoETypes     = errors.New("kerberos: request lists no encryption type")
)

// pvno is the only protocol version there is.
const pvno = 5

// Parse reads one Kerberos message.
//
// The application tag decides what the message is, and the msg-type field
// inside has to agree with it. A reader that believed only the tag would
// be deciding about a message a KDC will read as a different type, which
// is the whole point of checking two fields that say the same thing.
func Parse(b []byte) (Message, error) {
	r := newDER(b)
	top, err := r.next()
	if err != nil {
		return Message{}, err
	}
	if top.class != classApplication || !top.cons {
		return Message{}, ErrNotMessage
	}
	if !r.empty() {
		return Message{}, ErrTrailing
	}
	m := Message{Type: MsgType(top.tag)}
	if !m.Type.Known() {
		return Message{}, fmt.Errorf("%w: %s", ErrUnknownType, m.Type)
	}
	in, err := r.inner(top)
	if err != nil {
		return Message{}, err
	}
	seq, err := in.next()
	if err != nil {
		return Message{}, err
	}
	body, err := in.sequence(seq)
	if err != nil {
		return Message{}, err
	}
	if !in.empty() {
		return Message{}, ErrTrailing
	}
	switch m.Type {
	case MsgASReq, MsgTGSReq:
		err = m.readRequest(body)
	case MsgASRep, MsgTGSRep:
		err = m.readReply(body)
	case MsgError:
		err = m.readError(body)
	case MsgAPReq:
		err = m.readAPReq(body)
	}
	if err != nil {
		return Message{}, err
	}
	return m, nil
}

// readRequest reads a KDC-REQ: the version, the type, the
// pre-authentication and the body.
func (m *Message) readRequest(r *der) error {
	for !r.empty() {
		e, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case e.ctx(1):
			if m.PVNO, err = intField(r, e); err != nil {
				return err
			}
			if m.PVNO != pvno {
				return ErrPVNO
			}
		case e.ctx(2):
			n, err := intField(r, e)
			if err != nil {
				return err
			}
			if MsgType(n) != m.Type {
				return fmt.Errorf("%w: tag %s, field %d", ErrTypeMismatch, m.Type, n)
			}
		case e.ctx(3):
			if err := m.readPAData(r, e); err != nil {
				return err
			}
		case e.ctx(4):
			inner, in, err := r.only(e)
			if err != nil {
				return err
			}
			sub, err := in.sequence(inner)
			if err != nil {
				return err
			}
			if err := m.readReqBody(sub); err != nil {
				return err
			}
		default:
			m.Unknown++
		}
	}
	if m.Realm == "" {
		return ErrNoRealm
	}
	if len(m.ETypes) == 0 {
		// RFC 4120 §5.4.1 makes etype mandatory and non-empty. A request
		// with none is one the KDC cannot answer, and it is also the
		// shape of a request trying to get a reader to conclude something
		// about an empty list -- "no weak type was asked for" is true of
		// a list with nothing in it.
		return ErrNoETypes
	}
	return nil
}

// readReqBody reads KDC-REQ-BODY, which is where everything a policy
// decides on lives.
func (m *Message) readReqBody(r *der) error {
	for !r.empty() {
		e, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case e.ctx(0):
			inner, _, err := r.only(e)
			if err != nil {
				return err
			}
			bits, err := derBits(inner)
			if err != nil {
				return err
			}
			m.Options = Options(bits)
		case e.ctx(1):
			if m.Client, err = principalField(r, e); err != nil {
				return err
			}
			m.HasClient = true
		case e.ctx(2):
			if m.Realm, err = stringField(r, e); err != nil {
				return err
			}
		case e.ctx(3):
			if m.Server, err = principalField(r, e); err != nil {
				return err
			}
			m.HasServer = true
		case e.ctx(4):
			if m.From, err = timeField(r, e); err != nil {
				return err
			}
			m.HasFrom = true
		case e.ctx(5):
			if m.Till, err = timeField(r, e); err != nil {
				return err
			}
			m.HasTill = true
		case e.ctx(6):
			if m.RTime, err = timeField(r, e); err != nil {
				return err
			}
			m.HasRTime = true
		case e.ctx(7):
			n, err := intField(r, e)
			if err != nil {
				return err
			}
			m.Nonce = uint32(n) //nolint:gosec // derInteger bounds the width; a nonce past UInt32 is a KDC's problem, not a slice bound
		case e.ctx(8):
			if err := m.readETypes(r, e); err != nil {
				return err
			}
		case e.ctx(9):
			if m.Addresses, err = countField(r, e); err != nil {
				return err
			}
		case e.ctx(11):
			if m.AdditionalTickets, err = countField(r, e); err != nil {
				return err
			}
		default:
			// Field 10 is enc-authorization-data, which is encrypted, and
			// anything else is an extension.
			m.Unknown++
		}
	}
	return nil
}

// readETypes reads the encryption type list, in order.
func (m *Message) readETypes(r *der, e element) error {
	inner, in, err := r.only(e)
	if err != nil {
		return err
	}
	list, err := in.sequence(inner)
	if err != nil {
		return err
	}
	for !list.empty() {
		item, err := list.next()
		if err != nil {
			return err
		}
		n, err := derInteger(item)
		if err != nil {
			return err
		}
		m.ETypes = append(m.ETypes, EType(n))
	}
	return nil
}

// readPAData reads the pre-authentication list, and reads inside the one
// element whose contents a policy is written about.
func (m *Message) readPAData(r *der, e element) error {
	inner, in, err := r.only(e)
	if err != nil {
		return err
	}
	list, err := in.sequence(inner)
	if err != nil {
		return err
	}
	for !list.empty() {
		item, err := list.next()
		if err != nil {
			return err
		}
		fields, err := list.sequence(item)
		if err != nil {
			return err
		}
		var pt PAType
		var value []byte
		for !fields.empty() {
			f, err := fields.next()
			if err != nil {
				return err
			}
			switch {
			case f.ctx(1):
				n, err := intField(fields, f)
				if err != nil {
					return err
				}
				pt = PAType(n)
			case f.ctx(2):
				iv, _, err := fields.only(f)
				if err != nil {
					return err
				}
				if !iv.is(tagOctetString) {
					return fmt.Errorf("%w: padata-value is not an OCTET STRING", ErrTag)
				}
				value = iv.data
			default:
				m.Unknown++
			}
		}
		m.PAData = append(m.PAData, pt)
		if pt == PAForUser && len(value) > 0 {
			// S4U2Self names the impersonated user in the clear, and that
			// name is the whole of what the request is asking for -- so it
			// is read. A PA-FOR-USER this reader cannot parse is not an
			// error: the type's presence is already recorded, and the
			// policy that refuses S4U2Self outright does not need the
			// name.
			if p, ok := forUser(value); ok {
				m.ForUser, m.HasForUser = p, true
			}
		}
	}
	return nil
}

// forUser reads the principal out of a PA-FOR-USER (MS-SFU §2.2.1).
func forUser(b []byte) (Principal, bool) {
	r := newDER(b)
	top, err := r.next()
	if err != nil {
		return Principal{}, false
	}
	seq, err := r.sequence(top)
	if err != nil {
		return Principal{}, false
	}
	for !seq.empty() {
		e, err := seq.next()
		if err != nil {
			return Principal{}, false
		}
		if !e.ctx(0) {
			continue
		}
		p, err := principalField(seq, e)
		if err != nil {
			return Principal{}, false
		}
		return p, true
	}
	return Principal{}, false
}

// readReply reads a KDC-REP: who it is for, and the two encryption types
// the KDC chose.
func (m *Message) readReply(r *der) error {
	for !r.empty() {
		e, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case e.ctx(0):
			if m.PVNO, err = intField(r, e); err != nil {
				return err
			}
			if m.PVNO != pvno {
				return ErrPVNO
			}
		case e.ctx(1):
			n, err := intField(r, e)
			if err != nil {
				return err
			}
			if MsgType(n) != m.Type {
				return fmt.Errorf("%w: tag %s, field %d", ErrTypeMismatch, m.Type, n)
			}
		case e.ctx(2):
			if err := m.readPAData(r, e); err != nil {
				return err
			}
		case e.ctx(3):
			if m.Realm, err = stringField(r, e); err != nil {
				return err
			}
		case e.ctx(4):
			if m.Client, err = principalField(r, e); err != nil {
				return err
			}
			m.HasClient = true
		case e.ctx(5):
			// The ticket. Its realm, service name and the encryption type
			// of its encrypted part are all in the clear, and the last of
			// those is what says whether a service ticket just left in
			// RC4.
			inner, in, err := r.only(e)
			if err != nil {
				return err
			}
			if err := m.readTicket(in, inner); err != nil {
				return err
			}
		case e.ctx(6):
			et, ok, err := encType(r, e)
			if err != nil {
				return err
			}
			m.EncPartEType, m.HasEncPartEType = et, ok
		default:
			m.Unknown++
		}
	}
	if m.Realm == "" {
		return ErrNoRealm
	}
	return nil
}

// readTicket reads a Ticket's plaintext: realm, sname and the encryption
// type of its enc-part.
func (m *Message) readTicket(r *der, e element) error {
	if e.class != classApplication || !e.cons {
		return fmt.Errorf("%w: ticket is not application-tagged", ErrTag)
	}
	in, err := r.inner(e)
	if err != nil {
		return err
	}
	seq, err := in.next()
	if err != nil {
		return err
	}
	fields, err := in.sequence(seq)
	if err != nil {
		return err
	}
	for !fields.empty() {
		f, err := fields.next()
		if err != nil {
			return err
		}
		switch {
		case f.ctx(2):
			if m.Server, err = principalField(fields, f); err != nil {
				return err
			}
			m.HasServer = true
		case f.ctx(3):
			et, ok, err := encType(fields, f)
			if err != nil {
				return err
			}
			m.TicketEType, m.HasTicketEType = et, ok
		default:
			// tkt-vno and realm, which the reply's own realm already
			// carries.
			m.Unknown++
		}
	}
	return nil
}

// encType reads an EncryptedData's etype field.
func encType(r *der, e element) (EType, bool, error) {
	inner, in, err := r.only(e)
	if err != nil {
		return 0, false, err
	}
	seq, err := in.sequence(inner)
	if err != nil {
		return 0, false, err
	}
	for !seq.empty() {
		f, err := seq.next()
		if err != nil {
			return 0, false, err
		}
		if !f.ctx(0) {
			continue
		}
		n, err := intField(seq, f)
		if err != nil {
			return 0, false, err
		}
		return EType(n), true, nil
	}
	return 0, false, nil
}

// readError reads a KRB-ERROR: the code, the realm and the text.
func (m *Message) readError(r *der) error {
	for !r.empty() {
		e, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case e.ctx(0):
			if m.PVNO, err = intField(r, e); err != nil {
				return err
			}
			if m.PVNO != pvno {
				return ErrPVNO
			}
		case e.ctx(1):
			n, err := intField(r, e)
			if err != nil {
				return err
			}
			if MsgType(n) != m.Type {
				return fmt.Errorf("%w: tag %s, field %d", ErrTypeMismatch, m.Type, n)
			}
		case e.ctx(6):
			n, err := intField(r, e)
			if err != nil {
				return err
			}
			m.ErrorCode = n
		case e.ctx(8):
			if m.Client, err = principalField(r, e); err != nil {
				return err
			}
			m.HasClient = true
		case e.ctx(9):
			if m.Realm, err = stringField(r, e); err != nil {
				return err
			}
		case e.ctx(10):
			if m.Server, err = principalField(r, e); err != nil {
				return err
			}
			m.HasServer = true
		case e.ctx(11):
			if m.ErrorText, err = stringField(r, e); err != nil {
				return err
			}
		default:
			// The timestamps, the client realm and e-data. A relay has no
			// use for the first two, and e-data is the KDC telling the
			// client which pre-authentication to bring.
			m.Unknown++
		}
	}
	if m.Realm == "" {
		return ErrNoRealm
	}
	return nil
}

// readAPReq reads an AP-REQ as far as it is readable: the ticket's
// plaintext, which names the service. The authenticator is encrypted.
//
// It reaches a proxy through kpasswd (RFC 3244), where a password change
// is an AP-REQ and a sealed request. The useful reading is that the
// service is kadmin/changepw and which realm it is in.
func (m *Message) readAPReq(r *der) error {
	for !r.empty() {
		e, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case e.ctx(0):
			if m.PVNO, err = intField(r, e); err != nil {
				return err
			}
			if m.PVNO != pvno {
				return ErrPVNO
			}
		case e.ctx(1):
			n, err := intField(r, e)
			if err != nil {
				return err
			}
			if MsgType(n) != m.Type {
				return fmt.Errorf("%w: tag %s, field %d", ErrTypeMismatch, m.Type, n)
			}
		case e.ctx(3):
			inner, in, err := r.only(e)
			if err != nil {
				return err
			}
			if err := m.readAPTicket(in, inner); err != nil {
				return err
			}
		default:
			// ap-options and the encrypted authenticator.
			m.Unknown++
		}
	}
	if m.Realm == "" {
		return ErrNoRealm
	}
	return nil
}

// readAPTicket reads the ticket of an AP-REQ, where -- unlike a reply's --
// the realm is the only realm the message has.
func (m *Message) readAPTicket(r *der, e element) error {
	if e.class != classApplication || !e.cons {
		return fmt.Errorf("%w: ticket is not application-tagged", ErrTag)
	}
	in, err := r.inner(e)
	if err != nil {
		return err
	}
	seq, err := in.next()
	if err != nil {
		return err
	}
	fields, err := in.sequence(seq)
	if err != nil {
		return err
	}
	for !fields.empty() {
		f, err := fields.next()
		if err != nil {
			return err
		}
		switch {
		case f.ctx(1):
			if m.Realm, err = stringField(fields, f); err != nil {
				return err
			}
		case f.ctx(2):
			if m.Server, err = principalField(fields, f); err != nil {
				return err
			}
			m.HasServer = true
		case f.ctx(3):
			et, ok, err := encType(fields, f)
			if err != nil {
				return err
			}
			m.TicketEType, m.HasTicketEType = et, ok
		default:
			m.Unknown++
		}
	}
	return nil
}

// The field readers. Each unwraps the explicit context tag and reads the
// one value inside it, which is the shape of every field in the protocol.

func intField(r *der, e element) (int32, error) {
	inner, _, err := r.only(e)
	if err != nil {
		return 0, err
	}
	return derInteger(inner)
}

func stringField(r *der, e element) (string, error) {
	inner, _, err := r.only(e)
	if err != nil {
		return "", err
	}
	return derString(inner)
}

func timeField(r *der, e element) (time.Time, error) {
	inner, _, err := r.only(e)
	if err != nil {
		return time.Time{}, err
	}
	return derTime(inner)
}

// countField counts a SEQUENCE OF's members without reading them, which
// is what the two fields a policy only counts need: how many addresses a
// request pinned itself to, and how many tickets it carried.
func countField(r *der, e element) (int, error) {
	inner, in, err := r.only(e)
	if err != nil {
		return 0, err
	}
	list, err := in.sequence(inner)
	if err != nil {
		return 0, err
	}
	n := 0
	for !list.empty() {
		if _, err := list.next(); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// principalField reads a PrincipalName.
func principalField(r *der, e element) (Principal, error) {
	inner, in, err := r.only(e)
	if err != nil {
		return Principal{}, err
	}
	seq, err := in.sequence(inner)
	if err != nil {
		return Principal{}, err
	}
	var p Principal
	for !seq.empty() {
		f, err := seq.next()
		if err != nil {
			return Principal{}, err
		}
		switch {
		case f.ctx(0):
			n, err := intField(seq, f)
			if err != nil {
				return Principal{}, err
			}
			p.Type = n
		case f.ctx(1):
			parts, in, err := seq.only(f)
			if err != nil {
				return Principal{}, err
			}
			list, err := in.sequence(parts)
			if err != nil {
				return Principal{}, err
			}
			for !list.empty() {
				item, err := list.next()
				if err != nil {
					return Principal{}, err
				}
				s, err := derString(item)
				if err != nil {
					return Principal{}, err
				}
				p.Parts = append(p.Parts, s)
			}
		}
	}
	return p, nil
}

// HasPAData reports whether a message carried a pre-authentication type.
func (m Message) HasPAData(t PAType) bool {
	for _, p := range m.PAData {
		if p == t {
			return true
		}
	}
	return false
}

// Preauthenticated reports whether the message carried pre-authentication
// that proves a credential.
//
// Read on a *request* this answers "did the client prove it knows the
// password", and on a reply "was this exchange pre-authenticated" --
// because a KDC echoes the client's padata in the reply only sometimes, so
// the reliable reading is on the request and the pairing is the relay's
// job.
func (m Message) Preauthenticated() bool {
	for _, p := range m.PAData {
		if p.Preauth() {
			return true
		}
	}
	return false
}

// WeakETypes are the weak encryption types a request asked for.
func (m Message) WeakETypes() []EType {
	var out []EType
	for _, e := range m.ETypes {
		if e.Weak() {
			out = append(out, e)
		}
	}
	return out
}

// OnlyWeakETypes reports whether every type a request offered is weak,
// which is a stronger signal than merely listing one.
//
// A Windows client in a mixed estate lists aes256, aes128 and rc4, in that
// order, and the KDC picks the first it can -- so a request *mentioning*
// RC4 is ordinary. A request offering nothing else has asked for a ticket
// it can crack, and in a TGS-REQ for a service principal that is
// Kerberoasting with no ambiguity left in it.
func (m Message) OnlyWeakETypes() bool {
	if len(m.ETypes) == 0 {
		return false
	}
	for _, e := range m.ETypes {
		if !e.Weak() {
			return false
		}
	}
	return true
}

// Lifetime is how long a request asked its ticket to be valid for, and
// whether that could be read: Till is mandatory, From is not and defaults
// to now.
func (m Message) Lifetime(now time.Time) (time.Duration, bool) {
	if !m.HasTill {
		return 0, false
	}
	from := now
	if m.HasFrom && m.From.After(now) {
		from = m.From
	}
	d := m.Till.Sub(from)
	if d < 0 {
		return 0, false
	}
	return d, true
}

// S4U2Self reports whether a request is MS-SFU's protocol transition: a
// service asking for a ticket to itself as another user.
func (m Message) S4U2Self() bool { return m.HasPAData(PAForUser) }

// S4U2Proxy reports whether a request is MS-SFU's constrained delegation:
// the cname-in-addl-tkt option with a ticket to present.
//
// Both halves are required. The option alone is a client setting a
// reserved bit, and an additional ticket alone is a user-to-user request
// -- it is the pair that is a delegation.
func (m Message) S4U2Proxy() bool {
	return m.Options.Has(OptConstrainedDelegation) && m.AdditionalTickets > 0
}

// Summary renders a message for a log line: what it is, which realm, who
// it is about and what it asked for.
func (m Message) Summary() string {
	s := m.Type.String()
	if m.Realm != "" {
		s += " realm=" + m.Realm
	}
	if m.HasClient && !m.Client.Empty() {
		s += " cname=" + m.Client.String()
	}
	if m.HasServer && !m.Server.Empty() {
		s += " sname=" + m.Server.String()
	}
	if m.Type == MsgError {
		s += " error=" + ErrorName(m.ErrorCode)
	}
	return s
}
