// Package snmp reads SNMP, the protocol that manages every switch, router,
// printer and UPS in an estate and has almost no security in it.
//
// Versions 1 and 2c authenticate with a *community string*: a cleartext
// password in every datagram, which is "public" for reading and "private"
// for writing on equipment nobody reconfigured. There is no integrity, no
// replay protection and no confidentiality. One UDP datagram with the right
// string reads a device's whole configuration; one with the write string
// changes it. The devices cannot be fixed -- they are switches and printers
// and building controllers with firmware nobody ships updates for -- so the
// only place a policy can exist is in the path.
//
// Version 3 has a real security model (USM, RFC 3414): an engine identifier,
// authentication with HMAC, and privacy with a block cipher. It also has
// noAuthNoPriv, which is v2c with more fields, and a great many estates
// enable v3 and leave it there.
//
// What this package reads, and why each field is worth reading:
//
//   - The **version**, because "this listener accepts v3 only" is the single
//     most useful line an operator can write, and because a v1 datagram and
//     a v3 datagram are different messages that must not be confused.
//   - The **community string** for v1 and v2c, because it is the credential,
//     and because a relay is the only thing that can hold a different one on
//     each side -- which is what lets a manager stop knowing the device's.
//   - The **security level** for v3, because noAuthNoPriv is not security
//     and an operator should be able to refuse it by name.
//   - The **PDU type**, because it says what is being *done*: a GetRequest
//     reads, a SetRequest reconfigures, a GetBulkRequest can be made to
//     answer with a thousand times what it asked, and a Trap travels the
//     other way entirely.
//   - The **object identifiers**, because they say what is being read or
//     written, and a policy over subtrees is the only kind of SNMP policy
//     that survives a firmware upgrade.
//   - The **max-repetitions** of a GETBULK, because that field is the
//     amplification factor of the best-known SNMP reflection attack.
//
// What is not decoded is the *values* beyond their type: this package reads
// a varbind's tag and extent, not what a Counter64 means. A policy about
// values would need a MIB per estate, and a relay that mis-decoded one
// would corrupt a reading nobody could trace.
package snmp

import (
	"errors"
	"fmt"
)

// The ports the protocol fixes. The two TLS ones are RFC 6353's.
const (
	// Port is where agents listen, and TrapPort where managers receive.
	Port     = 161
	TrapPort = 162
	// TLSPort and TLSTrapPort are RFC 6353's on TCP, and DTLSPort and
	// DTLSTrapPort the same two numbers on UDP, which is where the DTLS
	// variant of the same transport model lives (IANA: snmptls and
	// snmp-dtls, snmptls-trap and snmp-dtls-trap). The number says which
	// direction, and the transport says which stack -- a command responder
	// on 10161 either way, notifications on 10162.
	//
	// Almost nothing deployed speaks any of the four, which is the reason a
	// relay that terminates one and speaks v2c to the device is worth
	// having: the certificate is at this end and the switch never learns
	// there was one.
	TLSPort      = 10161
	TLSTrapPort  = 10162
	DTLSPort     = 10161
	DTLSTrapPort = 10162
)

// MaxMessage bounds what this package will read at all.
//
// RFC 3416 requires an implementation to accept 484 octets and recommends
// 1472 (an Ethernet datagram without fragmenting). Agents in practice
// accept more, so the bound is generous and a listener bounds it tighter.
// What it stops is a stream framing that claims a message of a gigabyte.
const MaxMessage = 65507

// Version is the message version, as the field encodes it rather than as
// people say it: the integer is 0 for v1 and 1 for v2c, which is off by one
// from the names and is a mistake worth making impossible.
type Version int

// The versions.
const (
	V1  Version = 0
	V2c Version = 1
	V3  Version = 3
)

// String names a version the way an operator writes it.
func (v Version) String() string {
	switch v {
	case V1:
		return "v1"
	case V2c:
		return "v2c"
	case V3:
		return "v3"
	}
	return fmt.Sprintf("v?%d", int(v))
}

// VersionOf reads a version name as the configuration spells it.
func VersionOf(s string) (Version, bool) {
	switch s {
	case "1", "v1":
		return V1, true
	case "2c", "v2c", "2":
		return V2c, true
	case "3", "v3":
		return V3, true
	}
	return 0, false
}

// Known says whether this is a version the protocol defines.
func (v Version) Known() bool { return v == V1 || v == V2c || v == V3 }

// PDUType is what a message asks for.
type PDUType Tag

// The PDU types, by the tag that carries them.
const (
	GetRequest     = PDUType(TagGetRequest)
	GetNextRequest = PDUType(TagGetNextRequest)
	Response       = PDUType(TagResponse)
	SetRequest     = PDUType(TagSetRequest)
	TrapV1         = PDUType(TagTrapV1)
	GetBulkRequest = PDUType(TagGetBulkRequest)
	InformRequest  = PDUType(TagInformRequest)
	TrapV2         = PDUType(TagTrapV2)
	ReportPDU      = PDUType(TagReport)
)

var pduNames = map[string]PDUType{
	"get": GetRequest, "get_next": GetNextRequest, "response": Response,
	"set": SetRequest, "trap_v1": TrapV1, "get_bulk": GetBulkRequest,
	"inform": InformRequest, "trap": TrapV2, "report": ReportPDU,
}

var pduByType = func() map[PDUType]string {
	out := make(map[PDUType]string, len(pduNames))
	for n, t := range pduNames {
		out[t] = n
	}
	return out
}()

// PDUTypeOf reads a PDU name as the configuration spells it.
func PDUTypeOf(s string) (PDUType, bool) {
	t, ok := pduNames[s]
	return t, ok
}

// String names a PDU type.
func (t PDUType) String() string {
	if n, ok := pduByType[t]; ok {
		return n
	}
	return fmt.Sprintf("pdu_%#02x", byte(t))
}

// Known says whether the protocol defines this PDU type.
func (t PDUType) Known() bool { _, ok := pduByType[t]; return ok }

// Writes says whether this PDU type changes something on the agent.
//
// It is exactly one type, and that is the point: "read only" on an SNMP
// listener is a one-line policy because the protocol has one writing
// operation. Everything else either reads or reports.
func (t PDUType) Writes() bool { return t == SetRequest }

// Reads says whether this PDU type retrieves objects.
func (t PDUType) Reads() bool {
	return t == GetRequest || t == GetNextRequest || t == GetBulkRequest
}

// Notification says whether this PDU travels from the agent to the manager
// rather than the other way: a trap, or an inform, which is a trap that
// wants an acknowledgement.
func (t PDUType) Notification() bool {
	return t == TrapV1 || t == TrapV2 || t == InformRequest
}

// SecurityLevel is a v3 message's security level, from the two flag bits
// RFC 3412 defines.
type SecurityLevel int

// The three levels.
const (
	NoAuthNoPriv SecurityLevel = iota
	AuthNoPriv
	AuthPriv
)

// String names a level the way RFC 3414 does, which is how it appears in
// every vendor's configuration guide.
func (l SecurityLevel) String() string {
	switch l {
	case AuthNoPriv:
		return "authNoPriv"
	case AuthPriv:
		return "authPriv"
	}
	return "noAuthNoPriv"
}

// LevelOf reads a security level name, case insensitively because the
// documentation an operator is copying from varies.
func LevelOf(s string) (SecurityLevel, bool) {
	switch lower(s) {
	case "noauthnopriv":
		return NoAuthNoPriv, true
	case "authnopriv":
		return AuthNoPriv, true
	case "authpriv":
		return AuthPriv, true
	}
	return 0, false
}

// Authenticated says whether the level includes authentication.
func (l SecurityLevel) Authenticated() bool { return l == AuthNoPriv || l == AuthPriv }

// Encrypted says whether the level includes privacy.
func (l SecurityLevel) Encrypted() bool { return l == AuthPriv }

// VarBind is one variable binding: the name of an object and what was said
// about it.
type VarBind struct {
	// OID is the object's name.
	OID OID
	// Tag is the value's type, which is read but not interpreted. A
	// policy about *values* would need a MIB per estate.
	Tag Tag
	// Len is how many octets the value occupied, which is what a response
	// size bound is measured in.
	Len int
}

// Exception says whether this binding carries one of the three values an
// agent returns instead of a value. They are not errors: an agent
// answering a walk ends it with end-of-MIB-view.
func (v VarBind) Exception() bool {
	return v.Tag == TagNoSuchObject || v.Tag == TagNoSuchInstance || v.Tag == TagEndOfMibView
}

// PDU is a parsed protocol data unit.
type PDU struct {
	Type PDUType
	// RequestID pairs a response with its request. It is the only thing
	// that does, which is why an unsolicited response is recognisable.
	RequestID int64
	// ErrorStatus and ErrorIndex are the response fields; on a GETBULK
	// request the same two positions carry non-repeaters and
	// max-repetitions instead, which is the field this protocol's
	// amplification is measured in.
	ErrorStatus, ErrorIndex int64
	NonRepeaters            int64
	MaxRepetitions          int64
	// VarBinds are the bindings, in order.
	VarBinds []VarBind
	// Enterprise, Agent, GenericTrap, SpecificTrap and Timestamp are the
	// v1 trap's own header, which v2 replaced with two varbinds. A relay
	// that bridges the two has to read both shapes.
	Enterprise                OID
	Agent                     [4]byte
	GenericTrap, SpecificTrap int64
	Timestamp                 uint64
	// Raw is the PDU element exactly as it arrived, tag and length
	// included, and Bindings the variable-binding SEQUENCE inside it, the
	// same way. They are what the rewriting in edit.go carries over
	// unchanged: this relay changes a message's envelope and its
	// repetition count, and never what was asked for.
	Raw      []byte
	Bindings []byte
}

// V3Header is the header of a version 3 message.
type V3Header struct {
	// MessageID is v3's own identifier, separate from the PDU's request
	// identifier.
	MessageID int64
	// MaxSize is the largest response the sender will accept.
	MaxSize int64
	// Reportable, Authenticated and Encrypted are the msgFlags bits.
	Reportable bool
	Level      SecurityLevel
	// SecurityModel is 3 for USM. Another value is a security model this
	// does not read, and a relay must not pretend it read one.
	SecurityModel int64
	// EngineID is the authoritative engine's identifier, from the USM
	// security parameters. An empty one is a discovery message.
	EngineID []byte
	// User is the USM user name, which is v3's equivalent of the
	// community string and the field a policy names.
	User string
	// EngineBoots and EngineTime are the sender's view of the
	// authoritative engine's clock, which is what USM's replay window is
	// built on.
	EngineBoots, EngineTime int64
	// ScopedPDUEncrypted says the scoped PDU is a privacy blob rather than
	// a readable PDU. Without the user's privacy key that is the case a
	// relay cannot inspect and must say so about rather than guess; with
	// it, Ciphertext below is what Decrypt reads.
	ScopedPDUEncrypted bool
	// AuthParams is the message digest as it arrived, and AuthParamsAt its
	// offset in the whole message.
	//
	// The offset is what makes the digest verifiable: the computation is
	// over the whole message with this field zeroed, so a verifier has to
	// know where it is rather than which fields it covers. Zero means
	// there was none.
	AuthParams   []byte
	AuthParamsAt int
	// PrivParams is the privacy salt, which is half the initialisation
	// vector; the engine's boots and time are the other half.
	PrivParams []byte
	// Ciphertext is the encrypted scoped PDU, when there is one.
	Ciphertext []byte
	// ContextEngineID and ContextName come from the scoped PDU, when it is
	// readable.
	ContextEngineID []byte
	ContextName     string
}

// Message is a parsed SNMP message.
type Message struct {
	Version Version
	// Community is the v1 and v2c credential, in the clear, as it
	// arrived.
	Community string
	// V3 is the version 3 header, nil for v1 and v2c.
	V3 *V3Header
	// PDU is the protocol data unit. It is nil for a v3 message whose
	// scoped PDU is encrypted: there is nothing to read, and a relay has
	// to decide about the message on its header alone.
	PDU *PDU
	// Raw is the whole message as it arrived. A relay forwards these
	// octets rather than re-encoding: re-encoding a message is how a relay
	// and an agent come to disagree about what was asked, and on an
	// authenticated v3 message it would break the HMAC.
	Raw []byte
}

// Errors this package returns beyond the BER ones.
var (
	// ErrVersion is a version field this does not know. It is refused
	// rather than forwarded, because a relay cannot decide about a message
	// whose shape it does not know -- the credential is in a different
	// place in each version.
	ErrVersion = errors.New("snmp: unknown version")
	// ErrSecurityModel is a v3 security model other than USM.
	ErrSecurityModel = errors.New("snmp: unknown security model")
	// ErrCommunity is a community string longer than any agent accepts.
	ErrCommunity = errors.New("snmp: community string too long")
)

// MaxCommunity bounds the community string and the USM user name.
//
// Neither has a length in the standard, and both are compared against a
// configured list, so the bound is what stops a datagram carrying a
// megabyte where a word belongs.
const MaxCommunity = 255

// Parse reads one SNMP message.
//
// A v3 message with an encrypted scoped PDU parses successfully with a nil
// PDU: the header is readable and the payload is not, and that distinction
// is the whole of what a relay can decide about such a message. That is the
// only case where something is missing without an error; an error always
// comes with a nil message, so a caller never has to wonder whether the
// fields it is about to read were filled in.
func Parse(raw []byte) (*Message, error) {
	if len(raw) == 0 || len(raw) > MaxMessage {
		return nil, ErrTruncated
	}
	top := &reader{b: raw}
	seq, err := top.expect(TagSequence)
	if err != nil {
		return nil, err
	}
	if !top.empty() {
		// Octets after the message. On a datagram that is a second
		// message in one packet, and on a stream it is a framing this
		// reader did not agree to.
		return nil, ErrTrailing
	}
	r, err := top.sub(seq)
	if err != nil {
		return nil, err
	}
	m := &Message{Raw: raw}
	ve, err := r.expect(TagInteger)
	if err != nil {
		return nil, err
	}
	v, err := readInt(ve)
	if err != nil {
		return nil, err
	}
	m.Version = Version(v)
	if !m.Version.Known() {
		return nil, fmt.Errorf("%w: %d", ErrVersion, v)
	}
	if m.Version == V3 {
		if err := parseV3(r, m); err != nil {
			// nil rather than the half-built message. A caller that reads a
			// field off a message this refused would be reading whatever the
			// header happened to fill before it failed, and every caller here
			// already discards it -- returning it invites the one that does
			// not. The "reads as far as it can" above is about the encrypted
			// scoped PDU, which is a success with a nil PDU, not about errors.
			return nil, err
		}
		return m, nil
	}
	ce, err := r.expect(TagOctetStr)
	if err != nil {
		return nil, err
	}
	if len(ce.body) > MaxCommunity {
		return nil, ErrCommunity
	}
	m.Community = string(ce.body)
	pdu, err := parsePDU(r)
	if err != nil {
		return nil, err
	}
	m.PDU = pdu
	if !r.empty() {
		return nil, ErrTrailing
	}
	return m, nil
}

// parseV3 reads the version 3 header and, when it is readable, the scoped
// PDU inside it.
func parseV3(r *reader, m *Message) error {
	h := &V3Header{}
	m.V3 = h
	// msgGlobalData: message id, max size, flags, security model.
	gd, err := r.expect(TagSequence)
	if err != nil {
		return err
	}
	g, err := r.sub(gd)
	if err != nil {
		return err
	}
	if h.MessageID, err = intField(g); err != nil {
		return err
	}
	if h.MaxSize, err = intField(g); err != nil {
		return err
	}
	fe, err := g.expect(TagOctetStr)
	if err != nil {
		return err
	}
	if len(fe.body) != 1 {
		return fmt.Errorf("%w: msgFlags is %d octets", ErrTruncated, len(fe.body))
	}
	flags := fe.body[0]
	h.Reportable = flags&0x04 != 0
	switch {
	case flags&0x02 != 0 && flags&0x01 != 0:
		h.Level = AuthPriv
	case flags&0x01 != 0:
		h.Level = AuthNoPriv
	default:
		// The privacy bit without the authentication bit is not a level
		// the standard defines: privacy without authentication is
		// encryption nobody can attribute. It reads as noAuthNoPriv here
		// and a listener refuses it by level.
		h.Level = NoAuthNoPriv
	}
	if h.SecurityModel, err = intField(g); err != nil {
		return err
	}
	// msgSecurityParameters: an OCTET STRING whose contents are, for USM,
	// another SEQUENCE. For any other security model the octets are that
	// model's and are not read.
	se, err := r.expect(TagOctetStr)
	if err != nil {
		return err
	}
	switch h.SecurityModel {
	case SecurityModelUSM:
		// Where these octets sit in the whole message. A reader consumes
		// from the front of a slice of the message itself, so what it still
		// holds ends where the message ends: the element just stepped past
		// finishes there, and begins that less its own body. This is how the
		// digest field's offset is arrived at without any pointer
		// arithmetic, and without a caller having to say where it started.
		at := len(m.Raw) - len(r.b) - len(se.body)
		if err := parseUSM(se.body, h, at); err != nil {
			return err
		}
	case SecurityModelTSM:
		// RFC 5591 s3.1.1: a zero-length OCTET STRING, because the transport
		// carries the security and the message carries none. Octets here are
		// refused rather than skipped -- see ErrTSMParams.
		if len(se.body) != 0 {
			return fmt.Errorf("%w: %d octets", ErrTSMParams, len(se.body))
		}
	}
	// The scoped PDU: plain when there is no privacy, an OCTET STRING of
	// ciphertext when there is.
	//
	// The transport security model is the exception, and it is not a special
	// case so much as the model working as written: RFC 5591 s3.1.1 sets the
	// flags from the *transport's* security level, so a TSM message says
	// authPriv while its scoped PDU is in the clear, because the record layer
	// underneath already encrypted it. A reader that took the privacy bit
	// here as "ciphertext follows" would refuse every TSM message ever sent.
	if h.Level.Encrypted() && h.SecurityModel != SecurityModelTSM {
		ce, err := r.expect(TagOctetStr)
		if err != nil {
			return err
		}
		h.ScopedPDUEncrypted = true
		h.Ciphertext = ce.body
		return nil
	}
	sd, err := r.expect(TagSequence)
	if err != nil {
		return err
	}
	s, err := r.sub(sd)
	if err != nil {
		return err
	}
	ce, err := s.expect(TagOctetStr)
	if err != nil {
		return err
	}
	h.ContextEngineID = ce.body
	ne, err := s.expect(TagOctetStr)
	if err != nil {
		return err
	}
	if len(ne.body) > MaxCommunity {
		return ErrCommunity
	}
	h.ContextName = string(ne.body)
	pdu, err := parsePDU(s)
	if err != nil {
		return err
	}
	m.PDU = pdu
	return nil
}

// parseUSM reads the user security model's parameters.
func parseUSM(b []byte, h *V3Header, at int) error {
	outer := &reader{b: b}
	sd, err := outer.expect(TagSequence)
	if err != nil {
		return err
	}
	// Where the sequence's contents begin, in the whole message.
	inner := at + (len(b) - len(outer.b)) - len(sd.body)
	r, err := outer.sub(sd)
	if err != nil {
		return err
	}
	ee, err := r.expect(TagOctetStr)
	if err != nil {
		return err
	}
	if len(ee.body) > 32 {
		// RFC 3411 bounds an engine identifier at 32 octets.
		return fmt.Errorf("%w: engine id is %d octets", ErrTruncated, len(ee.body))
	}
	h.EngineID = ee.body
	if h.EngineBoots, err = intField(r); err != nil {
		return err
	}
	if h.EngineTime, err = intField(r); err != nil {
		return err
	}
	ue, err := r.expect(TagOctetStr)
	if err != nil {
		return err
	}
	if len(ue.body) > MaxCommunity {
		return ErrCommunity
	}
	h.User = string(ue.body)
	// The authentication and privacy parameters. The digest is kept with
	// its offset in the whole message, because verifying it means hashing
	// the message with this field zeroed -- see usm.go. Without a key
	// configured for the user they are read for their extent only, which is
	// what this did before there was anywhere for a key to come from.
	ae, err := r.expect(TagOctetStr)
	if err != nil {
		return err
	}
	h.AuthParams = ae.body
	if len(ae.body) > 0 {
		h.AuthParamsAt = inner + (len(sd.body) - len(r.b)) - len(ae.body)
	}
	pe, err := r.expect(TagOctetStr)
	if err != nil {
		return err
	}
	h.PrivParams = pe.body
	return nil
}

// intField reads the next element as an INTEGER.
func intField(r *reader) (int64, error) {
	e, err := r.expect(TagInteger)
	if err != nil {
		return 0, err
	}
	return readInt(e)
}

// parsePDU reads a protocol data unit of any of the eight types.
func parsePDU(r *reader) (*PDU, error) {
	e, err := r.next()
	if err != nil {
		return nil, err
	}
	p := &PDU{Type: PDUType(e.tag), Raw: e.raw}
	if !p.Type.Known() {
		return nil, fmt.Errorf("%w: pdu %#02x", ErrTag, byte(e.tag))
	}
	b, err := r.sub(e)
	if err != nil {
		return nil, err
	}
	if p.Type == TrapV1 {
		return p, parseTrapV1(b, p)
	}
	if p.RequestID, err = intField(b); err != nil {
		return nil, err
	}
	a, err := intField(b)
	if err != nil {
		return nil, err
	}
	c, err := intField(b)
	if err != nil {
		return nil, err
	}
	if p.Type == GetBulkRequest {
		// The same two positions, read as what a GETBULK puts there. This
		// is the field the protocol's amplification is measured in: a
		// request of forty octets with max-repetitions of ten thousand
		// asks for a response of megabytes.
		p.NonRepeaters, p.MaxRepetitions = a, c
	} else {
		p.ErrorStatus, p.ErrorIndex = a, c
	}
	if p.VarBinds, p.Bindings, err = parseVarBinds(b); err != nil {
		return nil, err
	}
	if !b.empty() {
		return nil, ErrTrailing
	}
	return p, nil
}

// parseTrapV1 reads the version 1 trap, whose header is its own shape.
func parseTrapV1(r *reader, p *PDU) error {
	ee, err := r.expect(TagOID)
	if err != nil {
		return err
	}
	if p.Enterprise, err = readOID(ee); err != nil {
		return err
	}
	ae, err := r.expect(TagIPAddress)
	if err != nil {
		return err
	}
	if len(ae.body) != 4 {
		return fmt.Errorf("%w: agent address is %d octets", ErrTruncated, len(ae.body))
	}
	copy(p.Agent[:], ae.body)
	if p.GenericTrap, err = intField(r); err != nil {
		return err
	}
	if p.SpecificTrap, err = intField(r); err != nil {
		return err
	}
	te, err := r.expect(TagTimeTicks)
	if err != nil {
		return err
	}
	if p.Timestamp, err = readUint(te); err != nil {
		return err
	}
	if p.VarBinds, p.Bindings, err = parseVarBinds(r); err != nil {
		return err
	}
	if !r.empty() {
		return ErrTrailing
	}
	return nil
}

// parseVarBinds reads the variable binding list, and returns the list
// element as it arrived beside it: a refusal echoes those octets and a
// rewritten request forwards them, neither having to re-encode a value this
// relay deliberately did not interpret.
func parseVarBinds(r *reader) ([]VarBind, []byte, error) {
	le, err := r.expect(TagSequence)
	if err != nil {
		return nil, nil, err
	}
	list, err := r.sub(le)
	if err != nil {
		return nil, nil, err
	}
	var out []VarBind
	for !list.empty() {
		if len(out) >= MaxVarBinds {
			return nil, nil, fmt.Errorf("%w: more than %d variable bindings", ErrCount, MaxVarBinds)
		}
		be, err := list.expect(TagSequence)
		if err != nil {
			return nil, nil, err
		}
		bind, err := list.sub(be)
		if err != nil {
			return nil, nil, err
		}
		oe, err := bind.expect(TagOID)
		if err != nil {
			return nil, nil, err
		}
		oid, err := readOID(oe)
		if err != nil {
			return nil, nil, err
		}
		ve, err := bind.next()
		if err != nil {
			return nil, nil, err
		}
		if !bind.empty() {
			return nil, nil, ErrTrailing
		}
		out = append(out, VarBind{OID: oid, Tag: ve.tag, Len: len(ve.body)})
	}
	return out, le.raw, nil
}

// lower folds an ASCII name to lower case.
func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
