// Package radius reads RADIUS (RFC 2865 and 2866) and the parts of it a
// relay has to decide about: the extensions (RFC 2869, 3579, 5176, 6929),
// the authentication methods carried inside it, and the two integrity
// checks the protocol has.
//
// RADIUS authenticates most of the network equipment in most estates:
// every switch port doing 802.1X, every VPN concentrator, every wireless
// controller, and -- where TACACS+ is not deployed -- the administrative
// logins to the routers themselves. It is also, by any modern reading, a
// protocol with no transport security at all.
//
// Four facts shape everything this package exposes.
//
// **The shared secret is the whole of the cryptography, and it is MD5.**
// There is no key agreement, no nonce either end contributes to beyond a
// 16-octet Request Authenticator, and no algorithm agility: MD5 and
// HMAC-MD5 are named in the standard. A relay in front of RADIUS is
// therefore holding a secret that is the same for every exchange on that
// link, and the only honest thing to do with it is use it -- to verify
// what arrives, rather than to pass a packet on because it arrived.
//
// **Access-Accept and Access-Reject differ by one octet, and MD5 is
// collidable.** The Response Authenticator is MD5 over the response with
// the request's authenticator spliced in and the secret appended. An
// attacker on the path between a client and a server who can predict the
// request can compute a chosen-prefix collision and turn a Reject into an
// Accept; that is CVE-2024-3596, and the published mitigation is the
// Message-Authenticator attribute, which is HMAC-MD5 over the whole
// packet and is not forgeable that way. So this package verifies both,
// separately, and the kind's policy can require the one that works.
//
// **User-Password is obfuscated, not encrypted.** RFC 2865 §5.2 XORs the
// password with MD5(secret || Request Authenticator), chained in 16-octet
// blocks. Anyone holding the secret reads the password, which includes
// this relay and includes anyone who has read the secret out of a
// switch's configuration. This package reports *that* a packet carries
// one and how long it is. It does not decrypt it: a relay that recovered
// the password would be a second place it leaks, and no policy worth
// writing needs the plaintext.
//
// **The identifier space is 256 wide.** A request is matched to its
// answer by (source address, identifier) and nothing else, which is why a
// relay has to keep that pairing itself rather than trust an answer that
// arrives. With 8 bits of identifier and a 16-octet authenticator, an
// off-path answer that guesses both is not a real worry; an on-path one
// that observed the request is the attack above.
//
// What this package does not do is decide anything. It reads a packet
// into its attributes, reassembles EAP, pulls out the names and the
// vendor attributes a policy is written about, and verifies the two
// authenticators against a secret the caller supplies. Which codes,
// methods, realms and privilege levels may cross a listener is
// internal/kinds/radius's business.
package radius

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // RFC 2865 specifies MD5 and RFC 3579 HMAC-MD5; verifying them is this package's job
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The sizes the standard fixes.
const (
	// HeaderBytes is code, identifier, length and authenticator.
	HeaderBytes = 20
	// AuthenticatorBytes is the Request and Response Authenticator field.
	AuthenticatorBytes = 16
	// MaxMessage is RFC 2865's maximum packet length. RFC 7930 raises it
	// for stream transports; this is the datagram one, and a datagram
	// listener is what this package is read by.
	MaxMessage = 4096
	// MaxPassword is the longest User-Password RFC 2865 allows: 128
	// octets, which is eight chained blocks.
	MaxPassword = 128
)

// Code is the RADIUS packet code: the first octet, and the whole of what
// the packet is.
type Code uint8

// The codes a relay sees. The first six are RFC 2865 and 2866; the last
// six are RFC 5176's dynamic authorization, which is a different thing
// and is treated as one throughout.
const (
	CodeAccessRequest      Code = 1
	CodeAccessAccept       Code = 2
	CodeAccessReject       Code = 3
	CodeAccountingRequest  Code = 4
	CodeAccountingResponse Code = 5
	CodeAccessChallenge    Code = 11
	CodeStatusServer       Code = 12
	CodeStatusClient       Code = 13
	CodeDisconnectRequest  Code = 40
	CodeDisconnectACK      Code = 41
	CodeDisconnectNAK      Code = 42
	CodeCoARequest         Code = 43
	CodeCoAACK             Code = 44
	CodeCoANAK             Code = 45
)

var codeNames = map[Code]string{
	CodeAccessRequest:      "access-request",
	CodeAccessAccept:       "access-accept",
	CodeAccessReject:       "access-reject",
	CodeAccountingRequest:  "accounting-request",
	CodeAccountingResponse: "accounting-response",
	CodeAccessChallenge:    "access-challenge",
	CodeStatusServer:       "status-server",
	CodeStatusClient:       "status-client",
	CodeDisconnectRequest:  "disconnect-request",
	CodeDisconnectACK:      "disconnect-ack",
	CodeDisconnectNAK:      "disconnect-nak",
	CodeCoARequest:         "coa-request",
	CodeCoAACK:             "coa-ack",
	CodeCoANAK:             "coa-nak",
}

func (c Code) String() string {
	if n, ok := codeNames[c]; ok {
		return n
	}
	return "code(" + strconv.Itoa(int(c)) + ")"
}

// Known says whether this is a code the standards define.
func (c Code) Known() bool { _, ok := codeNames[c]; return ok }

// Request says whether a client sends this code towards a server.
//
// The dynamic authorization codes run the other way -- a server sends
// Disconnect-Request and CoA-Request to the equipment -- so they are
// requests that are not client requests, and this reports false for them.
// Direction on this protocol is a property of the code, and it is the
// check that catches a server reaching back into a client network.
func (c Code) Request() bool {
	switch c {
	case CodeAccessRequest, CodeAccountingRequest, CodeStatusServer, CodeStatusClient:
		return true
	}
	return false
}

// Response says whether a server sends this code back to a client.
func (c Code) Response() bool {
	switch c {
	case CodeAccessAccept, CodeAccessReject, CodeAccountingResponse, CodeAccessChallenge:
		return true
	}
	return false
}

// Dynamic says whether this is one of RFC 5176's dynamic authorization
// codes: the ones that end a live session or change what it is allowed to
// do, sent from a server towards the equipment.
//
// They are worth a predicate of their own because they are the codes a
// relay in the ordinary position should never carry. A Disconnect-Request
// drops a user's session and a CoA-Request re-authorizes it -- a new VLAN,
// a new filter, a new privilege level -- from one UDP datagram
// authenticated by the same shared secret as everything else.
func (c Code) Dynamic() bool {
	switch c {
	case CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAACK, CodeCoANAK:
		return true
	}
	return false
}

// CodeOf reads a code from the name a rule is written with.
func CodeOf(s string) (Code, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	for c, n := range codeNames {
		if n == k {
			return c, true
		}
	}
	// The bare forms an operator is likely to write.
	switch k {
	case "auth", "access":
		return CodeAccessRequest, true
	case "acct", "accounting":
		return CodeAccountingRequest, true
	case "status":
		return CodeStatusServer, true
	case "disconnect":
		return CodeDisconnectRequest, true
	case "coa":
		return CodeCoARequest, true
	}
	if n, err := strconv.ParseUint(k, 10, 8); err == nil {
		return Code(n), true
	}
	return 0, false
}

// CodeNames are the codes a rule may name, sorted, for an error message.
func CodeNames() []string {
	out := make([]string, 0, len(codeNames))
	for _, n := range codeNames {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// AttrType is an attribute's type octet.
type AttrType uint8

// The attributes a policy on this protocol is written about. Not every
// attribute the IANA registry holds -- the ones here are the ones that
// name a person, place a session, carry a credential, grant a privilege
// or bound what a relay must do.
const (
	AttrUserName             AttrType = 1
	AttrUserPassword         AttrType = 2
	AttrCHAPPassword         AttrType = 3
	AttrNASIPAddress         AttrType = 4
	AttrNASPort              AttrType = 5
	AttrServiceType          AttrType = 6
	AttrFramedProtocol       AttrType = 7
	AttrFramedIPAddress      AttrType = 8
	AttrFilterID             AttrType = 11
	AttrReplyMessage         AttrType = 18
	AttrState                AttrType = 24
	AttrClass                AttrType = 25
	AttrVendorSpecific       AttrType = 26
	AttrCalledStationID      AttrType = 30
	AttrCallingStationID     AttrType = 31
	AttrNASIdentifier        AttrType = 32
	AttrProxyState           AttrType = 33
	AttrAcctStatusType       AttrType = 40
	AttrAcctSessionID        AttrType = 44
	AttrCHAPChallenge        AttrType = 60
	AttrNASPortType          AttrType = 61
	AttrTunnelType           AttrType = 64
	AttrTunnelMediumType     AttrType = 65
	AttrEAPMessage           AttrType = 79
	AttrMessageAuthenticator AttrType = 80
	AttrTunnelPrivateGroupID AttrType = 81
	AttrNASIPv6Address       AttrType = 95
	AttrOperatorName         AttrType = 126
)

var attrNames = map[AttrType]string{
	AttrUserName: "user-name", AttrUserPassword: "user-password",
	AttrCHAPPassword: "chap-password", AttrNASIPAddress: "nas-ip-address",
	AttrNASPort: "nas-port", AttrServiceType: "service-type",
	AttrFramedProtocol: "framed-protocol", AttrFramedIPAddress: "framed-ip-address",
	AttrFilterID: "filter-id", AttrReplyMessage: "reply-message",
	AttrState: "state", AttrClass: "class", AttrVendorSpecific: "vendor-specific",
	AttrCalledStationID: "called-station-id", AttrCallingStationID: "calling-station-id",
	AttrNASIdentifier: "nas-identifier", AttrProxyState: "proxy-state",
	AttrAcctStatusType: "acct-status-type", AttrAcctSessionID: "acct-session-id",
	AttrCHAPChallenge: "chap-challenge", AttrNASPortType: "nas-port-type",
	AttrTunnelType: "tunnel-type", AttrTunnelMediumType: "tunnel-medium-type",
	AttrEAPMessage: "eap-message", AttrMessageAuthenticator: "message-authenticator",
	AttrTunnelPrivateGroupID: "tunnel-private-group-id",
	AttrNASIPv6Address:       "nas-ipv6-address", AttrOperatorName: "operator-name",
}

func (a AttrType) String() string {
	if n, ok := attrNames[a]; ok {
		return n
	}
	return "attr(" + strconv.Itoa(int(a)) + ")"
}

// AttrOf reads an attribute type from the name a rule is written with, or
// from its number -- because the registry has hundreds and a policy may
// legitimately be about one this package has no name for.
func AttrOf(s string) (AttrType, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	for t, n := range attrNames {
		if n == k {
			return t, true
		}
	}
	if n, err := strconv.ParseUint(k, 10, 8); err == nil && n >= 1 {
		return AttrType(n), true
	}
	return 0, false
}

// AttrNames are the attributes this package names, sorted, for an error
// message that has to list them.
func AttrNames() []string {
	out := make([]string, 0, len(attrNames))
	for _, n := range attrNames {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// Extended reports whether a type is one of RFC 6929's extended
// attributes, whose first value octet is an extended type rather than
// data.
//
// They matter to a reader for one reason: a rule written about attribute
// 241 is not about one attribute but about 256 of them, and a relay that
// treated the extended type as data would decide about the wrong thing.
func (a AttrType) Extended() bool { return a >= 241 && a <= 246 }

// Vendor identifiers whose attributes carry privilege.
const (
	// VendorCisco's cisco-avpair (26/1) is a string, and
	// `shell:priv-lvl=15` inside one is how a RADIUS server hands out
	// enable on a Cisco device. A relay that reads replies reads this.
	VendorCisco uint32 = 9
	// VendorMicrosoft carries the MS-CHAP attributes and MPPE keys.
	VendorMicrosoft uint32 = 311
	// VendorJuniper's Juniper-Local-User-Name (26/1) names a local
	// template on the device, which is that platform's privilege grant.
	VendorJuniper uint32 = 2636
	// VendorFortinet's Fortinet-Access-Profile (26/6) is the same idea.
	VendorFortinet uint32 = 12356
)

var vendorNames = map[uint32]string{
	VendorCisco: "cisco", VendorMicrosoft: "microsoft",
	VendorJuniper: "juniper", VendorFortinet: "fortinet",
}

// VendorName names a vendor identifier, or renders the number.
func VendorName(id uint32) string {
	if n, ok := vendorNames[id]; ok {
		return n
	}
	return "vendor(" + strconv.FormatUint(uint64(id), 10) + ")"
}

// Attr is one attribute, as it was found.
//
// Value aliases the packet rather than copying it, which is what lets
// VerifyMessageAuthenticator zero the digest in place over a copy without
// re-walking the attributes. Callers must not modify it.
type Attr struct {
	Type AttrType
	// ExtType is RFC 6929's extended type, set when Type is extended.
	ExtType uint8
	// Vendor and VendorType are set for a Vendor-Specific attribute whose
	// contents follow RFC 2865 §5.26's recommended encoding. Vendor is
	// set and VendorType is zero where the vendor used its own.
	Vendor     uint32
	VendorType uint8
	// Value is the attribute's data: after the type and length octets,
	// and after the vendor and extended headers where those were read.
	Value []byte
	// Offset is where Value begins in the packet, so a verifier can find
	// it again in a copy.
	Offset int
}

// Name renders the attribute the way a log line should.
func (a Attr) Name() string {
	switch {
	case a.Vendor != 0:
		return VendorName(a.Vendor) + "." + strconv.Itoa(int(a.VendorType))
	case a.Type.Extended():
		return a.Type.String() + "." + strconv.Itoa(int(a.ExtType))
	}
	return a.Type.String()
}

// Text reads the attribute as a string, with the control characters it has
// no business carrying refused rather than cleaned: a NAS-Identifier with
// a newline in it is either broken equipment or somebody writing a second
// line into a log, and this relay's answer to both is the same.
func (a Attr) Text() (string, bool) {
	for _, c := range a.Value {
		if c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	return string(a.Value), true
}

// Uint32 reads a four-octet integer attribute.
func (a Attr) Uint32() (uint32, bool) {
	if len(a.Value) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(a.Value), true
}

// Packet is one parsed RADIUS packet.
type Packet struct {
	Code Code
	ID   uint8
	// Length is the length field, which is authoritative: octets beyond
	// it are padding the standard says to ignore.
	Length        int
	Authenticator [AuthenticatorBytes]byte
	Attrs         []Attr
	// Raw is the packet as it arrived, truncated to Length.
	Raw []byte
}

// Errors this package returns. They are values because the kind's log
// line says which one, and a reason string built from an error's text
// would change when the text did.
var (
	ErrShort        = errors.New("radius: shorter than a header")
	ErrLength       = errors.New("radius: length field outside the standard's bounds")
	ErrTruncated    = errors.New("radius: length field is longer than the datagram")
	ErrAttrLength   = errors.New("radius: attribute length is impossible")
	ErrAttrOverruns = errors.New("radius: attribute runs past the packet")
	ErrTooMany      = errors.New("radius: more attributes than a packet can hold")
	ErrNoSecret     = errors.New("radius: no shared secret, so nothing can be verified")
	ErrNoDigest     = errors.New("radius: no Message-Authenticator attribute")
	ErrBadDigest    = errors.New("radius: Message-Authenticator does not verify")
)

// maxAttrs bounds the attribute list a parse will build. 4096 octets of
// packet cannot hold more than 2038 two-octet attributes, so this is the
// structural bound rather than a policy: it exists so that a packet
// claiming to be full of empty attributes cannot make the parser build a
// slice out of proportion to the datagram.
const maxAttrs = 2048

// Parse reads a datagram.
//
// The length field decides where the packet ends, not the datagram: RFC
// 2865 §3 says octets outside Length are padding and must be ignored, and
// a Length longer than what arrived means the packet is to be discarded.
// Getting that the wrong way round is how a reader and a server come to
// disagree about which attributes are in a packet, which is the shape of
// every attribute-injection trick on this protocol.
func Parse(b []byte) (*Packet, error) {
	if len(b) < HeaderBytes {
		return nil, ErrShort
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < HeaderBytes || n > MaxMessage {
		return nil, ErrLength
	}
	if n > len(b) {
		return nil, ErrTruncated
	}
	b = b[:n]
	p := &Packet{Code: Code(b[0]), ID: b[1], Length: n, Raw: b}
	copy(p.Authenticator[:], b[4:HeaderBytes])
	for off := HeaderBytes; off < n; {
		if off+2 > n {
			return nil, ErrAttrOverruns
		}
		l := int(b[off+1])
		if l < 2 {
			// A zero or one length would not advance, so a packet
			// carrying one would be an endless loop in every reader
			// that did not check. It is refused rather than skipped:
			// there is no way to know where the next attribute starts.
			return nil, ErrAttrLength
		}
		if off+l > n {
			return nil, ErrAttrOverruns
		}
		if len(p.Attrs) >= maxAttrs {
			return nil, ErrTooMany
		}
		p.Attrs = append(p.Attrs, readAttr(AttrType(b[off]), b, off+2, off+l))
		off += l
	}
	return p, nil
}

// readAttr reads one attribute's value, unwrapping the two headers that
// sit inside a value rather than beside it.
func readAttr(t AttrType, b []byte, from, to int) Attr {
	a := Attr{Type: t, Value: b[from:to], Offset: from}
	switch {
	case t == AttrVendorSpecific && to-from >= 4:
		a.Vendor = binary.BigEndian.Uint32(b[from : from+4])
		rest, at := b[from+4:to], from+4
		// RFC 2865 §5.26 recommends vendor-type, vendor-length, data --
		// and says a vendor need not follow it. The recommended form is
		// read only when the inner length accounts for exactly what is
		// there; otherwise the value stays whole, so a rule about a
		// vendor's attribute number is never matched against octets that
		// are not one.
		if len(rest) >= 2 && int(rest[1]) == len(rest) && rest[1] >= 2 {
			a.VendorType = rest[0]
			a.Value, a.Offset = b[at+2:to], at+2
			return a
		}
		a.Value, a.Offset = rest, at
	case t.Extended() && to-from >= 1:
		a.ExtType = b[from]
		a.Value, a.Offset = b[from+1:to], from+1
	}
	return a
}

// First returns the first attribute of a type, which for the attributes
// that name things is the only one that should be there.
func (p *Packet) First(t AttrType) (Attr, bool) {
	for _, a := range p.Attrs {
		if a.Type == t {
			return a, true
		}
	}
	return Attr{}, false
}

// Count returns how many attributes of a type the packet carries.
func (p *Packet) Count(t AttrType) int {
	n := 0
	for _, a := range p.Attrs {
		if a.Type == t {
			n++
		}
	}
	return n
}

// Has reports whether the packet carries an attribute of a type.
func (p *Packet) Has(t AttrType) bool { _, ok := p.First(t); return ok }

// Vendor returns the first attribute of a vendor and vendor type.
func (p *Packet) Vendor(vendor uint32, vendorType uint8) (Attr, bool) {
	for _, a := range p.Attrs {
		if a.Vendor == vendor && a.VendorType == vendorType {
			return a, true
		}
	}
	return Attr{}, false
}

// UserName is the User-Name attribute as text, empty where there is none
// or where it carries control characters.
func (p *Packet) UserName() string {
	a, ok := p.First(AttrUserName)
	if !ok {
		return ""
	}
	s, ok := a.Text()
	if !ok {
		return ""
	}
	return s
}

// Realm splits a User-Name into its local part and its realm, in the
// three forms the installed base uses: user@realm (RFC 4282's NAI, and
// what 802.1X sends), realm\user (what a Windows client sends) and
// realm/user (what some equipment rewrites it to).
//
// The split matters because a realm is routing: a RADIUS server proxies
// by realm, so a user-name carrying one asks this estate's server to
// forward the credential somewhere else. A relay that has an allow list
// of realms has a say in that, and one that reads only the whole string
// does not.
//
// Where a name carries more than one separator the *first* decides, and
// the rest stays in the part it fell in -- because that is how a server
// reading left to right will split it, and a reader that disagreed with
// the server about the realm would be deciding about a different realm
// than the one the credential goes to.
func Realm(user string) (local, realm string) {
	i := strings.IndexAny(user, `@\/`)
	if i < 0 {
		return user, ""
	}
	if user[i] == '@' {
		return user[:i], user[i+1:]
	}
	return user[i+1:], user[:i]
}

// AuthType is the credential an Access-Request carries.
type AuthType string

// The methods this package tells apart. They are the five shapes a
// RADIUS credential comes in, and they are not equally strong.
const (
	// AuthNone is an Access-Request with no credential at all: the first
	// message of an EAP exchange that carried no EAP-Message yet, or a
	// request relying on something outside the protocol.
	AuthNone AuthType = "none"
	// AuthPAP is User-Password: the password itself, obfuscated with the
	// shared secret. Reversible by anyone holding the secret.
	AuthPAP AuthType = "pap"
	// AuthCHAP is CHAP-Password: a challenge and an MD5 response, which
	// requires the server to hold the password in a reversible form.
	AuthCHAP AuthType = "chap"
	// AuthMSCHAP is Microsoft's CHAP, versions 1 and 2, in the
	// MS-CHAP-Response and MS-CHAP2-Response vendor attributes. Both
	// derive from NT hashes and version 1 is broken.
	AuthMSCHAP AuthType = "mschap"
	// AuthEAP is EAP-Message: an exchange this relay sees the type of
	// and, past the first round, nothing else.
	AuthEAP AuthType = "eap"
)

// Microsoft's vendor attribute numbers for the CHAP variants.
const (
	msCHAPResponse  uint8 = 1
	msCHAP2Response uint8 = 25
)

// AuthType reads which credential a request carries.
//
// EAP wins where both are present, because that is what a server does:
// RFC 3579 §2.6.2 says a server receiving both EAP-Message and
// User-Password may do either, and every implementation worth naming
// prefers EAP -- so a relay that reported PAP would be deciding about a
// method the server is not going to use.
func (p *Packet) AuthType() AuthType {
	switch {
	case p.Has(AttrEAPMessage):
		return AuthEAP
	case p.Has(AttrUserPassword):
		return AuthPAP
	case p.Has(AttrCHAPPassword):
		return AuthCHAP
	}
	if _, ok := p.Vendor(VendorMicrosoft, msCHAP2Response); ok {
		return AuthMSCHAP
	}
	if _, ok := p.Vendor(VendorMicrosoft, msCHAPResponse); ok {
		return AuthMSCHAP
	}
	return AuthNone
}

// AuthTypeOf reads a method from the name a rule is written with.
func AuthTypeOf(s string) (AuthType, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return AuthNone, true
	case "pap", "password", "user-password":
		return AuthPAP, true
	case "chap":
		return AuthCHAP, true
	case "mschap", "ms-chap", "mschapv2", "ms-chapv2":
		return AuthMSCHAP, true
	case "eap":
		return AuthEAP, true
	}
	return "", false
}

// AuthTypeNames are the methods a rule may name, sorted.
func AuthTypeNames() []string {
	return []string{string(AuthCHAP), string(AuthEAP), string(AuthMSCHAP),
		string(AuthNone), string(AuthPAP)}
}

// PasswordBytes is the length of the obfuscated User-Password, and
// whether it is a length RFC 2865 §5.2 allows: a non-zero multiple of 16,
// at most 128.
//
// A length that is not is worth refusing rather than correcting. The
// obfuscation is a chain of 16-octet blocks, so a server decoding a short
// final block reads past it or truncates, and which it does is an
// implementation's choice -- which makes a packet with a 17-octet password
// a request two servers may read differently.
func (p *Packet) PasswordBytes() (int, bool) {
	a, ok := p.First(AttrUserPassword)
	if !ok {
		return 0, false
	}
	n := len(a.Value)
	return n, n > 0 && n <= MaxPassword && n%16 == 0
}

// PrivilegeLevel reads the administrative privilege a reply grants, where
// it grants one in a form this package recognises.
//
// There are three such forms and they are all vendor attributes, because
// RADIUS itself has no notion of a privilege level: Cisco's
// cisco-avpair carrying `shell:priv-lvl=N`, the same vendor's
// Cisco-AVPair spelling `priv-lvl=N`, and Service-Type =
// Administrative-User (6), which is the standard attribute that means
// "this login gets the enable prompt" on a lot of equipment.
//
// A relay reads this on the *reply* leg, which is the only place it
// exists. A client asking for privilege is asking by logging in; the
// grant is the server's answer, and it is the thing an estate wants
// bounded -- a RADIUS server, or anything that can forge its answers,
// hands out enable on every router with one attribute.
// It reads every attribute rather than the first that parses, and returns the
// highest level any of them grants. Both halves of that matter, because a
// bound applied to a grant the equipment is not the one to act on is not a
// bound: a reply carrying `priv-lvl=1` and then `priv-lvl=15` is read here as
// 15 whichever of them a given platform takes, and a reply whose first vendor
// attribute is unparsable no longer hides the one after it.
func (p *Packet) PrivilegeLevel() (int, bool) {
	best, found := 0, false
	for _, a := range p.Attrs {
		if a.Vendor != VendorCisco {
			continue
		}
		// The raw octets, not Text: the pair list is NUL-separated on some
		// platforms, Text refuses control characters, and a reader that asked
		// Text first would answer "this reply grants no privilege" for exactly
		// the spelling an attacker would choose -- one NUL in the attribute and
		// the bound would never have been applied. The separators below include
		// it, so the list is read in every form it arrives in.
		if n, ok := privLevel(string(a.Value)); ok && (!found || n > best) {
			best, found = n, true
		}
	}
	return best, found
}

// serviceTypeAdministrative is RFC 2865's Administrative-User.
const serviceTypeAdministrative uint32 = 6

// Administrative reports whether a reply carries Service-Type =
// Administrative-User, which on most equipment is the enable grant
// written in the standard's own attributes rather than a vendor's.
// Every occurrence is read, for the same reason PrivilegeLevel reads every
// vendor attribute: a reply whose first Service-Type is Login and whose second
// is Administrative-User is a reply that grants the enable prompt on whatever
// equipment takes the second, and a check that stopped at the first would have
// called it an ordinary login.
func (p *Packet) Administrative() bool {
	for _, a := range p.Attrs {
		if a.Type != AttrServiceType {
			continue
		}
		if v, ok := a.Uint32(); ok && v == serviceTypeAdministrative {
			return true
		}
	}
	return false
}

// privLevel reads a priv-lvl out of a vendor attribute's octets.
//
// It takes the value as it arrived rather than a text-safe rendering of it,
// and the separator set below is why: the attribute is a list of pairs on some
// platforms and the separator is a comma, a space, a semicolon or a NUL,
// depending on the platform. A reader that refused the NUL form would be a
// reader with a hole the shape of one octet.
func privLevel(s string) (int, bool) {
	best, found := 0, false
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == 0
	}) {
		i := strings.IndexAny(part, "=*")
		if i < 0 {
			continue
		}
		key, val := part[:i], part[i+1:]
		if k := strings.LastIndex(key, ":"); k >= 0 {
			key = key[k+1:]
		}
		if !strings.EqualFold(key, "priv-lvl") && !strings.EqualFold(key, "priv_lvl") {
			continue
		}
		// The protocol's levels are 0 to 15 and the bound is validated in that
		// range, but a value outside it is still read and returned rather than
		// ignored: a reply saying `priv-lvl=99` is a reply the policy should
		// refuse, and a reader that dropped it on the floor would be answering
		// "this grants nothing" about a grant.
		// The highest pair wins, for the same reason the highest attribute
		// does: a list with `priv-lvl=1` before `priv-lvl=15` grants 15 on
		// whatever equipment reads the last of them, and a bound applied to
		// the first would be a bound on the wrong number.
		if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && n >= 0 && (!found || n > best) {
			best, found = n, true
		}
	}
	return best, found
}

// VerifyMessageAuthenticator checks RFC 3579 §3.2's HMAC-MD5 digest.
//
// The digest is computed over the whole packet with the digest's own 16
// octets zeroed, and with the authenticator field holding the *request's*
// authenticator -- the packet's own for a request, and the request it
// answers for a response. That substitution is why the caller passes
// requestAuth: a verifier that used the response's own field would reject
// every valid response.
//
// It is the check worth requiring. The Response Authenticator is MD5 with
// the secret appended, and a chosen-prefix MD5 collision turns an
// Access-Reject into an Access-Accept on the wire (CVE-2024-3596); this
// one is a keyed HMAC over the same octets and that attack does not reach
// it.
func (p *Packet) VerifyMessageAuthenticator(secret []byte, requestAuth [AuthenticatorBytes]byte) error {
	if len(secret) == 0 {
		return ErrNoSecret
	}
	a, ok := p.First(AttrMessageAuthenticator)
	if !ok {
		return ErrNoDigest
	}
	if len(a.Value) != AuthenticatorBytes {
		// A digest of the wrong length cannot be the digest, and a
		// verifier that compared the first 16 octets of a longer one
		// would be accepting a packet whose attribute a server will
		// reject. Refused as a failed verification rather than as a
		// malformed packet, because that is what it is.
		return ErrBadDigest
	}
	want := make([]byte, AuthenticatorBytes)
	copy(want, a.Value)
	// The computation needs two edits, so it runs over a copy: the
	// authenticator field becomes the request's, and the digest becomes
	// zeroes. Editing the packet itself would leave the caller holding
	// something that is no longer what arrived.
	buf := make([]byte, len(p.Raw))
	copy(buf, p.Raw)
	copy(buf[4:HeaderBytes], requestAuth[:])
	at := a.Offset
	if at < 0 || at+AuthenticatorBytes > len(buf) {
		return ErrBadDigest
	}
	for i := 0; i < AuthenticatorBytes; i++ {
		buf[at+i] = 0
	}
	h := hmac.New(md5.New, secret) //nolint:gosec // RFC 3579 specifies HMAC-MD5
	h.Write(buf)
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return ErrBadDigest
	}
	return nil
}

// ResponseAuthenticator computes RFC 2865 §3's Response Authenticator:
// MD5 over the response with the request's authenticator spliced in and
// the secret appended.
//
// It is also the Accounting-Request authenticator, with sixteen zero
// octets in place of a request authenticator, which is why requestAuth is
// a parameter rather than read from a stored request.
func (p *Packet) ResponseAuthenticator(secret []byte, requestAuth [AuthenticatorBytes]byte) [AuthenticatorBytes]byte {
	h := md5.New() //nolint:gosec // RFC 2865 specifies MD5
	h.Write(p.Raw[:4])
	h.Write(requestAuth[:])
	h.Write(p.Raw[HeaderBytes:])
	h.Write(secret)
	var out [AuthenticatorBytes]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyResponseAuthenticator checks that authenticator.
//
// A relay should treat a pass here as weaker than a Message-Authenticator
// pass rather than as equivalent, which is why this returns a bool and
// the other returns the error saying what was wrong: there is nothing
// useful to say about a failure here beyond that the secret or the packet
// is not what it should be, and a pass proves less than it looks like it
// does.
func (p *Packet) VerifyResponseAuthenticator(secret []byte, requestAuth [AuthenticatorBytes]byte) bool {
	if len(secret) == 0 {
		return false
	}
	want := p.ResponseAuthenticator(secret, requestAuth)
	return subtle.ConstantTimeCompare(want[:], p.Authenticator[:]) == 1
}

// sortStrings is a two-line insertion sort, so this package's name tables
// need no import of sort for the three places that list them.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Summary renders a packet for a log line: what it is, who it says it is
// about, and the facts a reader needs without the attributes a reader
// does not.
func (p *Packet) Summary() string {
	var b strings.Builder
	b.WriteString(p.Code.String())
	b.WriteString(" id=")
	b.WriteString(strconv.Itoa(int(p.ID)))
	if u := p.UserName(); u != "" {
		b.WriteString(" user=")
		b.WriteString(u)
	}
	if n := len(p.Attrs); n > 0 {
		b.WriteString(" attrs=")
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

// String makes a Packet printable in a test failure without printing the
// credential it carries.
func (p *Packet) String() string { return fmt.Sprintf("radius.Packet{%s}", p.Summary()) }
