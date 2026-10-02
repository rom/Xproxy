package radius

import (
	"errors"
	"strconv"
	"strings"
)

// EAP, as much of it as a RADIUS relay can see.
//
// RFC 3579 carries EAP inside RADIUS by splitting the EAP packet across
// as many EAP-Message attributes as it needs -- each one at most 253
// octets -- and requiring the receiver to concatenate them in the order
// they appear. So a relay reading EAP is reassembling it, and a relay
// that read only the first attribute would be reading the first 253
// octets of a method exchange and calling it the method.
//
// What is visible is the first round and the type negotiation: the
// identity the client claims, the method the server asks for, the Nak
// the client answers with when it will not do that method, and then the
// method's own start. What is not visible is anything inside a tunnelled
// method: once EAP-TLS, PEAP or TTLS has its handshake, the inner
// identity and the inner credential are inside TLS the relay has no key
// for. That boundary is worth being explicit about, because an estate
// reading `allow_eap_types` may otherwise believe it bought more than it
// did -- it bought which outer methods may be attempted, which is the
// decision that keeps EAP-MD5 off the network, and not a view of what
// happens inside PEAP.

// EAPCode is an EAP packet's code.
type EAPCode uint8

// RFC 3748 §4's four codes.
const (
	EAPRequest  EAPCode = 1
	EAPResponse EAPCode = 2
	EAPSuccess  EAPCode = 3
	EAPFailure  EAPCode = 4
)

func (c EAPCode) String() string {
	switch c {
	case EAPRequest:
		return "request"
	case EAPResponse:
		return "response"
	case EAPSuccess:
		return "success"
	case EAPFailure:
		return "failure"
	}
	return "code(" + strconv.Itoa(int(c)) + ")"
}

// EAPType is an EAP method type.
type EAPType uint8

// The method types worth naming. The first three are not methods but the
// negotiation itself; the rest are the methods an estate's equipment
// actually attempts.
const (
	EAPTypeIdentity     EAPType = 1
	EAPTypeNotification EAPType = 2
	EAPTypeNak          EAPType = 3
	// EAPTypeMD5Challenge is EAP-MD5: a challenge and an MD5 response,
	// with no server authentication and no key material. It is
	// offline-crackable from a single observed exchange and it cannot be
	// used with WPA-Enterprise for that reason. A relay's most useful
	// single line about EAP is refusing it.
	EAPTypeMD5Challenge EAPType = 4
	EAPTypeOTP          EAPType = 5
	EAPTypeGTC          EAPType = 6
	EAPTypeTLS          EAPType = 13
	// EAPTypeLEAP is Cisco's, long broken, and still configured.
	EAPTypeLEAP     EAPType = 17
	EAPTypeSIM      EAPType = 18
	EAPTypeTTLS     EAPType = 21
	EAPTypeAKA      EAPType = 23
	EAPTypePEAP     EAPType = 25
	EAPTypeMSCHAPv2 EAPType = 26
	EAPTypeFAST     EAPType = 43
	EAPTypePWD      EAPType = 52
	EAPTypeAKAPrime EAPType = 50
	EAPTypeTEAP     EAPType = 55
	// EAPTypeExpanded is RFC 3748 §5.7's escape to a vendor's own method,
	// carrying a vendor identifier and a vendor type in its first seven
	// octets. WPS and a few proprietary methods live here.
	EAPTypeExpanded EAPType = 254
)

var eapTypeNames = map[EAPType]string{
	EAPTypeIdentity: "identity", EAPTypeNotification: "notification",
	EAPTypeNak: "nak", EAPTypeMD5Challenge: "md5-challenge",
	EAPTypeOTP: "otp", EAPTypeGTC: "gtc", EAPTypeTLS: "tls",
	EAPTypeLEAP: "leap", EAPTypeSIM: "sim", EAPTypeTTLS: "ttls",
	EAPTypeAKA: "aka", EAPTypePEAP: "peap", EAPTypeMSCHAPv2: "mschapv2",
	EAPTypeFAST: "fast", EAPTypePWD: "pwd", EAPTypeAKAPrime: "aka-prime",
	EAPTypeTEAP: "teap", EAPTypeExpanded: "expanded",
}

func (t EAPType) String() string {
	if n, ok := eapTypeNames[t]; ok {
		return n
	}
	return "eap-type(" + strconv.Itoa(int(t)) + ")"
}

// EAPTypeOf reads a method from the name a rule is written with, or from
// its number: the registry has more than this package names, and a policy
// about a method it does not name is still a policy worth writing.
func EAPTypeOf(s string) (EAPType, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	k = strings.TrimPrefix(k, "eap-")
	for t, n := range eapTypeNames {
		if n == k || strings.TrimPrefix(n, "eap-") == k {
			return t, true
		}
	}
	switch k {
	case "md5":
		return EAPTypeMD5Challenge, true
	case "mschap", "ms-chapv2":
		return EAPTypeMSCHAPv2, true
	}
	// A bit-sized parse rather than Atoi and a comparison: the width is
	// then the parser's promise rather than a range check a reader has to
	// take on trust.
	if n, err := strconv.ParseUint(k, 10, 8); err == nil && n >= 1 {
		return EAPType(n), true
	}
	return 0, false
}

// EAPTypeNames are the methods this package names, sorted.
func EAPTypeNames() []string {
	out := make([]string, 0, len(eapTypeNames))
	for _, n := range eapTypeNames {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// Tunnelled reports whether a method hides its inner exchange from a
// reader on the path. It is what the documentation needs to be able to
// say, and what a relay's own log line should say, so nobody reads
// "peap" in a record and believes the inner identity was checked.
func (t EAPType) Tunnelled() bool {
	switch t {
	case EAPTypeTLS, EAPTypeTTLS, EAPTypePEAP, EAPTypeFAST, EAPTypeTEAP:
		return true
	}
	return false
}

// Weak reports whether a method is one no estate should be running: no
// server authentication, no key material, and offline-crackable from one
// observed exchange.
//
// This is a judgement rather than a reading of a standard, so it is in
// one place and named: EAP-MD5 (RFC 3748 §5.4, which says itself that it
// provides no key material and no protection against dictionary attack),
// LEAP, and the bare one-time-password and token-card types that send a
// credential with nothing around it.
func (t EAPType) Weak() bool {
	switch t {
	case EAPTypeMD5Challenge, EAPTypeLEAP, EAPTypeOTP, EAPTypeGTC:
		return true
	}
	return false
}

// WeakEAPTypes are those, by name, for a message that lists them.
func WeakEAPTypes() []string {
	return []string{"gtc", "leap", "md5-challenge", "otp"}
}

// EAP is a reassembled EAP packet, read as far as a relay can read it.
type EAP struct {
	Code EAPCode
	ID   uint8
	// Length is the EAP header's own length field.
	Length int
	// HasType is false for Success and Failure, which carry no type.
	HasType bool
	Type    EAPType
	// Identity is the claimed identity of an Identity response, with the
	// control characters refused. It is the outer identity, which on a
	// tunnelled method is routinely `anonymous` or `@realm` and is not
	// the user -- so a policy keyed on it is a policy about routing.
	Identity string
	// NakTypes are the methods a Nak response offers instead, which is
	// where a client says what it is willing to do. A client that Naks
	// everything down to EAP-MD5 is the downgrade this is read for.
	NakTypes []EAPType
	// Vendor and VendorType are set for an expanded type.
	Vendor     uint32
	VendorType uint32
	// Fragments is how many EAP-Message attributes were concatenated,
	// which is the only thing in a log line that says the packet was
	// split at all.
	Fragments int
	// Bytes is the reassembled length, which can exceed Length: a sender
	// may pad, and the standard says to believe the length field.
	Bytes int
}

// EAP errors.
var (
	ErrEAPNone     = errors.New("radius: no EAP-Message attribute")
	ErrEAPShort    = errors.New("radius: EAP packet shorter than its header")
	ErrEAPLength   = errors.New("radius: EAP length field disagrees with what was sent")
	ErrEAPTooLarge = errors.New("radius: reassembled EAP packet larger than a RADIUS packet")
	ErrEAPEmptyNak = errors.New("radius: EAP Nak offers no method")
	ErrEAPBadText  = errors.New("radius: EAP identity carries control characters")
	ErrEAPExpanded = errors.New("radius: expanded EAP type shorter than its vendor fields")
)

// eapHeaderBytes is code, identifier and length.
const eapHeaderBytes = 4

// EAP reassembles the EAP-Message attributes and reads the result.
//
// The length field is authoritative over what arrived, as RFC 3748 §4
// requires: a packet whose field is shorter than the octets sent has
// padding after it, and one whose field is longer is refused. The
// alternative -- reading to the end of what arrived -- is a reader that
// disagrees with the server about where the method's data stops.
func (p *Packet) EAP() (EAP, error) {
	var raw []byte
	frags := 0
	for _, a := range p.Attrs {
		if a.Type != AttrEAPMessage {
			continue
		}
		frags++
		if len(raw)+len(a.Value) > MaxMessage {
			return EAP{}, ErrEAPTooLarge
		}
		raw = append(raw, a.Value...)
	}
	if frags == 0 {
		return EAP{}, ErrEAPNone
	}
	if len(raw) < eapHeaderBytes {
		return EAP{}, ErrEAPShort
	}
	e := EAP{Code: EAPCode(raw[0]), ID: raw[1], Fragments: frags, Bytes: len(raw)}
	e.Length = int(raw[2])<<8 | int(raw[3])
	if e.Length < eapHeaderBytes || e.Length > len(raw) {
		return EAP{}, ErrEAPLength
	}
	raw = raw[:e.Length]
	if e.Length == eapHeaderBytes {
		// Success and Failure, and a malformed request that claims to be
		// neither. There is no type octet, so there is nothing more to
		// read and nothing to guess.
		return e, nil
	}
	e.HasType, e.Type = true, EAPType(raw[eapHeaderBytes])
	data := raw[eapHeaderBytes+1:]
	switch e.Type {
	case EAPTypeIdentity:
		for _, c := range data {
			if c < 0x20 || c == 0x7f {
				return EAP{}, ErrEAPBadText
			}
		}
		e.Identity = string(data)
	case EAPTypeNak:
		if len(data) == 0 {
			// RFC 3748 §5.3.1: a Nak carries at least one desired type,
			// and 0 means "no acceptable method". A Nak with no octets at
			// all is neither, and it is the shape of a client trying to
			// get a reader to conclude something about an empty list.
			return EAP{}, ErrEAPEmptyNak
		}
		for _, t := range data {
			e.NakTypes = append(e.NakTypes, EAPType(t))
		}
	case EAPTypeExpanded:
		// RFC 3748 §5.7: three octets of vendor identifier and four of
		// vendor type.
		if len(data) < 7 {
			return EAP{}, ErrEAPExpanded
		}
		e.Vendor = uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		e.VendorType = uint32(data[3])<<24 | uint32(data[4])<<16 |
			uint32(data[5])<<8 | uint32(data[6])
	}
	return e, nil
}

// Method renders the method for a log line: the type, and for an expanded
// type the vendor and number it escapes to.
func (e EAP) Method() string {
	if !e.HasType {
		return e.Code.String()
	}
	if e.Type == EAPTypeExpanded {
		return "expanded/" + VendorName(e.Vendor) + "/" +
			strconv.FormatUint(uint64(e.VendorType), 10)
	}
	return e.Type.String()
}
