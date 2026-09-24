package ntp

import (
	"encoding/binary"
	"fmt"
)

// Extension is one extension field (RFC 7822): a type, a length that
// counts the whole field including its own header and any padding, and
// the value between them.
type Extension struct {
	Type uint16
	// Body is the value, without the four-octet header and without the
	// padding the length covers.
	Body []byte
	// Length is the field's length as it appeared on the wire, which is
	// what the next field's offset depends on.
	Length int
}

// Bytes renders the field, padded to a multiple of four.
func (e Extension) Bytes() []byte {
	n := 4 + len(e.Body)
	if pad := n % 4; pad != 0 {
		n += 4 - pad
	}
	if n < MinExtensionLen {
		n = MinExtensionLen
	}
	b := make([]byte, n)
	binary.BigEndian.PutUint16(b, e.Type)
	binary.BigEndian.PutUint16(b[2:], uint16(n)) //nolint:gosec // bounded by MaxPacket
	copy(b[4:], e.Body)
	return b
}

// MinExtensionLen is the shortest extension field RFC 7822 allows: four
// octets of header and twelve of value. The minimum exists because of
// the ambiguity below -- a shorter field could not be told from a MAC.
const MinExtensionLen = 16

// The extension field types this relay recognises. The registry is
// IANA's; RFC 9748 is the current reference for what is in it and what
// the historical values were. A type not in this table is not
// interpreted -- see UnknownExtensions.
const (
	// EFUniqueIdentifier, EFNTSCookie, EFNTSCookiePlaceholder and
	// EFNTSAuthenticator are NTS (RFC 8915).
	EFUniqueIdentifier     uint16 = 0x0104
	EFNTSCookie            uint16 = 0x0204
	EFNTSCookiePlaceholder uint16 = 0x0304
	EFNTSAuthenticator     uint16 = 0x0404
	// EFChecksumComplement is RFC 7821: a field whose value makes the
	// UDP checksum come out to a chosen value, so a hardware
	// timestamper can rewrite a timestamp without recomputing it.
	EFChecksumComplement uint16 = 0x2005
)

var extensionNames = map[uint16]string{
	EFUniqueIdentifier:     "unique_identifier",
	EFNTSCookie:            "nts_cookie",
	EFNTSCookiePlaceholder: "nts_cookie_placeholder",
	EFNTSAuthenticator:     "nts_authenticator",
	EFChecksumComplement:   "checksum_complement",
}

// ExtensionName is the name of a field type, or a hexadecimal rendering
// of a type this relay does not know.
func ExtensionName(t uint16) string {
	if s, ok := extensionNames[t]; ok {
		return s
	}
	return fmt.Sprintf("unknown_0x%04x", t)
}

// KnownExtension says whether this relay knows what a field type means.
//
// It matters because of what a policy can honestly do with a field it
// does not know: nothing. A relay that forwarded an unknown extension
// field would be forwarding an instruction to the server behind it that
// it could not decide about -- which includes every field Autokey (RFC
// 5906) ever defined, a protocol this relay does not implement and will
// not tunnel.
func KnownExtension(t uint16) bool {
	_, ok := extensionNames[t]
	return ok
}

// NTSFields is what the visible NTS fields say -- and no more.
//
// Every field here is readable by anybody on the path, so none of them
// proves anything. A packet can carry a unique identifier, a cookie and
// an authenticator field and still be entirely forged: only the party
// holding the key can tell, and a relay that is not terminating NTS does
// not hold it. So this structure is named for what it is -- fields
// present -- and the relay's policy treats "NTS is present" as a routing
// and preservation fact, never as an authentication one.
type NTSFields struct {
	Present       bool
	UniqueID      []byte
	Cookies       int
	Placeholders  int
	Authenticator bool
	// AuthenticatorLen is the length of the authenticator field, which
	// is the only thing about it this relay can see: what is inside is
	// encrypted, including any extension fields the sender put there.
	AuthenticatorLen int
}

// NTS reads the visible NTS fields.
func (p *Packet) NTS() NTSFields {
	var n NTSFields
	for _, e := range p.Extensions {
		switch e.Type {
		case EFUniqueIdentifier:
			n.Present = true
			n.UniqueID = e.Body
		case EFNTSCookie:
			n.Present = true
			n.Cookies++
		case EFNTSCookiePlaceholder:
			n.Present = true
			n.Placeholders++
		case EFNTSAuthenticator:
			n.Present = true
			n.Authenticator = true
			n.AuthenticatorLen = e.Length
		}
	}
	return n
}

// UnknownExtensions is how many extension fields carried a type this
// relay does not know.
func (p *Packet) UnknownExtensions() int {
	n := 0
	for _, e := range p.Extensions {
		if !KnownExtension(e.Type) {
			n++
		}
	}
	return n
}

// parseTail divides everything after the header into extension fields
// and a MAC.
//
// This is the ambiguity RFC 7822 documents and cannot remove: the four
// octets after the header could begin an extension field or be a key
// identifier, and the only way to tell is by how much is left. The rules
// are the ones every implementation follows --
//
//	0 octets:  neither
//	4 octets:  a key identifier alone, which is a crypto-NAK
//	20 octets: a key identifier and a 128-bit digest
//	24 octets: a key identifier and a 160-bit digest
//	anything else: extension fields, whose last one may be followed by
//	one of the three MAC shapes above
//
// -- and a tail that is both a MAC shape and a syntactically valid
// extension field is read as a MAC and flagged, because the device on the
// other side may read it the other way and a relay that hid the
// disagreement would be the reason nobody could find it.
//
// Versions before 4 have no extension fields at all, so there the tail
// can only be a MAC. Saying so is what stops an NTPv3 packet with
// something appended being read as if the appendage meant anything.
func (p *Packet) parseTail(tail []byte, version uint8) error {
	if len(tail) == 0 {
		return nil
	}
	if version < 4 {
		// The MAC covers the header and nothing else here, because
		// there is nothing else: a version before 4 has no extension
		// fields, so the authenticated region ends where the header
		// does.
		p.MACStart = HeaderLen
		return p.readMAC(tail, len(tail))
	}
	rest := tail
	off := HeaderLen
	for len(rest) > 24 {
		if len(p.Extensions) >= MaxExtensions {
			return fmt.Errorf("%w: more than %d fields", ErrExtension, MaxExtensions)
		}
		e, err := readExtension(rest)
		if err != nil {
			return err
		}
		p.Extensions = append(p.Extensions, e)
		rest = rest[e.Length:]
		off += e.Length
	}
	switch len(rest) {
	case 0:
		p.MACStart = off
		return nil
	case 4, 20, 24:
		// A MAC shape. It may also be a well-formed extension field, in
		// which case the packet's meaning depends on a choice, and the
		// choice is recorded.
		if e, err := readExtension(rest); err == nil && e.Length == len(rest) {
			p.MACAmbiguous = true
		}
		p.MACStart = off
		return p.readMAC(rest, len(rest))
	}
	// One field exactly filling the tail is the remaining legal shape.
	e, err := readExtension(rest)
	if err != nil {
		return err
	}
	if e.Length != len(rest) {
		return fmt.Errorf("%w: %d octets after the last field", ErrTail, len(rest)-e.Length)
	}
	if len(p.Extensions) >= MaxExtensions {
		return fmt.Errorf("%w: more than %d fields", ErrExtension, MaxExtensions)
	}
	p.Extensions = append(p.Extensions, e)
	p.MACStart = off + e.Length
	return nil
}

// readExtension reads one field, checking the length field against what
// is actually there rather than trusting it: the length is a sender's
// claim, and it is the claim a reader that trusted it would walk off the
// end of.
func readExtension(b []byte) (Extension, error) {
	if len(b) < 4 {
		return Extension{}, fmt.Errorf("%w: %d octets", ErrExtension, len(b))
	}
	t := binary.BigEndian.Uint16(b)
	n := int(binary.BigEndian.Uint16(b[2:]))
	switch {
	case n < MinExtensionLen:
		return Extension{}, fmt.Errorf("%w: length %d below the minimum %d", ErrExtension, n, MinExtensionLen)
	case n%4 != 0:
		return Extension{}, fmt.Errorf("%w: length %d is not a multiple of four", ErrExtension, n)
	case n > len(b):
		return Extension{}, fmt.Errorf("%w: length %d with %d octets left", ErrExtension, n, len(b))
	}
	return Extension{Type: t, Body: b[4:n], Length: n}, nil
}

// readMAC reads a key identifier and digest of one of the three shapes.
func (p *Packet) readMAC(b []byte, n int) error {
	switch n {
	case 4:
		p.KeyID = binary.BigEndian.Uint32(b)
		p.CryptoNAK = true
		return nil
	case 20, 24:
		p.KeyID = binary.BigEndian.Uint32(b)
		p.MAC = b[4:n]
		p.HasMAC = true
		return nil
	}
	return fmt.Errorf("%w: a tail of %d octets", ErrTail, n)
}
