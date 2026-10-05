// Package tacacs reads TACACS+ (RFC 8907): the twelve-octet header, the
// MD5 obfuscation the protocol calls encryption, and the bodies of all
// three of its exchanges.
//
// TACACS+ is how the administrators of network equipment log in to it.
// Where RADIUS answers "may this user onto the network", TACACS+ answers
// "may this user, at this privilege level, run this command on this
// router" -- it authorises each command separately, and the command is in
// the packet. That makes it the most interesting protocol in this
// directory for a relay to read, because the thing it carries is
// privileged administrative access to the estate's own infrastructure,
// and the thing a policy can say about it is which commands.
//
// Three facts shape this package.
//
// **The obfuscation is not encryption and the standard says so.** RFC
// 8907 §4.5 is titled "Data Obfuscation" and §10.3 states plainly that it
// is "not cryptographically sound". The body is XORed with a pad of
// chained MD5 digests over the session identifier, the shared key, the
// version and the sequence number -- so the pad for a given session and
// sequence number is fixed, identical plaintext at the same offset gives
// identical ciphertext, and anyone holding the key reads everything. This
// package therefore de-obfuscates with the key it is given and treats
// having the key as the ordinary case: a relay that cannot read the body
// cannot police a command, and policing commands is the point.
//
// **A body may also arrive in the clear.** The header's
// TAC_PLUS_UNENCRYPTED_FLAG says the body was not obfuscated at all.
// RFC 8907 §4.5 requires that it be used only on a secured transport,
// which in practice means TLS. On a bare TCP connection it is a
// configuration mistake or somebody stripping the obfuscation, and either
// way the body of an administrative login is on the wire in plaintext.
//
// **The password is in the body, and this package keeps its length.** An
// ASCII login sends the password in a CONTINUE packet's user_msg; PAP
// sends it in the START packet's data. Both are readable here, which is
// unavoidable -- the relay has to parse the packet to find the fields
// after it. What is avoidable is keeping them, so the parsed bodies carry
// the *lengths* of the password-bearing fields and not their contents.
// There is no accessor that returns a password, because a relay that had
// one would be the second place every administrative credential in the
// estate leaks.
//
// What this package does not do is decide. Which commands, services,
// privilege levels and authentication types may cross a listener is
// internal/kinds/tacacs's business.
package tacacs

import (
	"crypto/md5" //nolint:gosec // RFC 8907 §4.5 specifies MD5 for the obfuscation pad
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// The sizes the standard fixes.
const (
	// HeaderBytes is the fixed header: version, type, sequence number,
	// flags, session identifier and length.
	HeaderBytes = 12
	// VersionMajor is the only major version there is, 0xc.
	VersionMajor = 0xc
	// MaxBody is the largest body this package will read. The length
	// field is 32 bits wide, and RFC 8907 §4.1 says a server should
	// refuse a body longer than 2^16 because nothing legitimate is --
	// this is that bound, applied by the reader rather than left to the
	// caller, so a header claiming four gigabytes never reaches an
	// allocation.
	MaxBody = 1 << 16
)

// The header flags.
const (
	// FlagUnencrypted says the body was not obfuscated.
	FlagUnencrypted uint8 = 0x01
	// FlagSingleConnect asks to carry more than one session on this TCP
	// connection. It is negotiated on the first packet each way and is
	// why a relay cannot assume one connection is one login.
	FlagSingleConnect uint8 = 0x04
)

// Type is the exchange a packet belongs to.
type Type uint8

// The three exchanges.
const (
	TypeAuthen Type = 1
	TypeAuthor Type = 2
	TypeAcct   Type = 3
)

var typeNames = map[Type]string{
	TypeAuthen: "authentication", TypeAuthor: "authorization", TypeAcct: "accounting",
}

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return "type(" + strconv.Itoa(int(t)) + ")"
}

// Known says whether this is one of the three.
func (t Type) Known() bool { _, ok := typeNames[t]; return ok }

// TypeOf reads an exchange from the name a rule is written with.
func TypeOf(s string) (Type, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "authentication", "authen", "auth":
		return TypeAuthen, true
	case "authorization", "authorisation", "author":
		return TypeAuthor, true
	case "accounting", "acct":
		return TypeAcct, true
	}
	return 0, false
}

// TypeNames are the exchanges a rule may name, sorted.
func TypeNames() []string {
	return []string{"accounting", "authentication", "authorization"}
}

// Header is the twelve octets in front of every packet.
type Header struct {
	VersionMajor uint8
	VersionMinor uint8
	Type         Type
	// Seq is the sequence number: 1 for the client's first packet, even
	// for the server's, and a session ends when it would wrap past 255.
	Seq   uint8
	Flags uint8
	// SessionID is what pairs a request to its answer, and what tells two
	// sessions apart on a single-connect connection. It is chosen by the
	// client and is not authenticated by anything.
	SessionID uint32
	// Length is the body's length. It is read as an int because every use
	// of it is a slice bound, and a uint32 that reaches one of those is
	// exactly the bug this field causes.
	Length int
}

// Unencrypted reports whether the body arrived in the clear.
func (h Header) Unencrypted() bool { return h.Flags&FlagUnencrypted != 0 }

// SingleConnect reports whether this end asked to multiplex sessions on
// the connection.
func (h Header) SingleConnect() bool { return h.Flags&FlagSingleConnect != 0 }

// FromClient reports whether a sequence number is a client's. The client
// sends the odd ones, which is the only thing in the protocol that says
// which end a packet came from -- so a relay reading a packet off the
// upstream leg and finding an odd sequence number is reading something
// that should not have come from there.
func (h Header) FromClient() bool { return h.Seq%2 == 1 }

// Errors this package returns.
var (
	ErrShort        = errors.New("tacacs: shorter than a header")
	ErrVersion      = errors.New("tacacs: not major version 0xc")
	ErrLength       = errors.New("tacacs: body length past this reader's bound")
	ErrZeroSeq      = errors.New("tacacs: sequence number zero")
	ErrBodyShort    = errors.New("tacacs: body shorter than its fixed fields")
	ErrBodyFields   = errors.New("tacacs: body's declared field lengths do not fit it")
	ErrBodyTrailer  = errors.New("tacacs: body has octets after its last field")
	ErrArgCount     = errors.New("tacacs: more arguments than this reader will read")
	ErrArgEmpty     = errors.New("tacacs: zero-length argument")
	ErrArgSeparator = errors.New("tacacs: argument has no separator")
	ErrText         = errors.New("tacacs: field carries control characters")
)

// ParseHeader reads the fixed header.
//
// Three things are refused here rather than later. A major version that
// is not 0xc is not this protocol. A sequence number of zero is not a
// packet in any session -- the standard starts at 1 -- and admitting one
// would give a relay a session it could not pair. And a length past
// MaxBody is refused before anything is allocated for it, which is the
// only place that check is worth anything.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderBytes {
		return Header{}, ErrShort
	}
	h := Header{
		VersionMajor: b[0] >> 4,
		VersionMinor: b[0] & 0x0f,
		Type:         Type(b[1]),
		Seq:          b[2],
		Flags:        b[3],
		SessionID:    binary.BigEndian.Uint32(b[4:8]),
	}
	if h.VersionMajor != VersionMajor {
		return Header{}, ErrVersion
	}
	if h.Seq == 0 {
		return Header{}, ErrZeroSeq
	}
	n := binary.BigEndian.Uint32(b[8:12])
	if n > MaxBody {
		return Header{}, ErrLength
	}
	h.Length = int(n)
	return h, nil
}

// Marshal writes a header back out, which a relay needs because it
// re-obfuscates every packet it forwards: the two legs may have different
// keys, and a refusal it writes itself has to look like a server's.
func (h Header) Marshal() []byte {
	b := make([]byte, HeaderBytes)
	b[0] = h.VersionMajor<<4 | h.VersionMinor&0x0f
	b[1] = byte(h.Type)
	b[2] = h.Seq
	b[3] = h.Flags
	binary.BigEndian.PutUint32(b[4:8], h.SessionID)
	binary.BigEndian.PutUint32(b[8:12], uint32(h.Length)) //nolint:gosec // ParseHeader bounds Length at MaxBody, and a built header sets it from a body
	return b
}

// Obfuscate applies RFC 8907 §4.5's pad to a body, in place, and returns
// the same slice.
//
// It is its own inverse, which is the whole of the construction: the pad
// is a chain of MD5 digests over the session identifier, the key, the
// version octet and the sequence number, and the body is XORed with it.
// So de-obfuscating a packet that arrived and obfuscating one about to be
// sent are the same call, and a relay that re-keys between its two legs
// calls it twice.
//
// An empty key is a no-op rather than an error: a listener configured
// without a secret reads headers only, and the caller that has no key
// still needs the body it was handed to be the body it was handed.
func Obfuscate(h Header, key, body []byte) []byte {
	if len(key) == 0 || len(body) == 0 {
		return body
	}
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], h.SessionID)
	ver := h.VersionMajor<<4 | h.VersionMinor&0x0f
	var prev []byte
	for off := 0; off < len(body); off += md5.Size {
		d := md5.New() //nolint:gosec // RFC 8907 §4.5 specifies MD5
		d.Write(sid[:])
		d.Write(key)
		d.Write([]byte{ver, h.Seq})
		d.Write(prev)
		prev = d.Sum(nil)
		for i := 0; i < md5.Size && off+i < len(body); i++ {
			body[off+i] ^= prev[i]
		}
	}
	return body
}

// Deobfuscated returns a readable copy of a body: the body itself when
// the unencrypted flag is set, and the de-obfuscated copy otherwise.
//
// The copy is the point. A relay forwards the octets it received -- it
// cannot re-sign or re-pad them without the other leg's key, and on the
// same key it should forward exactly what arrived -- so the parse must
// not happen in the buffer that is about to be written on.
func Deobfuscated(h Header, key, body []byte) []byte {
	out := make([]byte, len(body))
	copy(out, body)
	if h.Unencrypted() {
		return out
	}
	return Obfuscate(h, key, out)
}

// text reads a field that the standard says is printable, refusing the
// control characters it has no business carrying.
//
// This is stricter than the standard requires and deliberately so. A
// user name or a command with a newline in it is a second line in
// somebody's log file, and a command with an escape sequence in it is a
// terminal that does what the sequence says when an operator reads the
// record back. Both are refused at the parse, so no part of this project
// is holding one.
func text(b []byte) (string, error) {
	for _, c := range b {
		if c < 0x20 || c == 0x7f {
			return "", ErrText
		}
	}
	return string(b), nil
}
