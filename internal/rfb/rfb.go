// Package rfb reads the Remote Framebuffer protocol (RFC 6143) and the
// parts of its negotiation a gateway has to decide on.
//
// What this package covers is the handshake: the version exchange, the
// security type negotiation, VNC authentication, VeNCrypt, and the
// initialisation messages that follow. That is where every decision a
// proxy makes lives. What comes after -- the framebuffer updates, the
// encodings, the pointer and key events -- is a stream this package
// does not decode, because a gateway does not need to: it records the
// stream and relays it, and decoding pixels would buy nothing but a
// dependency on every encoding a server might choose.
//
// The version and security negotiation are also where the variants
// diverge. RFB is an open protocol with two open security types (none,
// and the DES challenge of RFC 6143 section 7.2.2) and one open way to
// get TLS (VeNCrypt). Everything else in the wild -- RealVNC's RA2 and
// RSA-AES, UltraVNC's MSLogon and its DSM plugins, Apple's, Tight's --
// is a vendor's own, with no published specification this could be
// written against. This package names them so that a policy can decide
// what to do about them, and implements the open ones.
package rfb

import (
	"crypto/des" //nolint:gosec // RFC 6143 section 7.2.2 specifies DES; the choice is the protocol's
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is an RFB protocol version.
type Version struct{ Major, Minor int }

// The versions this proxy speaks. 3.3 has no security list -- the
// server names one type and that is that -- and 3.7 added the list.
// 3.8 added a reason string on a failed security result, which is the
// difference an operator notices.
var (
	V33 = Version{3, 3}
	V37 = Version{3, 7}
	V38 = Version{3, 8}
)

// Supported are the versions this proxy will speak, newest first.
var Supported = []Version{V38, V37, V33}

func (v Version) String() string { return fmt.Sprintf("RFB %03d.%03d", v.Major, v.Minor) }

// AtLeast reports whether v is at or above w.
func (v Version) AtLeast(w Version) bool {
	return v.Major > w.Major || (v.Major == w.Major && v.Minor >= w.Minor)
}

// Handshake is the twelve bytes a version is sent as.
func (v Version) Handshake() []byte {
	return []byte(fmt.Sprintf("RFB %03d.%03d\n", v.Major, v.Minor))
}

var errBadVersion = errors.New("rfb: not a version string")

// ReadVersion reads the twelve byte version handshake.
//
// A peer that sends something else is not speaking RFB, and the only
// answer is to stop: guessing the version from a prefix is how a proxy
// and a server come to disagree about whether a security list follows.
func ReadVersion(r io.Reader) (Version, error) {
	var b [12]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Version{}, err
	}
	return ParseVersion(b[:])
}

// ParseVersion reads the twelve byte form.
func ParseVersion(b []byte) (Version, error) {
	if len(b) != 12 || string(b[:4]) != "RFB " || b[7] != '.' || b[11] != '\n' {
		return Version{}, errBadVersion
	}
	major, err := digits3(b[4:7])
	if err != nil {
		return Version{}, err
	}
	minor, err := digits3(b[8:11])
	if err != nil {
		return Version{}, err
	}
	return Version{major, minor}, nil
}

func digits3(b []byte) (int, error) {
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, errBadVersion
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// Negotiated is the version two peers settle on: the lower of what
// each offers, and never below 3.3, which is the floor RFC 6143
// section 7.1.1 sets.
func Negotiated(client, server Version) (Version, bool) {
	v := server
	if client.AtLeast(server) {
		v = server
	} else {
		v = client
	}
	// Only the three versions with a defined handshake are spoken; a
	// peer announcing 3.4 or 3.889 (which real clients do) is treated
	// as the highest version at or below it.
	switch {
	case v.AtLeast(V38):
		return V38, true
	case v.AtLeast(V37):
		return V37, true
	case v.AtLeast(V33):
		return V33, true
	}
	return Version{}, false
}

// Security types. The numbers are from the IANA registry RFC 6143
// section 7.2 points at, plus the vendors' own.
const (
	SecInvalid   = 0
	SecNone      = 1
	SecVNCAuth   = 2
	SecRA2       = 5  // RealVNC, proprietary
	SecRA2ne     = 6  // RealVNC, proprietary
	SecTight     = 16 // TightVNC, its own sub-negotiation
	SecUltra     = 17 // UltraVNC
	SecTLS       = 18 // anonymous TLS, then a second security type
	SecVeNCrypt  = 19 // the open TLS and X.509 negotiation
	SecSASL      = 20
	SecMD5       = 21
	SecXvp       = 22
	SecARD       = 30  // Apple Remote Desktop
	SecMSLogon2  = 113 // UltraVNC MS-Logon II
	SecRSAAES    = 129 // RealVNC RSA-AES, proprietary
	SecRSAAESne  = 130 // RealVNC RSA-AES unencrypted, proprietary
	SecRSAAES256 = 133 // RealVNC RSA-AES-256, proprietary
)

// securityNames is what an operator writes in a configuration, and
// what a log line says.
var securityNames = map[uint8]string{
	SecNone: "none", SecVNCAuth: "vncauth", SecRA2: "ra2", SecRA2ne: "ra2ne",
	SecTight: "tight", SecUltra: "ultra", SecTLS: "tls", SecVeNCrypt: "vencrypt",
	SecSASL: "sasl", SecMD5: "md5", SecXvp: "xvp", SecARD: "ard",
	SecMSLogon2: "mslogon2", SecRSAAES: "rsa-aes", SecRSAAESne: "rsa-aes-ne",
	SecRSAAES256: "rsa-aes-256",
}

var securityByName = func() map[string]uint8 {
	m := make(map[string]uint8, len(securityNames))
	for b, n := range securityNames {
		m[n] = b
	}
	return m
}()

// SecurityName is a security type's name, or its number.
func SecurityName(t uint8) string {
	if n, ok := securityNames[t]; ok {
		return n
	}
	return fmt.Sprintf("security-%d", t)
}

// SecurityByName looks a name up, for reading a configuration.
func SecurityByName(s string) (uint8, bool) {
	t, ok := securityByName[s]
	return t, ok
}

// Mediated are the security types this proxy understands well enough
// to sit in the middle of: it can complete the handshake on both legs,
// which is what lets it record the session and decide the rest.
//
// none and vncauth are RFC 6143. vencrypt is the open TLS negotiation.
// tls is the older anonymous-TLS type, which VeNCrypt replaced.
var Mediated = map[uint8]bool{
	SecNone: true, SecVNCAuth: true, SecVeNCrypt: true, SecTLS: true,
}

// Reimplemented are the vendors' types this package completes anyway,
// written against published reverse engineering rather than against a
// specification the vendor stands behind. They are opt-in, each one is
// warned about where it is configured, and each says in its own file
// where its details come from and what it is actually worth.
//
// The reason to have them at all is that the desktops exist: an estate
// whose machines speak only one of these is better reached through a
// gateway that records the session and holds the policy than reached
// directly. That is a different claim from the type being secure, and
// the documentation does not make the second one.
var Reimplemented = map[uint8]bool{
	SecMSLogon2: true, SecRSAAES: true, SecRSAAESne: true, SecRSAAES256: true,
	SecTight: true, SecARD: true,
}

// NamesAUser are the types whose credential carries a user name. It
// matters because a second factor needs something to look an enrolment
// up by, and most of RFB carries nothing of the sort: a DES challenge
// proves a shared desktop password and says nothing about who holds
// it. VeNCrypt's plain subtypes are the other place a name appears,
// and they are subtypes rather than types, so they are not here.
var NamesAUser = map[uint8]bool{
	SecMSLogon2: true, SecRSAAES: true, SecRSAAESne: true, SecRSAAES256: true,
	SecARD: true,
}

// Proprietary are the types defined by a vendor rather than by a
// specification and not reimplemented here. A proxy cannot mediate one
// without reimplementing a cipher whose details are not published, so
// the only honest choices are to refuse it or to relay it without
// looking -- which is a session that cannot be recorded, and is a
// decision for an operator rather than for this package.
var Proprietary = map[uint8]bool{
	SecRA2: true, SecRA2ne: true, SecUltra: true,
	SecSASL: true, SecMD5: true, SecXvp: true,
}

// MaxSecurityTypes bounds a security list. A server offering more than
// this is not a server this proxy is going to reach agreement with.
const MaxSecurityTypes = 255

var ErrNoSecurity = errors.New("rfb: the peer offered no security types")

// ReadSecurityList reads the list a 3.7 or later server offers. An
// empty list is a failure, and carries a reason.
func ReadSecurityList(r io.Reader) ([]uint8, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	if n[0] == 0 {
		reason, _ := ReadString(r, MaxReason)
		if reason == "" {
			return nil, ErrNoSecurity
		}
		return nil, fmt.Errorf("%w: %s", ErrNoSecurity, reason)
	}
	types := make([]uint8, n[0])
	if _, err := io.ReadFull(r, types); err != nil {
		return nil, err
	}
	return types, nil
}

// SecurityList renders the list a 3.7 or later server sends.
func SecurityList(types []uint8) []byte {
	out := make([]byte, 0, 1+len(types))
	out = append(out, uint8(len(types))) //nolint:gosec // bounded by the caller
	return append(out, types...)
}

// SecurityFailure renders the empty list and its reason, which is how
// a 3.7 or later server refuses before any type is chosen.
func SecurityFailure(reason string) []byte {
	out := []byte{0}
	return append(out, String(reason)...)
}

// ReadSecurity33 reads the single type a 3.3 server names.
func ReadSecurity33(r io.Reader) (uint8, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	t := binary.BigEndian.Uint32(b[:])
	if t == 0 {
		reason, _ := ReadString(r, MaxReason)
		return 0, fmt.Errorf("%w: %s", ErrNoSecurity, reason)
	}
	if t > 255 {
		return 0, fmt.Errorf("rfb: security type %d is not one byte", t)
	}
	return uint8(t), nil
}

// Security33 renders what a 3.3 server names.
func Security33(t uint8) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(t))
}

// The results of the security handshake (RFC 6143 section 7.2).
const (
	ResultOK     = 0
	ResultFailed = 1
)

// SendsResult says whether a SecurityResult message follows the
// authentication for this version and security type. It does, except
// where RFC 6143 section 7.1.3 says it does not: before 3.8, a
// successful None goes straight to initialisation with nothing in
// between. A proxy that sent one there would put four bytes a viewer
// never reads in front of the ServerInit, and one that waited for one
// from such a server would wait forever.
func SendsResult(v Version, sec uint8) bool {
	return sec != SecNone || v.AtLeast(V38)
}

// SecurityResult renders the result. On 3.8 a failure carries a
// reason, which is the difference between a client that says what went
// wrong and one that says the connection closed.
func SecurityResult(v Version, ok bool, reason string) []byte {
	code := uint32(ResultFailed)
	if ok {
		code = ResultOK
	}
	out := binary.BigEndian.AppendUint32(nil, code)
	if !ok && v.AtLeast(V38) {
		out = append(out, String(reason)...)
	}
	return out
}

// ReadSecurityResult reads the result, and the reason a 3.8 server
// gives with a failure.
func ReadSecurityResult(r io.Reader, v Version) (bool, string, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return false, "", err
	}
	if binary.BigEndian.Uint32(b[:]) == ResultOK {
		return true, "", nil
	}
	if v.AtLeast(V38) {
		reason, _ := ReadString(r, MaxReason)
		return false, reason, nil
	}
	return false, "", nil
}

// MaxReason bounds a reason string, and MaxName a desktop name. Both
// are lengths a peer chooses, so both are bounded before anything is
// allocated.
const (
	MaxReason = 4096
	MaxName   = 4096
)

// String renders a length-prefixed string.
func String(s string) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(s))) //nolint:gosec // callers pass bounded text
	return append(out, s...)
}

// ReadString reads a length-prefixed string, refusing one longer than
// max before it is allocated.
func ReadString(r io.Reader, max uint32) (string, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(b[:])
	if n > max {
		return "", fmt.Errorf("rfb: string of %d bytes, over the %d bound", n, max)
	}
	if n == 0 {
		return "", nil
	}
	s := make([]byte, n)
	if _, err := io.ReadFull(r, s); err != nil {
		return "", err
	}
	return string(s), nil
}

// ChallengeSize is the length of a VNC authentication challenge.
const ChallengeSize = 16

// VNCAuthResponse answers a challenge with a password, as RFC 6143
// section 7.2.2 specifies: the password is truncated or zero-padded to
// eight bytes, each byte's bits are reversed, and the result is the
// DES key the sixteen byte challenge is encrypted with in two blocks.
//
// The bit reversal is not a mistake being reproduced: it is what the
// original implementation did, and every client and server does it, so
// a proxy that did the sensible thing instead would agree with nobody.
func VNCAuthResponse(challenge []byte, password string) ([]byte, error) {
	if len(challenge) != ChallengeSize {
		return nil, fmt.Errorf("rfb: challenge of %d bytes, want %d", len(challenge), ChallengeSize)
	}
	var key [8]byte
	for i := 0; i < 8 && i < len(password); i++ {
		key[i] = reverseBits(password[i])
	}
	block, err := des.NewCipher(key[:]) //nolint:gosec // the protocol specifies DES
	if err != nil {
		return nil, err
	}
	out := make([]byte, ChallengeSize)
	block.Encrypt(out[:8], challenge[:8])
	block.Encrypt(out[8:], challenge[8:])
	return out, nil
}

func reverseBits(b byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		out <<= 1
		out |= (b >> i) & 1
	}
	return out
}
