package rfb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// VeNCrypt is the open way to put RFB inside TLS. It is a security
// type (19) whose negotiation chooses a subtype, and the subtypes name
// a transport and an authentication together: whether the connection
// moves to TLS, whether the certificate is anonymous or X.509, and
// what happens inside it.
//
// It matters here because it is the only TLS negotiation in this
// protocol with a published specification. The older anonymous-TLS
// type (18) is simpler and weaker -- anonymous Diffie-Hellman with no
// certificate to check, so nothing is authenticated and an active
// attacker is unhindered -- and the vendors' own encrypted types are
// not specified at all.

// The VeNCrypt version this proxy speaks. 0.2 is what every
// implementation in use negotiates.
var VeNCrypt02 = Version{0, 2}

// VeNCrypt subtypes.
const (
	VeNCryptPlain     = 256 // no TLS, a username and password in clear
	VeNCryptTLSNone   = 257 // anonymous TLS, no further authentication
	VeNCryptTLSVnc    = 258 // anonymous TLS, then the DES challenge
	VeNCryptTLSPlain  = 259 // anonymous TLS, then a username and password
	VeNCryptX509None  = 260 // X.509 TLS, no further authentication
	VeNCryptX509Vnc   = 261 // X.509 TLS, then the DES challenge
	VeNCryptX509Plain = 262 // X.509 TLS, then a username and password
)

var subtypeNames = map[uint32]string{
	VeNCryptPlain: "plain", VeNCryptTLSNone: "tls-none", VeNCryptTLSVnc: "tls-vnc",
	VeNCryptTLSPlain: "tls-plain", VeNCryptX509None: "x509-none",
	VeNCryptX509Vnc: "x509-vnc", VeNCryptX509Plain: "x509-plain",
}

var subtypeByName = func() map[string]uint32 {
	m := make(map[string]uint32, len(subtypeNames))
	for b, n := range subtypeNames {
		m[n] = b
	}
	return m
}()

// SubtypeName is a subtype's name, or its number.
func SubtypeName(t uint32) string {
	if n, ok := subtypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("subtype-%d", t)
}

// SubtypeByName looks a name up, for reading a configuration.
func SubtypeByName(s string) (uint32, bool) {
	t, ok := subtypeByName[s]
	return t, ok
}

// UsesTLS reports whether a subtype moves the connection into TLS.
func UsesTLS(t uint32) bool {
	switch t {
	case VeNCryptTLSNone, VeNCryptTLSVnc, VeNCryptTLSPlain,
		VeNCryptX509None, VeNCryptX509Vnc, VeNCryptX509Plain:
		return true
	}
	return false
}

// UsesX509 reports whether a subtype requires a certificate that can
// be checked, rather than an anonymous key exchange.
func UsesX509(t uint32) bool {
	switch t {
	case VeNCryptX509None, VeNCryptX509Vnc, VeNCryptX509Plain:
		return true
	}
	return false
}

// AuthAfterTLS is the authentication a subtype does once the tunnel is
// up: SecNone, SecVNCAuth, or SecPlain for a username and password.
const SecPlain = 0xFF // not a wire value; names the plain authentication

func AuthAfterTLS(t uint32) uint8 {
	switch t {
	case VeNCryptTLSNone, VeNCryptX509None:
		return SecNone
	case VeNCryptTLSVnc, VeNCryptX509Vnc:
		return SecVNCAuth
	case VeNCryptPlain, VeNCryptTLSPlain, VeNCryptX509Plain:
		return SecPlain
	}
	return SecInvalid
}

// MaxSubtypes bounds a subtype list.
const MaxSubtypes = 255

var ErrVeNCryptVersion = errors.New("rfb: the peer's VeNCrypt version is not 0.2")

// ReadVeNCryptVersion reads the two byte version a VeNCrypt server
// sends once its security type is chosen.
func ReadVeNCryptVersion(r io.Reader) (Version, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Version{}, err
	}
	return Version{int(b[0]), int(b[1])}, nil
}

// VeNCryptVersion renders it.
func VeNCryptVersion(v Version) []byte {
	return []byte{uint8(v.Major), uint8(v.Minor)} //nolint:gosec // 0..255 by construction
}

// ReadSubtypes reads the subtype list a server offers.
func ReadSubtypes(r io.Reader) ([]uint32, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	if n[0] == 0 {
		return nil, errors.New("rfb: the peer offered no VeNCrypt subtypes")
	}
	raw := make([]byte, int(n[0])*4)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, err
	}
	out := make([]uint32, n[0])
	for i := range out {
		out[i] = binary.BigEndian.Uint32(raw[i*4:])
	}
	return out, nil
}

// Subtypes renders the list.
func Subtypes(types []uint32) []byte {
	out := make([]byte, 0, 1+len(types)*4)
	out = append(out, uint8(len(types))) //nolint:gosec // bounded by the caller
	for _, t := range types {
		out = binary.BigEndian.AppendUint32(out, t)
	}
	return out
}

// ReadSubtypeChoice reads the four byte subtype a client chose.
func ReadSubtypeChoice(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// Plain renders VeNCrypt's plain credentials: both lengths first, then
// both values. That framing is the subtype's own and not RFB's usual
// length-prefixed string, so it has a function rather than two calls
// to String.
func Plain(user, secret string) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(user)))  //nolint:gosec // callers pass bounded text
	out = binary.BigEndian.AppendUint32(out, uint32(len(secret))) //nolint:gosec // callers pass bounded text
	out = append(out, user...)
	return append(out, secret...)
}

// ReadPlain reads them, refusing either field longer than max before
// anything is allocated.
func ReadPlain(r io.Reader, max uint32) (string, string, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", "", err
	}
	ulen := binary.BigEndian.Uint32(b[0:4])
	plen := binary.BigEndian.Uint32(b[4:8])
	if ulen > max || plen > max {
		return "", "", fmt.Errorf("rfb: plain credential of %d and %d bytes, over the %d bound", ulen, plen, max)
	}
	buf := make([]byte, ulen+plen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", "", err
	}
	return string(buf[:ulen]), string(buf[ulen:]), nil
}

// ClientInit is the one byte a client sends once security is done:
// whether it will share the desktop with other clients.
type ClientInit struct{ Shared bool }

// ReadClientInit reads it.
func ReadClientInit(r io.Reader) (ClientInit, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return ClientInit{}, err
	}
	return ClientInit{Shared: b[0] != 0}, nil
}

// Encode renders it.
func (c ClientInit) Encode() []byte {
	if c.Shared {
		return []byte{1}
	}
	return []byte{0}
}

// ServerInit is what a server answers with: the framebuffer size, its
// pixel format, and the desktop's name.
type ServerInit struct {
	Width, Height uint16
	// PixelFormat is the sixteen bytes of RFC 6143 section 7.4,
	// carried as they arrived: a gateway relays them and does not
	// decode pixels.
	PixelFormat [16]byte
	Name        string
}

// serverInitHead is the fixed part of a ServerInit: two 16 bit
// dimensions, the sixteen byte pixel format, and the name's length
// (RFC 6143 section 7.3.2).
const serverInitHead = 2 + 2 + 16 + 4

// ReadServerInit reads it, bounding the name before it is allocated.
func ReadServerInit(r io.Reader) (ServerInit, error) {
	var head [serverInitHead]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return ServerInit{}, err
	}
	var si ServerInit
	si.Width = binary.BigEndian.Uint16(head[0:])
	si.Height = binary.BigEndian.Uint16(head[2:])
	copy(si.PixelFormat[:], head[4:20])
	n := binary.BigEndian.Uint32(head[20:24])
	if n > MaxName {
		return ServerInit{}, fmt.Errorf("rfb: desktop name of %d bytes, over the %d bound", n, MaxName)
	}
	if n > 0 {
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return ServerInit{}, err
		}
		si.Name = string(b)
	}
	return si, nil
}

// Encode renders a ServerInit.
func (s ServerInit) Encode() []byte {
	out := binary.BigEndian.AppendUint16(nil, s.Width)
	out = binary.BigEndian.AppendUint16(out, s.Height)
	out = append(out, s.PixelFormat[:]...)
	return append(out, String(s.Name)...)
}
