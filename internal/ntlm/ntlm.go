// Package ntlm implements the client half of NTLM version 2, as
// MS-NLMP specifies it.
//
// It is here because network level authentication towards a Windows
// desktop needs it: CredSSP carries NTLM tokens, and a gateway that
// opens a desktop with its own account has to be able to produce
// them. Nothing else in this proxy should reach for it -- NTLM is a
// protocol to talk to Windows with, not one to choose.
//
// What it does not do. There is no server half: this package proves a
// credential, it never checks one. That is deliberate. Checking an
// NTLM response means holding the password hash of whoever is
// connecting, and a gateway that held those would be a better target
// than the desktops behind it.
package ntlm

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // the protocol specifies MD5
	"crypto/rand"
	"crypto/rc4" //nolint:gosec // the protocol specifies RC4
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	//nolint:staticcheck,gosec // MD4 is what NTLM derives its key with; there is no other version of the protocol
	"golang.org/x/crypto/md4"
)

// ErrNTLM is a message this package cannot make sense of.
var ErrNTLM = errors.New("ntlm")

// signature opens every message, followed by the message type.
var signature = []byte("NTLMSSP\x00")

const (
	typeNegotiate    = 1
	typeChallenge    = 2
	typeAuthenticate = 3
)

// The negotiate flags of MS-NLMP 2.2.2.5 that this package sets or
// reads.
const (
	NegotiateUnicode            = 0x00000001
	NegotiateOEM                = 0x00000002
	RequestTarget               = 0x00000004
	NegotiateSign               = 0x00000010
	NegotiateSeal               = 0x00000020
	NegotiateNTLM               = 0x00000200
	NegotiateAlwaysSign         = 0x00008000
	NegotiateExtendedSessionSec = 0x00080000
	NegotiateTargetInfo         = 0x00800000
	NegotiateVersion            = 0x02000000
	Negotiate128                = 0x20000000
	NegotiateKeyExch            = 0x40000000
	Negotiate56                 = 0x80000000
)

// clientFlags are what this package asks for: a session that is
// signed and sealed with the strongest keys available, which is what
// CredSSP needs in order to protect the credential it carries.
const clientFlags = NegotiateUnicode | RequestTarget | NegotiateSign | NegotiateSeal |
	NegotiateNTLM | NegotiateAlwaysSign | NegotiateExtendedSessionSec |
	NegotiateKeyExch | Negotiate128 | Negotiate56

// maxField bounds a length a peer chose, before anything is allocated
// for it. The descriptors are sixteen bit, so this is a policy rather
// than the format's ceiling: a target name and an attribute list are
// hundreds of bytes, and a server sending megabytes of either is not
// one to authenticate to.
const maxField = 8 << 10

// Negotiate renders the first message.
func Negotiate() []byte {
	out := append(append([]byte(nil), signature...), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[8:12], typeNegotiate)
	out = binary.LittleEndian.AppendUint32(out, clientFlags)
	// Empty domain and workstation fields: their lengths, and offsets
	// past the end of the fixed part.
	out = append(out, make([]byte, 16)...)
	return out
}

// Challenge is the server's answer, as far as this package reads it.
type Challenge struct {
	// Flags is what the server agreed to.
	Flags uint32
	// ServerChallenge is the eight bytes the response is computed
	// over.
	ServerChallenge []byte
	// TargetInfo is the attribute list, carried into the response as
	// it arrived: it binds the response to this server.
	TargetInfo []byte
	// TargetName is what the server calls itself, for the log.
	TargetName string
	// raw is the message as it arrived. The integrity check in the
	// third message is over the bytes of all three, so the ones that
	// came in are what it has to be computed from rather than a
	// re-encoding of them.
	raw []byte
}

// ParseChallenge reads it.
func ParseChallenge(b []byte) (*Challenge, error) {
	if len(b) < 48 {
		return nil, fmt.Errorf("%w: a challenge of %d bytes", ErrNTLM, len(b))
	}
	if string(b[:8]) != string(signature) || binary.LittleEndian.Uint32(b[8:12]) != typeChallenge {
		return nil, fmt.Errorf("%w: not a challenge message", ErrNTLM)
	}
	c := &Challenge{Flags: binary.LittleEndian.Uint32(b[20:24]), raw: append([]byte(nil), b...)}
	name, err := field(b, 12)
	if err != nil {
		return nil, err
	}
	c.TargetName = decodeUTF16(name)
	c.ServerChallenge = append([]byte(nil), b[24:32]...)
	info, err := field(b, 40)
	if err != nil {
		return nil, err
	}
	c.TargetInfo = append([]byte(nil), info...)
	return c, nil
}

// field reads one of the length-and-offset descriptors the format uses
// for its variable parts.
func field(b []byte, at int) ([]byte, error) {
	if at+8 > len(b) {
		return nil, fmt.Errorf("%w: a field descriptor past the message", ErrNTLM)
	}
	n := int(binary.LittleEndian.Uint16(b[at : at+2]))
	off := int(binary.LittleEndian.Uint32(b[at+4 : at+8]))
	if n > maxField {
		return nil, fmt.Errorf("%w: a field of %d bytes", ErrNTLM, n)
	}
	if n == 0 {
		return nil, nil
	}
	if off < 0 || off+n > len(b) {
		return nil, fmt.Errorf("%w: a field of %d bytes at %d of %d", ErrNTLM, n, off, len(b))
	}
	return b[off : off+n], nil
}

// Session is what an exchange leaves behind: the keys that sign and
// seal what follows.
type Session struct {
	// ExportedSessionKey is what the signing and sealing keys are
	// derived from, and what a caller needs if it derives more.
	ExportedSessionKey []byte
	// The keys this end writes with, and the ones it reads with. Which
	// pair is which is decided by the role.
	clientSigning []byte
	serverSigning []byte
	clientSeal    *rc4.Cipher
	serverSeal    *rc4.Cipher
	clientSeq     uint32
	serverSeq     uint32
}

// Credential is who to authenticate as.
type Credential struct {
	Domain   string
	User     string
	Password string
	// Workstation is what this end calls itself. Windows accepts an
	// empty one; a name is kinder to whoever reads the logs.
	Workstation string
}

// Authenticate answers a challenge and returns the message to send
// with the session it establishes.
func Authenticate(c *Challenge, cred Credential) ([]byte, *Session, error) {
	if c == nil || len(c.ServerChallenge) != 8 {
		return nil, nil, fmt.Errorf("%w: no server challenge to answer", ErrNTLM)
	}
	if c.Flags&NegotiateExtendedSessionSec == 0 {
		// Without extended session security the session keys are the
		// weaker construction of NTLM version 1, and CredSSP's
		// protection of the credential rests on them. A server that
		// will not do it is a server not to send a credential to.
		return nil, nil, fmt.Errorf("%w: the server did not offer extended session security", ErrNTLM)
	}
	ntowf := ntowfv2(cred.User, cred.Domain, cred.Password)

	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, nil, err
	}
	temp := ntlmv2Temp(clientChallenge, c.TargetInfo)
	proof := hmacMD5(ntowf, concat(c.ServerChallenge, temp))
	ntResponse := concat(proof, temp)
	sessionBaseKey := hmacMD5(ntowf, proof)

	exported := make([]byte, 16)
	if _, err := rand.Read(exported); err != nil {
		return nil, nil, err
	}
	sealed, err := rc4Once(sessionBaseKey, exported)
	if err != nil {
		return nil, nil, err
	}

	msg, micAt := buildAuthenticate(cred, ntResponse, sealed, c.Flags)
	// The integrity check covers all three messages, so a peer cannot
	// have rewritten the first two.
	mic := hmacMD5(exported, concat(Negotiate(), rawChallenge(c), msg))
	copy(msg[micAt:micAt+16], mic)

	s, err := newSession(exported)
	if err != nil {
		return nil, nil, err
	}
	return msg, s, nil
}

// rawChallenge re-renders the challenge for the integrity check. The
// check is over the bytes that arrived, so the caller keeps them.
func rawChallenge(c *Challenge) []byte { return c.raw }

// ntlmv2Temp is the blob the response is built around: a version, a
// timestamp, this end's challenge and the server's own attribute list.
func ntlmv2Temp(clientChallenge, targetInfo []byte) []byte {
	out := []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0}
	// Windows time: hundreds of nanoseconds since 1601.
	const epochDelta = 116444736000000000
	out = binary.LittleEndian.AppendUint64(out, uint64(time.Now().UnixNano()/100+epochDelta)) //nolint:gosec // a time in this century
	out = append(out, clientChallenge...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, targetInfo...)
	return append(out, 0, 0, 0, 0)
}

// ntowfv2 is the key everything else is derived from: the MD4 of the
// password, keyed over the name and domain.
func ntowfv2(user, domain, password string) []byte {
	h := md4.New() //nolint:gosec // the protocol specifies MD4
	h.Write(encodeUTF16(password))
	return hmacMD5(h.Sum(nil), encodeUTF16(strings.ToUpper(user)+domain))
}

// buildAuthenticate renders the third message and says where its
// integrity check goes.
func buildAuthenticate(cred Credential, ntResponse, sealedKey []byte, flags uint32) ([]byte, int) {
	domain := encodeUTF16(cred.Domain)
	user := encodeUTF16(cred.User)
	host := encodeUTF16(cred.Workstation)
	// The fixed part: the header, six field descriptors, the flags,
	// the version and the integrity check.
	const fixed = 8 + 4 + 6*8 + 4 + 8 + 16
	var payload []byte
	descriptor := func(b []byte) []byte {
		off := fixed + len(payload)
		payload = append(payload, b...)
		d := make([]byte, 8)
		binary.LittleEndian.PutUint16(d[0:2], uint16(len(b))) //nolint:gosec // bounded by the caller's fields
		binary.LittleEndian.PutUint16(d[2:4], uint16(len(b))) //nolint:gosec // the same
		binary.LittleEndian.PutUint32(d[4:8], uint32(off))    //nolint:gosec // bounded by the message
		return d
	}
	// An empty LM response: NTLM version 2 does not use one, and
	// sending the old one back would be a downgrade to offer.
	lm := descriptor(make([]byte, 24))
	nt := descriptor(ntResponse)
	dom := descriptor(domain)
	usr := descriptor(user)
	ws := descriptor(host)
	key := descriptor(sealedKey)

	out := append(append([]byte(nil), signature...), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[8:12], typeAuthenticate)
	out = append(out, lm...)
	out = append(out, nt...)
	out = append(out, dom...)
	out = append(out, usr...)
	out = append(out, ws...)
	out = append(out, key...)
	out = binary.LittleEndian.AppendUint32(out, flags&clientFlags|NegotiateVersion)
	// A version, which the integrity check is defined to include.
	out = append(out, 10, 0, 0, 0, 0, 0, 0, 15)
	micAt := len(out)
	out = append(out, make([]byte, 16)...)
	return append(out, payload...), micAt
}

// Role says which end of a session a Session is. The four keys are not
// symmetric -- each direction has its own signing and sealing key --
// so which pair a Session writes with is what its role decides.
type Role int

const (
	// RoleClient writes with the client-to-server keys and reads with
	// the others, which is what this package's own exchange produces.
	RoleClient Role = iota
	// RoleServer is the other way round. This package does not
	// authenticate anyone, but the session layer is symmetric and the
	// far end's view of one is worth being able to construct.
	RoleServer
)

// NewSession derives the four keys of a session from its exported key
// and returns the view one end has of it.
func NewSession(exported []byte, role Role) (*Session, error) {
	s := &Session{ExportedSessionKey: exported}
	mine, theirs := "client-to-server", "server-to-client"
	if role == RoleServer {
		mine, theirs = theirs, mine
	}
	s.clientSigning = keyFrom(exported, "session key to "+mine+" signing key magic constant\x00")
	s.serverSigning = keyFrom(exported, "session key to "+theirs+" signing key magic constant\x00")
	cs, err := rc4.NewCipher(keyFrom(exported, "session key to "+mine+" sealing key magic constant\x00")) //nolint:gosec // the protocol specifies RC4
	if err != nil {
		return nil, err
	}
	ss, err := rc4.NewCipher(keyFrom(exported, "session key to "+theirs+" sealing key magic constant\x00")) //nolint:gosec // the protocol specifies RC4
	if err != nil {
		return nil, err
	}
	s.clientSeal, s.serverSeal = cs, ss
	return s, nil
}

// newSession is the client's view, which is what an exchange here
// always produces.
func newSession(exported []byte) (*Session, error) { return NewSession(exported, RoleClient) }

func keyFrom(exported []byte, magic string) []byte {
	h := md5.New() //nolint:gosec // the protocol specifies MD5
	h.Write(exported)
	h.Write([]byte(magic))
	return h.Sum(nil)
}

// Seal encrypts a message and returns the signature that goes with it,
// which is what CredSSP puts on the wire.
func (s *Session) Seal(msg []byte) (ciphertext, sig []byte) {
	out := make([]byte, len(msg))
	s.clientSeal.XORKeyStream(out, msg)
	sig = s.sign(s.clientSigning, s.clientSeal, s.clientSeq, msg)
	s.clientSeq++
	return out, sig
}

// Unseal decrypts a message and checks its signature.
func (s *Session) Unseal(ciphertext, sig []byte) ([]byte, error) {
	out := make([]byte, len(ciphertext))
	s.serverSeal.XORKeyStream(out, ciphertext)
	want := s.sign(s.serverSigning, s.serverSeal, s.serverSeq, out)
	s.serverSeq++
	if !hmac.Equal(want, sig) {
		return nil, fmt.Errorf("%w: a message did not authenticate", ErrNTLM)
	}
	return out, nil
}

// SignatureSize is the length of the signature Seal produces.
const SignatureSize = 16

// sign renders the sixteen byte signature: a version, an eight byte
// checksum encrypted with the same stream as the message, and the
// sequence number.
func (s *Session) sign(key []byte, seal *rc4.Cipher, seq uint32, msg []byte) []byte {
	mac := hmacMD5(key, concat(binary.LittleEndian.AppendUint32(nil, seq), msg))[:8]
	enc := make([]byte, 8)
	seal.XORKeyStream(enc, mac)
	out := binary.LittleEndian.AppendUint32(nil, 1)
	out = append(out, enc...)
	return binary.LittleEndian.AppendUint32(out, seq)
}

func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key) //nolint:gosec // the protocol specifies MD5
	h.Write(data)
	return h.Sum(nil)
}

func rc4Once(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key) //nolint:gosec // the protocol specifies RC4
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func encodeUTF16(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

func decodeUTF16(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}
