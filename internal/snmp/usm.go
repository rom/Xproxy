package snmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:staticcheck,gosec // RFC 3414's privacy protocol is DES-CBC; reading it is the point
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // RFC 3414's HMAC-MD5-96 is what the installed base speaks
	"crypto/sha1" //nolint:gosec // and HMAC-SHA-96 beside it
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// The user security model, read rather than trusted.
//
// Version 3 is the one version of this protocol with real security in it: a
// keyed digest over the whole message and, at authPriv, a privacy layer over
// the scoped PDU. Until this file existed, a relay could see the *header* of
// such a message -- the user name, the engine, the security level -- and
// nothing else, so a policy about what was being read or written could not
// be applied to it at all. A v3 message was either refused for being
// unreadable or forwarded unexamined.
//
// With the user's key, it can be both verified and read. What this file does
// *not* do is write: the message forwarded to the agent is the octets that
// arrived, byte for byte. There is no re-encryption and no re-signing, so
// there is no way for this relay to corrupt a message it did not understand,
// and no reason for it to hold a key the agent does not already share with
// the manager.
//
// The cryptography is old and some of it is weak. HMAC-MD5-96 and DES-CBC
// are what the installed base speaks, and a relay that refused to read them
// would be a relay that cannot police the traffic that actually exists; the
// listener's own policy is where an operator says that authPriv with AES is
// the minimum. Reading a weak algorithm is not endorsing it.

// AuthAlgo is a USM authentication protocol.
type AuthAlgo string

// The authentication protocols: RFC 3414's two and RFC 7860's four.
const (
	AuthMD5    AuthAlgo = "md5"
	AuthSHA1   AuthAlgo = "sha1"
	AuthSHA224 AuthAlgo = "sha224"
	AuthSHA256 AuthAlgo = "sha256"
	AuthSHA384 AuthAlgo = "sha384"
	AuthSHA512 AuthAlgo = "sha512"
)

// PrivAlgo is a USM privacy protocol.
type PrivAlgo string

// The privacy protocols: RFC 3414's DES and RFC 3826's AES, with the two
// wider AES variants the installed base also uses.
const (
	PrivDES    PrivAlgo = "des"
	PrivAES128 PrivAlgo = "aes128"
	PrivAES192 PrivAlgo = "aes192"
	PrivAES256 PrivAlgo = "aes256"
)

// AuthAlgos and PrivAlgos are the names configuration accepts.
var (
	AuthAlgos = []AuthAlgo{AuthMD5, AuthSHA1, AuthSHA224, AuthSHA256, AuthSHA384, AuthSHA512}
	PrivAlgos = []PrivAlgo{PrivDES, PrivAES128, PrivAES192, PrivAES256}
)

// AuthAlgoOf reads an authentication protocol name.
func AuthAlgoOf(s string) (AuthAlgo, bool) {
	want := AuthAlgo(strings.ToLower(strings.ReplaceAll(s, "-", "")))
	for _, a := range AuthAlgos {
		if a == want {
			return a, true
		}
	}
	return "", false
}

// PrivAlgoOf reads a privacy protocol name.
func PrivAlgoOf(s string) (PrivAlgo, bool) {
	want := PrivAlgo(strings.ToLower(strings.ReplaceAll(s, "-", "")))
	for _, p := range PrivAlgos {
		if p == want {
			return p, true
		}
	}
	return "", false
}

// Errors this file returns.
var (
	// ErrAuth is a digest that does not check out: the message was not
	// written by somebody holding the key.
	ErrAuth = errors.New("snmp: authentication failed")
	// ErrNoAuthParams is an authenticated message with no digest in it, or
	// one whose digest is the wrong length for its protocol.
	ErrNoAuthParams = errors.New("snmp: no usable authentication parameters")
	// ErrPrivParams is a privacy salt that is not eight octets.
	ErrPrivParams = errors.New("snmp: privacy parameters are not a salt")
	// ErrKeyLength is a localised key too short for the privacy protocol
	// asked for, which is the AES-192 and AES-256 case on a short hash.
	ErrKeyLength = errors.New("snmp: the localised key is too short for this privacy protocol")
	// ErrCiphertext is a privacy blob that is not a whole number of
	// blocks, or is empty.
	ErrCiphertext = errors.New("snmp: the encrypted scoped PDU is not a whole number of blocks")
)

// NewHash is the hash function behind an authentication protocol, or nil for
// a name that is not one. It is exported because a caller that has to compute
// this protocol's keyed digest -- a test, or a tool that checks a capture --
// needs the same hash this file uses, and picking it from the name again
// somewhere else is how the two come to disagree.
func (a AuthAlgo) NewHash() func() hash.Hash {
	switch a {
	case AuthMD5:
		return md5.New
	case AuthSHA1:
		return sha1.New
	case AuthSHA224:
		return sha256.New224
	case AuthSHA256:
		return sha256.New
	case AuthSHA384:
		return sha512.New384
	case AuthSHA512:
		return sha512.New
	}
	return nil
}

// DigestLen is how many octets of the HMAC go on the wire. RFC 3414
// truncates to 96 bits; RFC 7860 truncates each of its four to half the
// hash, which is what "HMAC-SHA-256-192" means.
func (a AuthAlgo) DigestLen() int {
	switch a {
	case AuthMD5, AuthSHA1:
		return 12
	case AuthSHA224:
		return 16
	case AuthSHA256:
		return 24
	case AuthSHA384:
		return 32
	case AuthSHA512:
		return 48
	}
	return 0
}

// KeyLen is the length of a localised key, which is the hash's own output.
func (a AuthAlgo) KeyLen() int {
	h := a.NewHash()
	if h == nil {
		return 0
	}
	return h().Size()
}

// KeyLen is how many octets of the localised key a privacy protocol uses.
func (p PrivAlgo) KeyLen() int {
	switch p {
	case PrivDES:
		// Eight for the key and eight more for the pre-initialisation
		// vector, which is what RFC 3414 §8.1.1.1 makes of the first
		// sixteen octets.
		return 16
	case PrivAES128:
		return 16
	case PrivAES192:
		return 24
	case PrivAES256:
		return 32
	}
	return 0
}

// PasswordToKey turns a pass phrase into the key for one engine, which is
// RFC 3414 §2.6 in two steps.
//
// The first is deliberately expensive: the pass phrase is repeated until a
// megabyte of it has gone through the hash, so that a dictionary attack on
// the key costs a megabyte of hashing per candidate rather than one block.
// The second localises the result to one engine, so that a key learned from
// one device is not a key for another.
func PasswordToKey(a AuthAlgo, password string, engineID []byte) []byte {
	newHash := a.NewHash()
	if newHash == nil || password == "" {
		return nil
	}
	h := newHash()
	// A megabyte of the pass phrase, repeated. The chunking is the
	// standard's own: sixty-four octets at a time, continuing round the
	// pass phrase rather than restarting it.
	var chunk [64]byte
	at := 0
	for written := 0; written < 1<<20; written += len(chunk) {
		for i := range chunk {
			chunk[i] = password[at%len(password)]
			at++
		}
		h.Write(chunk[:])
	}
	ku := h.Sum(nil)
	// And localised: H(Ku || engineID || Ku).
	local := newHash()
	local.Write(ku)
	local.Write(engineID)
	local.Write(ku)
	return local.Sum(nil)
}

// Verify checks the digest of an authenticated message.
//
// The digest covers the whole message with the digest field itself zeroed,
// which is what makes it verifiable by anybody holding the key: the field is
// at a known place and a known length, and everything else -- including the
// engine's clock and the user name -- is inside the computation.
func Verify(m *Message, key []byte, a AuthAlgo) error {
	if m == nil || m.V3 == nil {
		return ErrAuth
	}
	h := a.NewHash()
	if h == nil {
		return ErrAuth
	}
	want := m.V3.AuthParams
	n := a.DigestLen()
	if len(want) != n || m.V3.AuthParamsAt <= 0 || m.V3.AuthParamsAt+n > len(m.Raw) {
		return ErrNoAuthParams
	}
	// The message with the digest field zeroed, on a copy: the octets that
	// go to the agent are the octets that arrived.
	zeroed := make([]byte, len(m.Raw))
	copy(zeroed, m.Raw)
	for i := m.V3.AuthParamsAt; i < m.V3.AuthParamsAt+n; i++ {
		zeroed[i] = 0
	}
	mac := hmac.New(h, key)
	mac.Write(zeroed)
	if !hmac.Equal(mac.Sum(nil)[:n], want) {
		return ErrAuth
	}
	return nil
}

// Decrypt reads the scoped PDU of an authPriv message.
//
// The key is the *privacy* key, localised the same way the authentication
// key is and truncated to what the cipher takes. The salt and the engine's
// clock make the initialisation vector, which is why a message carries both.
func Decrypt(m *Message, key []byte, p PrivAlgo) ([]byte, error) {
	if m == nil || m.V3 == nil || len(m.V3.Ciphertext) == 0 {
		return nil, ErrCiphertext
	}
	if n := p.KeyLen(); len(key) < n {
		return nil, fmt.Errorf("%w: %s needs %d octets and the key is %d", ErrKeyLength, p, n, len(key))
	}
	// The salt is eight octets in both protocols: exclusive-ored with half
	// the DES key to make that cipher's initialisation vector, and the
	// second half of AES's. A shorter one would be read past in the first
	// case and would make a short vector in the second, both of which panic,
	// so the length is checked before either cipher sees it.
	if len(m.V3.PrivParams) != 8 {
		return nil, ErrPrivParams
	}
	if p == PrivDES {
		return decryptDES(m.V3.Ciphertext, key, m.V3.PrivParams)
	}
	return decryptAES(m.V3.Ciphertext, key[:p.KeyLen()], m.V3)
}

// decryptDES is RFC 3414 §8.1.1.2: the first eight octets of the key are the
// DES key, the next eight are exclusive-ored with the salt to make the
// initialisation vector, and the mode is CBC.
func decryptDES(ct, key, salt []byte) ([]byte, error) {
	// A cipher-block chain is decrypted a block at a time, so a length that
	// is not a whole number of blocks is not decryptable -- and passing one
	// to CryptBlocks is a panic, not an error.
	if len(ct)%des.BlockSize != 0 {
		return nil, ErrCiphertext
	}
	block, err := des.NewCipher(key[:8]) //nolint:gosec // the protocol's own cipher
	if err != nil {
		return nil, err
	}
	iv := make([]byte, des.BlockSize)
	for i := range iv {
		iv[i] = key[8+i] ^ salt[i]
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	// The padding is not length-prefixed and not checked: RFC 3414 pads to
	// the block size with whatever the sender liked, and the BER length
	// inside says where the scoped PDU ends. Trimming on a padding byte
	// would be trimming on a value an attacker chose.
	return out, nil
}

// decryptAES is RFC 3826: AES in counter-feedback mode, with the engine's
// boots and time as the first eight octets of the initialisation vector and
// the salt as the other eight.
func decryptAES(ct, key []byte, h *V3Header) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 0, 16)
	iv = binary.BigEndian.AppendUint32(iv, uint32(h.EngineBoots)) //nolint:gosec // a clock counter, bounded by the parse
	iv = binary.BigEndian.AppendUint32(iv, uint32(h.EngineTime))  //nolint:gosec // and likewise
	iv = append(iv, h.PrivParams...)
	out := make([]byte, len(ct))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, ct) //nolint:staticcheck // RFC 3826 is CFB
	return out, nil
}

// Scoped is a scoped PDU: which engine and which context the PDU is for,
// and the PDU.
type Scoped struct {
	ContextEngineID []byte
	ContextName     string
	PDU             *PDU
}

// ParseScoped reads a scoped PDU, which is what decryption leaves behind.
//
// The octets after the PDU are ignored rather than refused: a privacy layer
// pads to the cipher's block size, so a decrypted scoped PDU is followed by
// whatever the sender used to pad it.
func ParseScoped(b []byte) (*Scoped, error) {
	r := &reader{b: b}
	se, err := r.expect(TagSequence)
	if err != nil {
		return nil, err
	}
	in, err := r.sub(se)
	if err != nil {
		return nil, err
	}
	ee, err := in.expect(TagOctetStr)
	if err != nil {
		return nil, err
	}
	if len(ee.body) > 32 {
		return nil, fmt.Errorf("%w: context engine id is %d octets", ErrTruncated, len(ee.body))
	}
	ne, err := in.expect(TagOctetStr)
	if err != nil {
		return nil, err
	}
	if len(ne.body) > MaxCommunity {
		return nil, ErrCommunity
	}
	s := &Scoped{ContextEngineID: ee.body, ContextName: string(ne.body)}
	if s.PDU, err = parsePDU(in); err != nil {
		return nil, err
	}
	return s, nil
}
