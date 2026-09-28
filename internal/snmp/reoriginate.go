package snmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // RFC 3414's own cipher, for the agents that only have it
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Building a version 3 message: the other half of reading one.
//
// usm.go verifies and decrypts, so that the ordinary rules can decide about a
// v3 message. That is enough for a relay that forwards the octets it received,
// and it is the reason the rest of this package does not re-encode: a message
// re-encoded is a message the relay and the agent might read differently, and
// on an authenticated one it would break the digest.
//
// This is for the case where forwarding the same octets is the wrong thing.
// Terminating the client's USM session and originating a new one toward the
// agent buys three things that cannot be had otherwise:
//
//   - **Separate credentials.** The manager's pass phrase and the agent's are
//     different secrets. A manager's credential that leaks does not open the
//     agent, and an agent's pass phrase never leaves the relay.
//   - **A level the client could not reach.** A manager that only speaks
//     authNoPriv reaches an authPriv-only agent, with the privacy added here
//     rather than not at all. It is the secure upgrade the other kinds have,
//     on the protocol that needs it most.
//   - **Editing at all.** A bound on max-repetitions, a refusal answered as
//     the agent would answer it: none of it is possible on a message whose
//     digest covers the field being changed.
//
// What it costs is stated rather than hidden: the relay is now a party to the
// security, not a reader of it. Two USM sessions exist, the relay holds both
// sets of keys, and end-to-end authentication between the manager and the
// agent is gone -- which is the point of terminating it and is also exactly
// what an estate must decide it wants.

// Errors this file returns.
var (
	// ErrBuildLevel is a build whose level and keys disagree.
	ErrBuildLevel = errors.New("snmp: security level needs keys that were not given")
	// ErrScoped is a missing or oversize scoped PDU.
	ErrScoped = errors.New("snmp: scoped PDU")
)

// V3Build is a version 3 message to originate.
//
// EngineID, EngineBoots and EngineTime are the *authoritative* engine's --
// the agent's, discovered from it -- because that is whose clock USM's replay
// window is against. Putting this relay's own numbers there would make every
// message a replay to the agent.
type V3Build struct {
	MessageID  int64
	MaxSize    int64
	Reportable bool
	Level      SecurityLevel
	EngineID   []byte
	User       string
	// EngineBoots and EngineTime are the agent's clock as this relay last
	// learned it. They are also half of AES's initialisation vector, which
	// is why a build with privacy needs them to be the agent's and not zero.
	EngineBoots, EngineTime int64
	// Scoped is the encoded scoped PDU: the whole SEQUENCE, contextEngineID
	// and contextName included. ScopedPDU builds one.
	Scoped []byte
	// Auth and AuthKey sign the message; both are needed above
	// noAuthNoPriv. The key is the localised one, from PasswordToKey with
	// the agent's engine identifier.
	Auth    AuthAlgo
	AuthKey []byte
	// Priv and PrivKey encrypt the scoped PDU at authPriv.
	Priv    PrivAlgo
	PrivKey []byte
	// Salt is the privacy salt. Left nil a fresh random one is used, which
	// is what a real originator does; a test sets it to get a fixed
	// message.
	Salt []byte
}

// ScopedPDU encodes a scoped PDU around an already-encoded PDU element.
//
// The context engine identifier is the agent's, as the agent's own responses
// carry it. An empty one is what a manager sends before discovery and what an
// agent accepts as "whichever engine you are".
func ScopedPDU(contextEngineID []byte, contextName string, pdu []byte) ([]byte, error) {
	if len(pdu) == 0 {
		return nil, ErrScoped
	}
	if len(contextName) > MaxCommunity {
		return nil, ErrCommunity
	}
	body := make([]byte, 0, len(pdu)+len(contextEngineID)+len(contextName)+8)
	body = append(body, encodeTLV(TagOctetStr, contextEngineID)...)
	body = append(body, encodeTLV(TagOctetStr, []byte(contextName))...)
	body = append(body, pdu...)
	return encodeTLV(TagSequence, body), nil
}

// BuildV3 originates one version 3 message.
//
// The digest is computed last, over the finished message with its own field
// zeroed, because that is what RFC 3414 s6.3.1 says the digest covers: the
// whole message rather than a list of fields. So the field is written as
// zeroes of the right length, the message is assembled, and the digest
// replaces them in place -- which is also why the length must be right before
// the assembly rather than after it.
func BuildV3(b V3Build) ([]byte, error) {
	if len(b.Scoped) == 0 {
		return nil, ErrScoped
	}
	if len(b.User) > MaxCommunity {
		return nil, ErrCommunity
	}
	digestLen := 0
	if b.Level.Authenticated() {
		if b.Auth.NewHash() == nil {
			return nil, fmt.Errorf("%w: %s needs an authentication algorithm", ErrBuildLevel, b.Level)
		}
		digestLen = b.Auth.DigestLen()
		if n := b.Auth.KeyLen(); len(b.AuthKey) < n {
			return nil, fmt.Errorf("%w: %s needs %d octets and the key is %d",
				ErrKeyLength, b.Auth, n, len(b.AuthKey))
		}
	}

	// The payload: the scoped PDU in the clear, or encrypted with a salt the
	// receiver needs to decrypt it.
	payload, salt := b.Scoped, []byte(nil)
	if b.Level == AuthPriv {
		if n := b.Priv.KeyLen(); n == 0 || len(b.PrivKey) < n {
			return nil, fmt.Errorf("%w: %s needs %d octets and the key is %d",
				ErrKeyLength, b.Priv, n, len(b.PrivKey))
		}
		var err error
		if payload, salt, err = encryptScoped(b); err != nil {
			return nil, err
		}
	}

	// The security parameters, with the digest field zeroed. Its offset
	// inside the finished message is what the signing step needs, and it is
	// computed rather than searched for: searching for a run of zeroes would
	// find whichever run came first.
	zeroes := make([]byte, digestLen)
	sec := make([]byte, 0, 64+len(b.EngineID)+len(b.User)+digestLen+len(salt))
	sec = append(sec, encodeTLV(TagOctetStr, b.EngineID)...)
	sec = append(sec, encodeTLV(TagInteger, encodeInt(b.EngineBoots))...)
	sec = append(sec, encodeTLV(TagInteger, encodeInt(b.EngineTime))...)
	sec = append(sec, encodeTLV(TagOctetStr, []byte(b.User))...)
	authAt := len(sec) + headerLen(digestLen) // inside sec, before wrapping
	sec = append(sec, encodeTLV(TagOctetStr, zeroes)...)
	sec = append(sec, encodeTLV(TagOctetStr, salt)...)
	secSeq := encodeTLV(TagSequence, sec)
	// Wrapped again: the security parameters travel as an OCTET STRING whose
	// contents happen to be a SEQUENCE (RFC 3412 s6.5).
	secField := encodeTLV(TagOctetStr, secSeq)
	// ...so the offset gains both wrappers' headers.
	authAt += (len(secSeq) - len(sec)) + (len(secField) - len(secSeq))

	var flags byte
	switch b.Level {
	case AuthNoPriv:
		flags |= 0x01
	case AuthPriv:
		flags |= 0x03
	case NoAuthNoPriv:
	}
	if b.Reportable {
		flags |= 0x04
	}
	global := make([]byte, 0, 32)
	global = append(global, encodeTLV(TagInteger, encodeInt(b.MessageID))...)
	global = append(global, encodeTLV(TagInteger, encodeInt(b.MaxSize))...)
	global = append(global, encodeTLV(TagOctetStr, []byte{flags})...)
	global = append(global, encodeTLV(TagInteger, encodeInt(3))...) // USM
	globalSeq := encodeTLV(TagSequence, global)

	body := make([]byte, 0, len(globalSeq)+len(secField)+len(payload)+8)
	body = append(body, encodeTLV(TagInteger, encodeInt(int64(V3)))...)
	body = append(body, globalSeq...)
	authAt += len(body) // the version and the global header are before it
	body = append(body, secField...)
	if b.Level == AuthPriv {
		// The encrypted scoped PDU travels as an OCTET STRING; a plain one
		// is its own SEQUENCE and goes as it is.
		body = append(body, encodeTLV(TagOctetStr, payload)...)
	} else {
		body = append(body, payload...)
	}
	out := encodeTLV(TagSequence, body)
	authAt += len(out) - len(body) // and the outermost header too
	if len(out) > MaxMessage {
		return nil, ErrTruncated
	}
	if digestLen == 0 {
		return out, nil
	}
	if authAt+digestLen > len(out) {
		// Unreachable arithmetic, checked anyway: a wrong offset would sign
		// the wrong octets, and a message that verifies nowhere is worse than
		// one that was never built.
		return nil, ErrNoAuthParams
	}
	mac := hmac.New(b.Auth.NewHash(), b.AuthKey)
	mac.Write(out)
	copy(out[authAt:authAt+digestLen], mac.Sum(nil)[:digestLen])
	return out, nil
}

// headerLen is the octets encodeTLV puts before a body of n octets.
func headerLen(n int) int {
	switch {
	case n < 0x80:
		return 2
	case n <= 0xff:
		return 3
	case n <= 0xffff:
		return 4
	default:
		return 5
	}
}

// encryptScoped encrypts the scoped PDU and returns it with its salt.
func encryptScoped(b V3Build) ([]byte, []byte, error) {
	salt := b.Salt
	if salt == nil {
		salt = make([]byte, 8)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	if len(salt) != 8 {
		return nil, nil, ErrPrivParams
	}
	if b.Priv == PrivDES {
		ct, err := encryptDES(b.Scoped, b.PrivKey, salt)
		return ct, salt, err
	}
	ct, err := encryptAES(b.Scoped, b.PrivKey[:b.Priv.KeyLen()], b.EngineBoots, b.EngineTime, salt)
	return ct, salt, err
}

// encryptDES is the other half of decryptDES: CBC, with the initialisation
// vector made from the second half of the key and the salt.
//
// The padding is zeroes to the block size. RFC 3414 s8.1.1.2 lets a sender pad
// with anything, and the BER length inside the scoped PDU is what says where it
// ends -- but a sender that padded with its own memory would be handing it to
// whoever holds the key, so zeroes it is.
func encryptDES(pt, key, salt []byte) ([]byte, error) {
	block, err := des.NewCipher(key[:8]) //nolint:gosec // the protocol's own cipher
	if err != nil {
		return nil, err
	}
	padded := pt
	if n := len(pt) % des.BlockSize; n != 0 {
		padded = make([]byte, len(pt)+des.BlockSize-n)
		copy(padded, pt)
	}
	iv := make([]byte, des.BlockSize)
	for i := range iv {
		iv[i] = key[8+i] ^ salt[i]
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// encryptAES is the other half of decryptAES: counter feedback, with the
// engine's boots and time as the first eight octets of the vector and the salt
// as the other eight. No padding: the mode is a stream.
func encryptAES(pt, key []byte, boots, t int64, salt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 0, 16)
	iv = binary.BigEndian.AppendUint32(iv, uint32(boots)) //nolint:gosec // a clock counter
	iv = binary.BigEndian.AppendUint32(iv, uint32(t))     //nolint:gosec // and likewise
	iv = append(iv, salt...)
	out := make([]byte, len(pt))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, pt) //nolint:staticcheck // RFC 3826 is CFB
	return out, nil
}
