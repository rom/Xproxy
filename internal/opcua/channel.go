package opcua

import (
	"fmt"
	"strings"
)

// A SecurityPolicy is the URI in an OpenSecureChannel's asymmetric header. It
// names the whole cryptographic suite: the signature algorithm, the encryption
// algorithm, the key derivation and the minimum key lengths.
//
// The URIs are long and the deprecated ones look very like the current ones, which
// is the reason this is a type with a Deprecated method rather than a string a
// configuration file compares by hand. Basic128Rsa15 and Basic256 were deprecated
// in 1.04 and are the two an estate most often still has switched on, because a
// single old client keeps them there.
type SecurityPolicy string

// The policies of IEC 62541-7.
const (
	// PolicyNone is no signature and no encryption. Everything, including the
	// user's password if the identity token is a plain one, is on the wire in
	// the clear.
	PolicyNone SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#None"
	// PolicyBasic128Rsa15 is deprecated: RSA-PKCS#1 v1.5 and SHA-1.
	PolicyBasic128Rsa15 SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
	// PolicyBasic256 is deprecated: SHA-1 again, with a longer key.
	PolicyBasic256 SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
	// PolicyBasic256Sha256 is the first of the current set.
	PolicyBasic256Sha256 SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	// PolicyAes128Sha256RsaOaep is RSA-OAEP with AES-128.
	PolicyAes128Sha256RsaOaep SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
	// PolicyAes256Sha256RsaPss is RSA-PSS with AES-256, the strongest the
	// standard defines.
	PolicyAes256Sha256RsaPss SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
)

// policyPrefix is the part every policy URI shares.
const policyPrefix = "http://opcfoundation.org/UA/SecurityPolicy#"

// Known says the policy is one the standard defines.
func (p SecurityPolicy) Known() bool {
	switch p {
	case PolicyNone, PolicyBasic128Rsa15, PolicyBasic256,
		PolicyBasic256Sha256, PolicyAes128Sha256RsaOaep, PolicyAes256Sha256RsaPss:
		return true
	}
	return false
}

// Deprecated says the policy is one IEC 62541 withdrew: SHA-1 based, and not to be
// used for new deployments since 1.04.
//
// None is not deprecated, which reads oddly until you see what the two categories
// are for. Deprecated means "broken cryptography still switched on"; None means "no
// cryptography, deliberately", which is a legitimate configuration for a segment
// where something else provides the security and an illegitimate one everywhere
// else. A listener refuses them separately because the reasons differ.
func (p SecurityPolicy) Deprecated() bool {
	return p == PolicyBasic128Rsa15 || p == PolicyBasic256
}

// Short returns the policy's name without the URI prefix: "Basic256Sha256". It is
// what belongs in a log line and in a configuration file, and what PolicyOf reads.
func (p SecurityPolicy) Short() string {
	return strings.TrimPrefix(string(p), policyPrefix)
}

// PolicyOf reads a policy back from its short name, case-insensitively, so a
// configuration file can say "basic256sha256" rather than the whole URI. The full
// URI is also accepted, for a file written from a capture.
func PolicyOf(name string) (SecurityPolicy, bool) {
	if p := SecurityPolicy(name); p.Known() {
		return p, true
	}
	for _, p := range []SecurityPolicy{
		PolicyNone, PolicyBasic128Rsa15, PolicyBasic256,
		PolicyBasic256Sha256, PolicyAes128Sha256RsaOaep, PolicyAes256Sha256RsaPss,
	} {
		if strings.EqualFold(name, p.Short()) {
			return p, true
		}
	}
	return "", false
}

// MessageSecurityMode is what the channel does to a message: nothing, sign it, or
// sign and encrypt it.
//
// For a relay this is the single most consequential field in the protocol, because
// it decides whether there is a body to read at all. It is carried in the
// OpenSecureChannel *request body*, not in the header — so a relay learns it from
// the service call, and until it has read that call it knows the policy but not the
// mode.
type MessageSecurityMode uint32

// The modes of IEC 62541-4 s7.15.
const (
	// ModeInvalid is the zero value and not a mode a peer may name.
	ModeInvalid MessageSecurityMode = 0
	// ModeNone is no signature and no encryption.
	ModeNone MessageSecurityMode = 1
	// ModeSign signs the body and leaves it readable. This is the mode where a
	// relay can enforce the most and change the least: every node id and every
	// method argument is in the clear, and the signature is over exactly those
	// octets, so rewriting one breaks the channel.
	ModeSign MessageSecurityMode = 2
	// ModeSignAndEncrypt signs and encrypts. The body is opaque and a relay sees
	// the channel, the sizes and the timing.
	ModeSignAndEncrypt MessageSecurityMode = 3
)

func (m MessageSecurityMode) String() string {
	switch m {
	case ModeNone:
		return "none"
	case ModeSign:
		return "sign"
	case ModeSignAndEncrypt:
		return "sign_and_encrypt"
	case ModeInvalid:
		return "invalid"
	}
	return fmt.Sprintf("mode(%d)", uint32(m))
}

// Known says the mode is one of the three the standard defines.
func (m MessageSecurityMode) Known() bool {
	return m == ModeNone || m == ModeSign || m == ModeSignAndEncrypt
}

// Readable says a body secured with this mode is one a relay can parse. It is the
// question every service-level rule depends on, and the answer is that signing
// leaves the plaintext alone.
func (m MessageSecurityMode) Readable() bool {
	return m == ModeNone || m == ModeSign
}

// ModeOf reads a mode back from its name.
func ModeOf(name string) (MessageSecurityMode, bool) {
	switch strings.ToLower(name) {
	case "none":
		return ModeNone, true
	case "sign":
		return ModeSign, true
	case "sign_and_encrypt", "signandencrypt":
		return ModeSignAndEncrypt, true
	}
	return ModeInvalid, false
}

// An AsymmetricHeader is what an OpenSecureChannel chunk carries instead of a
// token: the policy being proposed and the certificates that will establish it.
//
// The certificates are here in the clear by necessity — they are how each end
// learns the other's public key — which is why a relay can enforce certificate
// rules without holding a private key of its own.
type AsymmetricHeader struct {
	// SecureChannelID is zero on the first OpenSecureChannel of a connection and
	// the existing channel's identifier on a renewal.
	SecureChannelID uint32
	// Policy is the URI, as sent. It may be one this package does not know, which
	// is a refusal and not a parse failure.
	Policy SecurityPolicy
	// SenderCertificate is the DER certificate (or chain) of whichever end sent
	// this chunk. It is null when the policy is None.
	SenderCertificate []byte
	// ReceiverThumbprint is the SHA-1 thumbprint of the certificate the sender
	// encrypted to, and is null under policy None. SHA-1 here is not a weakness
	// the standard overlooked: it identifies a certificate rather than
	// authenticating one.
	ReceiverThumbprint []byte
}

// MaxCertificate bounds the sender certificate. A chain of three RSA-4096
// certificates is about six kilobytes; this leaves room for an unusual one and
// refuses a field being used as a buffer.
const MaxCertificate = 16 << 10

// ParseAsymmetric reads the security header of an OPN chunk and returns it with the
// offset of the sequence header that follows.
//
// Returning the offset rather than the remaining slice is deliberate: the signature
// and the encryption are computed over positions in the whole chunk, so a caller
// that has to reason about either needs to know where it is, not merely what is
// left.
func ParseAsymmetric(body []byte) (*AsymmetricHeader, int, error) {
	r := &reader{b: body}
	h := &AsymmetricHeader{SecureChannelID: r.uint32()}
	if n, ok := r.length("security policy uri", MaxString); ok {
		h.Policy = SecurityPolicy(r.bytes(n))
	}
	if n, ok := r.length("sender certificate", MaxCertificate); ok {
		h.SenderCertificate = r.bytes(n)
	}
	if n, ok := r.length("receiver thumbprint", MaxString); ok {
		h.ReceiverThumbprint = r.bytes(n)
	}
	if err := r.done(); err != nil {
		return nil, 0, err
	}
	return h, HeaderLen + r.i, nil
}

// A SymmetricHeader is what every MSG and CLO chunk carries: the channel and the
// token that currently secures it.
//
// Two identifiers rather than one, because a channel outlives its keys. A token has
// a lifetime and is renewed by a second OpenSecureChannel on the same channel, so
// the pair is what identifies the key material; a relay that tracked only the
// channel would attribute a renewed channel's messages to the retired token.
type SymmetricHeader struct {
	SecureChannelID uint32
	TokenID         uint32
}

// ParseSymmetric reads the eight-octet symmetric security header and returns the
// offset of the sequence header.
func ParseSymmetric(body []byte) (*SymmetricHeader, int, error) {
	r := &reader{b: body}
	h := &SymmetricHeader{SecureChannelID: r.uint32(), TokenID: r.uint32()}
	if err := r.done(); err != nil {
		return nil, 0, err
	}
	return h, HeaderLen + r.i, nil
}

// A SequenceHeader follows the security header of every secured chunk: a sequence
// number for the channel and a request identifier for the message.
//
// The RequestID is what joins chunks into a message, and it is also what pairs a
// response with its request — the same role a token plays in CoAP. The
// SequenceNumber is the channel's own counter and must increase by one per chunk,
// wrapping at 4294966271 by IEC 62541-6 s6.7.2.4; a gap means a chunk was lost or
// a peer is replaying, which is the secure channel's business rather than a relay's,
// but a relay that reads it can say which.
type SequenceHeader struct {
	SequenceNumber uint32
	RequestID      uint32
}

// ParseSequence reads the eight-octet sequence header at off in the chunk.
func ParseSequence(chunk []byte, off int) (*SequenceHeader, int, error) {
	if off < 0 || off > len(chunk) {
		return nil, 0, fmt.Errorf("%w: a sequence header at %d of %d", ErrShort, off, len(chunk))
	}
	r := &reader{b: chunk[off:]}
	s := &SequenceHeader{SequenceNumber: r.uint32(), RequestID: r.uint32()}
	if err := r.done(); err != nil {
		return nil, 0, err
	}
	return s, off + r.i, nil
}
