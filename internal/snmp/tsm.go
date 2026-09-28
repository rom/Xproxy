package snmp

import (
	"errors"
	"fmt"
)

// The transport security model, RFC 5591, and the transport it exists for,
// RFC 6353.
//
// USM is the security model everyone means when they say SNMPv3: a user name,
// an engine identifier, a pass phrase hashed into a localised key, and a
// digest over the message. It works, and its cost is a shared secret per user
// per engine -- which on an estate of ten thousand devices is ten thousand
// secrets in a spreadsheet, rotated never.
//
// The transport security model says something simpler: the *transport* already
// authenticated and encrypted this, so the message carries no security
// parameters at all. Over (D)TLS the peer presented a certificate, which is an
// identity an estate already has a way to issue, revoke and rotate; RFC 6353
// s5.3 says how that certificate becomes the security name a policy is written
// about, and this package's only part in it is to read a message that has none
// of its own.
//
// Three consequences are worth stating, because each is a check or a
// capability further in:
//
//   - **msgSecurityParameters is empty.** RFC 5591 s3.1.1 requires a
//     zero-length OCTET STRING. A TSM message carrying parameters is either
//     a sender that does not implement the model or one hiding something in
//     a field nothing reads, and it is refused rather than ignored.
//   - **The flags say authPriv and the payload is in the clear.** The flags
//     are set from the transport's security level, not from anything the
//     message did, so a reader that took the privacy bit as "there is
//     ciphertext here" would refuse every TSM message ever sent. The scoped
//     PDU is plain because the record layer underneath already encrypted it.
//   - **A response needs no keys.** This is what makes the model worth
//     relaying: an answer is authenticated by the session it is written into,
//     so a relay can take a v2c answer from a switch that will never speak
//     anything else and hand it back as a v3 message the manager's stack
//     accepts -- without holding a pass phrase for the manager, because there
//     is not one. BuildTSM is that half.

// The security models this package knows by number, as RFC 3411 s5 registers
// them and as the msgSecurityModel field carries them.
const (
	// SecurityModelUSM is the user-based security model, RFC 3414.
	SecurityModelUSM int64 = 3
	// SecurityModelTSM is the transport security model, RFC 5591.
	SecurityModelTSM int64 = 4
)

// SecurityModelName names a security model the way its standard does, for a
// log line and a counter label.
func SecurityModelName(v int64) string {
	switch v {
	case 1:
		return "snmpv1"
	case 2:
		return "snmpv2c"
	case SecurityModelUSM:
		return "usm"
	case SecurityModelTSM:
		return "tsm"
	}
	return fmt.Sprintf("model_%d", v)
}

// ErrTSMParams is a transport security model message whose security
// parameters are not the zero-length OCTET STRING RFC 5591 s3.1.1 requires.
//
// It is an error rather than a field to skip because the model's whole claim
// is that the message carries no security of its own: octets in that field
// are either an implementation that is not this model or a sender putting
// something where nothing is read, and neither is traffic to forward.
var ErrTSMParams = errors.New("snmp: a transport security model message with security parameters")

// TSMBuild is a version 3 message under the transport security model.
//
// There is no user, no engine identifier, no clock and no key, and that is the
// whole difference from V3Build: the session the message is written into is
// what authenticates it. What is left is the envelope the manager's stack
// matches its request against.
type TSMBuild struct {
	// MessageID is v3's own identifier, which a response must echo for the
	// manager's stack to pair it with the request it sent.
	MessageID int64
	// MaxSize is the largest message the sender will accept back.
	MaxSize int64
	// Reportable is the msgFlags bit that says a report may be sent about
	// this message. It is off on a response by RFC 3412 s6.4.
	Reportable bool
	// Level is the transport's security level, which the flags carry. Over
	// (D)TLS with an AEAD cipher suite that is authPriv, and RFC 6353 s3.1.2
	// says so: a message claiming less than the transport gave is a message
	// disagreeing with the session it arrived in.
	Level SecurityLevel
	// Scoped is the encoded scoped PDU: the whole SEQUENCE, contextEngineID
	// and contextName included. ScopedPDU builds one.
	Scoped []byte
}

// BuildTSM originates one version 3 message under the transport security
// model.
//
// It is a much shorter function than BuildV3 and every line that is missing is
// missing for the same reason: there is no digest to compute, so there is no
// offset to compute it at, no key length to check, and no salt. The security
// is the session's.
func BuildTSM(b TSMBuild) ([]byte, error) {
	if len(b.Scoped) == 0 {
		return nil, ErrScoped
	}
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
	global = append(global, encodeTLV(TagInteger, encodeInt(SecurityModelTSM))...)

	body := make([]byte, 0, len(global)+len(b.Scoped)+16)
	body = append(body, encodeTLV(TagInteger, encodeInt(int64(V3)))...)
	body = append(body, encodeTLV(TagSequence, global)...)
	// The empty security parameters, written rather than omitted: the field is
	// not optional, and a receiver reading a scoped PDU where it expected an
	// OCTET STRING would call the message malformed.
	body = append(body, encodeTLV(TagOctetStr, nil)...)
	body = append(body, b.Scoped...)
	out := encodeTLV(TagSequence, body)
	if len(out) > MaxMessage {
		return nil, ErrTruncated
	}
	return out, nil
}

// IsTSM says whether a message is under the transport security model, which is
// the question a relay asks before deciding what a response to it looks like.
func (m *Message) IsTSM() bool {
	return m != nil && m.Version == V3 && m.V3 != nil && m.V3.SecurityModel == SecurityModelTSM
}
