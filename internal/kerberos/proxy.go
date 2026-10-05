package kerberos

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The KDC-PROXY-MESSAGE: the envelope MS-KKDCP puts a Kerberos message in
// to carry it over HTTPS.
//
//	KDC-PROXY-MESSAGE ::= SEQUENCE {
//	    kerb-message   [0] OCTET STRING,
//	    target-domain  [1] KERB-REALM OPTIONAL,
//	    dclocator-hint [2] INTEGER OPTIONAL
//	}
//
// Three things about it are worth a reader's attention.
//
// **The inner message carries a TCP length prefix.** kerb-message is not
// a bare Kerberos message; it is the message as it would appear on a TCP
// connection to the KDC, four octets of big-endian length first. That is
// what makes the envelope a transport rather than a wrapper, and it is
// also a second length field a reader has to agree with the KDC about.
//
// **target-domain is routing and it is optional.** It names the realm the
// client wants this proxy to reach. A proxy with no realm policy will
// forward to whatever a client names; a proxy that reads only the inner
// message will miss the case where the two disagree -- and the two
// disagreeing is interesting, because the inner realm is what the KDC
// decides on and the outer one is what the proxy routes by.
//
// **dclocator-hint is a Windows-specific flag word** asking the proxy to
// pick a domain controller with particular properties. It is carried
// through and otherwise ignored: it says nothing about what the request
// does.

// ProxyMessage is a parsed envelope.
type ProxyMessage struct {
	// Inner is the Kerberos message, with the TCP length prefix removed.
	Inner []byte
	// TargetDomain is the realm the client asked this proxy to reach,
	// empty where it named none.
	TargetDomain string
	// HasHint and Hint are the domain-controller locator hint.
	HasHint bool
	Hint    int32
}

// Envelope errors.
var (
	ErrNotEnvelope = errors.New("kerberos: not a KDC-PROXY-MESSAGE")
	ErrNoInner     = errors.New("kerberos: envelope carries no kerb-message")
	ErrInnerLength = errors.New("kerberos: kerb-message's length prefix disagrees with its contents")
	ErrInnerEmpty  = errors.New("kerberos: kerb-message is empty")
	ErrInnerTooBig = errors.New("kerberos: kerb-message is longer than this listener will carry")
)

// lengthPrefixBytes is the TCP framing in front of the inner message.
const lengthPrefixBytes = 4

// ParseProxyMessage reads the envelope.
//
// maxInner bounds the inner message, and it is a parameter rather than a
// constant because the bound belongs to the listener: a reply carrying a
// Windows PAC for a user in several hundred groups is legitimately large,
// and how large is a judgement an estate makes.
func ParseProxyMessage(b []byte, maxInner int) (ProxyMessage, error) {
	r := newDER(b)
	top, err := r.next()
	if err != nil {
		return ProxyMessage{}, err
	}
	if !top.cons || top.class != classUniversal || top.tag != tagSequence {
		return ProxyMessage{}, ErrNotEnvelope
	}
	if !r.empty() {
		return ProxyMessage{}, ErrTrailing
	}
	seq, err := r.sequence(top)
	if err != nil {
		return ProxyMessage{}, err
	}
	var m ProxyMessage
	var framed []byte
	for !seq.empty() {
		e, err := seq.next()
		if err != nil {
			return ProxyMessage{}, err
		}
		switch {
		case e.ctx(0):
			inner, _, err := seq.only(e)
			if err != nil {
				return ProxyMessage{}, err
			}
			if !inner.is(tagOctetString) {
				return ProxyMessage{}, fmt.Errorf("%w: kerb-message is not an OCTET STRING", ErrTag)
			}
			framed = inner.data
		case e.ctx(1):
			if m.TargetDomain, err = stringField(seq, e); err != nil {
				return ProxyMessage{}, err
			}
		case e.ctx(2):
			if m.Hint, err = intField(seq, e); err != nil {
				return ProxyMessage{}, err
			}
			m.HasHint = true
		default:
			// An extension. The envelope is small and stable, so this is
			// skipped rather than refused for the same reason the inner
			// message's unknown fields are.
		}
	}
	if framed == nil {
		return ProxyMessage{}, ErrNoInner
	}
	if m.Inner, err = Unframe(framed, maxInner); err != nil {
		return ProxyMessage{}, err
	}
	return m, nil
}

// Unframe strips the four-octet length prefix a Kerberos message carries
// on TCP, checking that it says exactly what is there.
//
// "Exactly" rather than "at most". A prefix shorter than the octets
// present means something follows the message that this reader would not
// have seen and the KDC would: on a stream that is a second message, and
// inside a single envelope it is octets nobody has read. Both are
// refused, because a relay that forwarded the whole thing after deciding
// about the first part of it has decided about the wrong message.
func Unframe(b []byte, maxInner int) ([]byte, error) {
	if len(b) < lengthPrefixBytes {
		return nil, ErrInnerLength
	}
	n := binary.BigEndian.Uint32(b[:lengthPrefixBytes])
	if n == 0 {
		return nil, ErrInnerEmpty
	}
	if maxInner > 0 && n > uint32(maxInner) { //nolint:gosec // maxInner is a configured bound, checked positive
		return nil, fmt.Errorf("%w: %d octets", ErrInnerTooBig, n)
	}
	if int64(n) != int64(len(b)-lengthPrefixBytes) {
		return nil, ErrInnerLength
	}
	return b[lengthPrefixBytes:], nil
}

// Frame puts the TCP length prefix back on, which is what a relay writes
// to the KDC and what it puts in the envelope going the other way.
func Frame(msg []byte) []byte {
	out := make([]byte, lengthPrefixBytes+len(msg))
	binary.BigEndian.PutUint32(out[:lengthPrefixBytes], uint32(len(msg))) //nolint:gosec // the caller's own message, bounded by the listener
	copy(out[lengthPrefixBytes:], msg)
	return out
}

// MarshalProxyMessage builds an envelope around a Kerberos message.
//
// The target domain is included when it is not empty, because a reply
// envelope does not need one and MS-KKDCP's own clients do not send one
// back. Nothing else is included: a relay that echoed the locator hint
// into a reply would be putting a field in a message the standard does not
// define one for.
func MarshalProxyMessage(msg []byte, targetDomain string) []byte {
	inner := derTLV(classUniversal, tagOctetString, Frame(msg))
	body := derTLV(classContext|constructed, 0, inner)
	if targetDomain != "" {
		realm := derTLV(classUniversal, tagGeneralStr, []byte(targetDomain))
		body = append(body, derTLV(classContext|constructed, 1, realm)...)
	}
	return derTLV(classUniversal|constructed, tagSequence, body)
}

// derTLV writes one element with a definite length in the shortest form.
func derTLV(class byte, tag uint32, data []byte) []byte {
	out := make([]byte, 0, len(data)+6)
	out = append(out, class|byte(tag))
	switch n := len(data); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 1<<8:
		out = append(out, 0x81, byte(n))
	case n < 1<<16:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, data...)
}
