package ntp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/rom/xproxy/internal/siv"
)

// NTS authentication of a time exchange: RFC 8915 sections 5.6 and 5.7.
//
// This is the half of NTS that happens on the time port. The key establishment
// on 4460 produced two keys and a cookie; a time packet carries the cookie,
// which tells the server which keys to use, and an authenticator that proves
// the packet was sent by whoever holds them. The authenticator also encrypts
// extension fields, which is how a server hands back replacement cookies
// without an observer being able to link one exchange of a client's to the
// next.
//
// Everything in this file is the part of that a party holding the keys can do,
// which is the part a relay terminating NTS has to do itself. A relay that is
// not terminating holds no keys and can see none of it -- see NTSFields, which
// is deliberately named for what is merely visible.

// The bounds and lengths this imposes.
const (
	// NTSNonceLen is the nonce this relay generates. RFC 8915 s5.7 requires at
	// least sixteen octets and this is what every implementation sends.
	NTSNonceLen = 16
	// MinNTSNonce is the shortest nonce this will accept, which is the
	// standard's own minimum. AES-SIV survives a repeated nonce, but a sender
	// using a shorter one than the standard allows is not a sender whose other
	// choices should be trusted either.
	MinNTSNonce = 16
	// MaxNTSNonce bounds the nonce, because the nonce is a length field a
	// sender chooses and this relay allocates against.
	MaxNTSNonce = 64
	// MaxNTSCookie bounds a cookie field's body. A cookie is opaque to
	// everyone but the server that issued it, so the only thing to say about
	// one is how large it may be.
	MaxNTSCookie = 256
	// MaxNTSCookies is how many cookies one response may carry, which is the
	// bound on the amplification a request with placeholders can ask for: a
	// client asks for a replacement cookie per cookie it spends, and a request
	// stuffed with placeholders is a request for a response larger than itself.
	MaxNTSCookies = 8
	// UniqueIDLen is the unique identifier this relay generates: RFC 8915 s5.3
	// requires at least 32 octets of randomness, because it is what ties a
	// response to a request.
	UniqueIDLen = 32
)

// Errors this half returns. They are distinct because they mean different
// things about the sender: a malformed field is a client that cannot speak NTS,
// and a failed verification is a packet that was forged or altered.
var (
	// ErrNoNTSAuth is a packet with no authenticator field at all.
	ErrNoNTSAuth = errors.New("ntp: the packet carries no NTS authenticator")
	// ErrNTSAuth is an authenticator field this cannot read.
	ErrNTSAuth = errors.New("ntp: the NTS authenticator is malformed")
	// ErrNTSVerify is an authenticator that did not verify. It is one error for
	// every way that can happen, because the sender must not be told which.
	ErrNTSVerify = errors.New("ntp: the NTS authenticator did not verify")
)

// NTSAuth is a parsed authenticator field and where in the packet it began.
type NTSAuth struct {
	// Offset is where the field starts, which is where the authenticated
	// region ends: the AEAD's associated data is every octet before it.
	Offset     int
	Nonce      []byte
	Ciphertext []byte
}

func pad4(n int) int {
	if r := n % 4; r != 0 {
		return n + 4 - r
	}
	return n
}

// NTSAuth finds and parses the authenticator field.
//
// It must be the last extension field and nothing may follow it. RFC 8915 s5.6
// says so, and the reason is the whole point of the field: everything before it
// is authenticated and anything after it is not, so a field that followed it
// would be a field an attacker could add to a packet a client had signed.
func (p *Packet) NTSAuth() (*NTSAuth, error) {
	off := HeaderLen
	for i, e := range p.Extensions {
		if e.Type != EFNTSAuthenticator {
			off += e.Length
			continue
		}
		if i != len(p.Extensions)-1 {
			return nil, fmt.Errorf("%w: %d extension fields follow it", ErrNTSAuth, len(p.Extensions)-1-i)
		}
		if p.HasMAC || p.CryptoNAK {
			return nil, fmt.Errorf("%w: a MAC follows it", ErrNTSAuth)
		}
		a, err := parseNTSAuth(e.Body)
		if err != nil {
			return nil, err
		}
		a.Offset = off
		return a, nil
	}
	return nil, ErrNoNTSAuth
}

// parseNTSAuth reads the field's body: two lengths, then the nonce and the
// ciphertext, each padded to a multiple of four.
func parseNTSAuth(body []byte) (*NTSAuth, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("%w: %d octets of body", ErrNTSAuth, len(body))
	}
	nl := int(binary.BigEndian.Uint16(body))
	cl := int(binary.BigEndian.Uint16(body[2:]))
	switch {
	case nl < MinNTSNonce:
		return nil, fmt.Errorf("%w: a nonce of %d octets, below the minimum %d", ErrNTSAuth, nl, MinNTSNonce)
	case nl > MaxNTSNonce:
		return nil, fmt.Errorf("%w: a nonce of %d octets", ErrNTSAuth, nl)
	case cl < siv.TagSize:
		// Shorter than the tag, so there is not even an authentication tag in
		// it, let alone anything it could authenticate.
		return nil, fmt.Errorf("%w: a ciphertext of %d octets", ErrNTSAuth, cl)
	}
	np, cp := pad4(nl), pad4(cl)
	if 4+np+cp > len(body) {
		// The lengths are the sender's claim about a field it also gave a
		// length to, and the two have to agree.
		return nil, fmt.Errorf("%w: %d octets of nonce and ciphertext in a body of %d",
			ErrNTSAuth, np+cp, len(body)-4)
	}
	return &NTSAuth{Nonce: body[4 : 4+nl], Ciphertext: body[4+np : 4+np+cl]}, nil
}

// OpenNTS verifies the packet under key and returns the extension fields the
// authenticator encrypted.
//
// It verifies over the packet as it arrived rather than a re-encoding: the
// associated data is p.Raw up to the authenticator, so a packet this relay
// re-rendered and then verified would be verifying its own rendering.
func (p *Packet) OpenNTS(key []byte) ([]Extension, error) {
	a, err := p.NTSAuth()
	if err != nil {
		return nil, err
	}
	if len(p.Raw) < a.Offset {
		return nil, fmt.Errorf("%w: the field begins past the packet", ErrNTSAuth)
	}
	aead, err := siv.New(key, len(a.Nonce))
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, a.Nonce, a.Ciphertext, p.Raw[:a.Offset])
	if err != nil {
		return nil, ErrNTSVerify
	}
	return ParseExtensions(plain)
}

// ParseExtensions reads a sequence of extension fields, which is what the
// authenticator's plaintext is.
//
// The plaintext has been authenticated by the time this reads it, so a
// malformed one is a peer with a bug rather than an attacker -- but it is still
// a length field being trusted, so it is still checked.
func ParseExtensions(b []byte) ([]Extension, error) {
	var out []Extension
	for len(b) > 0 {
		if len(out) >= MaxExtensions {
			return nil, fmt.Errorf("%w: more than %d encrypted fields", ErrExtension, MaxExtensions)
		}
		e, err := readExtension(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = b[e.Length:]
	}
	return out, nil
}

// SealNTS appends an authenticator to a packet under construction.
//
// packet is the header and every extension field that precedes the
// authenticator, and it is the associated data: the far end will not accept the
// packet if any of it changed in flight. encrypted are the fields to put inside,
// which is where a server's replacement cookies go -- a cookie sent in the
// clear would let anyone on the path follow a client from one exchange to the
// next, which is the linkability NTS exists to avoid.
func SealNTS(packet, key []byte, encrypted []Extension) ([]byte, error) {
	nonce := make([]byte, NTSNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return sealNTSWith(packet, key, nonce, encrypted)
}

func sealNTSWith(packet, key, nonce []byte, encrypted []Extension) ([]byte, error) {
	aead, err := siv.New(key, len(nonce))
	if err != nil {
		return nil, err
	}
	var plain []byte
	for _, e := range encrypted {
		plain = append(plain, e.Bytes()...)
	}
	ct := aead.Seal(nil, nonce, plain, packet)
	body := make([]byte, 0, 4+pad4(len(nonce))+pad4(len(ct)))
	body = binary.BigEndian.AppendUint16(body, uint16(len(nonce))) //nolint:gosec // bounded above
	body = binary.BigEndian.AppendUint16(body, uint16(len(ct)))    //nolint:gosec // bounded by MaxPacket
	body = append(body, nonce...)
	body = append(body, make([]byte, pad4(len(nonce))-len(nonce))...)
	body = append(body, ct...)
	body = append(body, make([]byte, pad4(len(ct))-len(ct))...)
	out := append([]byte(nil), packet...)
	return append(out, Extension{Type: EFNTSAuthenticator, Body: body}.Bytes()...), nil
}

// NTSUniqueIDField is the unique identifier a client puts on a request and a
// server copies onto the answer. It is what ties the two together, so it is
// randomness and not a counter: a predictable one would let an attacker
// prepare a forged answer before the request was sent.
func NTSUniqueIDField() (Extension, error) {
	id := make([]byte, UniqueIDLen)
	if _, err := rand.Read(id); err != nil {
		return Extension{}, err
	}
	return Extension{Type: EFUniqueIdentifier, Body: id}, nil
}

// NTSCookieField carries one cookie.
func NTSCookieField(cookie []byte) Extension {
	return Extension{Type: EFNTSCookie, Body: cookie}
}

// NTSPlaceholderField is how a client asks for an extra cookie: a field the
// size of a cookie and full of nothing.
//
// The size matters. The placeholder is there so that the request is as large as
// the response it asks for, which is what stops NTS being an amplifier: a
// server answering a small request with several cookies would be a reflector
// worth aiming at somebody.
func NTSPlaceholderField(size int) Extension {
	return Extension{Type: EFNTSCookiePlaceholder, Body: make([]byte, size)}
}

// NTSCookies pulls the cookies out of a set of extension fields, which is how
// both halves read them: a request's cookies are in the clear and a response's
// are inside the authenticator.
func NTSCookies(fields []Extension) [][]byte {
	out := make([][]byte, 0, len(fields))
	for _, e := range fields {
		if e.Type != EFNTSCookie {
			continue
		}
		if len(e.Body) == 0 || len(e.Body) > MaxNTSCookie {
			continue
		}
		out = append(out, e.Body)
	}
	return out
}
