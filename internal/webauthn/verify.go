package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The two ceremonies, and what each check is actually for.
//
// A WebAuthn assertion is a signature by a key the authenticator holds
// over two things joined together: the authenticator's own data (which
// says which relying party it was talking to, whether the user was
// present, and how many times this credential has been used) and the hash
// of the browser's clientDataJSON (which says what ceremony this was, the
// challenge, and the origin the page was served from).
//
// That structure is why the checks below are not a list of formalities.
// The signature proves the key was used; the *contents* prove it was used
// for this request, at this site, at this moment:
//
//   - type: a signature made during registration must not be replayable as
//     an authentication, and the reverse.
//   - challenge: the value this server issued, once, recently. Without it
//     every assertion is replayable forever.
//   - origin: the page the ceremony ran on. This is the anti-phishing
//     property of the whole mechanism: a look-alike site gets assertions
//     bound to its own origin, which this refuses.
//   - rpIdHash: the relying party the authenticator thought it was talking
//     to, which it computes itself and the page cannot choose.
//   - user present: somebody touched the key rather than a page calling
//     the API in the background.
//   - sign count: an authenticator that counts must not count backwards,
//     which is what a cloned credential looks like.

var (
	// ErrSignature is an assertion whose signature does not verify.
	ErrSignature = errors.New("webauthn: signature does not verify")
	// ErrCeremony is a client data or authenticator data problem: the
	// type, the challenge, the origin, the relying party or the flags.
	ErrCeremony = errors.New("webauthn: ceremony does not match")
	// ErrClone is a sign count that went backwards, which is what a
	// duplicated credential looks like.
	ErrClone = errors.New("webauthn: sign count went backwards")
)

// maxClientData bounds the clientDataJSON. It holds a type, a challenge,
// an origin and a flag; a megabyte of it is not one.
const maxClientData = 8 << 10

// maxAuthData bounds authenticator data. The fixed part is 37 bytes;
// attested credential data and extensions follow, and a key plus a
// credential identifier is well under a kilobyte.
const maxAuthData = 8 << 10

// Policy is what a relying party requires.
type Policy struct {
	// RPID is the relying party identifier: the site's registrable
	// domain, or a subdomain of it. The authenticator hashes it, so it
	// cannot be chosen by the page.
	RPID string
	// Origins are the exact origins a ceremony may run on. Exact, because
	// this is the anti-phishing property: a prefix or a suffix match
	// admits a look-alike host.
	Origins []string
	// UserVerification requires the authenticator to have verified the
	// user (a PIN or a biometric) and not merely their presence.
	UserVerification bool
}

// clientData is the browser's statement about the ceremony.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// authData is the authenticator's statement.
type authData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	// credentialID and publicKey are present during registration.
	credentialID []byte
	publicKey    []byte
	// raw is the bytes as signed.
	raw []byte
}

// The authenticator data flags.
const (
	flagUserPresent  = 1 << 0
	flagUserVerified = 1 << 2
	flagAttested     = 1 << 6
	flagExtensions   = 1 << 7
)

// parseAuthData reads authenticator data, including the attested
// credential when the flag says there is one.
func parseAuthData(b []byte) (authData, error) {
	var a authData
	if len(b) > maxAuthData {
		return a, fmt.Errorf("%w: authenticator data of %d bytes", ErrCeremony, len(b))
	}
	if len(b) < 37 {
		return a, fmt.Errorf("%w: authenticator data of %d bytes", ErrCeremony, len(b))
	}
	a.raw = b
	a.rpIDHash = b[:32]
	a.flags = b[32]
	a.signCount = binary.BigEndian.Uint32(b[33:37])
	rest := b[37:]
	if a.flags&flagAttested != 0 {
		// aaguid(16) | credential id length(2) | credential id | COSE key
		if len(rest) < 18 {
			return a, fmt.Errorf("%w: attested credential data of %d bytes", ErrCeremony, len(rest))
		}
		idLen := int(binary.BigEndian.Uint16(rest[16:18]))
		// The specification caps a credential identifier at 1023 bytes,
		// and the length field is the authenticator's: a larger one is a
		// read past the buffer waiting to happen.
		if idLen == 0 || idLen > 1023 || 18+idLen > len(rest) {
			return a, fmt.Errorf("%w: credential id length %d", ErrCeremony, idLen)
		}
		a.credentialID = rest[18 : 18+idLen]
		rest = rest[18+idLen:]
		// The key is the next CBOR item; extensions, if any, follow it,
		// so the key's own length comes from the decoder rather than from
		// the bytes that are left.
		_, n, err := decodeCBOR(rest)
		if err != nil {
			return a, fmt.Errorf("%w: credential key: %w", ErrCeremony, err)
		}
		a.publicKey = rest[:n]
		rest = rest[n:]
	}
	if a.flags&flagExtensions != 0 {
		if _, n, err := decodeCBOR(rest); err != nil {
			return a, fmt.Errorf("%w: extensions: %w", ErrCeremony, err)
		} else if n != len(rest) {
			return a, fmt.Errorf("%w: %d bytes after the extensions", ErrCeremony, len(rest)-n)
		}
	} else if len(rest) != 0 {
		return a, fmt.Errorf("%w: %d bytes after the authenticator data", ErrCeremony, len(rest))
	}
	return a, nil
}

// checkClientData holds the browser's statement to this ceremony.
func (p *Policy) checkClientData(raw []byte, want string, challenge []byte) error {
	if len(raw) > maxClientData {
		return fmt.Errorf("%w: client data of %d bytes", ErrCeremony, len(raw))
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("%w: client data is not JSON", ErrCeremony)
	}
	if cd.Type != want {
		// A registration signature replayed as an authentication, or the
		// reverse. The type is in the signed bytes precisely so this
		// cannot be done.
		return fmt.Errorf("%w: type is %q, want %q", ErrCeremony, cd.Type, want)
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		// The challenge is base64url without padding in clientDataJSON.
		// A browser that padded it is still unambiguous, so try that
		// before refusing.
		got, err = base64.URLEncoding.DecodeString(cd.Challenge)
		if err != nil {
			return fmt.Errorf("%w: challenge is not base64url", ErrCeremony)
		}
	}
	if len(got) == 0 || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return fmt.Errorf("%w: challenge is not the one that was issued", ErrCeremony)
	}
	if !p.originAllowed(cd.Origin) {
		// The anti-phishing check. A look-alike site produces assertions
		// bound to its own origin, and this is where they stop.
		return fmt.Errorf("%w: origin %q", ErrCeremony, cd.Origin)
	}
	if cd.CrossOrigin {
		// An ceremony inside an iframe on somebody else's page. The
		// specification allows a relying party to permit it; a second
		// factor has no reason to.
		return fmt.Errorf("%w: the ceremony was cross-origin", ErrCeremony)
	}
	return nil
}

// originAllowed compares an origin exactly, against the list.
func (p *Policy) originAllowed(origin string) bool {
	for _, want := range p.Origins {
		// Case-insensitively for the scheme and host, which is all an
		// origin is: there is no path in one, and a trailing slash is not
		// part of it.
		if strings.EqualFold(strings.TrimSuffix(origin, "/"), strings.TrimSuffix(want, "/")) {
			return true
		}
	}
	return false
}

// checkAuthData holds the authenticator's statement to this policy.
func (p *Policy) checkAuthData(a authData) error {
	want := sha256.Sum256([]byte(p.RPID))
	if subtle.ConstantTimeCompare(a.rpIDHash, want[:]) != 1 {
		return fmt.Errorf("%w: the authenticator was talking to another relying party", ErrCeremony)
	}
	if a.flags&flagUserPresent == 0 {
		return fmt.Errorf("%w: the user was not present", ErrCeremony)
	}
	if p.UserVerification && a.flags&flagUserVerified == 0 {
		return fmt.Errorf("%w: the user was not verified", ErrCeremony)
	}
	return nil
}

// Registration is what a completed registration ceremony produced.
type Registration struct {
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	// UserVerified says the authenticator verified the user, not only
	// their presence, during registration.
	UserVerified bool
}

// Register verifies a registration ceremony and returns the credential to
// store.
//
// The attestation statement is read far enough to get the authenticator
// data out of it and no further: see the package comment for why. The
// credential is trusted because this registration was authenticated by a
// factor the user already had.
func (p *Policy) Register(attestationObject, clientDataJSON, challenge []byte) (Registration, error) {
	var out Registration
	if err := p.checkClientData(clientDataJSON, "webauthn.create", challenge); err != nil {
		return out, err
	}
	v, n, err := decodeCBOR(attestationObject)
	if err != nil {
		return out, fmt.Errorf("%w: attestation object: %w", ErrCeremony, err)
	}
	if n != len(attestationObject) {
		return out, fmt.Errorf("%w: %d bytes after the attestation object", ErrCeremony, len(attestationObject)-n)
	}
	m, ok := cborMap(v)
	if !ok {
		return out, fmt.Errorf("%w: attestation object is not a map", ErrCeremony)
	}
	if _, ok := cborText(m[textKey("fmt")]); !ok {
		return out, fmt.Errorf("%w: attestation object without fmt", ErrCeremony)
	}
	raw, ok := cborBytes(m[textKey("authData")])
	if !ok {
		return out, fmt.Errorf("%w: attestation object without authData", ErrCeremony)
	}
	a, err := parseAuthData(raw)
	if err != nil {
		return out, err
	}
	if err := p.checkAuthData(a); err != nil {
		return out, err
	}
	if a.flags&flagAttested == 0 || len(a.credentialID) == 0 || len(a.publicKey) == 0 {
		return out, fmt.Errorf("%w: registration carried no credential", ErrCeremony)
	}
	// The key is parsed here rather than at first use: a credential this
	// proxy cannot verify with is one to refuse now, while somebody is
	// watching, instead of at a login weeks later.
	if _, err := parseCOSEKey(a.publicKey); err != nil {
		return out, err
	}
	return Registration{CredentialID: a.credentialID, PublicKey: a.publicKey,
		SignCount: a.signCount, UserVerified: a.flags&flagUserVerified != 0}, nil
}

// Credential is a registered key, as it is stored and presented back.
type Credential struct {
	// User is the account it belongs to.
	User string
	// ID is the credential identifier the authenticator chose.
	ID []byte
	// PublicKey is the COSE key, as the authenticator gave it.
	PublicKey []byte
	// SignCount is the last count seen for it.
	SignCount uint32
	// Label is an operator's or a user's note about which key this is.
	Label string
}

// Assertion verifies an authentication ceremony against a stored
// credential and returns the new sign count.
//
// An authenticator that counts must not count backwards: the same or a
// lower value from a counting authenticator is what a cloned credential
// looks like. Zero on both sides is an authenticator that does not count
// at all, which the specification permits and many do.
func (p *Policy) Assertion(cred Credential, authenticatorData, clientDataJSON, signature, challenge []byte) (uint32, error) {
	key, err := parseCOSEKey(cred.PublicKey)
	if err != nil {
		return 0, err
	}
	if err := p.checkClientData(clientDataJSON, "webauthn.get", challenge); err != nil {
		return 0, err
	}
	a, err := parseAuthData(authenticatorData)
	if err != nil {
		return 0, err
	}
	if err := p.checkAuthData(a); err != nil {
		return 0, err
	}
	// The signature is over the authenticator data followed by the hash of
	// the client data, in that order. Hashing the client data rather than
	// including it is what keeps the signed input short.
	sum := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(a.raw)+len(sum))
	signed = append(signed, a.raw...)
	signed = append(signed, sum[:]...)
	if err := key.verify(signed, signature); err != nil {
		return 0, err
	}
	if a.signCount != 0 || cred.SignCount != 0 {
		if a.signCount <= cred.SignCount {
			return 0, fmt.Errorf("%w: %d after %d", ErrClone, a.signCount, cred.SignCount)
		}
	}
	return a.signCount, nil
}
