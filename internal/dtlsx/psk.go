package dtlsx

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/pion/dtls/v3"
)

// Pre-shared keys, RFC 4279, and the identity that comes with them.
//
// A certificate is the security mode a server operator reaches for and the one
// a constrained device cannot afford: a chain, a clock to check it against and
// an asymmetric verification, on a part with sixty kilobytes of flash and a
// coin cell. RFC 7252 s9.1.3.1 names the alternative and makes
// TLS_PSK_WITH_AES_128_CCM_8 mandatory for it, which is why a sensor that does
// DTLS at all usually does it this way.
//
// What a pre-shared key gives a *relay* is the thing the rest of this protocol
// has none of: a name. In NoSec there is no identity whatsoever, and the
// source address is a guess about which device sent something. With PSK the
// client names itself in the clear, in the ClientKeyExchange, and then proves
// it by deriving keys from a secret only that name's holder should have. So the
// identity is what a rule names and what a log line carries -- it is the only
// thing on a shared segment that distinguishes one sensor from another.
//
// Three rules the table below holds to, and each is about the identity rather
// than the key:
//
//   - **An empty identity is refused at load.** RFC 4279 s5.1 permits one, and
//     it would be a row that matched every client that sent nothing. A table
//     whose keys are secrets must not have an entry that anybody reaches.
//   - **The identity is bounded before it is looked up.** It arrives from an
//     unauthenticated peer, in a handshake this process has not yet decided
//     anything about, and it ends up in a log line and a status view.
//   - **An unknown identity fails the handshake, and is reported.** A device
//     announcing a name this listener does not hold is either misconfigured or
//     is somebody guessing at names, and on a segment where the identity *is*
//     the identity those are the two things worth knowing about.

// Bounds on a table and on what a peer may say.
const (
	// MaxPSKIdentity is the longest identity this will read. RFC 4279 allows
	// up to 2^16-1 octets; a constrained estate uses a device name, and
	// anything past this is not one -- it is a peer finding out how much of
	// an unauthenticated string this process will carry into a log.
	MaxPSKIdentity = 128
	// MaxPSKEntries bounds one listener's table. A field estate is hundreds
	// of devices; a file with more than this in it is a file nobody curated,
	// and the bound is reported at load rather than found at a handshake.
	MaxPSKEntries = 8192
	// MinPSKKeyBytes is the shortest key this accepts. Sixteen octets is 128
	// bits, which is the width of the cipher the mandatory suite uses: a
	// shorter key is a shorter cipher key, whatever the suite says, and a
	// pass phrase somebody typed is exactly the case this refuses.
	MinPSKKeyBytes = 16
	// MaxPSKKeyBytes bounds one key. Past this it is not a key, it is a file
	// that was pointed at by mistake.
	MaxPSKKeyBytes = 64
)

// ErrUnknownIdentity is what the handshake fails with when a peer names an
// identity the table does not hold. It is returned to the library, which turns
// it into a handshake failure; the peer is told no more than that.
var ErrUnknownIdentity = errors.New("dtlsx: the peer's pre-shared key identity is not in the table")

// PSK is a listener's pre-shared key table: identity to key.
type PSK struct {
	// mu guards nothing that changes after Build -- the table is written at
	// load and read by every handshake -- but the counters below are written
	// from handshake goroutines.
	mu   sync.Mutex
	keys map[string][]byte
	// hint is the PSK identity hint the server offers (RFC 4279 s5.2). Most
	// constrained clients ignore it; it is here because an estate running two
	// key sets on one segment uses it to say which one this is.
	hint []byte
	// onUnknown is called with the identity a peer named that this table does
	// not hold, already bounded and safe to log. It runs on the handshake's
	// own goroutine, so it must not block.
	onUnknown func(identity string)

	known, unknown uint64
}

// NewPSK builds an empty table. hint may be empty.
func NewPSK(hint string, onUnknown func(identity string)) (*PSK, error) {
	if len(hint) > MaxPSKIdentity {
		return nil, fmt.Errorf("dtlsx: a pre-shared key hint of %d octets is past the %d-octet bound",
			len(hint), MaxPSKIdentity)
	}
	t := &PSK{keys: map[string][]byte{}, onUnknown: onUnknown}
	if hint != "" {
		t.hint = []byte(hint)
	}
	return t, nil
}

// Add records one identity's key.
func (t *PSK) Add(identity string, key []byte) error {
	switch {
	case identity == "":
		return errors.New("dtlsx: a pre-shared key identity may not be empty: it would be the row every client that names nothing reaches")
	case len(identity) > MaxPSKIdentity:
		return fmt.Errorf("dtlsx: the identity %q is %d octets, past the %d-octet bound",
			clipIdentity(identity), len(identity), MaxPSKIdentity)
	case len(key) < MinPSKKeyBytes:
		return fmt.Errorf("dtlsx: the key for %q is %d octets; %d is the least this accepts, because the mandatory suite's cipher key is that wide",
			clipIdentity(identity), len(key), MinPSKKeyBytes)
	case len(key) > MaxPSKKeyBytes:
		return fmt.Errorf("dtlsx: the key for %q is %d octets, past the %d-octet bound",
			clipIdentity(identity), len(key), MaxPSKKeyBytes)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.keys[identity]; ok {
		return fmt.Errorf("dtlsx: the identity %q appears twice", clipIdentity(identity))
	}
	if len(t.keys) >= MaxPSKEntries {
		return fmt.Errorf("dtlsx: more than %d pre-shared keys", MaxPSKEntries)
	}
	t.keys[identity] = append([]byte(nil), key...)
	return nil
}

// Len is how many identities the table holds.
func (t *PSK) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keys)
}

// Counts are the handshakes this table decided: the ones whose identity it
// held, and the ones it did not.
func (t *PSK) Counts() (known, unknown uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.known, t.unknown
}

// Holds says whether an identity is in the table, for a caller that maps the
// identity to something of its own.
func (t *PSK) Holds(identity string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.keys[identity]
	return ok
}

// lookup is the library's callback: the identity a peer named, and the key to
// derive from.
func (t *PSK) lookup(identity []byte) ([]byte, error) {
	if len(identity) > MaxPSKIdentity {
		// Refused before it is a map key or a log line. A peer has proved
		// nothing at this point in the handshake.
		t.miss(fmt.Sprintf("%d octets", len(identity)))
		return nil, ErrUnknownIdentity
	}
	t.mu.Lock()
	key, ok := t.keys[string(identity)]
	if ok {
		t.known++
	}
	t.mu.Unlock()
	if !ok {
		t.miss(clipIdentity(string(identity)))
		return nil, ErrUnknownIdentity
	}
	// A copy, because what the library does with it afterwards is not this
	// table's to assume.
	out := make([]byte, len(key))
	subtle.ConstantTimeCopy(1, out, key)
	return out, nil
}

// miss counts an identity this table does not hold and tells the caller.
func (t *PSK) miss(what string) {
	t.mu.Lock()
	t.unknown++
	cb := t.onUnknown
	t.mu.Unlock()
	if cb != nil {
		cb(what)
	}
}

// clipIdentity bounds an identity for a message. It is not textsafe.Clip --
// that is for a string on its way to a log, and this is for an error at load
// -- but the bound is the same idea.
func clipIdentity(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// PSKSuites are the cipher suites a listener with a table offers, in
// preference order.
//
// They are named rather than left to the library's defaults for a reason that
// is not style: the library's default list holds no PSK suite at all, so a
// configuration with a table and no list refuses to build. Given that the list
// has to be written, it is written as the four AEAD suites and not the
// CBC-with-SHA256 one the library also has:
//
//   - TLS_PSK_WITH_AES_128_GCM_SHA256 is what a gateway-class client offers.
//   - TLS_PSK_WITH_AES_128_CCM is AEAD with the full sixteen-octet tag.
//   - TLS_PSK_WITH_AES_128_CCM_8 is RFC 7252 s9.1.3.1's mandatory suite, with
//     an eight-octet tag: the shortened tag is a deliberate trade for a
//     protocol whose whole message fits in a datagram, and it is last because
//     a client that can do better should.
//   - TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 for the parts with no AES
//     instruction.
//
// What is missing is forward secrecy. The only ECDHE_PSK suite this library
// implements is CBC-with-SHA256, which is the construction every attack on TLS
// record padding has been about; a relay that offered it would be trading a
// known weakness for a property, and an estate that wants forward secrecy on
// this listener wants the certificate mode instead. That is a limit of what is
// available here and it is written down rather than left to be discovered.
func PSKSuites() []uint16 {
	return []uint16{
		uint16(dtls.TLS_PSK_WITH_AES_128_GCM_SHA256),
		uint16(dtls.TLS_PSK_WITH_AES_128_CCM),
		uint16(dtls.TLS_PSK_WITH_AES_128_CCM_8),
		uint16(dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256),
	}
}

// certificateSuites are the ones a listener keeps when it holds both a
// certificate and a table, so that naming the PSK suites does not take the
// certificate mode away. They are the library's own defaults, written out for
// the same reason: a list has to be given, so it is a list somebody chose.
func certificateSuites() []dtls.CipherSuiteID {
	return []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		dtls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
}

// KeyFingerprint is the SHA-256 of a public key's SubjectPublicKeyInfo, as
// lower-case hexadecimal with no separators.
//
// It is the identity RFC 7250's raw public key mode is about: the key itself,
// with nothing vouching for it and nothing to expire. A policy that names one
// of these is pinning a device rather than trusting an authority, which is the
// right shape for an estate that has a hundred sensors and no certificate
// authority -- and it is stable across a certificate being reissued, because
// the certificate is only the envelope the key arrived in.
func KeyFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ParseKeyFingerprint reads a public key fingerprint as an operator writes it:
// the SHA-256 of a SubjectPublicKeyInfo in hexadecimal, with "sha256:"
// optionally in front and colons, spaces or hyphens between the octets
// ignored, because a fingerprint gets pasted from whatever printed it.
//
// Only SHA-256 is accepted. The other digests RFC 6353's certificate table
// allows are there for equipment that shipped with them; this table is new, a
// raw public key is pinned rather than chained, and a pin is worth exactly the
// collision resistance of the hash that expresses it.
func ParseKeyFingerprint(s string) (string, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return "", errors.New("required")
	}
	lower := strings.ToLower(t)
	// A fingerprint written with colons between the octets begins with an
	// octet, so what is in front of the first colon is a digest name only
	// when it reads as one.
	if algo, rest, ok := strings.Cut(lower, ":"); ok && strings.Contains(algo, "sha") {
		if algo != "sha256" {
			return "", fmt.Errorf("%q names a digest other than sha256, which is the only one a key pin uses here",
				clipIdentity(s))
		}
		lower = rest
	}
	lower = strings.NewReplacer(":", "", "-", "", " ", "").Replace(lower)
	raw, err := hex.DecodeString(lower)
	if err != nil {
		return "", fmt.Errorf("%q is not hexadecimal: %w", clipIdentity(s), err)
	}
	if len(raw) != sha256.Size {
		return "", fmt.Errorf("%q is %d octets; a sha256 fingerprint is %d",
			clipIdentity(s), len(raw), sha256.Size)
	}
	return hex.EncodeToString(raw), nil
}
