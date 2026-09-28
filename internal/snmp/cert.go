package snmp

import (
	"crypto/sha1" //nolint:gosec // RFC 6353's own fingerprint algorithms, one of which is this
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
)

// RFC 6353's two textual conventions for naming a certificate and saying what
// to do with it: SnmpTLSFingerprint, which identifies one, and
// snmpTlstmCertToTSNMapType, which says how a security name is derived from it.
//
// They are here rather than in the listener because they are the standard's and
// not a configuration format's: a fingerprint is an algorithm identifier
// followed by a hash of the certificate's DER, and the mapping types are a
// closed list an SNMP implementation is expected to know. The listener reads a
// certificate; this says what the words mean.

// The mapping types, named as this project's configuration spells them. The
// order is worth keeping: the one that needs nothing from the certificate
// first, then the subject alternative names, then the one RFC 6353 provides
// and advises against.
const (
	// CertMapSpecified takes the name from the configuration: the certificate
	// only has to be the right one.
	CertMapSpecified = "specified"
	// CertMapSANRFC822, CertMapSANDNS and CertMapSANIP take it from a subject
	// alternative name, which is where a modern certificate puts the thing it
	// is about.
	CertMapSANRFC822 = "san_rfc822"
	CertMapSANDNS    = "san_dns"
	CertMapSANIP     = "san_ip"
	// CertMapSANAny takes whichever of those three the certificate has, in
	// that order, which is what RFC 6353 s5.3's snmpTlstmCertSANAny does.
	CertMapSANAny = "san_any"
	// CertMapCommonName takes the subject's common name. RFC 6353 provides it
	// for the certificates that predate subject alternative names and advises
	// against it: a common name is free text that has meant several things,
	// and two authorities can issue the same one.
	CertMapCommonName = "common_name"
)

// CertMaps are the mapping types, in that order.
func CertMaps() []string {
	return []string{CertMapSpecified, CertMapSANRFC822, CertMapSANDNS,
		CertMapSANIP, CertMapSANAny, CertMapCommonName}
}

// CertMapKnown says whether a mapping type is one of them.
func CertMapKnown(s string) bool {
	for _, m := range CertMaps() {
		if m == s {
			return true
		}
	}
	return false
}

// CertMapDerives says whether a mapping type takes the name from the
// certificate rather than from the configuration, which is the difference that
// decides whether a configured name is meaningful or misleading.
func CertMapDerives(s string) bool { return s != CertMapSpecified }

// fingerprintLen is the length of each algorithm's hash.
//
// They are RFC 6353's SnmpTLSFingerprint algorithms less MD5, which is refused:
// a fingerprint is an identity here, and an identity an attacker can collide is
// not one. SHA-1 is kept because equipment shipped with SHA-1 fingerprints in
// its configuration and a row naming one is still naming a specific
// certificate -- abusing it would need a second preimage, which is not a break
// anybody has.
var fingerprintLen = map[string]int{
	"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64,
}

// FingerprintAlgos are the algorithms a fingerprint may name, sorted weakest
// first, for a message that has to list them.
func FingerprintAlgos() []string { return []string{"sha1", "sha256", "sha384", "sha512"} }

// ParseFingerprint reads a certificate fingerprint as a configuration writes
// one: "sha256:ab:cd:..." with the algorithm named, plain hexadecimal with the
// algorithm taken from the length, or the empty string and "any", both of which
// mean any certificate and come back as an empty algorithm.
//
// Colons, spaces and hyphens between octets are ignored, so a fingerprint can
// be pasted from whatever printed it.
func ParseFingerprint(s string) (string, []byte, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "any") {
		return "", nil, nil
	}
	algo := ""
	if i := strings.Index(s, ":"); i > 0 && !hexPair(s) {
		algo, s = strings.ToLower(s[:i]), s[i+1:]
	}
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
	sum, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return "", nil, fmt.Errorf("fingerprint %q is not hexadecimal", s)
	}
	if algo == "" {
		for _, name := range FingerprintAlgos() {
			if len(sum) == fingerprintLen[name] {
				algo = name
				break
			}
		}
		if algo == "" {
			return "", nil, fmt.Errorf("a fingerprint of %d octets matches no algorithm; name one, as %q", len(sum), "sha256:<hex>")
		}
	}
	n, ok := fingerprintLen[algo]
	if !ok {
		return "", nil, fmt.Errorf("fingerprint algorithm %q: RFC 6353 names %s (md5 is refused: a fingerprint that can be collided is not an identity)",
			algo, strings.Join(FingerprintAlgos(), ", "))
	}
	if len(sum) != n {
		return "", nil, fmt.Errorf("a %s fingerprint is %d octets and this one is %d", algo, n, len(sum))
	}
	return algo, sum, nil
}

// hexPair says whether a string begins with two hexadecimal digits and a
// colon, so that "AB:CD:..." is not read as an algorithm called "AB".
func hexPair(s string) bool {
	if len(s) < 3 || s[2] != ':' {
		return false
	}
	_, err := hex.DecodeString(strings.ToLower(s[:2]))
	return err == nil
}

// Fingerprint hashes a certificate's DER with one of the algorithms above, and
// returns nil for one it does not know.
func Fingerprint(algo string, der []byte) []byte {
	switch algo {
	case "sha1":
		sum := sha1.Sum(der) //nolint:gosec // a fingerprint an operator configured, not a signature
		return sum[:]
	case "sha256":
		sum := sha256.Sum256(der)
		return sum[:]
	case "sha384":
		sum := sha512.Sum384(der)
		return sum[:]
	case "sha512":
		sum := sha512.Sum512(der)
		return sum[:]
	}
	return nil
}

// SameFingerprint compares two fingerprints.
//
// The lengths must match, which is the point: a comparison that stopped at the
// shorter of the two would let a truncated fingerprint match every certificate
// beginning with those octets, which is a prefix match wearing the word
// fingerprint. Lengths are checked when a configuration is read as well; this
// is the second of the two places.
func SameFingerprint(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
