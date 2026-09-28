package snmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/snmp"
)

// RFC 6353 s5.3's mapping, without a network: a certificate in, a security name
// out, and the reason there is none when there is none.

// leaf builds a certificate with the fields a mapping reads.
func leaf(t *testing.T, cn string, dns, emails []string, ips []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addrs := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		addrs = append(addrs, net.ParseIP(s))
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: cn},
		DNSNames:       dns,
		EmailAddresses: emails,
		IPAddresses:    addrs,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sha256Of(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// The five derivations the standard defines, each on a certificate that has
// what it looks for.
func TestTheMappingsDeriveWhatTheStandardSaysTheyDo(t *testing.T) {
	c := leaf(t, "Operations Centre", []string{"NMS1.Ops.Example.COM"},
		[]string{"FooBar@Example.COM"}, []string{"192.0.2.17"})
	for _, tc := range []struct {
		how, want string
	}{
		// The host part of an address is lowercased and the local part is not:
		// RFC 6353 s5.3's own example, and RFC 5321 says a local part is case
		// sensitive however few systems act like it.
		{wire.CertMapSANRFC822, "FooBar@example.com"},
		// A DNS name is lowercased whole, because it is case insensitive and a
		// policy that matched on case would break on reissue.
		{wire.CertMapSANDNS, "nms1.ops.example.com"},
		{wire.CertMapSANIP, "192.0.2.17"},
		// san_any takes the first of rfc822Name, dNSName, iPAddress that is
		// present, in that order.
		{wire.CertMapSANAny, "FooBar@example.com"},
		{wire.CertMapCommonName, "Operations Centre"},
	} {
		names, err := compileCertNames([]config.SNMPCertName{{Fingerprint: "any", Map: tc.how}})
		if err != nil {
			t.Fatalf("%s: %v", tc.how, err)
		}
		got, why := names.Name([]*x509.Certificate{c})
		if got != tc.want || why != "" {
			t.Errorf("%s derived %q (%s), want %q", tc.how, got, why, tc.want)
		}
	}

	// san_any falls through in order, so a certificate with no address gives
	// its DNS name and one with neither gives its address.
	for _, tc := range []struct {
		cert *x509.Certificate
		want string
	}{
		{leaf(t, "x", []string{"switch7.example.com"}, nil, nil), "switch7.example.com"},
		{leaf(t, "x", nil, nil, []string{"198.51.100.4"}), "198.51.100.4"},
	} {
		names, err := compileCertNames([]config.SNMPCertName{{Fingerprint: "any"}})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := names.Name([]*x509.Certificate{tc.cert}); got != tc.want {
			t.Errorf("san_any derived %q, want %q", got, tc.want)
		}
	}
}

// The table is ordered and the first matching fingerprint decides -- including
// deciding that there is no name, which is the case a fall-through would get
// wrong.
func TestTheFirstMatchingRowDecidesEvenWhenItDerivesNothing(t *testing.T) {
	bare := leaf(t, "", nil, nil, nil)
	names, err := compileCertNames([]config.SNMPCertName{
		{Fingerprint: sha256Of(bare), Map: wire.CertMapSANDNS},
		// A row that would have named it, and must not be reached: the row
		// above is about this certificate, and it decided.
		{Fingerprint: "any", Map: wire.CertMapSpecified, Name: "fallback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, why := names.Name([]*x509.Certificate{bare})
	if got != "" {
		t.Errorf("a later row named a certificate an earlier row had decided: %q", got)
	}
	if why != "cert_name_empty" {
		t.Errorf("reason %q, want cert_name_empty", why)
	}

	// A certificate no row is about reaches the `any` row, which is what makes
	// that row a default rather than an override.
	other := leaf(t, "x", []string{"switch9.example.com"}, nil, nil)
	if got, why := names.Name([]*x509.Certificate{other}); got != "fallback" {
		t.Errorf("the default row derived %q (%s)", got, why)
	}
}

// The reasons, which become refusal detail and have to tell an operator which
// of three quite different things went wrong.
func TestTheReasonSaysWhichWayItFailed(t *testing.T) {
	c := leaf(t, "x", []string{"a.example.com"}, nil, nil)
	pinned := leaf(t, "y", []string{"b.example.com"}, nil, nil)
	names, err := compileCertNames([]config.SNMPCertName{
		{Fingerprint: sha256Of(pinned), Map: wire.CertMapSANDNS},
	})
	if err != nil {
		t.Fatal(err)
	}
	for what, tc := range map[string]struct {
		table *certNames
		chain []*x509.Certificate
		want  string
	}{
		"no table at all":       {nil, []*x509.Certificate{c}, "no_cert_mapping"},
		"no certificate":        {names, nil, "no_certificate"},
		"no row about this one": {names, []*x509.Certificate{c}, "cert_not_mapped"},
	} {
		got, why := tc.table.Name(tc.chain)
		if got != "" || why != tc.want {
			t.Errorf("%s: %q %q, want reason %q", what, got, why, tc.want)
		}
	}
}

// What a row cannot be. Every one of these is a configuration that would look
// like a control and not be one, so it is refused at load rather than at the
// first handshake.
func TestARowThatWouldNotMeanWhatItSaysIsRefused(t *testing.T) {
	for what, row := range map[string]config.SNMPCertName{
		"specified with no name": {Fingerprint: "any", Map: wire.CertMapSpecified},
		"a derived name and one written beside it": {Fingerprint: "any",
			Map: wire.CertMapSANDNS, Name: "nms"},
		"a mapping that does not exist":         {Fingerprint: "any", Map: "subject"},
		"a fingerprint that is not hexadecimal": {Fingerprint: "sha256:zzzz"},
		"a fingerprint of the wrong length for its algorithm": {
			Fingerprint: "sha256:0102030405"},
		"a fingerprint no algorithm has": {Fingerprint: "0102030405"},
		"md5, which can be collided":     {Fingerprint: "md5:0102030405060708090a0b0c0d0e0f10"},
	} {
		if _, err := compileCertNames([]config.SNMPCertName{row}); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}

	// And what a row can be: the forms a fingerprint is pasted in.
	c := leaf(t, "x", []string{"switch9.example.com"}, nil, nil)
	sum := sha256.Sum256(c.Raw)
	plain := hex.EncodeToString(sum[:])
	for what, fp := range map[string]string{
		"with the algorithm named":   "sha256:" + plain,
		"as bare hexadecimal":        plain,
		"in upper case":              strings.ToUpper(plain),
		"with colons between octets": colonise(plain),
		"any":                        "any",
		"empty, which is any":        "",
	} {
		names, err := compileCertNames([]config.SNMPCertName{{Fingerprint: fp, Map: wire.CertMapSANDNS}})
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if got, why := names.Name([]*x509.Certificate{c}); got != "switch9.example.com" {
			t.Errorf("%s: derived %q (%s)", what, got, why)
		}
	}
}

// colonise writes hexadecimal the way a tool that prints a fingerprint does.
func colonise(s string) string {
	var parts []string
	for i := 0; i+2 <= len(s); i += 2 {
		parts = append(parts, s[i:i+2])
	}
	return strings.Join(parts, ":")
}

// A truncated fingerprint must not match every certificate that begins with
// those octets. The length is checked when the row is read, and again when it
// is compared, because the second is the one that would be a prefix match
// wearing the word fingerprint.
func TestATruncatedFingerprintMatchesNothing(t *testing.T) {
	c := leaf(t, "x", []string{"a.example.com"}, nil, nil)
	sum := sha256.Sum256(c.Raw)
	full := hex.EncodeToString(sum[:])
	if _, err := compileCertNames([]config.SNMPCertName{
		{Fingerprint: "sha256:" + full[:40], Map: wire.CertMapSANDNS},
	}); err == nil {
		t.Error("a truncated fingerprint was accepted at load")
	}
	// And the comparison itself, reached directly, because the row that got
	// past the first check is the one this is about.
	short := sum[:16]
	if wire.SameFingerprint(sum[:], short) {
		t.Error("a short fingerprint compared equal")
	}
	if wire.SameFingerprint(nil, nil) {
		t.Error("two empty fingerprints compared equal")
	}
	if !wire.SameFingerprint(sum[:], sum[:]) {
		t.Error("a fingerprint did not compare equal to itself")
	}
}

// The transports a rule may name, and the one question the listener asks of
// them: did the transport authenticate and encrypt this before we read it.
func TestTransportsAreNamedAndOnlyTwoAreSecure(t *testing.T) {
	for _, name := range Transports() {
		tr, ok := TransportOf(name)
		if !ok || tr.String() != name {
			t.Errorf("%q read back as %q %v", name, tr, ok)
		}
	}
	if _, ok := TransportOf("quic"); ok {
		t.Error("a transport this listener does not have was accepted")
	}
	// Case and space, because a configuration is written by hand.
	if tr, ok := TransportOf(" DTLS "); !ok || tr != TransportDTLS {
		t.Errorf("a transport with space and case read as %q %v", tr, ok)
	}
	for tr, want := range map[Transport]bool{
		TransportUDP: false, TransportTCP: false,
		TransportTLS: true, TransportDTLS: true,
	} {
		if got := tr.Secure(); got != want {
			t.Errorf("%s.Secure() = %v", tr, got)
		}
	}
}

// The discriminator detect mode rests on: a DTLS record and an SNMP message
// cannot be read as each other.
//
// This is not a heuristic that could go either way. An SNMP message is a BER
// SEQUENCE, so it begins with 0x30, which is not a DTLS content type; a record
// begins with 20 to 25 followed by a version whose major octet is 0xFE, and
// neither of those can begin a SEQUENCE.
func TestARecordAndAMessageCannotBeReadAsEachOther(t *testing.T) {
	// Every real SNMP message this package's own builders produce.
	for what, raw := range map[string][]byte{
		"a v2c get": v2c("public", get(1, 1, 3, 6, 1, 2, 1, 1, 1, 0)),
		"a v1 get":  v1msg("public", get(2, 1, 3, 6, 1)),
		"a v3 tsm":  tsm(3, 0x03, get(4, 1, 3, 6, 1)),
		"a v2c set": v2c("private", set(5, "x", 1, 3, 6, 1, 2, 1, 1, 5, 0)),
	} {
		if looksLikeDTLS(raw) {
			t.Errorf("%s was read as a DTLS record", what)
		}
	}
	// And the record types, each with the version octet that follows.
	for _, ct := range []byte{20, 21, 22, 23, 24, 25} {
		rec := append([]byte{ct, 0xFE, 0xFD}, make([]byte, 10)...)
		if !looksLikeDTLS(rec) {
			t.Errorf("a record of content type %d was read as a message", ct)
		}
	}
	// The near misses, which is where a one-octet test would be wrong: a
	// content type in range with a version that is not DTLS, a type out of
	// range, and a datagram too short to be a record header at all.
	for what, raw := range map[string][]byte{
		"a TLS record, not DTLS":    append([]byte{22, 0x03, 0x03}, make([]byte, 10)...),
		"a content type of 19":      append([]byte{19, 0xFE, 0xFD}, make([]byte, 10)...),
		"a content type of 26":      append([]byte{26, 0xFE, 0xFD}, make([]byte, 10)...),
		"a record header one short": {22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"nothing at all":            {},
	} {
		if looksLikeDTLS(raw) {
			t.Errorf("%s was read as a DTLS record", what)
		}
	}
}
