package snmp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/snmp"
)

// What stops this listener being built.
//
// Everything in the snmp section is compiled once, and this kind compiles a
// great deal: the policy, the identity it presents upstream, the certificate
// table, the behavioural models. Each is a configuration whose failure an
// operator would otherwise meet as traffic -- and on the protocol that
// monitors everything else, that means meeting it as an outage of the
// monitoring.

// loadError builds a listener from the section given and returns the error, or
// nil when it started.
func loadError(t *testing.T, section string) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return proxytest.StartError(t, fmt.Sprintf(snmpYAML, section, ln.Addr().String()))
}

func TestWhatStopsTheListenerBeingBuilt(t *testing.T) {
	dir := t.TempDir()
	notACert := filepath.Join(dir, "not-a-certificate.pem")
	if err := os.WriteFile(notACert, []byte("this is not PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "usm.secret")
	if err := os.WriteFile(secret, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const head = "        upstream: agents\n        allow_clients: [\"127.0.0.0/8\"]\n"
	for _, tc := range []struct{ name, section, want string }{
		{"a rule naming an OID that is not one", head + `        rules:
          - {name: r, action: allow, oids: ["not.an.oid"]}`, "oids"},

		{"a certificate row whose mapping derives the name and is given one",
			head + `        cert_to_name:
          - {fingerprint: any, map: san_dns, name: switch-3}`, "cert_to_name[0]"},
		{"a certificate row whose mapping needs a name and has none",
			head + `        cert_to_name:
          - {fingerprint: any, map: specified}`, "cert_to_name[0].name"},
		{"a certificate row whose mapping is not one",
			head + `        cert_to_name:
          - {fingerprint: any, map: by-vibes}`, "cert_to_name[0].map"},
		{"a certificate row whose fingerprint is not one",
			head + `        cert_to_name:
          - {fingerprint: "sha256:not-hexadecimal", map: san_any}`, "cert_to_name[0].fingerprint"},

		{"an upstream identity at a level that is not one",
			head + `        upstream_usm: {name: relay, auth: sha256, auth_secret: ` + secret + `}
        upstream_security_level: quite-secure`, "upstream_security_level"},
		{"an upstream identity with an authentication protocol that is not one",
			head + `        upstream_usm: {name: relay, auth: md4, auth_secret: ` + secret + `}`,
			"upstream_usm"},

		{"an upgrade to a version that is not one",
			head + "        upgrade_version: v4", "upgrade_version"},
		{"an upgrade to version three with no identity to sign with",
			head + "        upgrade_version: v3", "upgrade_version"},

		{"a trust store for the agents that is not one",
			head + "        upstream_tls_mode: implicit\n        upstream_tls: {ca_file: " +
				notACert + "}", "upstream_tls"},

		{"a behavioural action that is not one",
			head + "        anomaly: {enabled: true, action: tarpit}", "action"},
	} {
		err := loadError(t, tc.section)
		if err == nil {
			t.Errorf("%s: loaded", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not name %q", tc.name, err, tc.want)
		}
	}

	// And a section carrying every one of those settings correctly, including
	// the rate limit with no burst named -- which is the rate -- and a
	// downgrade to v2c, which needs the community a v3 message does not
	// carry.
	if err := loadError(t, head+`        rate_limit: 100
        upgrade_version: v2c
        upstream_community: nms-upstream
        versions: [v1, v2c]
        communities: [nms]
        rules:
          - {name: mib-2, action: allow, access: [read], oids: ["1.3.6.1.2.1"]}
`); err != nil {
		t.Errorf("a section that should load: %v", err)
	}
}

// The certificate table on its own, at the layer the validator sits in front
// of.
//
// Both layers check it, and that is deliberate rather than redundant: the
// validator is what an operator's `-validate` run reads, and this is what the
// listener will not start without. A table built from a configuration the
// validator never saw -- a test, a future caller, a reload path -- still has
// to be refused rather than silently mapping every certificate to nothing.
func TestTheCertificateTableIsCheckedWhereItIsBuilt(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		rows       []config.SNMPCertName
	}{
		{"a mapping that needs a name and has none", "needs a name",
			[]config.SNMPCertName{{Fingerprint: "any", Map: wire.CertMapSpecified}}},
		{"a mapping that derives the name and is given one", "must be empty",
			[]config.SNMPCertName{{Fingerprint: "any", Map: wire.CertMapSANDNS, Name: "switch-3"}}},
		{"a mapping nothing implements", "is not one of",
			[]config.SNMPCertName{{Fingerprint: "any", Map: "by-vibes"}}},
		{"a fingerprint that is not one", "",
			[]config.SNMPCertName{{Fingerprint: "sha256:not-hexadecimal", Map: wire.CertMapSANAny}}},
	} {
		_, err := compileCertNames(tc.rows)
		if err == nil {
			t.Errorf("%s: compiled", tc.name)
			continue
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say what was wrong", tc.name, err)
		}
	}
	// No rows is no table rather than an empty one, which is the difference
	// between a listener that maps nothing and a listener with no mapping
	// configured.
	if got, err := compileCertNames(nil); err != nil || got != nil {
		t.Errorf("no rows compiled to %+v, %v", got, err)
	}
	// And the mapping that takes the name from the row.
	got, err := compileCertNames([]config.SNMPCertName{
		{Fingerprint: "any", Map: wire.CertMapSpecified, Name: "switch-3"}})
	if err != nil || got == nil {
		t.Fatalf("a good row: %+v, %v", got, err)
	}
}

// The identity this relay presents to the agents, at the same layer.
//
// Without one there is nothing to sign with, and the relay says so rather
// than originating a message signed by nothing: an unauthenticated v3 message
// towards an agent that requires authentication is a poll that fails with
// nothing to look at.
func TestTheUpstreamIdentityIsCheckedWhereItIsBuilt(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "usm.secret")
	if err := os.WriteFile(secret, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := keysource.New(nil, time.Minute, nil)

	// No section is no originator, which is what a listener that only
	// forwards v3 messages unchanged has.
	o, err := compileOriginator(&config.SNMPListener{}, res)
	if err != nil || o != nil {
		t.Errorf("no section compiled to %+v, %v", o, err)
	}

	for _, tc := range []struct {
		name, want string
		m          config.SNMPListener
	}{
		{"a security level that is not one", "security level",
			config.SNMPListener{
				UpstreamUSM:           &config.SNMPUser{Name: "relay", Auth: "sha256", AuthSecret: secret},
				UpstreamSecurityLevel: "quite-secure"}},
		{"an authentication protocol that is not one", "authentication protocol",
			config.SNMPListener{
				UpstreamUSM: &config.SNMPUser{Name: "relay", Auth: "md4", AuthSecret: secret}}},
	} {
		if _, err := compileOriginator(&tc.m, res); err == nil {
			t.Errorf("%s: compiled", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say what was wrong", tc.name, err)
		}
	}
}

// How a name is derived from a certificate, which is RFC 6353 s5.3's table
// and the thing a transport-security-model policy is written against.
//
// Each mapping is read from a different part of the certificate, and each has
// a case rule the standard is specific about: a DNS name is case insensitive,
// so matching on case would break a policy on reissue, while the local part
// of an address is case sensitive by RFC 5321 however few systems act like
// it -- the standard's own example is FooBar@Example.COM becoming
// FooBar@example.com.
func TestANameIsDerivedFromTheCertificateTheStandardsWay(t *testing.T) {
	full := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "switch-3.corp.example"},
		EmailAddresses: []string{"FooBar@Example.COM"},
		DNSNames:       []string{"Switch-3.Corp.Example"},
		IPAddresses:    []net.IP{net.ParseIP("2001:db8:0:0:0:0:0:1")},
	}
	for _, tc := range []struct{ how, want string }{
		{wire.CertMapSANRFC822, "FooBar@example.com"},
		{wire.CertMapSANDNS, "switch-3.corp.example"},
		{wire.CertMapSANIP, "2001:db8::1"},
		{wire.CertMapSANAny, "FooBar@example.com"},
		{wire.CertMapCommonName, "switch-3.corp.example"},
	} {
		if got := deriveName(certRow{how: tc.how}, full); got != tc.want {
			t.Errorf("%s derived %q, want %q", tc.how, got, tc.want)
		}
	}
	if got := deriveName(certRow{how: wire.CertMapSpecified, name: "named-here"}, full); got != "named-here" {
		t.Errorf("specified derived %q", got)
	}

	// A certificate with nothing where the mapping looks derives nothing,
	// rather than falling back to another field: a policy written about DNS
	// names must not quietly start matching on common names.
	bare := &x509.Certificate{Subject: pkix.Name{CommonName: "only-a-cn"}}
	for _, how := range []string{wire.CertMapSANRFC822, wire.CertMapSANDNS,
		wire.CertMapSANIP, wire.CertMapSANAny} {
		if got := deriveName(certRow{how: how}, bare); got != "" {
			t.Errorf("%s on a certificate with no subject alternative names derived %q", how, got)
		}
	}
	// san_any takes the first of the three the certificate has, in the
	// standard's order.
	for _, tc := range []struct {
		name string
		c    *x509.Certificate
		want string
	}{
		{"only a DNS name", &x509.Certificate{DNSNames: []string{"Switch-4"}}, "switch-4"},
		{"only an address", &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.0.0.9")}}, "10.0.0.9"},
	} {
		if got := deriveName(certRow{how: wire.CertMapSANAny}, tc.c); got != tc.want {
			t.Errorf("san_any with %s derived %q, want %q", tc.name, got, tc.want)
		}
	}
	// And a mapping this version does not know derives nothing rather than
	// something from the wrong field.
	if got := deriveName(certRow{how: "by-vibes"}, full); got != "" {
		t.Errorf("an unknown mapping derived %q", got)
	}
}
