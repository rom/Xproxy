package snmp

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/snmp"
)

// The certificate to security name mapping, RFC 6353 s5.3.
//
// This is the piece that makes the transport security model a policy and not
// just an encrypted pipe. A (D)TLS peer proves it holds a private key whose
// certificate a certificate authority vouched for; that is authentication, and
// it is not yet an identity a rule can name. RFC 6353 defines a table --
// snmpTlstmCertToTSNTable -- that turns one into the other: rows in order,
// first match wins, each row saying which certificate it is about and how to
// derive a name from it.
//
// The derivations are the standard's, and each exists because estates issue
// certificates differently:
//
//   - **specified**: the name is written in the row. The certificate only has
//     to be the right one. This is the row an estate writes when it wants the
//     name in the policy to be a name it chose rather than whatever the
//     certificate happens to say.
//   - **san_rfc822**, **san_dns**, **san_ip**: the name comes from a subject
//     alternative name, which is where a modern certificate puts the thing it
//     is about. The host part of an address and the whole of a DNS name are
//     lowercased, because the standard says so and because a policy that
//     matched on case would be a policy that broke when a certificate was
//     reissued by a different tool.
//   - **san_any**: whichever of those three the certificate has, in that
//     order.
//   - **common_name**: the subject's common name, which is where a
//     certificate from 2009 puts it. RFC 6353 s5.3 provides it and advises
//     against it, and so does this: a common name is free text that has meant
//     several things, and two certificate authorities can issue the same one.
//
// One thing here is not in the standard and is deliberate: a row may name
// `any` fingerprint. The table is keyed by fingerprint, which means a row per
// certificate and a configuration change every time one is reissued -- and an
// estate that runs its own authority has already decided which authority to
// trust, in `tls.client_ca_file`, where the decision belongs. `any` says "any
// certificate this listener accepted", and it is safe exactly to the extent
// that the listener requires and verifies one; validation says so when it does
// not.

// errCertName is a cert_to_name row that cannot be compiled.
var errCertName = errors.New("cert_to_name")

// certRow is one compiled row.
type certRow struct {
	// algo and sum are the fingerprint this row is about, or algo == "" for
	// the row that is about any accepted certificate.
	algo string
	sum  []byte
	// how is the mapping type and name the security name for `specified`.
	how  string
	name string
}

// certNames is the compiled table.
type certNames struct {
	rows []certRow
	// anyRow says whether some row matches any certificate, which validation
	// asks about so that it can warn when the listener does not require one.
	anyRow bool
}

// compileCertNames builds the table. Everything that can be wrong with a row
// is wrong here, at load, rather than at the first handshake that presents a
// certificate.
func compileCertNames(in []config.SNMPCertName) (*certNames, error) {
	if len(in) == 0 {
		return nil, nil
	}
	t := &certNames{}
	for i := range in {
		r := &in[i]
		where := fmt.Sprintf("%s[%d]", errCertName, i)
		row := certRow{how: r.Map, name: r.Name}
		if row.how == "" {
			row.how = wire.CertMapSANAny
		}
		switch row.how {
		case wire.CertMapSpecified:
			if row.name == "" {
				return nil, fmt.Errorf("%s: map: specified needs a name", where)
			}
		case wire.CertMapSANRFC822, wire.CertMapSANDNS, wire.CertMapSANIP, wire.CertMapSANAny, wire.CertMapCommonName:
			if row.name != "" {
				// A name beside a mapping that derives one would look like it
				// applied and would not. Refusing is the difference between a
				// policy an operator can read and one they have to test.
				return nil, fmt.Errorf("%s: map: %s derives the name from the certificate, so name must be empty", where, row.how)
			}
		default:
			return nil, fmt.Errorf("%s: map: %q is not one of %s", where, row.how,
				strings.Join(wire.CertMaps(), ", "))
		}
		algo, sum, err := wire.ParseFingerprint(r.Fingerprint)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		row.algo, row.sum = algo, sum
		if algo == "" {
			t.anyRow = true
		}
		t.rows = append(t.rows, row)
	}
	return t, nil
}

// Name derives the security name for a peer's certificate chain, or says why
// it could not.
//
// The reason is a stable label rather than a sentence, because it becomes a
// refusal reason and a counter: an estate watching this listener needs to tell
// "nobody wrote a row for that certificate" from "the row matched and the
// certificate has nothing to derive a name from".
func (t *certNames) Name(chain []*x509.Certificate) (string, string) {
	if t == nil || len(t.rows) == 0 {
		return "", "no_cert_mapping"
	}
	if len(chain) == 0 {
		return "", "no_certificate"
	}
	leaf := chain[0]
	sums := map[string][]byte{}
	for _, row := range t.rows {
		if row.algo != "" {
			sum, ok := sums[row.algo]
			if !ok {
				sum = wire.Fingerprint(row.algo, leaf.Raw)
				sums[row.algo] = sum
			}
			if len(sum) == 0 || !wire.SameFingerprint(sum, row.sum) {
				continue
			}
		}
		if name := deriveName(row, leaf); name != "" {
			return name, ""
		}
		// The row is about this certificate and the certificate has nothing
		// where the row looked. The search stops rather than falling through
		// to a later row: the table is ordered and first match wins, and a
		// row that matched the fingerprint has decided which row applies.
		return "", "cert_name_empty"
	}
	return "", "cert_not_mapped"
}

// deriveName applies one row's mapping to a certificate.
func deriveName(row certRow, c *x509.Certificate) string {
	switch row.how {
	case wire.CertMapSpecified:
		return row.name
	case wire.CertMapSANRFC822:
		return firstEmail(c)
	case wire.CertMapSANDNS:
		return firstDNS(c)
	case wire.CertMapSANIP:
		return firstIP(c)
	case wire.CertMapSANAny:
		// RFC 6353 s5.3: the first of rfc822Name, dNSName, iPAddress the
		// certificate has, in that order.
		for _, f := range []func(*x509.Certificate) string{firstEmail, firstDNS, firstIP} {
			if name := f(c); name != "" {
				return name
			}
		}
		return ""
	case wire.CertMapCommonName:
		return c.Subject.CommonName
	}
	return ""
}

// firstEmail is the first rfc822Name, with its host part lowercased and its
// local part left exactly as it was: RFC 6353 s5.3's example is
// "FooBar@Example.COM" mapping to "FooBar@example.com", and the local part of
// an address is case sensitive by RFC 5321 however few systems act like it.
func firstEmail(c *x509.Certificate) string {
	if len(c.EmailAddresses) == 0 {
		return ""
	}
	e := c.EmailAddresses[0]
	if i := strings.LastIndex(e, "@"); i >= 0 {
		return e[:i+1] + strings.ToLower(e[i+1:])
	}
	return e
}

// firstDNS is the first dNSName, lowercased, because a DNS name is case
// insensitive and a policy that matched on case would break on reissue.
func firstDNS(c *x509.Certificate) string {
	if len(c.DNSNames) == 0 {
		return ""
	}
	return strings.ToLower(c.DNSNames[0])
}

// firstIP is the first iPAddress, in the presentation form RFC 5952 asks for,
// which is what net.IP.String writes.
func firstIP(c *x509.Certificate) string {
	if len(c.IPAddresses) == 0 {
		return ""
	}
	return netIPString(c.IPAddresses[0])
}

func netIPString(ip net.IP) string { return ip.String() }
