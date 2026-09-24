package modbus

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
)

// Modbus/TCP Security (MB-TCP-Security v21) is Modbus/TCP inside TLS
// with mutual authentication, and one idea beyond that: the client
// certificate carries the *role* the client holds, and the server
// authorises by role rather than by address.
//
// That is the part worth implementing here. A plant's addressing is what
// an attacker on the wire controls; a role in a certificate is what a
// certificate authority said, and a relay in the path can enforce it for
// devices that will never speak TLS themselves. The specification places
// the role in an x.509 extension under the Modbus organisation's arc,
// and says the server must refuse a client whose role it does not
// recognise -- which is what this package makes possible and the
// listener kind does.

// RoleOID is the object identifier of the Modbus role extension:
// iso.org.dod.internet.private.enterprise.modbus(50316).802.1, where 802
// is the port IANA assigned to Modbus/TCP Security.
var RoleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

// MaxRoleLen bounds a role name. A role is an identifier an operator
// wrote in a policy; anything longer is a certificate carrying something
// else.
const MaxRoleLen = 64

// ErrNoRole says the certificate carries no Modbus role extension.
var ErrNoRole = errors.New("modbus: certificate carries no role extension")

// RoleFromCert reads the role out of a client certificate.
//
// The specification writes the extension's value as a UTF8String. Real
// certificates are produced by real tooling, so a value wrapped in a
// SEQUENCE and a value written as a PrintableString or an IA5String are
// read too -- there is nothing ambiguous about any of them, and refusing
// a certificate over the tag its issuer's tooling chose would be
// refusing the deployment rather than the attack. Anything else is an
// error rather than a guess: a role this relay read differently from the
// device is worse than no role at all.
func RoleFromCert(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrNoRole
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(RoleOID) {
			continue
		}
		role, err := parseRole(ext.Value)
		if err != nil {
			return "", err
		}
		return role, nil
	}
	return "", ErrNoRole
}

func parseRole(der []byte) (string, error) {
	var s string
	rest, err := asn1.Unmarshal(der, &s)
	if err == nil && len(rest) == 0 {
		return checkRole(s)
	}
	// A SEQUENCE holding the string, which is how some tooling encodes
	// a one-field extension.
	var seq struct {
		Role string
	}
	if rest, err2 := asn1.Unmarshal(der, &seq); err2 == nil && len(rest) == 0 {
		return checkRole(seq.Role)
	}
	// An explicitly tagged string: the tag is accepted and the value is
	// what matters.
	var raw asn1.RawValue
	if rest, err2 := asn1.Unmarshal(der, &raw); err2 == nil && len(rest) == 0 && raw.IsCompound {
		var inner string
		if rest2, err3 := asn1.Unmarshal(raw.Bytes, &inner); err3 == nil && len(rest2) == 0 {
			return checkRole(inner)
		}
	}
	return "", fmt.Errorf("modbus: role extension is not a string: %w", err)
}

// checkRole refuses a role that cannot be compared with a configured
// one: an empty name, an overlong one, or one carrying control
// characters or spaces, which is how two implementations come to
// disagree about whether two roles are the same role.
func checkRole(s string) (string, error) {
	if s == "" {
		return "", errors.New("modbus: empty role")
	}
	if len(s) > MaxRoleLen {
		return "", fmt.Errorf("modbus: role of %d characters, over the %d bound", len(s), MaxRoleLen)
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7F {
			return "", errors.New("modbus: role carries a space or a control character")
		}
	}
	return s, nil
}

// RoleFromSubject reads a role out of the certificate subject, for an
// estate whose certificate authority cannot yet issue the extension.
// field is "cn" or "ou".
//
// It is a documented compromise rather than the specification: a subject
// field says who the certificate is for, and using it as a role means
// trusting the naming convention of whoever issues certificates. The
// listener kind makes it an explicit choice and says so in the log.
func RoleFromSubject(cert *x509.Certificate, field string) (string, error) {
	if cert == nil {
		return "", ErrNoRole
	}
	switch strings.ToLower(field) {
	case "cn":
		return checkRole(cert.Subject.CommonName)
	case "ou":
		if len(cert.Subject.OrganizationalUnit) == 0 {
			return "", ErrNoRole
		}
		return checkRole(cert.Subject.OrganizationalUnit[0])
	}
	return "", fmt.Errorf("modbus: role source %q is not cn or ou", field)
}

// RoleExtension builds the extension, which is what makes a test able to
// present a certificate a real device would present. It is exported for
// that reason and because an estate issuing its own certificates has to
// produce this exact encoding.
func RoleExtension(role string) (asn1.ObjectIdentifier, []byte, error) {
	if _, err := checkRole(role); err != nil {
		return nil, nil, err
	}
	der, err := asn1.MarshalWithParams(role, "utf8")
	if err != nil {
		return nil, nil, err
	}
	return RoleOID, der, nil
}
