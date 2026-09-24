package jwt

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// Certificate-bound access tokens, RFC 8705 section 3.
//
// This is the other half of the answer to a stolen bearer token, beside
// DPoP. Where DPoP has the client sign a fresh proof with a key it keeps,
// a certificate-bound token needs no proof at all: the client already
// proved possession of its private key in the TLS handshake, and the
// authorization server has recorded the certificate's thumbprint in the
// token as `cnf["x5t#S256"]`. So the check is a comparison -- the
// thumbprint of the certificate on this connection against the one in the
// token -- and a token lifted out of a log or a crash dump is useless on
// any other connection.
//
// It is the cheaper of the two and the more limited: it works only where
// the client can present a certificate, which in practice means machine
// to machine. A browser cannot do it, which is why DPoP exists.
//
// The certificate this proxy compares against is the one from the
// handshake it terminated. Where TLS is terminated in front of this proxy
// the certificate arrives in a header instead, and reading it is gated on
// the peer being inside trusted_proxies -- because a client that can set
// that header would otherwise choose which certificate its token is
// checked against, which is the whole of the check.

// Certificate binding errors.
var (
	// ErrCertMissing is a certificate-bound token presented on a
	// connection with no client certificate.
	ErrCertMissing = errors.New("jwt: no client certificate")
	// ErrCertBinding is a token bound to another certificate than the one
	// presented.
	ErrCertBinding = errors.New("jwt: client certificate is not the token's")
	// ErrCertUnbound is a token with no cnf.x5t#S256 where one is
	// required.
	ErrCertUnbound = errors.New("jwt: access token is not bound to a certificate")
)

// certBinding modes, spelled as DPoP's are.
const (
	certOff     = "off"
	certAllow   = "allow"
	certRequire = "require"
)

// maxCertHeader bounds a forwarded certificate. A certificate over 16 KiB
// is not one a handshake would have carried either.
const maxCertHeader = 16 << 10

// certBinding is a provider's compiled certificate-binding policy.
type certBinding struct {
	mode string
	// forwarded reads the certificate from the RFC 9440 Client-Cert
	// header, and only from a trusted peer.
	forwarded bool
}

func newCertBinding(c *config.CertificateBinding) *certBinding {
	if c == nil || c.Mode == "" || c.Mode == certOff {
		return &certBinding{mode: certOff}
	}
	return &certBinding{mode: c.Mode, forwarded: c.TrustForwardedHeader}
}

func (b *certBinding) on() bool { return b != nil && b.mode != certOff && b.mode != "" }

// check compares the token's confirmation thumbprint with the client
// certificate of this request. It returns the thumbprint it matched, or
// "" for a token that carries no binding where none is required.
//
// trustedPeer says whether the immediate peer is inside trusted_proxies;
// the forwarded certificate is read only then.
func (b *certBinding) check(r *http.Request, claims Claims, trustedPeer bool) (string, error) {
	want := confirmationCert(claims)
	if want == "" {
		if b.mode == certRequire {
			return "", ErrCertUnbound
		}
		return "", nil
	}
	der, ok := b.certificate(r, trustedPeer)
	if !ok {
		return "", ErrCertMissing
	}
	got := certThumbprint(der)
	// Trailing padding is not in RFC 8705's encoding, but an
	// authorization server that adds it has not issued a different
	// thumbprint, and a mismatch here would be indistinguishable from an
	// attack in the log.
	if subtle.ConstantTimeCompare([]byte(got), []byte(strings.TrimRight(want, "="))) != 1 {
		return "", fmt.Errorf("%w (token %s, connection %s)", ErrCertBinding, short(want), short(got))
	}
	return got, nil
}

// certificate is the client certificate of this request, as DER: the leaf
// of the handshake this proxy terminated, or the one a trusted peer
// forwarded.
func (b *certBinding) certificate(r *http.Request, trustedPeer bool) ([]byte, bool) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Raw, true
	}
	if !b.forwarded || !trustedPeer {
		return nil, false
	}
	return forwardedCertificate(r.Header.Get("Client-Cert"))
}

// forwardedCertificate reads an RFC 9440 Client-Cert field: a Structured
// Fields Byte Sequence, which is base64 between colons, holding the DER
// of the end-entity certificate.
func forwardedCertificate(v string) ([]byte, bool) {
	v = strings.TrimSpace(v)
	if len(v) < 3 || len(v) > maxCertHeader || v[0] != ':' || v[len(v)-1] != ':' {
		return nil, false
	}
	der, err := base64.StdEncoding.DecodeString(v[1 : len(v)-1])
	if err != nil || len(der) == 0 {
		return nil, false
	}
	// Parsed rather than hashed as it arrives: a header that is not a
	// certificate should be no certificate at all, not a thumbprint of
	// something else that will simply fail to match.
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, false
	}
	return der, true
}

// certThumbprint is the RFC 8705 confirmation value: the base64url of the
// SHA-256 of the DER, without padding.
func certThumbprint(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// confirmationCert reads cnf["x5t#S256"] out of an access token's claims.
func confirmationCert(c Claims) string {
	cnf, _ := c["cnf"].(map[string]any)
	if cnf == nil {
		return ""
	}
	thumb, _ := cnf["x5t#S256"].(string)
	return thumb
}

// short is enough of a thumbprint to tell two apart in a log without
// writing a whole one into it.
func short(thumb string) string {
	if len(thumb) > 12 {
		return thumb[:12] + "..."
	}
	return thumb
}
