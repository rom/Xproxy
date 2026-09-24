package http

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
)

// The headers that say "this client presented this certificate", and why
// they are removed from every request that did not come from a proxy this
// one trusts.
//
// A backend behind a TLS-terminating proxy cannot see the handshake, so
// the proxy tells it: RFC 9440 standardises Client-Cert and
// Client-Cert-Chain for that, Envoy has used X-Forwarded-Client-Cert for
// years, and nginx and Apache deployments read a handful of X-SSL-Client
// names their configurations set. Every one of them is a statement about
// something only the terminating proxy can know.
//
// Which makes every one of them an authentication bypass when a client
// can send it. The backend has no way to tell the proxy's header from the
// client's -- they are the same bytes in the same field -- so a request
// carrying its own Client-Cert is a request that chooses its own
// identity. RFC 9440 section 3 says this in so many words: the header
// "MUST be sanitised" by the terminating proxy.
//
// So they are deleted from every forwarded request, unless the immediate
// peer is inside trusted_proxies, which is the one case where the header
// belongs to a proxy that did terminate a handshake. A route that sets one
// from ${cert:...} writes the truth over the blank afterwards.
var clientCertHeaders = []string{
	// RFC 9440.
	"Client-Cert",
	"Client-Cert-Chain",
	// Envoy, and the many gateways that copied it.
	"X-Forwarded-Client-Cert",
	// The names nginx and Apache configurations conventionally set, which
	// a great many applications read.
	"X-Client-Cert",
	"X-Client-Cert-Chain",
	"X-Client-Verify",
	"X-Client-Subject-Dn",
	"X-Client-Issuer-Dn",
	"X-Ssl-Client-Cert",
	"X-Ssl-Client-Verify",
	"X-Ssl-Client-S-Dn",
	"X-Ssl-Client-I-Dn",
	"X-Ssl-Client-Serial",
	"X-Ssl-Client-Fingerprint",
	"Ssl-Client-Cert",
	"Ssl-Client-Verify",
	"Ssl-Client-Subject-Dn",
}

// stripClientCert removes the client certificate identity headers from a
// request that did not arrive from a trusted proxy.
func stripClientCert(h http.Header) {
	for _, name := range clientCertHeaders {
		h.Del(name)
	}
}

// How the proxy states the client's certificate to the backend.
const (
	// CertHeadersNone sends nothing; a route may still set its own with
	// ${cert:...}.
	CertHeadersNone = "none"
	// CertHeadersRFC9440 sends Client-Cert and Client-Cert-Chain.
	CertHeadersRFC9440 = "rfc9440"
	// CertHeadersXFCC sends Envoy's X-Forwarded-Client-Cert.
	CertHeadersXFCC = "xfcc"
)

// sendClientCert states the client's certificate to the backend in the
// chosen form. It runs after the strip and before the route's own header
// operations, so an operator can still override it.
//
// Nothing is sent when there is no certificate: an absent header is how
// the backend is told there was none, and an empty one would be a header
// whose meaning depends on how the backend parses emptiness.
func sendClientCert(out http.Header, chain []*x509.Certificate, mode string) {
	if len(chain) == 0 {
		return
	}
	switch mode {
	case CertHeadersRFC9440:
		out.Set("Client-Cert", sfBinary(chain[0].Raw))
		if len(chain) > 1 {
			parts := make([]string, 0, len(chain)-1)
			for _, c := range chain[1:] {
				parts = append(parts, sfBinary(c.Raw))
			}
			out.Set("Client-Cert-Chain", strings.Join(parts, ", "))
		}
	case CertHeadersXFCC:
		if v, ok := certField(chain[0], "xfcc"); ok {
			out.Set("X-Forwarded-Client-Cert", v)
		}
	}
}

// sfBinary encodes DER as the Structured Fields Byte Sequence RFC 9440
// uses: standard base64 with padding, between colons.
//
// Standard base64 and not the URL alphabet, and padded: RFC 8941 defines
// sf-binary that way, and a backend using a structured-fields parser
// rejects anything else rather than guessing.
func sfBinary(der []byte) string {
	return ":" + base64.StdEncoding.EncodeToString(der) + ":"
}
