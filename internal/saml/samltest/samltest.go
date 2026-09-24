// Package samltest is a minimal SAML identity provider for tests: it
// mints responses that are genuinely signed, so a service provider's
// checks can be exercised against documents a real provider could have
// sent rather than against fixtures the verifier itself produced.
//
// It is test scaffolding, not a provider: it has no user database, no
// session, and it signs whatever it is asked to sign, including
// documents a provider would refuse to make.
package samltest

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/saml"
)

const (
	nsAssertion  = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsProtocol   = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsMetadata   = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig       = "http://www.w3.org/2000/09/xmldsig#"
	algExcC14N   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"

	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	statusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	methodBearer    = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // a SAML confirmation method identifier
)

// IDP is the test provider: an entity identifier, a single sign-on
// endpoint and one RSA signing key with a self-signed certificate.
type IDP struct {
	EntityID string
	SSOURL   string
	Key      *rsa.PrivateKey
	Cert     *x509.Certificate
}

// New returns a provider with a fresh key.
func New(entityID, ssoURL string) (*IDP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "samltest identity provider"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &IDP{EntityID: entityID, SSOURL: ssoURL, Key: key, Cert: cert}, nil
}

// CertPEM is the signing certificate, for idp_cert_file.
func (i *IDP) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.Cert.Raw})
}

// MetadataXML is the provider's metadata, for idp_metadata_file.
func (i *IDP) MetadataXML() []byte {
	return []byte(`<?xml version="1.0"?>` +
		`<md:EntityDescriptor xmlns:md="` + nsMetadata + `" entityID="` + escapeAttr(i.EntityID) + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="` + nsProtocol + `">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="` + nsDSig + `"><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(i.Cert.Raw) +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleSignOnService Binding="` + bindingRedirect + `" Location="` + escapeAttr(i.SSOURL) + `"/>` +
		`<md:SingleSignOnService Binding="` + bindingPOST + `" Location="` + escapeAttr(i.SSOURL) + `"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`)
}

// Options describe one response. The zero value of a field means the
// obvious thing, so a test names only what it is about.
type Options struct {
	// ACS is the Destination of the response and the Recipient of the
	// subject confirmation.
	ACS string
	// Audience is the service provider the assertion is for.
	Audience string
	// InResponseTo is the request identifier the response answers.
	InResponseTo string
	NameID       string
	NameIDFormat string
	SessionIndex string
	Attributes   map[string][]string
	// Now is the issue instant; zero means the current time.
	Now time.Time
	// Lifetime is how long the assertion is valid; zero means five
	// minutes.
	Lifetime time.Duration
	// Sign is "assertion" (the default), "response", "both" or "none".
	Sign string
	// ResponseID and AssertionID default to fresh identifiers.
	ResponseID, AssertionID string
	// Status is the status code; empty means success.
	Status string
	// StatusMessage accompanies a failure.
	StatusMessage string
}

func (o *Options) fill() {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Lifetime == 0 {
		o.Lifetime = 5 * time.Minute
	}
	if o.Sign == "" {
		o.Sign = "assertion"
	}
	if o.Status == "" {
		o.Status = statusSuccess
	}
	if o.NameIDFormat == "" {
		o.NameIDFormat = saml.NameIDEmail
	}
	if o.ResponseID == "" {
		o.ResponseID = saml.NewID()
	}
	if o.AssertionID == "" {
		o.AssertionID = saml.NewID()
	}
	if o.SessionIndex == "" {
		o.SessionIndex = saml.NewID()
	}
}

// Response returns a signed response document.
func (i *IDP) Response(o Options) ([]byte, error) {
	o.fill()
	if o.ACS == "" || o.Audience == "" || o.NameID == "" {
		return nil, errors.New("samltest: ACS, Audience and NameID are required")
	}
	instant := o.Now.UTC().Format(time.RFC3339)
	expiry := o.Now.Add(o.Lifetime).UTC().Format(time.RFC3339)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<samlp:Response xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion + `"`)
	b.WriteString(` ID="` + escapeAttr(o.ResponseID) + `" Version="2.0" IssueInstant="` + instant + `"`)
	b.WriteString(` Destination="` + escapeAttr(o.ACS) + `"`)
	if o.InResponseTo != "" {
		b.WriteString(` InResponseTo="` + escapeAttr(o.InResponseTo) + `"`)
	}
	b.WriteString(`><saml:Issuer>` + escapeText(i.EntityID) + `</saml:Issuer>`)
	b.WriteString(`<!--RESPONSE-SIGNATURE-->`)
	b.WriteString(`<samlp:Status><samlp:StatusCode Value="` + escapeAttr(o.Status) + `"/>`)
	if o.StatusMessage != "" {
		b.WriteString(`<samlp:StatusMessage>` + escapeText(o.StatusMessage) + `</samlp:StatusMessage>`)
	}
	b.WriteString(`</samlp:Status>`)
	b.WriteString(`<saml:Assertion ID="` + escapeAttr(o.AssertionID) + `" Version="2.0" IssueInstant="` + instant + `">`)
	b.WriteString(`<saml:Issuer>` + escapeText(i.EntityID) + `</saml:Issuer>`)
	b.WriteString(`<!--ASSERTION-SIGNATURE-->`)
	b.WriteString(`<saml:Subject><saml:NameID Format="` + escapeAttr(o.NameIDFormat) + `">` + escapeText(o.NameID) + `</saml:NameID>`)
	b.WriteString(`<saml:SubjectConfirmation Method="` + methodBearer + `"><saml:SubjectConfirmationData Recipient="` + escapeAttr(o.ACS) + `"`)
	if o.InResponseTo != "" {
		b.WriteString(` InResponseTo="` + escapeAttr(o.InResponseTo) + `"`)
	}
	b.WriteString(` NotOnOrAfter="` + expiry + `"/></saml:SubjectConfirmation></saml:Subject>`)
	b.WriteString(`<saml:Conditions NotBefore="` + o.Now.Add(-time.Minute).UTC().Format(time.RFC3339) + `" NotOnOrAfter="` + expiry + `">`)
	b.WriteString(`<saml:AudienceRestriction><saml:Audience>` + escapeText(o.Audience) + `</saml:Audience></saml:AudienceRestriction>`)
	b.WriteString(`</saml:Conditions>`)
	b.WriteString(`<saml:AuthnStatement AuthnInstant="` + instant + `" SessionIndex="` + escapeAttr(o.SessionIndex) + `">`)
	b.WriteString(`<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>`)
	b.WriteString(`</saml:AuthnStatement>`)
	if len(o.Attributes) > 0 {
		b.WriteString(`<saml:AttributeStatement>`)
		names := make([]string, 0, len(o.Attributes))
		for name := range o.Attributes {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			b.WriteString(`<saml:Attribute Name="` + escapeAttr(name) + `" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">`)
			for _, v := range o.Attributes[name] {
				b.WriteString(`<saml:AttributeValue>` + escapeText(v) + `</saml:AttributeValue>`)
			}
			b.WriteString(`</saml:Attribute>`)
		}
		b.WriteString(`</saml:AttributeStatement>`)
	}
	b.WriteString(`</saml:Assertion></samlp:Response>`)
	doc := b.String()
	// The assertion is signed first: a signature over the response
	// covers the assertion's own signature, so it has to be there
	// already.
	if o.Sign == "assertion" || o.Sign == "both" {
		signed, err := i.sign(doc, "<!--ASSERTION-SIGNATURE-->", o.AssertionID)
		if err != nil {
			return nil, err
		}
		doc = signed
	}
	if o.Sign == "response" || o.Sign == "both" {
		signed, err := i.sign(doc, "<!--RESPONSE-SIGNATURE-->", o.ResponseID)
		if err != nil {
			return nil, err
		}
		doc = signed
	}
	return []byte(doc), nil
}

// Encoded is Response in the form the browser posts.
func (i *IDP) Encoded(o Options) (string, error) {
	raw, err := i.Response(o)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// sign replaces a placeholder with an enveloped signature over the
// element carrying id.
func (i *IDP) sign(doc, placeholder, id string) (string, error) {
	canon, err := saml.Canonical([]byte(doc), id, true)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canon)
	signedInfo := `<ds:SignedInfo xmlns:ds="` + nsDSig + `">` +
		`<ds:CanonicalizationMethod Algorithm="` + algExcC14N + `"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="` + algRSASHA256 + `"></ds:SignatureMethod>` +
		`<ds:Reference URI="#` + id + `">` +
		`<ds:Transforms><ds:Transform Algorithm="` + algEnveloped + `"></ds:Transform>` +
		`<ds:Transform Algorithm="` + algExcC14N + `"></ds:Transform></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + algSHA256 + `"></ds:DigestMethod>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue>` +
		`</ds:Reference></ds:SignedInfo>`
	siCanon, err := saml.Canonical([]byte(signedInfo), "", false)
	if err != nil {
		return "", err
	}
	siDigest := sha256.Sum256(siCanon)
	value, err := rsa.SignPKCS1v15(rand.Reader, i.Key, crypto.SHA256, siDigest[:])
	if err != nil {
		return "", err
	}
	sig := `<ds:Signature xmlns:ds="` + nsDSig + `">` + signedInfo +
		`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(value) + `</ds:SignatureValue>` +
		`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(i.Cert.Raw) +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`
	out := strings.Replace(doc, placeholder, sig, 1)
	if out == doc {
		return "", fmt.Errorf("samltest: placeholder %q not found", placeholder)
	}
	return out, nil
}

func escapeText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func escapeAttr(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")
	return r.Replace(s)
}

// AuthnRequest is what a provider reads out of a redirect a service
// provider sent it.
type AuthnRequest struct {
	ID          string
	Destination string
	ACS         string
	Issuer      string
	ForceAuthn  bool
	RelayState  string
}

// ReadRedirect parses a Location a service provider redirected the
// browser to: the deflated, base64 request in its query. The document is
// read with encoding/xml, which is fine here and nowhere near a
// signature: this is a request the test itself produced.
func ReadRedirect(location string) (*AuthnRequest, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	encoded := q.Get("SAMLRequest")
	if encoded == "" {
		return nil, errors.New("samltest: the redirect carries no SAMLRequest")
	}
	deflated, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("samltest: the request is not base64: %w", err)
	}
	r := flate.NewReader(bytes.NewReader(deflated))
	defer func() { _ = r.Close() }()
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("samltest: the request does not inflate: %w", err)
	}
	var doc struct {
		ID          string `xml:"ID,attr"`
		Destination string `xml:"Destination,attr"`
		ACS         string `xml:"AssertionConsumerServiceURL,attr"`
		ForceAuthn  string `xml:"ForceAuthn,attr"`
		Issuer      string `xml:"Issuer"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("samltest: the request does not parse: %w", err)
	}
	return &AuthnRequest{ID: doc.ID, Destination: doc.Destination, ACS: doc.ACS,
		Issuer: strings.TrimSpace(doc.Issuer), ForceAuthn: doc.ForceAuthn == "true",
		RelayState: q.Get("RelayState")}, nil
}
