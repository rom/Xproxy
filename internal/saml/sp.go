// Package saml is a SAML 2.0 service provider: it builds authentication
// requests for an identity provider and checks the signed assertions
// that come back through the browser.
//
// The profile is deliberately narrow, and narrow is the point. Web single
// sign-on breaks in one place -- the verifier and the consumer of an
// assertion disagreeing about what was signed -- and every feature that
// makes a document mean two things is a way to get there. So this
// implementation takes the HTTP POST binding for responses and the HTTP
// Redirect binding for requests, one unencrypted assertion per response
// signed with the key in the configuration, exclusive canonicalization,
// SHA-256 and above, and nothing else. It refuses, rather than ignores:
//
//   - a document type declaration, an entity declaration or any entity
//     reference but the five XML predefines (see xml.go);
//   - an encrypted assertion, attribute or name identifier: XML
//     Encryption in a SAML responder has been a decryption oracle more
//     than once, and TLS already covers the hop this response takes;
//   - more than one assertion in a response, or two elements sharing an
//     ID, which are the shapes signature wrapping needs;
//   - a signature that does not verify, anywhere in the document, even
//     one nothing would have read;
//   - a response with no InResponseTo, so an assertion this proxy did
//     not ask for is never a login (identity-provider-initiated single
//     sign-on is not supported, by choice: it has no state to bind to).
//
// What it accepts, it accepts completely: issuer, destination, audience,
// recipient, both condition windows, the subject confirmation window, the
// status code, the name identifier format and a one-time check on the
// assertion identifier.
package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"

	statusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	methodBearer    = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // a SAML confirmation method identifier
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

	// NameIDTransient and the formats beside it are the ones a service
	// provider normally asks for.
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

// The bounds on what one response may carry. They are generous for a
// login and small enough that a response cannot become a memory budget.
const (
	// MaxResponseBytes bounds the decoded SAMLResponse. The encoded form
	// the browser posts is bounded by the caller's body limit.
	MaxResponseBytes   = 256 << 10
	maxAttributes      = 100
	maxAttributeValues = 50
	maxAttributeName   = 256
	maxAttributeValue  = 4096
	maxNameID          = 1024
	maxIdentifier      = 256
)

// ErrStatus is an identity provider that answered a request with
// something other than success: the user cancelled, or the provider
// refused. It is not a failure of this proxy's checks.
var ErrStatus = errors.New("saml: status")

// ErrRefused is a response that does not satisfy the profile's checks:
// the wrong audience, an expired window, a name identifier format the
// configuration does not allow.
var ErrRefused = errors.New("saml: refused")

// Policy is the service provider's side of the arrangement: who this
// proxy is, where it receives assertions, which provider it believes and
// with which keys.
type Policy struct {
	// EntityID is this service provider's identifier, and the audience
	// every assertion must name.
	EntityID string
	// ACS is the assertion consumer service URL: the Destination of a
	// response and the Recipient of a subject confirmation must be it,
	// exactly, so an assertion minted for another service provider is
	// not a login here.
	ACS string
	// IDPEntityID is the issuer every response and assertion must name.
	IDPEntityID string
	// IDPSSOURL is where an authentication request is sent.
	IDPSSOURL string
	// Keys are the identity provider's signing keys, from the
	// configuration. KeyInfo in the document is never read.
	Keys []crypto.PublicKey
	// Skew is the tolerance on every timestamp.
	Skew time.Duration
	// MaxAge bounds how old an assertion may be, whatever windows it
	// declares: a provider that issues an assertion valid for a week has
	// issued a bearer token valid for a week.
	MaxAge time.Duration
	// RequireResponseSignature and RequireAssertionSignature say which
	// elements must be covered. At least one must be set; a response
	// where neither is signed is never accepted, whatever these say.
	RequireResponseSignature  bool
	RequireAssertionSignature bool
	// NameIDFormats are the accepted name identifier formats; empty
	// accepts any format the assertion declares.
	NameIDFormats []string
	// ForceAuthn asks the provider to re-authenticate the user rather
	// than reuse its own session.
	ForceAuthn bool
	// RequestedNameIDFormat is put in the authentication request; empty
	// asks for nothing in particular.
	RequestedNameIDFormat string
}

// Login is what a verified assertion said.
type Login struct {
	NameID       string
	NameIDFormat string
	SessionIndex string
	AssertionID  string
	InResponseTo string
	AuthnInstant time.Time
	// NotOnOrAfter is the earliest expiry the assertion declared: the
	// condition window, the subject confirmation window and the
	// provider's own session bound, whichever comes first. A session
	// this proxy issues never outlives it.
	NotOnOrAfter time.Time
	Attributes   map[string][]string
	// ResponseSigned and AssertionSigned say what the signatures covered.
	ResponseSigned, AssertionSigned bool
}

// Attr is the first value of an attribute, by name or by friendly name.
func (l *Login) Attr(name string) string {
	if v := l.Attributes[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Accept verifies and checks one response. raw is the decoded XML,
// inResponseTo is the identifier of the authentication request this
// proxy sent and now is the current time.
//
// Every check that can be made without state is made here; the caller
// adds the one that needs state, by refusing an assertion identifier it
// has already seen (see Seen).
func (p *Policy) Accept(raw []byte, inResponseTo string, now time.Time) (*Login, error) {
	if len(raw) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: response larger than %d bytes", errProfile, MaxResponseBytes)
	}
	if inResponseTo == "" {
		return nil, fmt.Errorf("%w: no authentication request to match the response against", ErrRefused)
	}
	doc, err := parseDocument(raw)
	if err != nil {
		return nil, err
	}
	if !doc.is(nsProtocol, "Response") {
		return nil, fmt.Errorf("%w: the document is %q, not a SAML Response", errProfile, doc.qname())
	}
	// Encryption is refused before anything else, so that the refusal
	// names the real reason rather than a missing assertion.
	for _, name := range []string{"EncryptedAssertion", "EncryptedID", "EncryptedAttribute"} {
		var found []*node
		findAll(doc, nsAssertion, name, &found)
		if len(found) > 0 {
			return nil, fmt.Errorf("%w: %s is not accepted; this profile takes assertions in the clear over TLS", errProfile, name)
		}
	}
	var assertions []*node
	findAll(doc, nsAssertion, "Assertion", &assertions)
	if len(assertions) != 1 {
		return nil, fmt.Errorf("%w: the response carries %d assertions, not one", errProfile, len(assertions))
	}
	assertion := assertions[0]
	if assertion.parent != doc {
		return nil, fmt.Errorf("%w: the assertion is not a child of the response", errProfile)
	}
	signed, err := verifySignatures(doc, p.Keys)
	if err != nil {
		return nil, err
	}
	switch {
	case p.RequireResponseSignature && !signed[doc]:
		return nil, fmt.Errorf("%w: the response is not signed", ErrSignature)
	case p.RequireAssertionSignature && !signed[assertion]:
		return nil, fmt.Errorf("%w: the assertion is not signed", ErrSignature)
	case !signed[doc] && !signed[assertion]:
		return nil, fmt.Errorf("%w: neither the response nor the assertion is signed", ErrSignature)
	}
	login := &Login{
		InResponseTo:   inResponseTo,
		Attributes:     map[string][]string{},
		ResponseSigned: signed[doc], AssertionSigned: signed[assertion],
	}
	if err := p.checkResponse(doc, inResponseTo, now); err != nil {
		return nil, err
	}
	if err := p.checkAssertion(assertion, inResponseTo, now, login); err != nil {
		return nil, err
	}
	return login, nil
}

// checkResponse checks the envelope: version, freshness, destination,
// the request it answers and the status the provider reported.
func (p *Policy) checkResponse(doc *node, inResponseTo string, now time.Time) error {
	if v := doc.attrValue("Version"); v != "2.0" {
		return fmt.Errorf("%w: response version %q is not 2.0", errProfile, v)
	}
	if id := doc.attrValue("ID"); id == "" || len(id) > maxIdentifier {
		return fmt.Errorf("%w: the response has no usable ID", errProfile)
	}
	if err := p.instant(doc.attrValue("IssueInstant"), "the response IssueInstant", now); err != nil {
		return err
	}
	// Destination is what makes a response unusable anywhere else. SAML
	// requires it on a signed response; this profile requires it on
	// every response, because a response with no destination is one that
	// can be replayed at another service provider of the same provider.
	if dest := doc.attrValue("Destination"); !sameURL(dest, p.ACS) {
		return fmt.Errorf("%w: the response is addressed to %q, not to %q", ErrRefused, dest, p.ACS)
	}
	if got := doc.attrValue("InResponseTo"); got != inResponseTo {
		return fmt.Errorf("%w: the response answers request %q, not %q", ErrRefused, got, inResponseTo)
	}
	if iss := doc.child(nsAssertion, "Issuer"); iss != nil {
		if got := iss.chars(); got != p.IDPEntityID {
			return fmt.Errorf("%w: the response was issued by %q, not by %q", ErrRefused, got, p.IDPEntityID)
		}
	}
	status := doc.child(nsProtocol, "Status")
	code := status.child(nsProtocol, "StatusCode")
	if code == nil {
		return fmt.Errorf("%w: the response has no status code", errProfile)
	}
	if v := code.attrValue("Value"); v != statusSuccess {
		detail := v
		if second := code.child(nsProtocol, "StatusCode"); second != nil {
			detail += " / " + second.attrValue("Value")
		}
		if msg := status.child(nsProtocol, "StatusMessage").chars(); msg != "" {
			detail += ": " + msg
		}
		return fmt.Errorf("%w: %s", ErrStatus, clip(detail, 200))
	}
	return nil
}

// checkAssertion checks the assertion itself and fills in login.
func (p *Policy) checkAssertion(a *node, inResponseTo string, now time.Time, login *Login) error {
	if v := a.attrValue("Version"); v != "2.0" {
		return fmt.Errorf("%w: assertion version %q is not 2.0", errProfile, v)
	}
	id := a.attrValue("ID")
	if id == "" || len(id) > maxIdentifier {
		return fmt.Errorf("%w: the assertion has no usable ID", errProfile)
	}
	login.AssertionID = id
	if err := p.instant(a.attrValue("IssueInstant"), "the assertion IssueInstant", now); err != nil {
		return err
	}
	if got := a.child(nsAssertion, "Issuer").chars(); got != p.IDPEntityID {
		return fmt.Errorf("%w: the assertion was issued by %q, not by %q", ErrRefused, got, p.IDPEntityID)
	}
	expiry := time.Time{}
	narrow := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if expiry.IsZero() || t.Before(expiry) {
			expiry = t
		}
	}
	// The subject: who this is, and the confirmation that says this
	// browser may present the assertion here and until when.
	subject := a.child(nsAssertion, "Subject")
	nameID := subject.child(nsAssertion, "NameID")
	if nameID == nil {
		return fmt.Errorf("%w: the assertion has no name identifier", errProfile)
	}
	login.NameID = nameID.chars()
	login.NameIDFormat = nameID.attrValue("Format")
	if login.NameID == "" || len(login.NameID) > maxNameID {
		return fmt.Errorf("%w: the name identifier is empty or longer than %d bytes", ErrRefused, maxNameID)
	}
	if len(p.NameIDFormats) > 0 && !contains(p.NameIDFormats, login.NameIDFormat) {
		return fmt.Errorf("%w: name identifier format %q is not allowed", ErrRefused, clip(login.NameIDFormat, 120))
	}
	confirmed := false
	var lastErr error
	for _, sc := range subject.children(nsAssertion, "SubjectConfirmation") {
		if sc.attrValue("Method") != methodBearer {
			continue
		}
		data := sc.child(nsAssertion, "SubjectConfirmationData")
		if data == nil {
			lastErr = fmt.Errorf("%w: a bearer subject confirmation carries no data", errProfile)
			continue
		}
		if r := data.attrValue("Recipient"); !sameURL(r, p.ACS) {
			lastErr = fmt.Errorf("%w: the subject may present this assertion at %q, not at %q", ErrRefused, clip(r, 200), p.ACS)
			continue
		}
		if got := data.attrValue("InResponseTo"); got != inResponseTo {
			lastErr = fmt.Errorf("%w: the subject confirmation answers request %q, not %q", ErrRefused, clip(got, 120), inResponseTo)
			continue
		}
		noa, err := p.deadline(data.attrValue("NotOnOrAfter"), "the subject confirmation", now)
		if err != nil {
			lastErr = err
			continue
		}
		if noa.IsZero() {
			lastErr = fmt.Errorf("%w: the subject confirmation has no expiry", errProfile)
			continue
		}
		if nb := data.attrValue("NotBefore"); nb != "" {
			// A bearer confirmation must not carry NotBefore (SAML 2.0
			// profiles, section 4.1.4.2). One that does is a document
			// written to a different rule than the one being checked.
			lastErr = fmt.Errorf("%w: a bearer subject confirmation must not carry NotBefore", errProfile)
			continue
		}
		narrow(noa)
		confirmed = true
		break
	}
	if !confirmed {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("%w: the assertion has no usable bearer subject confirmation", errProfile)
	}
	// Conditions: the validity window and the audience.
	conds := a.child(nsAssertion, "Conditions")
	if conds == nil {
		return fmt.Errorf("%w: the assertion has no conditions", errProfile)
	}
	if nb := conds.attrValue("NotBefore"); nb != "" {
		t, err := parseInstant(nb)
		if err != nil {
			return fmt.Errorf("%w: the condition NotBefore: %w", errProfile, err)
		}
		if now.Add(p.Skew).Before(t) {
			return fmt.Errorf("%w: the assertion is not valid before %s", ErrRefused, t.Format(time.RFC3339))
		}
	}
	noa, err := p.deadline(conds.attrValue("NotOnOrAfter"), "the assertion conditions", now)
	if err != nil {
		return err
	}
	if noa.IsZero() {
		return fmt.Errorf("%w: the assertion conditions have no expiry", errProfile)
	}
	narrow(noa)
	audienced := false
	for _, ar := range conds.children(nsAssertion, "AudienceRestriction") {
		for _, aud := range ar.children(nsAssertion, "Audience") {
			if aud.chars() == p.EntityID {
				audienced = true
			}
		}
	}
	if !audienced {
		return fmt.Errorf("%w: the assertion does not name %q as an audience", ErrRefused, p.EntityID)
	}
	// A condition this profile does not understand is refused: a
	// condition exists to restrict, and ignoring it grants more than the
	// provider meant to.
	for _, c := range conds.elements() {
		switch c.local {
		case "AudienceRestriction", "OneTimeUse", "ProxyRestriction":
		default:
			return fmt.Errorf("%w: condition %q is not understood", errProfile, c.qname())
		}
	}
	// The authentication statement: when the user authenticated and the
	// provider's own bound on the session that follows.
	stmts := a.children(nsAssertion, "AuthnStatement")
	if len(stmts) == 0 {
		return fmt.Errorf("%w: the assertion carries no authentication statement", errProfile)
	}
	st := stmts[0]
	login.SessionIndex = clip(st.attrValue("SessionIndex"), maxIdentifier)
	if ai := st.attrValue("AuthnInstant"); ai != "" {
		t, err := parseInstant(ai)
		if err != nil {
			return fmt.Errorf("%w: the AuthnInstant: %w", errProfile, err)
		}
		login.AuthnInstant = t
	}
	if sn := st.attrValue("SessionNotOnOrAfter"); sn != "" {
		t, err := p.deadline(sn, "the provider session", now)
		if err != nil {
			return err
		}
		narrow(t)
	}
	if p.MaxAge > 0 {
		narrow(now.Add(p.MaxAge))
	}
	login.NotOnOrAfter = expiry
	return p.attributes(a, login)
}

// attributes reads the attribute statements into login, within bounds.
func (p *Policy) attributes(a *node, login *Login) error {
	for _, as := range a.children(nsAssertion, "AttributeStatement") {
		for _, at := range as.children(nsAssertion, "Attribute") {
			name := at.attrValue("Name")
			if fn := at.attrValue("FriendlyName"); name == "" {
				name = fn
			}
			if name == "" || len(name) > maxAttributeName {
				continue
			}
			if len(login.Attributes) >= maxAttributes {
				return fmt.Errorf("%w: more than %d attributes", errProfile, maxAttributes)
			}
			for _, v := range at.children(nsAssertion, "AttributeValue") {
				// Only the value's own character data is read. A value
				// that arrives wrapped in markup -- a NameID, a nested
				// element -- is not a string, and reading one as a
				// string is how an attribute becomes two things.
				if len(v.elements()) > 0 {
					return fmt.Errorf("%w: attribute %q has a value that is not character data", errProfile, clip(name, 120))
				}
				s := v.chars()
				if len(s) > maxAttributeValue {
					return fmt.Errorf("%w: a value of attribute %q is longer than %d bytes", errProfile, clip(name, 120), maxAttributeValue)
				}
				if len(login.Attributes[name]) >= maxAttributeValues {
					return fmt.Errorf("%w: attribute %q has more than %d values", errProfile, clip(name, 120), maxAttributeValues)
				}
				login.Attributes[name] = append(login.Attributes[name], s)
			}
			if _, ok := login.Attributes[name]; !ok {
				login.Attributes[name] = nil
			}
		}
	}
	return nil
}

// instant checks a timestamp: present, parseable, not from the future
// and not older than MaxAge.
func (p *Policy) instant(s, what string, now time.Time) error {
	if s == "" {
		return fmt.Errorf("%w: %s is missing", errProfile, what)
	}
	t, err := parseInstant(s)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", errProfile, what, err)
	}
	if now.Add(p.Skew).Before(t) {
		return fmt.Errorf("%w: %s is in the future (%s)", ErrRefused, what, t.Format(time.RFC3339))
	}
	if p.MaxAge > 0 && t.Add(p.MaxAge).Before(now.Add(-p.Skew)) {
		return fmt.Errorf("%w: %s is older than %s", ErrRefused, what, p.MaxAge)
	}
	return nil
}

// deadline parses a NotOnOrAfter and refuses one that has passed.
func (p *Policy) deadline(s, what string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := parseInstant(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s expiry: %w", errProfile, what, err)
	}
	if !now.Add(-p.Skew).Before(t) {
		return time.Time{}, fmt.Errorf("%w: %s expired at %s", ErrRefused, what, t.Format(time.RFC3339))
	}
	return t, nil
}

// parseInstant reads an xsd:dateTime. SAML requires UTC, and a timestamp
// with no zone is a timestamp whose meaning depends on the reader.
func parseInstant(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a UTC timestamp", clip(s, 64))
	}
	return t.UTC(), nil
}

// sameURL compares two absolute URLs the way the SAML profile means them
// to be compared: as strings, but tolerating a trailing empty query and
// the default port of the scheme, which proxies and libraries add.
func sameURL(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	if got == want {
		return true
	}
	a, err1 := url.Parse(got)
	b, err2 := url.Parse(want)
	if err1 != nil || err2 != nil {
		return false
	}
	norm := func(u *url.URL) string {
		host := strings.ToLower(u.Host)
		switch {
		case u.Scheme == "https" && strings.HasSuffix(host, ":443"):
			host = strings.TrimSuffix(host, ":443")
		case u.Scheme == "http" && strings.HasSuffix(host, ":80"):
			host = strings.TrimSuffix(host, ":80")
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		s := strings.ToLower(u.Scheme) + "://" + host + path
		if u.RawQuery != "" {
			s += "?" + u.RawQuery
		}
		return s
	}
	return norm(a) == norm(b)
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// NewID is an identifier for a request this proxy sends. xsd:ID may not
// start with a digit, hence the underscore.
func NewID() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

// AuthnRequest is the request this proxy sends the identity provider,
// unsigned: it carries no secret, and the response it asks for is
// checked against this proxy's own state whatever the request looked
// like.
func (p *Policy) AuthnRequest(id string, now time.Time) []byte {
	var b strings.Builder
	b.WriteString(`<samlp:AuthnRequest xmlns:samlp="` + nsProtocol + `" ID="` + escapeAttr(id) + `" Version="2.0"`)
	b.WriteString(` IssueInstant="` + now.UTC().Format(time.RFC3339) + `"`)
	b.WriteString(` Destination="` + escapeAttr(p.IDPSSOURL) + `"`)
	b.WriteString(` ProtocolBinding="` + bindingPOST + `"`)
	b.WriteString(` AssertionConsumerServiceURL="` + escapeAttr(p.ACS) + `"`)
	if p.ForceAuthn {
		b.WriteString(` ForceAuthn="true"`)
	}
	b.WriteString(`><saml:Issuer xmlns:saml="` + nsAssertion + `">` + escapeText(p.EntityID) + `</saml:Issuer>`)
	if p.RequestedNameIDFormat != "" {
		b.WriteString(`<samlp:NameIDPolicy Format="` + escapeAttr(p.RequestedNameIDFormat) + `" AllowCreate="true"/>`)
	}
	b.WriteString(`</samlp:AuthnRequest>`)
	return []byte(b.String())
}

// RedirectURL encodes a request for the HTTP Redirect binding: raw
// DEFLATE, base64, in the query. relayState comes back unchanged and is
// opaque to the provider.
func (p *Policy) RedirectURL(request []byte, relayState string) (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(request); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	u, err := url.Parse(p.IDPSSOURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Metadata is this service provider's metadata document, for the
// identity provider to import: who this proxy is, where assertions go
// and that they are expected to be signed.
func (p *Policy) Metadata() []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<md:EntityDescriptor xmlns:md="` + nsMetadata + `" entityID="` + escapeAttr(p.EntityID) + `">` + "\n")
	b.WriteString(`  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="` + nsProtocol + `">` + "\n")
	formats := p.NameIDFormats
	if len(formats) == 0 && p.RequestedNameIDFormat != "" {
		formats = []string{p.RequestedNameIDFormat}
	}
	for _, f := range formats {
		b.WriteString(`    <md:NameIDFormat>` + escapeText(f) + `</md:NameIDFormat>` + "\n")
	}
	b.WriteString(`    <md:AssertionConsumerService Binding="` + bindingPOST + `" Location="` + escapeAttr(p.ACS) + `" index="0" isDefault="true"/>` + "\n")
	b.WriteString(`  </md:SPSSODescriptor>` + "\n</md:EntityDescriptor>\n")
	return []byte(b.String())
}

// IDPMetadata is what an identity provider's metadata document says, as
// far as a service provider needs it.
type IDPMetadata struct {
	EntityID string
	// SSOURL is the HTTP Redirect binding's single sign-on endpoint.
	SSOURL string
	// Certs are the signing certificates, in document order.
	Certs []*x509.Certificate
}

// ParseIDPMetadata reads an identity provider's metadata document, so an
// operator can point the configuration at the file the provider hands
// out instead of copying three fields out of it by hand. The document is
// read with the same strict parser as an assertion; its signature, if it
// carries one, is not checked, because a metadata file is a
// configuration file here -- it arrives from the operator, not from the
// network.
func ParseIDPMetadata(b []byte) (*IDPMetadata, error) {
	doc, err := parseDocument(b)
	if err != nil {
		return nil, err
	}
	desc := doc
	if doc.is(nsMetadata, "EntitiesDescriptor") {
		found := doc.children(nsMetadata, "EntityDescriptor")
		if len(found) != 1 {
			return nil, fmt.Errorf("%w: metadata describes %d entities; name one in the configuration instead", errProfile, len(found))
		}
		desc = found[0]
	}
	if !desc.is(nsMetadata, "EntityDescriptor") {
		return nil, fmt.Errorf("%w: %q is not a metadata EntityDescriptor", errProfile, desc.qname())
	}
	md := &IDPMetadata{EntityID: desc.attrValue("entityID")}
	if md.EntityID == "" {
		return nil, fmt.Errorf("%w: the metadata has no entityID", errProfile)
	}
	idp := desc.child(nsMetadata, "IDPSSODescriptor")
	if idp == nil {
		return nil, fmt.Errorf("%w: the metadata has no IDPSSODescriptor", errProfile)
	}
	for _, sso := range idp.children(nsMetadata, "SingleSignOnService") {
		if sso.attrValue("Binding") == bindingRedirect && md.SSOURL == "" {
			md.SSOURL = sso.attrValue("Location")
		}
	}
	if md.SSOURL == "" {
		return nil, fmt.Errorf("%w: the metadata has no HTTP Redirect single sign-on endpoint", errProfile)
	}
	for _, kd := range idp.children(nsMetadata, "KeyDescriptor") {
		if use := kd.attrValue("use"); use != "" && use != "signing" {
			continue
		}
		var certs []*node
		findAll(kd, nsDSig, "X509Certificate", &certs)
		for _, c := range certs {
			der, err := decodeBase64(c.chars())
			if err != nil {
				return nil, fmt.Errorf("%w: a certificate in the metadata is not base64: %w", errProfile, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("%w: a certificate in the metadata does not parse: %w", errProfile, err)
			}
			md.Certs = append(md.Certs, cert)
		}
	}
	if len(md.Certs) == 0 {
		return nil, fmt.Errorf("%w: the metadata carries no signing certificate", errProfile)
	}
	return md, nil
}

// Seen is the one-time table of assertion identifiers. An assertion is a
// bearer credential until it expires, so the same one arriving twice is
// either a replay or a browser retry, and neither is a second login.
//
// The table is bounded. When it is full it sweeps what has expired, and
// if that frees nothing it drops the entry that expires soonest to make
// room -- an assertion identifier only ever arrives here after its
// signature verified, so filling this table means holding the identity
// provider's key.
type Seen struct {
	mu  sync.Mutex
	max int
	ids map[string]time.Time
}

// NewSeen returns a table holding at most max identifiers.
func NewSeen(max int) *Seen {
	if max < 1 {
		max = 1
	}
	return &Seen{max: max, ids: make(map[string]time.Time)}
}

// Admit records an identifier until it expires and reports whether it is
// new. A false answer is a replay.
func (s *Seen) Admit(id string, until, now time.Time) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.ids[id]; ok {
		if now.Before(exp) {
			return false
		}
		delete(s.ids, id)
	}
	if len(s.ids) >= s.max {
		for k, exp := range s.ids {
			if !now.Before(exp) {
				delete(s.ids, k)
			}
		}
	}
	if len(s.ids) >= s.max {
		var soonest string
		var soonestExp time.Time
		for k, exp := range s.ids {
			if soonest == "" || exp.Before(soonestExp) {
				soonest, soonestExp = k, exp
			}
		}
		delete(s.ids, soonest)
	}
	s.ids[id] = until
	return true
}

// Len is the number of identifiers held, for the management view.
func (s *Seen) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ids)
}

// Names is the sorted attribute names of a login, for logging.
func (l *Login) Names() []string {
	out := make([]string, 0, len(l.Attributes))
	for k := range l.Attributes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// deflateLimit bounds what a compressed request may expand to; it is
// here because the redirect binding is the one place this package
// inflates anything.
const deflateLimit = MaxResponseBytes

// inflate expands a raw DEFLATE stream within bounds. It is used by the
// tests and by anything that has to read a redirect-bound request.
func inflate(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(io.LimitReader(r, deflateLimit+1))
	if err != nil {
		return nil, err
	}
	if len(out) > deflateLimit {
		return nil, errors.New("saml: compressed message expands beyond the bound")
	}
	return out, nil
}
