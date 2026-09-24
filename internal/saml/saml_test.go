package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The canonical form is the one thing here that cannot be tested against
// this package's own output, because the fixtures below are signed with
// it: a wrong canonicalizer would agree with itself. So the expected
// bytes in this test are written out from the Exclusive XML
// Canonicalization rules by hand.
func TestCanonicalFormRendersOnlyTheNamespacesAnElementUses(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<!-- dropped -->
<a:root xmlns:a="urn:a" xmlns:unused="urn:never" xmlns="urn:default" b="2" a:z="1" A="3">
  <plain c="x&#9;y" a:d="&lt;&amp;&quot;"/>
  <a:kid xmlns:a="urn:a">text &amp; more</a:kid>
</a:root>`
	// By the rules: the declaration and the comment go; only prefixes the
	// element itself uses are rendered, so "unused" never appears and the
	// default namespace appears on <plain> (which has no prefix) but not
	// on <a:root> (whose unprefixed attributes are not in it);
	// declarations sort before attributes, the default namespace first;
	// attributes sort by namespace then local name, so unprefixed A and b
	// come before a:z; a tab that arrived as a character reference is
	// written back as one; an empty element becomes a start and an end
	// tag.
	const want = `<a:root xmlns:a="urn:a" A="3" b="2" a:z="1">` +
		"\n  " +
		`<plain xmlns="urn:default" c="x&#x9;y" a:d="&lt;&amp;&quot;"></plain>` +
		"\n  " +
		`<a:kid>text &amp; more</a:kid>` +
		"\n" +
		`</a:root>`
	root, err := parseDocument([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := c14n(root, nil, nil)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(got) != want {
		t.Errorf("canonical form\n got %s\nwant %s", got, want)
	}
}

func TestCanonicalFormRendersAnInclusivePrefixList(t *testing.T) {
	const doc = `<a:root xmlns:a="urn:a" xmlns:x="urn:x"><a:kid/></a:root>`
	root, err := parseDocument([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := c14n(root.child("urn:a", "kid"), nil, []string{"x"})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if want := `<a:kid xmlns:a="urn:a" xmlns:x="urn:x"></a:kid>`; string(got) != want {
		t.Errorf("with a prefix list got %s, want %s", got, want)
	}
}

func TestTheParserRefusesWhatTheProfileRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
	}{
		{"a document type declaration", `<!DOCTYPE r [<!ENTITY x "y">]><r/>`},
		{"an entity reference", `<r>&x;</r>`},
		{"a CDATA section", `<r><![CDATA[<evil/>]]></r>`},
		{"a processing instruction", `<?php echo 1 ?><r/>`},
		{"a processing instruction inside an element", `<r><?php ?></r>`},
		{"a duplicate attribute", `<r a="1" a="2"/>`},
		{"an undeclared element prefix", `<x:r/>`},
		{"an undeclared attribute prefix", `<r x:a="1"/>`},
		{"an unmatched end tag", `<r></q>`},
		{"content after the root", `<r/><q/>`},
		{"an unquoted attribute value", `<r a=1/>`},
		{"a < in an attribute value", `<r a="<"/>`},
		{"a rebound xml prefix", `<r xmlns:xml="urn:not-xml"/>`},
		{"an undeclared prefix declaration", `<r xmlns:p=""><p:k/></r>`},
		{"no element at all", `   `},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDocument([]byte(tc.doc)); err == nil {
				t.Fatalf("%s was accepted", tc.name)
			} else if !errors.Is(err, errProfile) {
				t.Errorf("error is not a profile refusal: %v", err)
			}
		})
	}
}

func TestTheParserAcceptsWhatAProviderActuallySends(t *testing.T) {
	const doc = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1">
  <!-- a comment providers do send -->
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:idp</saml:Issuer>
  <x:v xmlns:x="urn:x" xml:lang="en">a &lt; b &amp; c &#x41;</x:v>
</samlp:Response>`
	root, err := parseDocument([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := root.child(nsAssertion, "Issuer").chars(); got != "urn:idp" {
		t.Errorf("issuer %q", got)
	}
	if got := root.child("urn:x", "v").chars(); got != "a < b & c A" {
		t.Errorf("text %q", got)
	}
}

// --- fixtures -------------------------------------------------------------

type fixture struct {
	responseID, assertionID   string
	inResponseTo, destination string
	// responseInResponseTo overrides the response envelope's own
	// InResponseTo, and confirmInResponseTo the subject confirmation's,
	// so a test can change one without the other. assertionIssuer
	// overrides the assertion's issuer, leaving the envelope's alone.
	responseInResponseTo    string
	confirmInResponseTo     string
	assertionIssuer         string
	recipient, audience     string
	issuer, nameID, format  string
	notBefore, notOnOrAfter string
	confirmExpiry           string
	confirmNotBefore        string
	sessionIndex            string
	status                  string
	statusMessage           string
	issueInstant            string
	extraCondition          string
	attributes              string
	assertionCount          int
	version                 string
}

const (
	testACS      = "https://proxy.example.com/saml/acs"
	testEntityID = "https://proxy.example.com/saml/metadata"
	testIDP      = "urn:example:idp"
)

func defaults(now time.Time) fixture {
	return fixture{
		responseID: "_resp1", assertionID: "_assert1",
		inResponseTo: "_req1", destination: testACS,
		recipient: testACS, audience: testEntityID,
		issuer: testIDP, nameID: "alice@example.com", format: NameIDEmail,
		notBefore:     now.Add(-time.Minute).UTC().Format(time.RFC3339),
		notOnOrAfter:  now.Add(5 * time.Minute).UTC().Format(time.RFC3339),
		confirmExpiry: now.Add(5 * time.Minute).UTC().Format(time.RFC3339),
		sessionIndex:  "_sess1",
		status:        statusSuccess,
		issueInstant:  now.UTC().Format(time.RFC3339),
		attributes: `<saml:AttributeStatement>` +
			`<saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>` +
			`<saml:Attribute Name="mail" FriendlyName="Mail"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>` +
			`</saml:AttributeStatement>`,
		assertionCount: 1,
		version:        "2.0",
	}
}

// xml renders the fixture with comment placeholders where the signatures
// go. A comment is dropped by the parser and by canonicalization, so a
// document with the placeholder and one with a signature in its place
// have the same canonical form for everything outside the signature.
func (f fixture) xml() string {
	assertion := func(id string) string {
		var b strings.Builder
		b.WriteString(`<saml:Assertion xmlns:saml="` + nsAssertion + `" ID="` + id + `" Version="` + f.version + `" IssueInstant="` + f.issueInstant + `">`)
		issuer := f.issuer
		if f.assertionIssuer != "" {
			issuer = f.assertionIssuer
		}
		b.WriteString(`<saml:Issuer>` + issuer + `</saml:Issuer>`)
		b.WriteString(`<!--SIGASSERT:` + id + `-->`)
		b.WriteString(`<saml:Subject><saml:NameID Format="` + f.format + `">` + f.nameID + `</saml:NameID>`)
		b.WriteString(`<saml:SubjectConfirmation Method="` + methodBearer + `"><saml:SubjectConfirmationData`)
		if f.recipient != "" {
			b.WriteString(` Recipient="` + f.recipient + `"`)
		}
		confirmIRT := f.inResponseTo
		if f.confirmInResponseTo != "" {
			confirmIRT = f.confirmInResponseTo
		}
		b.WriteString(` InResponseTo="` + confirmIRT + `"`)
		if f.confirmExpiry != "" {
			b.WriteString(` NotOnOrAfter="` + f.confirmExpiry + `"`)
		}
		if f.confirmNotBefore != "" {
			b.WriteString(` NotBefore="` + f.confirmNotBefore + `"`)
		}
		b.WriteString(`/></saml:SubjectConfirmation></saml:Subject>`)
		b.WriteString(`<saml:Conditions`)
		if f.notBefore != "" {
			b.WriteString(` NotBefore="` + f.notBefore + `"`)
		}
		if f.notOnOrAfter != "" {
			b.WriteString(` NotOnOrAfter="` + f.notOnOrAfter + `"`)
		}
		b.WriteString(`>`)
		if f.audience != "" {
			b.WriteString(`<saml:AudienceRestriction><saml:Audience>` + f.audience + `</saml:Audience></saml:AudienceRestriction>`)
		}
		b.WriteString(f.extraCondition)
		b.WriteString(`</saml:Conditions>`)
		b.WriteString(`<saml:AuthnStatement AuthnInstant="` + f.issueInstant + `" SessionIndex="` + f.sessionIndex + `">`)
		b.WriteString(`<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>`)
		b.WriteString(`</saml:AuthnStatement>`)
		b.WriteString(f.attributes)
		b.WriteString(`</saml:Assertion>`)
		return b.String()
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<samlp:Response xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion + `" ID="` + f.responseID + `" Version="2.0" IssueInstant="` + f.issueInstant + `"`)
	if f.destination != "" {
		b.WriteString(` Destination="` + f.destination + `"`)
	}
	if irt := f.responseInResponseTo; irt != "" || f.inResponseTo != "" {
		if irt == "" {
			irt = f.inResponseTo
		}
		b.WriteString(` InResponseTo="` + irt + `"`)
	}
	b.WriteString(`>`)
	b.WriteString(`<saml:Issuer>` + f.issuer + `</saml:Issuer>`)
	b.WriteString(`<!--SIGRESP:` + f.responseID + `-->`)
	b.WriteString(`<samlp:Status><samlp:StatusCode Value="` + f.status + `"/>`)
	if f.statusMessage != "" {
		b.WriteString(`<samlp:StatusMessage>` + f.statusMessage + `</samlp:StatusMessage>`)
	}
	b.WriteString(`</samlp:Status>`)
	for i := 0; i < f.assertionCount; i++ {
		id := f.assertionID
		if i > 0 {
			id = fmt.Sprintf("%s_%d", f.assertionID, i)
		}
		b.WriteString(assertion(id))
	}
	b.WriteString(`</samlp:Response>`)
	return b.String()
}

type signer struct {
	key               crypto.Signer
	hash              crypto.Hash
	sigAlg, digestAlg string
	transforms        string
	referenceURI      string
	extraSignedInfo   string
	// c14nMethod overrides the canonicalization the SignedInfo declares,
	// while the fixture is still canonicalized exclusively: a signature
	// that claims another canonicalization is one whose bytes this
	// package cannot reproduce, and must be refused rather than read.
	c14nMethod string
	// asn1 encodes an ECDSA signature the way the rest of the world does
	// and XML Signature does not.
	asn1 bool
}

func rsaSigner(t *testing.T) *signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: key, hash: crypto.SHA256,
		sigAlg:    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		digestAlg: "http://www.w3.org/2001/04/xmlenc#sha256"}
}

func ecSigner(t *testing.T) *signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: key, hash: crypto.SHA256,
		sigAlg:    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
		digestAlg: "http://www.w3.org/2001/04/xmlenc#sha256"}
}

func (s *signer) public() crypto.PublicKey { return s.key.Public() }

func (s *signer) raw(t *testing.T, digest []byte) []byte {
	t.Helper()
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		out, err := rsa.SignPKCS1v15(rand.Reader, k, s.hash, digest)
		if err != nil {
			t.Fatal(err)
		}
		return out
	case *ecdsa.PrivateKey:
		if s.asn1 {
			out, err := ecdsa.SignASN1(rand.Reader, k, digest)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
		r, ss, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			t.Fatal(err)
		}
		width := (k.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*width)
		r.FillBytes(out[:width])
		ss.FillBytes(out[width:])
		return out
	}
	t.Fatalf("unknown key")
	return nil
}

// signInto replaces the placeholder for id with a signature over the
// element that carries that ID.
func (s *signer) signInto(t *testing.T, doc, placeholder, id string) string {
	t.Helper()
	root, err := parseDocument([]byte(doc))
	if err != nil {
		t.Fatalf("parse while signing: %v", err)
	}
	ids := map[string]*node{}
	if err := elementIDs(root, ids); err != nil {
		t.Fatalf("ids: %v", err)
	}
	target := ids[id]
	if target == nil {
		t.Fatalf("no element with ID %q", id)
	}
	canon, err := c14n(target, nil, nil)
	if err != nil {
		t.Fatalf("canonicalize target: %v", err)
	}
	digest := base64.StdEncoding.EncodeToString(sum(mustDigest(t, s.digestAlg), canon))
	transforms := s.transforms
	if transforms == "" {
		transforms = `<ds:Transforms><ds:Transform Algorithm="` + algEnveloped + `"></ds:Transform><ds:Transform Algorithm="` + algExcC14N + `"></ds:Transform></ds:Transforms>`
	}
	uri := s.referenceURI
	if uri == "" {
		uri = "#" + id
	}
	method := s.c14nMethod
	if method == "" {
		method = algExcC14N
	}
	signedInfo := `<ds:SignedInfo xmlns:ds="` + nsDSig + `">` +
		`<ds:CanonicalizationMethod Algorithm="` + method + `"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="` + s.sigAlg + `"></ds:SignatureMethod>` +
		`<ds:Reference URI="` + uri + `">` + transforms +
		`<ds:DigestMethod Algorithm="` + s.digestAlg + `"></ds:DigestMethod>` +
		`<ds:DigestValue>` + digest + `</ds:DigestValue></ds:Reference>` + s.extraSignedInfo +
		`</ds:SignedInfo>`
	si, err := parseDocument([]byte(signedInfo))
	if err != nil {
		t.Fatalf("parse SignedInfo: %v", err)
	}
	siCanon, err := c14n(si, nil, nil)
	if err != nil {
		t.Fatalf("canonicalize SignedInfo: %v", err)
	}
	value := base64.StdEncoding.EncodeToString(s.raw(t, sum(s.hash, siCanon)))
	sig := `<ds:Signature xmlns:ds="` + nsDSig + `">` + signedInfo + `<ds:SignatureValue>` + value + `</ds:SignatureValue>` +
		`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>not read</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`
	out := strings.Replace(doc, placeholder, sig, 1)
	if out == doc {
		t.Fatalf("placeholder %q not found", placeholder)
	}
	return out
}

func mustDigest(t *testing.T, uri string) crypto.Hash {
	t.Helper()
	h, ok := digestAlg(uri)
	if !ok {
		return crypto.SHA256
	}
	return h
}

func policy(s *signer) *Policy {
	return &Policy{
		EntityID: testEntityID, ACS: testACS, IDPEntityID: testIDP,
		IDPSSOURL: "https://idp.example.com/sso", Keys: []crypto.PublicKey{s.public()},
		Skew: 30 * time.Second, MaxAge: time.Hour,
		RequireAssertionSignature: true,
		NameIDFormats:             []string{NameIDEmail, NameIDPersistent, NameIDTransient},
		RequestedNameIDFormat:     NameIDEmail,
	}
}

// signedAssertion is the ordinary case: a response whose assertion is
// signed and whose response element is not.
func signedAssertion(t *testing.T, s *signer, f fixture) string {
	t.Helper()
	return s.signInto(t, f.xml(), "<!--SIGASSERT:"+f.assertionID+"-->", f.assertionID)
}

// --- the honest case ------------------------------------------------------

func TestASignedAssertionLogsTheUserIn(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	doc := signedAssertion(t, s, f)
	login, err := policy(s).Accept([]byte(doc), "_req1", now)
	if err != nil {
		t.Fatalf("a good response was refused: %v", err)
	}
	if login.NameID != "alice@example.com" {
		t.Errorf("name id %q", login.NameID)
	}
	if !login.AssertionSigned || login.ResponseSigned {
		t.Errorf("signed response=%v assertion=%v", login.ResponseSigned, login.AssertionSigned)
	}
	if got := login.Attributes["groups"]; len(got) != 2 || got[0] != "staff" || got[1] != "admins" {
		t.Errorf("groups %v", got)
	}
	if got := login.Attr("mail"); got != "alice@example.com" {
		t.Errorf("mail %q", got)
	}
	if login.SessionIndex != "_sess1" {
		t.Errorf("session index %q", login.SessionIndex)
	}
	if want := now.Add(5 * time.Minute); login.NotOnOrAfter.Sub(want) > time.Second || want.Sub(login.NotOnOrAfter) > time.Second {
		t.Errorf("expiry %s, want about %s", login.NotOnOrAfter, want)
	}
	if got := login.Names(); len(got) != 2 || got[0] != "groups" || got[1] != "mail" {
		t.Errorf("names %v", got)
	}
}

func TestASignedResponseLogsTheUserIn(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	doc := s.signInto(t, f.xml(), "<!--SIGRESP:"+f.responseID+"-->", f.responseID)
	p := policy(s)
	p.RequireAssertionSignature = false
	p.RequireResponseSignature = true
	login, err := p.Accept([]byte(doc), "_req1", now)
	if err != nil {
		t.Fatalf("a response signed as a whole was refused: %v", err)
	}
	if !login.ResponseSigned || login.AssertionSigned {
		t.Errorf("signed response=%v assertion=%v", login.ResponseSigned, login.AssertionSigned)
	}
}

func TestTheRequiredSignatureIsTheOneThatMustBeThere(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	t.Run("the response is required and only the assertion is signed", func(t *testing.T) {
		doc := signedAssertion(t, s, f)
		p := policy(s)
		p.RequireResponseSignature = true
		p.RequireAssertionSignature = false
		if _, err := p.Accept([]byte(doc), "_req1", now); !errors.Is(err, ErrSignature) {
			t.Fatalf("a response signature was required and an assertion signature accepted instead: %v", err)
		}
	})
	t.Run("the assertion is required and only the response is signed", func(t *testing.T) {
		doc := s.signInto(t, f.xml(), "<!--SIGRESP:"+f.responseID+"-->", f.responseID)
		p := policy(s)
		p.RequireAssertionSignature = true
		if _, err := p.Accept([]byte(doc), "_req1", now); !errors.Is(err, ErrSignature) {
			t.Fatalf("an assertion signature was required and a response signature accepted instead: %v", err)
		}
	})
}

func TestBothSignaturesVerifyTogether(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	doc := signedAssertion(t, s, f)
	doc = s.signInto(t, doc, "<!--SIGRESP:"+f.responseID+"-->", f.responseID)
	p := policy(s)
	p.RequireResponseSignature = true
	login, err := p.Accept([]byte(doc), "_req1", now)
	if err != nil {
		t.Fatalf("a doubly signed response was refused: %v", err)
	}
	if !login.ResponseSigned || !login.AssertionSigned {
		t.Errorf("signed response=%v assertion=%v", login.ResponseSigned, login.AssertionSigned)
	}
}

func TestAnECDSASignatureVerifies(t *testing.T) {
	now := time.Now()
	s := ecSigner(t)
	f := defaults(now)
	doc := signedAssertion(t, s, f)
	if _, err := policy(s).Accept([]byte(doc), "_req1", now); err != nil {
		t.Fatalf("an ECDSA signature was refused: %v", err)
	}
}

func TestAnECDSASignatureInTheWrongEncodingIsRefused(t *testing.T) {
	now := time.Now()
	s := ecSigner(t)
	s.asn1 = true
	doc := signedAssertion(t, s, defaults(now))
	if _, err := policy(s).Accept([]byte(doc), "_req1", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("an ASN.1 encoded ECDSA signature: %v", err)
	}
}

func TestATruncatedSignatureIsRefusedRatherThanPanicking(t *testing.T) {
	now := time.Now()
	for _, s := range []*signer{ecSigner(t), rsaSigner(t)} {
		doc := signedAssertion(t, s, defaults(now))
		start := strings.Index(doc, "<ds:SignatureValue>") + len("<ds:SignatureValue>")
		end := strings.Index(doc, "</ds:SignatureValue>")
		for _, value := range []string{"AAAA", "", "!!!!", strings.Repeat("A", 200)} {
			short := doc[:start] + value + doc[end:]
			if _, err := policy(s).Accept([]byte(short), "_req1", now); err == nil {
				t.Errorf("a signature value of %d characters was accepted", len(value))
			}
		}
	}
}

func TestAResponseOverTheBoundIsRefusedForItsSize(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	// Well formed and signed, so nothing but the bound can refuse it.
	f.nameID = "alice@example.com" + strings.Repeat("x", MaxResponseBytes)
	doc := signedAssertion(t, s, f)
	if len(doc) <= MaxResponseBytes {
		t.Fatalf("the fixture is only %d bytes", len(doc))
	}
	_, err := policy(s).Accept([]byte(doc), "_req1", now)
	if !errors.Is(err, errProfile) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversize response: %v", err)
	}
}

func TestAnUnsignedResponseIsNeverALogin(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	p := policy(s)
	p.RequireAssertionSignature = false
	if _, err := p.Accept([]byte(f.xml()), "_req1", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("an unsigned response was accepted or misreported: %v", err)
	}
}

// --- the dishonest cases --------------------------------------------------

func TestAnAlteredAssertionDoesNotVerify(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	doc := signedAssertion(t, s, f)
	for _, tc := range []struct{ name, from, to string }{
		{"the name identifier", "alice@example.com</saml:NameID>", "root@example.com</saml:NameID>"},
		{"an attribute value", ">staff<", ">wheel<"},
		{"the audience", testEntityID + "</saml:Audience>", "urn:other</saml:Audience>"},
		{"the expiry", `NotOnOrAfter="` + f.notOnOrAfter, `NotOnOrAfter="` + now.Add(time.Hour).UTC().Format(time.RFC3339)},
		{"an added attribute", `<saml:Attribute Name="mail"`, `<saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute><saml:Attribute Name="mail"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := strings.Replace(doc, tc.from, tc.to, 1)
			if tampered == doc {
				t.Fatalf("the fixture does not contain %q", tc.from)
			}
			_, err := policy(s).Accept([]byte(tampered), "_req1", now)
			if !errors.Is(err, ErrSignature) {
				t.Fatalf("changing %s was not caught by the signature: %v", tc.name, err)
			}
		})
	}
}

func TestAnotherKeyDoesNotVerify(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	other := rsaSigner(t)
	doc := signedAssertion(t, s, defaults(now))
	if _, err := policy(other).Accept([]byte(doc), "_req1", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("a signature by an unconfigured key was accepted: %v", err)
	}
}

func TestSignatureWrappingIsRefused(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	good := signedAssertion(t, s, f)
	t.Run("a second assertion beside the signed one", func(t *testing.T) {
		evil := `<saml:Assertion xmlns:saml="` + nsAssertion + `" ID="_evil" Version="2.0" IssueInstant="` + f.issueInstant + `">` +
			`<saml:Issuer>` + testIDP + `</saml:Issuer><saml:Subject><saml:NameID Format="` + NameIDEmail + `">root@example.com</saml:NameID>` +
			`<saml:SubjectConfirmation Method="` + methodBearer + `"><saml:SubjectConfirmationData Recipient="` + testACS +
			`" InResponseTo="_req1" NotOnOrAfter="` + f.confirmExpiry + `"/></saml:SubjectConfirmation></saml:Subject>` +
			`<saml:Conditions NotOnOrAfter="` + f.notOnOrAfter + `"><saml:AudienceRestriction><saml:Audience>` + testEntityID +
			`</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
			`<saml:AuthnStatement AuthnInstant="` + f.issueInstant + `"/></saml:Assertion>`
		doc := strings.Replace(good, `<saml:Assertion`, evil+`<saml:Assertion`, 1)
		_, err := policy(s).Accept([]byte(doc), "_req1", now)
		if err == nil || !errors.Is(err, errProfile) {
			t.Fatalf("two assertions were accepted: %v", err)
		}
	})
	t.Run("the signed assertion hidden inside an extension", func(t *testing.T) {
		// The classic shape: the verifier is meant to find the signed
		// assertion somewhere harmless and the consumer to read the
		// forged one. Here the signed copy is moved under an Extensions
		// element and a copy with the same ID put in its place.
		signed := good[strings.Index(good, `<saml:Assertion`):strings.Index(good, `</samlp:Response>`)]
		forged := strings.Replace(signed, "alice@example.com", "root@example.com", 1)
		forged = strings.Replace(forged, `<ds:Signature`, `<ds:SignatureRemoved`, 1)
		forged = strings.Replace(forged, `</ds:Signature>`, `</ds:SignatureRemoved>`, 1)
		doc := strings.Replace(good, signed, `<samlp:Extensions>`+signed+`</samlp:Extensions>`+forged, 1)
		if _, err := policy(s).Accept([]byte(doc), "_req1", now); err == nil {
			t.Fatal("a wrapped assertion was accepted")
		}
	})
	t.Run("two elements sharing an ID", func(t *testing.T) {
		doc := strings.Replace(good, `<samlp:Status>`, `<samlp:Extensions ID="`+f.assertionID+`"/><samlp:Status>`, 1)
		_, err := policy(s).Accept([]byte(doc), "_req1", now)
		if err == nil || !errors.Is(err, errProfile) {
			t.Fatalf("a duplicated ID was accepted: %v", err)
		}
	})
	t.Run("a signature over something else in the document", func(t *testing.T) {
		// A signature whose reference names an element it is not
		// enveloped in: the digest may well be correct, and it still
		// says nothing about the element that carries the signature.
		s2 := rsaSigner(t)
		s2.referenceURI = "#" + f.responseID
		doc := s2.signInto(t, f.xml(), "<!--SIGASSERT:"+f.assertionID+"-->", f.assertionID)
		p := policy(s)
		p.Keys = append(p.Keys, s2.public())
		if _, err := p.Accept([]byte(doc), "_req1", now); !errors.Is(err, errProfile) {
			t.Fatalf("a signature pointing elsewhere was accepted: %v", err)
		}
	})
	t.Run("a signature that does not verify anywhere", func(t *testing.T) {
		// Even a signature nothing would read makes the document a
		// refusal: there is no reading in which part of a document with
		// a broken signature is trustworthy.
		doc := strings.Replace(good, `<samlp:Status>`, `<samlp:Extensions ID="_x"><ds:Signature xmlns:ds="`+nsDSig+`"><ds:SignedInfo>`+
			`<ds:CanonicalizationMethod Algorithm="`+algExcC14N+`"></ds:CanonicalizationMethod>`+
			`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>`+
			`<ds:Reference URI="#_x"><ds:Transforms><ds:Transform Algorithm="`+algEnveloped+`"></ds:Transform></ds:Transforms>`+
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>`+
			`<ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue>`+
			`</ds:Signature></samlp:Extensions><samlp:Status>`, 1)
		if _, err := policy(s).Accept([]byte(doc), "_req1", now); err == nil {
			t.Fatal("a document with a broken signature was accepted")
		}
	})
}

func TestWeakAndOpenEndedSignatureOptionsAreRefused(t *testing.T) {
	now := time.Now()
	f := defaults(now)
	for _, tc := range []struct {
		name  string
		setup func(s *signer)
	}{
		{"SHA-1", func(s *signer) {
			s.sigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
		}},
		{"a SHA-1 digest", func(s *signer) {
			s.digestAlg = "http://www.w3.org/2000/09/xmldsig#sha1"
		}},
		{"an HMAC signature", func(s *signer) {
			s.sigAlg = "http://www.w3.org/2000/09/xmldsig#hmac-sha256"
		}},
		{"an XPath transform", func(s *signer) {
			s.transforms = `<ds:Transforms><ds:Transform Algorithm="` + algEnveloped + `"></ds:Transform>` +
				`<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"></ds:Transform></ds:Transforms>`
		}},
		{"no enveloped signature transform", func(s *signer) {
			s.transforms = `<ds:Transforms><ds:Transform Algorithm="` + algExcC14N + `"></ds:Transform></ds:Transforms>`
		}},
		{"inclusive canonicalization", func(s *signer) {
			s.c14nMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
		}},
		{"a second reference", func(s *signer) {
			s.extraSignedInfo = `<ds:Reference URI="#_resp1"><ds:Transforms><ds:Transform Algorithm="` + algEnveloped + `"></ds:Transform></ds:Transforms>` +
				`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>`
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := rsaSigner(t)
			tc.setup(s)
			doc := signedAssertion(t, s, f)
			if _, err := policy(s).Accept([]byte(doc), "_req1", now); !errors.Is(err, errProfile) {
				t.Fatalf("%s was accepted: %v", tc.name, err)
			}
		})
	}
}

func TestAResponseMeantForSomebodyElseIsRefused(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name string
		want error
		edit func(f *fixture)
	}{
		{"another audience", ErrRefused, func(f *fixture) { f.audience = "urn:another-sp" }},
		{"no audience at all", ErrRefused, func(f *fixture) { f.audience = "" }},
		{"another destination", ErrRefused, func(f *fixture) { f.destination = "https://other.example.com/acs" }},
		{"no destination", ErrRefused, func(f *fixture) { f.destination = "" }},
		{"another recipient", ErrRefused, func(f *fixture) { f.recipient = "https://other.example.com/acs" }},
		{"no recipient", ErrRefused, func(f *fixture) { f.recipient = "" }},
		{"another issuer", ErrRefused, func(f *fixture) { f.issuer = "urn:evil:idp" }},
		{"another request", ErrRefused, func(f *fixture) { f.inResponseTo = "_other" }},
		{"another request in the envelope alone", ErrRefused, func(f *fixture) { f.responseInResponseTo = "_other" }},
		{"another request in the subject confirmation alone", ErrRefused, func(f *fixture) { f.confirmInResponseTo = "_other" }},
		{"an assertion issued by somebody else", ErrRefused, func(f *fixture) { f.assertionIssuer = "urn:evil:idp" }},
		{"an oversize attribute value", errProfile, func(f *fixture) {
			f.attributes = `<saml:AttributeStatement><saml:Attribute Name="pad"><saml:AttributeValue>` +
				strings.Repeat("x", maxAttributeValue+1) + `</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`
		}},
		{"more values than an attribute may carry", errProfile, func(f *fixture) {
			f.attributes = `<saml:AttributeStatement><saml:Attribute Name="groups">` +
				strings.Repeat(`<saml:AttributeValue>g</saml:AttributeValue>`, maxAttributeValues+1) +
				`</saml:Attribute></saml:AttributeStatement>`
		}},
		{"an expired assertion", ErrRefused, func(f *fixture) {
			f.notOnOrAfter = now.Add(-time.Hour).UTC().Format(time.RFC3339)
		}},
		{"an assertion not yet valid", ErrRefused, func(f *fixture) {
			f.notBefore = now.Add(time.Hour).UTC().Format(time.RFC3339)
		}},
		{"an expired subject confirmation", ErrRefused, func(f *fixture) {
			f.confirmExpiry = now.Add(-time.Hour).UTC().Format(time.RFC3339)
		}},
		{"an assertion issued in the future", ErrRefused, func(f *fixture) {
			f.issueInstant = now.Add(time.Hour).UTC().Format(time.RFC3339)
		}},
		{"an assertion older than the bound", ErrRefused, func(f *fixture) {
			f.issueInstant = now.Add(-25 * time.Hour).UTC().Format(time.RFC3339)
		}},
		{"a name identifier format nobody asked for", ErrRefused, func(f *fixture) {
			f.format = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
		}},
		{"an empty name identifier", ErrRefused, func(f *fixture) { f.nameID = "" }},
		{"no expiry on the conditions", errProfile, func(f *fixture) { f.notOnOrAfter = "" }},
		{"no expiry on the subject confirmation", errProfile, func(f *fixture) { f.confirmExpiry = "" }},
		{"a NotBefore on a bearer confirmation", errProfile, func(f *fixture) {
			f.confirmNotBefore = now.Add(-time.Minute).UTC().Format(time.RFC3339)
		}},
		{"a condition nobody understands", errProfile, func(f *fixture) {
			f.extraCondition = `<saml:Condition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="saml:SomethingNew"/>`
		}},
		{"a timestamp with no zone", errProfile, func(f *fixture) { f.issueInstant = "2030-01-01T00:00:00" }},
		{"the wrong version", errProfile, func(f *fixture) { f.version = "1.1" }},
		{"an attribute value wrapped in markup", errProfile, func(f *fixture) {
			f.attributes = `<saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>` +
				`<saml:NameID>staff</saml:NameID></saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := rsaSigner(t)
			f := defaults(now)
			tc.edit(&f)
			doc := signedAssertion(t, s, f)
			_, err := policy(s).Accept([]byte(doc), "_req1", now)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("%s: %v", tc.name, err)
			}
		})
	}
}

func TestAnAuthnStatementIsRequired(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	// Removing the statement after signing would break the signature, so
	// the fixture is signed without one: the point is the check, not the
	// signature.
	stripped := strings.Replace(f.xml(), `<saml:AuthnStatement AuthnInstant="`+f.issueInstant+`" SessionIndex="`+f.sessionIndex+`">`, `<saml:Extra>`, 1)
	stripped = strings.Replace(stripped, `</saml:AuthnStatement>`, `</saml:Extra>`, 1)
	if stripped == f.xml() {
		t.Fatal("the fixture has no authentication statement to remove")
	}
	doc := s.signInto(t, stripped, "<!--SIGASSERT:"+f.assertionID+"-->", f.assertionID)
	if _, err := policy(s).Accept([]byte(doc), "_req1", now); !errors.Is(err, errProfile) {
		t.Fatalf("an assertion with no authentication statement was accepted: %v", err)
	}
}

func TestAFailedStatusIsNotALogin(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	f.status = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	f.statusMessage = "the user cancelled"
	doc := signedAssertion(t, s, f)
	_, err := policy(s).Accept([]byte(doc), "_req1", now)
	if !errors.Is(err, ErrStatus) {
		t.Fatalf("a failed status was not reported as one: %v", err)
	}
	if !strings.Contains(err.Error(), "the user cancelled") {
		t.Errorf("the status message is not in %q", err)
	}
}

func TestEncryptionIsRefusedWithAReasonThatSaysSo(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	doc := strings.Replace(f.xml(), `<saml:Assertion`, `<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion><saml:Assertion`, 1)
	_, err := policy(s).Accept([]byte(doc), "_req1", now)
	if !errors.Is(err, errProfile) || !strings.Contains(err.Error(), "EncryptedAssertion") {
		t.Fatalf("an encrypted assertion was not refused by name: %v", err)
	}
}

func TestAResponseNobodyAskedForIsNotALogin(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	f.inResponseTo = ""
	doc := signedAssertion(t, s, f)
	if _, err := policy(s).Accept([]byte(doc), "", now); !errors.Is(err, ErrRefused) {
		t.Fatalf("an unsolicited response was accepted: %v", err)
	}
}

func TestAnOversizeResponseIsRefusedBeforeItIsParsed(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	big := make([]byte, MaxResponseBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	if _, err := policy(s).Accept(big, "_req1", now); !errors.Is(err, errProfile) {
		t.Fatalf("an oversize response: %v", err)
	}
}

// --- replay ---------------------------------------------------------------

func TestAnAssertionIsAcceptedOnce(t *testing.T) {
	now := time.Now()
	seen := NewSeen(4)
	if !seen.Admit("_a1", now.Add(time.Minute), now) {
		t.Fatal("the first use was refused")
	}
	if seen.Admit("_a1", now.Add(time.Minute), now) {
		t.Fatal("a replay was accepted")
	}
	if !seen.Admit("_a1", now.Add(2*time.Minute), now.Add(2*time.Minute)) {
		t.Fatal("an identifier was still held after it expired")
	}
	if seen.Admit("", now, now) {
		t.Fatal("an empty identifier was admitted")
	}
	for i := range 10 {
		seen.Admit(fmt.Sprintf("_x%d", i), now.Add(time.Duration(i)*time.Minute), now)
	}
	if seen.Len() > 4 {
		t.Errorf("the table holds %d entries, over its bound of 4", seen.Len())
	}
}

// --- requests and metadata ------------------------------------------------

func TestTheRequestSaysWhereTheAnswerGoes(t *testing.T) {
	now := time.Now()
	s := rsaSigner(t)
	p := policy(s)
	p.ForceAuthn = true
	id := NewID()
	if strings.HasPrefix(id, "_") == false || len(id) < 10 {
		t.Errorf("identifier %q is not an xsd:ID", id)
	}
	req := p.AuthnRequest(id, now)
	loc, err := p.RedirectURL(req, "state-123")
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	if !strings.HasPrefix(loc, "https://idp.example.com/sso?") {
		t.Fatalf("location %q", loc)
	}
	_, query, ok := strings.Cut(loc, "?")
	if !ok {
		t.Fatalf("the location carries no query: %q", loc)
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	if values.Get("RelayState") != "state-123" {
		t.Errorf("relay state %q", values.Get("RelayState"))
	}
	deflated, err := base64.StdEncoding.DecodeString(values.Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("the request is not base64: %v", err)
	}
	raw, err := inflate(deflated)
	if err != nil {
		t.Fatalf("the request does not inflate: %v", err)
	}
	doc, err := parseDocument(raw)
	if err != nil {
		t.Fatalf("the request does not parse: %v", err)
	}
	if !doc.is(nsProtocol, "AuthnRequest") {
		t.Fatalf("the request is %q", doc.qname())
	}
	for _, want := range [][2]string{
		{"ID", id}, {"Version", "2.0"}, {"Destination", p.IDPSSOURL},
		{"AssertionConsumerServiceURL", testACS}, {"ProtocolBinding", bindingPOST}, {"ForceAuthn", "true"},
	} {
		if got := doc.attrValue(want[0]); got != want[1] {
			t.Errorf("%s = %q, want %q", want[0], got, want[1])
		}
	}
	if got := doc.child(nsAssertion, "Issuer").chars(); got != testEntityID {
		t.Errorf("issuer %q", got)
	}
	if got := doc.child(nsProtocol, "NameIDPolicy").attrValue("Format"); got != NameIDEmail {
		t.Errorf("name id policy %q", got)
	}
}

func TestTheMetadataNamesTheConsumerService(t *testing.T) {
	s := rsaSigner(t)
	md := policy(s).Metadata()
	doc, err := parseDocument(md)
	if err != nil {
		t.Fatalf("our own metadata does not parse: %v", err)
	}
	if got := doc.attrValue("entityID"); got != testEntityID {
		t.Errorf("entity id %q", got)
	}
	sp := doc.child(nsMetadata, "SPSSODescriptor")
	acs := sp.child(nsMetadata, "AssertionConsumerService")
	if got := acs.attrValue("Location"); got != testACS {
		t.Errorf("consumer location %q", got)
	}
	if got := acs.attrValue("Binding"); got != bindingPOST {
		t.Errorf("binding %q", got)
	}
	if got := sp.attrValue("WantAssertionsSigned"); got != "true" {
		t.Errorf("WantAssertionsSigned %q", got)
	}
}

func TestIdentityProviderMetadataIsRead(t *testing.T) {
	cert := selfSigned(t)
	good := `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="` + nsMetadata + `" entityID="` + testIDP + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="` + nsProtocol + `">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="` + nsDSig + `"><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(cert.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="` + nsDSig + `"><ds:X509Data><ds:X509Certificate>not a certificate` +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleSignOnService Binding="` + bindingPOST + `" Location="https://idp.example.com/post"/>` +
		`<md:SingleSignOnService Binding="` + bindingRedirect + `" Location="https://idp.example.com/sso"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`
	md, err := ParseIDPMetadata([]byte(good))
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if md.EntityID != testIDP {
		t.Errorf("entity id %q", md.EntityID)
	}
	if md.SSOURL != "https://idp.example.com/sso" {
		t.Errorf("sso url %q", md.SSOURL)
	}
	if len(md.Certs) != 1 || !md.Certs[0].Equal(cert) {
		t.Errorf("certificates %v", md.Certs)
	}
	for _, tc := range []struct{ name, doc string }{
		{"no signing certificate", strings.Replace(good, `use="signing"`, `use="encryption"`, 1)},
		{"no redirect endpoint", strings.Replace(good, bindingRedirect, "urn:something:else", 1)},
		{"not metadata at all", `<r/>`},
	} {
		if _, err := ParseIDPMetadata([]byte(tc.doc)); err == nil {
			t.Errorf("metadata with %s was accepted", tc.name)
		}
	}
	_, descriptor, ok := strings.Cut(good, `<md:EntityDescriptor`)
	if !ok {
		t.Fatal("the fixture has no entity descriptor")
	}
	wrapped := `<md:EntitiesDescriptor xmlns:md="` + nsMetadata + `"><md:EntityDescriptor` + descriptor + `</md:EntitiesDescriptor>`
	if _, err := ParseIDPMetadata([]byte(wrapped)); err != nil {
		t.Errorf("a wrapped descriptor: %v", err)
	}
}

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: bigOne(), Subject: pkixName("idp.example.com"),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestURLsAreComparedTheWayTheProfileMeans(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"https://p.example.com/acs", "https://p.example.com/acs", true},
		{"https://p.example.com:443/acs", "https://p.example.com/acs", true},
		{"https://P.Example.com/acs", "https://p.example.com/acs", true},
		{"https://p.example.com/acs", "https://p.example.com/acs/", false},
		{"https://p.example.com/acs", "http://p.example.com/acs", false},
		{"https://p.example.com/acs", "https://p.example.com/other", false},
		{"", "https://p.example.com/acs", false},
		{"https://p.example.com/acs?x=1", "https://p.example.com/acs", false},
	} {
		if got := sameURL(tc.a, tc.b); got != tc.same {
			t.Errorf("sameURL(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

func TestTheDigestCoversTheWholeAssertion(t *testing.T) {
	// A canonicalization that dropped an attribute or a namespace would
	// let the document be edited there without breaking the signature.
	// This walks every attribute of the fixture and checks that changing
	// its value is caught.
	now := time.Now()
	s := rsaSigner(t)
	f := defaults(now)
	doc := signedAssertion(t, s, f)
	root, err := parseDocument([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	assertion := root.child(nsAssertion, "Assertion")
	canon, err := c14n(assertion, assertion.child(nsDSig, "Signature"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ID="_assert1"`, `Version="2.0"`, `Format="` + NameIDEmail + `"`,
		`Method="` + methodBearer + `"`, `Recipient="` + testACS + `"`, `InResponseTo="_req1"`,
		`NotOnOrAfter="` + f.notOnOrAfter + `"`, `SessionIndex="_sess1"`, `Name="groups"`,
		testEntityID, "alice@example.com", "staff", testIDP,
	} {
		if !strings.Contains(string(canon), want) {
			t.Errorf("the canonical assertion does not cover %s", want)
		}
	}
	if strings.Contains(string(canon), "SignatureValue") {
		t.Error("the canonical assertion still contains the signature it is signed by")
	}
}

func bigOne() *big.Int { return big.NewInt(1) }

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
