package saml

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"
	"testing"
)

// The algorithm tables of XML Signature, and the digest they select.
//
// These two maps are where a verifier decides what it is about to verify, and
// the failure they stand against is not a wrong answer but a confused one: a
// SignatureMethod naming SHA-512 while the digest is computed with SHA-256
// would verify a hash the signer never signed. So every URI the profile
// accepts is checked to select the hash its name claims, and -- the part that
// matters more -- everything else is checked to be refused rather than
// defaulted.
//
// SHA-1 is the case worth being explicit about. Both tables leave it out, so a
// document signed with rsa-sha1 is refused at the method rather than verified
// against a hash nobody should still accept.
func TestEverySignatureMethodSelectsTheHashItsNameClaims(t *testing.T) {
	for _, c := range []struct {
		uri  string
		hash crypto.Hash
		kind keyKind
	}{
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", crypto.SHA256, keyRSA},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", crypto.SHA384, keyRSA},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", crypto.SHA512, keyRSA},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", crypto.SHA256, keyECDSA},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", crypto.SHA384, keyECDSA},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", crypto.SHA512, keyECDSA},
	} {
		hash, kind, ok := signatureAlg(c.uri)
		if !ok {
			t.Errorf("%s is not accepted", c.uri)
			continue
		}
		if hash != c.hash {
			t.Errorf("%s selects %v, want %v", c.uri, hash, c.hash)
		}
		if kind != c.kind {
			t.Errorf("%s selects key family %v, want %v", c.uri, kind, c.kind)
		}
	}

	for _, uri := range []string{
		// SHA-1, in both families: left out of the table on purpose.
		"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
		// HMAC, which would verify against a shared secret rather than
		// the identity provider's key.
		"http://www.w3.org/2000/09/xmldsig#hmac-sha1",
		"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
		// DSA, and nonsense.
		"http://www.w3.org/2000/09/xmldsig#dsa-sha1",
		"",
		"rsa-sha256",
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ",
	} {
		if hash, kind, ok := signatureAlg(uri); ok {
			t.Errorf("%q was accepted as %v/%v", uri, hash, kind)
		}
	}
}

// The digest table, the same way round: the three the profile accepts, and
// SHA-1 refused rather than defaulted.
func TestEveryDigestMethodSelectsItsOwnHash(t *testing.T) {
	for _, c := range []struct {
		uri  string
		hash crypto.Hash
	}{
		{"http://www.w3.org/2001/04/xmlenc#sha256", crypto.SHA256},
		{"http://www.w3.org/2001/04/xmldsig-more#sha384", crypto.SHA384},
		{"http://www.w3.org/2001/04/xmlenc#sha512", crypto.SHA512},
	} {
		hash, ok := digestAlg(c.uri)
		if !ok {
			t.Errorf("%s is not accepted", c.uri)
			continue
		}
		if hash != c.hash {
			t.Errorf("%s selects %v, want %v", c.uri, hash, c.hash)
		}
	}
	for _, uri := range []string{
		"http://www.w3.org/2000/09/xmldsig#sha1",
		"http://www.w3.org/2001/04/xmlenc#ripemd160",
		"",
		"sha256",
	} {
		if hash, ok := digestAlg(uri); ok {
			t.Errorf("%q was accepted as %v", uri, hash)
		}
	}
}

// The digest itself, at each width.
//
// sum takes the hash the tables chose, so it has to compute the one it was
// handed rather than the one it prefers: a SHA-384 reference digested with
// SHA-256 would never match, and a SHA-256 reference digested with SHA-512
// would never match either -- but a default that silently handled an unknown
// hash as SHA-256 could make a mismatch look like a match if the reference
// agreed.
func TestTheDigestIsTheHashItWasHandedNotTheDefault(t *testing.T) {
	body := []byte("<Assertion>the signed bytes</Assertion>")
	s256 := sha256.Sum256(body)
	s384 := sha512.Sum384(body)
	s512 := sha512.Sum512(body)

	for _, c := range []struct {
		hash crypto.Hash
		want []byte
	}{
		{crypto.SHA256, s256[:]},
		{crypto.SHA384, s384[:]},
		{crypto.SHA512, s512[:]},
	} {
		got := sum(c.hash, body)
		if fmt.Sprintf("%x", got) != fmt.Sprintf("%x", c.want) {
			t.Errorf("sum(%v) = %x, want %x", c.hash, got, c.want)
		}
		if len(got) != c.hash.Size() {
			t.Errorf("sum(%v) is %d bytes, want %d", c.hash, len(got), c.hash.Size())
		}
	}
	// The three are different, which is what makes picking the wrong one a
	// verification failure rather than a coincidence.
	if fmt.Sprintf("%x", s256[:]) == fmt.Sprintf("%x", s384[:]) {
		t.Fatal("the fixtures collide")
	}
}

// The InclusiveNamespaces PrefixList, which decides what the canonicalizer
// treats as declared.
//
// A signer uses it to keep a prefix declared outside the signed element inside
// the signature. The bound matters because the list comes out of the document:
// a PrefixList naming ten thousand prefixes would be the identity provider's
// assertion asking this verifier for work, and the canonicalizer walks the
// list per element.
func TestThePrefixListIsReadAndBounded(t *testing.T) {
	read := func(t *testing.T, inner string) []string {
		t.Helper()
		doc := `<Transform xmlns="` + algExcC14N + `">` + inner + `</Transform>`
		root, err := parseDocument([]byte(doc))
		if err != nil {
			t.Fatalf("the fixture does not parse: %v", err)
		}
		return prefixList(root)
	}

	// No InclusiveNamespaces at all: nothing is named, which is the common
	// case and must not be an error.
	if got := read(t, ""); got != nil {
		t.Errorf("a transform with no InclusiveNamespaces named %v", got)
	}
	// An empty PrefixList is also nothing named.
	if got := read(t, `<InclusiveNamespaces PrefixList=""/>`); len(got) != 0 {
		t.Errorf("an empty PrefixList named %v", got)
	}
	// The prefixes are whitespace separated, and the separators are the
	// XML ones rather than only the space.
	got := read(t, `<InclusiveNamespaces PrefixList="ds saml&#9;xs&#10;md"/>`)
	if strings.Join(got, ",") != "ds,saml,xs,md" {
		t.Errorf("PrefixList = %v, want ds saml xs md", got)
	}
	// Past the bound the list is cut rather than carried.
	many := make([]string, maxAttrs+50)
	for i := range many {
		many[i] = fmt.Sprintf("p%d", i)
	}
	got = read(t, `<InclusiveNamespaces PrefixList="`+strings.Join(many, " ")+`"/>`)
	if len(got) != maxAttrs {
		t.Errorf("a list of %d prefixes came back as %d, want the bound of %d",
			len(many), len(got), maxAttrs)
	}
}

// Canonical is the primitive a signer needs, and it was at 0 %.
//
// Verification does not go through it -- that path canonicalizes internally --
// but the tools and test providers that produce a signature this package will
// verify do, so the two have to agree about what the signed bytes are. A
// signer that canonicalized a different subtree, or kept the Signature element
// inside the digest, would produce signatures this package rejects for reasons
// nobody can see from either side.
func TestCanonicalIsTheBytesASignerSigns(t *testing.T) {
	const doc = `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1">` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">` +
		`<Issuer>idp.test</Issuer>` +
		`<Signature xmlns="` + nsDSig + `"><SignatureValue>AAAA</SignatureValue></Signature>` +
		`</Assertion>` +
		`</Response>`

	// The whole document, when no ID is named.
	all, err := Canonical([]byte(doc), "", false)
	if err != nil {
		t.Fatalf("the whole document: %v", err)
	}
	if !strings.Contains(string(all), "<Response") {
		t.Errorf("the whole document did not start at Response:\n%s", all)
	}

	// One element, by ID: the subtree and nothing above it.
	one, err := Canonical([]byte(doc), "a1", false)
	if err != nil {
		t.Fatalf("by ID: %v", err)
	}
	if strings.Contains(string(one), "<Response") {
		t.Errorf("canonicalizing a1 included its parent:\n%s", one)
	}
	if !strings.Contains(string(one), "idp.test") {
		t.Errorf("canonicalizing a1 lost its contents:\n%s", one)
	}

	// With the signature dropped, which is what a signer digests: the
	// enveloped-signature transform removes the element the signature is
	// going into, because it cannot contain its own digest.
	without, err := Canonical([]byte(doc), "a1", true)
	if err != nil {
		t.Fatalf("dropping the signature: %v", err)
	}
	if strings.Contains(string(without), "SignatureValue") {
		t.Errorf("the signature survived the drop:\n%s", without)
	}
	if !strings.Contains(string(without), "idp.test") {
		t.Errorf("dropping the signature took the contents with it:\n%s", without)
	}
	if string(without) == string(one) {
		t.Error("dropping the signature changed nothing, so the transform is not happening")
	}

	// An ID nobody carries is an error naming the ID rather than the whole
	// document canonicalized by accident -- which would be a signature over
	// more than the signer meant.
	if out, err := Canonical([]byte(doc), "nope", false); err == nil {
		t.Errorf("an unknown ID produced %d bytes", len(out))
	} else if !strings.Contains(err.Error(), "nope") {
		t.Errorf("the error does not name the ID: %v", err)
	}

	// A document that does not parse is refused here rather than producing
	// bytes a signer would sign.
	if _, err := Canonical([]byte("<unclosed>"), "", false); err == nil {
		t.Error("a document that does not parse was canonicalized")
	}

	// Two elements with one ID is the oldest wrapping trick there is: the
	// verifier resolves the reference to one and the consumer walks to the
	// other. The signer's own primitive has to refuse it too, or it would
	// be the thing producing such a document.
	twice := strings.Replace(doc, `ID="r1"`, `ID="a1"`, 1)
	if _, err := Canonical([]byte(twice), "a1", false); err == nil {
		t.Error("a document using one ID twice was canonicalized")
	}
}

// The text escape, which decides what the canonical form of a character is.
//
// A character escaped differently by the signer and the verifier is a digest
// that does not match, so this is one of the places where exactness is the
// whole requirement rather than a nicety. The carriage return is the one worth
// naming: it has to become &#xD; because an unescaped one is normalised away
// by any XML reader, and a signer that left it raw would sign bytes the
// verifier never sees.
func TestTheTextEscapeIsExact(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain", "plain"},
		{"a & b", "a &amp; b"},
		{"a < b", "a &lt; b"},
		{"a > b", "a &gt; b"},
		{"a\rb", "a&#xD;b"},
		// A tab and a newline stay as they are: those survive
		// normalisation, so escaping them would be the difference instead.
		{"a\tb\nc", "a\tb\nc"},
		{"", ""},
		{`"quoted"`, `"quoted"`}, // a quote is an attribute's problem, not text's
		{"&<>\r", "&amp;&lt;&gt;&#xD;"},
	} {
		if got := escapeText(c.in); got != c.want {
			t.Errorf("escapeText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The character range XML 1.0 allows, which is what makes a reference like
// &#0; a refusal rather than a NUL in a canonicalized document.
func TestOnlyTheCharactersXMLAllowsAreCharacters(t *testing.T) {
	for _, r := range []rune{0x9, 0xA, 0xD, 0x20, 'a', 0xD7FF, 0xE000, 0xFFFD, 0x10000, 0x10FFFF} {
		if !validChar(r) {
			t.Errorf("validChar(%#x) = false, want true", r)
		}
	}
	for _, r := range []rune{
		0x0, // NUL
		0x1, // the C0 controls other than tab, newline and return
		0x8,
		0xB, 0xC,
		0x1F,
		0xD800, 0xDFFF, // the surrogate range, which is not a character
		0xFFFE, 0xFFFF, // the non-characters at the end of the BMP
		0x110000, // past the last code point
	} {
		if validChar(r) {
			t.Errorf("validChar(%#x) = true, want false", r)
		}
	}
}
