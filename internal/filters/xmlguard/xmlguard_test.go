package xmlguard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func build(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	if opts == nil {
		opts = filter.Options{}
	}
	f, err := filtertest.Build("xml_guard", "soap", opts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return f
}

func post(t *testing.T, f filter.Filter, contentType, body string) (filtertest.Result, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://api.test/soap", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		return res, ""
	}
	// What the application would read: the guard replays the body, and it
	// must be the bytes the client sent.
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("the replayed body: %v", err)
	}
	return res, string(got)
}

// The attacks, each refused with a detail that names what it was. This is
// the reason the filter exists.
func TestTheXMLAttacksAreRefused(t *testing.T) {
	f := build(t, nil)
	for _, tc := range []struct{ name, body, detail string }{
		{"an external entity", `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`, "xml_doctype"},
		{"a billion laughs", `<!DOCTYPE r [<!ENTITY a "aa"><!ENTITY b "&a;&a;">]><r>&b;</r>`, "xml_doctype"},
		{"an external DTD", `<!DOCTYPE r SYSTEM "http://evil.test/x.dtd"><r/>`, "xml_doctype"},
		{"an undeclared entity", `<r>&secret;</r>`, "xml_entity"},
		{"a processing instruction", `<?php system("id") ?><r/>`, "xml_processing_instruction"},
		{"a malformed document", `<r><a></r>`, "xml_malformed"},
		{"a document that is not UTF-8", "<r>\xff</r>", "xml_encoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := post(t, f, "application/xml", tc.body)
			if !res.Request.Deny {
				t.Fatalf("%s was accepted", tc.name)
			}
			if res.Request.Detail != tc.detail {
				t.Errorf("detail %q, want %q", res.Request.Detail, tc.detail)
			}
			if res.Request.Status != http.StatusBadRequest {
				t.Errorf("status %d", res.Request.Status)
			}
		})
	}
}

// And an ordinary request passes with its body untouched, which is the
// half that makes the filter usable.
func TestAnOrdinaryDocumentPassesByteForByte(t *testing.T) {
	f := build(t, nil)
	const body = `<?xml version="1.0"?><order id="1"><item sku="A">Widget &amp; bolt</item><![CDATA[<raw>]]></order>`
	res, replayed := post(t, f, "application/xml; charset=utf-8", body)
	if res.Request.Deny {
		t.Fatalf("refused: %+v", res.Request)
	}
	if replayed != body {
		t.Errorf("the application would read\n%q\nnot\n%q", replayed, body)
	}
}

// Only the media types and methods the policy names are read; everything
// else is somebody else's business and passes with its body intact.
func TestOnlyXMLBodiesAreRead(t *testing.T) {
	f := build(t, nil)
	const attack = `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`
	for _, ct := range []string{"application/json", "text/plain", "", "application/octet-stream"} {
		if res, _ := post(t, f, ct, attack); res.Request.Deny {
			t.Errorf("a %q body was inspected", ct)
		}
	}
	for _, ct := range []string{"application/xml", "text/xml", "application/soap+xml", "application/vnd.thing+xml", "APPLICATION/XML"} {
		if res, _ := post(t, f, ct, attack); !res.Request.Deny {
			t.Errorf("a %q body was not inspected", ct)
		}
	}
	// A GET has no body worth reading, whatever it says it carries.
	r := httptest.NewRequest(http.MethodGet, "https://api.test/soap", strings.NewReader(attack))
	r.Header.Set("Content-Type", "application/xml")
	if res := filtertest.Run(f, r, nil); res.Request.Deny {
		t.Errorf("a GET was inspected: %+v", res.Request)
	}
}

// The SOAP shape: the envelope it must be, in the namespace it must be in.
func TestTheDocumentShapeCanBeRequired(t *testing.T) {
	const soapNS = "http://schemas.xmlsoap.org/soap/envelope/"
	f := build(t, filter.Options{"require_root": "Envelope", "require_root_namespace": soapNS})
	good := `<soap:Envelope xmlns:soap="` + soapNS + `"><soap:Body><Get/></soap:Body></soap:Envelope>`
	if res, _ := post(t, f, "application/soap+xml", good); res.Request.Deny {
		t.Fatalf("a SOAP envelope was refused: %+v", res.Request)
	}
	for _, tc := range []struct{ name, body string }{
		{"another root", `<order/>`},
		{"the right name in another namespace", `<soap:Envelope xmlns:soap="urn:not-soap"><soap:Body/></soap:Envelope>`},
	} {
		res, _ := post(t, f, "application/soap+xml", tc.body)
		if !res.Request.Deny || res.Request.Detail != "xml_root" {
			t.Errorf("%s: %+v, want xml_root", tc.name, res.Request)
		}
	}
	// An element set, which is a positive model without a schema language.
	g := build(t, filter.Options{"allow_elements": []string{"order", "item"}})
	if res, _ := post(t, g, "application/xml", `<order><item/></order>`); res.Request.Deny {
		t.Fatalf("an allowed shape: %+v", res.Request)
	}
	res, _ := post(t, g, "application/xml", `<order><item/><exec/></order>`)
	if !res.Request.Deny || res.Request.Detail != "xml_element" {
		t.Errorf("an element outside the set: %+v", res.Request)
	}
}

func TestTheBoundsRefuseAnExpensiveDocument(t *testing.T) {
	f := build(t, filter.Options{"max_bytes": 256, "max_depth": 8, "max_elements": 16, "max_attributes": 4, "max_text_bytes": 64})
	for _, tc := range []struct{ name, body, detail string }{
		{"over the size bound", `<r>` + strings.Repeat("x", 300) + `</r>`, "xml_size"},
		{"too deep", strings.Repeat("<a>", 9) + strings.Repeat("</a>", 9), "xml_depth"},
		{"too many elements", `<r>` + strings.Repeat("<a/>", 20) + `</r>`, "xml_elements"},
		{"too many attributes", `<r a="1" b="2" c="3" d="4" e="5"/>`, "xml_attributes"},
		{"too much text", `<r>` + strings.Repeat("y", 100) + `</r>`, "xml_text_length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := post(t, f, "application/xml", tc.body)
			if !res.Request.Deny || res.Request.Detail != tc.detail {
				t.Errorf("%s: %+v, want %s", tc.name, res.Request, tc.detail)
			}
		})
	}
}

// A body over the bound is refused rather than passed uninspected: an
// oversize document must not be the way past the filter.
func TestAnOversizeBodyIsNotAWayPast(t *testing.T) {
	f := build(t, filter.Options{"max_bytes": 128})
	attack := `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;` + strings.Repeat("<pad/>", 100) + `</r>`
	res, _ := post(t, f, "application/xml", attack)
	if !res.Request.Deny {
		t.Fatalf("an oversize document went through uninspected: %+v", res.Request)
	}
	if res.Request.Detail != "xml_size" {
		t.Errorf("detail %q, want xml_size", res.Request.Detail)
	}
}

// Report mode is for turning the filter on in front of traffic nobody has
// read yet: it says what it would have refused and refuses nothing.
func TestReportModeOnlySays(t *testing.T) {
	f := build(t, filter.Options{"report": true})
	res, body := post(t, f, "application/xml", `<!DOCTYPE r><r/>`)
	if res.Request.Deny {
		t.Fatalf("report mode refused: %+v", res.Request)
	}
	if body != `<!DOCTYPE r><r/>` {
		t.Errorf("the body was changed: %q", body)
	}
	found := false
	for i := 0; i+1 < len(res.Attrs); i += 2 {
		if res.Attrs[i] == "xml_would_refuse" && res.Attrs[i+1] == "doctype" {
			found = true
		}
	}
	if !found {
		t.Errorf("the access log does not say what it would have refused: %v", res.Attrs)
	}
}

func TestTheOptionsAreChecked(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts filter.Options
		want string
	}{
		{"a namespace with no name", filter.Options{"require_root_namespace": "urn:x"}, "needs require_root"},
		{"an element name that is not one", filter.Options{"require_root": "a b"}, "is not an element name"},
		{"an allow list without the root", filter.Options{"require_root": "Envelope", "allow_elements": []string{"Body"}}, "does not contain require_root"},
		{"a bound out of range", filter.Options{"max_depth": 0xffffff}, "max_depth"},
		{"a size bound of nothing", filter.Options{"max_bytes": 1}, "max_bytes"},
		{"a status that is not a refusal", filter.Options{"status": 503}, "status: must be a 4xx"},
		{"a method with no body", filter.Options{"methods": []string{"GET"}}, "has no body worth reading"},
		{"a media type that is not one", filter.Options{"content_types": []string{"application/ xml"}}, "is not a media type"},
		{"a denied element that is not a name", filter.Options{"deny_elements": []string{"<x>"}}, "deny_elements"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := filtertest.Build("xml_guard", "soap", tc.opts)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
	if _, err := filtertest.Build("xml_guard", "soap", filter.Options{}); err != nil {
		t.Fatalf("the defaults were refused: %v", err)
	}
}

func TestTheStatusViewCounts(t *testing.T) {
	f := build(t, nil)
	post(t, f, "application/xml", `<r/>`)
	post(t, f, "application/xml", `<!DOCTYPE r><r/>`)
	post(t, f, "application/json", `{}`)
	st := f.(*guard).Status()
	if st.Inspected != 2 || st.Refused != 1 || st.Reported != 0 {
		t.Errorf("status %+v", st)
	}
}
