package syslog

import (
	"strings"
	"testing"
)

// FuzzParseFormatRoundTrip is the property the whole relay rests on:
// whatever arrives, what leaves is one record. A message that could
// carry a frame delimiter through the formatter would let any sender
// write a second record of its own — with a priority, a hostname and a
// timestamp it chose — into the collector everybody trusts.
func FuzzParseFormatRoundTrip(f *testing.F) {
	f.Add([]byte("<34>1 2003-10-11T22:14:15.003Z host app 1 ID47 - message"))
	f.Add([]byte(`<34>1 2003-10-11T22:14:15Z h a 1 i [ex@1 k="v\"q\]b\\"] text`))
	f.Add([]byte("<13>Oct 11 22:14:15 host tag: text"))
	f.Add([]byte("<0>1 - - - - - -"))
	f.Add([]byte("<191>1 - - - - [a][b][c] x"))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		out := m.Format()
		// Nothing that leaves may end a record early.
		if i := strings.IndexAny(string(out), "\n\r\x00"); i >= 0 {
			t.Fatalf("formatted record carries a delimiter at %d: %q", i, out)
		}
		// And what leaves must parse back to the same thing, or the
		// relay is not relaying what it said it read.
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("a formatted record did not parse back: %v (%q)", err, out)
		}
		if again.Priority() != m.Priority() {
			t.Fatalf("priority changed: %d then %d", m.Priority(), again.Priority())
		}
		third := again.Format()
		if string(third) != string(out) {
			t.Fatalf("formatting is not settled:\n%q\n%q", out, third)
		}
	})
}

// TestElementWithNoParametersIsReadable. RFC 5424 section 6.3 allows
// "[id]", and this relay's own formatter writes it, so a parser that
// refuses it refuses the relay's own output: two of these in a chain
// and the record is dropped at the second one. Worse, taking the id up
// to either delimiter and then looking for a "]" that has already been
// consumed sends the parser on into the NEXT element to find a
// parameter there, merging two elements into one with a name the sender
// chose -- which is how a sender suppresses the annotation this relay
// adds about where the message really came from.
func TestElementWithNoParametersIsReadable(t *testing.T) {
	m, err := Parse([]byte(`<34>1 - - - - - [ex@1] text`))
	if err != nil {
		t.Fatalf("an element with no parameters was refused: %v", err)
	}
	if len(m.Structured) != 1 || m.Structured[0].ID != "ex@1" || len(m.Structured[0].Params) != 0 {
		t.Fatalf("got %+v", m.Structured)
	}
	if m.Message != "text" {
		t.Fatalf("message %q", m.Message)
	}
	// And it does not eat what comes after it.
	m, err = Parse([]byte(`<34>1 - - - - - [a][b@2 k="v"] text`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Structured) != 2 {
		t.Fatalf("two elements became %d: %+v", len(m.Structured), m.Structured)
	}
	if m.Structured[0].ID != "a" || len(m.Structured[0].Params) != 0 {
		t.Fatalf("first element: %+v", m.Structured[0])
	}
	if m.Structured[1].ID != "b@2" || len(m.Structured[1].Params) != 1 ||
		m.Structured[1].Params[0].Name != "k" || m.Structured[1].Params[0].Value != "v" {
		t.Fatalf("second element: %+v", m.Structured[1])
	}
}

// TestStructuredNamesAreNames: an id or a parameter name carrying what
// ends a name, a value or the element is a name that would be read back
// as something else, so it is refused rather than re-spelled.
func TestStructuredNamesAreNames(t *testing.T) {
	for _, in := range []string{
		`<34>1 - - - - - [a "b"="c"] x`,
		`<34>1 - - - - - [a b]c="d"] x`,
		`<34>1 - - - - - [a b[c="d"] x`,
		"<34>1 - - - - - [a b\x01c=\"d\"] x",
		`<34>1 - - - - - [a ="v"] x`,
		`<34>1 - - - - - ["quoted" k="v"] x`,
		`<34>1 - - - - - [` + strings.Repeat("n", 33) + ` k="v"] x`,
		`<34>1 - - - - - [a ` + strings.Repeat("n", 33) + `="v"] x`,
	} {
		if m, err := Parse([]byte(in)); err == nil {
			t.Errorf("%q parsed to %+v", in, m.Structured)
		}
	}
}

// TestParseIsBounded: a parser whose output can be much larger than its
// input is one a sender can use to spend the relay's memory.
func TestParseIsBounded(t *testing.T) {
	cases := []string{
		"<34>1 - - - - " + strings.Repeat("[a@1 k=\"v\"]", 200) + " x",
		"<34>1 - - - - - " + strings.Repeat("\n", 4000),
		"<34>1 - - - - [" + strings.Repeat("a", 4000) + "] x",
		"<13>" + strings.Repeat("a", 8000),
	}
	for _, in := range cases {
		m, err := Parse([]byte(in))
		if err != nil {
			continue
		}
		out := m.Format()
		// The newline symbol is three bytes for one, which is the
		// widest any byte gets; anything past that is a parser
		// inventing content.
		if len(out) > 4*len(in)+256 {
			t.Errorf("input of %d bytes formatted to %d", len(in), len(out))
		}
	}
}

// TestStructuredDataCannotEscapeItsElement: the escaping in section
// 6.3.3 is the only thing between a parameter value and a record of the
// sender's own design.
func TestStructuredDataCannotEscapeItsElement(t *testing.T) {
	hostile := []string{
		`v" k2="injected`,
		`v] [evil@1 k="x`,
		`v\`,
		"v\nline",
		"v\x00nul",
		strings.Repeat(`\`, 50),
	}
	for _, v := range hostile {
		m := Message{Facility: 1, Severity: 5, Version: 1,
			Structured: []SDElement{{ID: "t@1", Params: []SDParam{{Name: "k", Value: v}}}}}
		out := m.Format()
		back, err := Parse(out)
		if err != nil {
			t.Fatalf("%q: own output did not parse: %v (%q)", v, err, out)
		}
		if len(back.Structured) != 1 || len(back.Structured[0].Params) != 1 {
			t.Fatalf("%q: escaped its element: %q -> %+v", v, out, back.Structured)
		}
		if back.Structured[0].ID != "t@1" {
			t.Fatalf("%q: element id changed to %q", v, back.Structured[0].ID)
		}
	}
}
