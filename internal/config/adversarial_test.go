package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The configuration parser is the one parser an operator points at a file
// they did not necessarily write: a fragment from a configuration
// management system, a document rendered by a template, a file a
// colleague edited. These tests are the adversarial half of its
// contract — every one of them describes an input that must not cost
// more than it is worth, and must not be silently accepted as something
// other than what it says.

// base is a minimal valid document the cases below graft onto.
const base = `version: 1
server:
  listeners:
    - name: web
      address: "127.0.0.1:8080"
upstreams:
  - name: app
    endpoints:
      - address: "127.0.0.1:9000"
routes:
  - name: all
    upstream: app
`

// serverDoc is base with extra keys grafted into the server section,
// which is where the global limits live. Appending a second top level
// `server:` would be a duplicate key, and duplicate keys are refused —
// see TestDuplicateKeys.
func serverDoc(extra string) string {
	return `version: 1
server:
  listeners:
    - name: web
      address: "127.0.0.1:8080"
` + extra + `upstreams:
  - name: app
    endpoints:
      - address: "127.0.0.1:9000"
routes:
  - name: all
    upstream: app
`
}

// limitsDoc is base with one key set under server.limits.
func limitsDoc(key, val string) string {
	return serverDoc("  limits:\n    " + key + ": " + val + "\n")
}

// parseBudget is the wall clock a single hostile document may cost.
// Every case here is smaller than 8 MiB, so a parser without quadratic
// or exponential behaviour finishes in milliseconds; a second is three
// orders of magnitude of headroom on a throttled machine and still
// catches a blow-up.
const parseBudget = 5 * time.Second

// mustFailFast parses data, requires an error and requires the parse to
// stay inside parseBudget. It returns the error for further inspection.
func mustFailFast(t *testing.T, data string) error {
	t.Helper()
	start := time.Now()
	_, err := ParseWith([]byte(data), false)
	took := time.Since(start)
	if err == nil {
		t.Fatalf("accepted a document that must be refused")
	}
	if took > parseBudget {
		t.Fatalf("refused after %v, budget is %v", took, parseBudget)
	}
	return err
}

// TestEntityExpansion covers the YAML analogue of the billion laughs
// attack: an anchor referenced by the next anchor, ten deep. A parser
// that expands aliases without a budget turns a 200 byte document into
// gigabytes of nodes before any of our own limits are consulted.
func TestEntityExpansion(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 1\n")
	b.WriteString("a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n")
	prev := "a"
	for i := 0; i < 9; i++ {
		cur := fmt.Sprintf("x%d", i)
		b.WriteString(cur + ": &" + cur + " [")
		for j := 0; j < 9; j++ {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString("*" + prev)
		}
		b.WriteString("]\n")
		prev = cur
	}
	b.WriteString("boom: *" + prev + "\n")

	doc := b.String()
	if len(doc) > 4096 {
		t.Fatalf("test document grew to %d bytes; it is meant to be tiny", len(doc))
	}
	// Refused either as an alias budget overrun or as unknown fields —
	// what matters is that it is refused quickly and the process is
	// still here to report it.
	err := mustFailFast(t, doc)
	t.Logf("refused: %v", err)
}

// TestAliasFanOutIsBounded is the flatter cousin of the case above: one
// large anchor referenced many times. The product of the two is what a
// billion laughs document is made of, and a limit on only one of them
// is not a limit.
func TestAliasFanOutIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 1\n")
	b.WriteString("anchor: &big [")
	for i := 0; i < 2000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("\"x\"")
	}
	b.WriteString("]\n")
	b.WriteString("uses:\n")
	for i := 0; i < 2000; i++ {
		b.WriteString("  - *big\n")
	}
	mustFailFast(t, b.String())
}

// TestNestingDepth is the recursion case. A recursive descent parser
// without a depth limit meets the goroutine stack instead, and a stack
// overflow in Go is not recoverable: the process dies. The flag
// document is a few kilobytes.
func TestNestingDepth(t *testing.T) {
	for _, n := range []int{1000, 10000, 100000} {
		t.Run(fmt.Sprintf("depth%d", n), func(t *testing.T) {
			doc := "version: 1\ndeep: " + strings.Repeat("[", n) + strings.Repeat("]", n) + "\n"
			mustFailFast(t, doc)
		})
	}
}

// TestUnclosedNesting is the same shape truncated: the opening brackets
// with none of the closing ones, which is what a document cut off by a
// full disk or a killed template renderer looks like.
func TestUnclosedNesting(t *testing.T) {
	doc := "version: 1\ndeep: " + strings.Repeat("[", 100000) + "\n"
	mustFailFast(t, doc)
}

// TestOversizeDocument proves the byte ceiling is checked before the
// parser sees the document, not after.
func TestOversizeDocument(t *testing.T) {
	big := make([]byte, MaxConfigBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if _, err := Read(strings.NewReader(string(big))); err == nil {
		t.Fatal("accepted a document over MaxConfigBytes")
	}
}

// TestTruncation walks the valid document one byte at a time and
// requires every prefix to be either refused or a config — never a
// panic, and never a hang. Truncation is the most common malformed
// input in the field: a partial write, a full disk, a killed renderer.
func TestTruncation(t *testing.T) {
	full := base
	for i := 0; i < len(full); i++ {
		prefix := full[:i]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on prefix of %d bytes: %v", i, r)
				}
			}()
			_, _ = ParseWith([]byte(prefix), false)
		}()
	}
}

// TestTypeConfusion covers a value whose YAML type is not the type the
// field wants. Each of these is a real mistake — a quoted port, a
// scalar where a list belongs — and each must be an error naming the
// field rather than a zero value that quietly disables something.
func TestTypeConfusion(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"scalar for list", "version: 1\nserver:\n  listeners: web\n"},
		{"map for list", "version: 1\nserver:\n  listeners: {name: web}\n"},
		{"list for map", "version: 1\nserver:\n  - 1\n"},
		{"string for int", limitsDoc("max_header_bytes", "\"lots\"")},
		{"list for string", base + "logging:\n  directory: [\"/var/log\"]\n"},
		{"bool for string", base + "logging:\n  directory: true\n"},
		{"float for int", limitsDoc("max_header_bytes", "1.5")},
		{"map for duration", limitsDoc("read_timeout", "{}")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { mustFailFast(t, tc.doc) })
	}
}

// TestYAMLBooleanLookalikes pins YAML 1.1's famous trap. `no` is a
// boolean in YAML 1.1 and a string in 1.2, and a country code that
// turns into false is the kind of bug nobody finds by reading. yaml.v3
// is a 1.2 parser, so these stay strings — the test exists so that a
// library swap cannot change it silently.
func TestYAMLBooleanLookalikes(t *testing.T) {
	for _, word := range []string{"no", "yes", "on", "off", "y", "n"} {
		doc := base + "security_txt:\n  - contact: [\"mailto:a@b.c\"]\n    preferred_languages: [\"" + word + "\"]\n"
		c, err := ParseWith([]byte(doc), false)
		if err != nil {
			t.Fatalf("%q: %v", word, err)
		}
		if got := c.SecurityTxt[0].PreferredLanguages[0]; got != word {
			t.Fatalf("%q became %q", word, got)
		}
	}
}

// TestNumericSemantics covers the numbers that look like other numbers:
// a leading zero (octal in YAML 1.1), an underscore separator (a Go
// literal, not a YAML one), a value past int64 and the non-finite
// floats. Every one of them must be an error or the value as written,
// never a different number.
func TestNumericSemantics(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want int64 // -1 means "must be refused"
	}{
		{"plain", "4096", 4096},
		{"leading zero", "0755", -1},
		{"explicit octal", "0o10000", 4096},
		{"hex", "0x1000", 4096},
		// yaml.v3 keeps YAML 1.1's underscore separators in integers. It
		// reads as the number it looks like, which is the only thing that
		// matters here.
		{"underscores", "4_096", 4096},
		{"overflow", "99999999999999999999", -1},
		{"negative", "-1", -1},
		{"nan", ".nan", -1},
		{"inf", ".inf", -1},
		{"decimal comma", "4,096", -1},
		// A float scalar with no fractional part lands on an int field
		// without loss; 1.5 above is the case that must be refused.
		{"trailing dot", "4096.", 4096},
		{"exponent", "4e3", 4000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := limitsDoc("max_header_bytes", tc.val)
			c, err := ParseWith([]byte(doc), false)
			if tc.want < 0 {
				if err == nil {
					t.Fatalf("accepted %s as %d", tc.val, c.Server.Limits.MaxHeaderBytes)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", tc.val, err)
			}
			if got := int64(c.Server.Limits.MaxHeaderBytes); got != tc.want {
				t.Fatalf("%s decoded as %d, want %d", tc.val, got, tc.want)
			}
		})
	}
}

// TestDurationSemantics is the same exercise for durations, which are
// parsed by our own type rather than by the YAML library.
func TestDurationSemantics(t *testing.T) {
	cases := []struct {
		val  string
		want time.Duration
		ok   bool
	}{
		{"30s", 30 * time.Second, true},
		{"1m30s", 90 * time.Second, true},
		{"1h", time.Hour, true},
		{"500ms", 500 * time.Millisecond, true},
		{"\"30\"", 0, false},
		{"30", 0, false},
		{"-30s", 0, false},
		{"\"30 s\"", 0, false},
		{"\"30S\"", 0, false},
		{"\"1d\"", 0, false},
		{"\"9999999999h\"", 0, false},
		{"\"30s\\n\"", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.val, func(t *testing.T) {
			doc := limitsDoc("read_timeout", tc.val)
			c, err := ParseWith([]byte(doc), false)
			if !tc.ok {
				if err == nil {
					t.Fatalf("accepted %s as %v", tc.val, c.Server.Limits.ReadTimeout)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", tc.val, err)
			}
			if got := time.Duration(c.Server.Limits.ReadTimeout); got != tc.want {
				t.Fatalf("%s decoded as %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

// TestEmptyDurationMeansDefault pins the one case the table above
// leaves out: an empty string is not zero, it is "use the default".
// A timeout that silently became zero would be no timeout at all.
func TestEmptyDurationMeansDefault(t *testing.T) {
	c, err := ParseWith([]byte(limitsDoc("read_timeout", `""`)), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Duration(c.Server.Limits.ReadTimeout); got != DefaultReadTimeout {
		t.Fatalf("read_timeout is %v, want the default %v", got, DefaultReadTimeout)
	}
}

// TestDuplicateKeys requires a repeated mapping key to be an error. A
// parser that takes the last wins turns a review of the first half of a
// document into no review at all: `allow_cidrs` written twice, the
// second one wider.
func TestDuplicateKeys(t *testing.T) {
	doc := serverDoc("  limits:\n    max_header_bytes: 4096\n    max_header_bytes: 1048576\n")
	err := mustFailFast(t, doc)
	if !strings.Contains(err.Error(), "already") && !strings.Contains(err.Error(), "duplicate") {
		t.Logf("refused, though not as a duplicate: %v", err)
	}
}

// TestUnknownFieldsRefused is the property the package doc promises:
// a typo can never silently disable a control. The cases are the
// plausible typos, not nonsense.
func TestUnknownFieldsRefused(t *testing.T) {
	cases := []string{
		limitsDoc("max_headers_bytes", "4096"),
		base + "waf:\n  enabled: true\n  paranoia_level: 2\n  enable: true\n",
		"version: 1\nserver:\n  listeners:\n    - name: web\n      addr: \"127.0.0.1:8080\"\n",
	}
	for i, doc := range cases {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) { mustFailFast(t, doc) })
	}
}

// TestEncodingHazards covers what arrives when a file has been through
// an editor, a template or a transfer that was not byte transparent.
func TestEncodingHazards(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		ok   bool
	}{
		{"utf8 bom", "\ufeff" + base, true},
		{"crlf", strings.ReplaceAll(base, "\n", "\r\n"), true},
		// A lone CR is a line break in YAML 1.2, so a file written by a
		// classic Mac editor still loads.
		{"lone cr", strings.ReplaceAll(base, "\n", "\r"), true},
		{"nul byte", base + "\x00", false},
		{"utf16 le bom", "\xff\xfe" + base, false},
		{"utf16 be bom", "\xfe\xff" + base, false},
		{"invalid utf8", "version: 1\nserver:\n  listeners:\n    - name: \"\xc3\x28\"\n", false},
		{"lone surrogate", "version: 1\nserver:\n  listeners:\n    - name: \"\\ud800\"\n", false},
		{"tabs for indent", "version: 1\nserver:\n  listeners:\n\t- name: web\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWith([]byte(tc.doc), false)
			if tc.ok && err != nil {
				t.Fatalf("refused a document that should load: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("accepted a document that should be refused")
			}
		})
	}
}

// TestControlCharactersInNames requires a name carrying a control byte
// to be refused. Names reach the logs, the management views and the
// metric labels, and a carriage return in one of them forges a log
// line.
func TestControlCharactersInNames(t *testing.T) {
	for _, bad := range []string{"we\x00b", "we\rb", "we\nb", "we\x1bb", "we\x7fb"} {
		doc := "version: 1\nserver:\n  listeners:\n    - name: " + fmt.Sprintf("%q", bad) + "\n      address: \"127.0.0.1:8080\"\n" +
			"upstreams:\n  - name: app\n    endpoints:\n      - address: \"127.0.0.1:9000\"\n" +
			"routes:\n  - name: all\n    upstream: app\n"
		if _, err := ParseWith([]byte(doc), false); err == nil {
			t.Fatalf("accepted a listener name containing %q", bad)
		}
	}
}

// TestMultipleDocuments requires a second YAML document in the stream
// to be refused rather than ignored: everything after `---` would
// otherwise be configuration the operator wrote and the proxy never
// read.
func TestMultipleDocuments(t *testing.T) {
	err := mustFailFast(t, base+"---\nversion: 1\n")
	if !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestEmptyAndWhitespaceOnly covers the documents that carry no
// information at all. Each must name the problem; an empty Config with
// every default applied would be a proxy that listens on nothing and
// says nothing about why.
func TestEmptyAndWhitespaceOnly(t *testing.T) {
	for _, doc := range []string{"", "\n", "   \n\t\n", "# just a comment\n", "---\n", "null\n", "~\n"} {
		if _, err := ParseWith([]byte(doc), false); err == nil {
			t.Fatalf("accepted %q", doc)
		}
	}
}

// TestWhitespaceInValues pins what happens to the space around a value.
// YAML strips it from a plain scalar and keeps it inside quotes, and an
// address with a trailing space must not become a listener on a host
// nobody can name.
func TestWhitespaceInValues(t *testing.T) {
	doc := "version: 1\nserver:\n  listeners:\n    - name: web\n      address: \" 127.0.0.1:8080 \"\n" +
		"upstreams:\n  - name: app\n    endpoints:\n      - address: \"127.0.0.1:9000\"\n" +
		"routes:\n  - name: all\n    upstream: app\n"
	if _, err := ParseWith([]byte(doc), false); err == nil {
		t.Fatal("accepted a listener address padded with spaces")
	}
	doc = "version: 1\nserver:\n  listeners:\n    - name: web\n      address: \"127.0.0.1:8080\"\n" +
		"upstreams:\n  - name: app\n    endpoints:\n      - address: \" 127.0.0.1:9000\"\n" +
		"routes:\n  - name: all\n    upstream: app\n"
	if _, err := ParseWith([]byte(doc), false); err == nil {
		t.Fatal("accepted an endpoint address padded with spaces")
	}
}

// TestLongValues is the size case for a single scalar rather than the
// document: one field carrying a megabyte. It must be refused by a
// rule, not accepted into a struct that is later written to a log line.
func TestLongValues(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	doc := "version: 1\nserver:\n  listeners:\n    - name: " + long + "\n      address: \"127.0.0.1:8080\"\n" +
		"upstreams:\n  - name: app\n    endpoints:\n      - address: \"127.0.0.1:9000\"\n" +
		"routes:\n  - name: all\n    upstream: app\n"
	mustFailFast(t, doc)
}

// TestManyItems is the size case for repetition: a document that stays
// under the byte ceiling while asking for a hundred thousand routes.
// It must either load without pathological cost or be refused — what it
// must not do is take minutes inside validation.
func TestManyItems(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 1\nserver:\n  listeners:\n    - name: web\n      address: \"127.0.0.1:8080\"\n")
	b.WriteString("upstreams:\n  - name: app\n    endpoints:\n      - address: \"127.0.0.1:9000\"\n")
	b.WriteString("routes:\n")
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, "  - name: r%d\n    paths: [\"/p%d\"]\n    upstream: app\n", i, i)
	}
	start := time.Now()
	c, err := ParseWith([]byte(b.String()), false)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if took > 30*time.Second {
		t.Fatalf("20000 routes took %v", took)
	}
	// No silent truncation: every route the operator wrote is present.
	if len(c.Routes) != 20000 {
		t.Fatalf("loaded %d routes, wrote 20000", len(c.Routes))
	}
	t.Logf("20000 routes parsed and validated in %v", took)
}

// TestDeterministicErrors requires the same document to produce the
// same error text every time. Validation walks maps in several places,
// and Go randomises map iteration: an error list whose order changes
// between runs makes a configuration review a diff of noise.
func TestDeterministicErrors(t *testing.T) {
	doc := "version: 1\nserver:\n  listeners:\n    - name: web\n      address: \"bad\"\n    - name: web\n      address: \"127.0.0.1:8080\"\n" +
		"upstreams:\n  - name: app\n    endpoints:\n      - address: \"nonsense\"\n" +
		"routes:\n  - name: all\n    upstream: missing\n  - name: all\n    upstream: app\n"
	var first string
	for i := 0; i < 20; i++ {
		_, err := ParseWith([]byte(doc), false)
		if err == nil {
			t.Fatal("expected errors")
		}
		if i == 0 {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Fatalf("error text changed between runs:\nfirst: %s\nnow:   %s", first, err.Error())
		}
	}
}

// TestIdempotentParse requires parsing the same bytes twice to produce
// the same configuration. Defaulting mutates the struct it is given,
// and a default computed from an already defaulted field would drift.
func TestIdempotentParse(t *testing.T) {
	a, err := ParseWith([]byte(base), false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseWith([]byte(base), false)
	if err != nil {
		t.Fatal(err)
	}
	// Compare the documents rather than the structs: the structs hold
	// pointers, whose addresses differ by construction.
	ya, err := yaml.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	yb, err := yaml.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ya) != string(yb) {
		t.Fatalf("two parses of the same document differ:\n%s\n---\n%s", ya, yb)
	}
}

// TestConcurrentParse runs the parser from many goroutines at once. It
// is the regression test for shared state hiding in package level
// variables — a compiled regular expression cache, a reused buffer, a
// validator that is not really per call.
func TestConcurrentParse(t *testing.T) {
	docs := []string{base, base + "logging:\n  stdout: true\n", base + "logging:\n  level: debug\n"}
	done := make(chan string, 64)
	for i := 0; i < 64; i++ {
		go func(i int) {
			c, err := ParseWith([]byte(docs[i%len(docs)]), false)
			if err != nil {
				done <- err.Error()
				return
			}
			done <- c.Server.Listeners[0].Name
		}(i)
	}
	for i := 0; i < 64; i++ {
		if got := <-done; got != "web" {
			t.Fatalf("goroutine %d: %s", i, got)
		}
	}
}
