package jsonschema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// This validator stands between an unauthenticated request body and the
// origin. Everything it is asked to check arrives from the client; the
// schema it checks against arrives from configuration, which is only
// half a mitigation — an OpenAPI description is often generated, vendored
// or fetched. These tests are the hostile half of the package's
// contract.

// doc parses a JSON schema document written as a string, the way the
// tests below spell them.
func doc(t *testing.T, s string) map[string]any {
	t.Helper()
	v, err := Decode([]byte(s))
	if err != nil {
		t.Fatalf("test schema is not JSON: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatal("test schema is not an object")
	}
	return m
}

// value parses a JSON value the way Decode gives it to Validate.
func value(t *testing.T, s string) any {
	t.Helper()
	v, err := Decode([]byte(s))
	if err != nil {
		t.Fatalf("test value is not JSON: %v", err)
	}
	return v
}

// check runs one validation and returns the report.
func check(t *testing.T, schema, val string) (bool, *Report) {
	t.Helper()
	d := doc(t, schema)
	v := New(d)
	rep := &Report{}
	ok := v.Validate(d, value(t, val), "", rep, 0)
	return ok, rep
}

// TestReferenceCycle is the schema equivalent of a cyclic data
// structure: A refers to B, B back to A. Nothing in the document is
// wrong — it is a legal way to describe a linked list — so the
// validator must build, and validating against it must end.
func TestReferenceCycle(t *testing.T) {
	schema := `{
	  "$ref": "#/defs/A",
	  "defs": {
	    "A": {"type": "object", "properties": {"b": {"$ref": "#/defs/B"}}},
	    "B": {"type": "object", "properties": {"a": {"$ref": "#/defs/A"}}}
	  }
	}`
	done := make(chan bool, 1)
	go func() {
		ok, _ := check(t, schema, `{"b":{"a":{"b":{"a":{}}}}}`)
		done <- ok
	}()
	select {
	case <-done:
	case <-timeout(t):
		t.Fatal("a cyclic $ref did not terminate")
	}
}

// TestSelfReference is the tightest cycle: a node that refers to
// itself. cacheRef seeds the cache before it resolves, which is what
// keeps this from recursing forever.
func TestSelfReference(t *testing.T) {
	schema := `{"$ref": "#/defs/Loop", "defs": {"Loop": {"$ref": "#/defs/Loop"}}}`
	ok, _ := check(t, schema, `{}`)
	_ = ok // the verdict is not the point; returning at all is
}

// TestRefChain is a long chain of references, each one hop. It must
// resolve to the end or stop at the hop limit, never walk forever.
func TestRefChain(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"$ref": "#/defs/s0", "defs": {`)
	const n = 200
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		if i == n-1 {
			fmt.Fprintf(&b, `"s%d": {"type": "string"}`, i)
		} else {
			fmt.Fprintf(&b, `"s%d": {"$ref": "#/defs/s%d"}`, i, i+1)
		}
	}
	b.WriteString("}}")
	ok, _ := check(t, b.String(), `"hello"`)
	t.Logf("a %d hop chain validated: %v", n, ok)
}

// TestDanglingRef covers a pointer that names nothing: a document
// trimmed of its components section, a typo, a remote reference in a
// validator that only does local ones. It must not match everything
// silently and it must not panic.
func TestDanglingRef(t *testing.T) {
	for _, ref := range []string{
		`"#/components/schemas/Gone"`,
		`"https://example.com/schema.json"`,
		`"#"`,
		`""`,
		`"#/"`,
		`"#/a/b/c/d/e"`,
		`"#/defs/0/1"`,
	} {
		schema := `{"$ref": ` + ref + `, "defs": {}}`
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on $ref %s: %v", ref, r)
				}
			}()
			check(t, schema, `{"anything": 1}`)
		}()
	}
}

// TestExternalReferenceIsNotFetched is the XXE question asked of JSON:
// a reference naming a URL or a file must never be dereferenced. A
// validator that fetched them would turn every request body into a
// request the proxy makes on the client's behalf — a server-side
// request forgery with the proxy's network position.
func TestExternalReferenceIsNotFetched(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.json")
	if err := os.WriteFile(secret, []byte(`{"type":"string"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{
		"https://example.invalid/schema.json",
		"http://169.254.169.254/latest/meta-data/",
		"file://" + secret,
		secret,
		"//evil.example/schema.json",
		"../../etc/passwd",
	} {
		schema := fmt.Sprintf(`{"$ref": %q}`, ref)
		d := doc(t, schema)
		v := New(d)
		s := v.Resolve(d)
		if len(s.Raw) != 0 {
			t.Fatalf("$ref %q resolved to %v; only local pointers may resolve", ref, s.Raw)
		}
	}
}

// TestPointerEscapes covers the two escapes a JSON pointer defines and
// the percent escape the resolver also accepts. A pointer that walks
// somewhere else than it spells is a way to aim a schema at a node the
// author did not mean.
func TestPointerEscapes(t *testing.T) {
	schema := `{
	  "$ref": "#/defs/a~1b",
	  "defs": {"a/b": {"type": "string"}, "a~b": {"type": "integer"}}
	}`
	d := doc(t, schema)
	v := New(d)
	if got := v.Resolve(d).Raw["type"]; got != "string" {
		t.Fatalf("~1 resolved to %v, want the \"a/b\" node", got)
	}
	schema = `{"$ref": "#/defs/a~0b", "defs": {"a/b": {"type": "string"}, "a~b": {"type": "integer"}}}`
	d = doc(t, schema)
	v = New(d)
	if got := v.Resolve(d).Raw["type"]; got != "integer" {
		t.Fatalf("~0 resolved to %v, want the \"a~b\" node", got)
	}
}

// TestDeepValueIsBounded is the recursion case on the value side: a
// body nested far deeper than the schema. maxDepth must end it with an
// issue rather than with a stack the runtime cannot grow.
func TestDeepValueIsBounded(t *testing.T) {
	for _, depth := range []int{100, 1000, 10000} {
		t.Run(fmt.Sprintf("depth%d", depth), func(t *testing.T) {
			body := strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth)
			schema := `{"type": "object", "additionalProperties": true}`
			d := doc(t, schema)
			v := New(d)
			parsed, err := Decode([]byte(body))
			if err != nil {
				// encoding/json has its own nesting ceiling; being
				// refused before the validator sees it is also correct.
				return
			}
			rep := &Report{}
			ok := v.Validate(d, parsed, "", rep, 0)
			t.Logf("depth %d: ok=%v issues=%d", depth, ok, len(rep.Issues))
		})
	}
}

// TestDeepSchemaIsBounded is the same question from the schema side: a
// deeply nested allOf chain applied to a trivial value.
func TestDeepSchemaIsBounded(t *testing.T) {
	const depth = 500
	schema := strings.Repeat(`{"allOf": [`, depth) + `{"type": "string"}` + strings.Repeat("]}", depth)
	ok, rep := check(t, schema, `"x"`)
	t.Logf("a %d deep allOf: ok=%v issues=%d", depth, ok, len(rep.Issues))
}

// TestReportIsBounded requires a body with thousands of problems to
// produce at most MaxErrors issues. The report becomes a log line and a
// response body; unbounded, one request writes megabytes to both.
func TestReportIsBounded(t *testing.T) {
	var props, body []string
	for i := 0; i < 5000; i++ {
		props = append(props, fmt.Sprintf(`"p%d": {"type": "string"}`, i))
		body = append(body, fmt.Sprintf(`"p%d": %d`, i, i))
	}
	schema := `{"type":"object","properties":{` + strings.Join(props, ",") + `}}`
	_, rep := check(t, schema, `{`+strings.Join(body, ",")+`}`)
	if len(rep.Issues) != MaxErrors {
		t.Fatalf("report holds %d issues, the cap is %d", len(rep.Issues), MaxErrors)
	}
}

// TestIssueOrderIsStable requires the same body to report the same
// first issue every time. Object properties live in a map, and Go
// randomises map iteration: a denial that names a different field on
// every request is one nobody can act on.
func TestIssueOrderIsStable(t *testing.T) {
	schema := `{"type":"object","properties":{
	  "a":{"type":"string"},"b":{"type":"string"},"c":{"type":"string"},
	  "d":{"type":"string"},"e":{"type":"string"},"f":{"type":"string"}}}`
	body := `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6}`
	var first string
	for i := 0; i < 50; i++ {
		_, rep := check(t, schema, body)
		got := fmt.Sprint(rep.Issues)
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("issue order changed:\nfirst: %s\nnow:   %s", first, got)
		}
	}
}

// TestPatternIsNotBacktracking is the ReDoS question. Go's regexp is
// RE2 and runs in time linear in the subject, so the classic
// catastrophic patterns are safe here — this test is the regression
// that says so, because a swap to a backtracking engine would make
// every `pattern` keyword a denial of service with a 40 byte body.
func TestPatternIsNotBacktracking(t *testing.T) {
	schema := `{"type":"string","pattern":"^(a+)+$"}`
	subject := strings.Repeat("a", 40) + "!"
	done := make(chan struct{})
	go func() {
		check(t, schema, fmt.Sprintf("%q", subject))
		close(done)
	}()
	select {
	case <-done:
	case <-timeout(t):
		t.Fatal("a nested quantifier pattern did not finish: the engine backtracks")
	}
}

// TestBadPatternIsIgnored covers a `pattern` the engine will not
// compile. It must not match everything and must not panic — the
// keyword is dropped and the rest of the schema still applies.
func TestBadPatternIsIgnored(t *testing.T) {
	schema := `{"type":"string","pattern":"([","maxLength":3}`
	if ok, _ := check(t, schema, `"abcdef"`); ok {
		t.Fatal("maxLength stopped applying because pattern would not compile")
	}
}

// TestHugePatternIsBounded covers a schema whose pattern is enormous.
// It comes from configuration, but a generated description can carry
// one, and regexp.Compile is not free.
func TestHugePatternIsBounded(t *testing.T) {
	pattern := "^(" + strings.Repeat("a|", 20000) + "b)$"
	schema := fmt.Sprintf(`{"type":"string","pattern":%q}`, pattern)
	done := make(chan struct{})
	go func() {
		check(t, schema, `"b"`)
		close(done)
	}()
	select {
	case <-done:
	case <-timeout(t):
		t.Fatal("compiling a large pattern did not finish")
	}
}

// TestRegexpCacheIsBounded requires the compiled pattern cache to stop
// growing. patternProperties keys are compiled too, and a schema with
// thousands of them would otherwise pin them all in memory for the life
// of the generation.
func TestRegexpCacheIsBounded(t *testing.T) {
	v := New(map[string]any{})
	for i := 0; i < 10000; i++ {
		v.regexp(fmt.Sprintf("^p%d$", i))
	}
	v.reMu.Lock()
	n := len(v.res)
	v.reMu.Unlock()
	if n > 4096 {
		t.Fatalf("the regexp cache holds %d entries, the bound is 4096", n)
	}
}

// TestNumericEdges covers the numbers a bound has to survive: the ends
// of the int64 range, a value past float64's integer precision, a very
// long literal, and the spellings JSON does not have.
func TestNumericEdges(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		val    string
		want   bool
	}{
		{"int64 max", `{"type":"integer","maximum":9223372036854775807}`, "9223372036854775807", true},
		{"int64 min", `{"type":"integer","minimum":-9223372036854775808}`, "-9223372036854775808", true},
		{"past int64", `{"type":"integer","maximum":9223372036854775807}`, "9223372036854775808", true},
		{"huge exponent", `{"type":"number","maximum":100}`, "1e308", false},
		{"overflowing exponent", `{"type":"number","maximum":100}`, "1e400", false},
		{"tiny", `{"type":"number","minimum":0}`, "1e-308", true},
		{"negative zero", `{"type":"number","minimum":0}`, "-0", true},
		{"long literal", `{"type":"number","maximum":1}`, "0." + strings.Repeat("0", 400) + "1", true},
		{"integer as float", `{"type":"integer"}`, "1.0", true},
		{"fraction as integer", `{"type":"integer"}`, "1.5", false},
		{"multipleOf", `{"type":"number","multipleOf":0.1}`, "0.3", true},
		{"exclusive bound", `{"type":"number","exclusiveMaximum":10}`, "10", false},
		{"draft4 exclusive", `{"type":"number","maximum":10,"exclusiveMaximum":true}`, "10", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, rep := check(t, tc.schema, tc.val)
			if ok != tc.want {
				t.Fatalf("got %v want %v (%v)", ok, tc.want, rep.Issues)
			}
		})
	}
}

// TestNonFiniteNeverSatisfiesABound is the property behind the NaN
// case: a value that is not a finite number must fail every bound
// rather than pass them all. NaN compares false against both a minimum
// and a maximum, which is how an out-of-range value slips through a
// naive implementation.
func TestNonFiniteNeverSatisfiesABound(t *testing.T) {
	d := doc(t, `{"type":"number","minimum":0,"maximum":10}`)
	v := New(d)
	for _, n := range []json.Number{"NaN", "Inf", "-Inf", "+Inf", "inf", "nan"} {
		rep := &Report{}
		if v.Validate(d, n, "", rep, 0) {
			t.Fatalf("%q satisfied a bounded schema", n)
		}
	}
}

// TestCoerceRejectsNonJSONNumbers is the same question for a query
// parameter, which arrives as text. strconv.ParseFloat is wider than
// JSON: it takes NaN, Inf, hexadecimal floats and Go's underscore
// separators, each of which the origin reads differently from the proxy.
func TestCoerceRejectsNonJSONNumbers(t *testing.T) {
	raw := map[string]any{"type": "integer"}
	for _, s := range []string{
		"NaN", "nan", "Inf", "+Inf", "-Inf", "infinity",
		"0x1p8", "0x10", "1_0", "1e1_0", " 1", "1 ", "+1", "01", "00", ".5", "5.", "1e", "--1", "1,5",
	} {
		if got := Coerce(raw, s); got != any(s) {
			t.Fatalf("Coerce(%q) produced the number %v; it must stay a string", s, got)
		}
	}
	for _, s := range []string{"0", "-0", "1", "-1", "1.5", "1e3", "1E3", "1e-3", "0.5", "123456789012345678901234567890"} {
		if _, isNum := Coerce(raw, s).(json.Number); !isNum {
			t.Fatalf("Coerce(%q) did not produce a number", s)
		}
	}
}

// TestCoerceArrayAndBoolean covers the other two coercions, including
// the separators a list parameter is split on and the strings that are
// not booleans however much they look like one.
func TestCoerceArrayAndBoolean(t *testing.T) {
	arr := map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}
	got, _ := Coerce(arr, "1,2,3").([]any)
	if len(got) != 3 {
		t.Fatalf("a three item list coerced to %v", got)
	}
	for _, e := range got {
		if _, ok := e.(json.Number); !ok {
			t.Fatalf("list item %v is not a number", e)
		}
	}
	if one, _ := Coerce(arr, "").([]any); len(one) != 1 {
		t.Fatalf("an empty list parameter coerced to %v", one)
	}
	b := map[string]any{"type": "boolean"}
	for _, s := range []string{"TRUE", "True", "1", "yes", "on", "t", " true"} {
		if v := Coerce(b, s); v != any(s) {
			t.Fatalf("Coerce(%q) produced the boolean %v", s, v)
		}
	}
	if Coerce(b, "true") != true || Coerce(b, "false") != false {
		t.Fatal("true and false did not coerce")
	}
}

// TestStringSemantics covers what a length bound counts and what a
// format check accepts. minLength counts characters, not bytes: an
// implementation that counted bytes would let a limit of ten hold three
// emoji and reject ten Greek letters.
func TestStringSemantics(t *testing.T) {
	if ok, _ := check(t, `{"type":"string","maxLength":3}`, `"åäö"`); !ok {
		t.Fatal("three multi-byte characters failed a three character limit")
	}
	if ok, _ := check(t, `{"type":"string","minLength":3}`, `"åä"`); ok {
		t.Fatal("two characters passed a three character minimum")
	}
	// A combining sequence is more code points than it is graphemes.
	// The rule is documented as characters, meaning runes, and this
	// test pins that so a change of mind is deliberate.
	if ok, _ := check(t, `{"type":"string","maxLength":1}`, `"é"`); ok {
		t.Fatal("e + combining acute passed a one character limit")
	}
	// A lone surrogate does not survive JSON decoding as one rune.
	if _, err := Decode([]byte(`"\ud800"`)); err != nil {
		t.Logf("a lone surrogate was refused at decode: %v", err)
	}
	// NUL and the other control characters are legal JSON when escaped.
	if ok, _ := check(t, `{"type":"string","maxLength":3}`, `"a\u0000b"`); !ok {
		t.Fatal("an escaped NUL failed a length check")
	}
}

// TestFormats walks every format the package knows, with the values
// that must pass and the near misses that must not.
func TestFormats(t *testing.T) {
	cases := []struct {
		format string
		good   []string
		bad    []string
	}{
		{"date-time", []string{"2026-09-20T10:00:00Z", "2026-09-20T10:00:00+02:00"}, []string{"2026-09-20", "2026-09-20 10:00:00", "not a time", ""}},
		{"date", []string{"2026-09-20"}, []string{"2026-9-20", "20/09/2026", "2026-13-01", "2026-02-30", ""}},
		{"email", []string{"a@b.co", "first.last@example.com"}, []string{"a@", "@b.co", "a b@c.d", "<a@b.co>", ""}},
		{"uuid", []string{"123e4567-e89b-12d3-a456-426614174000"}, []string{"123e4567e89b12d3a456426614174000", "123e4567-e89b-12d3-a456-42661417400", "zzze4567-e89b-12d3-a456-426614174000", ""}},
		{"ipv4", []string{"127.0.0.1", "0.0.0.0"}, []string{"::1", "127.0.0.1.1", "127.1", "999.0.0.1", ""}},
		{"ipv6", []string{"::1", "2001:db8::1"}, []string{"127.0.0.1", "not an address", ""}},
		{"uri", []string{"https://example.com/a", "mailto:a@b.co"}, []string{"/relative", "example.com", ""}},
		{"hostname", []string{"example.com", "a"}, []string{"a b", "a/b", "a:b", "", strings.Repeat("a", 254)}},
		{"unknown-format", []string{"anything at all"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			schema := fmt.Sprintf(`{"type":"string","format":%q}`, tc.format)
			for _, s := range tc.good {
				if ok, rep := check(t, schema, mustJSON(t, s)); !ok {
					t.Errorf("%q was refused as %s: %v", s, tc.format, rep.Issues)
				}
			}
			for _, s := range tc.bad {
				if ok, _ := check(t, schema, mustJSON(t, s)); ok {
					t.Errorf("%q was accepted as %s", s, tc.format)
				}
			}
		})
	}
}

// TestCombinators covers allOf, anyOf, oneOf and not, including the
// empty forms, which are the ones a generated document produces and
// which must not mean "everything passes".
func TestCombinators(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		val    string
		want   bool
	}{
		{"allOf both", `{"allOf":[{"type":"string"},{"maxLength":3}]}`, `"ab"`, true},
		{"allOf one fails", `{"allOf":[{"type":"string"},{"maxLength":1}]}`, `"ab"`, false},
		{"anyOf first", `{"anyOf":[{"type":"string"},{"type":"integer"}]}`, `"a"`, true},
		{"anyOf second", `{"anyOf":[{"type":"string"},{"type":"integer"}]}`, `1`, true},
		{"anyOf none", `{"anyOf":[{"type":"string"},{"type":"integer"}]}`, `true`, false},
		{"anyOf empty", `{"anyOf":[]}`, `1`, false},
		{"oneOf exactly one", `{"oneOf":[{"type":"string"},{"type":"integer"}]}`, `1`, true},
		{"oneOf both", `{"oneOf":[{"type":"integer"},{"minimum":0}]}`, `1`, false},
		{"oneOf none", `{"oneOf":[{"type":"string"},{"type":"boolean"}]}`, `1`, false},
		{"not", `{"not":{"type":"string"}}`, `1`, true},
		{"not matches", `{"not":{"type":"string"}}`, `"a"`, false},
		{"not empty", `{"not":{}}`, `1`, false},
		{"false schema", `{"$ref":"#/defs/no","defs":{"no":false}}`, `1`, false},
		{"true schema", `{"$ref":"#/defs/yes","defs":{"yes":true}}`, `1`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, rep := check(t, tc.schema, tc.val)
			if ok != tc.want {
				t.Fatalf("got %v want %v (%v)", ok, tc.want, rep.Issues)
			}
		})
	}
}

// TestObjectKeywords covers required, the property count bounds,
// patternProperties and the three shapes additionalProperties takes.
func TestObjectKeywords(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		val    string
		want   bool
	}{
		{"required present", `{"type":"object","required":["a"]}`, `{"a":1}`, true},
		{"required missing", `{"type":"object","required":["a"]}`, `{"b":1}`, false},
		{"required null", `{"type":"object","required":["a"]}`, `{"a":null}`, true},
		{"minProperties", `{"type":"object","minProperties":2}`, `{"a":1}`, false},
		{"maxProperties", `{"type":"object","maxProperties":1}`, `{"a":1,"b":2}`, false},
		{"additional false", `{"type":"object","properties":{"a":{}},"additionalProperties":false}`, `{"a":1,"b":2}`, false},
		{"additional true", `{"type":"object","properties":{"a":{}},"additionalProperties":true}`, `{"a":1,"b":2}`, true},
		{"additional schema", `{"type":"object","additionalProperties":{"type":"string"}}`, `{"b":2}`, false},
		{"patternProperties", `{"type":"object","patternProperties":{"^x":{"type":"string"}}}`, `{"xa":1}`, false},
		{"pattern beats additional", `{"type":"object","patternProperties":{"^x":{}},"additionalProperties":false}`, `{"xa":1}`, true},
		{"empty object", `{"type":"object","required":[]}`, `{}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, rep := check(t, tc.schema, tc.val)
			if ok != tc.want {
				t.Fatalf("got %v want %v (%v)", ok, tc.want, rep.Issues)
			}
		})
	}
}

// TestArrayKeywords covers the array bounds and uniqueItems, whose
// comparison is by JSON encoding and therefore has opinions about
// numbers that look alike.
func TestArrayKeywords(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		val    string
		want   bool
	}{
		{"minItems", `{"type":"array","minItems":2}`, `[1]`, false},
		{"maxItems", `{"type":"array","maxItems":1}`, `[1,2]`, false},
		{"items", `{"type":"array","items":{"type":"string"}}`, `["a",1]`, false},
		{"unique ok", `{"type":"array","uniqueItems":true}`, `[1,2,3]`, true},
		{"unique repeat", `{"type":"array","uniqueItems":true}`, `[1,1]`, false},
		{"unique objects", `{"type":"array","uniqueItems":true}`, `[{"a":1},{"a":1}]`, false},
		{"unique empty", `{"type":"array","uniqueItems":true}`, `[]`, true},
		{"nested items", `{"type":"array","items":{"type":"array","items":{"type":"integer"}}}`, `[[1],[2,"x"]]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, rep := check(t, tc.schema, tc.val)
			if ok != tc.want {
				t.Fatalf("got %v want %v (%v)", ok, tc.want, rep.Issues)
			}
		})
	}
}

// TestUniqueItemsCostIsNotQuadratic is the algorithmic complexity case
// for uniqueItems: a comparison of every pair would make a 20000 item
// array 400 million comparisons from one request body.
func TestUniqueItemsCostIsNotQuadratic(t *testing.T) {
	var items []string
	for i := 0; i < 20000; i++ {
		items = append(items, fmt.Sprint(i))
	}
	schema := `{"type":"array","uniqueItems":true}`
	done := make(chan struct{})
	go func() {
		check(t, schema, "["+strings.Join(items, ",")+"]")
		close(done)
	}()
	select {
	case <-done:
	case <-timeout(t):
		t.Fatal("uniqueItems over 20000 items did not finish: the check is quadratic")
	}
}

// TestNullHandling pins what null means at each keyword. OpenAPI 3.0
// spells it `nullable`, 3.1 spells it in `type`, and a schema with
// neither must not reject a null it never spoke about — except where an
// explicit type says otherwise.
func TestNullHandling(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		want   bool
	}{
		{"no type", `{}`, true},
		{"nullable", `{"type":"string","nullable":true}`, true},
		{"type list", `{"type":["string","null"]}`, true},
		{"typed", `{"type":"string"}`, false},
		{"enum without null", `{"enum":["a","b"]}`, false},
		{"enum with null", `{"enum":["a",null]}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, rep := check(t, tc.schema, `null`)
			if ok != tc.want {
				t.Fatalf("got %v want %v (%v)", ok, tc.want, rep.Issues)
			}
		})
	}
}

// TestEnumAndConst covers equality, which is by JSON encoding except
// for numbers, where 1 and 1.0 are the same value.
func TestEnumAndConst(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		val    string
		want   bool
	}{
		{"enum hit", `{"enum":["a","b"]}`, `"a"`, true},
		{"enum miss", `{"enum":["a","b"]}`, `"c"`, false},
		{"enum number forms", `{"enum":[1]}`, `1.0`, true},
		{"enum string not number", `{"enum":[1]}`, `"1"`, false},
		{"enum object", `{"enum":[{"a":1}]}`, `{"a":1}`, true},
		{"enum object key order", `{"enum":[{"a":1,"b":2}]}`, `{"b":2,"a":1}`, true},
		{"const hit", `{"const":"x"}`, `"x"`, true},
		{"const miss", `{"const":"x"}`, `"y"`, false},
		{"const number forms", `{"const":1}`, `1.000`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, rep := check(t, tc.schema, tc.val)
			if ok != tc.want {
				t.Fatalf("got %v want %v (%v)", ok, tc.want, rep.Issues)
			}
		})
	}
}

// TestDecodeIsStrict covers what Decode accepts. Trailing data is the
// dangerous one: two JSON documents in one body are read differently by
// the proxy and by an origin whose parser stops at the first.
func TestDecodeIsStrict(t *testing.T) {
	bad := []string{
		``, `   `, `{`, `{"a":}`, `{"a":1}{"b":2}`, `{"a":1} trailing`,
		`[1,2,`, `"unterminated`, `nul`, `01`, `{'a':1}`, `{"a":1,}`, `[1,]`,
		"\x00", `NaN`, `Infinity`, `-Infinity`, `+1`, `.5`,
	}
	for _, s := range bad {
		if _, err := Decode([]byte(s)); err == nil {
			t.Errorf("Decode accepted %q", s)
		}
	}
	good := []string{`{}`, `[]`, `null`, `true`, `1`, `"a"`, `{"a":1}`, ` {"a":1} `}
	for _, s := range good {
		if _, err := Decode([]byte(s)); err != nil {
			t.Fatalf("Decode refused %q: %v", s, err)
		}
	}
	// A byte order mark is not JSON. It must be refused rather than
	// skipped, because an origin that skips it and a proxy that does
	// not are reading two different documents.
	if _, err := Decode([]byte("\ufeff{}")); err == nil {
		t.Fatal("Decode accepted a leading byte order mark")
	}
}

// TestDecodeKeepsNumberText requires Decode to hand the validator the
// number as written. A float64 round trip loses the difference between
// 9223372036854775807 and 9223372036854775808, which is the difference
// between an id that exists and one that does not.
func TestDecodeKeepsNumberText(t *testing.T) {
	v, err := Decode([]byte(`{"id":9223372036854775807}`))
	if err != nil {
		t.Fatal(err)
	}
	n := v.(map[string]any)["id"].(json.Number)
	if n.String() != "9223372036854775807" {
		t.Fatalf("the number came back as %s", n)
	}
}

// TestDuplicateKeysInBody pins what happens when a body spells the same
// key twice. encoding/json keeps the last, which is what most origins
// do — the test exists so that a divergence is noticed, because a
// validator and an origin that disagree about which value counts is a
// bypass: `{"role":"user","role":"admin"}`.
func TestDuplicateKeysInBody(t *testing.T) {
	v, err := Decode([]byte(`{"role":"user","role":"admin"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := v.(map[string]any)["role"]
	if got != "admin" {
		t.Fatalf("the duplicate key resolved to %v, not the last one", got)
	}
	// And the schema sees the same value the origin will.
	if ok, _ := check(t, `{"type":"object","properties":{"role":{"enum":["user"]}}}`, `{"role":"user","role":"admin"}`); ok {
		t.Fatal("the enum was checked against the first value, not the last")
	}
}

// TestJsonify converts the shapes a YAML decoder produces into the
// shapes the validator expects, including the map with non-string keys
// that YAML alone can make.
func TestJsonify(t *testing.T) {
	in := map[any]any{
		1:     "one",
		"two": 2,
		"l":   []any{1, int64(2), 3.5, "s"},
		"m":   map[string]any{"n": int64(7)},
		true:  "yes",
	}
	out, ok := Jsonify(in).(map[string]any)
	if !ok {
		t.Fatal("Jsonify did not produce a string keyed map")
	}
	if out["1"] != "one" || out["true"] != "yes" {
		t.Fatalf("non-string keys became %v", out)
	}
	if _, isNum := out["two"].(json.Number); !isNum {
		t.Fatalf("an int stayed %T", out["two"])
	}
	l := out["l"].([]any)
	for i, e := range l {
		if i == 3 {
			break
		}
		if _, isNum := e.(json.Number); !isNum {
			t.Fatalf("list element %d stayed %T", i, e)
		}
	}
	if _, isNum := out["m"].(map[string]any)["n"].(json.Number); !isNum {
		t.Fatal("a nested int was not converted")
	}
}

// TestLoadDocument covers the file loader: the size ceiling, a missing
// file, a document that is not a mapping, and both syntaxes.
func TestLoadDocument(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := LoadDocument(write("ok.json", `{"a":1}`), 1<<20); err != nil {
		t.Fatalf("a small JSON document: %v", err)
	}
	if _, err := LoadDocument(write("ok.yaml", "a: 1\n"), 1<<20); err != nil {
		t.Fatalf("a small YAML document: %v", err)
	}
	if _, err := LoadDocument(write("big.json", strings.Repeat("x", 100)), 10); err == nil {
		t.Fatal("a document over the ceiling was accepted")
	}
	if _, err := LoadDocument(filepath.Join(dir, "absent.json"), 1<<20); err == nil {
		t.Fatal("a missing file was accepted")
	}
	if _, err := LoadDocument(write("list.yaml", "- 1\n- 2\n"), 1<<20); err == nil {
		t.Fatal("a list was accepted as a document")
	}
	if _, err := LoadDocument(write("bad.yaml", "a: [\n"), 1<<20); err == nil {
		t.Fatal("a malformed document was accepted")
	}
	if _, err := LoadDocument(write("empty.yaml", ""), 1<<20); err == nil {
		t.Fatal("an empty document was accepted")
	}
}

// TestLoadDocumentDoesNotExpandAliases is the billion laughs case on
// the schema side: the document is YAML, and YAML has anchors.
func TestLoadDocumentDoesNotExpandAliases(t *testing.T) {
	var b strings.Builder
	b.WriteString("a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n")
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
	p := filepath.Join(t.TempDir(), "bomb.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadDocument(p, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		t.Logf("the alias bomb resolved to: %v", err)
	case <-timeout(t):
		t.Fatal("a YAML alias bomb in a schema document did not finish")
	}
}

// TestConcurrentValidation runs one validator from many goroutines with
// different bodies. The validator is built once per route and shared by
// every request on it, so a map written on the request path here is a
// process-fatal error two unauthenticated requests can cause. Run this
// one under -race.
func TestConcurrentValidation(t *testing.T) {
	d := doc(t, `{
	  "type":"object",
	  "properties":{
	    "a":{"$ref":"#/defs/S"},
	    "b":{"$ref":"#/defs/N"},
	    "c":{"type":"string","pattern":"^[a-z]+$"}
	  },
	  "defs":{"S":{"type":"string"},"N":{"type":"integer","minimum":0}}
	}`)
	v := New(d)
	bodies := []string{
		`{"a":"x","b":1,"c":"abc"}`,
		`{"a":1,"b":"x","c":"ABC"}`,
		`{"a":"y","b":-1}`,
		`{}`,
		`{"c":"zzz","a":"q","b":99}`,
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := value(t, bodies[i%len(bodies)])
			for j := 0; j < 20; j++ {
				v.Validate(d, body, "", &Report{}, 0)
			}
		}(i)
	}
	wg.Wait()
}

// TestValidateIsPure requires validation to leave the value alone. The
// same body is validated twice against schemas that would rewrite it if
// anything here mutated, and the second verdict must equal the first.
func TestValidateIsPure(t *testing.T) {
	d := doc(t, `{"type":"object","properties":{"a":{"type":"integer","minimum":5}}}`)
	v := New(d)
	body := value(t, `{"a":1}`)
	first := v.Validate(d, body, "", &Report{}, 0)
	second := v.Validate(d, body, "", &Report{}, 0)
	if first != second {
		t.Fatal("validating the same value twice gave different verdicts")
	}
	if got := body.(map[string]any)["a"]; got.(json.Number).String() != "1" {
		t.Fatalf("the value was modified to %v", got)
	}
}

// TestTypeAllows exercises the type keyword in both of its shapes,
// including the one OpenAPI 3.1 introduced.
func TestTypeAllows(t *testing.T) {
	if !TypeAllows("number", "integer") {
		t.Fatal("a number does not admit an integer")
	}
	if TypeAllows("integer", "number") {
		t.Fatal("an integer admitted a number")
	}
	if !TypeAllows([]any{"string", "null"}, "null") {
		t.Fatal("a type list did not admit null")
	}
	if TypeAllows(nil, "string") || TypeAllows(42, "string") || TypeAllows([]any{1, 2}, "string") {
		t.Fatal("a nonsense type keyword admitted a value")
	}
}

// mustJSON quotes a string as a JSON document.
func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// timeout is the deadline the cases that must terminate share. It is
// generous: the point is to separate "finished" from "never finishes",
// not to measure.
func timeout(t *testing.T) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{})
	timer := time.AfterFunc(30*time.Second, func() { close(ch) })
	t.Cleanup(func() { timer.Stop() })
	return ch
}
