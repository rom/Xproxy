package openapi

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// styleSpec declares the same array four ways and an object as a
// deepObject, which is how generated descriptions spell a filter.
const styleSpec = `
openapi: 3.0.3
info: {title: Styles, version: "1"}
servers: [{url: https://api.example.com/v1}]
paths:
  /items:
    get:
      parameters:
        - name: ids
          in: query
          schema: {type: array, items: {type: integer, minimum: 1}, maxItems: 4}
        - name: piped
          in: query
          style: pipeDelimited
          explode: false
          schema: {type: array, items: {type: integer, minimum: 1}}
        - name: spaced
          in: query
          style: spaceDelimited
          explode: false
          schema: {type: array, items: {type: integer, minimum: 1}}
        - name: filter
          in: query
          style: deepObject
          explode: true
          schema:
            type: object
            required: [from]
            additionalProperties: false
            properties:
              from: {type: string, format: date}
              size: {type: integer, minimum: 1, maximum: 50}
        - name: X-Tags
          in: header
          schema: {type: array, items: {type: string, enum: [a, b, c]}}
  /items/{ids}:
    get:
      parameters:
        - name: ids
          in: path
          required: true
          schema: {type: array, items: {type: integer, minimum: 1}}
`

func styleFilter(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	all := filter.Options{"spec_file": write(t, styleSpec)}
	for k, v := range opts {
		all[k] = v
	}
	f, err := filtertest.Build("openapi", "styles", all)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func doGet(t *testing.T, f filter.Filter, target string, hdr ...string) filter.Verdict {
	t.Helper()
	r, _ := http.NewRequest("GET", "http://api.example.com"+target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	return filtertest.Run(f, r, nil).Request
}

// An array parameter arrives in four spellings and a validator that knows
// one of them refuses the other three. That is a worse failure than not
// checking: the request was correct, the description said so, and the
// gateway refused it, which is how a validating gateway gets taken out of
// the path.
func TestAnArrayParameterInEverySpellingItIsDeclaredIn(t *testing.T) {
	f := styleFilter(t, nil)
	for _, target := range []string{
		"/v1/items?ids=1&ids=2&ids=3", // exploded form: repeated
		"/v1/items?ids=1,2,3",         // the same list in one value
		"/v1/items?ids=1,2&ids=3",     // and both at once
		"/v1/items?piped=1|2|3",
		"/v1/items?spaced=1%202%203",
		"/v1/items?spaced=1+2+3",
	} {
		if v := doGet(t, f, target); v.Deny {
			t.Errorf("%s: denied %+v", target, v)
		}
	}
	// The items are still validated, in each spelling.
	for _, tc := range []struct{ target, where string }{
		{"/v1/items?ids=1&ids=0", "query.ids"},
		{"/v1/items?ids=1,0", "query.ids"},
		{"/v1/items?ids=1,2,3,4,5", "query.ids"},
		{"/v1/items?piped=1|0", "query.piped"},
		{"/v1/items?piped=1|abc", "query.piped"},
		{"/v1/items?spaced=1%200", "query.spaced"},
	} {
		v := doGet(t, f, tc.target)
		if !v.Deny || !strings.HasPrefix(v.Detail, "schema:"+tc.where) {
			t.Errorf("%s: got %+v, want schema:%s", tc.target, v, tc.where)
		}
	}
	// A pipe-separated list sent to a comma-separated parameter is one
	// item that is not a number, which is a type error and not a pass.
	if v := doGet(t, f, "/v1/items?ids=1|2"); !v.Deny {
		t.Error("a pipe-separated value satisfied a form array")
	}
}

// A header array is simple style: comma-separated, and the enum still
// applies to each element.
func TestAHeaderArrayIsCommaSeparated(t *testing.T) {
	f := styleFilter(t, nil)
	if v := doGet(t, f, "/v1/items", "X-Tags", "a,b"); v.Deny {
		t.Fatalf("a valid header array was denied: %+v", v)
	}
	if v := doGet(t, f, "/v1/items", "X-Tags", "a", "X-Tags", "c"); v.Deny {
		t.Fatalf("a repeated header was denied: %+v", v)
	}
	v := doGet(t, f, "/v1/items", "X-Tags", "a,zzz")
	if !v.Deny || !strings.HasPrefix(v.Detail, "schema:header.X-Tags") {
		t.Fatalf("got %+v, want schema:header.X-Tags", v)
	}
}

// A path array is comma-separated too, and its elements are checked.
func TestAPathArrayIsCommaSeparated(t *testing.T) {
	f := styleFilter(t, nil)
	if v := doGet(t, f, "/v1/items/1,2,3"); v.Deny {
		t.Fatalf("a valid path array was denied: %+v", v)
	}
	v := doGet(t, f, "/v1/items/1,0")
	if !v.Deny || !strings.HasPrefix(v.Detail, "schema:path.ids") {
		t.Fatalf("got %+v, want schema:path.ids", v)
	}
}

// An object parameter arrives as bracketed names, which is how every
// generated client spells a filter. Looking it up by its own name finds
// nothing and calls a correct request incomplete.
func TestADeepObjectParameterIsAssembled(t *testing.T) {
	f := styleFilter(t, nil)
	if v := doGet(t, f, "/v1/items?filter%5Bfrom%5D=2026-01-01&filter%5Bsize%5D=10"); v.Deny {
		t.Fatalf("a valid deepObject was denied: %+v", v)
	}
	// Its properties are validated, its required property is required,
	// and an undeclared property is refused because the schema says
	// additionalProperties: false.
	for _, tc := range []struct{ target, want string }{
		{"/v1/items?filter%5Bsize%5D=10", "schema:query.filter"},        // from missing
		{"/v1/items?filter%5Bfrom%5D=nope", "schema:query.filter.from"}, // not a date
		{"/v1/items?filter%5Bfrom%5D=2026-01-01&filter%5Bsize%5D=99", "schema:query.filter.size"},
		{"/v1/items?filter%5Bfrom%5D=2026-01-01&filter%5Bnope%5D=1", "schema:query.filter"},
	} {
		v := doGet(t, f, tc.target)
		if !v.Deny || !strings.HasPrefix(v.Detail, tc.want) {
			t.Errorf("%s: got %+v, want %s", tc.target, v, tc.want)
		}
	}
}

// strict_query refuses names the operation does not declare, and a
// deepObject's values arrive under names that are not its name. Without
// the prefixes it would refuse the very shape the description asked for.
func TestStrictQueryAcceptsADeepObjectsOwnNames(t *testing.T) {
	f := styleFilter(t, filter.Options{"strict_query": true})
	if v := doGet(t, f, "/v1/items?filter%5Bfrom%5D=2026-01-01"); v.Deny {
		t.Fatalf("strict_query refused a declared deepObject: %+v", v)
	}
	// Something that is not the parameter is still refused, and so is a
	// bracketed name whose prefix is not a declared parameter.
	for _, target := range []string{"/v1/items?debug=1", "/v1/items?other%5Bx%5D=1"} {
		if v := doGet(t, f, target); !v.Deny || !strings.HasPrefix(v.Detail, "schema:query.") {
			t.Errorf("%s: got %+v, want a strict_query refusal", target, v)
		}
	}
}

// The style defaults are the ones OpenAPI gives by position, because a
// description that names no style is the common case and must behave as
// the specification says.
func TestStyleDefaultsFollowThePosition(t *testing.T) {
	for _, tc := range []struct {
		in      string
		style   string
		explode bool
	}{
		{"query", styleForm, true},
		{"cookie", styleForm, true},
		{"path", styleSimple, false},
		{"header", styleSimple, false},
	} {
		style, explode := styleOf(map[string]any{}, tc.in)
		if style != tc.style || explode != tc.explode {
			t.Errorf("%s: %s/%v, want %s/%v", tc.in, style, explode, tc.style, tc.explode)
		}
	}
	// An explicit explode wins over the default in both directions.
	if _, explode := styleOf(map[string]any{"explode": false}, "query"); explode {
		t.Error("explode: false was ignored in a query parameter")
	}
	if _, explode := styleOf(map[string]any{"explode": true}, "header"); !explode {
		t.Error("explode: true was ignored in a header parameter")
	}
}

// The keys of a deepObject come from the query string, so a client writes
// as many as the URL holds. The map built from them is bounded.
func TestADeepObjectIsBounded(t *testing.T) {
	q := url.Values{"filter[from]": {"2026-01-01"}}
	for i := 0; i < maxDeepObjects+50; i++ {
		q.Set("filter[k"+itoa(i)+"]", "x")
	}
	p := parameter{name: "filter", in: "query", style: styleDeep,
		schema: map[string]any{"type": "object", "properties": map[string]any{}}}
	obj, ok := deepObject(p, q, nil)
	if !ok {
		t.Fatal("nothing assembled")
	}
	if len(obj) > maxDeepObjects {
		t.Fatalf("assembled %d properties, want at most %d", len(obj), maxDeepObjects)
	}
}
