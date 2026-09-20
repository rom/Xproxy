package jsonschema

import (
	"encoding/json"
	"sync"
	"testing"
)

// The validator is built once per route and then shared by every request
// on it. Resolving a $ref used to write the reference cache on the
// request path, so two concurrent bodies through one $ref chain raced on
// a plain map: "concurrent map read and map write" is a fatal error, not
// a panic, so no recover and no request guard can contain it. The whole
// process dies, from two unauthenticated requests.
func TestConcurrentRefsDoNotWriteTheCache(t *testing.T) {
	doc := map[string]any{
		"components": map[string]any{"schemas": map[string]any{
			"Order": map[string]any{
				"type":       "object",
				"properties": map[string]any{"item": map[string]any{"$ref": "#/components/schemas/Item"}},
			},
			"Item": map[string]any{"$ref": "#/components/schemas/Named"},
			"Named": map[string]any{
				"type":       "object",
				"properties": map[string]any{"name": map[string]any{"type": "string"}},
			},
			// A cycle: the build must terminate and the entry must exist.
			"Loop": map[string]any{"$ref": "#/components/schemas/Loop"},
		}},
	}
	v := New(doc)
	// Item, Named and Loop are the three references the document
	// spells; Order is only reached through the node below, which the
	// resolver chases without caching.
	if len(v.cache) != 3 {
		t.Fatalf("New did not pre-resolve every reference: %d entries", len(v.cache))
	}
	node := map[string]any{"$ref": "#/components/schemas/Order"}
	value, err := Decode([]byte(`{"item":{"name":"x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	before := len(v.cache)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				rep := &Report{}
				if !v.Validate(node, value, "body", rep, 0) {
					t.Errorf("valid body rejected: %v", rep.Issues)
					return
				}
			}
		}()
	}
	wg.Wait()
	if len(v.cache) != before {
		t.Fatalf("the cache grew on the request path: %d to %d", before, len(v.cache))
	}
}

// A reference resolves to the schema it names, not to an empty one: the
// old code published a placeholder with no keywords while it resolved,
// so a concurrent request could validate a body against nothing.
func TestRefResolvesToItsTarget(t *testing.T) {
	v := New(map[string]any{"components": map[string]any{"schemas": map[string]any{
		"Count": map[string]any{"type": "integer", "maximum": 10},
	}}})
	node := map[string]any{"$ref": "#/components/schemas/Count"}
	rep := &Report{}
	if v.Validate(node, json.Number("99"), "q", rep, 0) {
		t.Fatal("a value past the referenced maximum was accepted")
	}
	rep = &Report{}
	if !v.Validate(node, json.Number("9"), "q", rep, 0) {
		t.Fatalf("a valid value was rejected: %v", rep.Issues)
	}
	// A reference the document does not spell resolves rather than
	// caching, and a dangling one is the permissive empty schema.
	if got := v.Resolve(map[string]any{"$ref": "#/components/schemas/Missing"}); len(got.Raw) != 0 {
		t.Fatalf("a dangling reference resolved to %v", got.Raw)
	}
}

// strconv.ParseFloat is wider than JSON: a parameter spelled "NaN" used
// to become a json.Number that compared false against every bound, so it
// satisfied a schema that admits 1..50 and reached the origin unchecked.
func TestCoerceTakesOnlyJSONNumbers(t *testing.T) {
	raw := map[string]any{"type": "integer", "minimum": 1, "maximum": 50}
	for _, s := range []string{"NaN", "nan", "Inf", "-Inf", "+Inf", "infinity", "0x1p8", "1_0", "01", ".5", "5.", "1e", "+1"} {
		if got := Coerce(raw, s); got != any(s) {
			t.Fatalf("%q coerced to the number %#v", s, got)
		}
		rep := &Report{}
		if New(nil).Validate(raw, Coerce(raw, s), "q", rep, 0) {
			t.Fatalf("%q passed an integer 1..50 schema", s)
		}
	}
	for _, s := range []string{"0", "7", "-3", "1.5", "1e2", "1E-2", "-0.25"} {
		if _, ok := Coerce(raw, s).(json.Number); !ok {
			t.Fatalf("%q did not coerce to a number", s)
		}
	}
}

// A json.Number built by hand (a filter, a WASM module) must not slip
// past the bounds either.
func TestNonFiniteNumberIsRejected(t *testing.T) {
	raw := map[string]any{"type": "number", "maximum": 10}
	for _, n := range []json.Number{"NaN", "Inf", "-Inf"} {
		rep := &Report{}
		if New(nil).Validate(raw, n, "q", rep, 0) {
			t.Fatalf("%s passed a bounded schema", n)
		}
	}
}
