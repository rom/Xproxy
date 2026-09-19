package schema

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config/schema/schemagen"
	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite xproxy.schema.json from the configuration types")

// TestSchemaCurrent fails when the committed schema no longer matches the
// configuration types; regenerate with go generate ./internal/config/schema
// or go test ./internal/config/schema -update.
func TestSchemaCurrent(t *testing.T) {
	want, err := schemagen.Generate("../config.go")
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile("xproxy.schema.json", want, 0o644); err != nil { //nolint:gosec // test data
			t.Fatal(err)
		}
	}
	if !bytes.Equal(want, JSON) {
		t.Fatal("xproxy.schema.json is stale: run go generate ./internal/config/schema")
	}
}

func load(t *testing.T) map[string]any {
	t.Helper()
	var s map[string]any
	if err := json.Unmarshal(JSON, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSchemaRefs checks that every $ref resolves and that objects forbid
// unknown keys, as the loader does.
func TestSchemaRefs(t *testing.T) {
	s := load(t)
	defs := s["$defs"].(map[string]any)
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch n := node.(type) {
		case map[string]any:
			if ref, ok := n["$ref"].(string); ok {
				name := strings.TrimPrefix(ref, "#/$defs/")
				if _, ok := defs[name]; !ok || !strings.HasPrefix(ref, "#/$defs/") {
					t.Errorf("%s: unresolved %s", path, ref)
				}
			}
			if n["type"] == "object" {
				if _, props := n["properties"]; props && n["additionalProperties"] != false {
					t.Errorf("%s: object allows unknown keys", path)
				}
			}
			for k, v := range n {
				walk(v, path+"/"+k)
			}
		case []any:
			for i, v := range n {
				walk(v, path+"/"+string(rune('0'+i)))
			}
		}
	}
	walk(s, "")
	if s["required"].([]any)[0] != "version" {
		t.Fatalf("root required: %v", s["required"])
	}
}

// TestSchemaCoversDump walks the golden dump of the example configuration
// and checks every key against the schema, which catches a field whose
// yaml tag and schema disagree.
func TestSchemaCoversDump(t *testing.T) {
	s := load(t)
	defs := s["$defs"].(map[string]any)
	raw, err := os.ReadFile("../testdata/example.dump.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	resolve := func(node map[string]any) map[string]any {
		for {
			if all, ok := node["allOf"].([]any); ok && len(all) == 1 {
				node = all[0].(map[string]any)
				continue
			}
			if ref, ok := node["$ref"].(string); ok {
				node = defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
				continue
			}
			return node
		}
	}
	var check func(schema map[string]any, value any, path string)
	check = func(schema map[string]any, value any, path string) {
		schema = resolve(schema)
		switch v := value.(type) {
		case map[string]any:
			props, ok := schema["properties"].(map[string]any)
			if !ok {
				if _, free := schema["additionalProperties"].(map[string]any); free || schema["type"] == "object" {
					return
				}
				t.Errorf("%s: mapping where the schema has %v", path, schema["type"])
				return
			}
			for k, val := range v {
				p, ok := props[k].(map[string]any)
				if !ok {
					t.Errorf("%s.%s: not in the schema", path, k)
					continue
				}
				if val != nil {
					check(p, val, path+"."+k)
				}
			}
		case []any:
			items, ok := schema["items"].(map[string]any)
			if !ok {
				t.Errorf("%s: sequence where the schema has %v", path, schema["type"])
				return
			}
			for i, val := range v {
				check(items, val, path+"["+string(rune('0'+i%10))+"]")
			}
		case string:
			if schema["type"] != "string" && schema["type"] != nil {
				t.Errorf("%s: string %q where the schema has %v", path, v, schema["type"])
			}
			if e, ok := schema["enum"].([]any); ok {
				found := false
				for _, x := range e {
					found = found || x == v
				}
				if !found {
					t.Errorf("%s: %q not in %v", path, v, e)
				}
			}
		case bool:
			if schema["type"] != "boolean" {
				t.Errorf("%s: bool where the schema has %v", path, schema["type"])
			}
		case int, int64, float64:
			if schema["type"] != "integer" && schema["type"] != "number" {
				t.Errorf("%s: number where the schema has %v", path, schema["type"])
			}
		}
	}
	check(s, doc, "$")
}
