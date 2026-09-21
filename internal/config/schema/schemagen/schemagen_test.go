package schemagen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The schema is what an editor and a CI check validate a configuration
// against, so a type the generator cannot express must stop the
// generation rather than produce a schema that silently allows anything.

func generateSource(t *testing.T, src string) ([]byte, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return Generate(path)
}

func TestGenerateRefusesWhatItCannotExpress(t *testing.T) {
	cases := map[string]string{
		"a file that does not parse":    "package config\ntype Config struct {",
		"no Config type":                "package config\ntype Other struct{}\n",
		"a field with no yaml tag":      "package config\ntype Config struct {\n\tA string\n}\n",
		"an empty yaml key":             "package config\ntype Config struct {\n\tA string `yaml:\",omitempty\"`\n}\n",
		"a map keyed by something else": "package config\ntype Config struct {\n\tA map[int]string `yaml:\"a\"`\n}\n",
		"an external type":              "package config\nimport \"time\"\ntype Config struct {\n\tA time.Time `yaml:\"a\"`\n}\n",
		"a type nobody defined":         "package config\ntype Config struct {\n\tA Missing `yaml:\"a\"`\n}\n",
		"a channel":                     "package config\ntype Config struct {\n\tA chan int `yaml:\"a\"`\n}\n",
		"a function":                    "package config\ntype Config struct {\n\tA func() `yaml:\"a\"`\n}\n",
		"a slice of something unknown":  "package config\ntype Config struct {\n\tA []Missing `yaml:\"a\"`\n}\n",
		"a nested field that fails":     "package config\ntype Config struct {\n\tA Inner `yaml:\"a\"`\n}\ntype Inner struct {\n\tB chan int `yaml:\"b\"`\n}\n",
	}
	for name, src := range cases {
		if _, err := generateSource(t, src); err == nil {
			t.Errorf("%s produced a schema", name)
		}
	}
	// A file that is simply missing is an error, not an empty schema.
	if _, err := Generate(filepath.Join(t.TempDir(), "absent.go")); err == nil {
		t.Error("a missing source produced a schema")
	}
}

func TestGenerateExpressesEveryShapeItSupports(t *testing.T) {
	const src = `package config

// Config is the document.
type Config struct {
	// Name of the thing.
	Name string ` + "`yaml:\"name\"`" + `
	On   bool   ` + "`yaml:\"on\"`" + `
	N    int    ` + "`yaml:\"n\"`" + `
	U    uint16 ` + "`yaml:\"u\"`" + `
	F    float64 ` + "`yaml:\"f\"`" + `
	D    Duration ` + "`yaml:\"d\"`" + `
	Any  any ` + "`yaml:\"any\"`" + `
	Iface interface{ Do() } ` + "`yaml:\"iface\"`" + `
	List []string ` + "`yaml:\"list\"`" + `
	Free map[string]any ` + "`yaml:\"free\"`" + `
	Typed map[string]string ` + "`yaml:\"typed\"`" + `
	Ptr  *Inner ` + "`yaml:\"ptr\"`" + `
	Self *Config ` + "`yaml:\"self\"`" + `
	Mode Mode ` + "`yaml:\"mode\"`" + `
	Skip string ` + "`yaml:\"-\"`" + `
}

// Inner is nested.
type Inner struct {
	B string ` + "`yaml:\"b\"`" + `
}

// Mode is a named string type.
type Mode string

const (
	ModeA Mode = "a"
	ModeB Mode = "b"
)

// Duration is the configuration's own duration.
type Duration int64
`
	out, err := generateSource(t, src)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("the schema is not JSON: %v", err)
	}
	props := s["properties"].(map[string]any)
	for key, wantType := range map[string]string{
		"name": "string", "on": "boolean", "n": "integer", "u": "integer",
		"f": "number", "d": "string", "free": "object", "typed": "object", "list": "array",
	} {
		p, ok := props[key].(map[string]any)
		if !ok {
			t.Errorf("%s is missing", key)
			continue
		}
		if p["type"] != wantType {
			t.Errorf("%s = %v want %v", key, p["type"], wantType)
		}
	}
	// A key tagged "-" is not part of the document at all.
	if _, ok := props["skip"]; ok {
		t.Error("a field tagged - reached the schema")
	}
	// Free-form objects take anything; typed ones constrain their values.
	if free := props["free"].(map[string]any); free["additionalProperties"] != nil {
		t.Errorf("a map[string]any was constrained: %v", free)
	}
	if typed := props["typed"].(map[string]any); typed["additionalProperties"] == nil {
		t.Error("a map[string]string was left unconstrained")
	}
	// A named string type becomes an enumeration of its constants, which
	// is what makes an editor refuse a misspelt mode.
	mode := props["mode"].(map[string]any)
	enum, ok := mode["enum"].([]any)
	if !ok || len(enum) != 2 {
		t.Errorf("mode = %v", mode)
	}
	// A duration is a string with the pattern, so "10 seconds" is
	// refused where "10s" is not.
	d := props["d"].(map[string]any)
	if d["pattern"] == nil || !strings.Contains(d["description"].(string), "duration") {
		t.Errorf("duration = %v", d)
	}
	// A pointer to a struct is a reference carrying the field's own
	// description through allOf, so the reference stays valid.
	ptr := props["ptr"].(map[string]any)
	if _, isRef := ptr["$ref"]; !isRef {
		if _, hasAllOf := ptr["allOf"]; !hasAllOf {
			t.Errorf("ptr = %v", ptr)
		}
	}
	// A type that refers to itself is rendered once rather than for ever.
	defs := s["$defs"].(map[string]any)
	if _, ok := defs["Inner"]; !ok {
		t.Errorf("Inner is not defined: %v", defs)
	}
	if _, ok := defs["Config"]; !ok {
		t.Errorf("the self reference did not define Config: %v", defs)
	}
	// Unknown keys are errors, as the loader treats them.
	if s["additionalProperties"] != false {
		t.Errorf("additionalProperties = %v", s["additionalProperties"])
	}
	// The header comes first so the file reads as a schema.
	if !strings.HasPrefix(string(out), "{\n  \"$schema\":") {
		t.Errorf("the schema starts with %.40q", string(out))
	}
	// The type's own doc comment becomes the description.
	if desc, _ := s["description"].(string); !strings.Contains(desc, "One YAML document") {
		t.Errorf("description = %q", desc)
	}
	inner := defs["Inner"].(map[string]any)
	if d, _ := inner["description"].(string); d != "Inner is nested." {
		t.Errorf("Inner description = %q", d)
	}
	// A doc comment that already ends in a full stop is not given another.
	name := props["name"].(map[string]any)
	if d, _ := name["description"].(string); d != "Name of the thing." {
		t.Errorf("name description = %q", d)
	}
}
