package config

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// keyRE matches the key as a whole word (keys are identifiers; the doc
// writes them in code spans, headings and inline mappings).
func keyRE(tag string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(tag) + `([^A-Za-z0-9_]|$)`)
}

// TestConfigReferenceComplete walks the configuration schema by reflection
// and checks that every YAML key is mentioned in docs/CONFIG.md, so the
// reference cannot silently fall behind the code (release checklist item
// "CONFIG.md matches the schema").
func TestConfigReferenceComplete(t *testing.T) {
	doc, err := os.ReadFile("../../docs/CONFIG.md")
	if err != nil {
		t.Skip("docs not available:", err)
	}
	text := string(doc)
	var missing []string
	seen := map[reflect.Type]bool{}
	var walk func(rt reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		for rt.Kind() == reflect.Ptr || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			if !keyRE(tag).MatchString(text) {
				missing = append(missing, path+tag)
			}
			walk(f.Type, path+tag+".")
		}
	}
	walk(reflect.TypeOf(Config{}), "")
	if len(missing) > 0 {
		t.Fatalf("keys without a mention in docs/CONFIG.md:\n  %s", strings.Join(missing, "\n  "))
	}
}
