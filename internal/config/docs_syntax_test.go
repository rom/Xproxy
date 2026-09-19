package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// docsYAMLFiles are the documents whose fenced yaml blocks are checked.
var docsYAMLFiles = []string{"../../README.md", "../../docs/USAGE.md", "../../docs/CONFIG.md", "../../docs/EXTENDING.md",
	"../../docs/SETUP.md", "../../docs/SETUP_MACOS.md", "../../docs/HARDENING.md"}

type yamlBlock struct {
	file string
	line int
	text string
}

// yamlBlocks extracts ```yaml fences with their starting line.
func yamlBlocks(t *testing.T, path string) []yamlBlock {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []yamlBlock
	var cur *yamlBlock
	var buf bytes.Buffer
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		switch {
		case cur == nil && strings.HasPrefix(line, "```yaml"):
			cur = &yamlBlock{file: filepath.Base(path), line: n + 1}
			buf.Reset()
		case cur != nil && strings.HasPrefix(line, "```"):
			cur.text = buf.String()
			out = append(out, *cur)
			cur = nil
		case cur != nil:
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	return out
}

// topLevelKeys returns the yaml keys of Config.
func topLevelKeys() map[string]bool {
	keys := map[string]bool{}
	t := reflect.TypeOf(Config{})
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if tag != "" && tag != "-" {
			keys[tag] = true
		}
	}
	return keys
}

// TestDocsYAMLSyntax decodes every yaml block of the documentation
// strictly against the configuration schema: a block whose top level
// keys are all configuration sections must have no unknown key at any
// depth, and a block that is a complete document (has version) must pass
// validation without file checks. Blocks that are not configuration
// (fragments of other files, Kubernetes manifests) are skipped and
// counted.
func TestDocsYAMLSyntax(t *testing.T) {
	known := topLevelKeys()
	checked, complete, skipped := 0, 0, 0
	for _, path := range docsYAMLFiles {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, b := range yamlBlocks(t, path) {
			where := fmt.Sprintf("%s:%d", b.file, b.line)
			// "[...]" is the documentation's elision of a list shown
			// elsewhere; an empty list keeps the block decodable.
			text := strings.ReplaceAll(b.text, "[...]", "[]")
			var doc any
			if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
				t.Errorf("%s: not valid YAML: %v", where, err)
				continue
			}
			top, isMap := doc.(map[string]any)
			if !isMap {
				skipped++ // a list fragment or a scalar example
				continue
			}
			if len(top) == 0 {
				skipped++
				continue
			}
			isConfig := true
			for k := range top {
				if !known[k] {
					isConfig = false
				}
			}
			if !isConfig {
				skipped++
				continue
			}
			dec := yaml.NewDecoder(strings.NewReader(text))
			dec.KnownFields(true)
			var c Config
			if err := dec.Decode(&c); err != nil {
				t.Errorf("%s: does not match the schema: %v\n%s", where, err, b.text)
				continue
			}
			checked++
			if _, ok := top["version"]; ok {
				if _, err := parseNoFiles([]byte(text)); err != nil {
					t.Errorf("%s: complete document fails validation: %v\n%s", where, err, b.text)
					continue
				}
				complete++
			}
		}
	}
	t.Logf("%d blocks checked against the schema, %d complete documents validated, %d non configuration blocks skipped", checked, complete, skipped)
	if checked < 40 {
		t.Fatalf("only %d configuration blocks found; extraction broken?", checked)
	}
}
