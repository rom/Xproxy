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

// TestDecoyReferenceComplete keeps the decoy table in docs/CONFIG.md in
// step with the names the validator accepts. A decoy an operator cannot
// find in the reference is a decoy nobody uses, and one in the reference
// that the build does not carry is a configuration that fails to load
// after somebody copied the documentation.
func TestDecoyReferenceComplete(t *testing.T) {
	doc, err := os.ReadFile("../../docs/CONFIG.md")
	if err != nil {
		t.Skip("docs not available:", err)
	}
	text := string(doc)
	for name := range HoneypotDecoys {
		if !strings.Contains(text, "| `"+name+"` |") {
			t.Errorf("decoy %q has no row in the docs/CONFIG.md table", name)
		}
	}
	// Every row in a decoy table names a decoy the build carries. The
	// tables are the ones between the decoy heading and the paragraph
	// that follows them.
	start := strings.Index(text, "The built-in decoys,")
	end := strings.Index(text, "`robots` and `sitemap` are the two to serve honestly")
	if start < 0 || end < start {
		t.Fatal("the decoy section is not where the test expects it")
	}
	row := regexp.MustCompile("(?m)^\\| `([a-z0-9-]+)` \\| ")
	found := 0
	for _, m := range row.FindAllStringSubmatch(text[start:end], -1) {
		if !HoneypotDecoys[m[1]] {
			t.Errorf("the decoy table has a row for %q, which the build does not carry", m[1])
		}
		found++
	}
	if found != len(HoneypotDecoys) {
		t.Errorf("the decoy tables hold %d rows for %d decoys", found, len(HoneypotDecoys))
	}
}

// TestRFCReferenceIsWellFormed keeps docs/RFC.md honest about its own
// shape: every row names an RFC number or a named specification and a
// status the document defines, and every status word it defines is
// used. A table that drifts into free text is a table nobody can check
// a claim against.
func TestRFCReferenceIsWellFormed(t *testing.T) {
	doc, err := os.ReadFile("../../docs/RFC.md")
	if err != nil {
		t.Skip("docs not available:", err)
	}
	text := string(doc)
	statuses := map[string]int{"Full": 0, "Partial": 0, "Refused": 0, "Not applicable": 0}
	row := regexp.MustCompile(`(?m)^\| ([0-9]{3,5}|[0-9]{3,5} / [0-9]{3,5}|` + "`[^`]+`" + `|[A-Za-z][^|]*) \| ([^|]*) \| (Full|Partial|Refused|Not applicable|See above)[^|]* \|`)
	rows := row.FindAllStringSubmatch(text, -1)
	if len(rows) < 80 {
		t.Fatalf("docs/RFC.md has %d status rows; the document is a table of them", len(rows))
	}
	for _, m := range rows {
		if n, ok := statuses[strings.TrimSpace(m[3])]; ok {
			statuses[strings.TrimSpace(m[3])] = n + 1
		}
	}
	for word, n := range statuses {
		if n == 0 {
			t.Errorf("docs/RFC.md defines the status %q and never uses it", word)
		}
	}
	// The document promises a reason for every refusal and for every
	// row it calls inapplicable, so one with an empty note is a promise
	// it did not keep.
	for _, status := range []string{"Refused", "Not applicable"} {
		re := regexp.MustCompile(`(?m)^\|[^|]*\|[^|]*\| ` + status + ` \|([^|]*)\|`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(strings.TrimSpace(m[1])) < 20 {
				t.Errorf("a %s row gives no reason: %q", status, strings.TrimSpace(m[0]))
			}
		}
	}
	// Every heading in the contents list exists as a heading.
	for _, m := range regexp.MustCompile(`(?m)^- \[([^\]]+)\]\(#([a-z0-9-]+)\)`).FindAllStringSubmatch(text, -1) {
		if !strings.Contains(text, "\n## "+m[1]+"\n") {
			t.Errorf("the contents name %q, which is not a heading", m[1])
		}
	}
}

// TestBanReasonReferenceComplete keeps the reason list on the
// bans.triggers[].reasons row in step with the table the validator
// checks against. Three reasons had drifted out of the document by the
// time this test was written -- one the day it was added -- and the
// shape of the mistake is the worst kind: an operator reads the list,
// does not find the refusal they are watching, and concludes the proxy
// cannot ban on it.
func TestBanReasonReferenceComplete(t *testing.T) {
	doc, err := os.ReadFile("../../docs/CONFIG.md")
	if err != nil {
		t.Skip("docs not available:", err)
	}
	var row string
	for _, l := range strings.Split(string(doc), "\n") {
		if strings.Contains(l, "Deny categories that count") {
			row = l
			break
		}
	}
	if row == "" {
		t.Fatal("docs/CONFIG.md no longer lists the deny categories a trigger may name")
	}
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z0-9_]+)`").FindAllStringSubmatch(row, -1) {
		if m[1] != "reasons" {
			listed[m[1]] = true
		}
	}
	for reason := range denyReasons {
		if !listed[reason] {
			t.Errorf("a trigger may name %q, which the reference does not list", reason)
		}
	}
	for reason := range listed {
		if !denyReasons[reason] {
			t.Errorf("the reference lists %q, which no trigger may name", reason)
		}
	}
}
