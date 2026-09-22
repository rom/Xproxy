package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// YARARuleSet is the rule set the stream and body scanning tests share:
// one string a rule names and one binary header, which is enough to
// cover a match in either direction and in either form.
const YARARuleSet = `
rule secret_marker : exfiltration {
  meta:
    description = "a marker that must not leave"
  strings:
    $a = "TOP-SECRET-MARKER"
  condition:
    $a
}

rule pe_header : malware {
  strings:
    $mz = { 4D 5A 90 00 }
  condition:
    $mz
}
`

// YARARules writes YARARuleSet to a file and returns its path, for a
// configuration that names one.
func YARARules(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(p, []byte(YARARuleSet), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
