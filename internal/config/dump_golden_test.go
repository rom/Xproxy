package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestExampleDumpGolden dumps the shipped example configuration with every
// default filled in and compares it with testdata/example.dump.yaml. A
// changed default, a renamed key or a new section shows up as a diff in
// review instead of silently changing what operators get. Regenerate with
// go test ./internal/config -run TestExampleDumpGolden -update.
func TestExampleDumpGolden(t *testing.T) {
	data, err := os.ReadFile("../../deploy/config/xproxy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseNoFiles(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Dump(c)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "example.dump.yaml")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil { //nolint:gosec // test data
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != string(got) {
		diff, _ := unifiedDiff(string(want), string(got), golden, "dump")
		t.Fatalf("dump of the example configuration changed:\n%s\nrun with -update if intended", diff)
	}
	// The dump must load back to the same dump (defaults are stable).
	again, err := parseNoFiles(got)
	if err != nil {
		t.Fatalf("dump does not load: %v", err)
	}
	got2, _ := Dump(again)
	if string(got2) != string(got) {
		diff, _ := unifiedDiff(string(got), string(got2), "dump", "dump of dump")
		t.Fatalf("dump is not a fixed point:\n%s", diff)
	}
}
