package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIncludes appends fragments in lexical order, refuses anything but
// the list sections, catches duplicates across files, and reports a
// glob that matches nothing.
func TestIncludes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("20-b.yaml", "routes:\n  - {name: b, hosts: [b.test], upstream: shared}\nupstreams:\n  - {name: shared, endpoints: [{address: 127.0.0.1:9002}]}\n")
	write("10-a.yaml", "routes:\n  - {name: a, hosts: [a.test], upstream: app}\nrate_limits:\n  - {name: api, rate: 10, burst: 20}\n")
	write("30-empty.yaml", "\n")
	write("notes.txt", "not yaml")
	main := `
version: 1
includes: ["` + dir + `/*.yaml"]
server:
  listeners:
    - {name: main, address: ":8080"}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: all
    upstream: app
`
	cfg, err := Parse([]byte(main))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 3 || cfg.Routes[1].Name != "a" || cfg.Routes[2].Name != "b" || len(cfg.Upstreams) != 2 || len(cfg.RateLimits) != 1 {
		t.Fatalf("merged: routes %v upstreams %d limits %d", cfg.Routes, len(cfg.Upstreams), len(cfg.RateLimits))
	}
	if len(cfg.IncludedFiles) != 2 || !strings.HasSuffix(cfg.IncludedFiles[0], "10-a.yaml") {
		t.Fatalf("included files: %v", cfg.IncludedFiles)
	}
	// Defaults apply to fragments too.
	if cfg.Routes[1].Paths[0] != "/" || cfg.Upstreams[1].Balancer != "round_robin" {
		t.Fatal("defaults not applied to fragments")
	}
	cases := []struct{ name, body, want string }{
		{"scalar section", "server:\n  listeners: []\n", "field server not found"},
		{"duplicate route", "routes:\n  - {name: all, upstream: app}\n", "duplicate"},
		{"unknown upstream", "routes:\n  - {name: x, upstream: nope}\n", "unknown upstream"},
		{"two documents", "routes: []\n---\nroutes: []\n", "more than one YAML document"},
	}
	for _, tc := range cases {
		p := write("40-bad.yaml", tc.body)
		_, err := Parse([]byte(main))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v want %q", tc.name, err, tc.want)
		}
		_ = os.Remove(p)
	}
	if _, err := Parse([]byte(strings.Replace(main, dir+"/*.yaml", dir+"/none/*.yaml", 1))); err == nil || !strings.Contains(err.Error(), "matches no file") {
		t.Fatalf("empty glob: %v", err)
	}
	if _, err := ParseWith([]byte(strings.Replace(main, dir+"/*.yaml", dir+"/none/*.yaml", 1)), false); err != nil {
		t.Fatalf("empty glob without file checks: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(main, dir+"/*.yaml", "conf.d/*.yaml", 1))); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative glob: %v", err)
	}
	ww := write("50-ww.yaml", "routes: []\n")
	_ = os.Chmod(ww, 0o666)
	if _, err := Parse([]byte(main)); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world writable fragment: %v", err)
	}
}
