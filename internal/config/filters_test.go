package config

import (
	"strings"
	"testing"

	_ "github.com/rom/xproxy/internal/filters" // registers the built-in kinds
)

const filtersYAML = `
filters:
  - name: scanners
    kind: header_guard
    options:
      deny: [{header: User-Agent, pattern: "(?i)sqlmap"}]
`

func withFilters(routeFilters string) string {
	return strings.Replace(minimal, "    upstream: app", "    upstream: app\n    filters: ["+routeFilters+"]", 1) + filtersYAML
}

func TestFiltersConfig(t *testing.T) {
	cfg, err := Parse([]byte(withFilters("scanners")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Filters[0].Stage != StageAfterAuth {
		t.Fatalf("default stage %q", cfg.Filters[0].Stage)
	}
	cases := map[string]string{
		"unknown kind":     strings.Replace(withFilters("scanners"), "kind: header_guard", "kind: nope", 1),
		"bad options":      strings.Replace(withFilters("scanners"), `pattern: "(?i)sqlmap"`, `pattern: "("`, 1),
		"unknown option":   strings.Replace(withFilters("scanners"), "    options:\n", "    options:\n      bogus: 1\n", 1),
		"bad stage":        strings.Replace(withFilters("scanners"), "kind: header_guard", "kind: header_guard\n    stage: sometime", 1),
		"unknown on route": withFilters("missing"),
		"bad name":         strings.Replace(withFilters("scanners"), "name: scanners", "name: bad name", 1),
		"duplicate name":   withFilters("scanners") + "  - name: scanners\n    kind: header_guard\n    options: {deny: [{header: A, pattern: b}]}\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "unknown kind" && !strings.Contains(err.Error(), "registered: basic_auth, header_guard") {
			t.Errorf("%s: error does not list kinds: %v", name, err)
		}
	}
}
