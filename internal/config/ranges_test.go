package config

import (
	"strings"
	"testing"
)

func rangesConfig(route string) string {
	return `
version: 1
server:
  listeners: [{name: main, address: ":8080"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.5:8080"}]}
routes:
  - {name: files, paths: ["/files/"], upstream: app` + route + `}
`
}

// A range policy that says something this proxy cannot act on is a load
// error rather than a section that quietly does nothing.
func TestRangePolicyIsCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct{ route, want string }{
		{", ranges: {action: drop}", "must be ignore or refuse"},
		{", ranges: {max_ranges: -1}", "between 0"},
		{", ranges: {max_ranges: 2000}", "between 0"},
	} {
		_, err := ParseWith([]byte(rangesConfig(tc.route)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one about %q", tc.route, err, tc.want)
		}
	}
	// The section an operator would write loads, and so does one that
	// says nothing at all.
	for _, route := range []string{
		", ranges: {}",
		", ranges: {max_ranges: 8, action: refuse}",
		", ranges: {max_ranges: 1024, action: ignore, coalesce: true}",
	} {
		if _, err := ParseWith([]byte(rangesConfig(route)), false); err != nil {
			t.Errorf("%s should load: %v", route, err)
		}
	}
	// Turning coalescing off is advice, not an error: the set is then
	// counted as it arrived, so a client that overlaps its ranges is
	// refused for asking twice for the same bytes.
	cfg, err := ParseWith([]byte(rangesConfig(", ranges: {coalesce: false}")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(cfg.Advice(), "\n"), "coalesce") {
		t.Errorf("no advice about coalescing: %v", cfg.Advice())
	}
	if r := cfg.Routes[0].Ranges; r == nil || r.Coalesce == nil || *r.Coalesce {
		t.Errorf("the section was read as %+v", r)
	}
}
