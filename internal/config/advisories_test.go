package config

import (
	"strings"
	"testing"
)

// The advisory section, checked at load.
//
// Everything here is checked before the first document is read, for the reason
// the matching itself gives: a source that cannot be read is a set that
// silently matches nothing, and a proxy reporting no advisories against an
// estate is the one wrong answer this feature must not give.
func TestTheAdvisorySectionIsCheckedAtLoad(t *testing.T) {
	for _, c := range []struct {
		what string
		yaml string
		want string
	}{
		{
			what: "no sources",
			yaml: "  advisories: {enabled: true}\n",
			want: "sources: required",
		},
		{
			what: "a source with neither a file nor a directory",
			yaml: "  advisories:\n    enabled: true\n    sources: [{name: a}]\n",
			want: "one of file or directory",
		},
		{
			what: "a source with both",
			yaml: "  advisories:\n    enabled: true\n    sources: [{name: a, file: /a.json, directory: /d}]\n",
			want: "file and directory are alternatives",
		},
		{
			what: "a source with no name",
			yaml: "  advisories:\n    enabled: true\n    sources: [{directory: /d}]\n",
			want: "name: required",
		},
		{
			what: "two sources with one name",
			yaml: "  advisories:\n    enabled: true\n    sources: [{name: a, directory: /d}, {name: a, directory: /e}]\n",
			want: "duplicate name",
		},
		{
			// A relative path is refused for the same reason every other path
			// in this file is: which directory the daemon started in is not
			// something an advisory set should depend on.
			what: "a relative directory",
			yaml: "  advisories:\n    enabled: true\n    sources: [{name: a, directory: csaf}]\n",
			want: "must be an absolute path",
		},
		{
			what: "a refresh nobody could want",
			yaml: "  advisories:\n    enabled: true\n    sources: [{name: a, directory: /d}]\n    refresh: 5s\n",
			want: "refresh: must be between",
		},
		{
			what: "a severity that is not one",
			yaml: "  advisories:\n    enabled: true\n    sources: [{name: a, directory: /d}]\n    min_severity: quite-bad\n",
			want: "min_severity: must be",
		},
	} {
		_, err := Parse([]byte("version: 1\nasset_inventory:\n  enabled: true\n  state_file: /var/lib/x/a.json\n" + c.yaml))
		if err == nil {
			t.Errorf("%s was accepted", c.what)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.what, err, c.want)
		}
	}
}

// The matching needs the inventory it matches, and saying so at load is better
// than an advisory set nothing is ever compared against.
func TestAdvisoriesWithoutAnInventory(t *testing.T) {
	_, err := Parse([]byte("version: 1\nasset_inventory:\n  advisories:\n    enabled: true\n" +
		"    sources: [{name: a, directory: /d}]\n"))
	if err == nil || !strings.Contains(err.Error(), "asset_inventory.enabled must be true") {
		t.Fatalf("%v", err)
	}
}

// And what a good section parses to, including the defaults a reader has to be
// able to predict.
func TestTheAdvisoryDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: r, upstream: u}
asset_inventory:
  enabled: true
  state_file: /var/lib/xproxy/assets.json
  advisories:
    enabled: true
    sources:
      - name: siemens
        directory: /var/lib/xproxy/csaf/siemens
      - name: one-off
        file: /var/lib/xproxy/csaf/ssa-482757.json
`))
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.AssetInventory.Advisories
	if a == nil || !a.Enabled || len(a.Sources) != 2 {
		t.Fatalf("advisories %+v", a)
	}
	if got := a.RefreshInterval().D().String(); got != "1h0m0s" {
		t.Errorf("refresh default %s", got)
	}
	if !a.AlertsOnAffected() {
		t.Error("a device an advisory names should raise an event by default")
	}
	if a.AlertsOnNotAssessed() {
		t.Error("not-assessed should be off by default: on a first run it is most of the estate")
	}
	// A section that is absent behaves like one that is off, so every reader
	// of it works on a configuration that has none.
	var none *Advisories
	if none.RefreshInterval() != 0 || none.AlertsOnNotAssessed() {
		t.Error("the zero section does not read as off")
	}
	if !none.AlertsOnAffected() {
		t.Error("the default for a nil section should be the same as for an empty one")
	}
}

// A warning rather than an error: matching against advisories with no state
// file works, and every restart re-assesses an estate it has forgotten, so the
// findings arrive again as if they were new.
func TestAdvisoriesWithNoStateFileWarn(t *testing.T) {
	cfg, err := Parse([]byte("version: 1\n" + `server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: r, upstream: u}
` + "asset_inventory:\n  enabled: true\n" +
		"  advisories:\n    enabled: true\n    sources: [{name: a, directory: /d}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "re-assesses an estate it has forgotten") {
		t.Errorf("no warning about the missing state file: %v", cfg.Advice())
	}
}
