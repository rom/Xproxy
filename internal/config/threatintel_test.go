package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func intelConfig(t *testing.T, section string) string {
	t.Helper()
	dir := t.TempDir()
	list := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(list, []byte("10.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return `
version: 1
server:
  listeners: [{name: main, address: ":8080"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.5:8080"}]}
routes:
  - {name: app, upstream: app}
` + strings.ReplaceAll(section, "LIST", list)
}

// What a file cannot say is checked at load: the name, the kind, the
// action, the interval, and whether there is anything to challenge with.
func TestThreatIntelIsCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"threat_intel: {lists: []}", "no lists"},
		{"threat_intel: {refresh: 1s, lists: [{name: a, file: LIST}]}", "at least 10s"},
		{"threat_intel: {lists: [{name: \"not a name!\", file: LIST}]}", "not a valid name"},
		{"threat_intel: {lists: [{name: a, file: LIST}, {name: a, file: LIST}]}", "duplicate"},
		{"threat_intel: {lists: [{name: a, kind: asn, file: LIST}]}", "must be cidr"},
		{"threat_intel: {lists: [{name: a, action: tarpit, file: LIST}]}", "must be log, challenge or block"},
		{"threat_intel: {lists: [{name: a}]}", "file: required"},
		{"threat_intel: {lists: [{name: a, file: relative/list.txt}]}", "absolute path"},
		// A challenge with no challenge section has nothing to challenge
		// with, and saying so at load beats discovering it in the logs.
		{"threat_intel: {lists: [{name: a, action: challenge, file: LIST}]}", "nothing to challenge with"},
	} {
		_, err := ParseWith([]byte(intelConfig(t, tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\nerror %v, want one about %q", tc.section, err, tc.want)
		}
	}
}

func TestThreatIntelThatLoads(t *testing.T) {
	cfg, err := ParseWith([]byte(intelConfig(t, `threat_intel:
  refresh: 15m
  lists:
    - {name: office, file: LIST, action: log}
    - {name: scanners, kind: ja4, file: LIST, action: log}
`)), false)
	if err != nil {
		t.Fatalf("a section that should load: %v", err)
	}
	if n := len(cfg.ThreatIntel.Lists); n != 2 {
		t.Fatalf("%d lists", n)
	}
	if got := cfg.ThreatIntel.RefreshInterval().D().Minutes(); got != 15 {
		t.Errorf("refresh %v, want 15m", got)
	}
	if !cfg.ThreatIntel.Logs() {
		t.Error("log_matches defaults to false")
	}
	// The defaults: five minutes, and a section that says 0 never
	// re-checks.
	def, err := ParseWith([]byte(intelConfig(t, "threat_intel: {lists: [{name: a, file: LIST}], log_matches: false}")), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := def.ThreatIntel.RefreshInterval().D().Minutes(); got != 5 {
		t.Errorf("default refresh %v, want 5m", got)
	}
	// And 0 is a decision, not an unset field: nothing watches the files
	// and a reload is what re-reads them.
	never, err := ParseWith([]byte(intelConfig(t, "threat_intel: {refresh: 0, lists: [{name: a, file: LIST}]}")), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := never.ThreatIntel.RefreshInterval(); got != 0 {
		t.Errorf("refresh: 0 read as %v, want never", got.D())
	}
	if def.ThreatIntel.Logs() {
		t.Error("log_matches: false was not read")
	}
	var none *ThreatIntel
	if none.RefreshInterval() != 0 || !none.Logs() {
		t.Error("a missing section should refresh never and log by default")
	}
	// Blocking on an imported feed is advice, not an error.
	adv, err := ParseWith([]byte(intelConfig(t, "threat_intel: {lists: [{name: a, file: LIST, action: block}]}")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(adv.Advice(), "\n"), "one wrong line") {
		t.Errorf("no advice about blocking on a feed: %v", adv.Advice())
	}
}

// A challenge section with no rate limits used to leave the validator
// thinking there was no challenger, which refused a configuration that
// was fine.
func TestAChallengeSectionCountsWithoutRateLimits(t *testing.T) {
	section := `challenge: {secret_file: /etc/xproxy/challenge.key}
threat_intel: {lists: [{name: a, action: challenge, file: LIST}]}`
	if _, err := ParseWith([]byte(intelConfig(t, section)), false); err != nil {
		t.Fatalf("a challenge list with a challenge section and no rate limits: %v", err)
	}
}
