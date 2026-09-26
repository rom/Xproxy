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
	// A file that is a valid entry of every kind the tests use: an address for
	// cidr, and validation does not read the file for the others (the package
	// does, at load, which is its own tests' business).
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
		// A list with no source at all: the message names every form the
		// source may take, because "file" is no longer the only one.
		{"threat_intel: {lists: [{name: a}]}", "one of file, url, taxii or misp is required"},
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

// A list has exactly one source, and each source's own settings are checked.
// The first case is the one that matters: a list whose source is ambiguous is a
// list nobody can say the contents of.
func TestAFeedSourceIsCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{`threat_intel: {lists: [{name: a, file: LIST, url: "https://f.example/x"}]}`,
			"exactly one says where the entries come from"},
		{`threat_intel: {lists: [{name: a, file: LIST, taxii: {api_root: "https://t.example/api1/", collection: c}}]}`,
			"exactly one says where the entries come from"},
		// Every form a URL can be wrong in.
		{`threat_intel: {lists: [{name: a, url: "ftp://f.example/x"}]}`, "must be an http:// or https:// URL"},
		{`threat_intel: {lists: [{name: a, url: "https:///x"}]}`, "no host"},
		{`threat_intel: {lists: [{name: a, url: "https://f.example/x#frag"}]}`, "a fragment is not sent"},
		// TAXII needs a collection, and its timestamp has one shape.
		{`threat_intel: {lists: [{name: a, taxii: {api_root: "https://t.example/api1/"}}]}`, "collection: required"},
		{`threat_intel: {lists: [{name: a, taxii: {api_root: "https://t.example/api1/", collection: c, added_after: yesterday}}]}`,
			"not an RFC 3339 timestamp"},
		// A TAXII collection answers STIX, and a misp source answers MISP.
		// Saying otherwise is a list that fetches correctly and reads the
		// answer with the wrong parser.
		{`threat_intel: {lists: [{name: a, format: misp, taxii: {api_root: "https://t.example/api1/", collection: c}}]}`,
			"a taxii source answers STIX"},
		{`threat_intel: {lists: [{name: a, format: stix, misp: {url: "https://m.example"}}]}`,
			"a misp source answers MISP JSON"},
		{`threat_intel: {lists: [{name: a, format: csv, url: "https://f.example/x"}]}`, "must be lines, stix, misp or auto"},
		{`threat_intel: {lists: [{name: a, misp: {url: "https://m.example", limit: -1}}]}`, "limit: must be between"},
		// The HTTP half.
		{`threat_intel: {lists: [{name: a, url: "https://f.example/x", http: {timeout: 1ms}}]}`, "timeout: must be between"},
		{`threat_intel: {lists: [{name: a, url: "https://f.example/x", http: {header: X-Feed}}]}`, "header and header_value go together"},
		{`threat_intel: {lists: [{name: a, url: "https://f.example/x", http: {insecure: true}}]}`, "two decisions rather than one"},
		// The one that matters most: a feed nobody authenticated becomes this
		// proxy's block list, so verification may only be skipped on this
		// machine.
		{`threat_intel: {lists: [{name: a, url: "https://feeds.example/x", http: {insecure: true, allow_insecure: true}}]}`,
			"is not a loopback address"},
		// A hash list has nobody to challenge: the match is on a payload, not
		// on a browser asking for a page.
		{`threat_intel: {lists: [{name: a, kind: hash, action: challenge, file: LIST}]}`, "nobody to challenge"},
	} {
		_, err := ParseWith([]byte(intelConfig(t, tc.section)), false)
		if err == nil {
			t.Errorf("%s was accepted", tc.section)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want %q", tc.section, err, tc.want)
		}
	}
}

// The forms that load, and what they default to.
func TestAFeedSourceLoads(t *testing.T) {
	for _, section := range []string{
		`threat_intel: {lists: [{name: a, kind: domain, url: "https://f.example/x"}]}`,
		`threat_intel: {lists: [{name: a, kind: url, taxii: {api_root: "https://t.example/api1/", collection: c}, http: {token: "env:TAXII_TOKEN"}}]}`,
		`threat_intel: {lists: [{name: a, kind: hash, misp: {url: "https://m.example", tags: ["tlp:amber"]}, http: {token: "env:MISP_KEY"}}]}`,
		// Verification may be skipped for a development instance on this
		// machine, with both opt-ins.
		`threat_intel: {lists: [{name: a, kind: domain, url: "https://127.0.0.1:8443/x", http: {insecure: true, allow_insecure: true}}]}`,
	} {
		if _, err := ParseWith([]byte(intelConfig(t, section)), false); err != nil {
			t.Errorf("%s: %v", section, err)
		}
	}
	// A MISP search asks only for published events unless told otherwise,
	// because unpublished ones are somebody's drafts.
	cfg, err := ParseWith([]byte(intelConfig(t,
		`threat_intel: {lists: [{name: a, kind: domain, misp: {url: "https://m.example"}, http: {token: "env:K"}}]}`)), false)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.ThreatIntel.Lists[0]
	if l.MISP.Published == nil || !*l.MISP.Published {
		t.Errorf("published %v, want true by default", l.MISP.Published)
	}
	if l.HTTP.Timeout.D() != DefaultFeedTimeout {
		t.Errorf("timeout %v, want %v", l.HTTP.Timeout.D(), DefaultFeedTimeout)
	}
}

// The advice a feed draws: what loads but should be reconsidered.
func TestAFeedIsAdvisedAbout(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		// http:// means anything on the path chooses what the proxy blocks.
		{`threat_intel: {lists: [{name: a, kind: domain, url: "http://f.example/x"}]}`,
			"chooses what the proxy blocks"},
		// A TAXII server or MISP instance with no credential answers 401 for
		// ever, which leaves a list that never updates and still matches.
		{`threat_intel: {lists: [{name: a, kind: domain, taxii: {api_root: "https://t.example/api1/", collection: c}}]}`,
			"fetched anonymously"},
		// Unpublished MISP events are drafts.
		{`threat_intel: {lists: [{name: a, kind: domain, misp: {url: "https://m.example", published: false}, http: {token: "env:K"}}]}`,
			"somebody's draft"},
		// A domain block takes a whole zone from one wrong line.
		{`threat_intel: {lists: [{name: a, kind: domain, action: block, file: LIST}]}`,
			"one wrong line takes a whole zone"},
		// And an http section on a file source does nothing.
		{`threat_intel: {lists: [{name: a, file: LIST, http: {token: "env:K"}}]}`,
			"the source is a file"},
	} {
		cfg, err := ParseWith([]byte(intelConfig(t, tc.section)), false)
		if err != nil {
			t.Errorf("%s: %v", tc.section, err)
			continue
		}
		if !hasAdvice(cfg, tc.want) {
			t.Errorf("%s: advice %v, want %q", tc.section, cfg.Advice(), tc.want)
		}
	}
}
