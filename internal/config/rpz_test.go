package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rpzConfig(t *testing.T, section string) string {
	t.Helper()
	dir := t.TempDir()
	zone := filepath.Join(dir, "feed.rpz")
	if err := os.WriteFile(zone, []byte("$ORIGIN rpz.local.\n@ SOA ns.rpz.local. h.rpz.local. 1 3600 600 86400 60\nevil.example.rpz.local. CNAME .\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := `
version: 1
server:
  listeners:
    - {name: main, address: ":8080"}
    - name: resolver
      address: ":5353"
      kind: dns
      dns:
        upstreams: ["10.0.0.53:53"]
`
	return base + strings.ReplaceAll(section, "ZONE", zone) + `
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.5:8080"}]}
routes:
  - {name: app, upstream: app}
`
}

// The section that loads, with the default interval.
func TestRPZDefaults(t *testing.T) {
	cfg, err := ParseWith([]byte(rpzConfig(t, `        rpz:
          zones: [{name: feed, file: ZONE}]
`)), false)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Server.Listeners[1].DNS.RPZ
	if r == nil || len(r.Zones) != 1 {
		t.Fatalf("section: %+v", r)
	}
	if got := r.RefreshInterval(); got.Minutes() != 5 {
		t.Errorf("refresh %v, want the default 5m", got)
	}
	// 0 means never, which a pointer is what tells apart from unset.
	never, err := ParseWith([]byte(rpzConfig(t, `        rpz:
          refresh: 0
          zones: [{name: feed, file: ZONE}]
`)), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := never.Server.Listeners[1].DNS.RPZ.RefreshInterval(); got != 0 {
		t.Errorf("refresh %v, want never", got)
	}
}

// What a zone file cannot say is checked at load.
func TestRPZIsCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"        rpz: {zones: []}\n", "no zones"},
		{"        rpz: {refresh: 1s, zones: [{name: feed, file: ZONE}]}\n", "at least 10s"},
		{"        rpz: {zones: [{name: \"not a name!\", file: ZONE}]}\n", "not a valid name"},
		{"        rpz: {zones: [{name: feed, file: ZONE}, {name: feed, file: ZONE}]}\n", "duplicate"},
		{"        rpz: {zones: [{name: feed}]}\n", "file: required"},
		{"        rpz: {zones: [{name: feed, file: relative/feed.rpz}]}\n", "absolute path"},
		{"        rpz: {zones: [{name: feed, file: ZONE, action: sinkhole}]}\n", "must be zone, nxdomain"},
	} {
		_, err := ParseWith([]byte(rpzConfig(t, tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\nerror %v, want one about %q", tc.section, err, tc.want)
		}
	}
}

// The advice: two configurations that load and are worth saying out loud.
func TestRPZAdvice(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"        rpz: {zones: [{name: feed, file: ZONE, action: passthru}]}\n", "blocks nothing"},
		{"        rpz: {zones: [{name: feed, file: ZONE, ignore_unsupported: true}]}\n", "are skipped"},
	} {
		cfg, err := ParseWith([]byte(rpzConfig(t, tc.section)), false)
		if err != nil {
			t.Fatalf("%s: %v", tc.section, err)
		}
		if !strings.Contains(strings.Join(cfg.Advice(), "\n"), tc.want) {
			t.Errorf("%s\nadvice %v, want one about %q", tc.section, cfg.Advice(), tc.want)
		}
	}
}

// A trigger can name the reason a policy zone raises, so a client
// walking a feed's names is banned at the edge.
func TestDNSRPZIsABanReason(t *testing.T) {
	if !denyReasons["dns_rpz"] {
		t.Error("dns_rpz is not a reason a trigger can name")
	}
}
