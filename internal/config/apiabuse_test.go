package config

import (
	"strings"
	"testing"
)

func abuseConfig(section string) string {
	return `
version: 1
server:
  listeners: [{name: main, address: ":8080"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.5:8080"}]}
routes:
  - {name: app, upstream: app}
` + section
}

// The api_abuse filter refuses with the reason "api_abuse", and
// docs/CONFIG.md says a ban trigger can name it. A reason the proxy
// raises but the trigger table does not hold is a configuration that
// looks right and does not load, so the claim is a test.
func TestAPIAbuseIsABanReason(t *testing.T) {
	const section = `
filters:
  - name: walk
    kind: api_abuse
    options: {action: block}
bans:
  triggers:
    - {name: walkers, reasons: [api_abuse], threshold: 3, window: 1m, duration: 10m}
`
	cfg, err := ParseWith([]byte(abuseConfig(section)), false)
	if err != nil {
		t.Fatalf("a trigger naming api_abuse does not load: %v", err)
	}
	if got := cfg.Bans.Triggers[0].Reasons[0]; got != "api_abuse" {
		t.Errorf("reason %q, want api_abuse", got)
	}
	// The same reason serves a capture rule, which validates against
	// both tables.
	if !denyReasons["api_abuse"] {
		t.Error("api_abuse is not in denyReasons")
	}
}

// A misspelling is still refused: the table is a list of reasons, not
// an invitation to invent one.
func TestUnknownAbuseReasonIsRefused(t *testing.T) {
	const section = `
bans:
  triggers:
    - {name: walkers, reasons: [api_abuses], threshold: 3, window: 1m, duration: 10m}
`
	_, err := ParseWith([]byte(abuseConfig(section)), false)
	if err == nil || !strings.Contains(err.Error(), "unknown reason") {
		t.Errorf("error %v, want one about an unknown reason", err)
	}
}
