package config

import (
	"strings"
	"testing"
	"time"
)

func tunnelConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: main
      address: ":8080"
    - name: resolver
      address: ":5353"
      kind: dns
      dns:
        upstreams: ["9.9.9.9:53"]
        tunnel_detection:
` + section + `
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: r
    hosts: [example.test]
    upstream: app
`
}

// TestDNSTunnelDefaults pins the two that decide whether this feature
// helps or cries wolf: signals have to agree, and the detector watches
// rather than blocks until somebody says otherwise.
func TestDNSTunnelDefaults(t *testing.T) {
	cfg, err := ParseWith([]byte(tunnelConfig("          action: log\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	td := cfg.Server.Listeners[1].DNS.TunnelDetection
	if td == nil {
		t.Fatal("no tunnel_detection section")
	}
	if td.MinSignals != 2 {
		t.Fatalf("min_signals defaulted to %d, want 2", td.MinSignals)
	}
	if td.Action != "log" {
		t.Fatalf("action defaulted to %q, want log", td.Action)
	}
	if td.Window.D() != 5*time.Minute || td.MinQueries != 50 || td.MinLabelLength != 12 ||
		td.distinct() != 50 || td.payloadBytes() != 4096 || td.MaxTracked != 65536 ||
		td.Cooldown.D() != 10*time.Minute {
		t.Fatalf("defaults: %+v", td)
	}
	if td.Entropy != 3.6 || td.entropyShare() != 0.5 || td.txtShare() != 0.5 || td.nxShare() != 0.5 {
		t.Fatalf("thresholds: %+v", td)
	}
}

// TestDNSTunnelZeroMeansOff: a signal an operator switched off stays
// off. A plain zero value cannot be told apart from an absent key, so a
// default would quietly switch it back on and the detector would be
// doing something other than what its configuration reads.
func TestDNSTunnelZeroMeansOff(t *testing.T) {
	cfg, err := ParseWith([]byte(tunnelConfig(
		"          min_signals: 1\n          txt_share: 0\n          nxdomain_share: 0\n          payload_bytes: 0\n          distinct_subdomains: 0\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	td := cfg.Server.Listeners[1].DNS.TunnelDetection
	if td.txtShare() != 0 || td.nxShare() != 0 || td.payloadBytes() != 0 || td.distinct() != 0 {
		t.Fatalf("a signal switched off came back on: %+v", td)
	}
	// The one left on still has its default.
	if td.entropyShare() != 0.5 {
		t.Fatalf("entropy_share: %v", td.entropyShare())
	}
}

// TestDNSTunnelWarnings: the two settings that will produce false
// positives or an outage say so at validation rather than at 3am.
func TestDNSTunnelWarnings(t *testing.T) {
	cfg, err := ParseWith([]byte(tunnelConfig("          min_signals: 1\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "min_signals: 1") {
		t.Fatalf("no warning about a single signal: %v", cfg.Advice())
	}
	cfg, err = ParseWith([]byte(tunnelConfig("          action: block\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "action: block") {
		t.Fatalf("no warning about blocking a whole domain: %v", cfg.Advice())
	}
	// And the ordinary configuration is quiet.
	cfg, err = ParseWith([]byte(tunnelConfig("          action: log\n          min_signals: 3\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range cfg.Advice() {
		if strings.Contains(a, "tunnel_detection") {
			t.Fatalf("a sane configuration warned: %q", a)
		}
	}
}

// TestDNSTunnelRefusals lists what does not load. The last is the one
// worth having: a policy that switches signals off and still asks for
// more agreement than it has left can never detect anything, and
// silently never firing is the worst way for a detector to fail.
func TestDNSTunnelRefusals(t *testing.T) {
	cases := []struct {
		name, section, want string
	}{
		{"window", "          window: 2h\n", "window: must be between 10s and 1h"},
		{"min_queries", "          min_queries: 1\n", "min_queries"},
		{"min_signals", "          min_signals: 9\n", "min_signals: must be between 1 and 5"},
		{"entropy", "          entropy: 12\n", "entropy: must be between 0 and 8"},
		{"entropy_share", "          entropy_share: 4\n", "entropy_share: must be a share between 0 and 1"},
		{"txt_share", "          txt_share: -1\n", "txt_share: must be a share"},
		{"label length", "          min_label_length: 2\n", "min_label_length"},
		{"distinct", "          distinct_subdomains: -1\n", "distinct_subdomains"},
		{"payload", "          payload_bytes: -1\n", "payload_bytes"},
		{"allow domain", "          allow_domains: [\"a b\"]\n", "allow_domains"},
		{"action", "          action: drop\n", "action: must be log or block"},
		{"cooldown", "          cooldown: 48h\n", "cooldown"},
		{"max tracked", "          max_tracked: 4\n", "max_tracked"},
		{
			"more agreement than signals",
			"          min_signals: 3\n          txt_share: 0\n          nxdomain_share: 0\n          payload_bytes: 0\n",
			"only 2 are switched on, so nothing can ever be detected",
		},
	}
	for _, tc := range cases {
		_, err := ParseWith([]byte(tunnelConfig(tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}
