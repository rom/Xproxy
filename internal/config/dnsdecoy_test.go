package config

import (
	"strings"
	"testing"
)

// dnsDecoyConfig is one dns listener with a deception section.
func dnsDecoyConfig(dns string) string {
	return `
version: 1
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
` + dns + `
logging: {access: {enabled: false}}
`
}

// The client list, and the two contradictions worth refusing.
func TestDNSDeceptionInsistsOnAClientList(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "answer mode with a client list",
			section: `        upstreams: ["9.9.9.9:53"]
        deception: {mode: answer, clients: ["10.0.0.0/8"]}`,
		},
		{
			name: "answer mode with no client list",
			section: `        upstreams: ["9.9.9.9:53"]
        deception: {mode: answer}`,
			wants: "clients: required in mode answer",
		},
		{
			name:    "a decoy listener needs no upstreams and no clients",
			section: `        deception: {mode: decoy}`,
		},
		{
			name: "a decoy listener with upstreams is a contradiction",
			section: `        upstreams: ["9.9.9.9:53"]
        deception: {mode: decoy}`,
			wants: "decoy is the whole listener",
		},
		{
			// With the section switched off there is nothing to resolve with
			// and nothing to fabricate, so the ordinary requirement is back.
			name:    "a disabled decoy still needs upstreams",
			section: `        deception: {mode: decoy, enabled: false}`,
			wants:   "upstreams: at least one resolver is required",
		},
		{
			name: "a mode that is neither",
			section: `        upstreams: ["9.9.9.9:53"]
        deception: {mode: sinkhole}`,
			wants: "mode: must be answer or decoy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(dnsDecoyConfig(tc.section)))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// The fields of the section.
func TestDNSDeceptionFieldsAreChecked(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a profile that does not exist",
			section: `        deception: {mode: decoy, profile: bind}`,
			wants:   "is not a profile",
		},
		{
			name:    "a pool that is not a prefix",
			section: `        deception: {mode: decoy, addresses: ["192.0.2.1"]}`,
			wants:   "addresses[0]",
		},
		{
			// One prefix per family: two IPv4 pools is a configuration where
			// only one of them could ever be used, and nothing says which.
			name:    "two pools of one family",
			section: `        deception: {mode: decoy, addresses: ["192.0.2.0/24", "198.51.100.0/24"]}`,
			wants:   "a second IPv4 pool",
		},
		{
			name:    "an IPv4 pool written as IPv6",
			section: `        deception: {mode: decoy, addresses: ["::ffff:192.0.2.0/120"]}`,
			wants:   "written as IPv6",
		},
		{
			name:    "a tripwire with a space in it",
			section: `        deception: {mode: decoy, tripwire: ["pay roll"]}`,
			wants:   "tripwire[0]",
		},
		{
			name:    "a TTL outside the bounds",
			section: `        deception: {mode: decoy, ttl: 2h}`,
			wants:   "ttl: must be between 1s and 1h",
		},
		{
			name:    "a period outside the bounds",
			section: `        deception: {mode: decoy, period: 2h}`,
			wants:   "period: must be between 1s and 1h",
		},
		{
			name:    "a client record bound that is not a bound",
			section: `        deception: {mode: decoy, max_clients: -1}`,
			wants:   "max_clients",
		},
		{
			name: "and a whole section that is right",
			section: `        cookies: require
        deception:
          mode: decoy
          profile: documentation
          addresses: ["192.0.2.0/24", "2001:db8::/32"]
          ttl: 300s
          period: 30s
          max_clients: 512
          tripwire: [payroll.internal]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(dnsDecoyConfig(tc.section)))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// What is worth saying at load, because a resolver is an amplifier and a
// fabricated address is somewhere a visitor then goes.
func TestDNSDeceptionWarnings(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a decoy that answers every client",
			section: `        cookies: require` + "\n" + `        deception: {mode: decoy}`,
			wants:   "every client that connects is answered by the fabricated",
		},
		{
			// A honeypot's record of who visited is the whole product, and
			// without cookies the address in it is the one the packet claimed.
			name:    "a decoy without cookies",
			section: `        deception: {mode: decoy}`,
			wants:   "cookies: require is what makes the record",
		},
		{
			name:    "a pool inside the estate",
			section: `        deception: {mode: decoy, addresses: ["10.70.0.0/24"]}`,
			wants:   "is inside the estate",
		},
		{
			// And the opposite: on a decoy listener the warning about cookies
			// breaking stub resolvers does not apply, because there are no
			// clients to break.
			name:    "a decoy is not told that require breaks its clients",
			section: `        cookies: require` + "\n" + `        deception: {mode: decoy}`,
			wants:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(dnsDecoyConfig(tc.section)), false)
			if err != nil {
				t.Fatalf("did not load: %v", err)
			}
			if tc.wants == "" {
				if hasAdvice(cfg, "most stub resolvers do not") {
					t.Errorf("a decoy was warned that cookies break its clients: %v", cfg.Advice())
				}
				return
			}
			if !hasAdvice(cfg, tc.wants) {
				t.Errorf("no warning %q: %v", tc.wants, cfg.Advice())
			}
		})
	}
}

// The profile list the validator checks against must be the one the listener
// has, or a configuration that loads names a profile the kind will refuse.
func TestTheDNSProfileListsAgree(t *testing.T) {
	for _, name := range DNSDecoyProfiles {
		section := `        cookies: require` + "\n" +
			`        deception: {mode: decoy, profile: ` + name + `}`
		if _, err := parseNoFiles([]byte(dnsDecoyConfig(section))); err != nil {
			t.Errorf("profile %q does not load: %v", name, err)
		}
	}
}
