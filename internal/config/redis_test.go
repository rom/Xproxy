package config

import (
	"strings"
	"testing"
)

// redisDeceptionConfig is one redis listener with a deception section.
func redisDeceptionConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: cache
      address: "127.0.0.1:0"
      kind: redis
      redis:
        require_tls: false
` + section + `
upstreams:
  - name: rd
    endpoints: [{address: "10.0.0.9:6379"}]
`
}

// The client list, and the one contradiction worth refusing: a decoy is the
// whole listener, so it cannot also front a real server.
func TestRedisDeceptionInsistsOnAClientList(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "answer mode with a client list",
			section: `        upstream: rd
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]`,
		},
		{
			name: "answer mode with no client list",
			section: `        upstream: rd
        deception:
          mode: answer`,
			wants: "clients: required in mode answer",
		},
		{
			name: "the default mode is answer, so the same rule holds",
			section: `        upstream: rd
        deception:
          profile: queue`,
			wants: "clients: required in mode answer",
		},
		{
			name:    "a decoy listener needs no upstream and no clients",
			section: `        deception: {mode: decoy}`,
		},
		{
			name: "a decoy listener with an upstream is a contradiction",
			section: `        upstream: rd
        deception: {mode: decoy}`,
			wants: "decoy is the whole listener",
		},
		{
			name:    "a mode that is neither",
			section: `        deception: {mode: mirror}`,
			wants:   "mode: must be answer or decoy",
		},
		{
			name:    "a section switched off leaves the listener needing an upstream",
			section: `        deception: {mode: decoy, enabled: false}`,
			wants:   "upstream: required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(redisDeceptionConfig(tc.section)))
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

// The fields of the section, each of which would otherwise be a listener that
// starts and fabricates something nobody meant.
func TestRedisDeceptionFieldsAreChecked(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a profile that does not exist",
			section: `        deception: {mode: decoy, profile: memcached}`,
			wants:   "is not a profile",
		},
		{
			name:    "a version longer than a version",
			section: `        deception: {mode: decoy, version: "` + strings.Repeat("7", 70) + `"}`,
			wants:   "version: 70 characters",
		},
		{
			name:    "more keys than the fabrication holds",
			section: `        deception: {mode: decoy, key_count: 9000}`,
			wants:   "key_count: must be between 0 and 4096",
		},
		{
			name:    "a key that is not one",
			section: `        deception: {mode: decoy, keys: [""]}`,
			wants:   "keys[0]: empty",
		},
		{
			name:    "a tripwire that is not a command name",
			section: `        deception: {mode: decoy, tripwire: ["GET key value"]}`,
			wants:   "tripwire[0]",
		},
		{
			name:    "a tripwire with a character no command has",
			section: `        deception: {mode: decoy, tripwire: ["GET;DROP"]}`,
			wants:   "tripwire[0]",
		},
		{
			name:    "a client record bound that is not a bound",
			section: `        deception: {mode: decoy, max_clients: -1}`,
			wants:   "max_clients",
		},
		{
			name:    "a period outside the bounds",
			section: `        deception: {mode: decoy, period: 2h}`,
			wants:   "period: must be between 1s and 1h",
		},
		{
			name: "and a whole section that is right",
			section: `        deception:
          mode: decoy
          profile: session-store
          version: "7.0.15"
          key_count: 128
          keys: ["session:abc123", "app:flags"]
          tripwire: ["keys", "config get"]
          period: 30s
          max_clients: 512`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(redisDeceptionConfig(tc.section)))
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

// What is worth saying at load rather than being discovered from a decoy that
// nobody believed.
func TestRedisDeceptionWarnings(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a decoy that answers every client",
			section: `        deception: {mode: decoy}`,
			wants:   "every client that connects is answered by the fabricated",
		},
		{
			name:    "no version, so the profile's is reported",
			section: `        deception: {mode: decoy}`,
			wants:   "A decoy should say what the",
		},
		{
			name: "deny_response drop does not reach the deceived clients",
			section: `        upstream: rd
        deny_response: drop
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]
          version: "7.2.4"`,
			wants: "deny_response drop does not apply",
		},
		{
			name:    "a decoy that asks for a password",
			section: `        deception: {mode: decoy, version: "7.2.4", require_auth: true}`,
			wants:   "accept any of them",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(redisDeceptionConfig(tc.section)), false)
			if err != nil {
				t.Fatalf("did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.wants) {
				t.Errorf("no warning %q: %v", tc.wants, cfg.Advice())
			}
		})
	}
}
