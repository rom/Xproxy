package config

import (
	"strings"
	"testing"
)

// snmpDeceptionConfig is one snmp listener with a deception section.
func snmpDeceptionConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: poll
      address: "127.0.0.1:0"
      kind: snmp
      snmp:
` + section + `
upstreams:
  - name: agents
    endpoints: [{address: "10.0.0.9:161"}]
`
}

// The client list, and one warning worth being sure of: a fabricated agent
// that answers every client is a UDP service answering strangers, and the
// amplification bounds are what keep that from being an amplifier.
func TestSNMPDeceptionInsistsOnAClientList(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "answer mode with a client list",
			section: `        upstream: agents
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]`,
		},
		{
			name: "answer mode with no client list",
			section: `        upstream: agents
        deception:
          mode: answer`,
			wants: "clients: required in mode answer",
		},
		{
			name: "the default mode is answer, so the same rule holds",
			section: `        upstream: agents
        deception:
          profile: generic-router`,
			wants: "clients: required in mode answer",
		},
		{
			name:    "a decoy listener needs no upstream and no clients",
			section: `        deception: {mode: decoy}`,
		},
		{
			name: "a decoy listener with an upstream is a contradiction",
			section: `        upstream: agents
        deception: {mode: decoy}`,
			wants: "decoy is the whole listener",
		},
		{
			name:    "and a listener with neither is not a listener",
			section: `        communities: ["public"]`,
			wants:   "upstream: required",
		},
		{
			name: "a mode that does not exist",
			section: `        upstream: agents
        deception:
          mode: pretend
          clients: ["10.9.0.0/24"]`,
			wants: "must be answer or decoy",
		},
		{
			name: "turned off, and then nothing else has to make sense",
			section: `        upstream: agents
        deception: {enabled: false}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(snmpDeceptionConfig(tc.section)))
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

// The identity is what a scanner reads, and the object identifiers in it have
// to be object identifiers: a sys_object_id nothing can parse is a value the
// fabrication could not answer with at all.
func TestSNMPDeceptionFieldsAreChecked(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a profile that does not exist",
			section: `        deception: {mode: decoy, profile: generic-firewall}`,
			wants:   "is not a profile",
		},
		{
			name:    "an object identifier that is not one",
			section: `        deception: {mode: decoy, sys_object_id: "1.3.6.four"}`,
			wants:   "sys_object_id",
		},
		{
			name:    "a tripwire that is not an object identifier",
			section: `        deception: {mode: decoy, tripwire: ["private.9.9"]}`,
			wants:   "tripwire[0]",
		},
		{
			name:    "more interfaces than the shape allows",
			section: `        deception: {mode: decoy, interfaces: 512}`,
			wants:   "interfaces: must be between 0 and 256",
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
			section: `        deception:
          mode: decoy
          profile: generic-switch
          sys_descr: "24-port managed Ethernet switch"
          sys_object_id: "1.3.6.1.4.1.8072.3.2.10"
          sys_name: "sw-cell9"
          sys_location: "Cell 9"
          sys_contact: "controls@example.invalid"
          interfaces: 24
          period: 30s
          tripwire: ["1.3.6.1.4.1.9.9.96"]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(snmpDeceptionConfig(tc.section)))
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

// The version 3 users whose keys a listener holds.
//
// Everything checked here is a configuration that would load and then refuse
// the traffic it was written to read -- which on this protocol means a
// listener that looks like it is policing v3 and is not.
func TestSNMPUSMUsersAreChecked(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "a user with a digest and a cipher",
			section: `        upstream: agents
        versions: [v3]
        usm_users:
          - name: poller
            auth: sha256
            auth_secret: "env:SNMP_AUTH"
            privacy: aes128
            privacy_secret: "env:SNMP_PRIV"`,
		},
		{
			name: "a digest and no cipher, which is authNoPriv",
			section: `        upstream: agents
        versions: [v3]
        usm_users:
          - name: poller
            auth: sha512
            auth_secret: "env:SNMP_AUTH"`,
		},
		{
			name: "no name",
			section: `        upstream: agents
        usm_users: [{auth: sha256, auth_secret: "env:A"}]`,
			wants: "name: required",
		},
		{
			name: "one name twice, which would be two sets of keys for one user",
			section: `        upstream: agents
        versions: [v3]
        usm_users:
          - {name: poller, auth: sha256, auth_secret: "env:A"}
          - {name: poller, auth: sha512, auth_secret: "env:B"}`,
			wants: "appears twice",
		},
		{
			name: "an authentication protocol that is not one",
			section: `        upstream: agents
        usm_users: [{name: poller, auth: sha3, auth_secret: "env:A"}]`,
			wants: "is not an authentication protocol",
		},
		{
			name: "no pass phrase to derive a key from",
			section: `        upstream: agents
        usm_users: [{name: poller, auth: sha256}]`,
			wants: "auth_secret: required",
		},
		{
			name: "a privacy protocol that is not one",
			section: `        upstream: agents
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A", privacy: rc4, privacy_secret: "env:B"}]`,
			wants: "is not a privacy protocol",
		},
		{
			name: "a cipher with no pass phrase",
			section: `        upstream: agents
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A", privacy: aes128}]`,
			wants: "privacy_secret: required with privacy",
		},
		{
			name: "a pass phrase with no cipher to use it",
			section: `        upstream: agents
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A", privacy_secret: "env:B"}]`,
			wants: "privacy: required with privacy_secret",
		},
		{
			// USM has one key derivation and the cipher truncates it, so a
			// sixteen-octet MD5 key cannot key AES-256. Refusing at load is
			// the difference between a listener that does not start and one
			// that refuses every message it was built to read.
			name: "a hash too narrow for the cipher beside it",
			section: `        upstream: agents
        usm_users: [{name: p, auth: md5, auth_secret: "env:A", privacy: aes256, privacy_secret: "env:B"}]`,
			wants: "needs 32 key octets and md5 derives 16",
		},
		{
			name: "and the same pair where the hash is wide enough",
			section: `        upstream: agents
        versions: [v3]
        usm_users: [{name: p, auth: sha384, auth_secret: "env:A", privacy: aes256, privacy_secret: "env:B"}]`,
		},
		{
			name: "an engine identifier that is not hexadecimal",
			section: `        upstream: agents
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A", engine_id: "not-hex"}]`,
			wants: "is not hexadecimal",
		},
		{
			name: "an engine identifier longer than the protocol allows",
			section: `        upstream: agents
        usm_users:
          - name: p
            auth: sha256
            auth_secret: "env:A"
            engine_id: "000000000000000000000000000000000000000000000000000000000000000000000000"`,
			wants: "1 to 32 octets",
		},
		{
			name: "and one written the way the tools print it",
			section: `        upstream: agents
        versions: [v3]
        usm_users:
          - name: p
            auth: sha256
            auth_secret: "env:A"
            engine_id: "80:00:1f:88:80:8f:3e:4c:5d"`,
		},
		{
			// authPriv on the listener and no privacy key for a user means
			// every message from that user arrives encrypted and none of them
			// can be read, so all of them are refused.
			name: "a floor of authPriv and a user with no cipher",
			section: `        upstream: agents
        versions: [v3]
        min_security_level: authPriv
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A"}]`,
			wants: "min_security_level authPriv",
		},
		{
			name: "a replay window outside the bounds",
			section: `        upstream: agents
        versions: [v3]
        replay_window: 3h
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A"}]`,
			wants: "replay_window: must be between 1s and 1h",
		},
		{
			name: "an engine bound that is not a bound",
			section: `        upstream: agents
        versions: [v3]
        max_usm_engines: -1
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A"}]`,
			wants: "max_usm_engines: must be between 0 and 1024",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(snmpDeceptionConfig(tc.section)))
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

// What is worth saying at load about version 3, rather than being discovered
// from a listener that turns out to be policing half its traffic.
func TestSNMPUSMWarnings(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "a listener that takes v3 and holds no keys",
			section: `        upstream: agents
        versions: [v3]`,
			wants: "a v3 message is a header and an opaque payload here",
		},
		{
			name: "RFC 3414's original digest",
			section: `        upstream: agents
        versions: [v3]
        usm_users: [{name: p, auth: md5, auth_secret: "env:A"}]`,
			wants: "RFC 3414's original and is weak",
		},
		{
			name: "RFC 3414's original cipher",
			section: `        upstream: agents
        versions: [v3]
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A", privacy: des, privacy_secret: "env:B"}]`,
			wants: "fifty-six bit cipher",
		},
		{
			name: "one pass phrase keying both the digest and the cipher",
			section: `        upstream: agents
        versions: [v3]
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A", privacy: aes128, privacy_secret: "env:A"}]`,
			wants: "one guess gets both",
		},
		{
			// Keys held for a user the allow list does not admit: the
			// listener reads as working and refuses everything.
			name: "keys for a user the allow list keeps out",
			section: `        upstream: agents
        versions: [v3]
        users: ["someone-else"]
        usm_users: [{name: poller, auth: sha256, auth_secret: "env:A"}]`,
			wants: "is not in users",
		},
		{
			name: "keys on a listener that does not take v3",
			section: `        upstream: agents
        versions: [v2c]
        usm_users: [{name: p, auth: sha256, auth_secret: "env:A"}]`,
			wants: "does not accept v3, so these keys are never used",
		},
		{
			name: "a replay window and nothing to verify one with",
			section: `        upstream: agents
        versions: [v2c]
        replay_window: 60s`,
			wants: "without usm_users to verify one with",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(snmpDeceptionConfig(tc.section)), false)
			if err != nil {
				t.Fatalf("did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.wants) {
				t.Errorf("no warning %q: %v", tc.wants, cfg.Advice())
			}
		})
	}
}
