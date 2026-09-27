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
