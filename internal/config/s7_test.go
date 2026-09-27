package config

import (
	"strings"
	"testing"
)

// s7DeceptionConfig is one s7 listener with a deception section.
func s7DeceptionConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: cell
      address: "127.0.0.1:0"
      kind: s7
      s7:
` + section + `
upstreams:
  - name: cpu
    endpoints: [{address: "10.0.0.9:102"}]
`
}

// The client list is the rule worth being strict about: the worst case of a
// fabricated answer here is an engineer reading a value nothing measured off a
// real machine, so a section that would answer for anybody on a listener that
// reaches a controller does not load.
func TestS7DeceptionInsistsOnAClientList(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "answer mode with a client list",
			section: `        upstream: cpu
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]`,
		},
		{
			name: "answer mode with no client list",
			section: `        upstream: cpu
        deception:
          mode: answer`,
			wants: "clients: required in mode answer",
		},
		{
			name: "the default mode is answer, so the same rule holds",
			section: `        upstream: cpu
        deception:
          profile: generic-s7-400`,
			wants: "clients: required in mode answer",
		},
		{
			name:    "a decoy listener needs no upstream and no clients",
			section: `        deception: {mode: decoy}`,
		},
		{
			name: "a decoy listener with an upstream is a contradiction",
			section: `        upstream: cpu
        deception: {mode: decoy}`,
			wants: "decoy is the whole listener",
		},
		{
			name:    "and a listener with neither is not a listener",
			section: `        dbs: ["1"]`,
			wants:   "upstream: required",
		},
		{
			name: "a mode that does not exist",
			section: `        upstream: cpu
        deception:
          mode: pretend
          clients: ["10.9.0.0/24"]`,
			wants: "must be answer or decoy",
		},
		{
			name: "turned off, and then nothing else has to make sense",
			section: `        upstream: cpu
        deception: {enabled: false}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(s7DeceptionConfig(tc.section)))
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

// The identity is what a scanner reads, so the fields it comes out of are
// checked against what the protocol's own lists can carry: an order number of
// thirty characters would be truncated into something that is not an order
// number, and a firmware version of "latest" is not a version any CPU reports.
func TestS7DeceptionFieldsAreChecked(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a profile that does not exist",
			section: `        deception: {mode: decoy, profile: generic-s7-1500}`,
			wants:   "is not a profile",
		},
		{
			name:    "a PDU length no classic CPU negotiates",
			section: `        deception: {mode: decoy, pdu_length: 1024}`,
			wants:   "is not a length a classic CPU negotiates",
		},
		{
			name:    "a firmware version that is not one",
			section: `        deception: {mode: decoy, version: latest}`,
			wants:   "is not a firmware version",
		},
		{
			name:    "an order number the module list cannot carry",
			section: `        deception: {mode: decoy, order_number: "6ES7 315-2EH14-0AB0-EXTRA"}`,
			wants:   "the module identification list carries 20",
		},
		{
			name:    "a module type the component list cannot carry",
			section: `        deception: {mode: decoy, module_type: "` + strings.Repeat("C", 33) + `"}`,
			wants:   "the component identification list carries 32",
		},
		{
			name: "a block run with no numbers",
			section: `        deception:
          mode: decoy
          blocks:
            - {bytes: 512}`,
			wants: "dbs: required",
		},
		{
			name: "a band with no addresses",
			section: `        deception:
          mode: decoy
          bands:
            - {shape: analogue}`,
			wants: "addresses: required",
		},
		{
			name: "a shape that is not one",
			section: `        deception:
          mode: decoy
          bands:
            - {addresses: "0-99", shape: wobbly}`,
			wants: "must be analogue, discrete or counter",
		},
		{
			name: "a totaliser that would go backwards",
			section: `        deception:
          mode: decoy
          bands:
            - {addresses: "0-99", shape: counter, rate: -1}`,
			wants: "must not be negative",
		},
		{
			name:    "a period outside the bounds",
			section: `        deception: {mode: decoy, period: 2h}`,
			wants:   "period: must be between 1s and 1h",
		},
		{
			name:    "a tripwire past the block numbering",
			section: `        deception: {mode: decoy, tripwire: ["70000"]}`,
			wants:   "tripwire",
		},
		{
			name: "and a whole section that is right",
			section: `        deception:
          mode: decoy
          profile: generic-s7-400
          order_number: "6ES7 416-3FS07-0AB0"
          module_type: "CPU 416F-3 PN/DP"
          plant: "LINE2"
          serial: "S C-C2UR28922012"
          version: "7.0.3"
          pdu_length: 480
          period: 30s
          tripwire: ["666"]
          blocks:
            - {dbs: "1-32", bytes: 2048}
          bands:
            - {addresses: "0-499", shape: analogue, min: 0, max: 27648}
            - {addresses: "500-699", shape: discrete}
            - {addresses: "700-999", shape: counter, rate: 13}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(s7DeceptionConfig(tc.section)))
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
