package config

import (
	"strings"
	"testing"
)

// iec104DeceptionConfig is one iec104 listener with a deception section.
func iec104DeceptionConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: grid
      address: "127.0.0.1:0"
      kind: iec104
      iec104:
` + section + `
upstreams:
  - name: rtu
    endpoints: [{address: "10.0.0.9:2404"}]
`
}

// The client list is the rule worth being strict about, and on this
// protocol more than on any other here: the worst case of a fabricated
// answer is a control room that believes a breaker is open when it is
// closed. So a section that would confirm a refused activation for anybody,
// on a listener that reaches a real station, does not load.
func TestIEC104DeceptionInsistsOnAClientList(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "answer mode with a client list",
			section: `        upstream: rtu
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]`,
		},
		{
			name: "answer mode with no client list",
			section: `        upstream: rtu
        deception:
          mode: answer`,
			wants: "clients: required in mode answer",
		},
		{
			name: "the default mode is answer, so the same rule holds",
			section: `        upstream: rtu
        deception:
          profile: generic-rtu`,
			wants: "clients: required in mode answer",
		},
		{
			name:    "a decoy listener needs no upstream and no clients",
			section: `        deception: {mode: decoy}`,
		},
		{
			name: "a decoy listener with an upstream is a contradiction",
			section: `        upstream: rtu
        deception: {mode: decoy}`,
			wants: "decoy is the whole listener",
		},
		{
			name:    "and a listener with neither an upstream nor a decoy is not a listener",
			section: `        common_addresses: ["1"]`,
			wants:   "upstream: required",
		},
		{
			name: "a mode that does not exist",
			section: `        upstream: rtu
        deception:
          mode: pretend
          clients: ["10.9.0.0/24"]`,
			wants: "must be answer or decoy",
		},
		{
			name: "turned off, and then nothing else has to make sense",
			section: `        upstream: rtu
        deception: {enabled: false}`,
		},
		{
			name:    "turned off is also not an upstream, so the listener still needs one",
			section: `        deception: {mode: decoy, enabled: false}`,
			wants:   "upstream: required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(iec104DeceptionConfig(tc.section)))
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

// The rest of the section is held to the same bounds every other one is,
// and one of them is worth naming: a point run with no type identification
// is not something a value can be fabricated for, and a totaliser with a
// negative rate would be the one thing a fabricated station cannot do and
// be believed.
func TestIEC104DeceptionFieldsAreChecked(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a profile that does not exist",
			section: `        deception: {mode: decoy, profile: generic-turbine}`,
			wants:   "is not a profile",
		},
		{
			name:    "a common address past the field",
			section: `        deception: {mode: decoy, common_addresses: ["70000"]}`,
			wants:   "common_addresses",
		},
		{
			name:    "a tripwire past the information object address space",
			section: `        deception: {mode: decoy, tripwire: ["16777216"]}`,
			wants:   "tripwire",
		},
		{
			name: "a point run with no type",
			section: `        deception:
          mode: decoy
          points:
            - {addresses: "1-8"}`,
			wants: "type: required",
		},
		{
			name: "a type nothing can fabricate a value for",
			section: `        deception:
          mode: decoy
          points:
            - {addresses: "1-8", type: C_SC_NA_1}`,
			wants: "is not a type this can fabricate",
		},
		{
			name: "a point run with no addresses",
			section: `        deception:
          mode: decoy
          points:
            - {type: M_SP_NA_1}`,
			wants: "addresses: required",
		},
		{
			name: "a measurement band with max below min",
			section: `        deception:
          mode: decoy
          points:
            - {addresses: "101-108", type: M_ME_NB_1, min: 100, max: 10}`,
			wants: "max must be above min",
		},
		{
			name: "a totaliser that would go backwards",
			section: `        deception:
          mode: decoy
          points:
            - {addresses: "201-208", type: M_IT_NA_1, rate: -1}`,
			wants: "must not be negative",
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
          profile: generic-substation
          common_addresses: ["1-4"]
          tripwire: ["9000-9099"]
          period: 30s
          max_clients: 64
          points:
            - {addresses: "1-16", type: M_DP_NA_1}
            - {addresses: "101-148", type: M_ME_NB_1, min: 0, max: 27648}
            - {addresses: "201-208", type: M_IT_NA_1, rate: 11}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(iec104DeceptionConfig(tc.section)))
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

// A redundancy group is an assertion that a set of addresses is one
// controlling station. Each of these is a way of writing one that would not
// be an assertion at all.
func TestIEC104RedundancyRefusals(t *testing.T) {
	for _, tc := range []struct{ name, section, want string }{
		{"a group with no name", `        upstream: rtu
        redundancy: {groups: [{clients: ["10.40.1.0/24"]}]}
`, "is not a valid name"},
		{"a group with no clients", `        upstream: rtu
        redundancy: {groups: [{name: centre}]}
`, "clients: required"},
		{"a client that is not a network", `        upstream: rtu
        redundancy: {groups: [{name: centre, clients: ["10.40.1.1"]}]}
`, "clients"},
		{"two groups with one name", `        upstream: rtu
        redundancy:
          groups:
            - {name: centre, clients: ["10.40.1.0/24"]}
            - {name: centre, clients: ["10.40.2.0/24"]}
`, "duplicate"},
		{"client lists that overlap", `        upstream: rtu
        redundancy:
          groups:
            - {name: north, clients: ["10.40.0.0/16"]}
            - {name: south, clients: ["10.40.2.0/24"]}
`, "two controlling stations at once"},
		{"more paths than a group has", `        upstream: rtu
        redundancy: {groups: [{name: centre, clients: ["10.40.1.0/24"], max_connections: 99}]}
`, "max_connections"},
		{"a takeover that is neither", `        upstream: rtu
        redundancy: {groups: [{name: centre, clients: ["10.40.1.0/24"], takeover: maybe}]}
`, "must be switch or refuse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWith([]byte(iec104DeceptionConfig(tc.section)), false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one about %q", err, tc.want)
			}
		})
	}
}

// Two warnings, and the shape that must be quiet. A section with no groups
// enforces nothing, and a group carrying selections across a network wide
// enough that the client list is not really an assertion about two or three
// paths is trusting more than the operator probably meant to.
func TestIEC104RedundancyAdvice(t *testing.T) {
	for _, tc := range []struct{ name, section, want string }{
		{"a section with no groups", `        upstream: rtu
        allow_clients: ["10.40.1.0/24"]
        redundancy: {groups: []}
`, "nothing about redundancy is enforced"},
		{"a group carrying selections across a whole network", `        upstream: rtu
        allow_clients: ["10.40.0.0/16"]
        require_select: true
        redundancy: {groups: [{name: centre, clients: ["10.40.0.0/16"]}]}
`, "wider than the two or three paths"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(iec104DeceptionConfig(tc.section)), false)
			if err != nil {
				t.Fatalf("the document did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.want) {
				t.Fatalf("no advice about %q: %v", tc.want, cfg.Advice())
			}
		})
	}
	// The group a control centre actually has -- two paths, named -- is
	// quiet, because a validator warning that fires on a correct
	// configuration is a warning an operator learns to scroll past.
	cfg, err := ParseWith([]byte(iec104DeceptionConfig(`        upstream: rtu
        allow_clients: ["10.40.1.0/24"]
        require_select: true
        redundancy:
          groups:
            - name: centre
              clients: ["10.40.1.11/32", "10.40.1.12/32"]
              max_connections: 2
`)), false)
	if err != nil {
		t.Fatalf("the document did not load: %v", err)
	}
	for _, a := range cfg.Advice() {
		if strings.Contains(a, "redundancy") || strings.Contains(a, "selections") {
			t.Errorf("a sound group warned: %q", a)
		}
	}
}
