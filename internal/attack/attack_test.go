package attack

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/listener"
)

// The table is data, so the tests are about the table being consistent
// with itself and with the rest of the project: a mapping naming a
// technique the catalogue does not have, or a kind this project does not
// implement, is a row that tags nothing at run time and would be found
// only by somebody reading a log line that should have carried a
// technique and did not.

func TestEveryMappingNamesAKnownTechnique(t *testing.T) {
	for _, m := range mappings {
		if len(m.ids) == 0 {
			t.Errorf("%s/%s maps to no technique at all", m.kind, m.reason)
		}
		for _, id := range m.ids {
			if !Known(id) {
				t.Errorf("%s/%s names %s, which the catalogue does not have", m.kind, m.reason, id)
			}
		}
	}
}

func TestEveryMappingNamesAKindThisProjectServes(t *testing.T) {
	for _, m := range mappings {
		if _, ok := listener.RoleOf(m.kind); !ok {
			t.Errorf("%s/%s is about kind %q, which no daemon serves", m.kind, m.reason, m.kind)
		}
	}
}

func TestNoMappingIsWrittenTwice(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range mappings {
		k := m.kind + "/" + m.reason
		if seen[k] {
			t.Errorf("%s is mapped twice, and the second row is the one that wins silently", k)
		}
		seen[k] = true
	}
}

// A technique in the catalogue that nothing maps to is a detection this
// project claims and does not have. It is the failure that matters most
// here, because attack.All() is what a coverage answer is built from.
func TestEveryTechniqueIsReachable(t *testing.T) {
	used := map[string]bool{}
	for _, m := range mappings {
		for _, id := range m.ids {
			used[id] = true
		}
	}
	for id := range catalogue {
		if !used[id] {
			t.Errorf("%s is in the catalogue and nothing maps to it: either map it or take it out, "+
				"because All() is read as what this relay can detect", id)
		}
	}
}

func TestEveryTechniqueIsDescribed(t *testing.T) {
	for _, tech := range All() {
		if !strings.HasPrefix(tech.ID, "T0") || len(tech.ID) != 5 {
			t.Errorf("%q is not an ATT&CK for ICS identifier", tech.ID)
		}
		if tech.Name == "" {
			t.Errorf("%s has no name", tech.ID)
		}
		if len(tech.Tactics) == 0 {
			t.Errorf("%s sits under no tactic", tech.ID)
		}
		if len(tech.Why) < 40 {
			t.Errorf("%s: the justification is %d characters, which is not one",
				tech.ID, len(tech.Why))
		}
	}
}

// Lookup works from both ends, because the counter has the kind in hand
// and the log line has the event name.
func TestLookupFromAKindAndFromAnEventName(t *testing.T) {
	ts := Of("modbus", "read_only")
	if len(ts) == 0 || ts[0].ID != "T0855" {
		t.Fatalf("modbus/read_only: %v", ts)
	}
	// The kinds spell the prefix both ways, so both have to resolve.
	if got := Of("iec104", "iec104_control"); len(got) == 0 || got[0].ID != "T0855" {
		t.Errorf("a reason carrying its own kind prefix did not resolve: %v", got)
	}
	if got := OfEvent("modbus_read_only"); len(got) != len(ts) {
		t.Errorf("the event index and the kind index disagree: %v against %v", got, ts)
	}
	if got := OfEvent("modbus_tls_handshake"); got != nil {
		t.Errorf("a reason that is protocol hygiene was tagged %v", got)
	}
	if got := Of("http", "waf"); got != nil {
		t.Errorf("an HTTP refusal was given an ICS technique: %v", got)
	}
}

func TestTheLogFieldsAreJoinedAndDeduplicated(t *testing.T) {
	ts := Of("modbus", "unsafe_sub_function")
	if len(ts) != 2 {
		t.Fatalf("unsafe_sub_function carries %d techniques", len(ts))
	}
	if got := IDs(ts); got != "T0816,T0804" {
		t.Errorf("ids %q", got)
	}
	if got := Tactics(ts); got != "inhibit-response-function" {
		t.Errorf("two techniques under one tactic should read as one tactic, got %q", got)
	}
	if got := Names(ts); !strings.Contains(got, "Device Restart/Shutdown") {
		t.Errorf("names %q", got)
	}
	if got := IDs(Of("modbus", "read_only")); got != "T0855,T0835" {
		t.Errorf("a single reason with two techniques: %q", got)
	}
}

func TestGetIsForgivingAboutHowAPackWritesAnIdentifier(t *testing.T) {
	for _, s := range []string{"T0855", "t0855", " T0855 "} {
		if _, ok := Get(s); !ok {
			t.Errorf("Get(%q) found nothing", s)
		}
	}
	if _, ok := Get("T9999"); ok {
		t.Error("an identifier nothing here can observe was accepted")
	}
}

// The OT kinds are the point of this package, so each of them has to
// have something mapped: a kind with no mapping at all is a kind whose
// refusals reach a SIEM as strings nobody can catalogue.
func TestEveryOTKindTagsSomething(t *testing.T) {
	for _, kind := range []string{
		"modbus", "iec104", "s7", "mms", "bacnet", "opcua", "coap", "snmp", "tftp", "dhcp", "dhcp6",
	} {
		if len(byKindReason[kind]) == 0 {
			t.Errorf("kind %s tags nothing", kind)
		}
	}
}
