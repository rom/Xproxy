package proxy

import (
	"testing"

	"github.com/rom/xproxy/internal/attack"
)

// A refusal that means something in ATT&CK for ICS terms is counted under
// the technique as well as under the reason, and one that does not is
// counted only under the reason.
//
// The second half is the one worth a test: a table that tagged everything
// would produce a coverage report claiming detections this proxy does not
// have, which is worse than no report.
func TestRefusalsAreCountedByTechnique(t *testing.T) {
	var s Stats
	if got := s.TechniqueCounts(); got != nil {
		t.Fatalf("a process that refused nothing reported techniques %v", got)
	}

	// A write refused on a read-only Modbus listener: an unauthorised
	// command (T0855) whose target is the I/O image (T0835).
	s.Refuse("modbus", "read_only")
	counts := s.TechniqueCounts()
	if counts["T0855"] != 1 || counts["T0835"] != 1 {
		t.Errorf("modbus read_only counted %v", counts)
	}
	// One reason, two techniques: the totals do not sum to the refusals,
	// and that is the documented reading of this table.
	if n := s.RefusalCounts()["modbus"]["read_only"]; n != 1 {
		t.Errorf("the refusal itself counted %d times", n)
	}

	// Protocol hygiene carries no technique.
	s.Refuse("modbus", "tls_handshake")
	if counts := s.TechniqueCounts(); len(counts) != 2 {
		t.Errorf("a handshake failure was given a technique: %v", counts)
	}

	// A second sighting adds to the same counter.
	s.Refuse("iec104", "iec104_control")
	if got := s.TechniqueCounts()["T0855"]; got != 2 {
		t.Errorf("T0855 across two kinds counted %d", got)
	}
}

// A listener in shadow mode did not detect a technique; it decided not to
// act on one. Counting it here would put "what we would have refused"
// into the same number as "what we refused", which the two refusal tables
// exist to keep apart.
func TestShadowRefusalsDoNotCountAsTechniques(t *testing.T) {
	var s Stats
	s.WouldRefuse("modbus", "read_only")
	if got := s.TechniqueCounts(); got != nil {
		t.Errorf("a shadowed refusal counted as a detection: %v", got)
	}
}

// Every technique the counters can produce is one the catalogue
// describes, because the metric's labels are taken from it.
func TestEveryCountedTechniqueIsInTheCatalogue(t *testing.T) {
	var s Stats
	for _, m := range attack.Mappings() {
		s.Refuse(m.Kind, m.Reason)
	}
	for id := range s.TechniqueCounts() {
		if _, ok := attack.Get(id); !ok {
			t.Errorf("counted %s, which the catalogue does not describe", id)
		}
	}
	// And the mappings reach the table at all: a mapping naming a kind
	// the roster does not have would be counted nowhere, because Refuse
	// drops an unknown kind.
	if len(s.TechniqueCounts()) < 10 {
		t.Errorf("only %d techniques were reachable through Refuse", len(s.TechniqueCounts()))
	}
}

// The snapshot carries the table, so a status view and the exporter read
// the same numbers.
func TestSnapshotCarriesTheTechniques(t *testing.T) {
	var s Stats
	if sn := s.snapshot(); sn.Techniques != nil {
		t.Errorf("a quiet process's snapshot carries %v", sn.Techniques)
	}
	s.Refuse("s7", "block_type_not_allowed")
	sn := s.snapshot()
	if sn.Techniques["T0843"] != 1 || sn.Techniques["T0845"] != 1 {
		t.Errorf("snapshot techniques %v", sn.Techniques)
	}
}
