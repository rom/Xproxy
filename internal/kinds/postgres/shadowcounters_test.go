package postgres

import "testing"

// A listener in shadow mode must not report refusals it did not make.
//
// The process keeps two tables, refusals and would-be refusals, and
// internal/proxy keeps them apart on purpose so that a status view cannot add
// them up. A relay in monitor mode that counted both would defeat that in the
// one way that matters: an operator reading the refusal count of a listener
// being trialled would see enforcement that is not happening, and would draw
// exactly the wrong conclusion about whether the policy is ready.
//
// A hard refusal is the other half: monitor mode does not carry those, so they
// are real refusals and are counted as such.
func TestShadowModeCountsOnlyWouldBeRefusals(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := relayFor(t, base+"        read_only: true\n        monitor_only: true\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	_ = cl.waitReady(t)

	// Soft: carried, so not a refusal.
	if e := cl.query(t, "DELETE FROM users"); e != "" {
		t.Fatalf("shadow mode refused a soft decision: %s", e)
	}
	st := s.Stats()
	if n := st.Refusals["postgres"]["read_only"]; n != 0 {
		t.Errorf("shadow mode counted %d read_only refusals it did not make: %v", n, st.Refusals["postgres"])
	}
	if n := st.WouldRefusals["postgres"]["read_only"]; n != 1 {
		t.Errorf("would-be refusals %d, want 1: %v", n, st.WouldRefusals["postgres"])
	}

	// Hard: not carried, so it is a refusal and counts as one.
	if e := cl.query(t, "COPY t FROM PROGRAM 'id'"); e == "" {
		t.Fatal("shadow mode forwarded copy from program")
	}
	st = s.Stats()
	total := 0
	for _, n := range st.Refusals["postgres"] {
		total += int(n)
	}
	if total != 1 {
		t.Errorf("refusals %v, want exactly the one hard refusal", st.Refusals["postgres"])
	}
}
