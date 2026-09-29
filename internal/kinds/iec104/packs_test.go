package iec104_test

import (
	"os"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The shipped behaviour pack for Industroyer, driven through the relay.
//
// A pack is configuration, and configuration nobody runs is a document of
// intentions. This takes the file as it ships, points it at a fabricated
// station, and sends what the payload sent.
//
// Two substitutions are made and no others: the listener binds a loopback
// port the kernel picks instead of the plant address in the file, and the
// control centre's network becomes the loopback so that a test can be the
// control centre. The rules are the file's own.
func industroyerPack(t *testing.T, st *station) (*proxy.Server, string) {
	t.Helper()
	b, err := os.ReadFile("../../../examples/ot/packs/industroyer-iec104.yaml") //nolint:gosec // a file in this repository
	if err != nil {
		t.Fatalf("read the pack: %v", err)
	}
	doc := string(b)
	for _, sub := range [][2]string{
		{"10.40.0.10:2404", "127.0.0.1:0"},
		{"10.40.1.0/24", "127.0.0.1/32"},
		{"10.40.1.11/32", "127.0.0.1/32"},
		{"10.40.9.31:2404", st.addr()},
	} {
		if !strings.Contains(doc, sub[0]) {
			t.Fatalf("the pack does not mention %s, so the substitution would test nothing", sub[0])
		}
		// Every occurrence, not the first: the file's own header comment
		// names these addresses, and a substitution that hit the comment and
		// left the rule alone would be testing a listener nobody could
		// connect to.
		doc = strings.ReplaceAll(doc, sub[0], sub[1])
	}
	s := proxytest.Start(t, doc)
	return s, proxytest.Addr(t, s, "substation-gateway")
}

// The object walk: Industroyer commanded a range of information object
// addresses because it knew the protocol and not the substation. The pack's
// answer is the list of objects this control centre operates -- so the walk
// stops at the first object outside it, by a rule named after the technique.
func TestTheIndustroyerPackRefusesTheObjectWalk(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := industroyerPack(t, st)

	c := dialCentre(t, addr)
	c.startdt()

	// The walk first, because the pack's command rate limit is two a second
	// -- which is what a control centre that switches when an operator clicks
	// actually sends, and which the walk itself runs into after a few frames.
	// Sending this one first is what shows the *named* rule refusing it
	// rather than the rate limit getting there first.
	//
	// Select-before-operate does not stop this and the pack says so: the
	// payload sent the select too.
	c.ask(command(1, 4200, true, true))
	if f := expectASDU(c, "the refusal"); !f.ASDU.Negative {
		t.Fatalf("an object outside the range was carried: %+v", f.ASDU)
	}
	awaitPack(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["rule"] >= 1
	}, "the pack's deny rule refused the walk")

	// And a breaker this centre does operate still works, which is the half
	// of a pack that matters on the morning after it is installed.
	//
	// The wait is the pack's own command rate limit: two a second, which is
	// what a control centre that switches when an operator clicks sends, and
	// which three commands in a millisecond are well past. A refused command
	// spends a token too -- the bound is a bound on what arrives, not on what
	// is carried -- so the walk above has to be paid for before the
	// legitimate pair is sent.
	time.Sleep(1500 * time.Millisecond)
	c.ask(command(1, 4001, true, true))
	if f := expectASDU(c, "the select"); f.ASDU.Negative {
		t.Fatalf("a breaker this centre operates was refused: %+v", f.ASDU)
	}
	c.ask(command(1, 4001, false, true))
	if f := expectASDU(c, "the execute"); f.ASDU.Negative {
		t.Fatalf("the execute was refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 2 {
		t.Errorf("the station saw %d commands, want the select and execute of the one it operates", len(got))
	}
}

// The blinding, and the station reset. Neither is a breaker command, and both
// are what the payload did around the commanding: STOPDT stops data transfer
// without refusing anything, and C_RP_NA_1 restarts the station.
func TestTheIndustroyerPackRefusesTheBlindingAndTheReset(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := industroyerPack(t, st)

	c := dialCentre(t, addr)
	c.startdt()

	// STOPDT is not in allow_controls, and a refused U-format frame is
	// answered with nothing: the standard has no negative confirmation for
	// one, so what the client sees is a STOPDT nobody confirmed.
	c.write(uframe(wire.StopDTAct))
	c.expectSilence("the refused STOPDT")
	awaitPack(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["control"] >= 1
	}, "the pack refused STOPDT")

	// The process reset, which restarts the station.
	c.ask(asdu(wire.CRpNA1, 1, wire.CauseActivation, 1, 0, 0, 0, 1))
	if f := expectASDU(c, "the refusal of the reset"); !f.ASDU.Negative {
		t.Fatalf("a process reset was carried: %+v", f.ASDU)
	}
	if got := st.saw(wire.CRpNA1); len(got) != 0 {
		t.Errorf("%d process resets reached the station", len(got))
	}
}

// expectASDU reads until an ASDU arrives, skipping the acknowledgements the
// relay sends on its own second: a test that polls a counter for a while comes
// back to a connection with an S-format frame waiting on it, and an S frame
// carries no ASDU to decide about.
func expectASDU(c *centre, what string) *wire.Frame {
	c.t.Helper()
	for i := 0; i < 8; i++ {
		f := c.expect(what)
		if f.ASDU != nil {
			return f
		}
	}
	c.t.Fatalf("%s: eight frames and none carried an ASDU", what)
	return nil
}

// awaitPack polls a counter, because the counters are incremented on the
// relay's own goroutines after the frame has gone out.
func awaitPack(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	await(t, s, ok, what)
}
