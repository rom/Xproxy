package iec104_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
	kind "github.com/rom/xproxy/internal/kinds/iec104"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// interrogation is the general interrogation a control centre sends after a
// restart: send me everything you have.
func interrogation(common uint16) []byte {
	return asdu(wire.CIcNA1, 1, wire.CauseActivation, common, 0, 0, 0, 20)
}

// counters is the counter interrogation, which asks for the totals.
func counters(common uint16) []byte {
	return asdu(wire.CCiNA1, 1, wire.CauseActivation, common, 0, 0, 0, 5)
}

// read is a read command for one information object.
func read(common uint16, ioa uint32) []byte {
	return asdu(wire.CRdNA1, 1, wire.CauseRequest, common,
		byte(ioa), byte(ioa>>8), byte(ioa>>16))
}

// decoyYAML is a listener that is nothing but a fabricated station: no
// upstream, because there is nothing behind it.
const decoyYAML = `
version: 1
server:
  listeners:
    - name: spare
      address: "127.0.0.1:0"
      kind: iec104
      iec104:
%s
logging: {access: {enabled: false}}
`

func decoyServer(t *testing.T, section string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(decoyYAML, section))
	return s, proxytest.Addr(t, s, "spare")
}

// A sweep of common addresses is how this protocol gives up an estate, and
// it costs nothing: the address is two octets and a centre names it in every
// ASDU, so the listener's own refusal says which stations exist.
//
// This is the disclosure written down, so that the decoy below has
// something to be measured against.
func TestASweepOfCommonAddressesMapsTheEstate(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        rules:
          - {name: everything, action: allow, class: [monitoring, system]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// The station this listener carries: answered.
	c.ask(interrogation(1))
	if f := c.expect("the interrogation of station 1"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("station 1: %+v", f.ASDU)
	}
	// Every other address: refused, and the refusal is the answer a
	// scanner wanted.
	for _, common := range []uint16{2, 3, 41} {
		c.ask(interrogation(common))
		f := c.expect("the interrogation of station " + strconv.Itoa(int(common)))
		if f.ASDU == nil || !f.ASDU.Negative {
			t.Fatalf("station %d was not refused: %+v", common, f.ASDU)
		}
	}
}

// And the decoy, which answers for the addresses it claims and refuses the
// rest the way a station does -- so the sweep finishes with a map, and the
// map is of a substation that does not exist.
func TestTheDecoyAnswersForTheStationsItClaims(t *testing.T) {
	_, addr := decoyServer(t, `        deception:
          mode: decoy
          common_addresses: ["1-4"]
          spontaneous: false`)

	c := dialCentre(t, addr)
	c.startdt()
	// The end of initialisation, which a station sends when data transfer
	// starts and a centre uses to know the station has restarted.
	f := c.expect("the end of initialisation")
	if f.ASDU == nil || f.ASDU.Type != wire.MEiNA1 {
		t.Fatalf("the decoy did not announce its initialisation: %+v", f.ASDU)
	}
	for common := uint16(1); common <= 4; common++ {
		c.ask(interrogation(common))
		f := c.expect("the confirmation for station " + strconv.Itoa(int(common)))
		if f.ASDU == nil || f.ASDU.Negative || f.ASDU.Cause != wire.CauseActCon {
			t.Fatalf("station %d: %+v", common, f.ASDU)
		}
		// Drain the report and the termination.
		for {
			f = c.expect("the interrogation data for " + strconv.Itoa(int(common)))
			if f.ASDU != nil && f.ASDU.Cause == wire.CauseActTerm {
				break
			}
		}
	}
	// An address it does not claim: refused the way a station refuses one,
	// because one association carrying twenty substations is not a
	// substation.
	c.ask(interrogation(9))
	f = c.expect("the refusal for a station it is not")
	if f.ASDU == nil || !f.ASDU.Negative || f.ASDU.Cause != wire.CauseUnknownCommon {
		t.Fatalf("an unclaimed address: %+v", f.ASDU)
	}
}

// The association, in the order the standard describes and a control centre
// checks: a general interrogation is confirmed, then answered, then
// terminated, and a command is confirmed and terminated with nothing having
// moved.
func TestTheDecoySpeaksTheAssociation(t *testing.T) {
	s, addr := decoyServer(t, `        deception:
          mode: decoy
          profile: generic-substation
          common_addresses: ["1"]
          spontaneous: false`)

	c := dialCentre(t, addr)
	c.startdt()
	c.expect("the end of initialisation")

	// A general interrogation: confirmation, the points, the termination.
	c.ask(interrogation(1))
	if f := c.expect("the interrogation confirmation"); f.ASDU == nil ||
		f.ASDU.Cause != wire.CauseActCon || f.ASDU.Type != wire.CIcNA1 {
		t.Fatalf("the confirmation: %+v", f.ASDU)
	}
	seen := map[wire.Type]int{}
	addresses := map[uint32]bool{}
	for {
		f := c.expect("the interrogation data")
		if f.ASDU == nil {
			t.Fatal("a frame with no ASDU in an interrogation")
		}
		if f.ASDU.Cause == wire.CauseActTerm {
			break
		}
		if f.ASDU.Cause != wire.CauseIntroGeneral {
			t.Fatalf("a report at cause %s, and an interrogation answers at introgen", f.ASDU.Cause)
		}
		seen[f.ASDU.Type] += len(f.ASDU.Addresses)
		for _, a := range f.ASDU.Addresses {
			addresses[a] = true
		}
	}
	// The profile's shape, and every address in it: double points for the
	// breakers, single points for the protection signals, scaled
	// measurands. The totals answer a counter interrogation instead.
	for _, want := range []struct {
		typ      wire.Type
		lo, hi   uint32
		announce string
	}{
		{wire.MDpNA1, 1, 16, "breaker positions"},
		{wire.MSpNA1, 17, 64, "protection signals"},
		{wire.MMeNB1, 101, 148, "measurands"},
	} {
		if n := seen[want.typ]; n != int(want.hi-want.lo+1) {
			t.Errorf("%s: %d objects, want %d", want.announce, n, want.hi-want.lo+1)
		}
		for a := want.lo; a <= want.hi; a++ {
			if !addresses[a] {
				t.Errorf("%s: address %d was never reported", want.announce, a)
			}
		}
	}
	if n := seen[wire.MItNA1]; n != 0 {
		t.Errorf("a general interrogation answered with %d totals; those are a counter interrogation's", n)
	}

	// The counter interrogation, which is where the totals are.
	c.ask(counters(1))
	if f := c.expect("the counter confirmation"); f.ASDU == nil || f.ASDU.Cause != wire.CauseActCon {
		t.Fatalf("the counter confirmation: %+v", f.ASDU)
	}
	totals := 0
	for {
		f := c.expect("the counter data")
		if f.ASDU == nil {
			t.Fatal("a frame with no ASDU in a counter interrogation")
		}
		if f.ASDU.Cause == wire.CauseActTerm {
			break
		}
		if f.ASDU.Type != wire.MItNA1 {
			t.Fatalf("a counter interrogation answered with %s", f.ASDU.Type)
		}
		totals += len(f.ASDU.Addresses)
	}
	if totals != 8 {
		t.Errorf("%d totals, want 8", totals)
	}

	// A command: confirmed, then terminated. Nothing moved, because there
	// is nothing here to move.
	c.ask(command(1, 4, false, true))
	if f := c.expect("the command confirmation"); f.ASDU == nil ||
		f.ASDU.Negative || f.ASDU.Cause != wire.CauseActCon {
		t.Fatalf("the command confirmation: %+v", f.ASDU)
	}
	if f := c.expect("the command termination"); f.ASDU == nil || f.ASDU.Cause != wire.CauseActTerm {
		t.Fatalf("the command termination: %+v", f.ASDU)
	}
	// A selection is not a completion: the two-step form ends at the
	// confirmation until an execute arrives.
	c.ask(command(1, 4, true, true))
	if f := c.expect("the selection confirmation"); f.ASDU == nil || f.ASDU.Cause != wire.CauseActCon {
		t.Fatalf("the selection confirmation: %+v", f.ASDU)
	}
	c.expectSilence("a termination for a selection")

	// A read of a point it has, and of one it does not.
	c.ask(read(1, 120))
	if f := c.expect("the read answer"); f.ASDU == nil || f.ASDU.Type != wire.MMeNB1 ||
		len(f.ASDU.Addresses) != 1 || f.ASDU.Addresses[0] != 120 {
		t.Fatalf("the read of point 120: %+v", f.ASDU)
	}
	c.ask(read(1, 7000))
	if f := c.expect("the read refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a read of a point it does not have: %+v", f.ASDU)
	}

	// The keepalive.
	c.write(uframe(wire.TestFRAct))
	if f := c.expect("the test confirmation"); f.Format != wire.FormatU || f.Control != wire.TestFRCon {
		t.Fatalf("the keepalive: %s %s", f.Format, f.Control)
	}

	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Deceived >= 5 },
		"the deceived frames")
}

// What a decoy has to get right to survive a second look: a value that
// reads the same twice in a row, a value that has moved by the time a
// centre comes back, and a totaliser that never goes backwards.
func TestTheDecoyValuesAreStableAndThenMove(t *testing.T) {
	_, addr := decoyServer(t, `        deception:
          mode: decoy
          common_addresses: ["1"]
          spontaneous: false
          period: 1s
          points:
            - {addresses: "101-104", type: M_ME_NB_1, min: 0, max: 27648}
            - {addresses: "201-204", type: M_IT_NA_1, rate: 7}`)

	c := dialCentre(t, addr)
	c.startdt()
	c.expect("the end of initialisation")

	sweep := func(what string) (map[uint32]int, map[uint32]int) {
		c.t.Helper()
		measured, totalled := map[uint32]int{}, map[uint32]int{}
		c.ask(interrogation(1))
		c.expect(what + ": the confirmation")
		for {
			f := c.expect(what + ": data")
			if f.ASDU == nil || f.ASDU.Cause == wire.CauseActTerm {
				break
			}
			for i, a := range f.ASDU.Addresses {
				measured[a] = valueAt(t, f, i)
			}
		}
		c.ask(counters(1))
		c.expect(what + ": the counter confirmation")
		for {
			f := c.expect(what + ": counters")
			if f.ASDU == nil || f.ASDU.Cause == wire.CauseActTerm {
				break
			}
			for i, a := range f.ASDU.Addresses {
				totalled[a] = valueAt(t, f, i)
			}
		}
		return measured, totalled
	}

	first, firstTotals := sweep("the first sweep")
	again, _ := sweep("the same period")
	// Inside one period the same address reads the same, which is what a
	// process does and what a random number does not.
	for a, v := range first {
		if again[a] != v {
			t.Errorf("point %d read %d then %d inside one period", a, v, again[a])
		}
	}
	if len(first) == 0 {
		t.Fatal("the interrogation reported no measurements at all")
	}
	// A period later it has moved, and the totals have only gone up.
	deadline := time.Now().Add(5 * time.Second)
	moved := false
	for time.Now().Before(deadline) && !moved {
		time.Sleep(300 * time.Millisecond)
		later, laterTotals := sweep("a later period")
		for a, v := range later {
			if v != first[a] {
				moved = true
			}
		}
		for a, v := range laterTotals {
			if v < firstTotals[a] {
				t.Fatalf("total %d went backwards: %d then %d", a, firstTotals[a], v)
			}
		}
	}
	if !moved {
		t.Error("no measurement moved between periods: a register nothing drives is a device nothing drives")
	}
}

// valueAt reads the scaled value or the total of one object, which is the
// two octets after the address (and four for a total).
func valueAt(t *testing.T, f *wire.Frame, i int) int {
	t.Helper()
	// The ASDU body starts after the six-octet header; each object is the
	// three-octet address and then the element.
	size := 3
	switch f.ASDU.Type {
	case wire.MMeNB1:
		size += 3
	case wire.MItNA1:
		size += 5
	default:
		t.Fatalf("no value reader for %s", f.ASDU.Type)
	}
	body := f.Raw[wire.APCILen+6:]
	at := i * size
	if at+size > len(body) {
		t.Fatalf("object %d is past the end of a %d-octet body", i, len(body))
	}
	v := int(body[at+3]) | int(body[at+4])<<8
	if f.ASDU.Type == wire.MItNA1 {
		v |= int(body[at+5])<<16 | int(body[at+6])<<24
	}
	return v
}

// The tripwire: an address nothing legitimate reads is answered, because
// the answer is what keeps the visitor reading, and raised as an event
// somebody acts on.
func TestTheTripwireIsAnsweredAndRaised(t *testing.T) {
	s, addr := decoyServer(t, `        deception:
          mode: decoy
          common_addresses: ["1"]
          spontaneous: false
          tripwire: ["9000-9099"]
          points:
            - {addresses: "9000-9004", type: M_ME_NB_1}
            - {addresses: "101-104", type: M_ME_NB_1}`)

	c := dialCentre(t, addr)
	c.startdt()
	c.expect("the end of initialisation")
	c.ask(read(1, 9001))
	if f := c.expect("the tripwire answer"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a tripwire address was not answered: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Tripwire >= 1 },
		"the tripwire event")

	// And the status view says who arrived and what they touched.
	found := false
	for _, d := range s.DeviceDecoys() {
		if d.Listener == "spare" {
			found = true
			if d.Profile != "generic-substation" {
				t.Errorf("the status view says profile %q", d.Profile)
			}
			if d.Tripped == 0 {
				t.Error("the status view records no tripwire")
			}
			if len(d.Visitors) == 0 {
				t.Error("the status view records no visitor")
			}
		}
	}
	if !found {
		t.Error("the fabricated station is not in the status view")
	}
}

// mode answer, and the rule the whole feature is bounded by: what was going
// to reach the station still does, answered by the station; what was going
// to be refused is confirmed by the fabrication instead and never arrives.
func TestAnsweredRefusalsReplaceRefusalsAndNothingElse(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4099"]}
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          tripwire: ["9000-9099"]`, st)

	c := dialCentre(t, addr)
	c.startdt()

	// Allowed: it reaches the station, and the station's own confirmation
	// comes back. The fabrication is not involved.
	c.ask(command(1, 4001, false, true))
	if f := c.expect("the confirmation of an allowed command"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("an allowed command: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Fatalf("the station saw %d of the one allowed command", len(got))
	}

	// Refused: confirmed positively, and the station never sees it. A
	// termination follows, which is the sequence that tells a control
	// centre the breaker moved.
	c.ask(command(1, 9001, false, true))
	if f := c.expect("the fabricated confirmation"); f.ASDU == nil || f.ASDU.Negative ||
		f.ASDU.Cause != wire.CauseActCon {
		t.Fatalf("a refused command was not confirmed by the fabrication: %+v", f.ASDU)
	}
	if f := c.expect("the fabricated termination"); f.ASDU == nil || f.ASDU.Cause != wire.CauseActTerm {
		t.Fatalf("the fabricated termination: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Fatalf("a deceived command reached the station: %d commands arrived", len(got))
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.IEC104Deceived >= 1 && sn.IEC104Tripwire >= 1 && sn.IEC104Denied >= 1
	}, "the deception, the tripwire and the refusal")

	// The refusal is still a refusal in the record: the counters and the
	// log say the command was denied, because a deception that also hid
	// the refusal would hide the only signal an operator has.
	if n := s.Stats().Refusals["iec104"]["rule"] + s.Stats().Refusals["iec104"]["default_deny"]; n == 0 {
		t.Error("a deceived frame was not counted as a refusal")
	}

	// And the link is still usable, with its numbering intact: the
	// harness checks every frame's send sequence number.
	st.send <- measurement(1, 100, 7)
	if f := c.expect("telemetry after a deception"); f.ASDU == nil || f.ASDU.Type != wire.MMeNB1 {
		t.Fatalf("the link did not survive a deception: %+v", f)
	}
}

// A client the section does not name gets the refusal, not the
// fabrication. That is the half of mode answer that keeps it usable: the
// deception is for the networks an operator named and for nobody else.
func TestAClientOutsideTheSectionStillGetsARefusal(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        deception:
          mode: answer
          clients: ["10.90.0.0/24"]`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a client outside the section was deceived: %+v", f.ASDU)
	}
}

// The validator refuses a profile or a type this package would not know, so
// the lists have to be the same lists. One in the validator and not here is
// a name that loads and then does nothing; one here and not there fails at
// load for no reason.
func TestTheDecoyNamesMatchTheValidator(t *testing.T) {
	same := func(what string, mine, theirs []string) {
		t.Helper()
		have := map[string]bool{}
		for _, n := range mine {
			have[n] = true
		}
		for _, n := range theirs {
			if !have[n] {
				t.Errorf("%s: the validator accepts %q and this package does not have it", what, n)
			}
			delete(have, n)
		}
		for n := range have {
			t.Errorf("%s: this package has %q and the validator would refuse it", what, n)
		}
	}
	same("profiles", kind.ProfileNames(), config.IEC104DecoyProfiles)
	same("types", kind.DecoyTypeNames(), config.IEC104DecoyTypes)

	// And every profile loads, which is the round trip.
	for _, n := range config.IEC104DecoyProfiles {
		if _, addr := decoyServer(t, "        deception: {mode: decoy, profile: "+n+
			", spontaneous: false}"); addr == "" {
			t.Errorf("profile %q did not start", n)
		}
	}
}

// A station that says nothing until spoken to is a station somebody looks
// at twice, so the fabrication reports between interrogations.
func TestTheDecoyReportsSpontaneously(t *testing.T) {
	_, addr := decoyServer(t, `        deception:
          mode: decoy
          common_addresses: ["1"]
          period: 1s`)

	c := dialCentre(t, addr)
	c.startdt()
	c.expect("the end of initialisation")
	f := c.expect("a spontaneous report")
	if f.ASDU == nil || f.ASDU.Cause != wire.CauseSpontaneous {
		t.Fatalf("the report arrived at cause %v", f.ASDU)
	}
}

// Only an activation is answered by the fabrication, in either mode.
//
// There is nothing to confirm about a measurement: the protocol has no
// confirmation for one, so a "confirmation of a measurement" is an ASDU no
// station would ever send. That frame would be the tell rather than the
// deception, and a control centre receiving one would have no idea what to
// do with it.
func TestOnlyAnActivationIsAnsweredByTheFabrication(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// A measurement naming a station this listener does not carry: refused,
	// and answered with nothing at all.
	c.ask(measurement(99, 100, 7))
	c.expectSilence("a fabricated answer to a measurement")
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["common_address"] >= 1
	}, "the refusal")
	if got := st.saw(wire.MMeNB1); len(got) != 0 {
		t.Error("a refused measurement reached the station")
	}
	// And a command is: the deception is for the activations.
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the fabricated confirmation"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a refused command was not confirmed: %+v", f.ASDU)
	}
}

// The test bit says a frame is part of a test of the transmission path and
// not a real operation, and a confirmation carries back the one it was
// given. A fabrication that dropped it would answer a test frame as though
// it were live traffic, which is a difference a control centre's own test
// facility looks at.
func TestTheFabricationKeepsTheTestBit(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// The cause octet's top bit is the test bit.
	c.ask(asdu(wire.CScNA1, 1, wire.CauseActivation|0x80, 1, 0xe1, 0x10, 0, 0x01))
	f := c.expect("the confirmation of a test command")
	if f.ASDU == nil {
		t.Fatal("no ASDU in the confirmation")
	}
	if !f.ASDU.Test {
		t.Error("the fabrication answered a test frame as live traffic")
	}
	if f.ASDU.Negative || f.ASDU.Cause != wire.CauseActCon {
		t.Errorf("the confirmation: %+v", f.ASDU)
	}
}
