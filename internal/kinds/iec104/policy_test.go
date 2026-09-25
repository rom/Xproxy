package iec104

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
)

// The matchers a rule is made of, driven directly. Each of them is a way an
// operator narrows a rule, and a matcher that silently matched everything
// would turn a narrow allow rule into a wide one -- which is the failure
// mode that does not look like a failure.

func policyOf(t *testing.T, l *config.IEC104Listener) *Policy {
	t.Helper()
	p, err := compile(l, func() time.Time { return time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// ask builds a decision request: one ASDU from one client.
func ask(client string, a *wire.ASDU) request {
	return request{client: netip.MustParseAddr(client), frame: &wire.Frame{Format: wire.FormatI, ASDU: a}}
}

func sc(common uint16, ioa uint32, cause wire.Cause, sel bool) *wire.ASDU {
	return &wire.ASDU{Type: wire.CScNA1, Objects: 1, Cause: cause, Common: common,
		Addresses: []uint32{ioa}, Select: sel, Qualifier: []byte{0x01}}
}

func TestARuleNarrowsByEveryFieldItNames(t *testing.T) {
	p := policyOf(t, &config.IEC104Listener{
		Rules: []config.IEC104Rule{{
			Name: "breakers", Action: "allow",
			Clients:         []string{"10.0.0.0/24"},
			CommonAddresses: []string{"1-2"},
			Originators:     []string{"7"},
			Types:           []string{"C_SC_NA_1"},
			Causes:          []string{"act"},
			Addresses:       []string{"4000-4999"},
		}},
	})
	good := sc(1, 4321, wire.CauseActivation, false)
	good.Originator = 7
	if d := p.Decide(ask("10.0.0.5", good)); !d.Allow || d.Rule != "breakers" {
		t.Fatalf("the rule did not match its own traffic: %+v", d)
	}
	// One field wrong at a time, and each must fall through to the
	// default deny. The client and the type are the two the sweep found
	// untested, and they are the two that matter most: a type list that
	// matched everything would let a reset process command through a rule
	// written for a breaker.
	for what, change := range map[string]func(*wire.ASDU) request{
		"another client":     func(a *wire.ASDU) request { return ask("10.0.1.5", a) },
		"another station":    func(a *wire.ASDU) request { a.Common = 9; return ask("10.0.0.5", a) },
		"another originator": func(a *wire.ASDU) request { a.Originator = 8; return ask("10.0.0.5", a) },
		"another type": func(a *wire.ASDU) request {
			a.Type = wire.CRpNA1 // reset process: reboot the station
			return ask("10.0.0.5", a)
		},
		"another cause":   func(a *wire.ASDU) request { a.Cause = wire.CauseActCon; return ask("10.0.0.5", a) },
		"another point":   func(a *wire.ASDU) request { a.Addresses = []uint32{9999}; return ask("10.0.0.5", a) },
		"no point at all": func(a *wire.ASDU) request { a.Addresses = nil; return ask("10.0.0.5", a) },
	} {
		a := sc(1, 4321, wire.CauseActivation, false)
		a.Originator = 7
		if d := p.Decide(change(a)); d.Allow {
			t.Errorf("%s still matched: %+v", what, d)
		}
	}
}

// The common address list on the listener is the estate boundary: a control
// centre that may address one substation and reaches ten is the commonest
// finding in this protocol.
func TestTheCommonAddressListIsABoundary(t *testing.T) {
	p := policyOf(t, &config.IEC104Listener{
		CommonAddresses: []string{"1", "10-12"},
		DefaultAction:   "allow",
	})
	for _, ca := range []uint16{1, 10, 11, 12} {
		if d := p.Decide(ask("10.0.0.5", sc(ca, 1, wire.CauseActivation, false))); !d.Allow {
			t.Errorf("station %d: %+v", ca, d)
		}
	}
	for _, ca := range []uint16{0, 2, 9, 13, 65535} {
		d := p.Decide(ask("10.0.0.5", sc(ca, 1, wire.CauseActivation, false)))
		if d.Allow || d.Reason != "iec104_common_address" {
			t.Errorf("station %d: %+v", ca, d)
		}
	}
	// It is checked before the rules and before default_action allow, so
	// a permissive listener still cannot reach a station it does not name.
	if d := p.Decide(ask("10.0.0.5", sc(500, 1, wire.CauseSpontaneous, false))); d.Allow {
		t.Errorf("a station outside the list was reached on telemetry: %+v", d)
	}
}

// The select and execute halves of a rule: how "this client may select
// anything and execute nothing" is written -- a four-eyes control where one
// operator arms and another fires.
func TestARuleCanNameOneHalfOfATwoStepCommand(t *testing.T) {
	p := policyOf(t, &config.IEC104Listener{
		Rules: []config.IEC104Rule{
			{Name: "arming", Action: "allow", Select: "select", Clients: []string{"10.0.0.1/32"}},
			{Name: "firing", Action: "allow", Select: "execute", Clients: []string{"10.0.0.2/32"}},
		},
	})
	// The arming operator may select and may not execute.
	if d := p.Decide(ask("10.0.0.1", sc(1, 7, wire.CauseActivation, true))); !d.Allow || d.Rule != "arming" {
		t.Errorf("the select: %+v", d)
	}
	if d := p.Decide(ask("10.0.0.1", sc(1, 7, wire.CauseActivation, false))); d.Allow {
		t.Errorf("the arming operator executed: %+v", d)
	}
	// And the firing operator the other way round.
	if d := p.Decide(ask("10.0.0.2", sc(1, 7, wire.CauseActivation, false))); !d.Allow || d.Rule != "firing" {
		t.Errorf("the execute: %+v", d)
	}
	if d := p.Decide(ask("10.0.0.2", sc(1, 7, wire.CauseActivation, true))); d.Allow {
		t.Errorf("the firing operator selected: %+v", d)
	}
	// A measurement has no select bit at all and is not an execute, so an
	// execute rule must not carry telemetry: that would make a rule about
	// operating equipment into a rule about everything.
	m := &wire.ASDU{Type: wire.MMeNB1, Objects: 1, Cause: wire.CauseSpontaneous, Common: 1, Addresses: []uint32{7}}
	if d := p.Decide(ask("10.0.0.2", m)); d.Allow {
		t.Errorf("an execute rule matched a measurement: %+v", d)
	}
}

// A control function list names pairs: naming an activation names its
// confirmation, or the station's reply would be refused and the control
// centre would wait for ever.
func TestNamingAControlActivationNamesItsConfirmation(t *testing.T) {
	p := policyOf(t, &config.IEC104Listener{AllowControls: []string{"STARTDT_act", "TESTFR_act"}})
	for _, c := range []wire.Control{wire.StartDTAct, wire.StartDTCon, wire.TestFRAct, wire.TestFRCon} {
		if d := p.Control(c); !d.Allow {
			t.Errorf("%s was refused although its pair is named: %+v", c, d)
		}
	}
	for _, c := range []wire.Control{wire.StopDTAct, wire.StopDTCon} {
		if d := p.Control(c); d.Allow {
			t.Errorf("%s was allowed although it is not named", c)
		}
	}
	// No list allows every function, which is what a listener without the
	// key has.
	none := policyOf(t, &config.IEC104Listener{})
	if d := none.Control(wire.StopDTAct); !d.Allow {
		t.Error("a listener with no list refused a control function")
	}
}

// A selection belongs to the connection that made it. A selection that
// outlived its connection would let a later client execute on an earlier
// one's intention, which is precisely the injection the check exists to
// stop.
func TestASelectionDiesWithItsConnection(t *testing.T) {
	now := time.Now()
	s := newSelects(16, time.Minute, func() time.Time { return now })
	a := sc(1, 4321, wire.CauseActivation, true)

	if !s.Select(1, a) {
		t.Fatal("the selection was not recorded")
	}
	if held, _ := s.Status(); held != 1 {
		t.Fatalf("held %d", held)
	}
	// Another connection cannot take it, even for the same point on the
	// same station.
	if s.Take(2, a) {
		t.Error("another connection consumed a selection")
	}
	// And when the connection that made it ends, it is gone.
	s.Close(1)
	if held, _ := s.Status(); held != 0 {
		t.Errorf("a closed connection left %d selections", held)
	}
	if s.Take(1, a) {
		t.Error("a selection survived its connection")
	}

	// The window expires, which is what stops an execute sent hours later
	// riding on a selection somebody thought better of.
	s2 := newSelects(16, 30*time.Second, func() time.Time { return now })
	if !s2.Select(1, a) {
		t.Fatal("select")
	}
	now = now.Add(31 * time.Second)
	if s2.Take(1, a) {
		t.Error("an expired selection was consumed")
	}

	// The bound refuses rather than forgetting silently, and a sweep of
	// what has expired comes first: a full table is usually a table full
	// of selections nobody executed.
	now = time.Now()
	s3 := newSelects(2, time.Minute, func() time.Time { return now })
	for i := uint32(1); i <= 2; i++ {
		if !s3.Select(1, sc(1, i, wire.CauseActivation, true)) {
			t.Fatalf("select %d", i)
		}
	}
	if s3.Select(1, sc(1, 3, wire.CauseActivation, true)) {
		t.Error("the bound was not a bound")
	}
	if _, dropped := s3.Status(); dropped != 1 {
		t.Errorf("dropped %d", dropped)
	}
	now = now.Add(2 * time.Minute)
	if !s3.Select(1, sc(1, 3, wire.CauseActivation, true)) {
		t.Error("a table full of expired selections stayed full")
	}
	// A command naming no point cannot be selected: there is nothing to
	// key a selection on, and inventing one would let any execute match.
	if s3.Select(1, &wire.ASDU{Type: wire.CScNA1, Cause: wire.CauseActivation}) {
		t.Error("a command with no address was selected")
	}
	// A nil-safe status, which is what a listener without the section has.
	var nilSel *selects
	if held, dropped := nilSel.Status(); held != 0 || dropped != 0 {
		t.Error("a nil table holds selections")
	}
}

// A schedule limits a rule to a window, and a window whose end is before
// its start spans midnight, which is how a night shift is written.
func TestARuleCanBeLimitedToAWindow(t *testing.T) {
	at := func(h, m int) *Policy {
		p, err := compile(&config.IEC104Listener{
			Rules: []config.IEC104Rule{{Name: "shift", Action: "allow",
				Schedule: &config.ModbusSchedule{Days: []string{"wed"}, From: "08:00", To: "17:00"}}},
		}, func() time.Time { return time.Date(2026, 3, 4, h, m, 0, 0, time.UTC) }) // a Wednesday
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return p
	}
	a := sc(1, 7, wire.CauseActivation, false)
	if d := at(9, 0).Decide(ask("10.0.0.1", a)); !d.Allow {
		t.Errorf("inside the shift: %+v", d)
	}
	for _, when := range [][2]int{{7, 59}, {17, 0}, {23, 0}} {
		if d := at(when[0], when[1]).Decide(ask("10.0.0.1", a)); d.Allow {
			t.Errorf("%02d:%02d is outside the shift and matched", when[0], when[1])
		}
	}
	// A night shift, which is the window the arithmetic gets wrong.
	night, err := compile(&config.IEC104Listener{
		Rules: []config.IEC104Rule{{Name: "night", Action: "allow",
			Schedule: &config.ModbusSchedule{From: "22:00", To: "06:00"}}},
	}, func() time.Time { return time.Date(2026, 3, 4, 2, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	if d := night.Decide(ask("10.0.0.1", a)); !d.Allow {
		t.Errorf("02:00 is inside a 22:00-06:00 window: %+v", d)
	}
}

// observe is what an operator uses to try a rule on live traffic before it
// decides anything: the frame is recorded and the search carries on.
func TestAnObserveRuleDecidesNothing(t *testing.T) {
	p := policyOf(t, &config.IEC104Listener{
		Rules: []config.IEC104Rule{
			{Name: "watching", Action: "observe", Types: []string{"C_SC_NA_1"}},
			{Name: "refusing", Action: "deny", Types: []string{"C_SC_NA_1"}},
		},
	})
	d := p.Decide(ask("10.0.0.1", sc(1, 7, wire.CauseActivation, false)))
	if d.Allow || d.Rule != "refusing" {
		t.Errorf("the observe rule decided: %+v", d)
	}
}

// The acknowledgement check: a station whose receive sequence number
// acknowledges frames nobody sent is either a confused implementation or
// something trying to open the sending window, which is how a flood gets
// past the window bound.
func TestAnAcknowledgementCannotRunAheadOfWhatWasSent(t *testing.T) {
	var sender, receiver seqState

	// Three frames go out from the sender.
	for i := uint16(0); i < 3; i++ {
		if reason := sender.observe(i, 12); reason != "" {
			t.Fatalf("frame %d: %s", i, reason)
		}
	}
	// The peer acknowledges all three, which is what releases the window.
	if reason := receiver.acknowledge(3, sender.sent); reason != "" {
		t.Errorf("an honest acknowledgement: %s", reason)
	}
	// And acknowledging the same number again releases nothing more, which
	// must not be an error: a station repeats its receive sequence number
	// on every frame it sends.
	if reason := receiver.acknowledge(3, sender.sent); reason != "" {
		t.Errorf("a repeated acknowledgement: %s", reason)
	}
	// Now one past what was ever sent.
	if reason := receiver.acknowledge(4, sender.sent); reason != "iec104_ack_ahead" {
		t.Errorf("an acknowledgement of a frame nobody sent: %q", reason)
	}

	// The window bound: with k frames outstanding and none acknowledged,
	// the next one is one too many. This is what a flood looks like on
	// this protocol -- a station that has stopped listening to the
	// acknowledgements and keeps sending.
	var flood seqState
	for i := uint16(0); i < 4; i++ {
		if reason := flood.observe(i, 4); reason != "" {
			t.Fatalf("frame %d inside the window: %s", i, reason)
		}
	}
	if reason := flood.observe(4, 4); reason != "iec104_window" {
		t.Errorf("the frame past the window: %q", reason)
	}
	// With the window switched off (k = 0) the same traffic is carried,
	// which is what max_unacknowledged: false asks for.
	var unbounded seqState
	for i := uint16(0); i < 20; i++ {
		if reason := unbounded.observe(i, 0); reason != "" {
			t.Fatalf("frame %d without a window: %s", i, reason)
		}
	}

	// A gap is one refusal and the state moves to what arrived, so a
	// single lost frame does not take a substation off the air.
	var lossy seqState
	if reason := lossy.observe(0, 12); reason != "" {
		t.Fatal(reason)
	}
	if reason := lossy.observe(5, 12); reason != "iec104_sequence" {
		t.Errorf("a gap: %q", reason)
	}
	if reason := lossy.observe(6, 12); reason != "" {
		t.Errorf("the frame after the gap: %q", reason)
	}

	// The sequence space wraps at 15 bits, and the wrap is not a gap: a
	// link that has been up long enough reaches it, and a relay that
	// refused there would take the substation off the air on a timer.
	var wrapping seqState
	if reason := wrapping.observe(wire.MaxSeq-1, 12); reason != "" {
		t.Fatal(reason)
	}
	if reason := wrapping.observe(0, 12); reason != "" {
		t.Errorf("the wrap to 0: %q", reason)
	}

	// An acknowledgement that wraps releases the right number of frames
	// rather than a negative one: the arithmetic is modular, and a
	// subtraction that went negative would report every wrap as an
	// acknowledgement of frames nobody sent.
	var wrapAck seqState
	wrapAck.acked = wire.MaxSeq - 2
	if reason := wrapAck.acknowledge(1, 3); reason != "" {
		t.Errorf("an acknowledgement across the wrap: %q", reason)
	}
	if wrapAck.ackedCount != 3 {
		t.Errorf("released %d frames across the wrap, want 3", wrapAck.ackedCount)
	}
}
