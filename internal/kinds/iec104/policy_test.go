package iec104

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
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
	one := selectOwner{session: 1}
	two := selectOwner{session: 2}

	if !s.Select(one, a) {
		t.Fatal("the selection was not recorded")
	}
	if held, _ := s.Status(); held != 1 {
		t.Fatalf("held %d", held)
	}
	// Another connection cannot take it, even for the same point on the
	// same station -- and with no redundancy group in the picture, what it
	// is told is that the point was never selected.
	if took := s.Take(two, a); took != TakeNone {
		t.Errorf("another connection consumed a selection: %v", took)
	}
	// And when the connection that made it ends, it is gone.
	s.Close(1, "")
	if held, _ := s.Status(); held != 0 {
		t.Errorf("a closed connection left %d selections", held)
	}
	if took := s.Take(one, a); took != TakeNone {
		t.Errorf("a selection survived its connection: %v", took)
	}

	// The window expires, which is what stops an execute sent hours later
	// riding on a selection somebody thought better of -- and the refusal
	// says so rather than saying the point was never selected.
	s2 := newSelects(16, 30*time.Second, func() time.Time { return now })
	if !s2.Select(one, a) {
		t.Fatal("select")
	}
	now = now.Add(31 * time.Second)
	if took := s2.Take(one, a); took != TakeExpired {
		t.Errorf("an expired selection was %v", took)
	}

	// The bound refuses rather than forgetting silently, and a sweep of
	// what has expired comes first: a full table is usually a table full
	// of selections nobody executed.
	now = time.Now()
	s3 := newSelects(2, time.Minute, func() time.Time { return now })
	for i := uint32(1); i <= 2; i++ {
		if !s3.Select(one, sc(1, i, wire.CauseActivation, true)) {
			t.Fatalf("select %d", i)
		}
	}
	if s3.Select(one, sc(1, 3, wire.CauseActivation, true)) {
		t.Error("the bound was not a bound")
	}
	if _, dropped := s3.Status(); dropped != 1 {
		t.Errorf("dropped %d", dropped)
	}
	now = now.Add(2 * time.Minute)
	if !s3.Select(one, sc(1, 3, wire.CauseActivation, true)) {
		t.Error("a table full of expired selections stayed full")
	}
	// A command naming no point cannot be selected: there is nothing to
	// key a selection on, and inventing one would let any execute match.
	if s3.Select(one, &wire.ASDU{Type: wire.CScNA1, Cause: wire.CauseActivation}) {
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

// The relay's own end of the numbering, driven directly.
//
// What the relay writes to a peer is numbered by the relay, because the
// stream it writes is not the stream it read: it refuses frames, which
// leaves a hole, and it answers some itself, which adds one. An end handed
// a stream with a hole in it closes the association.
func TestTheRelayNumbersTheStreamItWrites(t *testing.T) {
	var e endpoint
	out := pipeInto(t, &e)

	// Two frames arrive from this peer, so the relay owes it an
	// acknowledgement of two.
	if reason := e.arrived(0, 12); reason != "" {
		t.Fatal(reason)
	}
	if reason := e.arrived(1, 12); reason != "" {
		t.Fatal(reason)
	}
	// Three frames written to it, each carrying numbers the caller got
	// wrong on purpose: the send sequence number is the relay's own count
	// and the receive sequence number is what it has read.
	for i := 0; i < 3; i++ {
		if err := e.writeI(iframe(999, 999, singlePoint()...)); err != nil {
			t.Fatal(err)
		}
		f := next(t, out, "frame "+strconv.Itoa(i))
		if f.Format != wire.FormatI {
			t.Fatalf("frame %d came out as %s", i, f.Format)
		}
		if int(f.Send) != i {
			t.Errorf("frame %d went out numbered %d", i, f.Send)
		}
		if f.Recv != 2 {
			t.Errorf("frame %d acknowledged %d of the two that arrived", i, f.Recv)
		}
	}

	// A supervisory frame is owed only when something is unacknowledged.
	if err := e.writeS(); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-out:
		t.Fatalf("an acknowledgement nothing was owed: %s %d", f.Format, f.Recv)
	case <-time.After(50 * time.Millisecond):
	}
	if reason := e.arrived(2, 12); reason != "" {
		t.Fatal(reason)
	}
	if err := e.writeS(); err != nil {
		t.Fatal(err)
	}
	if f := next(t, out, "the acknowledgement"); f.Format != wire.FormatS || f.Recv != 3 {
		t.Errorf("the acknowledgement was %s of %d, want S of 3", f.Format, f.Recv)
	}
}

// The acknowledgement check: a peer whose receive sequence number
// acknowledges frames nobody wrote to it is either a confused
// implementation or something trying to open the sending window, which is
// how a flood gets past the window bound.
func TestAnAcknowledgementCannotRunAheadOfWhatWasSent(t *testing.T) {
	var e endpoint
	out := pipeInto(t, &e)

	// Three frames go out to this peer.
	for i := 0; i < 3; i++ {
		if err := e.writeI(iframe(0, 0, singlePoint()...)); err != nil {
			t.Fatal(err)
		}
		next(t, out, "frame "+strconv.Itoa(i))
	}
	// The peer acknowledges all three, which is what releases the window.
	if reason := e.acknowledged(3); reason != "" {
		t.Errorf("an honest acknowledgement: %s", reason)
	}
	// And acknowledging the same number again releases nothing more, which
	// must not be an error: an end repeats its receive sequence number on
	// every frame it sends.
	if reason := e.acknowledged(3); reason != "" {
		t.Errorf("a repeated acknowledgement: %s", reason)
	}
	// Now one past what was ever written to it.
	if reason := e.acknowledged(4); reason != "iec104_ack_ahead" {
		t.Errorf("an acknowledgement of a frame nobody sent: %q", reason)
	}

	// The window bound: with k frames outstanding and none of them
	// acknowledged, the next one is one too many. This is what a flood
	// looks like on this protocol -- an end that has stopped listening to
	// the acknowledgements and keeps sending.
	var flood endpoint
	for i := uint16(0); i < 4; i++ {
		if reason := flood.arrived(i, 4); reason != "" {
			t.Fatalf("frame %d inside the window: %s", i, reason)
		}
	}
	if reason := flood.arrived(4, 4); reason != "iec104_window" {
		t.Errorf("the frame past the window: %q", reason)
	}
	// And the acknowledgement the relay owes releases it, which is why an
	// honest peer never reaches the bound: w is below k.
	floodOut := pipeInto(t, &flood)
	if err := flood.writeS(); err != nil {
		t.Fatal(err)
	}
	next(t, floodOut, "the window-releasing acknowledgement")
	if reason := flood.arrived(5, 4); reason != "" {
		t.Errorf("the frame after the acknowledgement: %q", reason)
	}

	// With the window switched off (k = 0) the same traffic is carried,
	// which is what max_unacknowledged: false asks for.
	var unbounded endpoint
	for i := uint16(0); i < 20; i++ {
		if reason := unbounded.arrived(i, 0); reason != "" {
			t.Fatalf("frame %d without a window: %s", i, reason)
		}
	}

	// A gap is one refusal and the state moves to what arrived, so a
	// single lost frame does not take a substation off the air.
	var lossy endpoint
	if reason := lossy.arrived(0, 12); reason != "" {
		t.Fatal(reason)
	}
	if reason := lossy.arrived(5, 12); reason != "iec104_sequence" {
		t.Errorf("a gap: %q", reason)
	}
	if reason := lossy.arrived(6, 12); reason != "" {
		t.Errorf("the frame after the gap: %q", reason)
	}

	// The sequence space wraps at 15 bits, and the wrap is not a gap: a
	// link that has been up long enough reaches it, and a relay that
	// refused there would take the substation off the air on a timer.
	var wrapping endpoint
	if reason := wrapping.arrived(wire.MaxSeq-1, 12); reason != "" {
		t.Fatal(reason)
	}
	if reason := wrapping.arrived(0, 12); reason != "" {
		t.Errorf("the wrap to 0: %q", reason)
	}

	// An acknowledgement that wraps releases the right number of frames
	// rather than a negative one: the arithmetic is modular, and a
	// subtraction that went negative would report every wrap as an
	// acknowledgement of frames nobody sent.
	wrapAck := endpoint{acked: wire.MaxSeq - 2, sent: 3}
	if reason := wrapAck.acknowledged(1); reason != "" {
		t.Errorf("an acknowledgement across the wrap: %q", reason)
	}
	if wrapAck.ackedCount != 3 {
		t.Errorf("released %d frames across the wrap, want 3", wrapAck.ackedCount)
	}
}

// next reads one frame the endpoint wrote, or fails.
//
// Bounded on purpose: a bare receive here turns "the endpoint wrote
// nothing" into a test that hangs until the package timeout, which is a
// worse way to learn it than a line saying so.
func next(t *testing.T, out <-chan *wire.Frame, what string) *wire.Frame {
	t.Helper()
	select {
	case f, ok := <-out:
		if !ok {
			t.Fatalf("%s: the endpoint's connection closed", what)
		}
		return f
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: the endpoint wrote nothing", what)
		return nil
	}
}

// pipeInto gives an endpoint somewhere to write and returns what comes out
// of it, parsed.
func pipeInto(t *testing.T, e *endpoint) <-chan *wire.Frame {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	e.conn = a
	out := make(chan *wire.Frame, 8)
	go func() {
		rd := wire.NewReader(b)
		for {
			f, err := rd.ReadFrame()
			if err != nil {
				close(out)
				return
			}
			out <- f
		}
	}()
	return out
}

// singlePoint is the smallest honest ASDU: one single point, spontaneous,
// for common address 1 and information object 1.
func singlePoint() []byte {
	return []byte{byte(wire.MSpNA1), 1, byte(wire.CauseSpontaneous), 0, 1, 0, 1, 0, 0, 0x01}
}

// iframe builds an I frame with the numbers a caller chose, which the
// endpoint then overwrites with its own.
func iframe(send, recv uint16, asdu ...byte) []byte {
	var c [4]byte
	binary.LittleEndian.PutUint16(c[0:2], send<<1)
	binary.LittleEndian.PutUint16(c[2:4], recv<<1)
	out := []byte{wire.Start, byte(4 + len(asdu)), c[0], c[1], c[2], c[3]}
	return append(out, asdu...)
}

// A peer whose numbering does not start at zero is acknowledged with the
// number it is waiting for, not with a count of what arrived.
//
// The two are the same on almost every association, because the standard
// resets both counters when the connection is established -- which is why
// getting this wrong would go unnoticed until the one station that starts
// somewhere else. The numbering survives a STOPDT and a STARTDT, so a
// gateway that reconnects mid-sequence can and does open with a number of
// its own, and an end acknowledged with "one frame" when it is waiting to
// hear "up to six" keeps its window shut.
func TestAnEndIsAcknowledgedWithTheNumberItWaitsFor(t *testing.T) {
	var e endpoint
	out := pipeInto(t, &e)
	if reason := e.arrived(5, 12); reason != "" {
		t.Fatal(reason)
	}
	if err := e.writeS(); err != nil {
		t.Fatal(err)
	}
	if f := next(t, out, "the acknowledgement"); f.Recv != 6 {
		t.Errorf("acknowledged %d, and the peer is waiting to hear 6", f.Recv)
	}
}

// An APDU shorter than the control information has nowhere to carry a
// sequence number, and stamping one would write outside its buffer.
func TestAnImpossiblyShortAPDUIsNotStamped(t *testing.T) {
	var e endpoint
	_ = pipeInto(t, &e)
	if err := e.writeI([]byte{wire.Start, 1, 0}); err == nil {
		t.Error("a three-octet APDU was numbered and sent")
	}
}

// A peer that stops reading is a write that never returns, and a pump
// blocked in a write holds the session for ever: the idle timeout is a read
// deadline and never fires on a writer. So a write is bounded too, and the
// error ends the session the way any other write error does.
func TestAPeerThatStopsReadingDoesNotHoldTheSession(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	var e endpoint
	// Nobody reads b, and a pipe carries nothing until somebody does.
	e.attach(a, 50*time.Millisecond)
	err := e.writeI(iframe(0, 0, singlePoint()...))
	if err == nil {
		t.Fatal("a write to a peer that never read returned no error")
	}
	var timeout interface{ Timeout() bool }
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Errorf("the write failed with %v, and it should have timed out", err)
	}
}
