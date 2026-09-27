package iec104_test

import (
	"strconv"
	"testing"

	wire "github.com/rom/xproxy/internal/iec104"
)

// numbering is what a conforming implementation does with the sequence
// numbers of the I frames it receives, and is the whole of why a refusal
// cannot be written as a copy of the frame it refuses.
//
// The reference implementation (mz-automation/lib60870,
// cs104_connection.c: "check the receive sequence number N(R) --
// connection will be closed on an unexpected value") closes the
// connection when a received I frame's send sequence number is not the
// one it was counting on. Its slave side does the same. So a relay that
// takes a frame out of one direction, or puts one in, has taken over the
// numbering of that direction whether it meant to or not.
//
// The control centre's side of this check lives in the shared harness, so
// that every test in this package makes it; this is the station's side.
type numbering struct {
	next uint16
}

// saw checks one arriving I frame.
func (n *numbering) saw(t *testing.T, what string, f *wire.Frame) {
	t.Helper()
	if f == nil || f.Format != wire.FormatI {
		return
	}
	if f.Send != n.next {
		t.Errorf("%s: N(S) = %d, the peer was counting on %d: a conforming "+
			"implementation closes the connection here", what, f.Send, n.next)
	}
	n.next = (n.next + 1) % wire.MaxSeq
}

// A refusal must not desynchronise either direction's numbering.
//
// The sequence: one allowed command, which the station confirms; one
// command the policy refuses, which the relay answers itself; then another
// allowed command. By the third the station has sent one I frame and the
// centre has received two, so any relay that passes the station's own
// numbering through has just told the centre to expect a number the
// station will not send for another frame -- and the centre drops the
// association, taking the substation's telemetry with it.
//
// The same arithmetic runs the other way: the refused command consumed one
// of the centre's numbers and never reached the station, so the next
// forwarded frame arrives at the station one ahead of what it expects.
func TestARefusalDoesNotDesynchroniseTheNumbering(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	c := dialCentre(t, addr)
	c.startdt()

	// Allowed: the station confirms it.
	c.ask(command(1, 4321, false, true))
	c.expect("the confirmation of the first command")

	// Refused: the relay answers, and the station never sees it.
	c.ask(command(1, 9999, false, true))
	c.expect("the refusal")

	// Allowed again: the station's own confirmation comes back up.
	c.ask(command(1, 4322, false, true))
	c.expect("the confirmation after a refusal")

	// And telemetry, which is what the link is for.
	st.send <- measurement(1, 100, 7)
	c.expect("telemetry after a refusal")

	// Now the other direction: what the station received must be
	// contiguous too, or the station closes the link.
	var toStation numbering
	st.mu.Lock()
	got := append([]*wire.Frame(nil), st.got...)
	st.mu.Unlock()
	for i, f := range got {
		toStation.saw(t, "the station's frame "+strconv.Itoa(i), f)
	}
}

// The sending window must be released by the acknowledgements that actually
// arrive, and most of them arrive on I frames rather than on supervisory
// ones: the standard's §5.5 lets a station piggyback N(R) on every frame it
// sends, and a station with data to send does exactly that rather than
// spending a frame on an S format.
//
// The number here is k + 1 with the standard's default k of 12: a control
// centre that issues thirteen commands in one association, each of them
// allowed and each of them confirmed by the station, is an ordinary
// afternoon in a control room.
func TestPiggybackedAcknowledgementsReleaseTheWindow(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        rules:
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	for i := 0; i < 13; i++ {
		c.ask(command(1, 4000+uint32(i), false, true))
		f := c.expect("confirmation " + strconv.Itoa(i))
		if f.ASDU == nil {
			t.Fatalf("confirmation %d: %+v", i, f)
		}
		if f.ASDU.Negative {
			t.Fatalf("command %d was refused, and the station had "+
				"acknowledged every frame before it", i)
		}
	}
	if got := len(st.saw(wire.CScNA1)); got != 13 {
		t.Errorf("the station saw %d of the 13 commands", got)
	}
}

// A station streaming telemetry with nothing travelling down must not run
// out of window.
//
// Its k frames outstanding are released by the acknowledgement this relay
// owes it, and on a quiet link there is no frame going the other way to
// carry one: the relay has to spend a supervisory frame at w. Thirteen
// measurements in a row with the standard's k of 12 is a substation with a
// busy afternoon, and a relay that refused the thirteenth would have
// blanked the control room's display and written "window" in the log.
func TestAStationStreamingTelemetryDoesNotRunOutOfWindow(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow`, st)

	c := dialCentre(t, addr)
	c.startdt()
	const frames = 13
	for i := 0; i < frames; i++ {
		st.send <- measurement(1, uint32(100+i), int16(i))
	}
	for i := 0; i < frames; i++ {
		f := c.expect("measurement " + strconv.Itoa(i))
		if f.ASDU == nil || f.ASDU.Type != wire.MMeNB1 {
			t.Fatalf("measurement %d: %+v", i, f)
		}
	}
	if n := s.Stats().Refusals["iec104"]["window"]; n != 0 {
		t.Errorf("the relay refused %d frames for want of a window", n)
	}
	// The station has been acknowledged, which is what let it keep
	// sending.
	if got := st.sawSupervisory(); got == 0 {
		t.Error("the relay never acknowledged the stream it was reading")
	}
}
