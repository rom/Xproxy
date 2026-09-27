package iec104_test

import (
	"encoding/binary"
	"testing"

	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/proxy"
)

// The value bound through the whole relay: what reaches the station, what
// the control centre is told, and what the counters say.
//
// A policy test can say the decision was right. Only a relay test can say
// the frame did not go past -- and on this protocol that is the whole
// question, because the equipment behind it will act on whatever arrives.

// setpoint builds a C_SE_NB_1: a scaled setpoint command, which is the one a
// substation point list uses for an engineering value.
func setpoint(common uint16, ioa uint32, val int16, sel bool) []byte {
	q := byte(0)
	if sel {
		q |= 0x80
	}
	var v [2]byte
	binary.LittleEndian.PutUint16(v[:], uint16(val))
	return asdu(wire.CSeNB1, 1, wire.CauseActivation, common,
		byte(ioa), byte(ioa>>8), byte(ioa>>16), v[0], v[1], q)
}

// A setpoint outside its bound never reaches the equipment, and the control
// centre is told so the way a station tells it: the same ASDU back with the
// negative-confirm bit set.
func TestASetpointOutsideItsBoundNeverReachesTheStation(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        setpoints:
          - {name: pressure, points: ["4711"], min: 0, max: 40}`, st)

	c := dialCentre(t, addr)
	c.startdt()

	// In range: it goes, and the station's own confirmation comes back.
	c.ask(setpoint(1, 4711, 20, false))
	if f := c.expect("the confirmation"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a setpoint inside its bound was refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CSeNB1); len(got) != 1 {
		t.Fatalf("the station saw %d setpoints, want 1", len(got))
	}

	// Out of range: refused, and nothing more arrives at the station.
	c.ask(setpoint(1, 4711, 900, false))
	if f := c.expect("the refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a setpoint of 900 where 0 to 40 is allowed was not refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CSeNB1); len(got) != 1 {
		t.Fatalf("a refused setpoint reached the station: %d frames", len(got))
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["setpoint_range"] >= 1 && sn.IEC104Setpoints >= 2
	}, "the setpoint range counter")
}

// A station's own report is not a command, so a value bound does not refuse
// it. An RTU that answers a setpoint with the value it actually applied --
// clamped by its own configuration, and outside the bound the relay holds --
// must reach the control centre: refusing the answer would leave the centre
// waiting for ever for a command this relay already let through, and hide
// from an operator the one number that says what the equipment did.
func TestAStationsOwnReportIsNotRefusedByAValueBound(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        setpoints:
          - {name: pressure, points: ["4711"], min: 0, max: 40}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// The station reports a value no command could have carried.
	st.send <- asduWithCause(wire.CSeNB1, wire.CauseActCon, 1, 4711, 900)
	f := c.expect("the station's report")
	if f.ASDU == nil || f.ASDU.Type != wire.CSeNB1 || f.ASDU.Negative {
		t.Fatalf("a station's report was refused by a value bound: %+v", f.ASDU)
	}
}

// asduWithCause builds a scaled setpoint ASDU with a cause of the caller's
// choosing, which is how a station's confirmation is spelled.
func asduWithCause(ty wire.Type, cause wire.Cause, common uint16, ioa uint32, val int16) []byte {
	var v [2]byte
	binary.LittleEndian.PutUint16(v[:], uint16(val))
	return asdu(ty, 1, cause, common, byte(ioa), byte(ioa>>8), byte(ioa>>16), v[0], v[1], 0)
}

// The delta is measured from the last value the relay saw, and what the
// relay saw is what it forwarded: so a control centre can nudge a setpoint
// and cannot jump it.
func TestASetpointMayBeNudgedAndNotJumped(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        setpoints:
          - {name: tap, points: ["4711"], min: 0, max: 40, max_delta: 5}`, st)

	c := dialCentre(t, addr)
	c.startdt()

	// The first command has nothing to measure from, and on_unknown's
	// default carries it with the range still in force.
	c.ask(setpoint(1, 4711, 20, false))
	if f := c.expect("the first setpoint"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("the first setpoint was refused: %+v", f.ASDU)
	}
	// A step inside the delta.
	c.ask(setpoint(1, 4711, 24, false))
	if f := c.expect("a step of four"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a step of four with max_delta 5 was refused: %+v", f.ASDU)
	}
	// And one outside it, from the value the relay now knows about.
	c.ask(setpoint(1, 4711, 40, false))
	if f := c.expect("the jump"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a jump of sixteen with max_delta 5 was not refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CSeNB1); len(got) != 2 {
		t.Fatalf("the station saw %d setpoints, want the two allowed", len(got))
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["setpoint_delta"] >= 1 && sn.IEC104SetpointPoints >= 1
	}, "the setpoint delta counter")
}

// on_unknown refuse holds a command to a point the relay has no value for,
// which is what an operator chooses when a setpoint must never be moved
// blind -- and the station's own report of the point is what unblocks it.
func TestOnUnknownRefuseHoldsTheFirstCommand(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        setpoints:
          - {name: tap, points: ["4711"], min: 0, max: 40, max_delta: 5, on_unknown: refuse}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(setpoint(1, 4711, 20, false))
	if f := c.expect("the first setpoint"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("on_unknown refuse carried a command to an unknown point: %+v", f.ASDU)
	}
	if got := st.saw(wire.CSeNB1); len(got) != 0 {
		t.Fatalf("a held setpoint reached the station: %d frames", len(got))
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["setpoint_unknown"] >= 1
	}, "the setpoint unknown counter")
}

// A selection carries the value, so the value is bounded at the selection:
// the station is never asked to hold a setpoint it may not be given.
func TestAnOutOfRangeSelectionIsRefusedBeforeTheStationHoldsIt(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        require_select: true
        setpoints:
          - {name: pressure, points: ["4711"], min: 0, max: 40}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(setpoint(1, 4711, 900, true))
	if f := c.expect("the refused selection"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("an out-of-range selection was not refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CSeNB1); len(got) != 0 {
		t.Fatalf("a refused selection reached the station: %d frames", len(got))
	}
	// And the refusal did not consume a selection: the two-step form still
	// holds afterwards, so an execute arriving alone is still unselected.
	c.ask(setpoint(1, 4711, 20, false))
	if f := c.expect("the execute"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("an execute rode on a selection that was refused: %+v", f.ASDU)
	}
}

// Shadow mode is a trial: the refusal is recorded and the frame goes on. A
// value bound that enforced while it was told to shadow would be a trial
// that tripped a substation.
func TestAValueBoundInShadowModeRecordsWithoutRefusing(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        setpoints:
          - {name: pressure, points: ["4711"], min: 0, max: 40}
      policy: {mode: shadow}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(setpoint(1, 4711, 900, false))
	if f := c.expect("the confirmation"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a shadowed bound refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CSeNB1); len(got) != 1 {
		t.Fatalf("a shadowed setpoint did not reach the station: %d frames", len(got))
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.IEC104WouldDeny >= 1
	}, "the shadow counter")
}
