package iec104_test

import (
	"encoding/binary"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/proxy"
)

// The information element, policed.
//
// Two postures pull in opposite directions here, and every case below is about
// which one applies. Telemetry is alerted on and carried, because a relay that
// refused it would blind a control room. A command's timestamp is refused,
// because a command forwarded so that its age could be written down is a moved
// actuator.

// timedCommand builds a C_SC_TA_1: a single command with a CP56Time2a, which is
// the shape whose replay this relay can notice.
func timedCommand(common uint16, ioa uint32, on bool, at time.Time) []byte {
	q := byte(0)
	if on {
		q |= 0x01
	}
	body := []byte{byte(ioa), byte(ioa >> 8), byte(ioa >> 16), q}
	body = wire.AppendCP56Time2a(body, at)
	return asdu(wire.CScTA1, 1, wire.CauseActivation, common, body...)
}

// measuredWithQuality builds a scaled measurement carrying a quality
// descriptor.
func measuredWithQuality(common uint16, ioa uint32, value int16, q wire.Quality) []byte {
	var v [2]byte
	binary.LittleEndian.PutUint16(v[:], uint16(value)) //nolint:gosec // the standard's signed encoding
	return asdu(wire.MMeNB1, 1, wire.CauseSpontaneous, common,
		byte(ioa), byte(ioa>>8), byte(ioa>>16), v[0], v[1], byte(q))
}

const timedRules = `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_TA_1, C_SC_NA_1], addresses: ["4000-4999"]}
`

// A command carrying a timestamp an hour old is a replay, and the whole reason
// the check exists: nothing in IEC 60870-5-104 makes a station compare the
// timestamp against its clock, so a recorded breaker command sent again opens the
// breaker again.
func TestAStaleCommandNeverReachesTheStation(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, timedRules+`        timestamps: {max_command_age: 30s}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(timedCommand(1, 4321, true, time.Now().UTC().Add(-time.Hour)))
	f := c.expect("the negative confirmation")
	if f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a replayed command should be refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScTA1); len(got) != 0 {
		t.Fatalf("a replayed command reached the station: %+v", got[0].ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["command_timestamp_old"] >= 1
	}, "the stale command")
}

// And a fresh one goes through, which is the half that says the check is a check
// rather than a wall.
func TestAFreshTimedCommandReachesTheStation(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, timedRules+`        timestamps: {max_command_age: 30s, max_command_future: 5s}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(timedCommand(1, 4321, true, time.Now().UTC()))
	f := c.expect("the command confirmation")
	if f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a fresh command should go through: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScTA1); len(got) != 1 {
		t.Fatalf("the station saw %d commands", len(got))
	}
}

// A command from the future is the same replay with the clocks the other way
// round.
func TestACommandFromTheFutureIsRefused(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, timedRules+`        timestamps: {max_command_future: 5s}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(timedCommand(1, 4321, true, time.Now().UTC().Add(time.Hour)))
	if f := c.expect("the negative confirmation"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a command from the future should be refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScTA1); len(got) != 0 {
		t.Fatal("a command from the future reached the station")
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["command_timestamp_future"] >= 1
	}, "the command from the future")
}

// A timestamp whose sender disclaims it is not compared: an age computed from a
// timestamp its own station says is untrustworthy is arithmetic on nothing. And
// `deny_invalid` is how an estate says that is not good enough.
func TestAnInvalidTimestampIsNotComparedUnlessAsked(t *testing.T) {
	stale := func() []byte {
		b := timedCommand(1, 4321, true, time.Now().UTC().Add(-time.Hour))
		// The IV bit lives in the minute octet of the tag, which follows the
		// address and the qualifier: six header octets, three of address, one of
		// qualifier, then two of milliseconds.
		b[6+3+1+2] |= 0x80
		return b
	}

	t.Run("not compared", func(t *testing.T) {
		st := startStation(t, &station{})
		_, addr := iec104Server(t, timedRules+`        timestamps: {max_command_age: 30s}`, st)
		c := dialCentre(t, addr)
		c.startdt()
		c.ask(stale())
		if f := c.expect("the confirmation"); f.ASDU == nil || f.ASDU.Negative {
			t.Fatalf("an hour-old timestamp its sender disclaims was aged anyway: %+v", f.ASDU)
		}
		if got := st.saw(wire.CScTA1); len(got) != 1 {
			t.Fatalf("the station saw %d commands", len(got))
		}
	})

	t.Run("refused when asked", func(t *testing.T) {
		st := startStation(t, &station{})
		s, addr := iec104Server(t, timedRules+`        timestamps: {deny_invalid: true}`, st)
		c := dialCentre(t, addr)
		c.startdt()
		c.ask(stale())
		if f := c.expect("the negative confirmation"); f.ASDU == nil || !f.ASDU.Negative {
			t.Fatalf("deny_invalid did not refuse it: %+v", f.ASDU)
		}
		if got := st.saw(wire.CScTA1); len(got) != 0 {
			t.Fatal("a command whose clock its station disclaims reached the station")
		}
		await(t, s, func(sn proxy.Snapshot) bool {
			return sn.Refusals["iec104"]["command_timestamp_invalid"] >= 1
		}, "the disclaimed timestamp")
	})
}

// A command type with no time tag has no timestamp for the policy to be about.
// require_on_commands must not refuse C_SC_NA_1, which carries none by
// definition -- an estate that wants every command timestamped says so by not
// allowing the untagged types.
func TestRequireOnCommandsDoesNotRefuseAnUntaggedType(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, timedRules+`        timestamps: {require_on_commands: true}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the confirmation"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("an untagged command was refused for having no tag: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Fatalf("the station saw %d commands", len(got))
	}
}

// A time-tagged command whose timestamp will not decode has none to offer, and
// require_on_commands is what that is for.
func TestRequireOnCommandsRefusesAnUnreadableTimestamp(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, timedRules+`        timestamps: {require_on_commands: true}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	b := timedCommand(1, 4321, true, time.Now().UTC())
	b[6+3+1+5] = 13 // month 13, which is no month at all
	c.ask(b)
	if f := c.expect("the negative confirmation"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("an unreadable timestamp was accepted: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScTA1); len(got) != 0 {
		t.Fatal("a command with an unreadable timestamp reached the station")
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["command_timestamp_missing"] >= 1
	}, "the unreadable timestamp")
}

// A substituted reading is alerted on and *carried*. This is the posture for
// telemetry: an operator is told, and the control room still sees the reading.
func TestASubstitutedReadingIsAlertedOnAndCarried(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measuredWithQuality(1, 100, 1234, wire.QualitySubstituted)
	f := c.expect("the measurement")
	if f.ASDU == nil || f.ASDU.Type != wire.MMeNB1 {
		t.Fatalf("the reading did not reach the centre: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["quality"] >= 1
	}, "the substituted reading")
}

// An ordinary reading is not alerted on. A listener that raised something for
// every measurement would teach an operator to ignore it.
func TestAGoodReadingRaisesNothing(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measuredWithQuality(1, 100, 1234, 0)
	c.expect("the measurement")
	// Nothing to wait for, so the assertion is that the counter stayed empty
	// after the frame has certainly been through: the next frame's arrival is
	// the fence.
	st.send <- measuredWithQuality(1, 101, 1235, 0)
	c.expect("the second measurement")
	if n := s.Stats().Refusals["iec104"]["quality"]; n != 0 {
		t.Errorf("a good reading raised %d quality events", n)
	}
}

// `deny` is for the estate that has decided a bit is not acceptable, and it is a
// soft refusal so monitor mode carries it.
func TestAQualityBitNamedInDenyRefusesTheFrame(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        quality: {deny: [substituted]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measuredWithQuality(1, 100, 1234, wire.QualitySubstituted)
	// The frame is refused, so nothing arrives. A good reading after it does,
	// which is the fence that says the first was dropped rather than delayed.
	st.send <- measuredWithQuality(1, 101, 1235, 0)
	f := c.expect("the good measurement")
	if f.ASDU == nil || f.ASDU.Addresses[0] != 101 {
		t.Fatalf("the substituted reading was carried anyway: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["quality"] >= 1
	}, "the refused reading")
}

// A reported value outside its bound: a pressure of 900 bar on a 40 bar
// transmitter is a broken instrument or a forged frame, and either way an
// operator should be told.
func TestAMeasurementOutsideItsBoundIsAlertedOn(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        measurements:
          - {name: pressure, points: ["100-140"], min: 0, max: 40}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measurement(1, 100, 900)
	f := c.expect("the measurement")
	if f.ASDU == nil || f.ASDU.Addresses[0] != 100 {
		t.Fatalf("the reading did not reach the centre: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["measurement_range"] >= 1
	}, "the implausible reading")
}

// A point no bound covers is not decided here at all, and a value inside its
// bound raises nothing.
func TestAMeasurementInsideItsBoundRaisesNothing(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        measurements:
          - {name: pressure, points: ["100-140"], min: 0, max: 40}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measurement(1, 100, 21) // inside
	c.expect("the in-range measurement")
	st.send <- measurement(1, 900, 5000) // a point no bound covers
	c.expect("the uncovered measurement")
	if n := s.Stats().Refusals["iec104"]["measurement_range"]; n != 0 {
		t.Errorf("an in-range or uncovered reading raised %d events", n)
	}
}

// `action: deny` refuses the frame, and is what an estate writes when a value
// that cannot be true is worse than a gap in the trend.
func TestAMeasurementBoundCanRefuse(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        measurements:
          - {name: pressure, points: ["100-140"], min: 0, max: 40, action: deny}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measurement(1, 100, 900)
	st.send <- measurement(1, 900, 5000) // uncovered, so it is carried
	f := c.expect("the uncovered measurement")
	if f.ASDU == nil || f.ASDU.Addresses[0] != 900 {
		t.Fatalf("the out-of-range reading was carried anyway: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["measurement_range"] >= 1
	}, "the refused reading")
}

// A station's own confirmation of a command is never checked against the
// timestamp policy: it carries the same type and the same timestamp, and
// refusing it would leave a control centre waiting for the answer to a command
// this relay already let through.
func TestAStationsConfirmationIsNotAgeChecked(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, timedRules+`        timestamps: {max_command_age: 30s}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// The station spontaneously sends a confirmation carrying an old timestamp,
	// which is what an RTU catching up after a communications outage does.
	old := timedCommand(1, 4321, true, time.Now().UTC().Add(-time.Hour))
	old[2] = byte(wire.CauseActCon)
	st.send <- old
	f := c.expect("the confirmation")
	if f.ASDU == nil || f.ASDU.Type != wire.CScTA1 {
		t.Fatalf("the station's confirmation did not reach the centre: %+v", f.ASDU)
	}
}

// twoMeasurements builds one ASDU carrying two scaled measurements, so a test
// can put the interesting one second.
func twoMeasurements(common uint16, a1 uint32, v1 int16, a2 uint32, v2 int16) []byte {
	enc := func(ioa uint32, v int16) []byte {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(v)) //nolint:gosec // the standard's signed encoding
		return []byte{byte(ioa), byte(ioa >> 8), byte(ioa >> 16), b[0], b[1], 0x00}
	}
	body := append(enc(a1, v1), enc(a2, v2)...)
	return asdu(wire.MMeNB1, 2, wire.CauseSpontaneous, common, body...)
}

// Every object of an ASDU is checked, not only the first. A report carrying
// forty measurements carries forty chances for one of them to be the bad one, and
// a check that read only the first would be one a station could evade by ordering
// its report.
func TestASecondObjectIsCheckedToo(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        measurements:
          - {name: pressure, points: ["100-140"], min: 0, max: 40}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// The first reading is fine and the second is not.
	st.send <- twoMeasurements(1, 100, 21, 101, 900)
	c.expect("the report")
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["measurement_range"] >= 1
	}, "the bad reading behind a good one")
}

// The bound is inclusive at both ends, which is what "between 0 and 40" means to
// the engineer who wrote it.
func TestAMeasurementBoundIsInclusive(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        measurements:
          - {name: pressure, points: ["100-140"], min: 0, max: 40}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measurement(1, 100, 0)  // exactly min
	st.send <- measurement(1, 101, 40) // exactly max
	c.expect("the low reading")
	c.expect("the high reading")
	if n := s.Stats().Refusals["iec104"]["measurement_range"]; n != 0 {
		t.Errorf("a reading at the bound raised %d events", n)
	}
}

// A measurement bound is about what a station reports and never about what a
// control centre commands, even when the bound names no types and so covers
// anything. What a command may carry is `setpoints`, which has a memory and a
// delta; a measurement bound reaching a setpoint would refuse commands under a
// name nobody would look for.
func TestAMeasurementBoundDoesNotReachASetpointCommand(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: setpoints, action: allow, types: [C_SE_NB_1], addresses: ["5000-5009"]}
        measurements:
          - {name: anything, points: ["0-16777215"], min: 0, max: 40}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// A scaled setpoint of 900, which is outside the measurement bound and which
	// no setpoint bound covers.
	var v [2]byte
	binary.LittleEndian.PutUint16(v[:], 900)
	c.ask(asdu(wire.CSeNB1, 1, wire.CauseActivation, 1,
		0x88, 0x13, 0x00, v[0], v[1], 0x00))
	f := c.expect("the confirmation")
	if f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a setpoint was refused by a measurement bound: %+v", f.ASDU)
	}
	if got := st.saw(wire.CSeNB1); len(got) != 1 {
		t.Fatalf("the station saw %d setpoints", len(got))
	}
	if n := s.Stats().Refusals["iec104"]["measurement_range"]; n != 0 {
		t.Errorf("a measurement bound raised %d events about a command", n)
	}
}

// A timestamp refusal is hard: **shadow mode does not carry it**, for the same
// reason it does not carry the integrity checks. A replayed command forwarded so
// that its age could be written down is a moved actuator, and a report afterwards
// undoes none of it.
func TestShadowModeStillRefusesAReplay(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, timedRules+`        timestamps: {max_command_age: 30s}
      policy: {mode: shadow}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(timedCommand(1, 4321, true, time.Now().UTC().Add(-time.Hour)))
	if f := c.expect("the negative confirmation"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("shadow mode carried a replayed command: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScTA1); len(got) != 0 {
		t.Fatal("shadow mode let a replayed command reach the station")
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["command_timestamp_old"] >= 1
	}, "the replay under shadow mode")
}

// And shadow mode does carry a quality refusal, which is the other half of the
// asymmetry: telemetry is exactly what an operator wants to find out about before
// enforcing, and a shadow run that dropped readings would have changed the thing
// it was measuring.
func TestShadowModeCarriesAQualityRefusal(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        quality: {deny: [substituted]}
      policy: {mode: shadow}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measuredWithQuality(1, 100, 1234, wire.QualitySubstituted)
	f := c.expect("the measurement")
	if f.ASDU == nil || f.ASDU.Addresses[0] != 100 {
		t.Fatalf("shadow mode refused a reading: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["quality"] >= 1
	}, "the reading shadow mode carried")
}

// And enforcing, the same listener drops it. The pair is what says `deny` is a
// real refusal rather than a loud alert.
func TestEnforcingTheSameQualityDenyDropsTheReading(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        quality: {deny: [substituted]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measuredWithQuality(1, 100, 1234, wire.QualitySubstituted)
	st.send <- measuredWithQuality(1, 101, 1235, 0)
	f := c.expect("the good measurement")
	if f.ASDU == nil || f.ASDU.Addresses[0] != 101 {
		t.Fatalf("the substituted reading was carried while enforcing: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["quality"] >= 1
	}, "the refused reading")
}
