package iec104_test

import (
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/proxy"
)

// A failover, through the whole relay.
//
// A policy test can say the bookkeeping is right. Only a relay test can say
// what the station saw, and on this protocol that is the whole question:
// whatever arrives at the substation gateway is acted on.
//
// The shape is the one a control room has. Two connections from the control
// centre, declared as one redundancy group. The first takes data transfer
// and selects a breaker. The path fails, the second takes data transfer
// over, and the execute lands on it. Without the group that execute is
// refused as unselected -- which is the bug a control room meets at three in
// the morning and answers by turning require_select off.
const redundantGrid = `        upstream: substation
        require_select: true
        redundancy:
          groups:
            - name: centre
              clients: ["127.0.0.1/32"]
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`

func TestASelectSurvivesAFailoverBetweenThePathsOfOneGroup(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, redundantGrid, st)

	// The first path takes data transfer and selects the breaker.
	first := dialCentre(t, addr)
	first.startdt()
	first.ask(command(1, 4321, true, true))
	if f := first.expect("the confirmation of the select"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("the select was refused: %+v", f.ASDU)
	}

	// The standby path opens. It may not command anything yet: the
	// standard says a connection that has not been started carries no
	// data, and that is what stops a second connection from the control
	// centre's own network operating a breaker.
	second := dialCentre(t, addr)
	second.ask(command(1, 4321, false, true))
	if f := second.expect("the refusal on the standby path"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a standby connection commanded a breaker: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Standby >= 1 },
		"the standby refusal was counted")
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Fatalf("the station saw %d commands, want the select only", len(got))
	}

	// The failover: the second path takes data transfer.
	second.write(uframe(wire.StartDTAct))
	if f := second.expect("the startdt confirmation after the failover"); f.Control != wire.StartDTCon {
		t.Fatalf("the failover was answered %s", f.Control)
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Failovers == 1 },
		"the failover was counted")

	// And the execute lands on the new path, against the selection the old
	// one made.
	second.ask(command(1, 4321, false, true))
	if f := second.expect("the confirmation of the execute"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("the execute after the failover was refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 2 {
		t.Fatalf("the station saw %d commands, want the select and the execute", len(got))
	}
	if sn := s.Stats(); sn.IEC104Unselected != 0 {
		t.Errorf("%d executes were refused as unselected", sn.IEC104Unselected)
	}
}

// The path that was active is standby once it has lost data transfer, so
// what it sends after the failover is refused. A failover is not two active
// paths for a while.
func TestThePathThatLostDataTransferIsStandby(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, redundantGrid, st)

	first := dialCentre(t, addr)
	first.startdt()
	first.ask(command(1, 4321, true, true))
	first.expect("the confirmation of the select")

	second := dialCentre(t, addr)
	second.startdt()
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Failovers == 1 }, "the failover")

	// The old path tries to execute. It no longer holds data transfer.
	first.ask(command(1, 4321, false, true))
	if f := first.expect("the refusal on the old path"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("the path that lost data transfer still commanded: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Fatalf("the station saw %d commands, want the select only", len(got))
	}
}

// takeover: refuse is the other posture: on an estate where the paths are
// moved deliberately, a second connection asking for data transfer while
// the first has it is something wrong rather than a failover.
func TestTakeoverRefuseKeepsTheActivePathActive(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        require_select: true
        redundancy:
          groups:
            - name: centre
              clients: ["127.0.0.1/32"]
              takeover: refuse
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	first := dialCentre(t, addr)
	first.startdt()

	// The second path asks for data transfer and is refused. A refused
	// STARTDT is answered with nothing -- there is no negative confirmation
	// for a U-format frame in the standard -- so what the path sees is a
	// STARTDT that was never confirmed, which is what it sees from a
	// station that is not there.
	second := dialCentre(t, addr)
	second.write(uframe(wire.StartDTAct))
	second.expectSilence("the refused takeover")
	await(t, s, func(sn proxy.Snapshot) bool { return sn.Refusals["iec104"]["redundancy_active"] >= 1 },
		"the refused takeover was counted")
	if sn := s.Stats(); sn.IEC104Failovers != 0 {
		t.Errorf("a refused takeover counted %d failovers", sn.IEC104Failovers)
	}

	// The first path still has it, and still works.
	first.ask(command(1, 4321, true, true))
	if f := first.expect("the select on the path that kept data transfer"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("the active path was refused: %+v", f.ASDU)
	}
}

// And a listener with no redundancy section behaves exactly as it did
// before there was one: a connection carries data without having taken
// anything from anybody, because there is no group to hold it.
func TestAListenerWithNoGroupsIsUnchanged(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        require_select: true
        rules:
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, true, true))
	c.expect("the select")
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the execute"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a two-step command on an ordinary listener was refused: %+v", f.ASDU)
	}
	// A second connection is just another client, and its bare execute is
	// refused the way it always was: as unselected.
	other := dialCentre(t, addr)
	other.startdt()
	other.ask(command(1, 4321, false, true))
	if f := other.expect("the bare execute"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a bare execute was allowed: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.Refusals["iec104"]["unselected"] >= 1 },
		"the bare execute was refused as unselected")
	if sn := s.Stats(); sn.IEC104Standby != 0 {
		t.Errorf("a listener with no groups refused %d frames as standby", sn.IEC104Standby)
	}
}

// A selection that expired is not a selection that never existed, and the
// refusal says which: an operator who selected a point, was interrupted and
// came back to it too late needs to be told that rather than being told they
// sent a bare command.
func TestAnExpiredSelectionIsItsOwnRefusal(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        require_select: true
        select_timeout: 1s
        rules:
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, true, true))
	c.expect("the confirmation of the select")

	// Past the window. The sleep is the point of the test: there is no
	// clock to move here, because the relay under test is the built one.
	time.Sleep(1200 * time.Millisecond)
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("an execute against an expired selection was allowed: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.Refusals["iec104"]["select_expired"] >= 1 },
		"the expiry was counted as an expiry")
	if sn := s.Stats(); sn.Refusals["iec104"]["unselected"] != 0 {
		t.Error("an expired selection was reported as never having been made")
	}
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Errorf("the station saw %d commands, want the select only", len(got))
	}
}

// A group holding more connections than the operator described is a client
// list that has caught something it should not, so the connection past the
// bound is refused at accept rather than admitted into the set.
func TestAGroupRefusesAConnectionPastItsBound(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        redundancy:
          groups:
            - name: centre
              clients: ["127.0.0.1/32"]
              max_connections: 1
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}`, st)

	first := dialCentre(t, addr)
	first.startdt()

	// The second connection is accepted by the kernel and refused by the
	// relay: nothing is answered and the connection ends.
	second := dialCentre(t, addr)
	second.write(uframe(wire.StartDTAct))
	second.expectSilence("the connection past the group's bound")
	await(t, s, func(sn proxy.Snapshot) bool { return sn.Refusals["iec104"]["redundancy_full"] >= 1 },
		"the refused connection was counted")

	// And the path that is in the group still works.
	st.send <- measurement(1, 100, 7)
	first.expect("telemetry on the path that is in the group")
}

// A group that does not carry selections gets the third refusal instead of
// the concession: the two-step command was done properly, the failover in
// the middle dropped it, and the refusal says so rather than reporting a
// bare execute. It is the difference between "somebody injected a command"
// and "our failover is losing selects", and a control room acts differently
// on the two.
func TestAGroupThatDoesNotCarrySelectsSaysWhichRefusalItIs(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        require_select: true
        redundancy:
          groups:
            - name: centre
              clients: ["127.0.0.1/32"]
              carry_selects: false
        rules:
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	first := dialCentre(t, addr)
	first.startdt()
	first.ask(command(1, 4321, true, true))
	first.expect("the confirmation of the select")

	second := dialCentre(t, addr)
	second.startdt()
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Failovers == 1 }, "the failover")

	second.ask(command(1, 4321, false, true))
	if f := second.expect("the refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("the execute was allowed on a group that does not carry selects: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["select_other_connection"] >= 1
	}, "the refusal named the other connection")
	if sn := s.Stats(); sn.Refusals["iec104"]["unselected"] != 0 {
		t.Error("a select dropped by a failover was reported as a bare execute")
	}
	// And the selection the first path holds was not spent by the refusal:
	// a refusal must not consume the intention it refused.
	if sn := s.Stats(); sn.IEC104SelectsHeld != 1 {
		t.Errorf("%d selections held, want the first path's", sn.IEC104SelectsHeld)
	}
}

// A path that gives data transfer up is standby, and the gauge says how many
// groups have a path carrying data at all -- which is what an operator looks
// at to see whether a control centre is talking to its substation.
func TestStoppingDataTransferMakesAPathStandby(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, redundantGrid, st)

	c := dialCentre(t, addr)
	c.startdt()
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104RedundancyActive == 1 },
		"the group has a path carrying data")

	// The command works while it holds data transfer.
	c.ask(command(1, 4321, true, true))
	if f := c.expect("the select"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("the active path was refused: %+v", f.ASDU)
	}

	// STOPDT gives it up.
	c.write(uframe(wire.StopDTAct))
	if f := c.expect("the stopdt confirmation"); f.Control != wire.StopDTCon {
		t.Fatalf("stopdt was answered %s", f.Control)
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104RedundancyActive == 0 },
		"the group has no path carrying data")

	// And now it may not command.
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the refusal after stopdt"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a path that gave up data transfer still commanded: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Standby >= 1 },
		"the refusal was counted as standby")
}

// What the *station* sends is not policed by the group, in either of the two
// ways it could be.
//
// A standby path still receives telemetry: the relay decides what a
// controlling station may send, and refusing a substation's own answer would
// be inventing a refusal against the end that is not being policed. And a
// station originating STOPDT does not take data transfer away from the
// control centre -- which is the frame a compromised substation gateway
// would send to make every command from its control centre refused.
func TestAGroupDoesNotPoliceWhatTheStationSends(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        redundancy:
          groups:
            - name: centre
              clients: ["127.0.0.1/32"]
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	// A path that has not taken data transfer at all: standby, and still
	// reading its substation's telemetry.
	standby := dialCentre(t, addr)
	st.send <- measurement(1, 100, 7)
	standby.expect("telemetry on a standby path")
	if sn := s.Stats(); sn.IEC104Standby != 0 {
		t.Errorf("a station's telemetry was refused as standby: %d", sn.IEC104Standby)
	}

	// Now the path takes data transfer, and the station sends STOPDT at it.
	standby.startdt()
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104RedundancyActive == 1 },
		"the path holds data transfer")
	st.control <- wire.StopDTAct
	if f := standby.expect("the station's stopdt"); f.Control != wire.StopDTAct {
		t.Fatalf("the station's frame arrived as %s", f.Control)
	}
	// The group is unchanged, and the control centre still commands.
	standby.ask(command(1, 4321, false, true))
	if f := standby.expect("the command after the station's stopdt"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("a station took data transfer away from its control centre: %+v", f.ASDU)
	}
	if sn := s.Stats(); sn.IEC104RedundancyActive != 1 {
		t.Errorf("the station's stopdt left %d groups carrying data", sn.IEC104RedundancyActive)
	}
}
