package iec104_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/proxy"
)

// Learning mode, through the whole listener.
//
// The defect it exists for: a policy written from the substation drawings
// refuses half the traffic on the first shift, which is how a security control
// gets turned off. So the listener writes down what it sees and proposes a
// policy from that.

// learnServer starts a listener that is learning, and returns the report's path.
func learnServer(t *testing.T, section string, st *station, enforce bool) (*proxy.Server, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "learned.yaml")
	s, addr := iec104Server(t, fmt.Sprintf(`        upstream: substation
        common_addresses: ["1", "7"]
        learn:
          enabled: true
          file: %s
          enforce: %t
%s`, path, enforce, section), st)
	return s, addr, path
}

// report reads what the listener has written, after a shutdown that writes it.
func report(t *testing.T, s *proxy.Server, path string) string {
	t.Helper()
	// The report is written on the interval and at shutdown. A test has no
	// business waiting out an interval, so it shuts the listener down.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the learning report was not written: %v", err)
	}
	return string(body)
}

// What a learning run produces: the traffic it saw, per subject, and a rule set
// that permits exactly that.
func TestALearningRunWritesWhatItSaw(t *testing.T) {
	st := startStation(t, &station{})
	s, addr, path := learnServer(t, `        rules:
          - {name: all, action: allow}`, st, true)

	c := dialCentre(t, addr)
	c.startdt()
	// A command down to one station, telemetry up from another, and a second
	// command to an adjacent point so the addresses merge into a range.
	c.ask(command(1, 4321, false, true))
	c.expect("the first confirmation")
	c.ask(command(1, 4322, false, true))
	c.expect("the second confirmation")
	st.send <- measurement(7, 101, 1234)
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Frames >= 3 }, "the frames")

	got := report(t, s, path)

	// The header says what the run rests on.
	if !strings.Contains(got, `listener "grid"`) {
		t.Errorf("the report does not name the listener:\n%s", got)
	}
	// The subject travelling down: the command, its cause and the two points as
	// one range rather than two entries.
	for _, want := range []string{
		"direction: centre_to_station",
		"common_address: 1",
		"type: C_SC_NA_1",
		"class: command",
		`addresses: ["4321-4322"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report has no %q:\n%s", want, got)
		}
	}
	// And the subject travelling up, which is a different subject for the same
	// reason the direction is part of the identity.
	for _, want := range []string{"direction: station_to_centre", "common_address: 7", "type: M_ME_NB_1", "class: monitoring"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report has no %q:\n%s", want, got)
		}
	}
	// The proposal: a rule per client, direction and class, in the vocabulary
	// the configuration actually uses, so it can be pasted under iec104.rules.
	if !strings.Contains(got, "rules:") || !strings.Contains(got, "action: allow") {
		t.Errorf("the report proposes no rules:\n%s", got)
	}
	if !strings.Contains(got, "class: [command]") || !strings.Contains(got, "class: [monitoring]") {
		t.Errorf("the proposal does not separate the classes:\n%s", got)
	}
	if !strings.Contains(got, "types: [C_SC_NA_1]") {
		t.Errorf("the proposal does not name the types seen:\n%s", got)
	}
}

// The process values are deliberately not in the report, because a learning
// report is a file that gets pasted into a ticket. A setpoint's span is, because
// it is the bound an engineer has to set.
func TestTheReportKeepsBoundsAndNotProcessValues(t *testing.T) {
	st := startStation(t, &station{})
	s, addr, path := learnServer(t, `        rules:
          - {name: all, action: allow}`, st, true)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(setpoint(1, 5000, 250, false))
	c.expect("the first setpoint confirmation")
	c.ask(setpoint(1, 5000, -40, false))
	c.expect("the second setpoint confirmation")
	st.send <- measurement(7, 101, 31337)
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Frames >= 3 }, "the frames")

	got := report(t, s, path)
	// The span of what was commanded, which is what a setpoint bound is written
	// from.
	if !strings.Contains(got, "setpoint_values:") {
		t.Errorf("the report has no setpoint span:\n%s", got)
	}
	if !strings.Contains(got, "min: -40") || !strings.Contains(got, "max: 250") {
		t.Errorf("the setpoint span is wrong:\n%s", got)
	}
	// But not the measurement travelling up.
	if strings.Contains(got, "31337") {
		t.Errorf("the report carries a process value:\n%s", got)
	}
}

// A subject the current policy and the traffic disagree about is the first thing
// to read in the report, so it is recorded whether or not the refusal is
// enforced.
func TestTheReportNamesWhatThePolicyRefused(t *testing.T) {
	st := startStation(t, &station{})
	// Learning without enforcement, which is the default and the usual way to
	// run one: the policy decides nothing and the report says what it would
	// have decided.
	s, addr, path := learnServer(t, `        rules:
          - {name: telemetry, action: allow, class: [monitoring]}`, st, false)

	c := dialCentre(t, addr)
	c.startdt()
	// A command no rule allows. The policy would refuse it; the listener is
	// learning, so it goes through and the report says so.
	c.ask(command(1, 4321, false, true))
	c.expect("the confirmation of a command the policy would have refused")
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Fatalf("a learning run refused the command it was meant to be measuring: the station saw %d", len(got))
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104WouldDeny >= 1 }, "the shadow counter")

	got := report(t, s, path)
	if !strings.Contains(got, "denied_by_policy: 1") {
		t.Errorf("the report does not say the policy disagreed:\n%s", got)
	}
}

// A command the equipment itself refuses belongs out of the policy rather than
// in it, so the report counts the negative confirmations and leaves that subject
// out of the proposal.
func TestACommandTheStationRefusesIsNotProposed(t *testing.T) {
	st := startStation(t, &station{})
	s, addr, path := learnServer(t, `        rules:
          - {name: all, action: allow}`, st, true)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, false, true))
	c.expect("the station's own confirmation")
	// The station answers that it will not: a negative confirmation, which is
	// bit 6 of the cause octet. Nothing the relay does produces this -- it is
	// the equipment saying no.
	st.send <- negativeConfirmation(1, 4321)
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Frames >= 3 }, "the frames")

	got := report(t, s, path)
	obs, rules, ok := strings.Cut(got, "rules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	// The refusal is counted where it arrived -- travelling up -- and also
	// against the command it refuses, travelling down, which is the subject an
	// engineer acts on.
	if !strings.Contains(obs, "negative_confirmations:") {
		t.Errorf("the report does not count the station's refusal:\n%s", obs)
	}
	if !strings.Contains(obs, "refused_by_equipment: 1") {
		t.Errorf("the refusal was not attributed to the command it refuses:\n%s", obs)
	}
	// So the command is out of the proposal: a rule for it would permit a thing
	// that cannot happen, and an engineer reading the rule would think it could.
	if strings.Contains(rules, "centre_to_station") {
		t.Errorf("the proposal writes a rule for a command the station always refuses:\n%s", rules)
	}
	// The confirmation travelling back is still proposed, because confirmations
	// do come back and a policy has to allow them.
	if !strings.Contains(rules, "station_to_centre") {
		t.Errorf("the proposal leaves out the station's confirmations:\n%s", rules)
	}
}

// negativeConfirmation is a station answering a command with "no": the
// activation confirmation with the negative bit of the cause octet set.
func negativeConfirmation(common uint16, ioa uint32) []byte {
	const negative = 0x40
	return asdu(wire.CScNA1, 1, wire.CauseActCon|negative, common,
		byte(ioa), byte(ioa>>8), byte(ioa>>16), 0x01)
}

// A station confirming something it was never asked to do must not put a command
// in the report that the control centre never sent. The report is read as
// evidence of what the traffic is, so it may not invent a request.
func TestAConfirmationAloneInventsNoCommand(t *testing.T) {
	st := startStation(t, &station{})
	s, addr, path := learnServer(t, `        rules:
          - {name: all, action: allow}`, st, true)

	c := dialCentre(t, addr)
	c.startdt()
	// No command goes down. The station volunteers a negative confirmation for
	// one, which is a station behaving oddly and is exactly what must not be
	// recorded as the centre having asked.
	st.send <- negativeConfirmation(1, 4321)
	await(t, s, func(sn proxy.Snapshot) bool { return sn.IEC104Frames >= 1 }, "the frame")

	got := report(t, s, path)
	if !strings.Contains(got, "station_to_centre") {
		t.Errorf("the station's own frame was not recorded:\n%s", got)
	}
	if strings.Contains(got, "centre_to_station") {
		t.Errorf("a confirmation alone invented a command the centre never sent:\n%s", got)
	}
}

// What the section refuses to load.
func TestWhatALearningSectionRefusesToLoad(t *testing.T) {
	st := startStation(t, &station{})
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "learning with no file",
			section: "        learn: {enabled: true}",
			wants:   "learn.file: required",
		},
		{
			name:    "a relative path",
			section: "        learn: {enabled: true, file: learned.yaml}",
			wants:   "must be an absolute path",
		},
		{
			name:    "an interval nobody meant",
			section: "        learn: {enabled: true, file: /tmp/l.yaml, interval: 1s}",
			wants:   "learn.interval: must be between 10s and 24h",
		},
		{
			name:    "a bound nobody meant",
			section: "        learn: {enabled: true, file: /tmp/l.yaml, max_subjects: 2}",
			wants:   "learn.max_subjects: must be between 16 and 1000000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf(iec104YAML, "        upstream: substation\n"+
				"        common_addresses: [\"1\"]\n"+tc.section, st.addr())
			if _, err := config.Parse([]byte(yaml)); err == nil {
				t.Fatal("the section loaded")
			} else if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the error is %v, want it to mention %q", err, tc.wants)
			}
		})
	}
}
