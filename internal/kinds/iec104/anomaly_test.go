package iec104_test

import (
	"testing"

	wire "github.com/rom/xproxy/internal/iec104"
	_ "github.com/rom/xproxy/internal/kinds/iec104" // the kind under test
	"github.com/rom/xproxy/internal/proxy"
)

// The behavioural models on this kind, end to end through the relay, because
// what is worth testing here is the translation: that a type identification
// reaches the models as a symbol, that a common address reaches them as a
// device, and that a measured value travelling *up* reaches the value models
// without being counted as something the control centre did.

const anomalyPolicy = `        upstream: substation
        common_addresses: ["1", "2"]
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}
        anomaly:
          enabled: true
          settle: 0s
          talkers: {enabled: true, ready_after: 1s}
`

func TestTheModelsSeeTheTypeIdentificationAndTheCommonAddress(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, anomalyPolicy, st)

	c := dialCentre(t, addr)
	c.startdt()
	// A command: a symbol this station has not sent, to a point it has not
	// driven. With no settling window both are reported at once.
	c.ask(command(1, 4321, false, true))
	c.expect("the command confirmation")
	await(t, s, func(sn proxy.Snapshot) bool {
		r := sn.Refusals["iec104"]
		return r["anomaly_new_symbol"] >= 1 && r["anomaly_new_write_point"] >= 1
	}, "the command's novelty")

	// The same command again is no longer novel in either way: the first
	// occurrence was recorded as it was reported.
	before := s.Stats().Refusals["iec104"]["anomaly_new_symbol"]
	c.ask(command(1, 4321, false, true))
	c.expect("the second confirmation")
	if got := s.Stats().Refusals["iec104"]["anomaly_new_symbol"]; got != before {
		t.Errorf("the second command was novel too: %d against %d", got, before)
	}

	// A second common address is a pair this centre has not spoken to.
	c.ask(command(2, 4321, false, true))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["anomaly_new_pair"] >= 1
	}, "a second substation")

	// Nothing was refused: the default action is alert, which is what a
	// signal derived from novelty is worth.
	if sn := s.Stats(); sn.IEC104Denied != 0 {
		t.Errorf("a behavioural finding refused %d frames on action: alert", sn.IEC104Denied)
	}
	if got := st.saw(wire.CScNA1); len(got) != 3 {
		t.Errorf("the station saw %d commands of 3", len(got))
	}
}

// Telemetry runs the value models and nothing else. A station's answer is not
// something the controlling station did: counting it as a request would teach
// the cycle model a rhythm that is the sum of the commands and the telemetry.
func TestTelemetryRunsTheValueModelsAndIsNeverRefused(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
        anomaly:
          enabled: true
          settle: 0s
          action: deny
          novelty: {symbols: false, write_points: false, burst: 0}
          telemetry: {enabled: true, frozen_samples: 3}
`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// A point that moves and then stops. Every reading reaches the control
	// centre, including the ones the model reported on.
	for _, v := range []int16{10, 20, 30, 30, 30, 30, 30} {
		st.send <- measurement(1, 100, v)
		c.expect("a measurement")
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["anomaly_telemetry_frozen"] >= 1
	}, "a measurement that stopped moving")
	if sn := s.Stats(); sn.IEC104Denied != 0 {
		t.Errorf("telemetry was refused %d times, on a listener with action: deny", sn.IEC104Denied)
	}
}
