package anomaly

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The glue between an operator's YAML and the models: what an absent block
// means, what the defaults are, and what `settle: 0s` means -- which is the
// one value where "nothing was asked for" and "none at all" have to be told
// apart.

func mustParse(t *testing.T, section string) *config.Anomaly {
	t.Helper()
	c, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        upstream: plc
        anomaly:
` + section + `
upstreams: [{name: plc, endpoints: [{address: "127.0.0.1:502"}]}]
`))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return c.Server.Listeners[0].Modbus.Anomaly
}

func TestNoBlockAndADisabledBlockAreBothNoDetector(t *testing.T) {
	for _, c := range []*config.Anomaly{nil, {Enabled: false}} {
		d, err := FromConfig(c, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if d.On() {
			t.Error("a detector was built for a block that is not enabled")
		}
		// And every method tolerates it, so a kind holds the result
		// without asking.
		if got := d.Observe(Event{}); got != nil {
			t.Errorf("nil detector reported %v", got)
		}
		if d.Deny() || d.Status().Actors != 0 {
			t.Error("a nil detector has an opinion")
		}
		if got := d.Decide(Event{}, true, Handler{}); got != "" {
			t.Errorf("a nil detector refused %q", got)
		}
	}
}

// Enabled and nothing else: the novelty model is on with the documented
// defaults, because "this peer has never done this" needs no configuration.
func TestAnEnabledBlockRunsNoveltyWithTheDefaults(t *testing.T) {
	d, err := FromConfig(mustParse(t, "          enabled: true"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !d.On() {
		t.Fatal("no detector")
	}
	if got := d.set.p.Settle; got != DefaultSettle {
		t.Errorf("settle %s", got)
	}
	if n := d.set.p.Novelty; !n.Symbols || !n.WritePoints || n.Burst != config.DefaultAnomalyBurst {
		t.Errorf("novelty %+v", n)
	}
	if d.Deny() {
		t.Error("the default action refuses")
	}
	if got := d.Status().Models; len(got) != 1 || got[0] != string(ModelNovelty) {
		t.Errorf("models %v", got)
	}
}

// `settle: 0s` is "report from this peer's first request", which is a
// different thing from an unset key -- and the difference is why zero
// cannot mean it inside the models.
func TestSettleZeroReportsTheFirstRequest(t *testing.T) {
	d, err := FromConfig(mustParse(t, "          enabled: true\n          settle: 0s"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := d.set.p.Settle; got != NoSettle {
		t.Errorf("settle %s, want NoSettle", got)
	}
	at := time.Date(2026, 4, 1, 6, 0, 0, 0, time.UTC)
	got := d.Observe(Event{Actor: netip.MustParseAddr("10.0.0.8"), Symbol: "read", At: at})
	if len(got) != 1 || got[0].Reason != ReasonNewSymbol {
		t.Errorf("the first request of the first peer reported %v", got)
	}
}

// Every model the block names reaches the policy, including the one that
// needs an operator.
func TestEveryModelReachesThePolicy(t *testing.T) {
	d, err := FromConfig(mustParse(t, `          enabled: true
          action: deny
          max_clients: 32
          novelty: {symbols: false, write_points: true, burst: 5, burst_period: 30s}
          cycle: {enabled: true, min_samples: 40, tolerance: 3, report_every: 1m}
          sequence: {enabled: true, min_samples: 50}
          talkers: {enabled: true, ready_after: 1m}
          telemetry: {enabled: true, frozen_samples: 5, replay_window: 4}
          correlations:
            - {name: pump-and-flow, a: "unit 1 40100", b: "unit 1 40110", ratio: 2, tolerance: 0.25, max_age: 30s}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := d.set.p
	if p.MaxActors != 32 || !d.Deny() {
		t.Errorf("bounds %+v deny=%v", p, d.Deny())
	}
	if p.Novelty.Symbols || !p.Novelty.WritePoints || p.Novelty.Burst != 5 || p.Novelty.Period != 30*time.Second {
		t.Errorf("novelty %+v", p.Novelty)
	}
	if !p.Cycle.Enabled || p.Cycle.MinSamples != 40 || p.Cycle.Tolerance != 3 || p.Cycle.ReportEvery != time.Minute {
		t.Errorf("cycle %+v", p.Cycle)
	}
	if !p.Sequence.Enabled || p.Sequence.MinSamples != 50 {
		t.Errorf("sequence %+v", p.Sequence)
	}
	if !p.Talkers.Enabled || p.Talkers.ReadyAfter != time.Minute {
		t.Errorf("talkers %+v", p.Talkers)
	}
	if !p.Telemetry.Enabled || p.Telemetry.FrozenSamples != 5 || p.Telemetry.ReplayWindow != 4 {
		t.Errorf("telemetry %+v", p.Telemetry)
	}
	if len(p.Correlations) != 1 {
		t.Fatalf("correlations %+v", p.Correlations)
	}
	if c := p.Correlations[0]; c.Name != "pump-and-flow" || c.A != "unit 1 40100" ||
		c.Ratio != 2 || c.Tolerance != 0.25 || c.MaxAge != 30*time.Second {
		t.Errorf("correlation %+v", c)
	}
}

func TestAnUnknownActionIsRefused(t *testing.T) {
	_, err := FromConfig(&config.Anomaly{Enabled: true, Action: "tarpit"}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "alert or deny") {
		t.Errorf("error %v", err)
	}
}

// Decide is the four things a kind does with a finding, and which of them
// happen depends on the action and on whether the listener is enforcing.
func TestDecide(t *testing.T) {
	at := time.Date(2026, 4, 1, 6, 0, 0, 0, time.UTC)
	peer := netip.MustParseAddr("10.0.0.8")
	build := func(t *testing.T, action string) *Detector {
		t.Helper()
		d, err := FromConfig(&config.Anomaly{Enabled: true, Action: action,
			Settle: new(config.Duration)}, at)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	type calls struct{ alert, would, refused int }
	run := func(d *Detector, enforcing bool, e Event) (string, calls) {
		var c calls
		reason := d.Decide(e, enforcing, Handler{
			Alert:   func(Finding) { c.alert++ },
			Would:   func(Finding) { c.would++ },
			Refused: func(Finding) { c.refused++ },
		})
		return reason, c
	}

	// alert: every finding is recorded and nothing is refused.
	d := build(t, "alert")
	e := Event{Actor: peer, Symbol: "write single register", Point: "unit 1 400", Write: true, At: at}
	reason, c := run(d, true, e)
	if reason != "" || c.alert != 2 || c.would != 0 || c.refused != 0 {
		t.Errorf("alert: reason %q calls %+v", reason, c)
	}

	// deny, enforcing: the first finding refuses and the rest only alert.
	d = build(t, "deny")
	reason, c = run(d, true, e)
	if reason != ReasonNewSymbol || c.alert != 2 || c.refused != 1 || c.would != 0 {
		t.Errorf("deny: reason %q calls %+v", reason, c)
	}
	// And the retry goes through, because the first occurrence was recorded
	// as it was refused. That is the documented limit of `deny`.
	if reason, _ := run(d, true, e); reason != "" {
		t.Errorf("the retry was refused as well: %q", reason)
	}

	// deny, not enforcing: shadow mode records what it would have cost.
	d = build(t, "deny")
	reason, c = run(d, false, e)
	if reason != "" || c.would != 1 || c.refused != 0 || c.alert != 2 {
		t.Errorf("shadow: reason %q calls %+v", reason, c)
	}
}

// A value seen in a reply runs the two models that are about values and
// nothing else: a reply is not something a peer did, so counting it as a
// request would teach the cycle model a rhythm that is twice the real one.
func TestValuesRunOnlyTheValueModels(t *testing.T) {
	at := time.Date(2026, 4, 1, 6, 0, 0, 0, time.UTC)
	d, err := FromConfig(&config.Anomaly{Enabled: true, Settle: new(config.Duration),
		Telemetry: &config.AnomalyTelemetry{FrozenSamples: 4},
		Cycle:     &config.AnomalyCycle{MinSamples: 4}}, at)
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("10.0.0.8")
	var findings []Finding
	h := Handler{Alert: func(f Finding) { findings = append(findings, f) }}
	// A point that moves and then stops.
	for i, v := range []float64{1, 2, 3, 4, 4, 4, 4, 4, 4} {
		d.Values(Event{Actor: peer, Point: "unit 1 400", Value: v, HasValue: true,
			At: at.Add(time.Duration(i) * time.Second)}, h)
	}
	var frozen bool
	for _, f := range findings {
		if f.Reason == ReasonTelemetryFrozen {
			frozen = true
		}
		if f.Model == ModelCycle || f.Model == ModelNovelty || f.Model == ModelTalkers {
			t.Errorf("a reply ran the %s model: %+v", f.Model, f)
		}
	}
	if !frozen {
		t.Errorf("a point that stopped moving was not reported: %+v", findings)
	}
	// No peer was recorded either: the reply is about a point, not about
	// whoever asked.
	if got := d.Status().Actors; got != 0 {
		t.Errorf("a reply created %d actors", got)
	}
}
