package coap

import (
	"testing"

	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/proxy"
)

// The behavioural models on this kind, through the relay.
//
// Rules on this protocol are written about paths and methods. What they
// cannot say is "this client has never asked for this before", and on a
// segment of sensors that sentence is what an intruder's first request makes
// true: the devices do the same handful of things for years, so novelty is
// the signal the allow list cannot carry.

// The novelty models alert rather than refuse, because a sensor that has been
// quiet for a year and wakes up is novel too. The finding is counted and
// written to the security log, and the request is still carried.
func TestTheModelsNoticeWhatNoRuleCanSay(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+`        anomaly:
          enabled: true
          settle: 0s
`, up.addr())

	c := dial(t, addr)
	// A path the rule permits, from a client the models have never seen.
	if got := c.ask(get(1, 0x11, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("a permitted request was answered %s", got.Code)
	}
	until(t, s, "the models to report the first request", func(sn proxy.Snapshot) bool {
		return len(sn.Refusals["coap"]) > 0
	})
	// It reached the device: a behavioural finding on this kind is a signal,
	// not a refusal.
	up.await(t, 1, "the request the models reported on")
}

// With the alerts turned off the finding is still counted, and nothing is
// written to the security log. An estate that has turned the alerts off has
// said it reads the counters, and the counter is what the enforcement
// decision is made from later.
func TestAFindingIsCountedEvenWithTheAlertsOff(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayFor(t, base+`        alert_on_deny: false
        anomaly:
          enabled: true
          settle: 0s
`, up.addr())

	c := dial(t, addr)
	c.ask(get(1, 0x12, "3303", "0", "5700"))
	until(t, s, "the finding to be counted", func(sn proxy.Snapshot) bool {
		return len(sn.Refusals["coap"]) > 0
	})
}

// In shadow mode a model configured to refuse says what it would have done
// and carries the message. That is how a behavioural policy is turned on over
// a plant: the shadow report is read for a week before anything refuses, since
// a model that has not settled refuses the plant's own traffic.
func TestInShadowModeTheModelsSayWhatTheyWouldHaveRefused(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := relayWith(t, base+`        anomaly:
          enabled: true
          settle: 0s
          action: deny
`, "      policy: {mode: shadow}", up.addr())

	c := dial(t, addr)
	if got := c.ask(get(1, 0x13, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("shadow mode refused a request: %s", got.Code)
	}
	until(t, s, "the would-be refusal", func(sn proxy.Snapshot) bool {
		return len(sn.WouldRefusals["coap"]) > 0
	})
	// The shadow report is the operator's own view of it, and it names the
	// listener, the reason and the path the model objected to.
	rep := s.Shadow().Report()
	if len(rep) == 0 {
		t.Fatalf("the shadow report is empty")
	}
	for _, e := range rep {
		if e.Kind != "coap" || e.Listener != "segment" {
			t.Errorf("the report does not name this listener: %+v", e)
		}
		if e.Sample != "/3303/0/5700" {
			t.Errorf("the report does not name the path: %+v", e)
		}
	}
	up.await(t, 1, "the request shadow mode carried")
}
