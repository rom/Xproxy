package iec104_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// "A station is reset only during an approved window", through the whole
// listener. The classification is unit-tested next door; what has to be true
// here is that the relay asked the ledger, reported the operation whatever
// the answer, refused it where this listener requires a grant, and carried
// the same command once a supervisor had approved one.

// engPolicy admits the engineering types this test drives. They are named in
// a rule rather than allowed by default: on this protocol a reset and a
// breaker are both commands, and which of them a listener carries is a
// decision a reviewer should be able to read.
const engPolicy = `        upstream: substation
        common_addresses: ["1"]
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: engineering, action: allow, types: [C_RP_NA_1, P_AC_NA_1, F_SC_NA_1]}
`

// engServer starts a relay with its own top-level sections, which is where
// the access ledger lives.
func engServer(t *testing.T, section, top string, st *station) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: grid
      address: "127.0.0.1:0"
      kind: iec104
      iec104:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: substation, endpoints: [{address: %q}]}
`, top, section, st.addr()))
	return s, proxytest.Addr(t, s, "grid")
}

// engLedger is the `access` section, with four eyes.
func engLedger(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h",
		filepath.Join(t.TempDir(), "access.jsonl"))
}

// resetProcess is C_RP_NA_1: the whole station told to restart.
func resetProcess(common uint16) []byte {
	return asdu(wire.CRpNA1, 1, wire.CauseActivation, common, 0x00, 0x00, 0x00, 0x01)
}

// paramActivate is P_AC_NA_1: the parameters of a measured value put into
// effect, which is how a deadband change takes hold.
func paramActivate(common uint16, ioa uint32) []byte {
	return asdu(wire.PAcNA1, 1, wire.CauseActivation, common,
		byte(ioa), byte(ioa>>8), byte(ioa>>16), 0x01)
}

// engEvents collects the security log.
type engEvents struct {
	mu     sync.Mutex
	events []engEvent
}

type engEvent struct {
	action, reason string
	attrs          map[string]any
}

func (c *engEvents) SecurityEvent(action, reason string, attrs []any) {
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		m[k] = attrs[i+1]
	}
	c.mu.Lock()
	c.events = append(c.events, engEvent{action: action, reason: reason, attrs: m})
	c.mu.Unlock()
}

func (c *engEvents) find(t *testing.T, reason string) engEvent {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		c.mu.Lock()
		for _, e := range c.events {
			if e.reason == reason {
				c.mu.Unlock()
				return e
			}
		}
		c.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("no %s event; saw %+v", reason, c.events)
	return engEvent{}
}

func (c *engEvents) forget() {
	c.mu.Lock()
	c.events = nil
	c.mu.Unlock()
}

func (c *engEvents) seen(reason string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.reason == reason {
			return true
		}
	}
	return false
}

// A reset with nothing open is refused and the station never hears about it;
// the same reset goes through once a supervisor has approved a window.
func TestAResetNeedsAnApprovedGrant(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := engServer(t, engPolicy+"        engineering:\n          require_grant: true\n",
		engLedger(t), st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(resetProcess(1))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["iec104/restart"] >= 1
	}, "the refusal and the engineering event")
	if got := st.saw(wire.CRpNA1); len(got) != 0 {
		t.Errorf("the reset reached the station: %d frames", len(got))
	}

	// The operation is in the hash-chained trail whether or not it was
	// carried, which is the record an audit asks for a year later.
	led := s.Access()
	if led == nil {
		t.Fatal("the daemon has no access ledger")
	}
	if got := led.Stats().Engineering; got == 0 {
		t.Error("the refused operation was not written to the trail")
	}

	// A window, asked for by the engineer and approved by somebody else. On
	// this protocol there is no user, so it names the control centre's
	// address.
	g, err := led.Request(access.Request{Subject: "127.0.0.1", Listener: "grid",
		Target: "substation", Reason: "change 4711: restart after the firmware update",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the outage meeting"); err != nil {
		t.Fatal(err)
	}

	c2 := dialCentre(t, addr)
	c2.startdt()
	c2.ask(resetProcess(1))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(st.saw(wire.CRpNA1)) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(st.saw(wire.CRpNA1)) == 0 {
		t.Error("the approved reset did not reach the station")
	}
}

// A parameter activation is engineering for the same reason, and it is the
// one an estate is more likely to see: it changes what the control centre's
// own telemetry looks like.
func TestAParameterActivationIsEngineering(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := engServer(t, engPolicy+"        engineering:\n          require_grant: true\n",
		engLedger(t), st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(paramActivate(1, 5001))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["iec104/configuration"] >= 1
	}, "the parameter refused as engineering")
	if got := st.saw(wire.PAcNA1); len(got) != 0 {
		t.Errorf("the parameter reached the station: %d frames", len(got))
	}
}

// A work order changes the tone and permits nothing. If one could stand in
// for an approval, the person who wanted the access could file one for
// themselves and four eyes would be decoration.
func TestAWorkOrderChangesTheToneOfAReset(t *testing.T) {
	st := startStation(t, &station{})
	// action: alert is the step an estate takes first: be told when a reset
	// happens outside a window, before refusing them.
	s, addr := engServer(t, engPolicy+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), st)
	cap := &engEvents{}
	s.Logs().Watch(cap)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(resetProcess(1))
	ev := cap.find(t, "engineering_restart")
	if got := ev.attrs["severity"]; got != "warning" {
		t.Errorf("severity %v: with nothing on file this is work nobody filed", got)
	}
	if _, ok := ev.attrs["work_order"]; ok {
		t.Errorf("an event with no work order named one: %+v", ev.attrs)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["iec104/restart"] >= 1
	}, "the operation recorded as outside every window")
	if n := s.Stats().Refusals["iec104"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a listener that only alerts refused anyway: %d", n)
	}

	// Now file one against the pool this listener reaches.
	led := s.Access()
	if _, err := led.FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0481",
		Device: "substation", Note: "firmware update on feeder 1", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cap.forget()

	c2 := dialCentre(t, addr)
	c2.startdt()
	c2.ask(resetProcess(1))
	ev = cap.find(t, "engineering_restart")
	if got := ev.attrs["severity"]; got != "notice" {
		t.Errorf("severity %v: somebody filed this work", got)
	}
	if got := ev.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("work_order %v", got)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringFiled["iec104/restart"] >= 1
	}, "the operation under a work order")

	// The alert beside the report follows the same tone, because that is the
	// event an alerting pipeline filters on.
	alert := cap.find(t, "iec104_engineering_ungranted")
	if got := alert.attrs["severity"]; got != "notice" {
		t.Errorf("the ungranted alert stayed at %v although the work was filed", got)
	}
	if got := alert.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("the ungranted alert names work_order %v", got)
	}
}

// A shadow listener says what it would have refused and forwards it, which
// is how an estate finds out how many windows it would have to file before
// it turns the refusal on.
func TestAShadowListenerSaysWhatTheEngineeringGateWouldHaveRefused(t *testing.T) {
	st := startStation(t, &station{})
	// Listener-level shadow, not monitor_only: on this protocol monitor_only
	// refuses every command outright -- a monitoring link has no business
	// commanding -- so the engineering gate would never be reached.
	s, addr := engServer(t, engPolicy+
		"        engineering:\n          require_grant: true\n"+
		"      policy: {mode: shadow}\n",
		engLedger(t), st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(resetProcess(1))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["iec104"]["engineering_no_grant"] >= 1
	}, "the shadow record")
	if n := s.Stats().Refusals["iec104"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a shadow listener refused: %d", n)
	}
}

// alert_on_deny off silences the alert and nothing else: the operation is
// still reported and still counted. An estate that turned the per-refusal
// alert off because the policy is noisy has not asked to stop hearing about
// resets.
func TestEngineeringAlertsFollowAlertOnDeny(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := engServer(t, engPolicy+"        alert_on_deny: false\n"+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), st)
	cap := &engEvents{}
	s.Logs().Watch(cap)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(resetProcess(1))
	// The report is the event that is not an alert, so waiting for it proves
	// the decision ran before the silence is asserted.
	cap.find(t, "engineering_restart")
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["iec104/restart"] >= 1
	}, "the operation recorded")
	if cap.seen("iec104_engineering_ungranted") {
		t.Error("the ungranted alert was raised although alert_on_deny is off")
	}
}

// With the block turned off the listener decides nothing about engineering:
// no report, no counter, no refusal.
func TestEngineeringCanBeTurnedOff(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := engServer(t, engPolicy+"        engineering:\n          enabled: false\n",
		engLedger(t), st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(resetProcess(1))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(st.saw(wire.CRpNA1)) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(st.saw(wire.CRpNA1)) == 0 {
		t.Fatal("the reset did not reach the station")
	}
	sn := s.Stats()
	if n := sn.EngineeringOps["iec104/restart"]; n != 0 {
		t.Errorf("the operation was reported anyway: %d", n)
	}
	if n := sn.Refusals["iec104"]["engineering_no_grant"]; n != 0 {
		t.Errorf("it was refused anyway: %d", n)
	}
}
