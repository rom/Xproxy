package modbus_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// "A PLC is reprogrammed only during an approved window", through the whole
// listener. The classification is unit-tested next door; what has to be true
// here is that the relay asked the ledger, reported the operation whatever
// the answer, refused it where this listener requires a grant, and carried
// the same request once a supervisor had approved one.

// The UMAS requests this test drives. UMAS is not in the specification,
// which is exactly why it matters: a block upload is how an attack that
// means to stay changes a plant, and nothing in the standard function codes
// describes one.
var (
	engUpload = []byte{0x5A, 0x21, 0x31} // upload a program block
	engStop   = []byte{0x5A, 0x21, 0x41} // stop the PLC
	engRead   = []byte{0x5A, 0x21, 0x22} // read variables
)

// engSection names the sub-functions in a rule, because naming them is how
// a policy says it meant them: a rule written for an engineering station
// that said only `umas` would allow a PLC stop by accident, so the relay
// refuses the unsafe ones until they are named.
const engSection = `        upstream: plant
        default_action: allow
        rules:
          - name: engineering-station
            action: allow
            umas_commands: [upload_block, stop_plc, read_variables]
`

// engServer starts a relay with its own top-level sections, which is where
// the access ledger lives.
func engServer(t *testing.T, section, top string, dev *plc) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: plant, endpoints: [{address: %q}]}
`, top, section, dev.addr()))
	return s, proxytest.Addr(t, s, "plant")
}

// engLedger is the `access` section, with four eyes.
func engLedger(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h",
		filepath.Join(t.TempDir(), "access.jsonl"))
}

func awaitEng(t *testing.T, s *proxy.Server, what string, ok func(proxy.Snapshot) bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	sn := s.Stats()
	t.Fatalf("%s never happened; refusals %v, would-refuse %v, engineering %v, outside %v",
		what, sn.Refusals["modbus"], sn.WouldRefusals["modbus"], sn.EngineeringOps,
		sn.EngineeringOutside)
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

// awaitDevice waits for the PLC to have seen a function code.
func awaitDevice(t *testing.T, dev *plc, fc byte, what string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if _, ok := dev.saw(fc); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s never reached the device: %+v", what, dev.requests())
}

// A block upload with nothing open is refused and the PLC never hears about
// it; the same upload goes through once a supervisor has approved a window.
func TestAProgramBlockNeedsAnApprovedGrant(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := engServer(t, engSection+"        engineering:\n          require_grant: true\n",
		engLedger(t), dev)

	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, engUpload)
	m.expectException("a block upload with nothing open", wire.ExIllegalFunction)
	awaitEng(t, s, "the refusal and the engineering event", func(sn proxy.Snapshot) bool {
		return sn.Refusals["modbus"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["modbus/program_download"] >= 1
	})
	if _, ok := dev.saw(wire.FCUMAS); ok {
		t.Errorf("the upload reached the PLC: %+v", dev.requests())
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

	// A window, asked for by the engineer and approved by somebody else.
	// Modbus names nobody, so it names the engineering station's address.
	g, err := led.Request(access.Request{Subject: "127.0.0.1", Listener: "plant",
		Target: "plant", Reason: "change 4711: new ladder logic for the filler",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the shift meeting"); err != nil {
		t.Fatal(err)
	}

	m2 := dialMaster(t, addr, wire.FramingTCP)
	m2.send(1, engUpload)
	awaitDevice(t, dev, wire.FCUMAS, "the approved upload")
}

// A PLC stop is the other class and the one an operator notices first: the
// line stops. It goes through the same gate.
func TestAPLCStopIsEngineeringToo(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := engServer(t, engSection+"        engineering:\n          require_grant: true\n",
		engLedger(t), dev)

	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, engStop)
	m.expectException("a stop with nothing open", wire.ExIllegalFunction)
	awaitEng(t, s, "the stop refused as engineering", func(sn proxy.Snapshot) bool {
		return sn.Refusals["modbus"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["modbus/mode_change"] >= 1
	})
	if _, ok := dev.saw(wire.FCUMAS); ok {
		t.Errorf("the stop reached the PLC: %+v", dev.requests())
	}
}

// A variable read through the same session is not engineering and is not
// touched by the gate, which is what makes this usable: an engineering
// station reads a hundred variables for every block it writes.
func TestAVariableReadIsNotHeldByTheEngineeringGate(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := engServer(t, engSection+"        engineering:\n          require_grant: true\n",
		engLedger(t), dev)

	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, engRead)
	awaitDevice(t, dev, wire.FCUMAS, "the variable read")
	sn := s.Stats()
	if n := sn.Refusals["modbus"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a variable read was refused as engineering: %d", n)
	}
	if len(sn.EngineeringOps) != 0 {
		t.Errorf("a variable read was reported as engineering: %v", sn.EngineeringOps)
	}
}

// A work order changes the tone and permits nothing. If one could stand in
// for an approval, the person who wanted the access could file one for
// themselves and four eyes would be decoration.
func TestAWorkOrderChangesTheToneOfAnUpload(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	// action: alert is the step an estate takes first: be told when a block
	// moves outside a window, before refusing them.
	s, addr := engServer(t, engSection+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), dev)
	cap := &engEvents{}
	s.Logs().Watch(cap)

	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, engUpload)
	awaitDevice(t, dev, wire.FCUMAS, "the upload this listener only reports")
	ev := cap.find(t, "engineering_program_download")
	if got := ev.attrs["severity"]; got != "warning" {
		t.Errorf("severity %v: with nothing on file this is work nobody filed", got)
	}
	if _, ok := ev.attrs["work_order"]; ok {
		t.Errorf("an event with no work order named one: %+v", ev.attrs)
	}
	awaitEng(t, s, "the operation recorded as outside every window", func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["modbus/program_download"] >= 1
	})
	if n := s.Stats().Refusals["modbus"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a listener that only alerts refused anyway: %d", n)
	}

	// Now file one against the pool this listener reaches.
	led := s.Access()
	if _, err := led.FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0481",
		Device: "plant", Note: "ladder logic change on the filler", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cap.forget()

	m2 := dialMaster(t, addr, wire.FramingTCP)
	m2.send(1, engUpload)
	ev = cap.find(t, "engineering_program_download")
	if got := ev.attrs["severity"]; got != "notice" {
		t.Errorf("severity %v: somebody filed this work", got)
	}
	if got := ev.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("work_order %v", got)
	}
	awaitEng(t, s, "the operation under a work order", func(sn proxy.Snapshot) bool {
		return sn.EngineeringFiled["modbus/program_download"] >= 1
	})

	// The alert beside the report follows the same tone, because that is the
	// event an alerting pipeline filters on.
	alert := cap.find(t, "modbus_engineering_ungranted")
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
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	// Daemon-wide shadow, which is where this kind's switch lives: it has no
	// monitor_only of its own.
	s, addr := engServer(t, engSection+
		"        engineering:\n          require_grant: true\n",
		engLedger(t)+"\npolicy: {mode: shadow}", dev)

	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, engUpload)
	awaitDevice(t, dev, wire.FCUMAS, "the upload a shadow listener forwards")
	awaitEng(t, s, "the shadow record", func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["modbus"]["engineering_no_grant"] >= 1
	})
	if n := s.Stats().Refusals["modbus"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a shadow listener refused: %d", n)
	}
}

// alert_on_deny off silences the alert and nothing else: the operation is
// still reported and still counted.
func TestEngineeringAlertsFollowAlertOnDeny(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := engServer(t, engSection+"        alert_on_deny: false\n"+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), dev)
	cap := &engEvents{}
	s.Logs().Watch(cap)

	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, engUpload)
	// The report is the event that is not an alert, so waiting for it proves
	// the decision ran before the silence is asserted.
	cap.find(t, "engineering_program_download")
	awaitEng(t, s, "the operation recorded", func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["modbus/program_download"] >= 1
	})
	if cap.seen("modbus_engineering_ungranted") {
		t.Error("the ungranted alert was raised although alert_on_deny is off")
	}
}

// With the block turned off the listener decides nothing about engineering:
// no report, no counter, no refusal.
func TestEngineeringCanBeTurnedOff(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := engServer(t, engSection+"        engineering:\n          enabled: false\n",
		engLedger(t), dev)

	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, engUpload)
	awaitDevice(t, dev, wire.FCUMAS, "the upload")
	sn := s.Stats()
	if n := sn.EngineeringOps["modbus/program_download"]; n != 0 {
		t.Errorf("the operation was reported anyway: %d", n)
	}
	if n := sn.Refusals["modbus"]["engineering_no_grant"]; n != 0 {
		t.Errorf("it was refused anyway: %d", n)
	}
}
