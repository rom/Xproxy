package tftp

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/tftp"
)

// Engineering on TFTP is one operation: a write.
//
// A read is not, and saying so is the whole judgement. Every switch, phone
// and field device in an estate boots by reading its own configuration or
// firmware over this protocol, thousands of times a week; a class that
// included those would be a class nobody could read. A write is the other
// thing: somebody putting an image onto the server those devices boot from,
// which is the step before every one of them runs it.
func TestOnlyATFTPWriteIsEngineering(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   wire.Op
		path wire.Path
		want engineering.Class
	}{
		{name: "a write puts an image where devices will boot it",
			op: wire.OpWrite, path: wire.Path{Name: "firmware/sw-img.bin"},
			want: engineering.ClassFirmware},
		// Whatever the filename says. The path classification this kind does
		// is about hygiene -- a NUL, a traversal, a control character -- and
		// it does not say what a file is: an image called test.txt is still
		// what the next device will run.
		{name: "a write of something that does not look like an image",
			op: wire.OpWrite, path: wire.Path{Name: "test.txt"},
			want: engineering.ClassFirmware},
		{name: "a read is how every device boots", op: wire.OpRead,
			path: wire.Path{Name: "firmware/sw-img.bin"}},
		{name: "an acknowledgement is not an operation", op: wire.OpAck},
		{name: "nor is an error", op: wire.OpError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, ok := engineeringOf(tc.op, tc.path)
			if tc.want == "" {
				if ok {
					t.Fatalf("reported as engineering: %+v", op)
				}
				return
			}
			if !ok {
				t.Fatal("not reported as engineering")
			}
			if op.Class != tc.want {
				t.Errorf("class %q, want %q", op.Class, tc.want)
			}
			if op.Point != tc.path.Name {
				t.Errorf("point %q, want the file name %q", op.Point, tc.path.Name)
			}
		})
	}
}

// "An image is written only during an approved window", through the whole
// relay.

const engOps = "        upstream: servers\n" +
	"        operations: [read, write]\n" +
	"        default_action: allow\n"

// engLedger is the `access` section, with four eyes. It is a top-level
// section, which on this harness goes in the `extra` slot.
func engLedger(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h",
		filepath.Join(t.TempDir(), "access.jsonl"))
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

// A write with nothing open is refused and the server never receives the
// file; the same write goes through once a supervisor has approved a window.
func TestAnImageWriteNeedsAnApprovedGrant(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	s, addr := tftpRelayWith(t,
		engOps+"        engineering:\n          require_grant: true\n",
		engLedger(t), fs.addr())

	c := dial(t, addr)
	if errp := c.write("firmware/sw-img.bin", content(64)); errp == nil {
		t.Fatal("the write was relayed with nothing open")
	}
	// Both counters: the operation reported, and the refusal counted the way
	// every other refusal on this kind is. The second is the one that was
	// missing -- a refused firmware write that no counter sees is invisible
	// to every dashboard and alert.
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringOps["tftp/firmware"] >= 1 &&
			sn.Refusals["tftp"]["engineering_no_grant"] >= 1 &&
			sn.TFTPDenied >= 1
	}, "the refusal and the engineering event")
	if n := len(fs.delivered()); n != 0 {
		t.Errorf("the server received %d octets", n)
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

	// A window. TFTP names nobody at all -- there is no login and no
	// identity in the protocol -- so it names the address, which is what the
	// estate has.
	g, err := led.Request(access.Request{Subject: "127.0.0.1", Listener: "boot",
		Target: "servers", Reason: "change 4711: the switch firmware rollout",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the change board"); err != nil {
		t.Fatal(err)
	}

	fs2 := startFileServer(t, &fileServer{})
	s2, addr2 := tftpRelayWith(t,
		engOps+"        engineering:\n          require_grant: true\n",
		engLedger(t), fs2.addr())
	led2 := s2.Access()
	g2, err := led2.Request(access.Request{Subject: "127.0.0.1", Listener: "boot",
		Target: "servers", Reason: "change 4711", By: "engineer",
		Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led2.Approve(g2.ID, "supervisor", "agreed"); err != nil {
		t.Fatal(err)
	}
	want := content(700)
	c2 := dial(t, addr2)
	if errp := c2.write("firmware/sw-img.bin", want); errp != nil {
		t.Fatalf("the approved write was refused: %s", errp.ErrorMessage)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) &&
		len(fs2.delivered()) < len(want); {
		time.Sleep(5 * time.Millisecond)
	}
	if !bytes.Equal(fs2.delivered(), want) {
		t.Errorf("the server received %d octets, want %d", len(fs2.delivered()), len(want))
	}
}

// A read through the same listener is untouched by the gate, which is what
// makes this deployable: an estate boots thousands of devices a week through
// this relay and none of them should need a work order.
func TestAReadIsNotHeldByTheEngineeringGate(t *testing.T) {
	want := content(600)
	fs := startFileServer(t, &fileServer{file: want})
	s, addr := tftpRelayWith(t,
		engOps+"        engineering:\n          require_grant: true\n",
		engLedger(t), fs.addr())

	c := dial(t, addr)
	got, errp := c.read("firmware/sw-img.bin")
	if errp != nil {
		t.Fatalf("a read was refused: %s", errp.ErrorMessage)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read %d octets, want %d", len(got), len(want))
	}
	sn := s.Stats()
	if n := sn.Refusals["tftp"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a read was refused as engineering: %d", n)
	}
	if len(sn.EngineeringOps) != 0 {
		t.Errorf("a read was reported as engineering: %v", sn.EngineeringOps)
	}
}

// A work order changes the tone and permits nothing, and the event names the
// file: "a write happened" is not a finding, "sw-img.bin was replaced" is.
func TestAWorkOrderChangesTheToneOfAnImageWrite(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	// action: alert is the step an estate takes first: be told when an image
	// is written outside a window, before refusing them.
	s, addr := tftpRelayWith(t,
		engOps+"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), fs.addr())
	cap := &engEvents{}
	s.Logs().Watch(cap)

	c := dial(t, addr)
	if errp := c.write("firmware/sw-img.bin", content(64)); errp != nil {
		t.Fatalf("a listener that only alerts refused: %s", errp.ErrorMessage)
	}
	ev := cap.find(t, "engineering_firmware")
	if got := ev.attrs["severity"]; got != "warning" {
		t.Errorf("severity %v: with nothing on file this is work nobody filed", got)
	}
	if got := ev.attrs["file"]; got != "firmware/sw-img.bin" {
		t.Errorf("the event names file %v", got)
	}
	if _, ok := ev.attrs["work_order"]; ok {
		t.Errorf("an event with no work order named one: %+v", ev.attrs)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["tftp/firmware"] >= 1
	}, "the operation recorded as outside every window")
	if n := s.Stats().Refusals["tftp"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a listener that only alerts refused anyway: %d", n)
	}

	// Now a relay with one on file against the pool it reaches.
	fs2 := startFileServer(t, &fileServer{})
	s2, addr2 := tftpRelayWith(t,
		engOps+"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), fs2.addr())
	if _, err := s2.Access().FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0481",
		Device: "servers", Note: "the switch firmware rollout", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cap2 := &engEvents{}
	s2.Logs().Watch(cap2)

	c2 := dial(t, addr2)
	if errp := c2.write("firmware/sw-img.bin", content(64)); errp != nil {
		t.Fatalf("the filed write was refused: %s", errp.ErrorMessage)
	}
	ev = cap2.find(t, "engineering_firmware")
	if got := ev.attrs["severity"]; got != "notice" {
		t.Errorf("severity %v: somebody filed this work", got)
	}
	if got := ev.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("work_order %v", got)
	}
	awaitCounter(t, s2, func(sn proxy.Snapshot) bool {
		return sn.EngineeringFiled["tftp/firmware"] >= 1
	}, "the operation under a work order")

	// The alert beside the report follows the same tone, because that is the
	// event an alerting pipeline filters on.
	alert := cap2.find(t, "tftp_engineering_ungranted")
	if got := alert.attrs["severity"]; got != "notice" {
		t.Errorf("the ungranted alert stayed at %v although the work was filed", got)
	}
	if got := alert.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("the ungranted alert names work_order %v", got)
	}
}

// A shadow listener says what it would have refused and carries the write,
// which is how an estate finds out how many windows it would have to file
// before it turns the refusal on.
func TestAShadowListenerSaysWhatTheEngineeringGateWouldHaveRefused(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	s, addr := tftpRelayWith(t,
		engOps+"        engineering:\n          require_grant: true\n",
		engLedger(t)+"\npolicy: {mode: shadow}", fs.addr())

	want := content(64)
	c := dial(t, addr)
	if errp := c.write("firmware/sw-img.bin", want); errp != nil {
		t.Fatalf("a shadow listener refused: %s", errp.ErrorMessage)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["tftp"]["engineering_no_grant"] >= 1
	}, "the shadow record")
	if n := s.Stats().Refusals["tftp"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a shadow listener refused: %d", n)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) &&
		len(fs.delivered()) < len(want); {
		time.Sleep(5 * time.Millisecond)
	}
	if !bytes.Equal(fs.delivered(), want) {
		t.Errorf("the server received %d octets, want %d", len(fs.delivered()), len(want))
	}
}

// alert_on_deny off silences the alert and nothing else: the operation is
// still reported and still counted.
func TestEngineeringAlertsFollowAlertOnDeny(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	s, addr := tftpRelayWith(t,
		engOps+"        alert_on_deny: false\n"+
			"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), fs.addr())
	cap := &engEvents{}
	s.Logs().Watch(cap)

	c := dial(t, addr)
	if errp := c.write("firmware/sw-img.bin", content(64)); errp != nil {
		t.Fatalf("the write was refused: %s", errp.ErrorMessage)
	}
	// The report is the event that is not an alert, so waiting for it proves
	// the decision ran before the silence is asserted.
	cap.find(t, "engineering_firmware")
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["tftp/firmware"] >= 1
	}, "the operation recorded")
	if cap.seen("tftp_engineering_ungranted") {
		t.Error("the ungranted alert was raised although alert_on_deny is off")
	}
}

// With the block turned off the listener decides nothing about engineering:
// no report, no counter, no refusal.
func TestEngineeringCanBeTurnedOff(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	s, addr := tftpRelayWith(t,
		engOps+"        engineering:\n          enabled: false\n",
		engLedger(t), fs.addr())

	want := content(64)
	c := dial(t, addr)
	if errp := c.write("firmware/sw-img.bin", want); errp != nil {
		t.Fatalf("the write was refused: %s", errp.ErrorMessage)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) &&
		len(fs.delivered()) < len(want); {
		time.Sleep(5 * time.Millisecond)
	}
	sn := s.Stats()
	if n := sn.EngineeringOps["tftp/firmware"]; n != 0 {
		t.Errorf("the operation was reported anyway: %d", n)
	}
	if n := sn.Refusals["tftp"]["engineering_no_grant"]; n != 0 {
		t.Errorf("it was refused anyway: %d", n)
	}
}
