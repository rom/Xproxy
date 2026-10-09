package opcua

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// "A method runs only during an approved window", through the whole listener.
// The classification is unit-tested next door; what has to be true here is
// that the relay asked the ledger, reported the operation whatever the
// answer, refused it where this listener requires a grant, and carried the
// same call once a supervisor had approved one.

const engRSAOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"

// engServer starts a relay with its own top-level sections, which is where
// the access ledger lives.
func engServer(t *testing.T, section, top, server string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: opcua
      opcua:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`, top, section, server))
	return s, proxytest.Addr(t, s, "plant")
}

// engLedger is the `access` section, with four eyes.
func engLedger(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h",
		filepath.Join(t.TempDir(), "access.jsonl"))
}

// engSession opens a session whose identity is a named user, which is what
// lets a grant on this protocol name a person rather than an address.
func engSession(t *testing.T, addr, user string) *client {
	t.Helper()
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:plant:scada:hmi1", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, user, "p", engRSAOaep))
	return cl
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
		what, sn.Refusals["opcua"], sn.WouldRefusals["opcua"], sn.EngineeringOps,
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

// A method call with nothing open is refused and the server never hears
// about it; the same call goes through once a supervisor has approved a
// window.
func TestAMethodCallNeedsAnApprovedGrant(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := engServer(t, base+"        engineering:\n          require_grant: true\n",
		engLedger(t), up.addr())
	cl := engSession(t, addr, "engineer")
	before := countOf(up, wire.SvcCall)

	cl.service(wire.SvcCall, callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
	awaitEng(t, s, "the refusal and the engineering event", func(sn proxy.Snapshot) bool {
		return sn.Refusals["opcua"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["opcua/method_call"] >= 1
	})
	if got := countOf(up, wire.SvcCall); got != before {
		t.Errorf("the call reached the server: %v", up.seen())
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

	// A window for the *person*, which is what this protocol's identity
	// makes possible: a grant on an OPC UA listener names a user, not an
	// address.
	g, err := led.Request(access.Request{Subject: "engineer", Listener: "plant",
		Target: "servers", Reason: "change 4711: reset the pump after the seal change",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the handover"); err != nil {
		t.Fatal(err)
	}

	cl2 := engSession(t, addr, "engineer")
	cl2.service(wire.SvcCall, callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if countOf(up, wire.SvcCall) > before {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("the approved call did not reach the server: %v", up.seen())
}

// And the window is that person's. Another user's call is refused by the
// same grant, which is the whole point of having an identity to name: an
// approval for the engineer is not an approval for everyone logged in.
func TestAnotherUsersCallIsNotCoveredByTheGrant(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := engServer(t, base+"        engineering:\n          require_grant: true\n",
		engLedger(t), up.addr())
	led := s.Access()
	g, err := led.Request(access.Request{Subject: "engineer", Listener: "plant",
		Target: "servers", Reason: "change 4711", By: "engineer",
		Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed"); err != nil {
		t.Fatal(err)
	}

	cl := engSession(t, addr, "contractor")
	before := countOf(up, wire.SvcCall)
	cl.service(wire.SvcCall, callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
	awaitEng(t, s, "the refusal of the other user's call", func(sn proxy.Snapshot) bool {
		return sn.Refusals["opcua"]["engineering_no_grant"] >= 1
	})
	if got := countOf(up, wire.SvcCall); got != before {
		t.Errorf("the call reached the server: %v", up.seen())
	}
}

// A work order changes the tone and permits nothing. If one could stand in
// for an approval, the person who wanted the access could file one for
// themselves and four eyes would be decoration.
func TestAWorkOrderChangesTheToneOfAMethodCall(t *testing.T) {
	up := startServer(t, &fakeServer{})
	// action: alert is the step an estate takes first: be told when a method
	// runs outside a window, before refusing them.
	s, addr := engServer(t, base+
		"        engineering:\n          require_grant: true\n          action: alert\n",
		engLedger(t), up.addr())
	cap := &engEvents{}
	s.Logs().Watch(cap)

	cl := engSession(t, addr, "engineer")
	cl.service(wire.SvcCall, callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
	ev := cap.find(t, "engineering_method_call")
	if got := ev.attrs["severity"]; got != "warning" {
		t.Errorf("severity %v: with nothing on file this is work nobody filed", got)
	}
	if _, ok := ev.attrs["work_order"]; ok {
		t.Errorf("an event with no work order named one: %+v", ev.attrs)
	}
	// This kind calls the attribute `user` rather than `identity`, which the
	// sibling kinds use; what matters here is that the person is named at all,
	// because an OPC UA session has one and most OT protocols do not.
	if got := ev.attrs["user"]; got != "engineer" {
		t.Errorf("user %v: this protocol has an identity and the event should name it", got)
	}
	awaitEng(t, s, "the operation recorded as outside every window", func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["opcua/method_call"] >= 1
	})
	if n := s.Stats().Refusals["opcua"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a listener that only alerts refused anyway: %d", n)
	}

	// Now file one against the pool this listener reaches.
	led := s.Access()
	if _, err := led.FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0481",
		Device: "servers", Note: "seal change on pump 1", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cap.forget()

	cl2 := engSession(t, addr, "engineer")
	cl2.service(wire.SvcCall, callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
	ev = cap.find(t, "engineering_method_call")
	if got := ev.attrs["severity"]; got != "notice" {
		t.Errorf("severity %v: somebody filed this work", got)
	}
	if got := ev.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("work_order %v", got)
	}
	awaitEng(t, s, "the operation under a work order", func(sn proxy.Snapshot) bool {
		return sn.EngineeringFiled["opcua/method_call"] >= 1
	})

	// The alert beside the report follows the same tone, because that is the
	// event an alerting pipeline filters on.
	alert := cap.find(t, "opcua_engineering_ungranted")
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
	up := startServer(t, &fakeServer{})
	s, addr := engServer(t, base+
		"        monitor_only: true\n"+
		"        engineering:\n          require_grant: true\n",
		engLedger(t), up.addr())
	cl := engSession(t, addr, "engineer")
	before := countOf(up, wire.SvcCall)

	cl.service(wire.SvcCall, callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
	awaitEng(t, s, "the shadow record", func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["opcua"]["engineering_no_grant"] >= 1
	})
	if n := s.Stats().Refusals["opcua"]["engineering_no_grant"]; n != 0 {
		t.Errorf("a shadow listener refused: %d", n)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if countOf(up, wire.SvcCall) > before {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("a shadow listener held the call it only meant to record: %v", up.seen())
}

// alert_on_deny off silences the alert and nothing else: the operation is
// still reported and still counted.
func TestEngineeringAlertsFollowAlertOnDeny(t *testing.T) {
	for _, tc := range []struct {
		name, section, alert string
	}{
		{"refused", "        engineering:\n          require_grant: true\n",
			"opcua_engineering_no_grant"},
		{"carried outside every window",
			"        engineering:\n          require_grant: true\n          action: alert\n",
			"opcua_engineering_ungranted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := startServer(t, &fakeServer{})
			s, addr := engServer(t, base+"        alert_on_deny: false\n"+tc.section,
				engLedger(t), up.addr())
			cap := &engEvents{}
			s.Logs().Watch(cap)

			cl := engSession(t, addr, "engineer")
			cl.serviceQuiet(wire.SvcCall,
				callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
			// The report is the event that is not an alert, so waiting for it
			// proves the decision ran before the silence is asserted.
			cap.find(t, "engineering_method_call")
			if cap.seen(tc.alert) {
				t.Errorf("%s was raised although alert_on_deny is off", tc.alert)
			}
		})
	}
}

// With the block turned off the listener decides nothing about engineering:
// no report, no counter, no refusal.
func TestEngineeringCanBeTurnedOff(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := engServer(t, base+"        engineering:\n          enabled: false\n",
		engLedger(t), up.addr())
	cl := engSession(t, addr, "engineer")
	before := countOf(up, wire.SvcCall)

	cl.service(wire.SvcCall, callBody("ns=4;s=Line1/Pump1", "ns=4;s=Line1/Pump1/Reset", 0))
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) &&
		countOf(up, wire.SvcCall) == before; {
		time.Sleep(5 * time.Millisecond)
	}
	if countOf(up, wire.SvcCall) == before {
		t.Fatalf("the call did not reach the server: %v", up.seen())
	}
	sn := s.Stats()
	if n := sn.EngineeringOps["opcua/method_call"]; n != 0 {
		t.Errorf("the operation was reported anyway: %d", n)
	}
	if n := sn.Refusals["opcua"]["engineering_no_grant"]; n != 0 {
		t.Errorf("it was refused anyway: %d", n)
	}
}
