package s7

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/s7"
)

// "Downloads only during an approved grant", end to end: the machinery the
// bastions have had since the just-in-time work, applied to a request on the
// plant's own protocol.
//
// The download here is a *stop*, because it is one PDU and this test is about the
// decision rather than about the transfer: the classification is unit-tested, and
// what has to be true here is that the relay asked the ledger, refused because
// nothing was open, and then carried the same operation once a supervisor had
// approved one.

const engYAML = `
version: 1
server:
  listeners:
    - name: plc
      address: "127.0.0.1:0"
      kind: s7
      s7:
        upstream: cpu
        default_action: allow
        operations: [setup, read, write, stop]
        engineering:
          require_grant: true
logging: {access: {enabled: false}}
access:
  ledger: %q
  approvals: 1
  max_duration: 2h
upstreams:
  - {name: cpu, endpoints: [{address: %q}]}
`

func TestAStopNeedsAnApprovedGrant(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	ledger := filepath.Join(t.TempDir(), "access.jsonl")
	s := proxytest.Start(t, fmt.Sprintf(engYAML, ledger, p.addr()))
	addr := proxytest.Addr(t, s, "plc")

	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	// No work order: refused, and the CPU never hears about it.
	cl.refused(stopJob(2))
	if p.got("stop") {
		t.Fatal("a stop with no approved grant reached the controller")
	}
	awaitEng(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["s7"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["s7/mode_change"] >= 1
	}, "the refusal and the engineering event")

	// The operation is in the ledger whether or not it was carried, which is the
	// record an audit asks for.
	led := s.Access()
	if led == nil {
		t.Fatal("the daemon has no access ledger")
	}
	if got := led.Stats().Engineering; got == 0 {
		t.Error("the refused operation was not written to the trail")
	}

	// A work order, approved by somebody else, for this address and this pool.
	g, err := led.Request(access.Request{Subject: "127.0.0.1", Listener: "plc",
		Target: "cpu", Reason: "change 4711: stop the line for the die change",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the morning meeting"); err != nil {
		t.Fatal(err)
	}

	// Now the same stop goes through.
	cl.allowed(stopJob(3))
	if !p.got("stop") {
		t.Error("an approved stop did not reach the controller")
	}
}

func TestS7CommPlusAdminNeedsAnApprovedWorkOrder(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	ledger := filepath.Join(t.TempDir(), "access.jsonl")
	config := fmt.Sprintf(engYAML, ledger, p.addr())
	config = strings.Replace(config, "        engineering:\n", "        s7comm_plus:\n          mode: policy\n          classes: [admin]\n        engineering:\n", 1)
	s := proxytest.Start(t, config)
	addr := proxytest.Addr(t, s, "plc")

	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)
	cl.write(plusFrame(wire.PlusRequest, wire.PlusInvoke))
	if p.got("plus invoke") {
		t.Fatal("an S7comm-plus invoke with no approved work order reached the controller")
	}
	awaitEng(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["s7"]["engineering_no_grant"] >= 1 &&
			sn.EngineeringOps["s7/method_call"] >= 1
	}, "the S7comm-plus refusal and engineering event")
	if got := s.Access().Stats().Engineering; got == 0 {
		t.Error("the refused S7comm-plus operation was not written to the trail")
	}
}

// awaitEng polls, because the counters are written on the relay's own goroutines.
func awaitEng(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	sn := s.Stats()
	t.Fatalf("%s: refusals %+v engineering %+v", what, sn.Refusals["s7"], sn.EngineeringOps)
}

// The listener that only asks to be told, which is the step every estate takes
// first, and the counter that was wrong about it.
//
// An operation outside every approved window on such a listener is carried. It
// used to be counted as a refusal -- on six of the eight kinds that recognise
// engineering, and not on the other two -- so the refusal counter said the relay
// had refused a stop it had forwarded, and disagreed with itself between
// protocols. It is now its own counter, and the technique is still observed,
// because the operation is a detection whether or not anybody refused it.
const engAlertYAML = `
version: 1
server:
  listeners:
    - name: plc
      address: "127.0.0.1:0"
      kind: s7
      s7:
        upstream: cpu
        default_action: allow
        operations: [setup, read, write, stop]
        engineering:
          require_grant: true
          action: alert
logging: {access: {enabled: false}}
access:
  ledger: %q
  approvals: 1
  max_duration: 2h
upstreams:
  - {name: cpu, endpoints: [{address: %q}]}
`

func TestAnOperationOutsideEveryWindowIsNotCountedAsARefusal(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	ledger := filepath.Join(t.TempDir(), "access.jsonl")
	s := proxytest.Start(t, fmt.Sprintf(engAlertYAML, ledger, p.addr()))
	addr := proxytest.Addr(t, s, "plc")

	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	// action: alert, so the stop is carried and the alert is the product.
	cl.allowed(stopJob(2))
	if !p.got("stop") {
		t.Fatal("action: alert refused a stop")
	}
	awaitEng(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringOutside["s7/mode_change"] >= 1
	}, "the operation outside every window")

	sn := s.Stats()
	if n := sn.Refusals["s7"]["engineering_ungranted"]; n != 0 {
		t.Errorf("an operation that was carried was counted as %d refusal(s)", n)
	}
	if n := sn.Refusals["s7"]["engineering_no_grant"]; n != 0 {
		t.Errorf("nothing was refused, so engineering_no_grant must be 0, got %d", n)
	}
	// T0859 (valid accounts) and T1078 are what the reason means, and losing
	// them was the risk in moving the count off the refusal path.
	if sn.Techniques["T0859"] == 0 {
		t.Errorf("the technique was not observed: %+v", sn.Techniques)
	}
}

// A work order changes the tone and nothing else, which is the pair of claims
// worth testing together: an operation on a device with one on file is reported
// as expected work, and a listener that requires a grant still refuses it.
//
// The second half is the one that matters. If a work order could stand in for
// an approval, the person who wanted the access could file one for themselves
// and four eyes would be decoration.
type securityEvents struct {
	mu     sync.Mutex
	events []recorded
}

type recorded struct {
	action, reason string
	attrs          map[string]any
}

func (c *securityEvents) SecurityEvent(action, reason string, attrs []any) {
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		m[k] = attrs[i+1]
	}
	c.mu.Lock()
	c.events = append(c.events, recorded{action: action, reason: reason, attrs: m})
	c.mu.Unlock()
}

// find waits for an event with this reason and returns it.
func (c *securityEvents) find(t *testing.T, reason string) recorded {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
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
	return recorded{}
}

func TestAWorkOrderChangesTheToneAndPermitsNothing(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	ledger := filepath.Join(t.TempDir(), "access.jsonl")
	s := proxytest.Start(t, fmt.Sprintf(engAlertYAML, ledger, p.addr()))
	addr := proxytest.Addr(t, s, "plc")
	cap := &securityEvents{}
	s.Logs().Watch(cap)

	// First, with nothing on file: the operation is reported as a warning and
	// carries no reference.
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)
	cl.allowed(stopJob(2))
	ev := cap.find(t, "engineering_mode_change")
	if got := ev.attrs["severity"]; got != "warning" {
		t.Errorf("severity %v: with nothing on file this is work nobody filed", got)
	}
	if _, ok := ev.attrs["work_order"]; ok {
		t.Errorf("an event with no work order named one: %+v", ev.attrs)
	}

	// Now file one against the pool this listener reaches.
	led := s.Access()
	if led == nil {
		t.Fatal("the daemon has no access ledger")
	}
	if _, err := led.FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0481",
		Device: "cpu", Note: "die change on line 1", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cap.mu.Lock()
	cap.events = nil
	cap.mu.Unlock()

	cl2 := dial(t, addr)
	cl2.connect(wire.ResourcePG, 0, 2)
	cl2.allowed(stopJob(3))
	ev = cap.find(t, "engineering_mode_change")
	if got := ev.attrs["severity"]; got != "notice" {
		t.Errorf("severity %v: somebody filed this work", got)
	}
	if got := ev.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("work_order %v", got)
	}
	awaitEng(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringFiled["s7/mode_change"] >= 1
	}, "the operation under a work order")

	// The alert beside the report follows the same tone, because that is the
	// event an alerting pipeline is filtering on.
	alert := cap.find(t, "s7_engineering_ungranted")
	if got := alert.attrs["severity"]; got != "notice" {
		t.Errorf("the ungranted alert stayed at %v although the work was filed", got)
	}
	if got := alert.attrs["work_order"]; got != "WO-2026-0481" {
		t.Errorf("the ungranted alert names work_order %v", got)
	}

	// And the reference is in the hash-chained trail beside the operation.
	b, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"work_order_ref":"WO-2026-0481"`) {
		t.Errorf("the trail does not tie the operation to the work order:\n%s", b)
	}

	// The other half: a listener that requires a grant refuses the same
	// operation, work order or not.
	strict := proxytest.Start(t, fmt.Sprintf(engYAML, filepath.Join(t.TempDir(), "strict.jsonl"), p.addr()))
	sled := strict.Access()
	if _, err := sled.FileWorkOrder(access.WorkOrder{Reference: "WO-2026-0482",
		Device: "cpu", Note: "the same work, filed", By: "maintenance",
		Expires: time.Now().Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	sc := dial(t, proxytest.Addr(t, strict, "plc"))
	sc.connect(wire.ResourcePG, 0, 2)
	sc.refused(stopJob(4))
	awaitEng(t, strict, func(sn proxy.Snapshot) bool {
		return sn.Refusals["s7"]["engineering_no_grant"] >= 1
	}, "the refusal, which a work order must not lift")
}
