package s7

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/s7"
)

// "Downloads only during an approved work order", end to end: the machinery the
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

func TestAStopNeedsAnApprovedWorkOrder(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	ledger := filepath.Join(t.TempDir(), "access.jsonl")
	s := proxytest.Start(t, fmt.Sprintf(engYAML, ledger, p.addr()))
	addr := proxytest.Addr(t, s, "plc")

	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	// No work order: refused, and the CPU never hears about it.
	cl.refused(stopJob(2))
	if p.got("stop") {
		t.Fatal("a stop with no approved work order reached the controller")
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
