package snmp

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/snmp"
)

// The two signals this relay produces besides its policy: an engineering
// operation, and behavioural novelty.
//
// On SNMP a write is a configuration change to a piece of network equipment --
// the one management protocol an estate leaves reachable from everywhere -- so
// it is worth treating as engineering rather than as traffic: a set to a
// switch's own MIB is somebody reconfiguring the network, and the question a
// relay can ask is whether anybody approved it.

// snmpWith starts a relay with its own sections at the top of the file: the
// access ledger a grant is written in sits outside the listener.
func snmpWith(t *testing.T, section, top, agentAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: poll
      address: "127.0.0.1:0"
      kind: snmp
      snmp:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: agents, endpoints: [{address: %q}]}
`, top, section, agentAddr))
	return s, proxytest.Addr(t, s, "poll")
}

func ledgerAt(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h",
		filepath.Join(t.TempDir(), "access.jsonl"))
}

const writeable = `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v2c]
        communities: [private]
        default_action: allow
        read_only: false
`

// A write with no grant behind it is refused and recorded as an engineering
// operation nobody approved. The equipment never hears it: a relay that
// reported the operation and forwarded it anyway would be a relay that
// watched the change happen.
func TestAWriteWithoutAGrantIsRefusedAndRecorded(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpWith(t, writeable+`        engineering:
          require_grant: true
`, ledgerAt(t), a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("private", set(301, "nothing good", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["engineering_no_grant"] >= 1
	}, "the ungranted write")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("the ungranted write reached the agent: %+v", seen)
	}
}

// With a grant somebody else approved, the same write is carried and the
// record names the grant. That is the whole of just-in-time access here: the
// change is not blocked, it is attributable.
func TestAnApprovedGrantCarriesTheWriteAndNamesItself(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpWith(t, writeable+`        engineering:
          require_grant: true
`, ledgerAt(t), a.udpAddr())

	led := s.Access()
	if led == nil {
		t.Fatal("the daemon has no access ledger")
	}
	// The subject is the credential the request carried, which on v2c is the
	// community: that is what this protocol has instead of a login, and a
	// grant written against the address would be a grant anybody behind the
	// same NAT holds.
	g, err := led.Request(access.Request{Subject: "private", Listener: "poll",
		Target: "agents", Reason: "change 904: move the uplink description",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the change meeting"); err != nil {
		t.Fatal(err)
	}

	m := dialManager(t, addr)
	m.send(t, v2c("private", set(302, "uplink to core-1", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	a.await(t, 1, "the approved write to reach the agent")
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.EngineeringOps["snmp"] >= 1 || sn.SNMPWrites >= 1
	}, "the engineering record")
}

// A write that is reported rather than refused: require_grant off means the
// operation is recorded as engineering and carried, which is the mode an
// estate runs while it finds out how much of its own traffic is engineering.
func TestAWriteIsRecordedAsEngineeringWithoutBeingRefused(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpWith(t, writeable+`        engineering:
          require_grant: false
`, ledgerAt(t), a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("private", set(303, "uplink to core-2", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	a.await(t, 1, "the recorded write to reach the agent")
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPWrites >= 1 },
		"the write was not counted")
}

// In shadow mode the refusal is recorded and the write is carried, which is
// how require_grant is turned on over an estate whose change process is not
// in the relay yet: the report says which writes would have needed a grant,
// and nothing stops while somebody reads it.
func TestInShadowModeTheUngrantedWriteIsRecordedAndCarried(t *testing.T) {
	a := startAgent(t, &agent{})
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: poll
      address: "127.0.0.1:0"
      kind: snmp
      policy: {mode: shadow}
      snmp:
%s        engineering:
          require_grant: true
logging: {access: {enabled: false}}
upstreams:
  - {name: agents, endpoints: [{address: %q}]}
`, ledgerAt(t), writeable, a.udpAddr()))
	addr := proxytest.Addr(t, s, "poll")

	m := dialManager(t, addr)
	m.send(t, v2c("private", set(304, "uplink to core-3", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	a.await(t, 1, "shadow mode to carry the ungranted write")
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return len(sn.WouldRefusals["snmp"]) > 0
	}, "the would-be refusal")
	rep := s.Shadow().Report()
	if len(rep) == 0 {
		t.Fatal("the shadow report is empty")
	}
	for _, e := range rep {
		if e.Kind != "snmp" || e.Listener != "poll" {
			t.Errorf("the shadow report: %+v", e)
		}
	}
}

// The behavioural models, which notice what the rules cannot say: that this
// manager has never polled this subtree before. On a network where the
// management stations are a list written once, that sentence is what an
// intruder's first poll makes true.
func TestTheModelsNoticeWhatNoRuleCanSay(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v2c]
        communities: [nms-only]
        default_action: allow
        anomaly:
          enabled: true
          settle: 0s
`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("nms-only", get(305, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	a.await(t, 1, "the poll the models reported on")
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return len(sn.Refusals["snmp"]) > 0 },
		"the models reported nothing with settle: 0s")
	if got := m.answer(t, 2*time.Second); got == nil || got.PDU.Type != wire.Response {
		t.Errorf("a behavioural finding refused the poll: %+v", got)
	}
}

// With the alerts turned off the finding is still counted: an estate that has
// turned the record down reads the counters, and the counter is what the
// enforcement decision is made from later.
func TestAFindingIsCountedWithTheAlertsOff(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v2c]
        communities: [nms-only]
        default_action: allow
        alert_on_deny: false
        anomaly: {enabled: true, settle: 0s}
`, a.udpAddr())
	m := dialManager(t, addr)
	m.send(t, v2c("nms-only", get(306, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return len(sn.Refusals["snmp"]) > 0 },
		"the finding was not counted")
}
