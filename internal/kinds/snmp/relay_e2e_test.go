package snmp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/snmp"
	"github.com/rom/xproxy/internal/testutil"
)

// agent is a fake SNMP agent. It records every message that reached it --
// which is the assertion that matters on a security relay: not what the
// manager was told, but what got through to the equipment.
type agent struct {
	pc net.PacketConn
	ln net.Listener

	mu  sync.Mutex
	got []*wire.Message
	// size is the value length the agent answers with, so a test can make
	// an answer disproportionate to the question that asked for it.
	size int
	// mute answers nothing, which is a device that is reachable and not
	// talking.
	mute bool
	// unsolicited is a response the agent sends with a request identifier
	// nobody used, which on a datagram protocol is the shape of a
	// response-spoofing attack on the manager.
	unsolicited int64
	// reply replaces the answer entirely, for a test about what the relay
	// does with something an agent should not have sent.
	reply func(*wire.Message) []byte
}

func startAgent(t *testing.T, a *agent) *agent {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a.pc = pc
	t.Cleanup(func() { _ = pc.Close() })
	go a.serveDatagrams()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go a.serveStream(c)
		}
	}()
	return a
}

func (a *agent) udpAddr() string { return a.pc.LocalAddr().String() }
func (a *agent) tcpAddr() string { return a.ln.Addr().String() }

func (a *agent) serveDatagrams() {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		out := a.record(raw)
		if out != nil {
			_, _ = a.pc.WriteTo(out, from)
		}
	}
}

func (a *agent) serveStream(c net.Conn) {
	defer func() { _ = c.Close() }()
	rd := newStreamReader(c, wire.MaxMessage)
	for {
		raw, err := rd.next()
		if err != nil {
			return
		}
		if out := a.record(raw); out != nil {
			if _, err := c.Write(out); err != nil {
				return
			}
		}
	}
}

// record parses what arrived, keeps it, and builds the answer.
func (a *agent) record(raw []byte) []byte {
	m, err := wire.Parse(raw)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		// A relay that forwarded something an agent cannot parse is a
		// finding, so the test wants to know rather than silently not
		// answering.
		a.got = append(a.got, nil)
		return nil
	}
	a.got = append(a.got, m)
	if a.mute || m.PDU == nil || m.PDU.Type.Notification() {
		return nil
	}
	if a.reply != nil {
		return a.reply(m)
	}
	id := m.PDU.RequestID
	if a.unsolicited != 0 {
		id = a.unsolicited
	}
	size := a.size
	if size == 0 {
		size = 8
	}
	v := m.Version
	if v == wire.V3 {
		// A v3 request never reaches this agent in these tests; answering
		// as v2c would be a fiction.
		v = wire.V2c
	}
	pdu := response(id, size, 1, 3, 6, 1, 2, 1, 1, 1, 0)
	if v == wire.V1 {
		return v1msg(m.Community, pdu)
	}
	return v2c(m.Community, pdu)
}

func (a *agent) seen() []*wire.Message {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*wire.Message, len(a.got))
	copy(out, a.got)
	return out
}

// await polls for a condition, because the relay decides on its own
// goroutines.
func (a *agent) await(t *testing.T, n int, what string) []*wire.Message {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := a.seen(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the agent saw %d messages", what, len(a.seen()))
	return nil
}

const snmpYAML = `
version: 1
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
`

func snmpServer(t *testing.T, section, agentAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(snmpYAML, section, agentAddr))
	return s, proxytest.Addr(t, s, "poll")
}

// manager is a management station: it sends a datagram and reads whatever
// comes back, or nothing.
type manager struct{ c net.Conn }

func dialManager(t *testing.T, addr string) *manager {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &manager{c: c}
}

func (m *manager) send(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := m.c.Write(raw); err != nil {
		t.Fatal(err)
	}
}

// answer reads one reply, or reports that none came within the window. A
// refusal that is a timeout and a refusal that is an error are different
// things to a manager, so a test has to be able to tell them apart.
func (m *manager) answer(t *testing.T, within time.Duration) *wire.Message {
	t.Helper()
	_ = m.c.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 65535)
	n, err := m.c.Read(buf)
	if err != nil {
		return nil
	}
	got, err := wire.Parse(buf[:n])
	if err != nil {
		t.Fatalf("the relay sent the manager something unparseable: %v", err)
	}
	return got
}

func awaitCounter(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the counters never said so: %+v", what, s.Stats().Refusals["snmp"])
}

// The relay in its ordinary shape: a poll under an allowed subtree reaches
// the agent and the answer reaches the manager.
func TestSNMPRelaysThePollItWasConfiguredFor(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v2c]
        communities: [nms-only]
        read_only: true
        rules:
          - {name: mib-2, action: allow, access: [read], oids: ["1.3.6.1.2.1"]}`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("nms-only", get(101, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	seen := a.await(t, 1, "the poll did not reach the agent")
	if seen[0] == nil || seen[0].PDU.RequestID != 101 {
		t.Fatalf("the agent saw %+v", seen[0])
	}
	got := m.answer(t, 2*time.Second)
	if got == nil {
		t.Fatal("the manager got no answer")
	}
	if got.PDU.Type != wire.Response || got.PDU.RequestID != 101 {
		t.Errorf("the answer was %+v", got.PDU)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPReads >= 1 }, "the read was not counted")
}

// A write through a read-only relay: the manager gets the error its version
// has a word for, and the agent never hears about it. A dropped request
// would be a timeout, and a timeout is what a dead device looks like.
func TestASetRequestIsRefusedWithTheErrorAManagerDisplays(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        read_only: true
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("private", set(202, "pwned", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	got := m.answer(t, 2*time.Second)
	if got == nil {
		t.Fatal("the refusal was a timeout, not an error")
	}
	if got.PDU.Type != wire.Response || got.PDU.RequestID != 202 {
		t.Fatalf("the answer was %+v", got.PDU)
	}
	if got.PDU.ErrorStatus != wire.StatusNoAccess {
		t.Errorf("error status %d, wanted noAccess", got.PDU.ErrorStatus)
	}
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("the write reached the agent: %+v", seen)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPDenied >= 1 && sn.Refusals["snmp"]["read_only"] >= 1
	}, "the refusal was not counted")
}

// The amplification bound, and the choice that makes it deployable: the
// repetition count is lowered rather than the request refused, so a
// mis-tuned poller still gets an answer and the amplifier is gone.
func TestAGetBulkIsLoweredRatherThanRefused(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        max_repetitions: 25
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("public", bulk(303, 10000, 1, 3, 6, 1, 2, 1)))
	seen := a.await(t, 1, "the walk did not reach the agent")
	if seen[0] == nil {
		t.Fatal("the agent could not parse the lowered request")
	}
	if got := seen[0].PDU.MaxRepetitions; got != 25 {
		t.Errorf("the agent was asked for %d repetitions", got)
	}
	if seen[0].PDU.RequestID != 303 {
		t.Errorf("the request identifier moved: %d", seen[0].PDU.RequestID)
	}
	if m.answer(t, 2*time.Second) == nil {
		t.Error("the manager got no answer to a request that was lowered, not refused")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPTruncated >= 1 }, "the lowering was not counted")
}

// An authenticated v3 GETBULK past the bound is the one shape that cannot be
// lowered: its digest covers the whole message and this relay has no key. It
// is refused rather than forwarded unbounded.
func TestAnAuthenticatedWalkPastTheBoundIsRefusedNotRewritten(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v3]
        max_repetitions: 25
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v3(0x05, "monitor", "", bulk(404, 10000, 1, 3, 6, 1, 2, 1)))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["max_repetitions"] >= 1
	}, "the walk was not refused")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("an unbounded walk reached the agent: %+v", seen[0])
	}
	// And no forged answer: a v3 request cannot be answered by a relay with
	// no key, so the manager gets a timeout and nothing pretending to be
	// authenticated.
	if got := m.answer(t, 300*time.Millisecond); got != nil {
		t.Errorf("the relay answered a v3 request: %+v", got)
	}
}

// The other half of the amplification bound, on the way back: an answer
// disproportionate to the question is a reflection attack whatever the
// question asked for.
func TestAnAnswerDisproportionateToItsQuestionIsRefused(t *testing.T) {
	a := startAgent(t, &agent{size: 4000})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        max_response_ratio: 4
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(505, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	a.await(t, 1, "the poll did not reach the agent")
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPAmplified >= 1 && sn.Refusals["snmp"]["response_ratio"] >= 1
	}, "the reflection was not refused")
	if got := m.answer(t, 300*time.Millisecond); got != nil {
		t.Errorf("the amplified answer reached the manager: %d bindings", len(got.PDU.VarBinds))
	}
}

// And the size bound, which an agent that ignores the repetition count
// still cannot get past.
func TestAnAnswerPastTheSizeBoundIsRefused(t *testing.T) {
	a := startAgent(t, &agent{size: 4000})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        max_response_bytes: 1000
        max_response_ratio: 0
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(606, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	a.await(t, 1, "the poll did not reach the agent")
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["response_too_large"] >= 1
	}, "the oversize answer was not refused")
	if got := m.answer(t, 300*time.Millisecond); got != nil {
		t.Error("the oversize answer reached the manager")
	}
}

// A response nobody asked for. On a datagram protocol that is the shape of
// a response-spoofing attack on the manager: an answer to a question it did
// ask, from somewhere else, arriving first.
func TestAResponseNobodyAskedForIsNotForwarded(t *testing.T) {
	a := startAgent(t, &agent{unsolicited: 999999})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(707, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	a.await(t, 1, "the poll did not reach the agent")
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPUnsolicited >= 1 && sn.Refusals["snmp"]["unsolicited_response"] >= 1
	}, "the unsolicited answer was not refused")
	if got := m.answer(t, 300*time.Millisecond); got != nil {
		t.Errorf("an answer to a question nobody asked reached the manager: %+v", got.PDU)
	}
}

// A malformed datagram is never shadowed and never forwarded: the agent
// behind this relay would read those octets somehow.
func TestAMalformedDatagramIsRefusedWhateverThePolicySays(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, []byte{0x30, 0x82, 0xff, 0xff, 0x02, 0x01, 0x01})
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPMalformed >= 1 && sn.Refusals["snmp"]["malformed"] >= 1
	}, "the malformed datagram was not refused")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("a malformed datagram reached the agent: %+v", seen)
	}
}

// Shadow mode: the policy is evaluated, the refusal is recorded, and the
// message goes on. It is the only honest way to find out what a policy
// would have broken -- and the bounds are not part of it.
func TestShadowModeRecordsTheRefusalAndForwardsTheMessage(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        rules:
          - {name: reads-only, action: allow, access: [read]}
      policy: {mode: shadow}`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("private", set(808, "pwned", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	seen := a.await(t, 1, "the write did not reach the agent in shadow mode")
	if seen[0] == nil || seen[0].PDU.Type != wire.SetRequest {
		t.Fatalf("the agent saw %+v", seen[0])
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPWouldDeny >= 1 }, "the shadow refusal was not counted")
	if sn := s.Stats(); sn.SNMPDenied != 0 {
		t.Errorf("shadow mode refused something: %d", sn.SNMPDenied)
	}
	report := s.Shadow().Report()
	if len(report) == 0 {
		t.Fatal("the shadow ledger recorded nothing")
	}
	if report[0].Reason != "snmp_default_deny" {
		t.Errorf("the ledger says %q", report[0].Reason)
	}
}

// A client outside the list is refused before a message is parsed, and that
// refusal is not shadowed: an address that may not reach the equipment does
// not reach it whatever the policy mode says.
func TestAClientOutsideTheListIsRefusedEvenInShadowMode(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["192.0.2.0/24"]
        default_action: allow
      policy: {mode: shadow}`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(909, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPRejected >= 1 && sn.Refusals["snmp"]["client_not_allowed"] >= 1
	}, "the unlisted client was not refused")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("an unlisted client reached the agent: %+v", seen)
	}
}

// The downgrade that works end to end: a v3 notification from a modern
// device, forwarded as v2c to a collector that understands nothing else,
// with a community string the device never knew.
func TestAVersionThreeTrapIsDowngradedForALegacyCollector(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        traps: true
        upgrade_version: v2c
        upstream_community: collector-secret
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v3(0x05, "device-a", "", trap(1010, 1, 3, 6, 1, 6, 3, 1, 1, 5, 3)))
	seen := a.await(t, 1, "the trap did not reach the collector")
	if seen[0] == nil {
		t.Fatal("the collector could not parse the downgraded trap")
	}
	if seen[0].Version != wire.V2c {
		t.Errorf("the collector saw %s", seen[0].Version)
	}
	if seen[0].Community != "collector-secret" {
		t.Errorf("the collector saw community %q", seen[0].Community)
	}
	if seen[0].PDU.Type != wire.TrapV2 {
		t.Errorf("the collector saw %s", seen[0].PDU.Type)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPUpgraded >= 1 && sn.SNMPTraps >= 1
	}, "the downgrade was not counted")
}

// A v3 request is not downgraded: its answer would have to be authenticated
// and this relay holds no keys, so it is refused rather than
// half-translated.
func TestAVersionThreeRequestIsNotDowngraded(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        upgrade_version: v2c
        upstream_community: switch-secret
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v3(0x05, "monitor", "", get(1111, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["upgrade_failed"] >= 1
	}, "the v3 request was not refused")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("a v3 request was downgraded to the agent: %+v", seen[0])
	}
}

// The downgrade between v1 and v2c does work both ways, because neither has
// any integrity to invalidate: the request goes out as v1 and the answer
// comes back in the version the manager spoke.
func TestTheAnswerComesBackInTheVersionTheManagerSpoke(t *testing.T) {
	a := startAgent(t, &agent{})
	_, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        upgrade_version: v1
        upstream_community: legacy-switch
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("nms-only", get(1212, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	seen := a.await(t, 1, "the poll did not reach the agent")
	if seen[0] == nil || seen[0].Version != wire.V1 {
		t.Fatalf("the agent saw %+v", seen[0])
	}
	if seen[0].Community != "legacy-switch" {
		t.Errorf("the agent saw community %q", seen[0].Community)
	}
	got := m.answer(t, 2*time.Second)
	if got == nil {
		t.Fatal("the manager got no answer")
	}
	if got.Version != wire.V2c {
		t.Errorf("the manager was answered in %s, having asked in v2c", got.Version)
	}
	if got.Community != "nms-only" {
		t.Errorf("the answer carried community %q, which the manager never sent upstream", got.Community)
	}
	if got.PDU.RequestID != 1212 {
		t.Errorf("the answer's request identifier is %d", got.PDU.RequestID)
	}
}

// The rate limit is a bound rather than policy, so it is never shadowed: a
// relay that let a flood through because its policy was in shadow mode
// would be a relay with no bound at all.
func TestTheRateLimitHoldsInShadowMode(t *testing.T) {
	a := startAgent(t, &agent{mute: true})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        rate_limit: 1
        rate_burst: 1
        default_action: allow
      policy: {mode: shadow}`, a.udpAddr())

	m := dialManager(t, addr)
	for i := 0; i < 30; i++ {
		m.send(t, v2c("public", get(int64(2000+i), 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPRateLimited >= 1 && sn.Refusals["snmp"]["rate_limited"] >= 1
	}, "the rate limit did not hold")
}

// The stream transport: RFC 3430 framing, the same policy, and the same
// refusal.
func TestTheStreamTransportCarriesTheSamePolicy(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        transport: tcp
        allow_clients: ["127.0.0.0/8"]
        read_only: true
        default_action: allow`, a.tcpAddr())

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(v2c("public", get(3001, 1, 3, 6, 1, 2, 1, 1, 1, 0))); err != nil {
		t.Fatal(err)
	}
	rd := newStreamReader(c, wire.MaxMessage)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, err := rd.next()
	if err != nil {
		t.Fatalf("no answer on the stream: %v", err)
	}
	got, err := wire.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.PDU.RequestID != 3001 || got.PDU.ErrorStatus != 0 {
		t.Errorf("the answer was %+v", got.PDU)
	}
	// And the write is refused on this transport too, with the error rather
	// than a closed connection.
	if _, err := c.Write(v2c("private", set(3002, "pwned", 1, 3, 6, 1, 2, 1, 1, 5, 0))); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, err = rd.next()
	if err != nil {
		t.Fatalf("no refusal on the stream: %v", err)
	}
	got, err = wire.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.PDU.ErrorStatus != wire.StatusNoAccess {
		t.Errorf("the refusal was %+v", got.PDU)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPSessions >= 1 }, "the session was not counted")
}

// A stream whose framing is wrong is a stream whose next octet is unknown.
// Guessing would be inventing a message boundary nobody sent, so the session
// ends.
func TestAStreamWithTheWrongFramingEnds(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        transport: tcp
        allow_clients: ["127.0.0.0/8"]
        default_action: allow`, a.tcpAddr())

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// Not a SEQUENCE: an HTTP request, which is what a scanner sends to
	// every open port it finds.
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["framing"] >= 1
	}, "the framing error was not refused")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("an HTTP request reached the agent: %+v", seen)
	}
}

// A message whose declared length is past the bound is refused unread:
// reading it to find out what it asked for is the work the bound exists to
// avoid.
func TestAStreamMessagePastTheBoundIsRefusedUnread(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        transport: tcp
        allow_clients: ["127.0.0.0/8"]
        max_message_bytes: 600
        default_action: allow`, a.tcpAddr())

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// A SEQUENCE claiming 60000 octets, with none of them sent.
	if _, err := c.Write([]byte{0x30, 0x82, 0xea, 0x60}); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["message_too_large"] >= 1
	}, "the oversize message was not refused")
}

// A datagram past the bound is refused the same way, and the bound is the
// one an operator set.
func TestADatagramPastTheBoundIsRefused(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        max_message_bytes: 600
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	big := make([]byte, 700)
	big[0] = 0x30
	m.send(t, big)
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["message_too_large"] >= 1
	}, "the oversize datagram was not refused")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("an oversize datagram reached the agent: %+v", seen)
	}
}

// The half of the secure upgrade that faces a management station: TLS from
// the first octet on the stream side, RFC 6353, with plain v2c going on
// towards a switch whose firmware has neither.
func TestTheStreamSideTakesTLSAndTheAgentSideDoesNot(t *testing.T) {
	a := startAgent(t, &agent{})
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "relay.test")
	s, addr := snmpServer(t, fmt.Sprintf(`        upstream: agents
        transport: tcp
        tls_mode: implicit
        allow_clients: ["127.0.0.0/8"]
        upgrade_version: v2c
        upstream_community: switch-secret
        default_action: allow
      tls:
        certificates: [{cert_file: %s, key_file: %s}]`, cert, key), a.tcpAddr())

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "relay.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(v1msg("nms-only", get(4001, 1, 3, 6, 1, 2, 1, 1, 1, 0))); err != nil {
		t.Fatal(err)
	}
	seen := a.await(t, 1, "the poll did not reach the agent over TLS")
	if seen[0] == nil || seen[0].Version != wire.V2c {
		t.Fatalf("the agent saw %+v", seen[0])
	}
	if seen[0].Community != "switch-secret" {
		t.Errorf("the agent saw community %q", seen[0].Community)
	}
	// And the answer comes back in the version the manager spoke, inside
	// the TLS session it spoke it on.
	rd := newStreamReader(c, wire.MaxMessage)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, err := rd.next()
	if err != nil {
		t.Fatalf("no answer over TLS: %v", err)
	}
	got, err := wire.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != wire.V1 || got.Community != "nms-only" {
		t.Errorf("the manager was answered with %s %q", got.Version, got.Community)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPUpgraded >= 2 },
		"the rewrite in both directions was not counted")
}

// An answer to a question nobody asked, on a stream. The connection cannot
// be spoofed the way a datagram can, but a peer answering questions nobody
// asked is still not a peer to keep talking to.
func TestAStreamAnswerNobodyAskedForEndsTheSession(t *testing.T) {
	a := startAgent(t, &agent{unsolicited: 424242})
	s, addr := snmpServer(t, `        upstream: agents
        transport: tcp
        allow_clients: ["127.0.0.0/8"]
        default_action: allow`, a.tcpAddr())

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(v2c("public", get(4101, 1, 3, 6, 1, 2, 1, 1, 1, 0))); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["unsolicited_response"] >= 1
	}, "the unsolicited answer was not refused on a stream")
	// The session ends rather than carrying on, so the manager sees the
	// connection close instead of an answer to something it did not ask.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("the relay forwarded an unsolicited answer")
	}
}

// A request from the upstream side. That side answers questions; it does not
// ask them, and a request arriving from there is a datagram sent in the
// wrong direction at best.
func TestARequestFromTheAgentSideIsRefused(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        transport: tcp
        allow_clients: ["127.0.0.0/8"]
        default_action: allow`, a.tcpAddr())

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// The agent in these tests answers with a Response, so this asks it to
	// answer a request the relay never sent by having it echo a GET: the
	// fake agent replies to whatever arrives, and a Response is what it
	// sends. To exercise the wrong-direction check the agent is asked for a
	// trap instead, which is a notification arriving where a response was
	// due.
	a.mu.Lock()
	a.reply = func(m *wire.Message) []byte { return v2c(m.Community, trap(1, 1, 3, 6, 1, 6, 3, 1, 1, 5, 3)) }
	a.mu.Unlock()
	if _, err := c.Write(v2c("public", get(4201, 1, 3, 6, 1, 2, 1, 1, 1, 0))); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["wrong_direction"] >= 1
	}, "a notification from the agent side was not refused")
}

// The connection bound, which is the whole admission policy of a stream
// listener beyond the client list.
func TestTheConnectionBoundHolds(t *testing.T) {
	a := startAgent(t, &agent{mute: true})
	s, addr := snmpServer(t, `        upstream: agents
        transport: tcp
        max_connections: 1
        allow_clients: ["127.0.0.0/8"]
        default_action: allow`, a.tcpAddr())

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	// The first connection has to be established before the second is
	// dialled, or the bound is being tested against a race.
	if _, err := first.Write(v2c("public", get(4301, 1, 3, 6, 1, 2, 1, 1, 1, 0))); err != nil {
		t.Fatal(err)
	}
	a.await(t, 1, "the first session did not reach the agent")
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["max_connections"] >= 1
	}, "the connection bound did not hold")
}

// The same wrong-direction check on the datagram path, where it is the one
// that matters: a notification arriving from the agent side of a UDP relay
// is either a device sending to the wrong port or something walking the
// relay's own socket.
func TestANotificationFromTheAgentSideOfADatagramRelayIsRefused(t *testing.T) {
	a := startAgent(t, &agent{})
	a.reply = func(m *wire.Message) []byte {
		return v2c(m.Community, trap(1, 1, 3, 6, 1, 6, 3, 1, 1, 5, 3))
	}
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(4401, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["wrong_direction"] >= 1
	}, "a notification from the agent side was not refused on a datagram relay")
	if got := m.answer(t, 300*time.Millisecond); got != nil {
		t.Errorf("a notification reached the manager as an answer: %+v", got.PDU)
	}
}
