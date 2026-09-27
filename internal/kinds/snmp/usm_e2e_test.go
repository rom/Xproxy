package snmp

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/snmp"
)

// Version 3 through the whole relay, with the user's keys configured.
//
// These are the tests that say the wiring is right rather than that the
// cryptography is: a signed request reaching the agent, an encrypted one whose
// rules were applied to what was inside it, a forged one that did not get
// through, and the counters an operator watches for each.

// usmSection is a listener holding one user's keys.
func usmSection(t *testing.T, extra string) string {
	t.Helper()
	t.Setenv("XPROXY_TEST_SNMP_AUTH", testPass)
	t.Setenv("XPROXY_TEST_SNMP_PRIV", testPriv)
	return `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v3]
        usm_users:
          - name: poller
            auth: sha256
            auth_secret: "env:XPROXY_TEST_SNMP_AUTH"
            privacy: aes128
            privacy_secret: "env:XPROXY_TEST_SNMP_PRIV"
` + extra
}

// An authenticated request reaches the agent, and the agent's signed answer
// reaches the manager. Before the keys existed the first half worked and the
// second did not: an encrypted answer had no request identifier to pair it by,
// so a v3 exchange through this relay stopped in the middle.
func TestAVersion3ExchangeGoesThroughWithTheUsersKeys(t *testing.T) {
	const id = 5501
	a := startAgent(t, &agent{reply: func(m *wire.Message) []byte {
		// The agent answers as itself: version 3, encrypted, signed with the
		// same key the manager used. Nothing in the middle re-signs it.
		return signedV3(t, v3Options{user: "poller", auth: "sha256", priv: "aes128",
			boots: 3, time: 12345, pdu: response(id, 8, 1, 3, 6, 1, 2, 1, 1, 1, 0)})
	}})
	s, addr := snmpServer(t, usmSection(t, `        default_action: allow`), a.udpAddr())

	mg := dialManager(t, addr)
	mg.send(t, signedV3(t, v3Options{user: "poller", auth: "sha256", priv: "aes128",
		boots: 3, time: 12345, pdu: get(id, 1, 3, 6, 1, 2, 1, 1, 1, 0)}))
	got := a.await(t, 1, "the signed request did not reach the agent")
	if got[0] == nil || got[0].Version != wire.V3 {
		t.Fatalf("the agent saw %+v", got[0])
	}
	if !got[0].V3.ScopedPDUEncrypted {
		t.Error("the relay forwarded a decrypted payload; the octets that arrive are the octets that go on")
	}
	if ans := mg.answer(t, 2*time.Second); ans == nil {
		t.Error("the agent's signed answer never reached the manager")
	} else if ans.Version != wire.V3 {
		t.Errorf("the answer reached the manager as %s", ans.Version)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		// One verified request and one verified answer, both decrypted.
		return sn.SNMPVerified >= 2 && sn.SNMPDecrypted >= 2
	}, "the verified and decrypted counters did not move")
}

// The rules, applied to what was inside an encrypted request. read_only is the
// one line that covers "nobody reconfigures anything through this relay", and
// without the key it covered every version except the one an operator insists
// on.
func TestAnEncryptedWriteIsRefusedByReadOnly(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, usmSection(t, `        read_only: true
        default_action: allow`), a.udpAddr())

	mg := dialManager(t, addr)
	mg.send(t, signedV3(t, v3Options{user: "poller", auth: "sha256", priv: "aes128",
		boots: 3, time: 12345, pdu: set(5502, "rogue", 1, 3, 6, 1, 2, 1, 1, 5, 0)}))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["read_only"] >= 1
	}, "an encrypted SetRequest was not refused by read_only")
	// And it did not reach the equipment, which is the assertion that matters.
	if got := a.seen(); len(got) != 0 {
		t.Errorf("the agent saw %d messages", len(got))
	}
}

// A message somebody rewrote on the way. The user name is a field the policy
// decides on, so swapping it is the forgery a relay reading only the header
// would carry.
func TestAForgedVersion3MessageDoesNotReachTheAgent(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, usmSection(t, `        default_action: allow`), a.udpAddr())

	raw := signedV3(t, v3Options{user: "poller", auth: "sha256", boots: 3, time: 12345,
		pdu: get(5503, 1, 3, 6, 1, 2, 1, 1, 1, 0)})
	forged := append([]byte(nil), raw...)
	forged[parse(raw).V3.AuthParamsAt] ^= 0xff
	mg := dialManager(t, addr)
	mg.send(t, forged)
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["auth_failed"] >= 1 && sn.SNMPAuthFailed >= 1
	}, "a forged digest was not refused")
	if got := a.seen(); len(got) != 0 {
		t.Errorf("a forged message reached the agent: %d", len(got))
	}
	// The honest one goes through, so the test is about the forgery.
	mg.send(t, raw)
	a.await(t, 1, "the honest message did not reach the agent")
}

// The downgrade: the same message with the authentication flags cleared, which
// asks the relay to stop checking rather than to produce a digest.
func TestADowngradedVersion3MessageDoesNotReachTheAgent(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, usmSection(t, `        default_action: allow`), a.udpAddr())

	mg := dialManager(t, addr)
	mg.send(t, signedV3(t, v3Options{user: "poller", auth: "sha256", boots: 3, time: 12345,
		noAuth: true, pdu: get(5504, 1, 3, 6, 1, 2, 1, 1, 1, 0)}))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["usm_downgrade"] >= 1
	}, "a message with the authentication flags stripped was not refused")
	if got := a.seen(); len(got) != 0 {
		t.Errorf("a downgraded message reached the agent: %d", len(got))
	}
}

// Shadow mode, which is what an operator trials a `usm_users` section with. A
// wrong pass phrase would otherwise stop every poll on the estate the moment
// the section is added, so the refusal is recorded and the message goes on --
// and the shadow ledger, not the refusal count, is where it appears.
func TestAUSMRefusalIsShadowable(t *testing.T) {
	a := startAgent(t, &agent{})
	// policy.mode is on the listener rather than in the snmp section, so this
	// one is assembled here rather than through the shared template.
	t.Setenv("XPROXY_TEST_SNMP_AUTH", testPass)
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: poll
      address: "127.0.0.1:0"
      kind: snmp
      policy: {mode: shadow}
      snmp:
        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v3]
        default_action: allow
        usm_users:
          - name: poller
            auth: sha256
            auth_secret: "env:XPROXY_TEST_SNMP_AUTH"
logging: {access: {enabled: false}}
upstreams:
  - {name: agents, endpoints: [{address: %q}]}
`, a.udpAddr()))
	addr := proxytest.Addr(t, s, "poll")

	raw := signedV3(t, v3Options{user: "poller", auth: "sha256", boots: 3, time: 12345,
		pdu: get(5505, 1, 3, 6, 1, 2, 1, 1, 1, 0)})
	forged := append([]byte(nil), raw...)
	forged[parse(raw).V3.AuthParamsAt] ^= 0xff
	mg := dialManager(t, addr)
	mg.send(t, forged)
	got := a.await(t, 1, "a shadowed listener did not forward the message")
	if got[0] == nil {
		t.Fatal("the agent could not parse what was forwarded")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["snmp"]["auth_failed"] >= 1
	}, "the shadow ledger did not record the refusal that did not happen")
	if n := s.Stats().Refusals["snmp"]["auth_failed"]; n != 0 {
		t.Errorf("a shadowed listener reported %d enforced refusals", n)
	}
}
