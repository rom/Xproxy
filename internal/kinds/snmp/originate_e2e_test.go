package snmp

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/snmp"
)

// The pass phrases the relay is configured with and the agent derives from.
const (
	upAuthPass = "the relay authenticates to the agent with this"
	upPrivPass = "and encrypts to the agent with this"
)

// v3agent is an agent that speaks only version 3, which is the deployment the
// upgrade exists for: the equipment was replaced and the polling system was
// not.
//
// It derives its keys from the pass phrases itself and verifies what arrives
// with them. That is the assertion worth having -- not that the relay built
// something it can read back, but that a party holding only the pass phrase
// accepts it.
type v3agent struct {
	engineID []byte
	boots    int64
	// clock is what the agent says its time is.
	clock int64
	// answerLevel is the level the agent answers at.
	answerLevel wire.SecurityLevel
	auth        wire.AuthAlgo
	priv        wire.PrivAlgo

	mu sync.Mutex
	// got is every message that reached the agent, and verified whether its
	// digest checked out against the agent's own keys.
	got      []*wire.Message
	verified []bool
	// discoveries counts the messages that named no engine.
	discoveries int
}

// reply is the agent's answer, for the `reply` hook of the fake agent above.
func (a *v3agent) reply(m *wire.Message) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if m == nil || m.V3 == nil {
		// Not version 3 at all. This agent has nothing to say to it, which is
		// what a v3-only agent does.
		a.got = append(a.got, m)
		a.verified = append(a.verified, false)
		return nil
	}
	a.got = append(a.got, m)
	if len(m.V3.EngineID) == 0 {
		// RFC 3414 s4: a message naming no engine is discovery, and the answer
		// is a report that names this agent and its clock.
		a.discoveries++
		a.verified = append(a.verified, false)
		return a.report(m)
	}
	keys := a.keys()
	ok := m.V3.Level.Authenticated() && wire.Verify(m, keys.auth, a.auth) == nil
	a.verified = append(a.verified, ok)
	if !ok {
		return nil
	}
	pdu := m.PDU
	if m.V3.ScopedPDUEncrypted {
		plain, err := wire.Decrypt(m, keys.priv, a.priv)
		if err != nil {
			return nil
		}
		s, err := wire.ParseScoped(plain)
		if err != nil || s.PDU == nil {
			return nil
		}
		pdu = s.PDU
	}
	if pdu == nil {
		return nil
	}
	return a.answer(pdu.RequestID)
}

func (a *v3agent) keys() *usmKeys {
	return &usmKeys{
		auth: wire.PasswordToKey(a.auth, upAuthPass, a.engineID),
		priv: wire.PasswordToKey(a.auth, upPrivPass, a.engineID),
	}
}

// report is the unauthenticated answer to a discovery.
func (a *v3agent) report(m *wire.Message) []byte {
	pdu := response(m.PDU.RequestID, 4, 1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0)
	// A Report, not a Response: that is what makes a manager treat it as the
	// engine statement it is.
	pdu[0] = byte(wire.TagReport)
	scoped, err := wire.ScopedPDU(a.engineID, "", pdu)
	if err != nil {
		return nil
	}
	out, err := wire.BuildV3(wire.V3Build{
		MessageID: m.V3.MessageID, MaxSize: wire.MaxMessage, Level: wire.NoAuthNoPriv,
		EngineID: a.engineID, EngineBoots: a.boots, EngineTime: a.clock, Scoped: scoped,
	})
	if err != nil {
		return nil
	}
	return out
}

// answer is the agent's authenticated response.
func (a *v3agent) answer(requestID int64) []byte {
	pdu := response(requestID, 8, 1, 3, 6, 1, 2, 1, 1, 1, 0)
	scoped, err := wire.ScopedPDU(a.engineID, "", pdu)
	if err != nil {
		return nil
	}
	keys := a.keys()
	out, err := wire.BuildV3(wire.V3Build{
		MessageID: requestID, MaxSize: wire.MaxMessage, Level: a.answerLevel,
		EngineID: a.engineID, User: "relay", EngineBoots: a.boots, EngineTime: a.clock,
		Scoped: scoped, Auth: a.auth, AuthKey: keys.auth, Priv: a.priv, PrivKey: keys.priv,
	})
	if err != nil {
		return nil
	}
	return out
}

func (a *v3agent) seen() ([]*wire.Message, []bool, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*wire.Message(nil), a.got...), append([]bool(nil), a.verified...), a.discoveries
}

// passphraseFiles writes the two pass phrases where the configuration can
// reference them.
func passphraseFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth")
	priv := filepath.Join(dir, "priv")
	if err := os.WriteFile(auth, []byte(upAuthPass), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priv, []byte(upPrivPass), 0o600); err != nil {
		t.Fatal(err)
	}
	return auth, priv
}

// A version 2c poller reaching a version 3 only agent.
//
// This is the whole point of the upgrade. The manager sends a community string
// it has sent for twenty years; the agent receives an authenticated, encrypted
// version 3 message signed with a pass phrase the manager has never held; and
// the answer comes back to the manager in the version it spoke.
func TestAV2cPollerReachesAV3OnlyAgent(t *testing.T) {
	up := &v3agent{engineID: []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xaa, 0xbb, 0xcc},
		boots: 4, clock: 90210, answerLevel: wire.AuthPriv,
		auth: wire.AuthSHA256, priv: wire.PrivAES128}
	dev := startAgent(t, &agent{reply: up.reply})
	authFile, privFile := passphraseFiles(t)
	s, addr := snmpServer(t, `        upstream: agents
        versions: [v2c]
        communities: [public]
        default_action: allow
        upgrade_version: v3
        upstream_security_level: authPriv
        upstream_usm:
          name: relay
          auth: sha256
          auth_secret: file:`+authFile+`
          privacy: aes128
          privacy_secret: file:`+privFile, dev.pc.LocalAddr().String())

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(4242, 1, 3, 6, 1, 2, 1, 1, 1, 0)))

	// The manager gets its answer, in v2c, with its own community string.
	got := m.answer(t, 3*time.Second)
	if got == nil {
		t.Fatal("the manager got no answer")
	}
	if got.Version != wire.V2c {
		t.Fatalf("the manager was answered in %s, not the version it spoke", got.Version)
	}
	if got.Community != "public" {
		t.Fatalf("the answer carries the community %q", got.Community)
	}
	if got.PDU == nil || got.PDU.RequestID != 4242 {
		t.Fatalf("the answer does not match the question: %+v", got.PDU)
	}

	// And the agent received version 3, authenticated, encrypted, verified
	// against keys it derived from the pass phrase itself.
	seen, verified, discoveries := up.seen()
	if discoveries != 1 {
		t.Errorf("the agent saw %d discoveries, wanted exactly one", discoveries)
	}
	var authed int
	for i, msg := range seen {
		if msg == nil || msg.V3 == nil || len(msg.V3.EngineID) == 0 {
			continue
		}
		if msg.Version != wire.V3 {
			t.Errorf("message %d reached the agent as %s", i, msg.Version)
		}
		if msg.V3.User != "relay" {
			t.Errorf("message %d names the user %q", i, msg.V3.User)
		}
		if msg.V3.Level != wire.AuthPriv {
			t.Errorf("message %d arrived at %s", i, msg.V3.Level)
		}
		if !msg.V3.ScopedPDUEncrypted {
			t.Errorf("message %d arrived with a readable payload", i)
		}
		if !verified[i] {
			t.Errorf("message %d did not verify against the agent's own keys", i)
		}
		if !bytes.Equal(msg.V3.EngineID, up.engineID) {
			t.Errorf("message %d names the engine %x", i, msg.V3.EngineID)
		}
		authed++
	}
	if authed == 0 {
		t.Fatal("no authenticated message reached the agent")
	}
	sn := s.Stats()
	if sn.SNMPDiscoveries == 0 {
		t.Error("the discovery was not counted")
	}
	if sn.SNMPOriginated == 0 {
		t.Error("the originated request was not counted")
	}
}

// The community string the manager uses never reaches the agent, which is the
// credential separation the upgrade is for.
func TestTheManagersCredentialDoesNotReachTheAgent(t *testing.T) {
	up := &v3agent{engineID: []byte{0x80, 0x00, 0x1f, 0x88, 0x01}, boots: 1, clock: 10,
		answerLevel: wire.AuthNoPriv, auth: wire.AuthSHA1, priv: wire.PrivAES128}
	dev := startAgent(t, &agent{reply: up.reply})
	authFile, _ := passphraseFiles(t)
	_, addr := snmpServer(t, `        upstream: agents
        versions: [v2c]
        communities: [s3cr3t-community]
        default_action: allow
        upgrade_version: v3
        upstream_security_level: authNoPriv
        upstream_usm:
          name: relay
          auth: sha1
          auth_secret: file:`+authFile, dev.pc.LocalAddr().String())

	m := dialManager(t, addr)
	m.send(t, v2c("s3cr3t-community", get(7, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := m.answer(t, 3*time.Second); got == nil {
		t.Fatal("the manager got no answer")
	}
	seen, _, _ := up.seen()
	for i, msg := range seen {
		if msg == nil {
			continue
		}
		if msg.Community != "" {
			t.Errorf("message %d carried a community string to the agent: %q", i, msg.Community)
		}
		if bytes.Contains(msg.Raw, []byte("s3cr3t-community")) {
			t.Errorf("message %d carried the manager's community string in its octets", i)
		}
	}
}

// One discovery, however many requests arrive while it is outstanding. An
// agent answering one discovery per poll would be an agent this relay had
// turned into its own amplifier.
func TestABurstSendsOneDiscovery(t *testing.T) {
	up := &v3agent{engineID: []byte{0x80, 0x00, 0x1f, 0x88, 0x02}, boots: 1, clock: 5,
		answerLevel: wire.AuthNoPriv, auth: wire.AuthSHA256, priv: wire.PrivAES128}
	dev := startAgent(t, &agent{reply: up.reply})
	authFile, _ := passphraseFiles(t)
	s, addr := snmpServer(t, `        upstream: agents
        versions: [v2c]
        communities: [public]
        default_action: allow
        upgrade_version: v3
        upstream_security_level: authNoPriv
        upstream_usm:
          name: relay
          auth: sha256
          auth_secret: file:`+authFile, dev.pc.LocalAddr().String())

	m := dialManager(t, addr)
	for i := 0; i < 5; i++ {
		m.send(t, v2c("public", get(int64(100+i), 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPOriginated > 0 },
		"a request originated as v3")
	// Give the burst time to finish arriving before counting.
	time.Sleep(100 * time.Millisecond)
	_, _, discoveries := up.seen()
	if discoveries > 1 {
		t.Errorf("a burst of five requests sent %d discoveries", discoveries)
	}
}
