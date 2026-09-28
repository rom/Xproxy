package snmp

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/snmp"
	"github.com/rom/xproxy/internal/testutil"
)

// SNMP inside DTLS, against the library that will do the handshake in the
// field: the client is pion's own DTLS client, the certificates are real ones
// signed by a real authority, and every message asserted on went through the
// record layer both ways.
//
// What each test is about is the same question asked of a different half: does
// the identity a certificate carries actually decide anything, and does the
// answer get back into the session it came from.

const dtlsYAML = `
version: 1
server:
  listeners:
    - name: poll
      address: "127.0.0.1:0"
      kind: snmp
      tls:
        certificates:
          - {cert_file: %q, key_file: %q}
        client_auth: %s
        client_ca_file: %q
      snmp:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: agents, endpoints: [{address: %q}]}
`

// estate is the certificates a test works with: an authority, the relay's own
// certificate, and whatever client certificates the test issued.
type estate struct {
	ca                    *testutil.CA
	dir                   string
	serverCert, serverKey string
}

func newEstate(t *testing.T) *estate {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "relay.example.com")
	return &estate{ca: ca, dir: dir, serverCert: cert, serverKey: key}
}

// client issues a client certificate for one name and loads it.
func (e *estate) client(t *testing.T, name string) tls.Certificate {
	t.Helper()
	cert, key := e.ca.Issue(t, e.dir, name)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// fingerprint is the sha256 of a certificate's DER, written the way a
// configuration writes one.
func fingerprint(t *testing.T, c tls.Certificate) string {
	t.Helper()
	if len(c.Certificate) == 0 {
		t.Fatal("a certificate with no DER")
	}
	sum := sha256.Sum256(c.Certificate[0])
	return "sha256:" + hex.EncodeToString(sum[:])
}

// dtlsServer starts a relay whose datagram half is inside DTLS.
func dtlsServer(t *testing.T, e *estate, clientAuth, section, agentAddr string) (*proxy.Server, string) {
	t.Helper()
	if _, err := os.Stat(e.serverCert); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(dtlsYAML, e.serverCert, e.serverKey, clientAuth, e.ca.Path, section, agentAddr)
	s := proxytest.Start(t, cfg)
	return s, proxytest.Addr(t, s, "poll")
}

// dtlsManager is a management station that handshakes DTLS and then speaks
// SNMP inside the session.
type dtlsManager struct{ conn *dtls.Conn }

func dialDTLS(t *testing.T, addr string, certs ...tls.Certificate) *dtlsManager {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	opts := []dtls.ClientOption{
		// The relay's certificate is a fresh one per test, so the client does
		// not verify it: what is under test is the relay's side of the
		// handshake and what it does with the session.
		dtls.WithInsecureSkipVerify(true),
	}
	if len(certs) > 0 {
		opts = append(opts, dtls.WithCertificates(certs...))
	}
	conn, err := dtls.ClientWithOptions(pc, ua, opts...)
	if err != nil {
		t.Fatalf("building the client failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Handshake(); err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}
	return &dtlsManager{conn: conn}
}

func (m *dtlsManager) send(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := m.conn.Write(raw); err != nil {
		t.Fatal(err)
	}
}

func (m *dtlsManager) answer(t *testing.T, within time.Duration) *wire.Message {
	t.Helper()
	_ = m.conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 65535)
	n, err := m.conn.Read(buf)
	if err != nil {
		return nil
	}
	got, err := wire.Parse(buf[:n])
	if err != nil {
		t.Fatalf("the relay sent the manager something unparseable: %v", err)
	}
	return got
}

// tsm builds a version 3 message under the transport security model: no
// security parameters, the flags the transport's level implies, and the scoped
// PDU in the clear.
func tsm(msgID int64, flags byte, pdu []byte) []byte {
	scoped, err := wire.ScopedPDU(nil, "", pdu)
	if err != nil {
		panic(err)
	}
	lvl := wire.NoAuthNoPriv
	switch {
	case flags&0x03 == 0x03:
		lvl = wire.AuthPriv
	case flags&0x01 != 0:
		lvl = wire.AuthNoPriv
	}
	out, err := wire.BuildTSM(wire.TSMBuild{MessageID: msgID, MaxSize: 65507,
		Level: lvl, Reportable: flags&0x04 != 0, Scoped: scoped})
	if err != nil {
		panic(err)
	}
	return out
}

// The exchange this whole transport exists for: a manager holding nothing but a
// certificate polls a switch that will never speak anything but v2c.
//
// Every part of it is the point. The request arrives as v3 under the transport
// security model, is downgraded to v2c with a community string the manager never
// learns, and the agent's v2c answer comes back rebuilt in the manager's own v3
// envelope -- which is possible only because a TSM message carries no digest, so
// the session authenticates the answer rather than a key this relay does not
// hold.
func TestATransportSecurityModelPollReachesAV2cAgentAndIsAnsweredInTheSession(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	s, addr := dtlsServer(t, e, "require", `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        upgrade_version: v2c
        upstream_community: switch-secret
        cert_to_name:
          - {fingerprint: any, map: san_dns}
        rules:
          - name: nms
            action: allow
            transports: [dtls]
            security_names: [nms1.ops.example.com]
            access: [read]
            oids: ["1.3.6.1.2.1"]`, a.udpAddr())

	m := dialDTLS(t, addr, e.client(t, "nms1.ops.example.com"))
	m.send(t, tsm(7, 0x03, get(301, 1, 3, 6, 1, 2, 1, 1, 1, 0)))

	seen := a.await(t, 1, "the poll did not reach the agent")
	if seen[0] == nil {
		t.Fatal("the agent could not parse what arrived")
	}
	// What reached the equipment is v2c with the relay's own credential: the
	// manager's certificate opened this relay, and this relay's community
	// string opened the switch.
	if seen[0].Version != wire.V2c {
		t.Errorf("the agent saw %s, want v2c", seen[0].Version)
	}
	if seen[0].Community != "switch-secret" {
		t.Errorf("the agent saw community %q", seen[0].Community)
	}
	if seen[0].PDU.RequestID != 301 {
		t.Errorf("the agent saw request %d", seen[0].PDU.RequestID)
	}

	got := m.answer(t, 3*time.Second)
	if got == nil {
		t.Fatal("the manager got no answer inside its session")
	}
	// And what came back is v3 under the same model, with the message
	// identifier the manager's stack pairs it by.
	if !got.IsTSM() {
		t.Fatalf("the answer was %s model %v", got.Version, got.V3)
	}
	if got.V3.MessageID != 7 {
		t.Errorf("the answer echoed message id %d, want 7", got.V3.MessageID)
	}
	if got.PDU == nil || got.PDU.Type != wire.Response || got.PDU.RequestID != 301 {
		t.Fatalf("the answer was %+v", got.PDU)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPTSMMessages >= 1 && sn.SNMPDTLSHandshakes >= 1
	}, "the session was not counted")
}

// The name the certificate carries is what the rule names, so a different
// certificate is a different principal even from the same address and the same
// authority.
func TestTheNameACertificateCarriesIsWhatTheRuleNames(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	_, addr := dtlsServer(t, e, "require", `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        cert_to_name:
          - {fingerprint: any, map: san_dns}
        rules:
          - name: nms
            action: allow
            security_names: [nms1.ops.example.com]
            access: [read]
            oids: ["1.3.6.1.2.1"]`, a.udpAddr())

	// The laptop's certificate is from the same authority and its address is
	// the same address. The only thing that differs is the name.
	other := dialDTLS(t, addr, e.client(t, "laptop.example.com"))
	other.send(t, tsm(11, 0x03, get(401, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := other.answer(t, time.Second); got == nil {
		t.Error("the refusal was a timeout, not an error a manager displays")
	} else if got.PDU == nil || got.PDU.ErrorStatus != wire.StatusNoAccess {
		t.Errorf("the answer was %+v", got.PDU)
	}
	if seen := a.seen(); len(seen) != 0 {
		t.Fatalf("a name no rule names reached the agent: %+v", seen)
	}

	// And the one the rule names is relayed.
	nms := dialDTLS(t, addr, e.client(t, "nms1.ops.example.com"))
	nms.send(t, tsm(12, 0x03, get(402, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	seen := a.await(t, 1, "the name the rule names did not reach the agent")
	if seen[0] == nil || seen[0].PDU.RequestID != 402 {
		t.Fatalf("the agent saw %+v", seen[0])
	}
}

// A fingerprint names one certificate, which is the standard's own arrangement:
// the row is keyed by the hash of the DER, and another certificate for the same
// name does not match it.
func TestAFingerprintNamesOneCertificateAndNotAName(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	pinned := e.client(t, "nms1.ops.example.com")
	_, addr := dtlsServer(t, e, "require", fmt.Sprintf(`        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        cert_to_name:
          - fingerprint: %q
            map: specified
            name: nms-primary
        rules:
          - {name: nms, action: allow, security_names: [nms-primary], access: [read], oids: ["1.3.6.1.2.1"]}`,
		fingerprint(t, pinned)), a.udpAddr())

	m := dialDTLS(t, addr, pinned)
	m.send(t, tsm(21, 0x03, get(501, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	seen := a.await(t, 1, "the pinned certificate did not reach the agent")
	if seen[0] == nil || seen[0].PDU.RequestID != 501 {
		t.Fatalf("the agent saw %+v", seen[0])
	}

	// A second certificate, reissued for the same name by the same authority,
	// is a different certificate and the row does not name it. That is the
	// standard's arrangement rather than an accident, and it is the reason
	// `fingerprint: any` exists for an estate that would otherwise edit this
	// file on every renewal.
	reissued := e.client(t, "nms1.ops.example.com")
	if fingerprint(t, reissued) == fingerprint(t, pinned) {
		t.Fatal("the two certificates have the same fingerprint")
	}
	other := dialDTLS(t, addr, reissued)
	other.send(t, tsm(22, 0x03, get(502, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := other.answer(t, time.Second); got == nil {
		t.Error("the refusal was a timeout")
	}
	if seen := a.seen(); len(seen) != 1 {
		t.Fatalf("a certificate no row names reached the agent: %+v", seen)
	}
}

// A message whose certificate maps to no name at all. The model carries no
// user, no engine and no digest, so there is no credential left -- and what
// happens next is a decision the listener makes out loud.
func TestAMessageWithNoDerivedNameIsRefusedUnlessTheListenerSaysOtherwise(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	// A row about a certificate nobody in this test holds, so nothing maps.
	elsewhere := "sha256:" + hex.EncodeToString(make([]byte, 32))
	s, addr := dtlsServer(t, e, "require", fmt.Sprintf(`        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        default_action: allow
        cert_to_name:
          - {fingerprint: %q, map: specified, name: somebody-else}`, elsewhere), a.udpAddr())

	m := dialDTLS(t, addr, e.client(t, "nms1.ops.example.com"))
	m.send(t, tsm(31, 0x03, get(601, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := m.answer(t, time.Second); got == nil {
		t.Error("the refusal was a timeout")
	}
	if seen := a.seen(); len(seen) != 0 {
		t.Fatalf("a message with no name reached the agent: %+v", seen)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPTSMUnnamed >= 1 && sn.Refusals["snmp"]["tsm_no_name"] >= 1
	}, "the unnamed message was not counted")

	// The same listener with require_security_name: false decides on the
	// address and the objects alone, which is a listener that wanted DTLS for
	// confidentiality rather than for identity.
	b := startAgent(t, &agent{})
	_, open := dtlsServer(t, e, "require", fmt.Sprintf(`        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        default_action: allow
        require_security_name: false
        cert_to_name:
          - {fingerprint: %q, map: specified, name: somebody-else}`, elsewhere), b.udpAddr())
	m2 := dialDTLS(t, open, e.client(t, "nms1.ops.example.com"))
	m2.send(t, tsm(32, 0x03, get(602, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	seen := b.await(t, 1, "a listener that does not require a name refused anyway")
	if seen[0] == nil || seen[0].PDU.RequestID != 602 {
		t.Fatalf("the agent saw %+v", seen[0])
	}
}

// A message claiming less than the session gave. RFC 5591 s3.1.1 has the sender
// copy the flags from the transport's security level and RFC 6353 s3.1.2 says a
// (D)TLS transport provides authPriv, so authNoPriv inside DTLS is a sender that
// either did not implement the model or is asking whether this listener reads
// the flags as policy.
func TestATransportModelMessageClaimingLessThanTheSessionGaveIsRefused(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	s, addr := dtlsServer(t, e, "require", `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        default_action: allow
        cert_to_name:
          - {fingerprint: any, map: san_dns}`, a.udpAddr())

	m := dialDTLS(t, addr, e.client(t, "nms1.ops.example.com"))
	// authNoPriv, inside a session that encrypted it.
	m.send(t, tsm(41, 0x01, get(701, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := m.answer(t, time.Second); got == nil {
		t.Error("the refusal was a timeout")
	}
	if seen := a.seen(); len(seen) != 0 {
		t.Fatalf("a message disagreeing with its session reached the agent: %+v", seen)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["tsm_level"] >= 1
	}, "the level mismatch was not counted")

	// And the same message with the flags the session actually justifies is
	// relayed, so the check is about the disagreement and not about the model.
	m.send(t, tsm(42, 0x03, get(702, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	seen := a.await(t, 1, "an authPriv message was refused too")
	if seen[0] == nil || seen[0].PDU.RequestID != 702 {
		t.Fatalf("the agent saw %+v", seen[0])
	}
}

// A transport security model message on a transport that provides no security.
//
// The model's whole claim is that the transport authenticated and encrypted the
// message: the flags say authPriv and there is no digest, because the session
// was supposed to be the digest. Arriving as a plain datagram, that claim is
// backed by nothing, and forwarding it would mean carrying "authenticated and
// encrypted" on a datagram from an address anybody can claim.
//
// It is refused even where require_security_name is off, because the two are
// different questions: that switch is about whether a *name* is needed, and this
// is about whether the message's own statement about its transport is true.
func TestATransportModelMessageOnAPlainDatagramIsRefused(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, tsm(61, 0x03, get(1001, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	// The refusal is answerable under this model, which is the other half of
	// what makes it worth relaying -- but nothing reaches the agent.
	if got := m.answer(t, time.Second); got != nil && got.PDU != nil &&
		got.PDU.ErrorStatus != wire.StatusNoAccess {
		t.Errorf("the answer was %+v", got.PDU)
	}
	if seen := a.seen(); len(seen) != 0 {
		t.Fatalf("a transport model message on a plain datagram reached the agent: %+v", seen)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["tsm_transport"] >= 1
	}, "the transport mismatch was not counted")
}

// Cleartext at a listener that requires DTLS. There is no session to answer in
// and answering would tell a scanner that something is here, so it is counted
// and dropped.
func TestCleartextAtADTLSListenerIsRefusedAndCounted(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	s, addr := dtlsServer(t, e, "require", `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(801, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := m.answer(t, 500*time.Millisecond); got != nil {
		t.Errorf("a plain datagram was answered: %+v", got.PDU)
	}
	if seen := a.seen(); len(seen) != 0 {
		t.Fatalf("a plain datagram reached the agent: %+v", seen)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["cleartext_at_dtls_listener"] >= 1
	}, "the cleartext datagram was not counted")
}

// detect mode: both on one port, and the policy is what tells them apart.
//
// This is the migration case, and the test is the shape of the configuration an
// estate part-way through one actually writes: the operations centre reaching
// the relay inside DTLS with a certificate, the plant's own pollers still
// sending plain v2c, and a narrower policy for the second.
func TestDetectModeTakesBothAndTheTransportDecides(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	_, addr := dtlsServer(t, e, "require", `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: detect
        default_action: deny
        cert_to_name:
          - {fingerprint: any, map: san_dns}
        rules:
          - name: nms
            action: allow
            transports: [dtls]
            security_names: [nms1.ops.example.com]
            access: [read]
            oids: ["1.3.6.1.2.1"]
          - name: plant-pollers
            action: allow
            transports: [udp]
            communities: [plant-ro]
            access: [read]
            oids: ["1.3.6.1.2.1.2"]`, a.udpAddr())

	// The plant's poller, plain v2c, inside the subtree its rule names.
	plain := dialManager(t, addr)
	plain.send(t, v2c("plant-ro", get(901, 1, 3, 6, 1, 2, 1, 2, 2, 1, 1)))
	seen := a.await(t, 1, "the plain poller did not reach the agent")
	if seen[0] == nil || seen[0].PDU.RequestID != 901 {
		t.Fatalf("the agent saw %+v", seen[0])
	}

	// The same poller reaching outside it. The operations centre's rule names
	// the wider subtree and the plant's does not, and a plain datagram is not
	// covered by a rule naming dtls however wide that rule is.
	plain.send(t, v2c("plant-ro", get(902, 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	if got := plain.answer(t, time.Second); got == nil {
		t.Error("the refusal was a timeout")
	}

	// And the operations centre, in a session on the same port.
	secure := dialDTLS(t, addr, e.client(t, "nms1.ops.example.com"))
	secure.send(t, tsm(51, 0x03, get(903, 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	seen = a.await(t, 2, "the DTLS manager did not reach the agent")
	last := seen[len(seen)-1]
	if last == nil || last.PDU.RequestID != 903 {
		t.Fatalf("the agent saw %+v", last)
	}
}

// A listener that requires a client certificate and a peer that has none.
//
// Two things are under test and the second is the interesting one. The peer gets
// no session, which is the certificate policy doing its job. And the relay's
// side of the failure is bounded by dtls_handshake_timeout rather than by
// whatever the peer chooses to do next: the server sends its alert and the peer
// simply stops, so without the bound this would be a socket, a goroutine and a
// slot in the peer table held by somebody who proved nothing. The count is also
// what separates an estate whose certificates expired -- every handshake fails
// and the sessions count stops climbing -- from a scanner sending flights of
// nonsense at the port, which never touches it.
func TestAPeerWithNoCertificateIsEndedByTheHandshakeBound(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	s, addr := dtlsServer(t, e, "require", `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        default_action: allow
        dtls_handshake_timeout: 1s
        cert_to_name:
          - {fingerprint: any, map: san_dns}`, a.udpAddr())

	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	conn, err := dtls.ClientWithOptions(pc, ua, dtls.WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// The handshake is expected to fail, and which side notices first is the
	// library's business, so the assertion is the relay's counter rather than
	// this error.
	if err := conn.Handshake(); err == nil {
		t.Fatal("a peer with no certificate got a session")
	}
	// The peer stops here, which is what makes the bound the thing that ends
	// this: the relay is left waiting for a flight that will not come.
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPDTLSHandshakeFail >= 1 &&
			sn.Refusals["snmp"]["dtls_handshake_failed"] >= 1
	}, "the failed handshake was not counted")
	if sn := s.Stats(); sn.SNMPDTLSSessions != 0 {
		t.Errorf("%d sessions after a handshake that failed", sn.SNMPDTLSSessions)
	}
	if seen := a.seen(); len(seen) != 0 {
		t.Fatalf("a peer with no certificate reached the agent: %+v", seen)
	}
}

// A message past the bound, inside a session.
//
// The bound is applied to the plaintext after the record layer, which is where
// it has to be: a message is refused unread because reading it to find out what
// it asked for is the work the bound exists to avoid, and inside DTLS "unread"
// means after decryption and before parsing. There is somebody to say so to,
// but nothing to say it against -- the message was not parsed, so there is no
// request identifier to answer -- so it is counted and dropped.
func TestAnOversizeMessageInsideASessionIsRefusedUnread(t *testing.T) {
	e := newEstate(t)
	a := startAgent(t, &agent{})
	s, addr := dtlsServer(t, e, "require", `        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        dtls_mode: implicit
        default_action: allow
        max_message_bytes: 484
        cert_to_name: [{fingerprint: any, map: san_dns}]`, a.udpAddr())

	m := dialDTLS(t, addr, e.client(t, "nms1.ops.example.com"))
	// A valid message, and too long: the value is what makes it long, so
	// nothing about it is malformed except its size.
	long := v2c("public", set(1101, strings.Repeat("x", 600), 1, 3, 6, 1, 2, 1, 1, 5, 0))
	if len(long) <= 484 {
		t.Fatalf("the test message is %d octets, which is inside the bound", len(long))
	}
	m.send(t, long)
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["message_too_large"] >= 1
	}, "the oversize message was not counted")
	if seen := a.seen(); len(seen) != 0 {
		t.Fatalf("a message past the bound reached the agent: %+v", seen)
	}
	// And the session is still usable: the bound refused one message rather
	// than the peer, because a poller that sent one oversize request is not a
	// peer to stop reading from.
	m.send(t, v2c("public", get(1102, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	seen := a.await(t, 1, "the session did not survive an oversize message")
	if seen[0] == nil || seen[0].PDU.RequestID != 1102 {
		t.Fatalf("the agent saw %+v", seen[0])
	}
}

// Why a session has no certificate to derive a name from, which is two facts
// rather than one: a peer that offered none was not configured with one, and a
// certificate that would not parse means the peer was. An operator reading the
// first looks at the client's configuration and one reading the second looks at
// its certificate store.
func TestTheReasonSaysWhetherThereWasACertificateAtAll(t *testing.T) {
	if got := certReason(dtlsx.ErrNoCertificate); got != "no_certificate" {
		t.Errorf("a peer with no certificate reported %q", got)
	}
	if got := certReason(errors.New("x509: malformed certificate")); got != "bad_certificate" {
		t.Errorf("a certificate that would not parse reported %q", got)
	}
}
