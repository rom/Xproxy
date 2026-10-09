package snmp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/snmp"
	"github.com/rom/xproxy/internal/testutil"
)

// The refusals on the stream transport.
//
// SNMP over TCP is what an estate uses where the messages are too large for a
// datagram -- a table walk, a v3 message carrying a long engine identifier --
// and it changes what a refusal costs: on a datagram each message is its own
// event, and on a stream a refusal has to decide between answering and ending
// the session, because the next octet after a message the relay would not read
// is a message boundary nobody agreed on.

const streamHead = `        upstream: agents
        transport: tcp
        allow_clients: ["127.0.0.0/8"]
`

func dialStream(t *testing.T, addr string) (net.Conn, *streamReader) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, newStreamReader(c, wire.MaxMessage)
}

// A client outside the list never reaches the agent, and the refusal is at
// accept: the connection has said nothing yet, and reading it to find out
// would be the work the list exists to avoid.
func TestAStreamFromAClientOutsideTheListIsRefused(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        transport: tcp
        allow_clients: ["10.0.0.0/8"]
        default_action: allow`, a.tcpAddr())

	c, _ := dialStream(t, addr)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("a client off the list was served")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPRejected >= 1 && sn.Refusals["snmp"]["client_not_allowed"] >= 1
	}, "the refused client")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("the agent was dialled anyway: %+v", seen)
	}
}

// deny_response: close ends the session instead of answering it. On a stream
// that is a real choice: an estate that would rather a poller noticed
// immediately sets it, and one that would rather every refusal looked like a
// permission error leaves it alone.
func TestOnAStreamDenyResponseCloseEndsTheSession(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, streamHead+`        read_only: true
        deny_response: close
        default_action: allow`, a.tcpAddr())

	c, _ := dialStream(t, addr)
	if _, err := c.Write(v2c("private", set(4001, "pwned", 1, 3, 6, 1, 2, 1, 1, 5, 0))); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("deny_response: close answered the refusal")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["read_only"] >= 1
	}, "the refusal")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("the write reached the agent: %+v", seen)
	}
}

// The per-client rate bound holds on a stream too, where one connection can
// carry as many messages as the client cares to send: a bound on connections
// would not be a bound on messages.
func TestAStreamIsRateLimitedPerClient(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, streamHead+`        rate_limit: 1
        default_action: allow`, a.tcpAddr())

	c, _ := dialStream(t, addr)
	for i := range 10 {
		if _, err := c.Write(v2c("public", get(int64(4100+i), 1, 3, 6, 1, 2, 1, 1, 1, 0))); err != nil {
			break
		}
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPRateLimited >= 1 && sn.Refusals["snmp"]["rate_limited"] >= 1
	}, "the rate limit on a stream")
}

// A message that is framed correctly and is not SNMP ends the session. The
// framing said where it ended, so the relay knows the boundary -- and it
// still has nothing to decide about, which is not a thing to forward to a
// device that will try to parse it.
func TestAFramedMessageThatIsNotSNMPEndsTheStream(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, streamHead+"        default_action: allow", a.tcpAddr())

	c, _ := dialStream(t, addr)
	// A well formed SEQUENCE holding a NULL: the length is honest and the
	// contents are not a message.
	if _, err := c.Write(tlv(wire.TagSequence, 0x05, 0x00)); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPMalformed >= 1 && sn.Refusals["snmp"]["malformed"] >= 1
	}, "the unparseable message")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("it reached the agent anyway: %+v", seen)
	}
}

// A listener whose agents are not reachable fails the session rather than
// holding a connection open with nothing behind it: a poller that is told
// nothing retries for ever, and a poller whose connection closed moves on.
func TestAStreamWhoseAgentIsNotThereIsAFailedSession(t *testing.T) {
	// A port nothing is listening on: taken and released, so the address is
	// routable and refuses.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()

	s, addr := snmpServer(t, streamHead+"        default_action: allow", dead)
	c, _ := dialStream(t, addr)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("a session with no agent behind it was held open")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPUpstreamFail >= 1 },
		"the unreachable agent")
}

// A stream listener with a certificate takes TLS from the first octet, which
// is RFC 6353's transport. The handshake is the admission: a plaintext client
// never reaches the framing, so there is no unencrypted session to have.
func TestAStreamListenerWithACertificateRefusesAPlaintextClient(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "127.0.0.1")
	a := startAgent(t, &agent{})
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: poll
      address: "127.0.0.1:0"
      kind: snmp
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
      snmp:
%s        tls_mode: implicit
        default_action: allow
logging: {access: {enabled: false}}
upstreams:
  - {name: agents, endpoints: [{address: %q}]}
`, cert, key, streamHead, a.tcpAddr()))
	addr := proxytest.Addr(t, s, "poll")

	// The client that speaks it gets through.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("the test CA did not read back")
	}
	tc, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("a TLS client was refused: %v", err)
	}
	defer func() { _ = tc.Close() }()
	if _, err := tc.Write(v2c("public", get(4201, 1, 3, 6, 1, 2, 1, 1, 1, 0))); err != nil {
		t.Fatal(err)
	}
	a.await(t, 1, "the poll over TLS to reach the agent")

	// And the one that does not is refused at the handshake.
	plain, _ := dialStream(t, addr)
	if _, err := plain.Write(v2c("public", get(4202, 1, 3, 6, 1, 2, 1, 1, 1, 0))); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["tls_handshake"] >= 1
	}, "the plaintext client")
}

// The amplification bound on a version 3 message is a refusal rather than a
// rewrite, on a stream as on a datagram. The repetition count sits inside a
// header with its own lengths and security parameters: rebuilding that is
// forging a v3 message rather than relaying one, so the honest answer is no.
func TestAVersionThreeBulkPastTheBoundIsRefusedOnAStream(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, streamHead+`        versions: [v3]
        min_security_level: noAuthNoPriv
        max_repetitions: 10
        default_action: allow`, a.tcpAddr())

	c, _ := dialStream(t, addr)
	if _, err := c.Write(v3(0x04, "nms", "", bulk(4301, 400, 1, 3, 6, 1, 2, 1))); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.SNMPAmplified >= 1 && sn.Refusals["snmp"]["max_repetitions"] >= 1
	}, "the amplifying bulk request")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("the amplifier reached the agent: %+v", seen)
	}
}

// Where a refusal goes besides the counter, and what the record carries.
//
// The ban ladder hears about it before alert_on_deny can silence the record,
// because turning the log down is not a decision to stop responding -- and
// the record names the rule that decided, so an operator reading it knows
// which line of the file to argue with.
func TestARefusalReachesTheBanLadderAndNamesItsRule(t *testing.T) {
	a := startAgent(t, &agent{})
	bans := func() string {
		return "bans:\n  action: reject\n  state_file: " +
			filepath.Join(t.TempDir(), "bans.state")
	}
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: poll
      address: "127.0.0.1:0"
      kind: snmp
      snmp:
        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v2c, v3]
        communities: [nms]
        log_messages: true
        rules:
          - {name: no-writes, action: deny, access: [write]}
          - {name: mib-2, action: allow, access: [read], oids: ["1.3.6.1.2.1"]}
logging: {access: {enabled: false}}
upstreams:
  - {name: agents, endpoints: [{address: %q}]}
`, bans(), a.udpAddr()))
	addr := proxytest.Addr(t, s, "poll")

	m := dialManager(t, addr)
	m.send(t, v2c("nms", set(5001, "pwned", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["snmp_rule"] >= 1 || sn.SNMPDenied >= 1
	}, "the refusal by rule")
	if seen := a.seen(); len(seen) != 0 {
		t.Errorf("the refused write reached the agent: %+v", seen)
	}

	// A version 3 message naming a context, so the record carries it: the
	// context is which MIB view the manager asked for, and a refusal that did
	// not say which would be a refusal nobody can place.
	m.send(t, v3(0x04, "nms", "vrf-blue", set(5002, "pwned", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPDenied >= 2 },
		"the version 3 refusal")

	// With the alerts off the counters and the ban observation still happen
	// and the security event does not.
	a2 := startAgent(t, &agent{})
	s2 := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: poll
      address: "127.0.0.1:0"
      kind: snmp
      snmp:
        upstream: agents
        allow_clients: ["127.0.0.0/8"]
        versions: [v2c]
        communities: [nms]
        alert_on_deny: false
        read_only: true
        default_action: allow
logging: {access: {enabled: false}}
upstreams:
  - {name: agents, endpoints: [{address: %q}]}
`, bans(), a2.udpAddr()))
	m2 := dialManager(t, proxytest.Addr(t, s2, "poll"))
	m2.send(t, v2c("nms", set(5003, "pwned", 1, 3, 6, 1, 2, 1, 1, 5, 0)))
	awaitCounter(t, s2, func(sn proxy.Snapshot) bool {
		return sn.Refusals["snmp"]["read_only"] >= 1
	}, "the refusal with the alerts off")
}
