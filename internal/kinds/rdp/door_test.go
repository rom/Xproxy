package rdp_test

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/rdp"
)

// The bounds that end a session without anything in the protocol being
// wrong: the address an operator did not allow, the ban a refusal
// earned, and the session bound.

// gatewayWithTop is gateway with lines outside the listener too, for
// the sections -- bans, for one -- that are the estate's rather than
// this listener's.
func gatewayWithTop(t *testing.T, d *desktop, extra, top string) (*proxy.Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desks
      address: "127.0.0.1:0"
      kind: rdp
      rdp:
        upstream: farm
%s
logging: {access: {enabled: false}}
upstreams:
  - name: farm
    endpoints: [{address: %s}]
%s
`, extra, d.addr(), top)
	s := proxytest.Start(t, yaml)
	return s, proxytest.Addr(t, s, "desks")
}

// An address outside allow_clients is refused before a single octet of
// the protocol is read, which is the point of having the list: a
// listener that read the negotiation first would be parsing attacker
// input it had already decided not to serve.
func TestAnAddressOutsideTheAllowListIsRefusedAtTheDoor(t *testing.T) {
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolRDP})
	s, addr := gateway(t, d, "        security: [rdp]\n        allow_clients: [192.0.2.0/24]")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	req, err := rdp.ConnectionRequest{HasNegotiation: true, Protocols: rdp.ProtocolSSL}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// The request may or may not be written before the socket closes;
	// either way nothing comes back.
	_, _ = conn.Write(req)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := io.ReadFull(conn, make([]byte, 4)); err == nil {
		t.Errorf("a client outside allow_clients was answered: %d octets", n)
	}
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().RDPRejected > 0 })
	if len(d.asked()) != 0 {
		t.Error("a refused client reached the desktop")
	}
}

// A refusal is observed by the ban ladder, and the ban is applied at
// the door: the next connection from that address is dropped without
// the negotiation being read at all.
func TestARefusalEarnsABanAndTheBanIsAppliedAtTheDoor(t *testing.T) {
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolRDP})
	s, addr := gatewayWithTop(t, d, "        security: [rdp]\n        alert_on_deny: false", `bans:
  action: reject
  triggers: [{name: desks, reasons: [rdp_denied], threshold: 1, window: 1m, duration: 1h}]`)

	// A first PDU that is not a connection request at all.
	first, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// A well-formed TPKT frame whose body is not an X.224 connection
	// request: the framing is read, the negotiation is not.
	if _, err := first.Write([]byte{0x03, 0x00, 0x00, 0x08, 0x03, 0xff, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	waitFor(t, "the refusal to be counted", func() bool { return len(s.Stats().Refusals["rdp"]) > 0 })

	again, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	req, err := rdp.ConnectionRequest{HasNegotiation: true, Protocols: rdp.ProtocolSSL}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = again.Write(req)
	_ = again.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := io.ReadFull(again, make([]byte, 4)); err == nil {
		t.Errorf("a banned address was answered: %d octets", n)
	}
}

// A session bound ends a session: an operator who set one is saying how
// long a desktop may be held, and the clock starts when the connection
// arrives rather than when the handshake finishes -- a session stuck in
// a handshake is one the bound has to reach too.
func TestTheSessionBoundEndsTheSession(t *testing.T) {
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolRDP})
	_, addr := gateway(t, d, "        security: [rdp]\n        session_timeout: 1s")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	start := time.Now()
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("the session ended with %v rather than being closed", err)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Errorf("the session bound took %s to end the session", took)
	}
}
