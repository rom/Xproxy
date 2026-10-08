package udp_test

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// udpWith starts a relay in front of the echo server with its own
// top-level sections, which the shared helper does not reach: the ban
// list and the estate's authorisation policy both sit outside the
// listener.
func udpWith(t *testing.T, e *echoUDP, listener, top string) (*proxy.Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: games
      address: "127.0.0.1:0"
      kind: udp
      udp:
        upstream: backends
%s
logging: {access: {enabled: false}}
upstreams:
  - name: backends
    endpoints: [{address: %s}]
`, top, listener, e.addr())
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["games"]
}

// silence asserts that nothing comes back, which on a datagram relay is
// what a refusal looks like: there is no error code to send.
func silence(t *testing.T, c *net.UDPConn, payload string) {
	t.Helper()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 65535)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("a refused datagram was answered with %q", buf[:n])
	}
}

// A client the policy does not admit is dropped, the ban ladder is told,
// and with alert_on_deny off the record stops while the ladder does not:
// turning the logging down is not a decision to stop responding.
func TestARefusedClientIsObservedWhetherOrNotItIsAlerted(t *testing.T) {
	for _, tc := range []struct {
		name     string
		listener string
	}{
		{"with the record on", "        allow_clients: [\"10.0.0.0/8\"]"},
		{"and with it off", "        allow_clients: [\"10.0.0.0/8\"]\n        alert_on_deny: false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := startEchoUDP(t, "")
			s, addr := udpWith(t, e, tc.listener, `bans:
  triggers:
    - {name: udp, reasons: [udp_denied], threshold: 1, window: 1m, duration: 10m}`)
			silence(t, dialUDP(t, addr), "hello")
			eventually(t, 2*time.Second, "the refusal to reach the ban ladder", func() bool {
				return s.Bans().Banned(netip.MustParseAddr("127.0.0.1"))
			})
			if n := s.Stats().Refusals["udp"]["client_not_allowed"]; n < 1 {
				t.Errorf("the refusal was not counted: %d", n)
			}
		})
	}
}

// A shadowed listener records what it would have refused and relays the
// datagram anyway, which is the only way to find out what enforcing an
// authorisation policy would cost before enforcing it.
func TestAShadowedUDPListenerRecordsWhatItWouldRefuse(t *testing.T) {
	e := startEchoUDP(t, "")
	s, addr := udpWith(t, e, "", `policy: {mode: shadow}
authorization:
  rules:
    - {name: not-loopback, networks: ["127.0.0.0/8"]}`)
	if got := exchange(t, dialUDP(t, addr), "hello"); got != "hello" {
		t.Errorf("a shadowed listener did not relay: %q", got)
	}
	found := false
	for _, ent := range s.Shadow().Report() {
		if ent.Kind == "udp" && ent.Rule == "not-loopback" {
			found = true
		}
	}
	if !found {
		t.Errorf("no shadow entry naming the rule: %+v", s.Shadow().Report())
	}
	if n := s.Stats().Refusals["udp"]["authorization"]; n != 0 {
		t.Errorf("a shadowed refusal was counted as a refusal: %d", n)
	}
}

// The session table is bounded, and the bound is per source address and
// port: a datagram from a new client when the table is full is dropped
// rather than queued, because a UDP relay with an unbounded table is a
// memory bound somebody else chooses.
func TestANewClientPastTheSessionBoundIsDropped(t *testing.T) {
	e := startEchoUDP(t, "")
	s, addr := udpWith(t, e, "        max_sessions: 1\n        max_sessions_per_ip: 1", "")
	first := dialUDP(t, addr)
	if got := exchange(t, first, "first"); got != "first" {
		t.Fatalf("the first client was not relayed: %q", got)
	}
	silence(t, dialUDP(t, addr), "second")
	eventually(t, 2*time.Second, "the second client to be refused", func() bool {
		return s.Stats().Refusals["udp"]["max_sessions"] >= 1 && s.Stats().UDPRejected >= 1
	})
	// And the client that holds the one session still works.
	if got := exchange(t, first, "again"); got != "again" {
		t.Errorf("the established session stopped working: %q", got)
	}
}

// An answer larger than the bound is dropped rather than truncated: a
// datagram cut in half is a different datagram, and handing one to a
// client that asked for a whole one is worse than handing it nothing.
func TestAnOversizeAnswerIsDroppedRatherThanTruncated(t *testing.T) {
	// The echo server prefixes its reply, so the answer is larger than
	// the request: the request is inside the bound and the answer is not.
	e := startEchoUDP(t, "0123456789012345678901234567890123456789")
	s, addr := udpWith(t, e, "        max_datagram_bytes: 20", "")
	silence(t, dialUDP(t, addr), "hello")
	eventually(t, 2*time.Second, "the oversize answer to be dropped", func() bool {
		return s.Stats().Refusals["udp"]["upstream_datagram_too_large"] >= 1
	})
}

// The byte bound ends the session rather than refusing a datagram in
// the middle of it, and the counters name which bound it was.
func TestTheByteBoundEndsTheSession(t *testing.T) {
	e := startEchoUDP(t, "")
	s, addr := udpWith(t, e, "        max_bytes_in: 1", "")
	// The bound is a byte, so the first datagram reaches it: the session
	// ends and the answer never comes, rather than the datagram being
	// refused in the middle of a session that stays open.
	silence(t, dialUDP(t, addr), "hello")
	eventually(t, 5*time.Second, "the session to end on the byte bound", func() bool {
		return s.Stats().UDPSessionsOpen == 0
	})
	if sn := s.Stats(); sn.UDPBytesIn != 5 {
		t.Errorf("inbound bytes %d, want the five that were sent", sn.UDPBytesIn)
	}
}

// A client that keeps sending keeps its session, even where the
// endpoint says nothing back for longer than the idle bound.
//
// The two sides of a datagram session go idle independently: the pump's
// read deadline is the idle bound, so without this a silent endpoint
// would end a session the client is still using -- and the next
// datagram would be relayed from a new source port, which on a protocol
// that keys state by port is a new client to whatever is behind it.
func TestASilentEndpointDoesNotEndABusySession(t *testing.T) {
	// A sink that reads and never answers, so only the client side is
	// ever active.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: games
      address: "127.0.0.1:0"
      kind: udp
      udp:
        upstream: backends
        idle_timeout: 200ms
logging: {access: {enabled: false}}
upstreams:
  - name: backends
    endpoints: [{address: %s}]
`, pc.LocalAddr().String()))
	c := dialUDP(t, s.Addrs()["games"])
	// Five datagrams over three idle bounds: the session has to survive
	// every one of the pump's read deadlines.
	for i := 0; i < 5; i++ {
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(120 * time.Millisecond)
		if n := s.Stats().UDPSessionsOpen; n != 1 {
			t.Fatalf("after %d datagrams the session count is %d, want 1", i+1, n)
		}
	}
	// And once the client stops, the session does end.
	eventually(t, 3*time.Second, "the idle session to end", func() bool {
		return s.Stats().UDPSessionsOpen == 0
	})
}

// An endpoint whose name does not resolve: the session is ended and
// counted as this relay's error rather than the client's, because a
// client that asked correctly and got nothing is owed an answer
// somewhere, and the only place left is the operator's counters.
func TestAnEndpointThatCannotBeResolvedEndsTheSession(t *testing.T) {
	s := proxytest.Start(t, `
version: 1
server:
  listeners:
    - name: games
      address: "127.0.0.1:0"
      kind: udp
      udp:
        upstream: backends
logging: {access: {enabled: false}}
upstreams:
  - name: backends
    endpoints: [{address: "no-such-host.invalid:69"}]
`)
	silence(t, dialUDP(t, s.Addrs()["games"]), "hello")
	eventually(t, 3*time.Second, "the unreachable endpoint to be counted", func() bool {
		sn := s.Stats()
		return sn.UDPErrors >= 1 && sn.UDPSessionsOpen == 0
	})
}

// The session bound ends a session that is still busy, which is the
// difference between it and the idle bound: a flow that never stops is
// exactly the one an operator wants a maximum duration on.
func TestTheSessionBoundEndsABusySession(t *testing.T) {
	e := startEchoUDP(t, "")
	s, addr := udpWith(t, e, "        session_timeout: 400ms\n        idle_timeout: 200ms", "")
	c := dialUDP(t, addr)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if s.Stats().UDPSessionsOpen == 0 && s.Stats().UDPDatagramsIn > 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("a session kept busy past its maximum duration was not ended")
}
