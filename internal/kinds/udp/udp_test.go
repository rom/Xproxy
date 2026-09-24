package udp_test

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/udp" // the kind under test
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// echoUDP is a UDP server that answers each datagram with a prefix and
// the payload, and remembers the source addresses it saw. What it
// remembers is the proof that the relay is one end of the exchange: the
// client's own address must never appear there.
type echoUDP struct {
	pc      net.PacketConn
	sources chan string
}

func startEchoUDP(t *testing.T, prefix string) *echoUDP {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &echoUDP{pc: pc, sources: make(chan string, 64)}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case e.sources <- addr.String():
			default:
			}
			_, _ = pc.WriteTo([]byte(prefix+string(buf[:n])), addr)
		}
	}()
	return e
}

func (e *echoUDP) addr() string { return e.pc.LocalAddr().String() }

// relay starts a proxy with one kind: udp listener in front of the echo
// server, with extra lines indented under the udp section.
func relay(t *testing.T, e *echoUDP, extra string) (*proxy.Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
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
`, extra, e.addr())
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["games"]
}

// dialUDP opens a socket towards the relay.
func dialUDP(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// exchange sends one datagram and reads the answer.
func exchange(t *testing.T, c *net.UDPConn, payload string) string {
	t.Helper()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer to %q: %v", payload, err)
	}
	return string(buf[:n])
}

// eventually retries ok until it holds or d passes. A session's close
// and the counters that go with it are the sweeper's work or the
// pump's, not the client's, so a test that reads them the instant it
// stops sending is racing another goroutine.
func eventually(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if ok() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s and it did not happen", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestUDPRelay is the whole of what a generic datagram relay has to do:
// the datagram reaches the endpoint, the answer comes back, the
// endpoint sees the relay rather than the client, several datagrams from
// one client take one session, two clients take two, and the counters
// say so.
func TestUDPRelay(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        idle_timeout: 30s")

	c := dialUDP(t, addr)
	if got := exchange(t, c, "ping"); got != "echo:ping" {
		t.Fatalf("answer %q", got)
	}
	// The endpoint's peer is the relay, not the client: an upstream that
	// saw the client's address would mean the datagram went round the
	// proxy.
	src := <-e.sources
	if src == c.LocalAddr().String() {
		t.Fatalf("the endpoint saw the client's own address %s", src)
	}
	// More datagrams from the same client are the same session.
	for i := 0; i < 5; i++ {
		if got := exchange(t, c, fmt.Sprintf("n%d", i)); got != fmt.Sprintf("echo:n%d", i) {
			t.Fatalf("answer %d was %q", i, got)
		}
	}
	// A second client is a second session.
	c2 := dialUDP(t, addr)
	if got := exchange(t, c2, "other"); got != "echo:other" {
		t.Fatalf("second client answer %q", got)
	}
	eventually(t, 5*time.Second, "both sessions to be counted", func() bool {
		return s.Stats().UDPSessions == 2
	})
	sn := s.Stats()
	if sn.UDPSessionsOpen != 2 {
		t.Errorf("open sessions %d, want 2", sn.UDPSessionsOpen)
	}
	if sn.UDPDatagramsIn != 7 || sn.UDPDatagramsOut != 7 {
		t.Errorf("datagrams in %d out %d, want 7 and 7", sn.UDPDatagramsIn, sn.UDPDatagramsOut)
	}
	if sn.UDPBytesIn == 0 || sn.UDPBytesOut <= sn.UDPBytesIn {
		t.Errorf("bytes in %d out %d: the echo adds a prefix, so out must exceed in", sn.UDPBytesIn, sn.UDPBytesOut)
	}
}

// A session with no datagram either way for idle_timeout is closed, and
// the client that comes back gets a new one rather than a dead handle.
func TestUDPIdleSessionEnds(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        idle_timeout: 1s")
	c := dialUDP(t, addr)
	if got := exchange(t, c, "hello"); got != "echo:hello" {
		t.Fatalf("answer %q", got)
	}
	eventually(t, 15*time.Second, "the idle session to be swept", func() bool {
		return s.Stats().UDPSessionsOpen == 0
	})
	if got := exchange(t, c, "again"); got != "echo:again" {
		t.Fatalf("after the sweep: %q", got)
	}
	eventually(t, 5*time.Second, "the second session to be counted", func() bool {
		return s.Stats().UDPSessions == 2
	})
}

// A client outside allow_clients is dropped rather than answered, which
// is the only safe refusal for a datagram: a source address is whatever
// the sender wrote, so an error would be traffic aimed at whoever was
// named.
func TestUDPClientPolicyDropsRatherThanAnswers(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        allow_clients: [\"10.99.0.0/16\"]")
	c := dialUDP(t, addr)
	if _, err := c.Write([]byte("let me in")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("a refused client was answered with %d bytes", n)
	}
	eventually(t, 5*time.Second, "the drop to be counted", func() bool {
		return s.Stats().UDPDropped == 1
	})
	if sn := s.Stats(); sn.UDPSessions != 0 {
		t.Errorf("a refused client opened %d sessions", sn.UDPSessions)
	}
}

// A datagram over max_datagram_bytes is dropped whole. Truncating it
// would hand the endpoint something the client never sent.
func TestUDPOversizeDatagramIsDroppedNotTruncated(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        max_datagram_bytes: 64")
	c := dialUDP(t, addr)
	if _, err := c.Write([]byte(strings.Repeat("x", 200))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("an oversize datagram was relayed")
	}
	eventually(t, 5*time.Second, "the oversize drop to be counted", func() bool {
		return s.Stats().UDPDropped == 1
	})
	// A datagram inside the bound still works on the same listener.
	if got := exchange(t, c, "small"); got != "echo:small" {
		t.Fatalf("answer %q", got)
	}
}

// The session table is bounded, and the bound is per source as well as
// in total: a forged source must not be able to fill it.
func TestUDPSessionTableIsBounded(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        max_sessions: 2\n        max_sessions_per_ip: 1")
	c := dialUDP(t, addr)
	if got := exchange(t, c, "first"); got != "echo:first" {
		t.Fatalf("answer %q", got)
	}
	// A second socket from the same address is a second session from one
	// IP, which max_sessions_per_ip refuses.
	c2 := dialUDP(t, addr)
	if _, err := c2.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_ = c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("a session over max_sessions_per_ip was served")
	}
	eventually(t, 5*time.Second, "the refusal to be counted", func() bool {
		return s.Stats().UDPRejected == 1
	})
	if sn := s.Stats(); sn.UDPSessions != 1 {
		t.Errorf("sessions %d, want 1", sn.UDPSessions)
	}
}

// A session that reaches max_datagrams ends, and ends once: the pump
// and the read loop can both find the bound, and a session counted
// closed twice would take the open gauge negative.
func TestUDPSessionBoundEndsItExactlyOnce(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        max_datagrams: 2")
	c := dialUDP(t, addr)
	if got := exchange(t, c, "one"); got != "echo:one" {
		t.Fatalf("answer %q", got)
	}
	eventually(t, 5*time.Second, "the bounded session to end", func() bool {
		return s.Stats().UDPSessionsOpen == 0
	})
	if sn := s.Stats(); sn.UDPSessions != 1 {
		t.Errorf("sessions %d, want 1", sn.UDPSessions)
	}
}

// The byte bounds are per direction, the same two names a kind: tcp
// listener uses: what a session relays from the client, and what it
// relays back. The echo answers more than it is sent, so a bound on the
// way back is reached first.
func TestUDPByteBoundsArePerDirection(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        max_bytes_out: 8")
	c := dialUDP(t, addr)
	// "echo:ping" is nine bytes back for four sent, so the answer
	// reaches an eight byte bound and the four byte one is untouched.
	if got := exchange(t, c, "ping"); got != "echo:ping" {
		t.Fatalf("answer %q", got)
	}
	eventually(t, 5*time.Second, "the outbound bound to end the session", func() bool {
		return s.Stats().UDPSessionsOpen == 0
	})
	if sn := s.Stats(); sn.UDPBytesIn != 4 {
		t.Errorf("inbound bytes %d, want 4: the bound that ended this was the other direction's", sn.UDPBytesIn)
	}
}

// A rate limit bounds one source's datagrams. The burst is served and
// what is over it is dropped, not answered.
func TestUDPRateLimit(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        rate_limit: {pps: 1, burst: 2}")
	c := dialUDP(t, addr)
	for i := 0; i < 10; i++ {
		_, _ = c.Write([]byte("flood"))
	}
	eventually(t, 5*time.Second, "the rate limit to drop something", func() bool {
		return s.Stats().UDPDropped > 0
	})
	if sn := s.Stats(); sn.UDPDatagramsIn > 3 {
		t.Errorf("%d datagrams relayed through a burst of 2", sn.UDPDatagramsIn)
	}
}

// A listener whose pool has no reachable endpoint drops the datagram
// and counts an error rather than holding a session open on nothing.
func TestUDPNoReachableEndpoint(t *testing.T) {
	yaml := `
version: 1
server:
  listeners:
    - name: games
      address: "127.0.0.1:0"
      kind: udp
      udp: {upstream: backends}
logging: {access: {enabled: false}}
upstreams:
  - name: backends
    endpoints: [{address: "127.0.0.1:1"}]
`
	s := proxytest.Start(t, yaml)
	c := dialUDP(t, s.Addrs()["games"])
	// A connected UDP socket to a closed port does not fail on dial, so
	// the relay does forward; what must not happen is a panic or a
	// session that never ends. The client gets nothing back.
	if _, err := c.Write([]byte("anyone there")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("something answered for a closed endpoint")
	}
}

// A kind: udp listener binds no TCP port. That is the whole reason the
// engine treats it as a datagram kind: a port nothing accepts on would
// hang a client that connected to it.
//
// The assertion is positive rather than "a dial fails", because a dial
// to an ephemeral port number can reach something else entirely on a
// busy machine, which is a flake waiting to happen. Instead the test
// holds the TCP port itself and gives the listener the same number: if
// the engine bound a stream socket, it could not start.
func TestUDPListenerBindsNoStreamPort(t *testing.T) {
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	port := hold.Addr().(*net.TCPAddr).Port

	e := startEchoUDP(t, "echo:")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: games
      address: "127.0.0.1:%d"
      kind: udp
      udp: {upstream: backends}
logging: {access: {enabled: false}}
upstreams:
  - name: backends
    endpoints: [{address: %s}]
`, port, e.addr())
	// This start is the test: the TCP port is taken, so a listener that
	// wanted one could not come up.
	s := proxytest.Start(t, yaml)
	c := dialUDP(t, fmt.Sprintf("127.0.0.1:%d", port))
	if got := exchange(t, c, "ping"); got != "echo:ping" {
		t.Fatalf("answer %q", got)
	}
	// And the socket the test is holding is still the test's: nothing
	// accepted on it.
	eventually(t, 5*time.Second, "the session to be counted", func() bool {
		return s.Stats().UDPSessions == 1
	})
}

// Every refusal has a reason, and the reason reaches the metrics
// endpoint. xproxy_udp_dropped_total says a datagram was not relayed;
// this says which policy did it, which is the difference between
// noticing drops and knowing whether to raise max_datagram_bytes or
// widen allow_clients.
func TestUDPRefusalsAreCountedByReason(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        max_datagram_bytes: 64\n        rate_limit: {pps: 1, burst: 2}\n        allow_clients: [\"127.0.0.0/8\"]")
	c := dialUDP(t, addr)

	// Over the datagram bound.
	if _, err := c.Write([]byte(strings.Repeat("x", 200))); err != nil {
		t.Fatal(err)
	}
	// Over the rate.
	for i := 0; i < 10; i++ {
		_, _ = c.Write([]byte("flood"))
	}
	want := map[string]bool{"datagram_too_large": false, "rate_limit": false}
	eventually(t, 10*time.Second, "both refusal reasons to be counted", func() bool {
		got := s.Stats().Refusals["udp"]
		for r := range want {
			want[r] = got[r] > 0
		}
		return want["datagram_too_large"] && want["rate_limit"]
	})
	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, w := range []string{
		`xproxy_refusals_total{kind="udp",reason="datagram_too_large"}`,
		`xproxy_refusals_total{kind="udp",reason="rate_limit"}`,
		"xproxy_refusals_untracked_total 0",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("the exposition does not carry %s", w)
		}
	}
	// A reason the listener cannot have must not appear: the family is
	// what this process refused, not a catalogue of what it could.
	if strings.Contains(out, `reason="client_not_allowed"`) {
		t.Error("a refusal that never happened was exported")
	}
}

// A client outside allow_clients is refused under its own reason, on a
// listener that relays for everybody else.
func TestUDPClientPolicyRefusalHasItsOwnReason(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := relay(t, e, "        allow_clients: [\"10.99.0.0/16\"]")
	c := dialUDP(t, addr)
	if _, err := c.Write([]byte("let me in")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the refusal to name the client policy", func() bool {
		return s.Stats().Refusals["udp"]["client_not_allowed"] == 1
	})
}
