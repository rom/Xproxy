package forward

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// What the UDP association does with a datagram it will not relay. The
// relay socket is reachable by anybody who can reach the port, so each
// of these is a refusal rather than a delivery: a UDP relay that
// forwards what it was not asked to is an open reflector.

// association opens a SOCKS UDP association and returns the relay's
// address and a socket to speak to it from.
func association(t *testing.T, addr string) (netip.AddrPort, net.PacketConn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0 {
		t.Fatalf("the association was refused: %d", head[1])
	}
	rest := make([]byte, 6)
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatal(err)
	}
	relay := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"),
		binary.BigEndian.Uint16(rest[4:]))

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return relay, client
}

// envelope wraps a payload in the RFC 1928 request header.
func envelope(host string, port int, payload string) []byte {
	msg := []byte{0, 0, 0, 1}
	a := netip.MustParseAddr(host).As4()
	msg = append(msg, a[:]...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(port)) //nolint:gosec // test port
	return append(msg, payload...)
}

func TestADatagramTheAssociationWillNotRelayIsDropped(t *testing.T) {
	// An echo server, so there is one destination the policy allows
	// and a reply to wait for.
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	s, addr := socksProxy(t, strconv.Itoa(echoPort), "")
	relay, client := association(t, addr)

	// First the one that works, so the association is known to be up
	// and the drops below cannot pass by everything being broken.
	if _, err := client.WriteTo(envelope("127.0.0.1", echoPort, "hello"), net.UDPAddrFromAddrPort(relay)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	if _, _, err := client.ReadFrom(buf); err != nil {
		t.Fatalf("the association never answered: %v", err)
	}

	before := s.Stats().ForwardUDPDropped
	for _, c := range []struct {
		name string
		msg  []byte
	}{
		// Too short to hold the envelope at all.
		{name: "not an envelope", msg: []byte{0, 0, 0}},
		// A fragment: this relay does not reassemble, and forwarding
		// one piece of a datagram is forwarding something nobody sent.
		{name: "a fragment", msg: append([]byte{0, 0, 1, 1, 127, 0, 0, 1, 0, 53}, "half"...)},
		// An address type that is not one.
		{name: "an address type that is not one", msg: append([]byte{0, 0, 0, 9, 1, 2, 3, 4, 0, 53}, "x"...)},
		// A destination whose port is not on the listener's list.
		{name: "a port the listener does not allow", msg: envelope("127.0.0.1", 9, "nope")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := client.WriteTo(c.msg, net.UDPAddrFromAddrPort(relay)); err != nil {
				t.Fatal(err)
			}
			_ = client.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			if n, _, err := client.ReadFrom(buf); err == nil {
				t.Errorf("a datagram that should have been dropped was answered: %q", buf[:n])
			}
		})
	}
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().ForwardUDPDropped < before+4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.Stats().ForwardUDPDropped - before; got < 4 {
		t.Errorf("forward_udp_dropped moved by %d, want the four that were dropped", got)
	}
}

// The relay socket belongs to one client. A datagram from another
// address on the same host is not that client's, whatever it says in
// its envelope.
func TestTheAssociationBelongsToTheClientThatOpenedIt(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	s, addr := socksProxy(t, strconv.Itoa(echoPort), "")
	relay, _ := association(t, addr)

	// 127.0.0.2 is the same host and a different address, which is
	// what makes it the case worth having: the check is on the
	// address, not on the host.
	other, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("no second loopback address here: %v", err)
	}
	defer func() { _ = other.Close() }()
	before := s.Stats().ForwardUDPDropped
	if _, err := other.WriteTo(envelope("127.0.0.1", echoPort, "not mine"), net.UDPAddrFromAddrPort(relay)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().ForwardUDPDropped <= before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Stats().ForwardUDPDropped <= before {
		t.Error("a datagram from another address was not dropped")
	}
	// And the echo server never saw it.
	_ = echo.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _, err := echo.ReadFrom(make([]byte, 64)); err == nil {
		t.Errorf("%d octets from another address were relayed", n)
	}
}
