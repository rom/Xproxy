package transparent

import (
	"net"
	"net/netip"
	"testing"
)

// The loop check is the one thing standing between a wrong firewall rule
// and a process that consumes descriptors until it dies, from a single
// client packet. It has to catch a wildcard listener as well as an exact
// address, because that is what the kernel will do with the connection.
func TestLoopCatchesTheProxysOwnAddress(t *testing.T) {
	own := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:8080"),
		netip.MustParseAddrPort("0.0.0.0:9090"), // a wildcard listener
	}
	for _, c := range []struct {
		dst  string
		loop bool
		why  string
	}{
		{"10.0.0.1:8080", true, "the listener's own address and port"},
		{"10.0.0.1:8081", false, "the same address, another port"},
		{"10.0.0.2:8080", false, "another address, the listener's port"},
		{"192.0.2.9:9090", true, "any address on a wildcard listener's port"},
		{"192.0.2.9:9091", false, "another port entirely"},
	} {
		err := Loop(netip.MustParseAddrPort(c.dst), own)
		if (err != nil) != c.loop {
			t.Errorf("%s (%s): loop=%v, want %v", c.dst, c.why, err != nil, c.loop)
		}
	}
}

// An empty policy allows nothing. A listener that dials whatever the
// firewall hands it must say where that may be, or it is a relay to
// anywhere for anyone who can reach the port -- so the failure mode of
// forgetting the list is "nothing works", not "everything does".
func TestAllowedWithNoPolicyAllowsNothing(t *testing.T) {
	if Allowed(netip.MustParseAddrPort("10.0.0.1:80"), nil, nil) {
		t.Fatal("an empty destination policy allowed a destination")
	}
}

func TestAllowedRangeAndPorts(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")}
	for _, c := range []struct {
		dst   string
		ports []int
		ok    bool
	}{
		{"10.1.2.3:443", nil, true},
		{"11.1.2.3:443", nil, false},
		{"10.1.2.3:443", []int{443, 8443}, true},
		{"10.1.2.3:22", []int{443, 8443}, false},
		{"[2001:db8::5]:443", nil, true},
		{"[2001:db9::5]:443", nil, false},
	} {
		if got := Allowed(netip.MustParseAddrPort(c.dst), allow, c.ports); got != c.ok {
			t.Errorf("Allowed(%s, ports=%v) = %v, want %v", c.dst, c.ports, got, c.ok)
		}
	}
}

// On a connection that was never intercepted, the destination read is the
// socket's own local address -- which is what TPROXY produces, and what
// makes the loop check above necessary rather than theoretical.
func TestDestinationOfAnOrdinaryConnectionIsTheLocalAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		done <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	server := <-done
	if server == nil {
		t.Fatal("accept failed")
	}
	defer func() { _ = server.Close() }()

	dst, err := Destination(server)
	if err != nil {
		t.Fatalf("Destination: %v", err)
	}
	want := ln.Addr().(*net.TCPAddr).AddrPort()
	if dst.Port() != want.Port() {
		t.Fatalf("destination %s, want the listener's port %d", dst, want.Port())
	}
	// And that destination is a loop, which is the whole point of the
	// check: an intercepting listener handed this would dial itself.
	if err := Loop(dst, []netip.AddrPort{want}); err == nil {
		t.Fatal("the listener's own address was not recognised as a loop")
	}
}
