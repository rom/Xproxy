package netutil_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/rom/xproxy/internal/netutil"
)

// TestProxyV2HeaderShapes is the outbound header the layer 4 kinds
// write, checked byte by byte: the signature, the family, the length
// and the addresses a peer will read back out of it.
func TestProxyV2HeaderShapes(t *testing.T) {
	sig := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	v4 := &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 4242}
	l4 := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	h := netutil.ProxyV2Header(v4, l4)
	if !bytes.HasPrefix(h, sig) {
		t.Fatal("the signature is missing")
	}
	if h[12] != 0x21 || h[13] != 0x11 {
		t.Fatalf("version/family = %#x %#x", h[12], h[13])
	}
	if got := int(h[14])<<8 | int(h[15]); got != 12 || len(h) != 16+12 {
		t.Fatalf("length %d with %d bytes of header", got, len(h))
	}
	if !bytes.Equal(h[16:20], net.ParseIP("198.51.100.9").To4()) {
		t.Error("the client address is wrong")
	}
	if got := int(h[28-4])<<8 | int(h[28-3]); got != 4242 {
		t.Errorf("client port = %d", got)
	}

	// Two IPv6 addresses, and a mixed pair, both take the IPv6 shape:
	// an address family cannot be silently truncated to four bytes.
	v6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::9"), Port: 1}
	for _, pair := range [][2]net.Addr{{v6, v6}, {v4, v6}, {v6, l4}} {
		h6 := netutil.ProxyV2Header(pair[0], pair[1])
		if h6[13] != 0x21 {
			t.Errorf("family = %#x, want IPv6", h6[13])
		}
		if got := int(h6[14])<<8 | int(h6[15]); got != 36 || len(h6) != 16+36 {
			t.Errorf("length %d with %d bytes", got, len(h6))
		}
	}

	// A connection that is not TCP at all gets the LOCAL command with no
	// address, rather than a header claiming an address nobody has.
	for _, a := range []net.Addr{&net.UnixAddr{Name: "/tmp/s", Net: "unix"}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}} {
		hl := netutil.ProxyV2Header(a, l4)
		if len(hl) != 16 || hl[12] != 0x20 || hl[13] != 0x00 || hl[14] != 0 || hl[15] != 0 {
			t.Errorf("a %s address produced %#v", a.Network(), hl)
		}
	}
	// The zero port and the highest one both survive the round trip.
	hp := netutil.ProxyV2Header(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 65535}, &net.TCPAddr{IP: net.ParseIP("192.0.2.2")})
	if got := int(hp[24])<<8 | int(hp[25]); got != 65535 {
		t.Errorf("port 65535 came back as %d", got)
	}
}
