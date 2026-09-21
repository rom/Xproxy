package masque

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

// TestVarint covers the encoding both directions, including that the
// shortest form is used — two encodings of one number would otherwise
// be two different context ids for the same context.
func TestVarint(t *testing.T) {
	for _, v := range []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903} {
		b := AppendVarint(nil, v)
		got, n, err := ParseVarint(b)
		if err != nil || got != v || n != len(b) {
			t.Fatalf("%d: round trip = %d, %d bytes, %v", v, got, n, err)
		}
		back, err := ReadVarint(bytes.NewReader(b))
		if err != nil || back != v {
			t.Fatalf("%d: ReadVarint = %d, %v", v, back, err)
		}
	}
	// The shortest encoding: 63 fits in one byte, 64 does not.
	if len(AppendVarint(nil, 63)) != 1 || len(AppendVarint(nil, 64)) != 2 {
		t.Fatal("varints are not encoded in the shortest form")
	}
	for _, b := range [][]byte{nil, {0x40}, {0x80, 0x00}, {0xc0, 1, 2, 3}} {
		if _, _, err := ParseVarint(b); err == nil {
			t.Errorf("truncated varint %v accepted", b)
		}
		if _, err := ReadVarint(bytes.NewReader(b)); err == nil {
			t.Errorf("truncated varint %v accepted by the reader", b)
		}
	}
}

func TestCapsuleRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := []Capsule{
		{Type: CapsuleDatagram, Value: []byte{0x00, 'h', 'i'}},
		{Type: CapsuleAddressAssign, Value: []byte{1, 2, 3}},
		{Type: 0x1234567, Value: nil},
	}
	for _, c := range in {
		if err := WriteCapsule(&buf, c); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range in {
		got, err := ReadCapsule(&buf)
		if err != nil {
			t.Fatalf("capsule %d: %v", i, err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Value, want.Value) {
			t.Fatalf("capsule %d = %+v, want %+v", i, got, want)
		}
	}
	if _, err := ReadCapsule(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last capsule: %v", err)
	}
}

// TestCapsuleBounds: the length is a varint a peer chooses, so an
// enormous one must be refused before the buffer is allocated.
func TestCapsuleBounds(t *testing.T) {
	huge := AppendVarint([]byte{0x00}, 1<<40)
	if _, err := ReadCapsule(bytes.NewReader(huge)); !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("a capsule claiming a terabyte: %v", err)
	}
	if err := WriteCapsule(io.Discard, Capsule{Value: make([]byte, MaxCapsule+1)}); !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("writing an oversize capsule: %v", err)
	}
	// A truncated value is an error, not a short capsule.
	short := AppendVarint([]byte{0x00}, 10)
	short = append(short, 1, 2, 3)
	if _, err := ReadCapsule(bytes.NewReader(short)); err == nil {
		t.Fatal("a capsule shorter than its length was accepted")
	}
}

func TestDatagramCapsule(t *testing.T) {
	c := Datagram(0, []byte("payload"))
	ctx, payload, err := SplitDatagram(c)
	if err != nil || ctx != 0 || string(payload) != "payload" {
		t.Fatalf("split = %d %q %v", ctx, payload, err)
	}
	if _, _, err := SplitDatagram(Capsule{Type: CapsuleAddressAssign}); err == nil {
		t.Error("a non-datagram capsule was split")
	}
	if _, _, err := SplitDatagram(Capsule{Type: CapsuleDatagram}); err == nil {
		t.Error("a datagram capsule with no context was split")
	}
	// A non-zero context is legal on the wire and means an extension.
	c2 := Datagram(9, []byte("x"))
	if ctx, _, err := SplitDatagram(c2); err != nil || ctx != 9 {
		t.Fatalf("context 9: %d %v", ctx, err)
	}
}

func TestParseUDPTarget(t *testing.T) {
	for _, c := range []struct {
		path string
		host string
		port int
	}{
		{"/.well-known/masque/udp/dns.example.com/53/", "dns.example.com", 53},
		{"/.well-known/masque/udp/192.0.2.1/443/", "192.0.2.1", 443},
		{"/.well-known/masque/udp/%5B2001%3Adb8%3A%3A1%5D/853/", "2001:db8::1", 853},
		{"/.well-known/masque/udp/host/1", "host", 1},
	} {
		got, err := ParseUDPTarget(c.path)
		if err != nil || got.Host != c.host || got.Port != c.port {
			t.Errorf("%s = %+v %v", c.path, got, err)
		}
	}
	for _, bad := range []string{
		"/.well-known/masque/udp/",
		"/.well-known/masque/udp/host/",
		"/.well-known/masque/udp//53/",
		"/.well-known/masque/udp/host/0/",
		"/.well-known/masque/udp/host/70000/",
		"/.well-known/masque/udp/host/https/",
		"/.well-known/masque/udp/host/53/extra/",
		"/.well-known/masque/udp/ho%2Fst/53/",
		"/.well-known/masque/udp/ho st/53/",
		"/.well-known/masque/ip/host/53/",
		"/elsewhere/host/53/",
	} {
		if got, err := ParseUDPTarget(bad); err == nil {
			t.Errorf("%s accepted as %+v", bad, got)
		}
	}
	if s := (UDPTarget{Host: "2001:db8::1", Port: 53}).String(); s != "[2001:db8::1]:53" {
		t.Errorf("ipv6 target string = %q", s)
	}
}

func TestParseIPTarget(t *testing.T) {
	got, err := ParseIPTarget("/.well-known/masque/ip/*/*/")
	if err != nil || got.Target != "*" || got.Protocol != -1 {
		t.Fatalf("wildcard = %+v %v", got, err)
	}
	got, err = ParseIPTarget("/.well-known/masque/ip/192.0.2.9/17/")
	if err != nil || got.Target != "192.0.2.9" || got.Protocol != 17 {
		t.Fatalf("specific = %+v %v", got, err)
	}
	for _, bad := range []string{
		"/.well-known/masque/ip/",
		"/.well-known/masque/ip/target/",
		"/.well-known/masque/ip/target/256/",
		"/.well-known/masque/ip/target/-1/",
		"/.well-known/masque/ip/target/udp/",
		"/.well-known/masque/ip/ta%2Frget/17/",
		"/.well-known/masque/udp/target/17/",
	} {
		if _, err := ParseIPTarget(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// TestAddressCapsules: a client cannot send a packet until it has been
// told a source address and where it may send, so these two capsules
// are the start of every CONNECT-IP session.
func TestAddressCapsules(t *testing.T) {
	assign := AddressAssign([]netip.Prefix{netip.MustParsePrefix("10.8.0.2/32"), netip.MustParsePrefix("2001:db8::2/128")})
	if assign.Type != CapsuleAddressAssign || len(assign.Value) == 0 {
		t.Fatalf("assign = %+v", assign)
	}
	// One IPv4 entry is a request id varint, a family byte, 4 address
	// bytes and a prefix length; the IPv6 one is 16 bytes of address.
	if len(assign.Value) != (1+1+4+1)+(1+1+16+1) {
		t.Fatalf("assign value is %d bytes", len(assign.Value))
	}
	routes := RouteAdvertisement([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, 17)
	if routes.Type != CapsuleRouteAdvertisement || len(routes.Value) != 1+4+4+1 {
		t.Fatalf("routes = %+v (%d bytes)", routes, len(routes.Value))
	}
	// The range's end is the last address of the prefix.
	end := routes.Value[5:9]
	if end[3] != 255 || end[2] != 2 {
		t.Fatalf("route end = %v, want 192.0.2.255", end)
	}
	// A wildcard protocol is encoded as zero, which RFC 9484 uses for
	// "any".
	any := RouteAdvertisement([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, -1)
	if any.Value[len(any.Value)-1] != 0 {
		t.Fatal("a wildcard protocol was not encoded as 0")
	}
	if !strings.Contains(errNoDevice(), "tunnel device") {
		t.Skip()
	}
}

func errNoDevice() string { return "tunnel device" }
