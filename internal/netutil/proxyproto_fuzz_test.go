package netutil

import (
	"bufio"
	"bytes"
	"net/netip"
	"testing"
)

// FuzzReadProxyHeader feeds arbitrary bytes to the PROXY protocol
// parser: it must never panic, and a parsed header must carry addresses
// in the one canonical form the rest of the proxy keys on.
//
// The earlier invariant here required the two addresses to share a
// family, and the fuzzer was right to break it: a dual-stack balancer
// with an IPv6 listener reports an IPv4 client as ::ffff:a.b.c.d beside
// an IPv6 destination, and unmapping that source is what makes an
// access list match. The parser was correct and the assertion was not.
func FuzzReadProxyHeader(f *testing.F) {
	f.Add([]byte("PROXY TCP4 192.0.2.1 198.51.100.2 12345 443\r\nGET / HTTP/1.1\r\n"))
	f.Add([]byte("PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	v2 := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0x00, 0x0c, 192, 0, 2, 1, 198, 51, 100, 2, 0x30, 0x39, 0x01, 0xbb)
	f.Add(v2)
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		if h.Version != 1 && h.Version != 2 {
			t.Fatalf("parsed header with version %d", h.Version)
		}
		if h.Local {
			return
		}
		if !h.Src.IsValid() || !h.Dst.IsValid() {
			t.Fatalf("non local header without addresses: %+v", h)
		}
		// The two addresses may legitimately differ in family: a
		// dual-stack balancer with an IPv6 listener reports an IPv4
		// client as ::ffff:a.b.c.d in an AF_INET6 header, and the
		// parser unmaps it. What must hold is that no mapped or zoned
		// form escapes the parser, because the source address becomes
		// the key for access lists, CIDR matching, bans and rate
		// limits, where a second spelling of one address is a bypass.
		for _, a := range []netip.Addr{h.Src.Addr(), h.Dst.Addr()} {
			if a != a.Unmap() {
				t.Fatalf("an IPv4-mapped address escaped the parser: %v in %+v", a, h)
			}
			if a.Zone() != "" {
				t.Fatalf("a zoned address escaped the parser: %v in %+v", a, h)
			}
		}
	})
}

func BenchmarkReadProxyHeader(b *testing.B) {
	line := []byte("PROXY TCP4 192.0.2.1 198.51.100.2 12345 443\r\n")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(line))); err != nil {
			b.Fatal(err)
		}
	}
}
