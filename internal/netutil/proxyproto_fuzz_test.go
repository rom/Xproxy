package netutil

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadProxyHeader feeds arbitrary bytes to the PROXY protocol parser:
// it must never panic, and a parsed header must carry an address of the
// family it claims.
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
		if h.Src.Addr().Unmap().Is4() != h.Dst.Addr().Unmap().Is4() {
			t.Fatalf("mixed families: %+v", h)
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
