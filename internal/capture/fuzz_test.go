package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// A capture is written from bytes an attacker chose: the request is
// theirs, the response may be an origin's answer to them, and the
// comment carries a route name and a deny reason derived from both.
// Whatever goes in, what comes out has to be a pcapng file a tool can
// walk to the end — a capture that crashes Wireshark is a capture that
// cannot be read during the incident it was taken for.
func FuzzWriteFlow(f *testing.F) {
	// The three endpoint pairings the proxy produces: two IPv4, two
	// IPv6, and the mixed one a dual-stack deployment makes.
	pairs := [][2]netip.AddrPort{
		{netip.MustParseAddrPort("198.51.100.7:44321"), netip.MustParseAddrPort("203.0.113.9:443")},
		{netip.MustParseAddrPort("[2001:db8::7]:44321"), netip.MustParseAddrPort("[2001:db8::9]:443")},
		{netip.MustParseAddrPort("[2001:db8::7]:44321"), netip.MustParseAddrPort("203.0.113.9:443")},
	}
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\n"), "request_id=a", uint8(0))
	f.Add([]byte{}, []byte{}, "", uint8(1))
	f.Add([]byte{0x00, 0x0a, 0x0d, 0x1b, 0xff}, []byte{0xff, 0xfe}, "route=\x1b[31m", uint8(2))
	f.Add(make([]byte, 5000), make([]byte, 3000), "long", uint8(0))

	f.Fuzz(func(t *testing.T, req, resp []byte, comment string, pairing uint8) {
		p := pairs[int(pairing)%len(pairs)]
		var buf capBuffer
		w := &writer{w: &buf}
		if err := w.header(262144); err != nil {
			t.Fatal(err)
		}
		flow := newFlow(p[0], p[1], sanitise(comment))
		when := time.Unix(0, 0).UTC()
		for _, step := range []func() error{
			func() error { return flow.open(w, when) },
			func() error { return flow.send(w, when, true, req) },
			func() error { return flow.send(w, when, false, resp) },
			func() error { return flow.close(w, when) },
		} {
			if err := step(); err != nil {
				t.Fatal(err)
			}
		}
		walk(t, buf.b)
	})
}

// walk reads the file the way a reader with no trust in it would: block
// by block, believing only the lengths, and refusing to run off the end.
func walk(t *testing.T, b []byte) {
	t.Helper()
	blocks := 0
	for len(b) > 0 {
		if len(b) < 12 {
			t.Fatalf("%d trailing bytes are not a block", len(b))
		}
		total := binary.LittleEndian.Uint32(b[4:8])
		if total < 12 || total%4 != 0 || int(total) > len(b) {
			t.Fatalf("block %d claims %d bytes of the %d left", blocks, total, len(b))
		}
		if tail := binary.LittleEndian.Uint32(b[total-4 : total]); tail != total {
			t.Fatalf("block %d: trailing length %d != %d", blocks, tail, total)
		}
		if kind := binary.LittleEndian.Uint32(b[0:4]); kind == blockEnhanced {
			body := b[8 : total-4]
			if len(body) < 20 {
				t.Fatalf("block %d: packet block of %d bytes", blocks, len(body))
			}
			capLen := binary.LittleEndian.Uint32(body[12:16])
			if int(capLen) > len(body)-20 {
				t.Fatalf("block %d: captured length %d exceeds the block", blocks, capLen)
			}
			if orig := binary.LittleEndian.Uint32(body[16:20]); orig < capLen {
				t.Fatalf("block %d: original length %d below the captured %d", blocks, orig, capLen)
			}
		}
		b = b[total:]
		blocks++
	}
	if blocks < 8 {
		t.Fatalf("%d blocks, want at least the header, the interface and a handshake", blocks)
	}
}
