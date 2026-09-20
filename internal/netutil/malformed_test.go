package netutil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http/httptest"
	"testing"
)

// The three wire parsers in this package read bytes from a client that
// has not authenticated and, in the QUIC and TLS cases, has not even
// completed a handshake. Every one of them runs on a listener's own
// goroutine, so a panic here is not one request's problem. These tests
// feed each of them the datagrams and records a real client never
// sends: truncated at every length, with one byte changed, and with
// the lengths inside them pointing past the end.

// TestClientHelloTruncation feeds ClientHelloSNI every prefix of a real
// ClientHello. Each must be an error or a "need more", never a panic
// and never a name read out of somebody else's memory.
func TestClientHelloTruncation(t *testing.T) {
	hello := clientHello(t, "example.test")
	if len(hello) < 40 {
		t.Fatalf("the captured hello is %d bytes", len(hello))
	}
	full, err := ClientHelloSNI(hello)
	if err != nil || full != "example.test" {
		t.Fatalf("the whole hello: %q %v", full, err)
	}
	for i := 0; i <= len(hello); i++ {
		i := i
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on a %d byte prefix: %v", i, r)
				}
			}()
			name, err := ClientHelloSNI(hello[:i])
			if err == nil && name != "example.test" {
				t.Fatalf("a %d byte prefix produced the name %q", i, name)
			}
		}()
	}
}

// TestClientHelloBitFlips changes one byte at a time. A parser that
// trusted a length inside the record would walk off the end here.
func TestClientHelloBitFlips(t *testing.T) {
	hello := clientHello(t, "example.test")
	r := rand.New(rand.NewPCG(1, 2))
	for n := 0; n < 3000; n++ {
		b := append([]byte(nil), hello...)
		i := r.IntN(len(b))
		b[i] ^= byte(1 << r.IntN(8))
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("panic with byte %d flipped: %v", i, rec)
				}
			}()
			name, err := ClientHelloSNI(b)
			if err == nil && len(name) > 253 {
				t.Fatalf("byte %d flipped produced a %d byte name", i, len(name))
			}
		}()
	}
}

// TestClientHelloGarbage covers the inputs that are not TLS at all,
// which is what a port scanner, an HTTP client on the wrong port and a
// deliberate probe all send.
func TestClientHelloGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x16},
		{0x16, 0x03},
		{0x16, 0x03, 0x01},
		{0x16, 0x03, 0x01, 0xff, 0xff}, // a record longer than what follows
		[]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), // a plaintext request
		{0x80, 0x1f, 0x01, 0x03, 0x01},              // an SSLv2 hello
		bytes.Repeat([]byte{0}, 4096),
		bytes.Repeat([]byte{0xff}, 4096),
	}
	for i, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked: %v", i, r)
				}
			}()
			if name, err := ClientHelloSNI(in); err == nil && name != "" {
				t.Fatalf("case %d produced the name %q", i, name)
			}
		}()
	}
}

// TestQUICTruncation feeds QUICCryptoData every prefix of a real
// Initial datagram. The keys are derived from the connection id inside
// it, so a truncated one exercises the derivation as well as the parse.
func TestQUICTruncation(t *testing.T) {
	dg := captureFlight(t, "quic.example.test")[0]
	for i := 0; i <= len(dg); i++ {
		i := i
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on a %d byte prefix: %v", i, r)
				}
			}()
			frames, err := QUICCryptoData(dg[:i])
			if err == nil {
				for _, f := range frames {
					if len(f.Data) > len(dg) {
						t.Fatalf("a %d byte prefix produced %d bytes of crypto data", i, len(f.Data))
					}
				}
			}
		}()
	}
}

// TestQUICBitFlips changes one byte of a real Initial packet at a time.
// Almost every flip breaks the AEAD tag, which is the point: the parse
// must fail rather than proceed on plaintext it could not authenticate.
func TestQUICBitFlips(t *testing.T) {
	dg := captureFlight(t, "quic.example.test")[0]
	r := rand.New(rand.NewPCG(3, 4))
	for n := 0; n < 500; n++ {
		b := append([]byte(nil), dg...)
		i := r.IntN(len(b))
		b[i] ^= byte(1 << r.IntN(8))
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("panic with byte %d flipped: %v", i, rec)
				}
			}()
			_, _ = QUICCryptoData(b)
		}()
	}
}

// TestQUICGarbage covers the datagrams that are not QUIC: a stray UDP
// payload, a DNS query on the wrong port, a version this build does not
// speak.
func TestQUICGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0xc0},
		{0xc0, 0x00, 0x00, 0x00, 0x01}, // v1 header and nothing else
		{0xc0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00}, // another version
		{0xc0, 0xff, 0x00, 0x00, 0x1d, 0x00, 0x00}, // a draft version
		{0x40, 0x00, 0x00, 0x00, 0x01},             // a short header
		bytes.Repeat([]byte{0}, 1200),
		bytes.Repeat([]byte{0xff}, 1200),
		bytes.Repeat([]byte{0xc0}, 65535), // the largest datagram there is
	}
	for i, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked: %v", i, r)
				}
			}()
			if _, err := QUICCryptoData(in); err == nil {
				t.Fatalf("case %d was accepted as a QUIC Initial", i)
			}
		}()
	}
}

// TestProxyHeaderTruncation feeds every prefix of each PROXY protocol
// header. A prefix must never be accepted as a complete header: the
// address in it decides the client every later decision is made about.
func TestProxyHeaderTruncation(t *testing.T) {
	v2 := func(fam byte, addr []byte) []byte {
		h := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, fam}
		h = append(h, byte(len(addr)>>8), byte(len(addr)))
		return append(h, addr...)
	}
	ipv4 := v2(0x11, []byte{192, 0, 2, 1, 198, 51, 100, 1, 0x1f, 0x90, 0x01, 0xbb})
	headers := [][]byte{
		[]byte("PROXY TCP4 192.0.2.1 198.51.100.1 8080 443\r\n"),
		[]byte("PROXY TCP6 2001:db8::1 2001:db8::2 8080 443\r\n"),
		[]byte("PROXY UNKNOWN\r\n"),
		ipv4,
	}
	for _, full := range headers {
		// The whole header parses.
		if _, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(full))); err != nil {
			t.Fatalf("the whole header %q: %v", trim(full), err)
		}
		for i := 0; i < len(full); i++ {
			i := i
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on a %d byte prefix of %q: %v", i, trim(full), r)
					}
				}()
				if _, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(full[:i]))); err == nil {
					t.Fatalf("a %d byte prefix of %q was accepted as a whole header", i, trim(full))
				}
			}()
		}
	}
}

// TestProxyHeaderGarbage covers what arrives when a plain client
// reaches a listener that expects the PROXY protocol, and the
// deliberate near misses.
func TestProxyHeaderGarbage(t *testing.T) {
	cases := []string{
		"",
		"GET / HTTP/1.1\r\n\r\n",
		"PROXY\r\n",
		"PROXY TCP4\r\n",
		"PROXY TCP4 192.0.2.1\r\n",
		"PROXY TCP4 192.0.2.1 198.51.100.1 8080\r\n",
		"PROXY TCP4 192.0.2.1 198.51.100.1 8080 443 extra\r\n",
		"PROXY TCP4 192.0.2.1 198.51.100.1 99999 443\r\n",
		"PROXY TCP4 192.0.2.1 198.51.100.1 -1 443\r\n",
		"PROXY TCP4 not-an-address 198.51.100.1 8080 443\r\n",
		"PROXY TCP6 192.0.2.1 198.51.100.1 8080 443\r\n",
		"PROXY TCP4 192.0.2.1 198.51.100.1 8080 443\n",
		"proxy tcp4 192.0.2.1 198.51.100.1 8080 443\r\n",
		"PROXY TCP4  192.0.2.1 198.51.100.1 8080 443\r\n",
		string(bytes.Repeat([]byte("A"), 8192)),
	}
	// A port written with a leading zero ("08080") is read as 8080.
	// It is a second spelling, but only of the peer's source port,
	// which is not a routing key and decides nothing: the address is
	// what every later decision is made about, and it has one
	// spelling.
	if h, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader([]byte("PROXY TCP4 192.0.2.1 198.51.100.1 08080 443\r\n")))); err != nil || h.Src.Port() != 8080 {
		t.Fatalf("a leading zero port: %v %v", h, err)
	}
	for _, in := range cases {
		in := in
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", trim([]byte(in)), r)
				}
			}()
			if _, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader([]byte(in)))); err == nil {
				t.Fatalf("%q was accepted as a PROXY header", trim([]byte(in)))
			}
		}()
	}
}

// TestProxyHeaderConsumesNothingWithoutASignature is the property a
// listener depends on: bytes that are not a PROXY header must still be
// there for the protocol behind it to read. A parser that consumed them
// would turn a plain client into a truncated request.
func TestProxyHeaderConsumesNothingWithoutASignature(t *testing.T) {
	const request = "GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"
	br := bufio.NewReader(bytes.NewReader([]byte(request)))
	if _, err := ReadProxyHeader(br); err == nil {
		t.Fatal("an HTTP request was accepted as a PROXY header")
	}
	rest := make([]byte, len(request))
	n, _ := br.Read(rest)
	for n < len(request) {
		m, err := br.Read(rest[n:])
		if m == 0 || err != nil {
			break
		}
		n += m
	}
	if string(rest[:n]) != request {
		t.Fatalf("the parser consumed %d bytes: %q", len(request)-n, rest[:n])
	}
}

// TestProxyHeaderV2Lengths covers the declared length inside a v2
// header, which is the field a parser must not trust: more than the
// family needs, less than it needs, and more than the reader has.
func TestProxyHeaderV2Lengths(t *testing.T) {
	sig := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	build := func(verCmd, fam byte, declared int, addr []byte) []byte {
		h := append([]byte(nil), sig...)
		h = append(h, verCmd, fam, byte(declared>>8), byte(declared))
		return append(h, addr...)
	}
	addr4 := []byte{192, 0, 2, 1, 198, 51, 100, 1, 0x1f, 0x90, 0x01, 0xbb}
	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"exact", build(0x21, 0x11, 12, addr4), true},
		{"declared short", build(0x21, 0x11, 11, addr4), false},
		{"declared long", build(0x21, 0x11, 13, addr4), false},
		{"declared enormous", build(0x21, 0x11, 65535, addr4), false},
		{"declared zero", build(0x21, 0x11, 0, nil), false},
		{"bad version", build(0x31, 0x11, 12, addr4), false},
		{"local command", build(0x20, 0x00, 0, nil), true},
		// An address family this parser does not know is not an error
		// but a header with no usable address: the connection keeps the
		// real peer, which is the safe direction. A family the parser
		// invented an address for would be the unsafe one.
		{"unknown family", build(0x21, 0x99, 12, addr4), true},
		{"trailing tlv", build(0x21, 0x11, 12+4, append(append([]byte(nil), addr4...), 0x03, 0x00, 0x01, 0x00)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			_, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(tc.in)))
			if tc.ok && err != nil && !errors.Is(err, ErrNeedMore) {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// trim renders a header for an error message.
func trim(b []byte) string {
	if len(b) > 60 {
		return fmt.Sprintf("%q...(%d bytes)", b[:60], len(b))
	}
	return fmt.Sprintf("%q", b)
}

// varint encodes a QUIC variable length integer in its shortest form.
func varint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return []byte{0x40 | byte(v>>8), byte(v)}
	case v < 1<<30:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		b := make([]byte, 8)
		for i := 7; i >= 0; i-- {
			b[i] = byte(v)
			v >>= 8
		}
		b[0] |= 0xc0
		return b
	}
}

// TestQUICFrameWalk drives the frame walker directly with payloads a
// decrypted Initial could carry. Building them by hand is the only way
// to reach the frames a real client's first flight does not contain —
// an ACK with many ranges, a CONNECTION_CLOSE, a frame type an Initial
// packet may not carry — and each of those is a path an attacker can
// put in a packet.
func TestQUICFrameWalk(t *testing.T) {
	crypto := func(offset uint64, data []byte) []byte {
		f := []byte{0x06}
		f = append(f, varint(offset)...)
		f = append(f, varint(uint64(len(data)))...)
		return append(f, data...)
	}
	ack := func(ecn bool, ranges ...[2]uint64) []byte {
		t := byte(0x02)
		if ecn {
			t = 0x03
		}
		f := []byte{t}
		f = append(f, varint(100)...)                 // largest acknowledged
		f = append(f, varint(0)...)                   // delay
		f = append(f, varint(uint64(len(ranges)))...) // range count
		f = append(f, varint(1)...)                   // first range
		for _, r := range ranges {
			f = append(f, varint(r[0])...)
			f = append(f, varint(r[1])...)
		}
		if ecn {
			f = append(f, varint(1)...)
			f = append(f, varint(2)...)
			f = append(f, varint(3)...)
		}
		return f
	}

	t.Run("crypto only", func(t *testing.T) {
		got, err := quicCryptoFrames(crypto(0, []byte("hello")))
		if err != nil || len(got) != 1 || string(got[0].Data) != "hello" {
			t.Fatalf("%v %v", got, err)
		}
	})
	t.Run("padding and ping around crypto", func(t *testing.T) {
		p := append([]byte{0x00, 0x00, 0x01}, crypto(7, []byte("x"))...)
		p = append(p, 0x00, 0x00)
		got, err := quicCryptoFrames(p)
		if err != nil || len(got) != 1 || got[0].Offset != 7 {
			t.Fatalf("%v %v", got, err)
		}
	})
	t.Run("ack then crypto", func(t *testing.T) {
		p := append(ack(false, [2]uint64{1, 2}, [2]uint64{3, 4}), crypto(0, []byte("abc"))...)
		got, err := quicCryptoFrames(p)
		if err != nil || len(got) != 1 || string(got[0].Data) != "abc" {
			t.Fatalf("%v %v", got, err)
		}
	})
	t.Run("ack with ecn counts", func(t *testing.T) {
		p := append(ack(true, [2]uint64{1, 2}), crypto(0, []byte("abc"))...)
		got, err := quicCryptoFrames(p)
		if err != nil || len(got) != 1 {
			t.Fatalf("%v %v", got, err)
		}
	})
	t.Run("two crypto frames keep their offsets", func(t *testing.T) {
		p := append(crypto(0, []byte("aa")), crypto(2, []byte("bb"))...)
		got, err := quicCryptoFrames(p)
		if err != nil || len(got) != 2 || got[1].Offset != 2 {
			t.Fatalf("%v %v", got, err)
		}
	})

	bad := map[string][]byte{
		"length past the end":  {0x06, 0x00, 0x40, 0xff, 'a'},
		"length is enormous":   append([]byte{0x06, 0x00}, varint(1<<20)...),
		"truncated offset":     {0x06, 0xc0},
		"truncated length":     {0x06, 0x00},
		"connection close":     {0x1c},
		"stream frame":         {0x08, 0x00},
		"handshake done":       {0x1e},
		"new connection id":    {0x18},
		"truncated ack":        {0x02},
		"ack with a bad count": {0x02, 0x00, 0x00, 0xc0},
		"unknown frame":        {0x7f},
	}
	for name, p := range bad {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			if got, err := quicCryptoFrames(p); err == nil {
				t.Fatalf("accepted: %v", got)
			}
		})
	}

	// An empty payload is a packet with nothing in it, which is legal
	// and carries no ClientHello.
	if got, err := quicCryptoFrames(nil); err != nil || len(got) != 0 {
		t.Fatalf("an empty payload: %v %v", got, err)
	}
}

// TestRemoteAddr covers the peer address as net/http spells it, which
// is not always host:port: a Unix socket, an address with no port, and
// an IPv4-mapped IPv6 address that must come back as IPv4 so that one
// client has one address in the ban list and the rate limiter.
func TestRemoteAddr(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1:1234":          "192.0.2.1",
		"[2001:db8::1]:1234":      "2001:db8::1",
		"192.0.2.1":               "192.0.2.1",
		"[::ffff:192.0.2.1]:1234": "192.0.2.1",
		"::1":                     "::1",
		"":                        "",
		"@":                       "",
		"/run/xproxy.sock":        "",
		"not-an-address:80":       "",
		"example.test:443":        "",
	}
	for in, want := range cases {
		r := httptest.NewRequest("GET", "http://a/", nil)
		r.RemoteAddr = in
		got := RemoteAddr(r)
		if want == "" {
			if got.IsValid() {
				t.Errorf("RemoteAddr(%q) = %v, want an invalid address", in, got)
			}
			continue
		}
		if got.String() != want {
			t.Errorf("RemoteAddr(%q) = %v, want %s", in, got, want)
		}
	}
}
