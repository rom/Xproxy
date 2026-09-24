package netutil

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// clientHelloWith captures the bytes a real client sends for a server
// name and a list of application protocols.
func clientHelloWith(t *testing.T, sni string, protos ...string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8192)
		n, _ := c.Read(buf)
		_ = c.Close()
		got <- buf[:n]
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: sni, NextProtos: protos,
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tc.Handshake() // fails when the fake server closes; the hello is out
	_ = tc.Close()
	return <-got
}

// A real client's offer is read back, in the order it made it -- which is
// the client's preference order and the only thing a relay can use to
// decide what a connection is for.
func TestClientHelloALPN(t *testing.T) {
	hello := clientHelloWith(t, "ke.test", "ntske/1", "h2")
	protos, err := ClientHelloALPN(hello)
	if err != nil {
		t.Fatal(err)
	}
	if len(protos) != 2 || protos[0] != "ntske/1" || protos[1] != "h2" {
		t.Fatalf("protocols %q", protos)
	}
	// The server name still reads the same, which is the point of the two
	// functions sharing one walk over the extensions.
	if name, err := ClientHelloSNI(hello); err != nil || name != "ke.test" {
		t.Fatalf("server name %q: %v", name, err)
	}
	// A hello that offers nothing is not an error: it is a client that
	// said nothing about what it wants.
	plain := clientHelloWith(t, "ke.test")
	protos, err = ClientHelloALPN(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(protos) != 0 {
		t.Fatalf("a hello with no offer read as %q", protos)
	}
}

// What the reader refuses. Each of these is a length a sender wrote, and
// a reader that believed any of them would be reading somebody else's
// memory or reporting a protocol nobody offered.
func TestClientHelloALPNRefuses(t *testing.T) {
	hello := clientHelloWith(t, "ke.test", "ntske/1")
	// Not TLS at all.
	if _, err := ClientHelloALPN([]byte("GET / HTTP/1.1\r\n\r\n")); err == nil {
		t.Error("a request that is not TLS was read as a hello")
	}
	// A record that has not all arrived.
	if _, err := ClientHelloALPN(hello[:20]); err == nil {
		t.Error("half a hello was read")
	}
	// The list length field disagreeing with the extension's own length.
	broken := breakALPN(t, hello, func(body []byte) {
		binary.BigEndian.PutUint16(body, uint16(len(body)))
	})
	if _, err := ClientHelloALPN(broken); err == nil {
		t.Error("a list length past the extension was believed")
	}
	// A protocol whose length runs past the list.
	broken = breakALPN(t, hello, func(body []byte) {
		if len(body) > 2 {
			body[2] = 0xFF
		}
	})
	if _, err := ClientHelloALPN(broken); err == nil {
		t.Error("a name length past the list was believed")
	}
	// A name of zero length, which is not a protocol.
	broken = breakALPN(t, hello, func(body []byte) {
		if len(body) > 2 {
			body[2] = 0
		}
	})
	if _, err := ClientHelloALPN(broken); err == nil {
		t.Error("an empty protocol name was accepted")
	}
	// A name carrying a control character: it would be compared against
	// a configured list and written to a log, and it can be neither.
	broken = breakALPN(t, hello, func(body []byte) {
		if len(body) > 3 {
			body[3] = 0x00
		}
	})
	if _, err := ClientHelloALPN(broken); err == nil {
		t.Error("a protocol name with a NUL in it was accepted")
	}
}

// breakALPN finds the ALPN extension in a captured hello and lets a test
// edit its body in place.
func breakALPN(t *testing.T, hello []byte, edit func(body []byte)) []byte {
	t.Helper()
	out := append([]byte(nil), hello...)
	// The extension body lives inside the handshake message, which lives
	// inside the record: searching for the extension header is enough
	// for a test, and it fails loudly if the shape changes.
	for i := 0; i+4 < len(out); i++ {
		if binary.BigEndian.Uint16(out[i:]) != extALPN {
			continue
		}
		l := int(binary.BigEndian.Uint16(out[i+2:]))
		if l < 4 || i+4+l > len(out) {
			continue
		}
		edit(out[i+4 : i+4+l])
		return out
	}
	t.Fatal("the captured hello has no ALPN extension")
	return nil
}

// FuzzClientHelloALPN drives the reader with whatever arrives. The
// properties: nothing panics, and anything it returns is a list of names
// a configuration could have been written about.
func FuzzClientHelloALPN(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		protos, err := ClientHelloALPN(data)
		if err != nil {
			if protos != nil {
				t.Fatal("a refusal returned protocols as well")
			}
			return
		}
		if len(protos) > maxALPNProtocols {
			t.Fatalf("%d protocols", len(protos))
		}
		for _, p := range protos {
			if p == "" || len(p) > maxALPNName {
				t.Fatalf("a protocol name of %d octets", len(p))
			}
			if !printableProtocol(p) {
				t.Fatalf("a protocol name that is not printable: %q", p)
			}
		}
	})
}
