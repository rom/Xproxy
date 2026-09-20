package netutil

import "testing"

// TestClientHelloExactlyThirtyFour: a handshake body of exactly 34 bytes
// holds the version and the random but not the session id length octet.
// The guard admitted it and the next read indexed one past the end, which
// panicked the QUIC listener loop and the layer 4 connection goroutine —
// neither of which is covered by a recover, so one datagram ended the
// process.
func TestClientHelloExactlyThirtyFour(t *testing.T) {
	body := make([]byte, 34)
	hs := append([]byte{0x01, 0x00, 0x00, byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(hs))}, hs...)
	for n := 0; n <= len(rec); n++ {
		if _, err := ClientHelloSNI(rec[:n]); err == nil {
			t.Fatalf("a %d-byte truncated ClientHello was accepted", n)
		}
	}
	// A body one byte longer carries the length octet and parses as far as
	// the session id.
	body = make([]byte, 35)
	hs = append([]byte{0x01, 0x00, 0x00, byte(len(body))}, body...)
	rec = append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(hs))}, hs...)
	if _, err := ClientHelloSNI(rec); err == nil {
		t.Fatal("a ClientHello with no extensions reported a server name")
	}
}
