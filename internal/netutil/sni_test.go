package netutil

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// clientHello captures the bytes a real client sends for a server name.
func clientHello(t *testing.T, sni string) []byte {
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
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tc.Handshake() // fails when the fake server closes; the hello is out
	_ = tc.Close()
	return <-got
}

func TestClientHelloSNI(t *testing.T) {
	hello := clientHello(t, "Example.TEST")
	name, err := ClientHelloSNI(hello)
	if err != nil || name != "example.test" {
		t.Fatalf("sni %q err %v", name, err)
	}
	// Truncated at every length reports need-more or not-TLS, never panics.
	for i := 0; i < len(hello); i++ {
		if _, err := ClientHelloSNI(hello[:i]); err == nil {
			t.Fatalf("truncated hello at %d accepted", i)
		}
	}
	if _, err := ClientHelloSNI([]byte("GET / HTTP/1.1\r\n\r\n")); !errors.Is(err, ErrNotTLS) {
		t.Fatalf("http bytes: %v", err)
	}
	noSNI := clientHello(t, "")
	if name, err := ClientHelloSNI(noSNI); err != nil || name != "" {
		t.Fatalf("no sni: %q %v", name, err)
	}
	// Corrupt lengths inside the record.
	bad := append([]byte{}, hello...)
	bad[3], bad[4] = 0xff, 0xff // record length far beyond the bytes
	if _, err := ClientHelloSNI(bad); err == nil {
		t.Fatal("bad record length accepted")
	}
}

// A ClientHello split across two records is the same message to every
// TLS stack behind the proxy. Bounding it by the first record meant the
// name was lost here while the origin read it fine: the flow stalled
// until the peek timeout, or, padded past the caller's buffer, took the
// default route with no name at all.
func TestClientHelloSNIAcrossRecords(t *testing.T) {
	one := clientHello(t, "secret.internal.test")
	name, err := ClientHelloSNI(one)
	if err != nil || name != "secret.internal.test" {
		t.Fatalf("one record: %q %v", name, err)
	}
	body := one[5:]
	for _, split := range []int{1, 4, 7, 20, len(body) - 1} {
		if split <= 0 || split >= len(body) {
			continue
		}
		var frag []byte
		for _, part := range [][]byte{body[:split], body[split:]} {
			frag = append(frag, 0x16, 0x03, 0x01, byte(len(part)>>8), byte(len(part)))
			frag = append(frag, part...)
		}
		name, err := ClientHelloSNI(frag)
		if err != nil || name != "secret.internal.test" {
			t.Fatalf("split at %d: %q %v", split, name, err)
		}
		// Every prefix of it asks for more rather than guessing.
		for n := 1; n < len(frag); n++ {
			if _, err := ClientHelloSNI(frag[:n]); err != nil && !errors.Is(err, ErrNeedMore) {
				t.Fatalf("prefix %d of the split hello: %v", n, err)
			}
		}
	}
}
