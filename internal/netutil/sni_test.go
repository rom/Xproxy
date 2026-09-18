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
