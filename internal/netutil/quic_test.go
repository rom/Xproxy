package netutil

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// captureFlight has a real quic-go client send its first flight to a
// silent socket and returns the datagrams (the ClientHello spans two).
func captureFlight(t *testing.T, sni string) [][]byte {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"x"}, MinVersion: tls.VersionTLS13}, &quic.Config{HandshakeIdleTimeout: time.Second}) //nolint:gosec // test
	}()
	var out [][]byte
	for len(out) < 2 {
		buf := make([]byte, 2048)
		_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, buf[:n])
	}
	return out
}

func TestQUICInitial(t *testing.T) {
	flight := captureFlight(t, "Passthrough.Example.TEST")
	dg := flight[0]
	frames, err := QUICCryptoData(dg)
	if err != nil {
		t.Fatalf("crypto data: %v", err)
	}
	var a QUICHelloAssembler
	if _, err := a.Add(frames); !errors.Is(err, ErrQUICNeedMore) {
		t.Fatalf("first datagram alone: %v", err)
	}
	more, err := QUICCryptoData(flight[1])
	if err != nil {
		t.Fatalf("second datagram: %v", err)
	}
	sni, err := a.Add(more)
	if err != nil || sni != "passthrough.example.test" {
		t.Fatalf("sni: %q %v", sni, err)
	}
	frames = append(frames, more...)
	// Tampering with the payload breaks authentication.
	bad := append([]byte(nil), dg...)
	bad[len(bad)-1] ^= 0xff
	if _, err := QUICCryptoData(bad); !errors.Is(err, ErrNotQUIC) {
		t.Fatalf("tampered: %v", err)
	}
	// Not QUIC: a short header, a TLS record, garbage, another version.
	for _, b := range [][]byte{{0x40, 1, 2, 3}, {0x16, 0x03, 0x01, 0, 5, 1, 2, 3, 4, 5}, {}, append([]byte{0xc0, 0xff, 0x00, 0x00, 0x1d}, dg[5:]...)} {
		if _, err := QUICCryptoData(b); !errors.Is(err, ErrNotQUIC) {
			t.Fatalf("%x: %v", b[:min(len(b), 8)], err)
		}
	}
	// Truncations never panic.
	for cut := 0; cut < len(dg); cut += 37 {
		_, _ = QUICCryptoData(dg[:cut])
	}
	// An assembler waits for a gap and reports need-more, then completes.
	var partial QUICHelloAssembler
	// Everything but the first 20 bytes, out of order, then the head.
	var whole []byte
	for _, f := range frames {
		if f.Offset == 0 {
			whole = append(f.Data, whole...)
		}
	}
	all := make([]byte, 0, 2048)
	for _, f := range sortedFrames(frames) {
		all = append(all[:f.Offset], f.Data...)
	}
	if _, err := partial.Add([]QUICCrypto{{Offset: 20, Data: all[20:]}}); !errors.Is(err, ErrQUICNeedMore) {
		t.Fatalf("gap: %v", err)
	}
	if sni, err := partial.Add([]QUICCrypto{{Offset: 0, Data: all[:20]}}); err != nil || sni != "passthrough.example.test" {
		t.Fatalf("assembled: %q %v", sni, err)
	}
	_ = whole
	var big QUICHelloAssembler
	if _, err := big.Add([]QUICCrypto{{Offset: 0, Data: make([]byte, MaxQUICHello+1)}}); !errors.Is(err, ErrNotTLS) {
		t.Fatalf("oversize: %v", err)
	}
	if v, n := quicVarint([]byte{0xc0, 0, 0, 0, 0, 0, 0, 1}); v != 1 || n != 8 {
		t.Fatalf("varint: %d %d", v, n)
	}
	if _, n := quicVarint([]byte{0x80, 0}); n != 0 {
		t.Fatal("short varint accepted")
	}
}

func sortedFrames(in []QUICCrypto) []QUICCrypto {
	out := append([]QUICCrypto(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}
