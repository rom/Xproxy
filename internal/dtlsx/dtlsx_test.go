package dtlsx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/rom/xproxy/internal/testutil"
)

// The transport, tested at the two places a datagram listener has to do for
// itself what the kernel does for a stream one: the translation from the
// engine's TLS configuration into the library's, and the demultiplexing of one
// socket into a socket per peer. The sessions themselves are tested through the
// kinds that serve them, against the library that will do the handshake in the
// field.

// The translation from the listener's TLS configuration to DTLS, including the one
// setting that has no DTLS equivalent here and is refused rather than ignored.
func TestTheTranslationRefusesWhatItCannotDo(t *testing.T) {
	cert := selfSigned(t)

	if _, err := NewConfig("coap", &tls.Config{}, Bounds{}); err == nil {
		t.Error("a listener with no certificate was accepted")
	}
	// TLS 1.3 is not DTLS 1.2, and a listener asking for it is asking for
	// something this transport cannot do -- said rather than ignored, because a
	// knob that appears to raise a floor and does not is worse than none.
	_, err := NewConfig("coap", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
	}, Bounds{})
	if err == nil {
		t.Error("a listener requiring TLS 1.3 was accepted")
	} else if !strings.Contains(err.Error(), "DTLS 1.2") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	// TLS 1.2, which is what RFC 7252 s9 names, is accepted.
	if _, err := NewConfig("coap", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	}, Bounds{}); err != nil {
		t.Errorf("a listener requiring TLS 1.2 was refused: %v", err)
	}

	// The five client-certificate policies map one to one, so a rule written
	// about one means the same thing on either transport.
	for tc, want := range map[tls.ClientAuthType]dtls.ClientAuthType{
		tls.NoClientCert:               dtls.NoClientCert,
		tls.RequestClientCert:          dtls.RequestClientCert,
		tls.RequireAnyClientCert:       dtls.RequireAnyClientCert,
		tls.VerifyClientCertIfGiven:    dtls.VerifyClientCertIfGiven,
		tls.RequireAndVerifyClientCert: dtls.RequireAndVerifyClientCert,
	} {
		if got := clientAuth(tc); got != want {
			t.Errorf("%v mapped to %v, wanted %v", tc, got, want)
		}
	}
	// And the client CAs are carried, because without them require means
	// "present a certificate I will not check".
	pool := x509.NewCertPool()
	dc, err := NewConfig("coap", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}, Bounds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(dc.opts) < 5 {
		t.Errorf("%d options, so the client CAs were not carried", len(dc.opts))
	}
}

// The per-peer splitter, which is the piece the kernel supplies for a stream
// listener and not for a datagram one.
func TestTheMuxSplitsByPeerAndIsBounded(t *testing.T) {
	pc := mustPacketConn(t)
	mux := NewMux(pc, Bounds{Peers: 2, Datagram: 2048})
	go mux.Run()
	t.Cleanup(mux.Close)

	// Two peers get two connections, each reading only its own datagrams.
	first, firstMsg := speak(t, pc.LocalAddr().String(), "one")
	second, secondMsg := speak(t, pc.LocalAddr().String(), "two")
	defer func() { _ = first.Close(); _ = second.Close() }()

	conns := map[string]net.PacketConn{}
	for i := 0; i < 2; i++ {
		conn, raddr, err := mux.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		buf := make([]byte, 64)
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read from %s: %v", raddr, err)
		}
		if from.String() != raddr.String() {
			t.Errorf("a datagram from %s arrived on the connection for %s", from, raddr)
		}
		conns[string(buf[:n])] = conn
	}
	if _, ok := conns[firstMsg]; !ok {
		t.Errorf("the first peer's datagram did not arrive: %v", keysOf(conns))
	}
	if _, ok := conns[secondMsg]; !ok {
		t.Errorf("the second peer's datagram did not arrive: %v", keysOf(conns))
	}

	// A third peer is past the bound, so its datagram is dropped and counted
	// rather than making a connection nobody bounded.
	third, _ := speak(t, pc.LocalAddr().String(), "three")
	defer func() { _ = third.Close() }()
	for deadline := time.Now().Add(3 * time.Second); ; {
		if mux.Dropped() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a third peer past the bound was not dropped")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A read past its deadline is a timeout rather than a hang, which is what the
	// handshake bound relies on.
	conn := conns[firstMsg]
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := conn.ReadFrom(make([]byte, 64))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("a read past its deadline returned %v", err)
	}

	// Closing a peer frees its slot, so a listener does not fill up permanently
	// with peers that went away.
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadFrom(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a read on a closed peer returned %v", err)
	}
	// And the slot is genuinely free rather than merely unreadable: a new peer
	// now gets a connection where the third one was refused. Without this the
	// listener would work perfectly until it had seen `max` peers and then stop
	// accepting for as long as it ran -- which is the failure mode that looks
	// like a network fault and is a bounded table nobody drains.
	fourth, fourthMsg := speak(t, pc.LocalAddr().String(), "four")
	defer func() { _ = fourth.Close() }()
	// accept blocks until a peer arrives, so it is given a bound of its own:
	// a slot that was not freed means nothing ever arrives, and a test that
	// waited for that would report a timeout rather than the reason.
	type accepted struct {
		conn net.PacketConn
		err  error
	}
	got := make(chan accepted, 1)
	go func() {
		c, _, err := mux.Accept()
		got <- accepted{c, err}
	}()
	select {
	case a := <-got:
		if a.err != nil {
			t.Fatalf("a peer after a close was not accepted: %v", a.err)
		}
		if err := a.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, _, err := a.conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("the new peer could not be read: %v", err)
		}
		if string(buf[:n]) != fourthMsg {
			t.Errorf("the new peer read %q, want %q", buf[:n], fourthMsg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("closing a peer did not free its slot: a new peer was never accepted")
	}
}

// A datagram larger than the caller's buffer is reported rather than truncated
// silently: a DTLS record read short is a different record.
func TestAnOversizeDatagramIsReportedNotTruncated(t *testing.T) {
	pc := mustPacketConn(t)
	mux := NewMux(pc, Bounds{Peers: 4, Datagram: 2048})
	go mux.Run()
	t.Cleanup(mux.Close)

	peer, err := net.Dial("udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	conn, _, err := mux.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := conn.ReadFrom(make([]byte, 10))
	if err == nil {
		t.Errorf("a hundred octets into ten read %d and reported nothing", n)
	}
}

// speak sends one datagram from a fresh socket and returns it, so the caller can
// keep the socket alive and know what to look for.
func speak(t *testing.T, to, msg string) (net.Conn, string) {
	t.Helper()
	c, err := net.Dial("udp4", to)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	return c, msg
}

func keysOf(m map[string]net.PacketConn) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// selfSigned is a certificate for the translation tests, loaded from disk the way
// the listener loads one.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "127.0.0.1")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func mustPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}
