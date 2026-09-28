package coap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// CoAP inside DTLS, with a real handshake against the library that will do it in
// the field. Nothing here is mocked: the client is pion's own DTLS client, the
// certificate is a real one, and the message that comes back out went through the
// record layer both ways.

const dtlsYAML = `
version: 1
server:
  listeners:
    - name: field
      address: "127.0.0.1:0"
      kind: coap
      tls:
        certificates:
          - {cert_file: %q, key_file: %q}
%s
      coap:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: devices, endpoints: [{address: %q}]}
`

// dtlsRelay starts a listener with a certificate and returns it with its address.
func dtlsRelay(t *testing.T, section, tlsExtra, device string) (*proxy.Server, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "127.0.0.1")
	s := proxytest.Start(t, fmt.Sprintf(dtlsYAML, cert, key, tlsExtra, section, device))
	return s, proxytest.Addr(t, s, "field")
}

// dtlsDial handshakes with the listener as a device would.
func dtlsDial(t *testing.T, addr string, certs ...tls.Certificate) *dtls.Conn {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	opts := []dtls.ClientOption{
		// The certificate is a fresh self-signed one per test, so the client
		// does not verify it. What is under test is the relay's side of the
		// handshake and what it does with the session, not this test's own trust
		// store.
		dtls.WithInsecureSkipVerify(true),
	}
	if len(certs) > 0 {
		opts = append(opts, dtls.WithCertificates(certs...))
	}
	conn, err := dtls.ClientWithOptions(mustPacketConn(t), ua, opts...)
	if err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
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

// ask sends one CoAP message inside the session and reads the answer.
func askDTLS(t *testing.T, conn *dtls.Conn, m *wire.Message) *wire.Message {
	t.Helper()
	raw, err := wire.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no answer inside the session: %v", err)
	}
	got, err := wire.Parse(buf[:n])
	if err != nil {
		t.Fatalf("the answer did not parse: %v", err)
	}
	return got
}

// The floor: a request inside a session reaches the device, and the answer comes
// back inside the same session rather than as cleartext on the socket.
func TestARequestInsideDTLSIsRelayedAndAnsweredInTheSession(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := dtlsRelay(t, base, "", up.addr())
	conn := dtlsDial(t, addr)

	got := askDTLS(t, conn, get(0x4000, 1, "3303", "0", "5700"))
	if got.Code != wire.Content {
		t.Fatalf("the client got %s", got.Code)
	}
	if string(got.Payload) != "21.5" {
		t.Errorf("payload %q", got.Payload)
	}
	seen := up.await(t, 1, "the request")[0]
	if seen.Path() != "/3303/0/5700" {
		t.Errorf("the device saw %s", seen.Path())
	}
	until(t, s, "the handshake", func(st proxy.Snapshot) bool {
		return st.CoAPHandshakes > 0 && st.CoAPSessions > 0
	})
}

// secure_only, which is the whole reason a DTLS listener is worth having: it lets
// a rule say "the actuators may only be written by a client that authenticated",
// and inside a session that is true.
func TestSecureOnlyIsSatisfiedInsideASession(t *testing.T) {
	section := "        upstream: devices\n" +
		"        rules:\n" +
		"          - name: lighting\n" +
		"            action: allow\n" +
		"            methods: [put]\n" +
		"            paths: [\"/3311/...\"]\n" +
		"            secure_only: true\n"
	up := startDevice(t, &fakeDevice{})
	_, addr := dtlsRelay(t, section, "", up.addr())
	conn := dtlsDial(t, addr)
	if got := askDTLS(t, conn, req(wire.PUT, 0x4100, 2, "3311", "0", "5850")); got.Code != wire.Content {
		t.Fatalf("a secure write was refused: %s", got.Code)
	}
	if n := len(up.seen()); n != 1 {
		t.Errorf("the device saw %d requests", n)
	}
}

// A refusal inside a session comes back inside the session, which is the case the
// replier exists for: an answer written to the socket instead would be cleartext to
// a peer that established a session precisely so that it would not be, and the
// peer's DTLS stack would discard it -- so the failure would look like a timeout
// rather than like a refusal.
func TestARefusalInsideDTLSComesBackInsideTheSession(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := dtlsRelay(t, base, "", up.addr())
	conn := dtlsDial(t, addr)

	got := askDTLS(t, conn, req(wire.PUT, 0x4200, 3, "3311", "0", "5850"))
	if got.Code != wire.Forbidden {
		t.Fatalf("the client got %s, wanted 4.03", got.Code)
	}
	if len(up.seen()) != 0 {
		t.Fatal("the refused request reached the device")
	}
	until(t, s, "the refusal", refused("default_deny"))
	if s.Stats().CoAPRefusalsAnswered == 0 {
		t.Error("the refusal was not counted as answered")
	}
}

// A plaintext CoAP datagram sent at a DTLS listener is not a CoAP message at all
// as far as the listener is concerned: it is the first flight of a handshake that
// will not parse. It must not be relayed, and the handshake failure is counted.
func TestCleartextAtADTLSListenerIsNotRelayed(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := dtlsRelay(t, base, "", up.addr())

	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp4", nil, ua)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	raw, err := wire.Encode(get(0x4300, 4, "3303", "0", "5700"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	// Nothing comes back, and nothing reaches the device.
	_ = c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("a cleartext request got %d octets back", n)
	}
	if len(up.seen()) != 0 {
		t.Fatal("a cleartext request reached the device through a DTLS listener")
	}
	// The handshake attempt is counted rather than silently ignored, so that a
	// client configured for the wrong port shows up somewhere.
	until(t, s, "the handshake attempt", func(st proxy.Snapshot) bool {
		return st.CoAPHandshakes > 0
	})
}

// A client certificate the listener requires, which is what turns a DTLS session
// into an identity a rule can name.
func TestAClientCertificateIsRequiredWhenAsked(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	clientCert, clientKey := ca.Issue(t, dir, "device-1")

	up := startDevice(t, &fakeDevice{})
	tlsExtra := "        client_auth: require\n        client_ca_file: " + ca.Path + "\n"
	_, addr := dtlsRelay(t, base, tlsExtra, up.addr())

	// With a certificate the CA issued: the session establishes and the request
	// is relayed.
	pair, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	conn := dtlsDial(t, addr, pair)
	if got := askDTLS(t, conn, get(0x4400, 5, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("a certified client was refused: %s", got.Code)
	}

	// And without one the handshake does not complete, so nothing this listener
	// polices is ever reached.
	//
	// The constructor is not what proves it: pion handshakes lazily, so
	// ClientWithOptions returns before a single flight has crossed the wire and
	// would return nil for a peer that is not there at all. What proves it is the
	// write, which is where the handshake happens.
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := dtls.ClientWithOptions(mustPacketConn(t), ua,
		dtls.WithInsecureSkipVerify(true))
	if err != nil {
		// A refusal this early is also a pass: the session was not established.
		return
	}
	defer func() { _ = bare.Close() }()
	before := len(up.seen())
	raw, err := wire.Encode(get(0x4401, 6, "3303", "0", "5700"))
	if err != nil {
		t.Fatal(err)
	}
	if err := bare.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := bare.Write(raw); err == nil {
		// The write went through the handshake, so if it succeeded the session
		// exists. Read as well, in case the library buffers the write.
		if _, err := bare.Read(make([]byte, 2048)); err == nil {
			t.Fatal("a client with no certificate got an answer where one is required")
		}
	}
	if n := len(up.seen()); n != before {
		t.Fatalf("a client with no certificate reached the device (%d then %d)", before, n)
	}
}

// The translation from the listener's TLS configuration to DTLS, including the one
// setting that has no DTLS equivalent here and is refused rather than ignored.
func TestTheDTLSTranslationRefusesWhatItCannotDo(t *testing.T) {
	cert := selfSigned(t)

	if _, err := dtlsOptions(&tls.Config{}); err == nil {
		t.Error("a listener with no certificate was accepted")
	}
	// TLS 1.3 is not DTLS 1.2, and a listener asking for it is asking for
	// something this transport cannot do -- said rather than ignored, because a
	// knob that appears to raise a floor and does not is worse than none.
	_, err := dtlsOptions(&tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
	})
	if err == nil {
		t.Error("a listener requiring TLS 1.3 was accepted")
	} else if !strings.Contains(err.Error(), "DTLS 1.2") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	// TLS 1.2, which is what RFC 7252 s9 names, is accepted.
	if _, err := dtlsOptions(&tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	}); err != nil {
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
	opts, err := dtlsOptions(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) < 5 {
		t.Errorf("%d options, so the client CAs were not carried", len(opts))
	}
}

// The per-peer splitter, which is the piece the kernel supplies for a stream
// listener and not for a datagram one.
func TestThePacketMuxSplitsByPeerAndIsBounded(t *testing.T) {
	pc := mustPacketConn(t)
	mux := newPacketMux(pc, 2, 2048)
	go mux.run()
	t.Cleanup(mux.close)

	// Two peers get two connections, each reading only its own datagrams.
	first, firstMsg := speak(t, pc.LocalAddr().String(), "one")
	second, secondMsg := speak(t, pc.LocalAddr().String(), "two")
	defer func() { _ = first.Close(); _ = second.Close() }()

	conns := map[string]net.PacketConn{}
	for i := 0; i < 2; i++ {
		conn, raddr, err := mux.accept()
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
		if mux.dropped.Load() > 0 {
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
}

// A datagram larger than the caller's buffer is reported rather than truncated
// silently: a DTLS record read short is a different record.
func TestAnOversizeDatagramIsReportedNotTruncated(t *testing.T) {
	pc := mustPacketConn(t)
	mux := newPacketMux(pc, 4, 2048)
	go mux.run()
	t.Cleanup(mux.close)

	peer, err := net.Dial("udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	conn, _, err := mux.accept()
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
	if _, err := os.Stat(certPath); err != nil {
		t.Fatal(err)
	}
	return pair
}
