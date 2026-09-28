package coap

import (
	"crypto/tls"
	"fmt"
	"net"
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

// mustPacketConn is the client's own socket, closed with the test.
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
	// Waited for rather than read, because the counter is bumped *after* the
	// answer is sent -- a send that failed is not an answer -- so the client can
	// be holding the refusal before the number moves.
	until(t, s, "the refusal to be counted as answered", func(st proxy.Snapshot) bool {
		return st.CoAPRefusalsAnswered > 0
	})
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

// The handshake bound: a peer that starts one and stops is given up on.
//
// It is the bound that matters most on a datagram listener, because a handshake
// is where a peer that has proved nothing already costs a socket, a goroutine and
// a slot in the peer table. Without a deadline on the socket the handshake reads
// from, one datagram from a spoofable source address holds all three for as long
// as the process runs — and the library takes no context, so the deadline is the
// only place to put the bound.
func TestAHandshakeThatStopsMidFlightIsGivenUpOn(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := dtlsRelay(t, base+"        dtls_handshake_timeout: 300ms\n", "", up.addr())

	// One datagram that makes the listener take a peer slot and a goroutine, and
	// then nothing. A real ClientHello is not needed: what is under test is the
	// deadline on the socket the handshake reads from, and the library is reading
	// it either way.
	pc := mustPacketConn(t)
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	// A DTLS record header: content type 22 (handshake), version 1.2, epoch and
	// sequence zero, and a length that will never be filled.
	hello := []byte{22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40}
	if _, err := pc.WriteTo(hello, ua); err != nil {
		t.Fatal(err)
	}

	// The handshake is abandoned within the bound, which the counter says. With
	// no deadline the library waits for the rest of the flight for as long as the
	// process runs, and this counter never moves.
	until(t, s, "an abandoned handshake was not given up on", func(st proxy.Snapshot) bool {
		return st.CoAPHandshakeFailed > 0
	})
	// And it was never counted as a session. A peer that sent one flight and
	// stopped establishing nothing is the point: a relay that counted it would
	// report sessions that do not exist, which is the number an operator watches
	// to see whether the listener is being used.
	if got := s.Stats().CoAPSessions; got != 0 {
		t.Errorf("%d sessions for a handshake that never completed", got)
	}
	if got := s.Stats().CoAPHandshakes; got == 0 {
		t.Error("the handshake was not counted as started")
	}
	// And the listener still works: giving up on one peer is not giving up on
	// the socket.
	conn := dtlsDial(t, addr)
	got := askDTLS(t, conn, get(0x4100, 2, "3303", "0", "5700"))
	if got.Code != wire.Content {
		t.Errorf("after the abandoned handshake the answer was %s", got.Code)
	}
}

// A session outliving the handshake bound keeps working, which is the other half
// of putting a deadline on the socket underneath it.
//
// The deadline has to be cleared once the handshake is done. pion reads that
// socket for as long as the session lives, so a handshake deadline left in place
// ends every session the moment it passes — however long the idle timeout says.
// On an estate of sensors reporting once a minute that is a handshake per report,
// and the handshake is the expensive part of the exchange for a battery-powered
// device.
func TestASessionOutlivesTheHandshakeBound(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := dtlsRelay(t, base+"        dtls_handshake_timeout: 300ms\n", "", up.addr())
	conn := dtlsDial(t, addr)

	// One exchange to establish the session, then silence for twice the
	// handshake bound, then another.
	if got := askDTLS(t, conn, get(0x4200, 3, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("the first request answered %s", got.Code)
	}
	time.Sleep(700 * time.Millisecond)
	if got := askDTLS(t, conn, get(0x4201, 4, "3303", "0", "5700")); got.Code != wire.Content {
		t.Errorf("after the handshake bound passed the session answered %s", got.Code)
	}
	until(t, s, "the session", func(st proxy.Snapshot) bool { return st.CoAPSessions > 0 })
}

// The idle bound: a session with nothing on it is closed.
//
// It is the other half of the handshake bound and it is what a deployment tunes
// rather than tightens. A session costs a goroutine, a buffer and a slot in the
// peer table for as long as it is held, and a device that reported once and went
// away holds all three until this fires.
func TestAnIdleSessionIsClosed(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	s, addr := dtlsRelay(t, base+"        dtls_idle_timeout: 300ms\n", "", up.addr())
	conn := dtlsDial(t, addr)

	if got := askDTLS(t, conn, get(0x4300, 5, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("the request answered %s", got.Code)
	}
	until(t, s, "the session", func(st proxy.Snapshot) bool { return st.CoAPSessions > 0 })
	// And then silence. The session goes without the client saying anything, which
	// is the point: the bound is on the peer's silence.
	until(t, s, "an idle session was not closed", func(st proxy.Snapshot) bool {
		return st.CoAPSessions == 0
	})
}
