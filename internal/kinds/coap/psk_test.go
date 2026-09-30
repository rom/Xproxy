package coap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// RFC 7252 s9's other two security modes, end to end.
//
// Nothing here is mocked: the client is pion's own DTLS client speaking the
// suite s9.1.3.1 makes mandatory, the keys are read from files the way an
// operator provisions them, and the message that comes back went through the
// record layer both ways. What is being checked is the thing the modes are
// *for*: that the peer arrives with a name, that the name reaches the policy
// and the log, and that a peer without one is refused where the estate said it
// should be.

const pskYAML = `
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

// pskRelay starts a listener whose coap section is the block given, with the
// key file written where the configuration points at it.
func pskRelay(t *testing.T, section, tlsExtra, device string, keys map[string]string) (*proxy.Server, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "127.0.0.1")
	for name, secret := range keys {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		section = strings.ReplaceAll(section, "KEYDIR/"+name, filepath.Join(dir, name))
	}
	s := proxytest.Start(t, fmt.Sprintf(pskYAML, cert, key, tlsExtra, section, device))
	return s, proxytest.Addr(t, s, "field")
}

// dialPSK handshakes as a constrained device does: an identity in the clear, a
// key it derives from, and TLS_PSK_WITH_AES_128_CCM_8.
func dialPSK(t *testing.T, addr, identity, key string) (*dtls.Conn, error) {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dtls.ClientWithOptions(mustPacketConn(t), ua,
		dtls.WithPSK(func([]byte) ([]byte, error) { return []byte(key), nil }),
		dtls.WithPSKIdentityHint([]byte(identity)),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
}

// The identity is the policy. A rule naming a security name covers the device
// that proved that name and nothing else -- which on a shared segment is the
// whole reason to run DTLS here, because the source address is a guess about
// which sensor sent something and this is not.
func TestAPreSharedKeyIdentityIsWhatTheRuleNames(t *testing.T) {
	section := "        upstream: devices\n" +
		"        psk:\n" +
		"          hint: plant-a\n" +
		"          identities:\n" +
		"            - {identity: hall-sensor-1, key: \"file:KEYDIR/hall1\", name: hall-sensors}\n" +
		"            - {identity: pump-controller, key: \"file:KEYDIR/pump\"}\n" +
		"        rules:\n" +
		"          - name: sensors-read\n" +
		"            action: allow\n" +
		"            security_names: [hall-sensors]\n" +
		"            methods: [get]\n" +
		"            paths: [\"/3303/...\"]\n" +
		"          - name: pump-writes\n" +
		"            action: allow\n" +
		"            security_names: [pump-controller]\n" +
		"            methods: [put]\n" +
		"            paths: [\"/3311/...\"]\n"
	up := startDevice(t, &fakeDevice{})
	s, addr := pskRelay(t, section, "", up.addr(),
		map[string]string{"hall1": "0123456789abcdef", "pump": "fedcba9876543210"})

	// The sensor, doing what the rule about its name permits.
	sensor, err := dialPSK(t, addr, "hall-sensor-1", "0123456789abcdef")
	if err != nil {
		t.Fatalf("the sensor's handshake: %v", err)
	}
	if got := askDTLS(t, sensor, get(0x5000, 1, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("the sensor's read was answered %s", got.Code)
	}
	until(t, s, "a pre-shared key session", func(st proxy.Snapshot) bool {
		return st.CoAPPSKSessions > 0
	})

	// And the same sensor doing what the *other* device's rule permits. The
	// rule names a name this peer does not have, so it does not select, and
	// the message falls through to the default -- which is deny.
	if got := askDTLS(t, sensor, req(wire.PUT, 0x5001, 2, "3311", "0", "5850")); got.Code != wire.Forbidden {
		t.Errorf("a sensor wrote through the pump's rule: %s", got.Code)
	}

	// The pump, whose identity maps to itself because the row named no name.
	pump, err := dialPSK(t, addr, "pump-controller", "fedcba9876543210")
	if err != nil {
		t.Fatalf("the pump's handshake: %v", err)
	}
	if got := askDTLS(t, pump, req(wire.PUT, 0x5002, 3, "3311", "0", "5850")); got.Code != wire.Content {
		t.Errorf("the pump's write was answered %s", got.Code)
	}
	if n := len(up.seen()); n != 2 {
		t.Errorf("the device saw %d requests, want the sensor's read and the pump's write", n)
	}
}

// An identity nobody enrolled does not get a session, and the attempt is
// counted and reported: on this protocol the identity is the only thing that
// distinguishes one device from another, so a name nobody enrolled is either a
// device provisioned wrong or somebody trying names.
func TestAnUnknownIdentityGetsNoSession(t *testing.T) {
	section := "        upstream: devices\n" +
		"        psk:\n" +
		"          identities:\n" +
		"            - {identity: hall-sensor-1, key: \"file:KEYDIR/hall1\"}\n" +
		"        rules:\n" +
		"          - {name: sensors, action: allow, security_names: [hall-sensor-1], paths: [\"/3303/...\"]}\n"
	up := startDevice(t, &fakeDevice{})
	s, addr := pskRelay(t, section, "", up.addr(), map[string]string{"hall1": "0123456789abcdef"})

	if _, err := dialPSK(t, addr, "hall-sensor-99", "0123456789abcdef"); err == nil {
		t.Fatal("a device naming an identity nobody enrolled established a session")
	}
	until(t, s, "the unknown identity", func(st proxy.Snapshot) bool {
		return st.CoAPUnknownIdentity > 0
	})
	if len(up.seen()) != 0 {
		t.Error("something reached the device")
	}
	// And the right key under the right identity still works, so what was
	// refused was the name and not the listener.
	conn, err := dialPSK(t, addr, "hall-sensor-1", "0123456789abcdef")
	if err != nil {
		t.Fatalf("the enrolled device: %v", err)
	}
	if got := askDTLS(t, conn, get(0x5100, 4, "3303", "0", "5700")); got.Code != wire.Content {
		t.Errorf("the enrolled device was answered %s", got.Code)
	}
}

// The wrong key under a right identity is a handshake that fails in the
// record layer rather than in the table: the identity is known, the derived
// keys do not agree, and nothing reaches the policy.
func TestTheWrongKeyUnderAKnownIdentity(t *testing.T) {
	section := "        upstream: devices\n" +
		"        psk:\n" +
		"          identities:\n" +
		"            - {identity: hall-sensor-1, key: \"file:KEYDIR/hall1\"}\n" +
		"        rules:\n" +
		"          - {name: sensors, action: allow, security_names: [hall-sensor-1], paths: [\"/3303/...\"]}\n"
	up := startDevice(t, &fakeDevice{})
	_, addr := pskRelay(t, section, "", up.addr(), map[string]string{"hall1": "0123456789abcdef"})
	if _, err := dialPSK(t, addr, "hall-sensor-1", "wrong-key-0123456"); err == nil {
		t.Fatal("a device with the wrong key established a session")
	}
	if len(up.seen()) != 0 {
		t.Error("something reached the device")
	}
}

// require_security_name is what a session that authenticated some other way
// means. The listener below holds a key table and a certificate, and a
// certificate-authenticated peer maps to no name -- so its messages are
// refused rather than decided by rules it cannot match.
func TestASessionWithNoNameIsRefusedWhereTheEstateSaidSo(t *testing.T) {
	section := "        upstream: devices\n" +
		"        psk:\n" +
		"          identities:\n" +
		"            - {identity: hall-sensor-1, key: \"file:KEYDIR/hall1\"}\n" +
		"        rules:\n" +
		"          - {name: sensors, action: allow, security_names: [hall-sensor-1], paths: [\"/3303/...\"]}\n"
	up := startDevice(t, &fakeDevice{})
	s, addr := pskRelay(t, section, "", up.addr(), map[string]string{"hall1": "0123456789abcdef"})

	// A certificate client: the handshake succeeds, because the listener has
	// a certificate too, and the message does not.
	conn := dtlsDial(t, addr)
	if got := askDTLS(t, conn, get(0x5200, 5, "3303", "0", "5700")); got.Code != wire.Unauthorized {
		t.Fatalf("a session with no security name was answered %s, want 4.01", got.Code)
	}
	until(t, s, "the unnamed session", func(st proxy.Snapshot) bool {
		return st.CoAPUnnamed > 0 && st.Refusals["coap"]["no_security_name"] > 0
	})
	if len(up.seen()) != 0 {
		t.Error("an unnamed session reached the device")
	}
}

// A pinned public key: the key is the identity, the policy names its
// fingerprint, and a peer holding a key nobody pinned gets no name.
func TestAPinnedPublicKeyIsAnIdentity(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "127.0.0.1")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	section := "        upstream: devices\n" +
		"        public_keys:\n" +
		"          - {fingerprint: \"sha256:" + dtlsx.KeyFingerprint(leaf) + "\", name: gateway}\n" +
		"        rules:\n" +
		"          - {name: gateway-reads, action: allow, security_names: [gateway], paths: [\"/3303/...\"]}\n"
	up := startDevice(t, &fakeDevice{})
	s, addr := pskRelay(t, section, "        client_auth: require_any\n", up.addr(), nil)

	conn := dtlsDial(t, addr, pair)
	if got := askDTLS(t, conn, get(0x5300, 6, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("the pinned key was answered %s", got.Code)
	}

	// Another device, with a key this listener does not pin. The handshake
	// succeeds -- the listener asks for a certificate and does not verify it
	// against an authority, which is the shape a raw public key takes -- and
	// the message is refused, because the peer maps to no name.
	other := t.TempDir()
	otherCert, otherKey := testutil.WriteCert(t, other, "127.0.0.1")
	otherPair, err := tls.LoadX509KeyPair(otherCert, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	conn2 := dtlsDial(t, addr, otherPair)
	if got := askDTLS(t, conn2, get(0x5301, 7, "3303", "0", "5700")); got.Code != wire.Unauthorized {
		t.Errorf("a key nobody pinned was answered %s, want 4.01", got.Code)
	}
	until(t, s, "the unpinned key", func(st proxy.Snapshot) bool {
		return st.Refusals["coap"]["no_security_name"] > 0
	})
	if n := len(up.seen()); n != 1 {
		t.Errorf("the device saw %d requests, want only the pinned peer's", n)
	}
}

// A listener with no tables behaves as it did before any of this existed: a
// DTLS session with a certificate carries no name, nothing requires one, and
// the rules decide on what they always decided on.
func TestAListenerWithNoTablesIsUnchanged(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	_, addr := pskRelay(t, base, "", up.addr(), nil)
	conn := dtlsDial(t, addr)
	if got := askDTLS(t, conn, get(0x5400, 8, "3303", "0", "5700")); got.Code != wire.Content {
		t.Fatalf("a certificate session on a listener with no tables was answered %s", got.Code)
	}
}

// A listener with a key table and no certificate at all, which is the shape a
// segment of constrained devices actually takes: the devices have no
// certificate machinery and the estate that runs them usually has no authority
// of its own either. RFC 7252 s9.1.3.1's mode needs a certificate at neither
// end, and requiring one here would be requiring the thing the mode replaces.
func TestAListenerWithKeysAndNoCertificate(t *testing.T) {
	up := startDevice(t, &fakeDevice{})
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "hall1")
	if err := os.WriteFile(keyFile, []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: field
      address: "127.0.0.1:0"
      kind: coap
      coap:
        upstream: devices
        psk:
          identities:
            - {identity: hall-sensor-1, key: %q}
        rules:
          - {name: sensors, action: allow, security_names: [hall-sensor-1], paths: ["/3303/..."]}
logging: {access: {enabled: false}}
upstreams:
  - {name: devices, endpoints: [{address: %q}]}
`, "file:"+keyFile, up.addr()))
	addr := proxytest.Addr(t, s, "field")

	// NoSec is not what this listener serves: a client that sends a bare
	// datagram gets no answer, because there is no session to answer in.
	conn, err := dialPSK(t, addr, "hall-sensor-1", "0123456789abcdef")
	if err != nil {
		t.Fatalf("the handshake against a certificate-less listener: %v", err)
	}
	if got := askDTLS(t, conn, get(0x5500, 9, "3303", "0", "5700")); got.Code != wire.Content {
		t.Errorf("answered %s", got.Code)
	}
	until(t, s, "a pre-shared key session", func(st proxy.Snapshot) bool {
		return st.CoAPPSKSessions > 0
	})
}
