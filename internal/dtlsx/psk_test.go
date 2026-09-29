package dtlsx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
)

// The pre-shared key table, and what it refuses at load.
//
// Every refusal here is about the *identity* rather than the key, because the
// identity is what the policy above this package is written in: a row nobody
// can name is a row that decides nothing, and a row everybody reaches is a
// hole.
func TestThePreSharedKeyTableRefuses(t *testing.T) {
	tab, err := NewPSK("", nil)
	if err != nil {
		t.Fatal(err)
	}
	good := []byte("0123456789abcdef")
	for _, c := range []struct {
		what     string
		identity string
		key      []byte
		want     string
	}{
		{"an empty identity", "", good, "may not be empty"},
		{"an identity past the bound", strings.Repeat("a", MaxPSKIdentity+1), good, "past the"},
		{"a key of eight octets", "sensor-1", []byte("01234567"), "least this accepts"},
		{"a key past the bound", "sensor-1", make([]byte, MaxPSKKeyBytes+1), "past the"},
	} {
		err := tab.Add(c.identity, c.key)
		if err == nil {
			t.Errorf("%s was accepted", c.what)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.what, err, c.want)
		}
	}
	if err := tab.Add("sensor-1", good); err != nil {
		t.Fatalf("a good row: %v", err)
	}
	if err := tab.Add("sensor-1", good); err == nil {
		t.Error("the same identity twice was accepted, and two keys for one identity is a table nobody can read")
	}
	if tab.Len() != 1 || !tab.Holds("sensor-1") || tab.Holds("sensor-2") {
		t.Errorf("the table holds %d", tab.Len())
	}
	if _, err := NewPSK(strings.Repeat("h", MaxPSKIdentity+1), nil); err == nil {
		t.Error("a hint past the bound was accepted")
	}
}

// A listener with a table and no certificate is a PSK-only listener, which is
// the ordinary shape on a segment of constrained devices; one with neither is
// a listener with no way to establish anything.
func TestAConfigurationNeedsACertificateOrATable(t *testing.T) {
	if _, err := NewConfig("coap", nil, Bounds{}); err == nil {
		t.Fatal("a DTLS configuration with neither a certificate nor a table was built")
	}
	tab := mustTable(t, "sensor-1", "0123456789abcdef")
	if _, err := NewConfig("coap", nil, Bounds{}, WithPSK(tab)); err != nil {
		t.Fatalf("a pre-shared key listener with no certificate: %v", err)
	}
	// An empty table is not a table: it would offer the mode and hold no key,
	// so every handshake in it would fail. The configuration then needs a
	// certificate like any other.
	empty, err := NewPSK("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewConfig("coap", nil, Bounds{}, WithPSK(empty)); err == nil {
		t.Error("an empty table stood in for a certificate")
	}
}

// A real handshake, against the library that will do it in the field: the
// identity the client names reaches the session, and the suite is one of the
// four this package offers.
func TestAPreSharedKeyHandshakeCarriesTheIdentity(t *testing.T) {
	tab := mustTable(t, "sensor-hall-1", "0123456789abcdef")
	cfg, err := NewConfig("coap", nil, Bounds{}, WithPSK(tab))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan identityResult, 1)
	addr := servePSK(t, cfg, got)

	conn := dialPSK(t, addr, "sensor-hall-1", "0123456789abcdef")
	defer func() { _ = conn.Close() }()

	select {
	case r := <-got:
		if r.err != "" {
			t.Fatalf("the server side: %s", r.err)
		}
		if r.identity != "sensor-hall-1" {
			t.Errorf("identity %q", r.identity)
		}
		if r.suite != uint16(dtls.TLS_PSK_WITH_AES_128_CCM_8) {
			t.Errorf("cipher suite %#04x, want RFC 7252 s9.1.3.1's mandatory one", r.suite)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the handshake never finished")
	}
	if known, unknown := tab.Counts(); known != 1 || unknown != 0 {
		t.Errorf("known %d unknown %d", known, unknown)
	}
}

// An identity the table does not hold fails the handshake and is reported --
// which is the event worth having, because on a protocol whose only identity
// is this one, a name nobody enrolled is either a device provisioned wrong or
// somebody trying names.
func TestAnUnknownIdentityFailsTheHandshakeAndIsReported(t *testing.T) {
	var seen []string
	tab, err := NewPSK("", func(id string) { seen = append(seen, id) })
	if err != nil {
		t.Fatal(err)
	}
	if err := tab.Add("sensor-1", []byte("0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	cfg, err := NewConfig("coap", nil, Bounds{}, WithPSK(tab))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan identityResult, 1)
	addr := servePSK(t, cfg, got)

	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dtls.ClientWithOptions(mustPacketConn(t), ua,
		dtls.WithPSK(func([]byte) ([]byte, error) { return []byte("0123456789abcdef"), nil }),
		dtls.WithPSKIdentityHint([]byte("sensor-99")),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8))
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err = conn.HandshakeContext(ctx)
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("a peer naming an identity nobody enrolled established a session")
	}
	select {
	case r := <-got:
		if r.err == "" {
			t.Fatalf("the server established a session for an unknown identity: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server never finished")
	}
	if len(seen) == 0 || seen[0] != "sensor-99" {
		t.Errorf("the unknown identity was not reported: %v", seen)
	}
	if known, unknown := tab.Counts(); known != 0 || unknown != 1 {
		t.Errorf("known %d unknown %d", known, unknown)
	}
}

// A certificate-authenticated session has no pre-shared key identity, and says
// so rather than answering with something.
func TestACertificateSessionHasNoIdentity(t *testing.T) {
	cert := deviceKey(t)
	cfg, err := NewConfig("coap", &tls.Config{Certificates: []tls.Certificate{cert}, //nolint:gosec // a test certificate
		MinVersion: tls.VersionTLS12}, Bounds{})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan identityResult, 1)
	addr := servePSK(t, cfg, got)
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dtls.ClientWithOptions(mustPacketConn(t), ua, dtls.WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatalf("the handshake: %v", err)
	}
	select {
	case r := <-got:
		if r.err != "" {
			t.Fatalf("the server side: %s", r.err)
		}
		if r.hasIdentity {
			t.Errorf("a certificate session reported a pre-shared key identity %q", r.identity)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the handshake never finished")
	}
}

// The fingerprint a policy pins a raw public key by: the hash of the key, not
// of the certificate that carried it.
func TestTheKeyFingerprintIsOfTheKey(t *testing.T) {
	cert := deviceKey(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := KeyFingerprint(leaf)
	if len(sum) != 64 {
		t.Fatalf("fingerprint %q", sum)
	}
	// The same key in a second certificate -- a reissue -- has the same
	// fingerprint, which is the property that makes pinning a key different
	// from pinning a certificate.
	again := reissue(t, cert)
	if got := KeyFingerprint(again); got != sum {
		t.Errorf("a reissued certificate around the same key gave %q, want %q", got, sum)
	}
	// And a different key does not.
	if got := KeyFingerprint(mustLeaf(t, deviceKey(t))); got == sum {
		t.Error("two different keys have the same fingerprint")
	}
	if KeyFingerprint(nil) != "" {
		t.Error("a fingerprint of nothing")
	}
}

// What an operator may paste into a configuration, and what is refused.
func TestParsingAKeyFingerprint(t *testing.T) {
	want := "4f2a" + strings.Repeat("00", 30)
	for _, in := range []string{
		want,
		"sha256:" + want,
		"SHA256:4F:2A:" + strings.Repeat("00:", 29) + "00",
		"4f 2a " + strings.Repeat("00 ", 29) + "00",
	} {
		got, err := ParseKeyFingerprint(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q gave %q", in, got)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"", "required"},
		{"sha1:4f2a", "other than sha256"},
		{"zz" + strings.Repeat("00", 31), "not hexadecimal"},
		{"4f2a", "octets"},
	} {
		if _, err := ParseKeyFingerprint(c.in); err == nil {
			t.Errorf("%q was accepted", c.in)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q gave %v, want %q", c.in, err, c.want)
		}
	}
}

// identityResult is what the server goroutine found out about its peer.
type identityResult struct {
	identity    string
	hasIdentity bool
	suite       uint16
	err         string
}

// servePSK runs one listener that accepts a single session and reports what
// the peer turned out to be.
func servePSK(t *testing.T, cfg *Config, out chan<- identityResult) string {
	t.Helper()
	pc := mustPacketConn(t)
	mux := NewMux(pc, Bounds{})
	go mux.Run()
	t.Cleanup(mux.Close)
	go func() {
		peer, raddr, err := mux.Accept()
		if err != nil {
			out <- identityResult{err: "accept: " + err.Error()}
			return
		}
		sess, err := cfg.Accept(peer, raddr, 5*time.Second)
		if err != nil {
			out <- identityResult{err: "handshake: " + err.Error()}
			return
		}
		id, ok := sess.PeerIdentity()
		out <- identityResult{identity: string(id), hasIdentity: ok, suite: sess.CipherSuite()}
	}()
	return pc.LocalAddr().String()
}

// dialPSK handshakes as a constrained device would: one identity, one key, and
// the suite RFC 7252 s9.1.3.1 makes mandatory.
func dialPSK(t *testing.T, addr, identity, key string) *dtls.Conn {
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
		t.Fatalf("the client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatalf("the handshake: %v", err)
	}
	return conn
}

func mustTable(t *testing.T, identity, key string) *PSK {
	t.Helper()
	tab, err := NewPSK("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tab.Add(identity, []byte(key)); err != nil {
		t.Fatal(err)
	}
	return tab
}

// deviceKey is a certificate around a fresh key, which is what a device in raw
// public key mode sends: the key is the identity and the certificate is only
// the envelope the transport has for carrying one.
func deviceKey(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "sensor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"sensor"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// reissue makes a second certificate around the same key.
func reissue(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject:   pkix.Name{CommonName: "sensor, reissued"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	out, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustLeaf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
