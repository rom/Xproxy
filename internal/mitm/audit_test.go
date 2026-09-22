package mitm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/mitm"
)

// helloNamed builds a ClientHello record carrying an arbitrary server
// name, which is what a client controls byte for byte.
func helloNamed(t *testing.T, name string) []byte {
	t.Helper()
	sni := []byte{0}                                            // host_name
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name))) //nolint:gosec // test input
	sni = append(sni, name...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(sni))) //nolint:gosec // test input
	list = append(list, sni...)
	ext := binary.BigEndian.AppendUint16(nil, 0)                // server_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(list))) //nolint:gosec // test input
	ext = append(ext, list...)
	exts := binary.BigEndian.AppendUint16(nil, uint16(len(ext))) //nolint:gosec // test input
	exts = append(exts, ext...)

	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 1, 0)
	body = append(body, exts...)

	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22, 3, 1}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs))) //nolint:gosec // test input
	return append(rec, hs...)
}

// TestClientHelloNameIsValidated: the name in a ClientHello is bytes a
// client chose, and it is about to become a certificate's subject, a
// SAN, an upstream server name and a cache key. A parser that hands
// back whatever was in the extension makes every one of those an
// injection point for whoever opened the tunnel.
func TestClientHelloNameIsValidated(t *testing.T) {
	refused := []string{
		strings.Repeat("a", 254),           // longer than a name may be
		strings.Repeat("a", 64) + ".test",  // a label longer than 63
		"has space.test",                   // not a name
		"nul\x00byte.test",                 // a NUL, which C libraries truncate at
		"newline\ninjected.test",           // a log and header injection
		"tab\tseparated.test",              // likewise
		"../../etc/passwd",                 // a path, not a name
		".leading.test",                    // an empty first label
		"trailing..test",                   // an empty middle label
		"name\x7f.test",                    // control bytes
		"h\xc3\xa9llo.test",                // not ASCII: a name is IA5
		strings.Repeat("a.", 200) + "test", // too long again, many labels
	}
	for _, name := range refused {
		got, ok := mitm.ClientHelloName(helloNamed(t, name))
		if !ok {
			t.Errorf("%q: not recognised as a ClientHello at all", clip(name))
			continue
		}
		if got != "" {
			t.Errorf("%q was returned as a server name: %q", clip(name), clip(got))
		}
	}
	// And the names that are names still come back.
	for _, name := range []string{
		"example.com", "www.example.com", "localhost",
		"a-b.example.co.uk", "xn--bcher-kva.example",
		strings.Repeat("a", 63) + ".test",
		"_dmarc.example.com",
	} {
		got, ok := mitm.ClientHelloName(helloNamed(t, name))
		if !ok || got != name {
			t.Errorf("%q: got %q ok=%v, want it accepted", name, got, ok)
		}
	}
	// A hello with no name at all is still a hello.
	if _, ok := mitm.ClientHelloName(helloNamed(t, "")); !ok {
		t.Error("a hello with an empty name was not recognised as a hello")
	}
}

// TestLeafRefusesANameThatIsNotOne is the second half of the same rule:
// even if a caller finds a name somewhere else, nothing that is not a
// name gets signed. One of these keys can impersonate every site to
// every client that trusts the CA, so what it will put its name to is
// not a question to leave to the caller.
func TestLeafRefusesANameThatIsNotOne(t *testing.T) {
	ca := testCA(t)
	for _, name := range []string{
		"", strings.Repeat("a", 254), "has space.test", "nul\x00byte.test",
		"newline\ninjected.test", ".leading.test",
	} {
		if _, err := ca.Leaf(name, nil); err == nil {
			t.Errorf("%q was signed", clip(name))
		}
	}
	if _, err := ca.Leaf("example.com", nil); err != nil {
		t.Fatalf("an ordinary name was refused: %v", err)
	}
	if _, err := ca.Leaf("192.0.2.7", nil); err != nil {
		t.Fatalf("an address was refused: %v", err)
	}
}

// TestLeafDoesNotCopyNamesItWouldNotIssue: the real certificate is the
// destination's, and a destination that puts rubbish in its own SANs
// must not get that rubbish copied into what this proxy signs and hands
// to a client.
func TestLeafDoesNotCopyNamesItWouldNotIssue(t *testing.T) {
	ca := testCA(t)
	real := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "evil\nname"},
		DNSNames: []string{"good.example.com", "bad name.test", strings.Repeat("x", 300)},
	}
	leaf, err := ca.Leaf("example.com", real)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	for _, n := range leaf.Leaf.DNSNames {
		if n != "example.com" && n != "good.example.com" {
			t.Errorf("a name the proxy would not issue was copied in: %q", clip(n))
		}
	}
	if strings.ContainsAny(leaf.Leaf.Subject.CommonName, "\r\n\x00 ") {
		t.Errorf("common name carried control bytes: %q", clip(leaf.Leaf.Subject.CommonName))
	}
}

func clip(s string) string {
	if len(s) > 48 {
		return s[:48] + "..."
	}
	return s
}

// testCA writes a throwaway CA and loads it.
func testCA(t *testing.T) *mitm.CA {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "audit-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	kd, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := mitm.Load(mitm.Options{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}
