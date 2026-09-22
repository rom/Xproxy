package mitm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/mitm"
)

// writeCA writes a signing CA and returns the two paths.
func writeCA(t *testing.T, dir string, mutate func(*x509.Certificate), mode os.FileMode) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xproxy interception CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), mode); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func load(t *testing.T) *mitm.CA {
	t.Helper()
	cert, key := writeCA(t, t.TempDir(), nil, 0o600)
	ca, err := mitm.Load(mitm.Options{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// A signing key anybody can read is the ability to impersonate every
// site to every client that trusts this CA, so the load fails over it.
func TestRefusesWorldReadableKey(t *testing.T) {
	cert, key := writeCA(t, t.TempDir(), nil, 0o644)
	_, err := mitm.Load(mitm.Options{CertFile: cert, KeyFile: key})
	if err == nil {
		t.Fatal("a world readable signing key was accepted")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Fatalf("err = %v", err)
	}
}

// A certificate that cannot sign cannot be a signing CA, and finding
// that out per connection is finding it out too late.
func TestRefusesNonCA(t *testing.T) {
	cert, key := writeCA(t, t.TempDir(), func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageDigitalSignature
	}, 0o600)
	if _, err := mitm.Load(mitm.Options{CertFile: cert, KeyFile: key}); err == nil {
		t.Fatal("a leaf certificate was accepted as a CA")
	}
}

func TestRefusesExpiredCA(t *testing.T) {
	cert, key := writeCA(t, t.TempDir(), func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-time.Hour)
	}, 0o600)
	if _, err := mitm.Load(mitm.Options{CertFile: cert, KeyFile: key}); err == nil {
		t.Fatal("an expired CA was accepted")
	}
}

// An issued certificate is valid for the name asked for, chains to the
// CA, and carries the names the real certificate carried so a client
// checking another of them still finds it.
func TestIssues(t *testing.T) {
	ca := load(t)
	real := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "www.example.com"},
		DNSNames:    []string{"www.example.com", "example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.7")},
	}
	got, err := ca.Leaf("www.example.com", real)
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf == nil {
		t.Fatal("no parsed leaf")
	}
	for _, want := range []string{"www.example.com", "example.com"} {
		if err := got.Leaf.VerifyHostname(want); err != nil {
			t.Errorf("the forged certificate is not valid for %s: %v", want, err)
		}
	}
	if len(got.Certificate) != 2 {
		t.Fatalf("the chain has %d certificates, want the leaf and the CA", len(got.Certificate))
	}
	// It verifies against the CA a client would have been given.
	pool := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(got.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(caCert)
	if _, err := got.Leaf.Verify(x509.VerifyOptions{DNSName: "www.example.com", Roots: pool}); err != nil {
		t.Fatalf("the forged certificate does not verify against the CA: %v", err)
	}
	// It is short lived: a forged certificate that outlives the proxy
	// that made it is one somebody else can still be holding.
	if time.Until(got.Leaf.NotAfter) > 25*time.Hour {
		t.Errorf("valid until %v", got.Leaf.NotAfter)
	}
}

func TestIssuesForIPAddress(t *testing.T) {
	ca := load(t)
	got, err := ca.Leaf("192.0.2.9", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Leaf.VerifyHostname("192.0.2.9"); err != nil {
		t.Fatalf("not valid for the address: %v", err)
	}
}

// The cache is keyed on what the real certificate said, so a server
// that changes its names is not served from one built for the old ones.
func TestCacheFollowsTheRealCertificate(t *testing.T) {
	ca := load(t)
	first := &x509.Certificate{DNSNames: []string{"a.example.com"}, Raw: []byte("one")}
	second := &x509.Certificate{DNSNames: []string{"a.example.com", "b.example.com"}, Raw: []byte("two")}
	c1, err := ca.Leaf("a.example.com", first)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ca.Leaf("a.example.com", first)
	if err != nil {
		t.Fatal(err)
	}
	if c1 != again {
		t.Error("the same name and certificate were issued twice")
	}
	c2, err := ca.Leaf("a.example.com", second)
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 {
		t.Fatal("a changed certificate was served from the cache")
	}
	if err := c2.Leaf.VerifyHostname("b.example.com"); err != nil {
		t.Errorf("the new name is missing: %v", err)
	}
}

func TestCacheIsBounded(t *testing.T) {
	cert, key := writeCA(t, t.TempDir(), nil, 0o600)
	ca, err := mitm.Load(mitm.Options{CertFile: cert, KeyFile: key, MaxCache: 4})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err := ca.Leaf(string(rune('a'+i%26))+strconv.Itoa(i)+".example.com", nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := ca.Cached(); n > 4 {
		t.Fatalf("the cache holds %d, want at most 4", n)
	}
}

// A CONNECT tunnel does not have to carry TLS. What cannot be read as a
// ClientHello is passed through rather than answered with a handshake.
func TestClientHelloName(t *testing.T) {
	hello := helloFor(t, "www.example.com")
	name, ok := mitm.ClientHelloName(hello)
	if !ok {
		t.Fatal("a real ClientHello was not recognised")
	}
	if name != "www.example.com" {
		t.Fatalf("name = %q", name)
	}

	// A hello with no SNI is still a hello: the name is a bonus.
	noSNI := helloFor(t, "")
	if _, ok := mitm.ClientHelloName(noSNI); !ok {
		t.Error("a ClientHello without SNI was not recognised")
	}

	for name, b := range map[string][]byte{
		"empty":           {},
		"ssh":             []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"http":            []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"short":           {22, 3, 1},
		"not a handshake": {23, 3, 1, 0, 5, 1, 2, 3, 4, 5},
		"wrong hs type":   {22, 3, 1, 0, 5, 2, 0, 0, 1, 0},
	} {
		if _, ok := mitm.ClientHelloName(b); ok {
			t.Errorf("%s was read as a ClientHello", name)
		}
	}
}

// helloFor captures a real ClientHello from crypto/tls, so the parser
// is tested against what a client actually sends rather than against
// bytes this test invented.
func helloFor(t *testing.T, name string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := c2.Read(buf)
		done <- buf[:n]
		_ = c2.Close()
	}()
	cfg := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12} //nolint:gosec // no handshake completes
	if name == "" {
		cfg.InsecureSkipVerify = true //nolint:gosec // a ClientHello with no SNI is the point
	}
	_ = tls.Client(c1, cfg).Handshake()
	_ = c1.Close()
	select {
	case b := <-done:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello")
		return nil
	}
}
