package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// writeCertUntil writes a certificate that stops being valid at a chosen
// moment, which is the whole point of these tests: the ordinary test
// helper writes one valid for an hour, and an hour is never the interesting
// case.
func writeCertUntil(t testing.TB, dir, host string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	certPath = filepath.Join(dir, host+".pem")
	keyPath = filepath.Join(dir, host+"-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// An expired certificate is a load error with refuse_expired, and the
// message names the file rather than the subject: the operator has to
// find the file to replace it.
func TestAnExpiredCertificateIsRefusedAtLoad(t *testing.T) {
	dir := t.TempDir()
	cp, kp := writeCertUntil(t, dir, "stale.test", time.Now().Add(-time.Hour))
	cfg := &config.TLS{Certificates: []config.Certificate{{CertFile: cp, KeyFile: kp}}}

	// Without the section it is served, because serving one is not a
	// security hole: the client decides whether to trust it.
	if _, _, err := Server(cfg, nil); err != nil {
		t.Fatalf("an expired certificate without a policy: %v", err)
	}
	// With it, the listener does not start.
	cfg.Expiry = &config.CertExpiry{RefuseExpired: true}
	_, _, err := Server(cfg, nil)
	if err == nil {
		t.Fatal("an expired certificate loaded with refuse_expired")
	}
	if !strings.Contains(err.Error(), cp) || !strings.Contains(err.Error(), "expired") {
		t.Errorf("the message should name the file: %v", err)
	}
}

// A certificate that is still valid loads, and a reload that would install
// an expired one is refused while the old one keeps working: this is the
// case where refusing is strictly better than serving.
func TestAReloadCannotInstallAnExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	cp, kp := writeCertUntil(t, dir, "live.test", time.Now().Add(48*time.Hour))
	cfg := &config.TLS{Certificates: []config.Certificate{{CertFile: cp, KeyFile: kp}},
		Expiry: &config.CertExpiry{RefuseExpired: true}}
	_, r, err := Server(cfg, nil)
	if err != nil {
		t.Fatalf("a valid certificate: %v", err)
	}
	before := r.NotAfter()

	// The file is replaced by an expired certificate, as a botched
	// renewal would.
	_, _ = writeCertUntil(t, dir, "live.test", time.Now().Add(-time.Minute))
	if err := r.Load(); err == nil {
		t.Fatal("the reload installed an expired certificate")
	}
	// And the certificate in use is untouched, which is the point.
	if got := r.NotAfter(); !got.Equal(before) {
		t.Errorf("the served certificate changed: %s then %s", before, got)
	}
}

// The warning is not a refusal: a certificate inside the window, and one
// that has expired under a running proxy, are reported worst first and go
// on being served.
func TestExpiryWarningsAreReportedWorstFirst(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	c1, k1 := writeCertUntil(t, dir, "soon.test", now.Add(3*24*time.Hour))
	c2, k2 := writeCertUntil(t, dir, "sooner.test", now.Add(24*time.Hour))
	c3, k3 := writeCertUntil(t, dir, "fine.test", now.Add(90*24*time.Hour))
	cfg := &config.TLS{Certificates: []config.Certificate{
		{CertFile: c1, KeyFile: k1}, {CertFile: c2, KeyFile: k2}, {CertFile: c3, KeyFile: k3}},
		Expiry: &config.CertExpiry{Warn: config.Duration(14 * 24 * time.Hour)}}
	_, r, err := Server(cfg, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := r.Expiring(now)
	if len(got) != 2 {
		t.Fatalf("expiring %v", got)
	}
	if !strings.Contains(got[0], "sooner.test") || !strings.Contains(got[1], "soon.test") {
		t.Errorf("worst first: %v", got)
	}
	// A time past both is two expiries, and neither is a refusal.
	got = r.Expiring(now.Add(7 * 24 * time.Hour))
	if len(got) != 2 || !strings.Contains(got[0], "expired on") {
		t.Errorf("after both: %v", got)
	}
	// Without a window there is nothing to report, whatever the dates --
	// both for a listener with no section at all and for one that asked
	// only for the refusal. warn: 0 means no warning, and a refusal is
	// not a warning.
	// The certificate used here has already expired, which is the case
	// that tells warn: 0 apart from a window that happens to exclude
	// everything: without a window even an expired certificate is not
	// reported, because reporting is what warn asks for and refusing is
	// a different question.
	cg, kg := writeCertUntil(t, dir, "gone.test", now.Add(-time.Hour))
	for what, cfg := range map[string]*config.TLS{
		"no section": {Certificates: []config.Certificate{{CertFile: cg, KeyFile: kg}}},
		"a section that asks for nothing": {Certificates: []config.Certificate{{CertFile: cg, KeyFile: kg}},
			Expiry: &config.CertExpiry{}},
	} {
		_, r2, err := Server(cfg, nil)
		if err != nil {
			t.Fatalf("%s: load: %v", what, err)
		}
		if got := r2.Expiring(now); got != nil {
			t.Errorf("%s reported %v", what, got)
		}
	}
}
