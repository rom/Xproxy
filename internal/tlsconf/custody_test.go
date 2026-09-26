package tlsconf

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/testutil"
)

// A listener serves a certificate whose key came from a reference rather than a
// path, and it serves it in a real handshake: the point of the arrangement is
// that a key held in a vault is as usable as one on the disk, so a test that
// only checked the load would miss the half that matters.
func TestAKeyFromAReferenceServesAHandshake(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "ref.test")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XPROXY_TEST_EDGE_KEY", string(keyPEM))
	res := keysource.New(nil, 0, nil)

	cfg := &config.TLS{
		Certificates: []config.Certificate{{CertFile: certPath, Key: "env:XPROXY_TEST_EDGE_KEY"}},
		MinVersion:   "1.3",
		ClientAuth:   "none",
	}
	tc, _, err := Server(cfg, []config.Protocol{config.ProtocolH1}, WithSecrets(res))
	if err != nil {
		t.Fatal(err)
	}
	// A handshake over a pipe, so the certificate's key is actually used to
	// sign rather than merely parsed.
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	errc := make(chan error, 1)
	go func() {
		s := tls.Server(server, tc)
		errc <- s.Handshake()
	}()
	c := tls.Client(client, &tls.Config{ServerName: "ref.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // the certificate is generated for this test and never leaves the process
	if err := c.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if got := c.ConnectionState().PeerCertificates[0].Subject.CommonName; got != "ref.test" {
		t.Errorf("served %q", got)
	}
}

// What a reference cannot do, and what the error says when it cannot.
//
// The rule the whole package turns on is in the last case: an error names the
// reference and never the material. A key in a log line is a key in the log
// archive, in the SIEM and in whatever the SIEM is backed up to.
func TestWhenAReferencedKeyCannotBeServed(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "ref.test")
	otherCert, otherKey := testutil.WriteCert(t, dir, "other.test")
	_ = otherCert
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := os.ReadFile(otherKey)
	if err != nil {
		t.Fatal(err)
	}

	// No resolver at all: a reference is an error rather than a path, so a
	// typo in a scheme cannot become a file nobody meant.
	cfg := &config.TLS{Certificates: []config.Certificate{{CertFile: certPath, Key: "env:WHATEVER"}}, MinVersion: "1.3"}
	_, _, err = Server(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "no secret resolver is configured") {
		t.Errorf("error %v, want a missing resolver", err)
	}

	// A reference that resolves to nothing.
	t.Setenv("XPROXY_TEST_EMPTY", "")
	cfg = &config.TLS{Certificates: []config.Certificate{{CertFile: certPath, Key: "env:XPROXY_TEST_EMPTY"}}, MinVersion: "1.3"}
	if _, _, err := Server(cfg, nil, WithSecrets(keysource.New(nil, 0, nil))); err == nil {
		t.Error("an empty reference was accepted")
	}

	// A reference that resolves to the wrong key: caught at load, and the
	// error names the certificate and the reference.
	t.Setenv("XPROXY_TEST_WRONG", string(otherPEM))
	cfg = &config.TLS{Certificates: []config.Certificate{{CertFile: certPath, Key: "env:XPROXY_TEST_WRONG"}}, MinVersion: "1.3"}
	_, _, err = Server(cfg, nil, WithSecrets(keysource.New(nil, 0, nil)))
	if err == nil {
		t.Fatal("a key that does not match the certificate was accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "env:XPROXY_TEST_WRONG") {
		t.Errorf("error %q does not name the reference", msg)
	}
	// The material itself must not be anywhere in it. Both keys are checked:
	// the one that was resolved and the one that was expected.
	for _, secret := range []string{string(otherPEM), string(keyPEM)} {
		for _, line := range strings.Split(strings.TrimSpace(secret), "\n") {
			if strings.HasPrefix(line, "-----") || len(line) < 16 {
				continue
			}
			if strings.Contains(msg, line) {
				t.Fatalf("the error carries key material: %q", msg)
			}
		}
	}
}

// A signer that is not there fails the load, and says it was the signer. The
// alternative is a listener that comes up and then fails every handshake, which
// looks to everyone else like the listener being down.
func TestAnAbsentSignerFailsTheLoad(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := testutil.WriteCert(t, dir, "hsm.test")
	cfg := &config.TLS{
		Certificates: []config.Certificate{{
			CertFile: certPath,
			Signer:   &config.CertSigner{Socket: filepath.Join(dir, "absent.sock"), Key: "edge"},
		}},
		MinVersion: "1.3",
	}
	_, _, err := Server(cfg, nil)
	if err == nil {
		t.Fatal("a certificate whose signer is not running was accepted")
	}
	if !strings.Contains(err.Error(), "signer") {
		t.Errorf("error %q does not say it was the signer", err)
	}
}

// A key rotated at its source reaches a listener that is already serving,
// without a reload.
//
// This is the property the whole vault arrangement is bought for, and it is not
// implied by the load path: a certificate is read once at load, so without a
// refresh a rotated key would reach the listener only at the next reload. The
// test drives it the only way that proves anything -- serve, rotate, refresh,
// and check that the certificate a handshake now gets is the new one.
func TestARotatedKeyReachesAServingListener(t *testing.T) {
	dir := t.TempDir()
	firstCert, firstKey := testutil.WriteCert(t, dir, "rotate.test")
	keyPEM, err := os.ReadFile(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XPROXY_TEST_ROTATE", string(keyPEM))

	cfg := &config.TLS{
		Certificates: []config.Certificate{{CertFile: firstCert, Key: "env:XPROXY_TEST_ROTATE"}},
		MinVersion:   "1.3",
	}
	// A real deployment always has a TTL: validation bounds refresh_interval
	// to 1m..24h and it defaults to 5m. The clock is driven by hand so the
	// test does not wait for one.
	now := time.Now()
	res := keysource.New(nil, 5*time.Minute, nil)
	res.SetClockForTest(func() time.Time { return now })
	_, rl, err := Server(cfg, nil, WithSecrets(res))
	if err != nil {
		t.Fatal(err)
	}
	if !rl.HasReferencedKeys() {
		t.Fatal("the listener does not know its key is a reference")
	}
	before := servedSerial(t, rl)

	// Nothing has changed yet: a refresh must be a no-op rather than a
	// reload, or every interval would rebuild every certificate.
	if changed, err := rl.RefreshSecrets(); err != nil || changed {
		t.Fatalf("an unchanged reference reported changed=%v err=%v", changed, err)
	}
	if servedSerial(t, rl) != before {
		t.Error("an unchanged reference replaced the certificate")
	}

	// Rotate: a new certificate and key at the same reference.
	secondCert, secondKey := testutil.WriteCert(t, dir, "rotate2.test")
	newKey, err := os.ReadFile(secondKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XPROXY_TEST_ROTATE", string(newKey))
	cfg.Certificates[0].CertFile = secondCert

	// Inside the TTL the resolver answers from its cache, which is the point
	// of the TTL: the source is not this proxy's hot path. So a refresh now
	// must still be a no-op, and only once the TTL has passed does the
	// rotation arrive.
	if changed, err := rl.RefreshSecrets(); err != nil || changed {
		t.Fatalf("a rotation inside the TTL was picked up early: changed=%v err=%v", changed, err)
	}
	now = now.Add(6 * time.Minute)

	changed, err := rl.RefreshSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("a rotated key was not noticed")
	}
	if after := servedSerial(t, rl); after == before {
		t.Error("the rotated key did not reach the served certificate")
	}
}

// servedSerial is the serial of the certificate a handshake would get now.
func servedSerial(t *testing.T, rl *Reloadable) string {
	t.Helper()
	cert, err := rl.getCertificate(&tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		t.Fatal("no leaf")
	}
	return cert.Leaf.SerialNumber.String()
}

// A source that goes away leaves the certificate in force and says so.
//
// The resolver absorbs the failure itself: it keeps the value it has, marks the
// reference stale and warns once. So the refresh sees no change rather than an
// error, and the listener keeps serving -- which is the whole rule. A vault that
// is down must not take a TLS key away from a proxy that is already serving
// with it, because otherwise an outage of something else becomes an outage of
// this.
//
// What the operator gets instead is the stale list, which is why this test
// asserts it: a proxy serving material it could not confirm is fine, and a proxy
// doing that silently is not.
func TestAFailedRefreshKeepsTheCertificateInForce(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "keep.test")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XPROXY_TEST_KEEP", string(keyPEM))

	now := time.Now()
	res := keysource.New(nil, 5*time.Minute, nil)
	res.SetClockForTest(func() time.Time { return now })
	cfg := &config.TLS{
		Certificates: []config.Certificate{{CertFile: certPath, Key: "env:XPROXY_TEST_KEEP"}},
		MinVersion:   "1.3",
	}
	_, rl, err := Server(cfg, nil, WithSecrets(res))
	if err != nil {
		t.Fatal(err)
	}
	before := servedSerial(t, rl)

	// The source goes away, and the TTL passes so the resolver actually asks.
	t.Setenv("XPROXY_TEST_KEEP", "")
	now = now.Add(6 * time.Minute)

	changed, err := rl.RefreshSecrets()
	if err != nil {
		t.Fatalf("a source that went away failed the refresh: %v", err)
	}
	if changed {
		t.Error("a failed refresh reported a rotation")
	}
	if after := servedSerial(t, rl); after != before {
		t.Errorf("a failed refresh replaced the certificate: %s -> %s", before, after)
	}
	stale := res.Stale()
	if len(stale) != 1 || stale[0] != "env:XPROXY_TEST_KEEP" {
		t.Errorf("stale references %v, want the one that stopped resolving", stale)
	}
}

// And the case the branch above cannot reach: a reference that never resolved.
// There is no previous value to keep, so the refresh fails and the certificates
// are left as they are rather than replaced with nothing.
func TestARefreshThatNeverResolvedFails(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "never.test")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XPROXY_TEST_NEVER", string(keyPEM))
	res := keysource.New(nil, time.Minute, nil)
	cfg := &config.TLS{
		Certificates: []config.Certificate{{CertFile: certPath, Key: "env:XPROXY_TEST_NEVER"}},
		MinVersion:   "1.3",
	}
	_, rl, err := Server(cfg, nil, WithSecrets(res))
	if err != nil {
		t.Fatal(err)
	}
	before := servedSerial(t, rl)
	// A second certificate whose reference has never resolved: appended after
	// the load, so the resolver holds nothing for it.
	rl.cfgs = append(rl.cfgs, config.Certificate{CertFile: certPath, Key: "env:XPROXY_TEST_ABSENT"})
	changed, err := rl.RefreshSecrets()
	if err == nil {
		t.Fatal("a reference that has never resolved was accepted")
	}
	if changed {
		t.Error("a failed refresh reported a rotation")
	}
	if after := servedSerial(t, rl); after != before {
		t.Errorf("a failed refresh replaced the certificate: %s -> %s", before, after)
	}
}
