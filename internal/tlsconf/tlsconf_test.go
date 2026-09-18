package tlsconf

import (
	"crypto/tls"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

func TestServer(t *testing.T) {
	dir := t.TempDir()
	c1, k1 := testutil.WriteCert(t, dir, "a.test")
	c2, k2 := testutil.WriteCert(t, dir, "b.test")
	cfg := &config.TLS{Certificates: []config.Certificate{{CertFile: c1, KeyFile: k1}, {CertFile: c2, KeyFile: k2}}, MinVersion: "1.2", ClientAuth: "none"}
	tc, r, err := Server(cfg, []config.Protocol{config.ProtocolH1, config.ProtocolH2})
	if err != nil {
		t.Fatal(err)
	}
	if tc.MinVersion != tls.VersionTLS12 || tc.Renegotiation != tls.RenegotiateNever {
		t.Fatal("hardening defaults")
	}
	cert, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.test", SupportedVersions: []uint16{tls.VersionTLS13}, CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}, SupportedCurves: []tls.CurveID{tls.X25519, tls.CurveP256}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.Subject.CommonName != "b.test" {
		t.Fatalf("SNI selected %s", cert.Leaf.Subject.CommonName)
	}
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	if len(tc.NextProtos) != 2 {
		t.Fatal("alpn")
	}
	cfg.CipherSuites = []string{"TLS_RSA_WITH_RC4_128_SHA"}
	if _, _, err := Server(cfg, nil); err == nil {
		t.Fatal("insecure suite accepted")
	}
}

func TestClient(t *testing.T) {
	tc, _, err := Client(&config.UpstreamTLS{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if tc.InsecureSkipVerify {
		t.Fatal("insecure without allow_insecure")
	}
	tc, _, _ = Client(&config.UpstreamTLS{InsecureSkipVerify: true, AllowInsecure: true})
	if !tc.InsecureSkipVerify {
		t.Fatal("double opt-in not honoured")
	}
	tc, _, _ = Client(&config.UpstreamTLS{MinVersion: "1.3"})
	if tc.MinVersion != tls.VersionTLS13 {
		t.Fatal("min version")
	}
	dir := t.TempDir()
	cp, kp := testutil.WriteCert(t, dir, "client.test")
	tc, rl, err := Client(&config.UpstreamTLS{ClientCertFile: cp, ClientKeyFile: kp})
	if err != nil || rl == nil || tc.GetClientCertificate == nil {
		t.Fatalf("client cert: %v", err)
	}
	c, _ := tc.GetClientCertificate(nil)
	if len(c.Certificate) == 0 {
		t.Fatal("no client certificate served")
	}
	if err := rl.Load(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Client(&config.UpstreamTLS{SPKIPins: []string{"nope"}}); err == nil {
		t.Fatal("bad pin accepted")
	}
}
