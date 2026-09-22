package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
	"golang.org/x/crypto/ocsp"
)

// TestOCSPStapledHandshake: a TLS listener with ocsp_stapling serves the
// responder's answer in the handshake and reports it through
// Certificates.
func TestOCSPStapledHandshake(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		der, _ := ocsp.CreateResponse(ca.Cert, ca.Cert, ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber,
			ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}, ca.Key)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}))
	t.Cleanup(responder.Close)
	// A leaf naming the responder, with the issuer in the chain file.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "staple.test"}, DNSNames: []string{"staple.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, OCSPServer: []string{responder.URL}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "leaf-key.pem")
	_ = os.WriteFile(certPath, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.CertPEM...), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)

	backend := newBackend(t, "a")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
        ocsp_stapling: {timeout: 2s}
        ct: {require: 1}
logging: {access: {enabled: false}}
upstreams:
  - name: app
    endpoints: [{address: %s}]
routes:
  - name: all
    upstream: app
`, certPath, keyPath, backend.addr())
	s, _ := startServer(t, yaml)
	addr := s.Addrs()["main"]
	deadline := time.Now().Add(5 * time.Second)
	var staple []byte
	for time.Now().Before(deadline) && staple == nil {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "staple.test"}) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		staple = conn.ConnectionState().OCSPResponse
		_ = conn.Close()
		if staple == nil {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if staple == nil {
		t.Fatalf("no staple in the handshake: %+v", s.Certificates())
	}
	parsed, err := ocsp.ParseResponseForCert(staple, nil, ca.Cert)
	if err != nil || parsed.Status != ocsp.Good || parsed.SerialNumber.Int64() != 77 {
		t.Fatalf("staple: %v %+v", err, parsed)
	}
	certs := s.Certificates()["main"]
	if len(certs) != 1 || certs[0].OCSP.Status != "good" || certs[0].Names[0] != "staple.test" || certs[0].Managed {
		t.Fatalf("certificates: %+v", certs)
	}
	// The CT policy (require 1, report only) flags the unlogged test
	// certificate without refusing it.
	if certs[0].CT.OK || certs[0].CT.Embedded != 0 || certs[0].CT.Required != 1 {
		t.Fatalf("ct: %+v", certs[0].CT)
	}
}
