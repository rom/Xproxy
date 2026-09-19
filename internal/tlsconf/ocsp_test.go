package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

// issueWithOCSP writes a leaf naming responder as its OCSP server, with
// the issuer appended to the chain file.
func issueWithOCSP(t *testing.T, ca *testutil.CA, dir, name, responder string, extra ...pkix.Extension) (certPath, keyPath string, leaf *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: name},
		DNSNames:        []string{name},
		IPAddresses:     []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: extra,
	}
	if responder != "" {
		tmpl.OCSPServer = []string{responder}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	kd, _ := x509.MarshalECPrivateKey(key)
	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.CertPEM...)
	if err := os.WriteFile(certPath, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, leaf
}

// fakeResponder answers OCSP requests for one CA with the chosen status.
type fakeResponder struct {
	srv    *httptest.Server
	status atomic.Int32 // ocsp.Good, ocsp.Revoked, or -1 for HTTP 500
	hits   atomic.Int64
}

func newResponder(t *testing.T, ca *testutil.CA) *fakeResponder {
	t.Helper()
	fr := &fakeResponder{}
	fr.status.Store(int32(ocsp.Good))
	fr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil || r.Header.Get("Content-Type") != "application/ocsp-request" {
			w.WriteHeader(400)
			return
		}
		st := int(fr.status.Load())
		if st < 0 {
			w.WriteHeader(500)
			return
		}
		tmpl := ocsp.Response{Status: st, SerialNumber: req.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(2 * time.Hour)}
		if st == ocsp.Revoked {
			tmpl.RevokedAt = time.Now().Add(-time.Minute)
			tmpl.RevocationReason = ocsp.KeyCompromise
		}
		der, err := ocsp.CreateResponse(ca.Cert, ca.Cert, tmpl, ca.Key)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}))
	t.Cleanup(fr.srv.Close)
	return fr
}

func waitOCSP(t *testing.T, rl *Reloadable, want string) CertInfo {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if certs := rl.Certificates(); len(certs) == 1 && certs[0].OCSP.Status == want {
			return certs[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("staple never reached %q: %+v", want, rl.Certificates())
	return CertInfo{}
}

func TestOCSPStapling(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	fr := newResponder(t, ca)
	certPath, keyPath, _ := issueWithOCSP(t, ca, dir, "www.test", fr.srv.URL)
	on := true
	cfg := &config.TLS{Certificates: []config.Certificate{{CertFile: certPath, KeyFile: keyPath}},
		OCSPStapling: &config.OCSPStapling{Enabled: &on, Timeout: config.Duration(2 * time.Second), Refresh: config.Duration(time.Hour)}}
	tc, rl, err := Server(cfg, []config.Protocol{config.ProtocolH1})
	if err != nil {
		t.Fatal(err)
	}
	// Before stapling starts the handshake carries no staple.
	if c, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "www.test"}); err != nil || c.OCSPStaple != nil {
		t.Fatalf("staple before start: %v %v", err, c)
	}
	rl.StartStapling(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rl.Close()
	info := waitOCSP(t, rl, "good")
	if info.OCSP.Responder != fr.srv.URL || info.OCSP.NextUpdate.Before(time.Now()) || info.OCSP.Error != "" || !info.CT.OK || info.CT.Embedded != 0 {
		t.Fatalf("info %+v", info)
	}
	c, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "www.test"})
	if err != nil || len(c.OCSPStaple) == 0 {
		t.Fatalf("staple missing: %v", err)
	}
	parsed, err := ocsp.ParseResponseForCert(c.OCSPStaple, c.Leaf, ca.Cert)
	if err != nil || parsed.Status != ocsp.Good {
		t.Fatalf("staple content: %v %v", err, parsed)
	}
	// The stored certificate is untouched; the staple travels on a copy.
	if (*rl.certs.Load())[0].OCSPStaple != nil {
		t.Fatal("staple written into the shared certificate")
	}
	// A failing responder keeps the valid staple and records the error.
	fr.status.Store(-1)
	rl.stapler.refreshAll()
	// Not due yet, so no fetch happened; force by clearing the fetched time.
	rl.stapler.mu.Lock()
	for _, st := range rl.stapler.staples {
		st.fetched = time.Time{}
	}
	rl.stapler.mu.Unlock()
	rl.stapler.refreshAll()
	info = rl.Certificates()[0]
	if info.OCSP.Status != "good" || info.OCSP.Error == "" {
		t.Fatalf("after responder failure: %+v", info.OCSP)
	}
	if c, _ := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "www.test"}); len(c.OCSPStaple) == 0 {
		t.Fatal("valid staple dropped on a fetch failure")
	}
	// A revoked answer is stapled too (clients must learn about it).
	fr.status.Store(int32(ocsp.Revoked))
	rl.stapler.mu.Lock()
	for _, st := range rl.stapler.staples {
		st.fetched = time.Time{}
		st.err = ""
	}
	rl.stapler.mu.Unlock()
	rl.stapler.refreshAll()
	if info := rl.Certificates()[0]; info.OCSP.Status != "revoked" {
		t.Fatalf("revoked: %+v", info.OCSP)
	}
	// A certificate without a responder or without its issuer is reported.
	c2, k2, _ := issueWithOCSP(t, ca, dir, "plain.test", "")
	rl2 := &Reloadable{cfgs: []config.Certificate{{CertFile: c2, KeyFile: k2}}, ocsp: cfg.OCSPStapling}
	if err := rl2.Load(); err != nil {
		t.Fatal(err)
	}
	rl2.stapler = newStapler(*cfg.OCSPStapling, rl2.allCertificates, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rl2.stapler.refreshAll()
	if info := rl2.Certificates()[0]; info.OCSP.Status != "none" {
		t.Fatalf("no responder: %+v", info.OCSP)
	}
}
