package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/acme/acmetest"
	"github.com/rom/xproxy/internal/acme/jose"
	"github.com/rom/xproxy/internal/config"
)

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestJWSRoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, err := jose.Sign(key, "", "n1", "https://ca/x", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	h, p, err := jose.Verify(raw, &key.PublicKey)
	if err != nil || h["nonce"] != "n1" || h["url"] != "https://ca/x" || string(p) != `{"a":1}` {
		t.Fatalf("verify: %v %v %s", err, h, p)
	}
	j := h["jwk"].(map[string]any)
	pub, err := jose.PublicKeyFromJWK(j)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatal("jwk round trip")
	}
	// kid form and POST-as-GET.
	raw, _ = jose.Sign(key, "https://ca/acct/1", "n2", "https://ca/y", nil)
	h, p, err = jose.Verify(raw, &key.PublicKey)
	if err != nil || h["kid"] != "https://ca/acct/1" || len(p) != 0 {
		t.Fatal("kid form")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, _, err := jose.Verify(raw, &other.PublicKey); err == nil {
		t.Fatal("wrong key accepted")
	}
	if len(jose.Thumbprint(&key.PublicKey)) != 43 || !strings.HasPrefix(jose.KeyAuthorization("tok", &key.PublicKey), "tok.") {
		t.Fatal("thumbprint")
	}
}

// holder lets the challenge listeners follow whichever manager a test is
// currently exercising.
type holder struct{ p atomic.Pointer[Manager] }

func (h *holder) set(m *Manager) { h.p.Store(m) }

// challengeServer serves http-01 and tls-alpn-01 from a manager the way
// the proxy does, on loopback listeners.
func challengeServer(t *testing.T, h *holder) (httpAddr, tlsAddr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := h.p.Load(); m != nil && strings.HasPrefix(r.URL.Path, HTTP01Path) {
			if ka, ok := m.HTTP01(strings.TrimPrefix(r.URL.Path, HTTP01Path)); ok {
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, ka)
				return
			}
		}
		http.NotFound(w, r)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	tc := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{ALPNProto, "http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		m := h.p.Load()
		if m == nil {
			return nil, io.EOF
		}
		for _, p := range hello.SupportedProtos {
			if p == ALPNProto {
				if c, ok := m.TLSALPN01(hello.ServerName); ok {
					return c, nil
				}
			}
		}
		certs := m.Certificates()
		if len(certs) > 0 {
			return &certs[0], nil
		}
		return nil, io.EOF
	}}
	tln, err := tls.Listen("tcp", "127.0.0.1:0", tc)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	t.Cleanup(func() { tln.Close() })
	return ln.Addr().String(), tln.Addr().String()
}

func manager(t *testing.T, ca *acmetest.CA, dir, challenge string, groups [][]string) *Manager {
	t.Helper()
	cfg := config.ACME{Directory: ca.Directory(), Email: "ops@example.test", AcceptTerms: true, CAFile: ca.CAPath, StateDir: filepath.Join(dir, "state"),
		Challenge: challenge, RenewBefore: config.Duration(30 * 24 * time.Hour), CheckInterval: config.Duration(time.Hour)}
	m, err := New(cfg, groups, nolog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	return m
}

func TestIssueHTTP01AndRenew(t *testing.T) {
	dir := t.TempDir()
	ca := acmetest.New(t, dir)
	m := manager(t, ca, dir, "http-01", [][]string{{"www.example.test", "example.test"}, {"api.example.test"}})
	h := &holder{}
	h.set(m)
	httpAddr, tlsAddr := challengeServer(t, h)
	ca.HTTPTarget, ca.TLSTarget = httpAddr, tlsAddr
	changes := 0
	m.OnChange(func() { changes++ })

	if st := m.Status(); len(st) != 2 || st[0].Present || st[1].Present {
		t.Fatalf("initial status %+v", st)
	}
	if err := m.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	certs := m.Certificates()
	if len(certs) != 2 || ca.IssuedCount() != 2 || changes < 2 {
		t.Fatalf("issued %d certs, ca issued %d, changes %d", len(certs), ca.IssuedCount(), changes)
	}
	// The certificate covers all group hosts and chains to the CA.
	opts := x509.VerifyOptions{Roots: ca.IssuerPool(), DNSName: "example.test"}
	var www *tls.Certificate
	for i := range certs {
		if certs[i].Leaf.Subject.CommonName == "www.example.test" {
			www = &certs[i]
		}
	}
	if www == nil {
		t.Fatal("www cert missing")
	}
	if _, err := www.Leaf.Verify(opts); err != nil {
		t.Fatalf("chain: %v", err)
	}
	// Persisted: a new manager over the same state dir loads them without
	// contacting the CA, and reuses the account.
	m2 := manager(t, ca, dir, "http-01", [][]string{{"www.example.test", "example.test"}, {"api.example.test"}})
	h.set(m2)
	if len(m2.Certificates()) != 2 || m2.client.KID() == "" {
		t.Fatal("certificates or account not loaded from disk")
	}
	// Not due: check does nothing.
	m2.check()
	if ca.IssuedCount() != 2 {
		t.Fatal("renewed a certificate that was not due")
	}
	// Due: shift the clock past renew_before.
	m2.now = func() time.Time { return time.Now().Add(70 * 24 * time.Hour) }
	m2.check()
	if ca.IssuedCount() != 4 {
		t.Fatalf("renewal did not happen: ca issued %d", ca.IssuedCount())
	}
	st := m2.Status()
	if st[0].Issued != 1 || st[0].LastError != "" || st[0].Issuer != "acmetest CA" {
		t.Fatalf("status %+v", st)
	}
	// Files on disk are private.
	fi, _ := os.Stat(filepath.Join(dir, "state", "certs", "api.example.test-key.pem"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", fi.Mode().Perm())
	}
}

func TestIssueTLSALPN01(t *testing.T) {
	dir := t.TempDir()
	ca := acmetest.New(t, dir)
	m := manager(t, ca, dir, "tls-alpn-01", [][]string{{"alpn.example.test"}})
	h := &holder{}
	h.set(m)
	httpAddr, tlsAddr := challengeServer(t, h)
	ca.HTTPTarget, ca.TLSTarget = httpAddr, tlsAddr
	if err := m.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(m.Certificates()) != 1 {
		t.Fatal("no certificate")
	}
	// Challenge material is removed after validation.
	if _, ok := m.TLSALPN01("alpn.example.test"); ok {
		t.Fatal("alpn certificate left behind")
	}
}

func TestFailures(t *testing.T) {
	dir := t.TempDir()
	ca := acmetest.New(t, dir)
	m := manager(t, ca, dir, "http-01", [][]string{{"nowhere.example.test"}})
	// No challenge server: validation fails, error is recorded, no cert.
	err := m.Renew(context.Background())
	if err == nil {
		t.Fatal("expected failure")
	}
	st := m.Status()
	if st[0].Present || st[0].LastError == "" {
		t.Fatalf("status %+v", st)
	}
	// Back-off: check does not retry within the hour.
	before := ca.IssuedCount()
	m.check()
	if ca.IssuedCount() != before {
		t.Fatal("retried during back-off")
	}
	// Bad account key file.
	os.WriteFile(filepath.Join(dir, "state", "account.key"), []byte("junk"), 0o600)
	if _, err := New(config.ACME{Directory: ca.Directory(), AcceptTerms: true, CAFile: ca.CAPath, StateDir: filepath.Join(dir, "state"), Challenge: "http-01", RenewBefore: config.Duration(time.Hour), CheckInterval: config.Duration(time.Hour)}, nil, nolog); err == nil {
		t.Fatal("junk account key accepted")
	}
	// Unpinned CA: the directory fetch fails.
	m3, err := New(config.ACME{Directory: ca.Directory(), AcceptTerms: true, StateDir: filepath.Join(dir, "state2"), Challenge: "http-01", RenewBefore: config.Duration(time.Hour), CheckInterval: config.Duration(time.Hour)}, [][]string{{"x.example.test"}}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if err := m3.Renew(context.Background()); err == nil {
		t.Fatal("unpinned CA accepted")
	}
	var probe map[string]any
	_ = json.Unmarshal([]byte(`{}`), &probe)
}
