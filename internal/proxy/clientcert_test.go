package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/testutil"
)

func TestClientCertificateIdentity(t *testing.T) {
	a, b := newBackend(t, "a"), newBackend(t, "b")
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	srvCert, srvKey := ca.Issue(t, dir, "edge.test")
	aliceCert, aliceKey := ca.Issue(t, dir, "alice")
	bobCert, bobKey := ca.Issue(t, dir, "bob")
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
        client_auth: require
        client_ca_file: %s
upstreams:
  - {name: a, endpoints: [{address: "%s"}]}
  - {name: b, endpoints: [{address: "%s"}]}
routes:
  - name: alice
    paths: ["/"]
    when: 'cert("cn") == "alice"'
    upstream: a
    request_headers:
      set:
        X-Client-CN: "${cert:cn}"
        X-Client-Fingerprint: "${cert:fingerprint}"
        X-Forwarded-Client-Cert: "${cert:xfcc}"
  - name: others
    paths: ["/"]
    upstream: b
    request_headers:
      set: {X-Client-Subject: "${cert:subject}", X-Client-Serial: "${cert:serial}"}
`
	s, _ := startServer(t, fmt.Sprintf(yaml, srvCert, srvKey, ca.Path, a.addr(), b.addr()))
	addr := s.Addrs()["main"]
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	fetch := func(certFile, keyFile string) (string, error) {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return "", err
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "edge.test", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}}
		req, _ := http.NewRequest("GET", "https://"+addr+"/x", nil)
		req.Header.Set("X-Client-CN", "spoofed") // overwritten by the route
		resp, err := c.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body), nil
	}
	body, err := fetch(aliceCert, aliceKey)
	if err != nil || body != "a:/x" {
		t.Fatalf("alice: %q %v", body, err)
	}
	h := a.last.Load().Header
	if h.Get("X-Client-CN") != "alice" || len(h.Get("X-Client-Fingerprint")) != 64 {
		t.Fatalf("alice headers: %v", h)
	}
	if xfcc := h.Get("X-Forwarded-Client-Cert"); !strings.HasPrefix(xfcc, "Hash=") || !strings.Contains(xfcc, `Subject="CN=alice`) {
		t.Fatalf("xfcc: %q", xfcc)
	}
	body, err = fetch(bobCert, bobKey)
	if err != nil || body != "b:/x" {
		t.Fatalf("bob: %q %v", body, err)
	}
	h = b.last.Load().Header
	if !strings.Contains(h.Get("X-Client-Subject"), "CN=bob") || h.Get("X-Client-Serial") == "" {
		t.Fatalf("bob headers: %v", h)
	}
}
