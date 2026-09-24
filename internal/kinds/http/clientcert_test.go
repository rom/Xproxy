package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

// The backend cannot tell the proxy's identity header from the client's:
// they are the same bytes in the same field. A request carrying its own
// is a request choosing its own identity, so every one of these names is
// removed -- on a plaintext listener where there is no certificate at all,
// which is the case where a forged header would otherwise be the only
// thing the backend ever sees.
func TestAClientMayNotSendItsOwnCertificateIdentity(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams: [{name: a, endpoints: [{address: "%s"}]}]
routes: [{name: r, paths: ["/"], upstream: a}]
`
	s, _ := startServer(t, fmt.Sprintf(yaml, a.addr()))
	addr := s.Addrs()["main"]
	req, _ := http.NewRequest("GET", "http://"+addr+"/x", nil)
	for _, name := range clientCertHeaders {
		req.Header.Set(name, "forged")
	}
	// A header that is not one of them, to prove this is a list and not a
	// filter on everything.
	req.Header.Set("X-Client-Trace", "keep-me")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	h := a.last.Load().Header
	for _, name := range clientCertHeaders {
		if got := h.Get(name); got != "" {
			t.Errorf("%s reached the backend as %q", name, got)
		}
	}
	if h.Get("X-Client-Trace") != "keep-me" {
		t.Errorf("an unrelated header was removed: %v", h)
	}
}

// RFC 9440: the leaf in Client-Cert and the rest of the chain in
// Client-Cert-Chain, each as a Structured Fields Byte Sequence. The
// assertion is that the bytes parse back into the certificate the client
// actually presented, because a header the backend cannot decode is a
// header that says nothing.
func TestRFC9440StatesTheCertificateTheClientPresented(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	srvCert, srvKey := ca.Issue(t, dir, "edge.test")
	aliceCert, aliceKey := ca.Issue(t, dir, "alice")
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
upstreams: [{name: a, endpoints: [{address: "%s"}]}]
routes:
  - name: r
    paths: ["/"]
    upstream: a
    client_cert_headers: rfc9440
`
	s, _ := startServer(t, fmt.Sprintf(yaml, srvCert, srvKey, ca.Path, a.addr()))
	addr := s.Addrs()["main"]
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	pair, err := tls.LoadX509KeyPair(aliceCert, aliceKey)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, ServerName: "edge.test", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}}
	req, _ := http.NewRequest("GET", "https://"+addr+"/x", nil)
	// And the client tries to claim somebody else's while it is here.
	req.Header.Set("Client-Cert", sfBinary([]byte("not a certificate")))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	h := a.last.Load().Header
	got := h.Get("Client-Cert")
	der, err := unSFBinary(got)
	if err != nil {
		t.Fatalf("Client-Cert %q does not decode: %v", got, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Client-Cert does not carry a certificate: %v", err)
	}
	if leaf.Subject.CommonName != "alice" {
		t.Fatalf("Client-Cert names %q, want alice", leaf.Subject.CommonName)
	}
	// One certificate was presented, so there is no chain to state: an
	// empty header would be one whose meaning depends on the parser.
	if h.Get("Client-Cert-Chain") != "" {
		t.Errorf("Client-Cert-Chain was set for a one certificate chain: %q", h.Get("Client-Cert-Chain"))
	}
	// Envoy's header is not set by this mode, and the client's own copy
	// of it is gone.
	if h.Get("X-Forwarded-Client-Cert") != "" {
		t.Errorf("xfcc was set by the rfc9440 mode: %q", h.Get("X-Forwarded-Client-Cert"))
	}
}

// Nothing is sent when there was no certificate: an absent header is how
// the backend is told there was none.
func TestNothingIsStatedWithoutACertificate(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams: [{name: a, endpoints: [{address: "%s"}]}]
routes: [{name: r, paths: ["/"], upstream: a, client_cert_headers: rfc9440}]
`
	s, _ := startServer(t, fmt.Sprintf(yaml, a.addr()))
	resp, err := http.Get("http://" + s.Addrs()["main"] + "/x")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if got := a.last.Load().Header.Get("Client-Cert"); got != "" {
		t.Fatalf("Client-Cert was set without a certificate: %q", got)
	}
}

// The encoding is RFC 8941's sf-binary and not something that merely
// looks like it: standard base64, padded, between colons. A backend using
// a structured-fields parser rejects anything else.
func TestTheByteSequenceEncodingIsTheOneRFC8941Defines(t *testing.T) {
	for _, raw := range []string{"", "a", "ab", "abc", "\x00\xff\xfe", strings.Repeat("x", 300)} {
		got := sfBinary([]byte(raw))
		if !strings.HasPrefix(got, ":") || !strings.HasSuffix(got, ":") {
			t.Fatalf("%q encoded as %q, want colons around it", raw, got)
		}
		back, err := unSFBinary(got)
		if err != nil || string(back) != raw {
			t.Fatalf("%q round-tripped as %q (%v)", raw, back, err)
		}
		if strings.ContainsAny(got[1:len(got)-1], "-_") {
			t.Fatalf("%q used the URL alphabet: %q", raw, got)
		}
	}
}

// unSFBinary decodes what sfBinary produced, the way a structured fields
// parser would.
func unSFBinary(s string) ([]byte, error) {
	if len(s) < 2 || s[0] != ':' || s[len(s)-1] != ':' {
		return nil, fmt.Errorf("not a byte sequence: %q", s)
	}
	return base64.StdEncoding.DecodeString(s[1 : len(s)-1])
}
