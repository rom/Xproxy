package http

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
	"github.com/rom/xproxy/internal/tlsconf"
)

// mtlsBackend is a TLS backend that requires a client certificate from ca.
func mtlsBackend(t *testing.T, dir string, ca *testutil.CA) *httptest.Server {
	t.Helper()
	cert, key := ca.Issue(t, dir, "backend.test")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cn := ""
		if len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		fmt.Fprintf(w, "client=%s", cn)
	}))
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

const mtlsYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: b
    scheme: https
    retries: 0
    endpoints: [{address: "%s"}]
    tls:
      server_name: backend.test
      ca_file: %s
      %s
routes:
  - name: r
    upstream: b
`

func TestUpstreamMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	backend := mtlsBackend(t, dir, ca)
	addr := strings.TrimPrefix(backend.URL, "https://")
	clientCert, clientKey := ca.Issue(t, dir, "xproxy-edge")

	// Without a client certificate the backend refuses the handshake.
	_, url := startServer(t, fmt.Sprintf(mtlsYAML, addr, ca.Path, ""))
	if resp, _ := get(t, url+"/"); resp.StatusCode != 502 {
		t.Fatalf("no client cert: %d", resp.StatusCode)
	}

	// With the pair, the backend sees the edge's identity.
	// Copy the files so we can rotate them later.
	cp := filepath.Join(dir, "edge.pem")
	kp := filepath.Join(dir, "edge-key.pem")
	copyFile(t, clientCert, cp)
	copyFile(t, clientKey, kp)
	s, url := startServer(t, fmt.Sprintf(mtlsYAML, addr, ca.Path, fmt.Sprintf("client_cert_file: %s\n      client_key_file: %s\n      min_version: \"1.3\"", cp, kp)))
	resp, body := get(t, url+"/")
	if resp.StatusCode != 200 || body != "client=xproxy-edge" {
		t.Fatalf("mtls: %d %q", resp.StatusCode, body)
	}

	// Rotate the client certificate on disk and reload certificates only:
	// the backend sees the new identity on the next connection.
	newCert, newKey := ca.Issue(t, dir, "xproxy-edge-2")
	copyFile(t, newCert, cp)
	copyFile(t, newKey, kp)
	if err := s.ReloadCertificates(); err != nil {
		t.Fatal(err)
	}
	resp, body = get(t, url+"/")
	if resp.StatusCode != 200 || body != "client=xproxy-edge-2" {
		t.Fatalf("after rotation: %d %q", resp.StatusCode, body)
	}
	// A broken key file fails reload-certs loudly and keeps the old one.
	os.WriteFile(kp, []byte("garbage"), 0o600)
	if err := s.ReloadCertificates(); err == nil {
		t.Fatal("broken key accepted")
	}
	if resp, _ := get(t, url+"/"); resp.StatusCode != 200 {
		t.Fatalf("old certificate lost: %d", resp.StatusCode)
	}
}

func TestUpstreamSPKIPin(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	backend := mtlsBackend(t, dir, ca)
	addr := strings.TrimPrefix(backend.URL, "https://")
	clientCert, clientKey := ca.Issue(t, dir, "edge")
	pin := tlsconf.SPKIPin(backend.Certificate())
	wrong := base64.StdEncoding.EncodeToString(make([]byte, 32))

	tlsBlock := func(pins string) string {
		return fmt.Sprintf("client_cert_file: %s\n      client_key_file: %s\n      spki_pins: [%s]", clientCert, clientKey, pins)
	}
	_, url := startServer(t, fmt.Sprintf(mtlsYAML, addr, ca.Path, tlsBlock(`"`+wrong+`"`)))
	if resp, _ := get(t, url+"/"); resp.StatusCode != 502 {
		t.Fatalf("wrong pin: %d", resp.StatusCode)
	}
	_, url = startServer(t, fmt.Sprintf(mtlsYAML, addr, ca.Path, tlsBlock(`"`+wrong+`", "`+pin+`"`)))
	if resp, body := get(t, url+"/"); resp.StatusCode != 200 || body != "client=edge" {
		t.Fatalf("correct pin: %d %q", resp.StatusCode, body)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---- JWT end to end -------------------------------------------------------

func rsaSigner(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "k1", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}}})
	return k, string(jwks)
}

func signRS256(t *testing.T, k *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`))
	pb, _ := json.Marshal(claims)
	signed := h + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256sum([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, 5 /* crypto.SHA256 */, sum)
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const jwtYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
bans:
  action: reject
  triggers: [{name: jwt, reasons: [jwt], threshold: 3, window: 1m, duration: 1h}]
jwt:
  providers:
    - name: idp
      issuer: https://idp.test/
      audiences: [api]
      %s
      forward_claims: {X-User: sub, X-Scopes: scope}
      log_claims: [sub]
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - {name: api,      hosts: [api.test],      jwt: {provider: idp}, upstream: a}
  - {name: optional, hosts: [optional.test], jwt: {provider: idp, required: false}, upstream: a}
  - {name: open,     hosts: [open.test],     upstream: a}
`

func TestJWTRoutes(t *testing.T) {
	backend := newBackend(t, "a")
	key, jwks := rsaSigner(t)
	dir := t.TempDir()
	jwksPath := filepath.Join(dir, "jwks.json")
	os.WriteFile(jwksPath, []byte(jwks), 0o600)
	s, url := startServer(t, fmt.Sprintf(jwtYAML, "jwks_file: "+jwksPath, backend.addr()))

	claims := map[string]any{"iss": "https://idp.test/", "aud": "api", "sub": "alice", "scope": "read", "exp": time.Now().Add(time.Hour).Unix()}
	token := signRS256(t, key, claims)

	// No token: 401 with a challenge.
	resp, _ := getAs(t, url+"/v1", "api.test", "198.51.100.40")
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("missing token: %d %v", resp.StatusCode, resp.Header)
	}
	// Valid token: forwarded claims, token stripped, spoofed header removed.
	resp, body := getAs(t, url+"/v1", "api.test", "198.51.100.40", "Authorization", "Bearer "+token, "X-User", "spoofed")
	if resp.StatusCode != 200 || body != "a:/v1" {
		t.Fatalf("valid: %d %q", resp.StatusCode, body)
	}
	last := backend.last.Load()
	if last.Header.Get("X-User") != "alice" || last.Header.Get("X-Scopes") != "read" || last.Header.Get("Authorization") != "" {
		t.Fatalf("forwarded headers: %v", last.Header)
	}
	// Expired token: 401 with error="invalid_token".
	expired := signRS256(t, key, map[string]any{"iss": "https://idp.test/", "aud": "api", "sub": "alice", "exp": time.Now().Add(-time.Hour).Unix()})
	resp, _ = getAs(t, url+"/v1", "api.test", "198.51.100.41", "Authorization", "Bearer "+expired)
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("expired: %d %v", resp.StatusCode, resp.Header)
	}
	// Optional route: no token passes with spoofed headers removed; a bad token is still rejected.
	resp, _ = getAs(t, url+"/", "optional.test", "198.51.100.42", "X-User", "spoofed")
	if resp.StatusCode != 200 || backend.last.Load().Header.Get("X-User") != "" {
		t.Fatalf("optional without token: %d", resp.StatusCode)
	}
	resp, _ = getAs(t, url+"/", "optional.test", "198.51.100.42", "Authorization", "Bearer junk.junk.junk")
	if resp.StatusCode != 401 {
		t.Fatalf("optional with bad token: %d", resp.StatusCode)
	}
	// Open route ignores tokens entirely.
	if resp, _ := getAs(t, url+"/", "open.test", "198.51.100.43", "Authorization", "Bearer junk.junk.junk"); resp.StatusCode != 200 {
		t.Fatalf("open: %d", resp.StatusCode)
	}
	// Repeated failures feed the ban trigger.
	for i := 0; i < 3; i++ {
		getAs(t, url+"/v1", "api.test", "198.51.100.44", "Authorization", "Bearer "+expired)
	}
	if !s.Bans().Banned(mustAddr("198.51.100.44")) {
		t.Fatal("jwt failures did not trigger a ban")
	}
	if st := s.Stats(); st.DeniedJWT < 5 {
		t.Fatalf("stats %+v", st)
	}
}

func TestJWTFromJWKSURL(t *testing.T) {
	backend := newBackend(t, "a")
	key, jwks := rsaSigner(t)
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	defer idp.Close()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "idp-ca.pem")
	os.WriteFile(caPath, []byte("-----BEGIN CERTIFICATE-----\n"+base64.StdEncoding.EncodeToString(idp.Certificate().Raw)+"\n-----END CERTIFICATE-----\n"), 0o600)
	_, url := startServer(t, fmt.Sprintf(jwtYAML, "jwks_url: "+idp.URL+"/jwks\n      jwks_ca_file: "+caPath, backend.addr()))
	token := signRS256(t, key, map[string]any{"iss": "https://idp.test/", "aud": "api", "sub": "bob", "exp": time.Now().Add(time.Hour).Unix()})
	resp, _ := getAs(t, url+"/", "api.test", "198.51.100.50", "Authorization", "Bearer "+token)
	if resp.StatusCode != 200 || backend.last.Load().Header.Get("X-User") != "bob" {
		t.Fatalf("jwks url: %d", resp.StatusCode)
	}
}
