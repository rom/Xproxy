package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/acme/acmetest"
)

const acmeYAML = `
version: 1
server:
  listeners:
    - {name: http, address: "127.0.0.1:0", redirect_to_https: true}
    - name: tls
      address: "127.0.0.1:0"
      tls:
        acme: [{hosts: [site.example.test, www.site.example.test]}]
acme:
  directory: %s
  email: ops@example.test
  accept_terms: true
  ca_file: %s
  state_dir: %s
  challenge: %s
  renew_before: 720h
  check_interval: 1h
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: a
`

func TestACMEEndToEnd(t *testing.T) {
	for _, challenge := range []string{"http-01", "tls-alpn-01"} {
		t.Run(challenge, func(t *testing.T) {
			backend := newBackend(t, "a")
			dir := t.TempDir()
			ca := acmetest.New(t, dir)
			s, _ := startServer(t, fmt.Sprintf(acmeYAML, ca.Directory(), ca.CAPath, dir+"/state", challenge, backend.addr()))
			addrs := s.Addrs()
			ca.HTTPTarget, ca.TLSTarget = addrs["http"], addrs["tls"]
			if s.ACME() == nil {
				t.Fatal("manager not created")
			}
			// Before issuance the TLS listener has no certificate for the host.
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.IssuerPool(), ServerName: "www.site.example.test", MinVersion: tls.VersionTLS12}}}
			if _, err := client.Get("https://" + addrs["tls"] + "/"); err == nil {
				t.Fatal("served TLS before any certificate existed")
			}
			// The http-01 path is served even though the listener redirects
			// everything else.
			resp, err := http.Get("http://" + addrs["http"] + "/.well-known/acme-challenge/unknown")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Fatalf("unknown token: %d", resp.StatusCode)
			}
			// Issue through the real listeners.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := s.ACME().Renew(ctx); err != nil {
				t.Fatalf("%s: %v", challenge, err)
			}
			st := s.ACME().Status()
			if len(st) != 1 || !st[0].Present || st[0].Issuer != "acmetest CA" {
				t.Fatalf("status %+v", st)
			}
			// The listener now serves the issued certificate, verified against
			// the CA, for both hosts of the group; ordinary traffic flows.
			for _, host := range []string{"site.example.test", "www.site.example.test"} {
				c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.IssuerPool(), ServerName: host, MinVersion: tls.VersionTLS12}}}
				resp, err := c.Get("https://" + addrs["tls"] + "/hello")
				if err != nil {
					t.Fatalf("%s after issuance: %v", host, err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(body) != "a:/hello" || resp.TLS.PeerCertificates[0].Subject.CommonName != "site.example.test" {
					t.Fatalf("%s: %d %q", host, resp.StatusCode, body)
				}
			}
			// A tls-alpn-01 handshake without a pending challenge is refused.
			d := &tls.Dialer{Config: &tls.Config{ServerName: "site.example.test", NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // test
			if conn, err := d.DialContext(ctx, "tcp", addrs["tls"]); err == nil {
				conn.Close()
				t.Fatal("acme-tls/1 handshake succeeded without a pending challenge")
			}
			if !strings.Contains(fmt.Sprint(s.Addrs()), "tls") {
				t.Fatal("addrs")
			}
		})
	}
}
