package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/testutil"
	"github.com/rom/xproxy/internal/tlsconf"
)

// Refusing in the ClientHello is the cheapest no there is. These tests
// are about the two things that have to be true for it to be worth
// having: the refused client gets no handshake at all, and every other
// client is untouched.

const handshakeYAML = `
version: 1
server:
  listeners:
    - name: tls
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
bans:
  action: reject
  triggers:
    - {name: probes, reasons: [honeypot], threshold: 1, window: 1m, duration: 1h}
handshake:
%s
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: trap, paths: [/.env], honeypot: {decoy: env}}
  - {name: app, paths: [/], upstream: app}
`

func startHandshakeServer(t *testing.T, policy string) (*proxy.Server, string) {
	t.Helper()
	a := newBackend(t, "a")
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "tls.test")
	s, _ := startServer(t, fmt.Sprintf(handshakeYAML, cert, key, policy, a.addr()))
	return s, s.Addrs()["tls"]
}

// tlsGet makes one HTTPS request and reports the status, and the local
// address the connection used — which is the key the proxy files the
// ClientHello fingerprint under, so a test can ask what fingerprint its
// own client sends.
func tlsGet(addr, path string) (int, string, error) {
	var local string
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "tls.test"}, //nolint:gosec // test
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, address)
			if err == nil {
				local = c.LocalAddr().String()
			}
			return c, err
		},
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := c.Get("https://" + addr + path)
	if err != nil {
		return 0, local, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, local, nil
}

// clientJA4 is the fingerprint the test's own client sends, learned
// from the proxy that just saw it. The connection is held open across
// the lookup: the proxy drops a fingerprint when its connection
// closes, so a transport that closed first would leave nothing to read.
func clientJA4(t *testing.T, s *proxy.Server, addr string) string {
	t.Helper()
	var local string
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "tls.test"}, //nolint:gosec // test
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, address)
			if err == nil {
				local = c.LocalAddr().String()
			}
			return c, err
		},
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("baseline request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	fp, ok := s.Fingerprints().Get(local)
	if !ok || fp.JA4 == "" {
		t.Fatalf("the proxy recorded no fingerprint for %s", local)
	}
	return fp.JA4
}

// A fingerprint on the deny list never negotiates. The test learns the
// fingerprint from the proxy itself — it is whatever Go's client sends
// — and then refuses exactly that.
func TestHandshakeRefusesADeniedFingerprint(t *testing.T) {
	s, addr := startHandshakeServer(t, "  deny_fingerprints: []")
	ja4 := clientJA4(t, s, addr)

	// Now refuse it.
	s2, addr2 := startHandshakeServer(t, "  deny_fingerprints: [\""+ja4+"\"]")
	_, _, err := tlsGet(addr2, "/")
	if err == nil {
		t.Fatal("the denied fingerprint completed a handshake")
	}
	if st := s2.Handshake(); !st.Enabled || st.Refused != 1 || st.Fingerprints != 1 {
		t.Errorf("status %+v, want one refusal", st)
	}
	if n := s2.Stats().HandshakesRefused; n != 1 {
		t.Errorf("handshakes_refused = %d, want 1", n)
	}
	// The refusal is a failed negotiation, not an answer: nothing a
	// scanner can read off it.
	if strings.Contains(err.Error(), "handshake refused") {
		t.Errorf("the reason reached the client: %v", err)
	}
}

// A JA4 prefix names a family of clients without pinning every
// extension order.
func TestHandshakeRefusesAFingerprintPrefix(t *testing.T) {
	s, addr := startHandshakeServer(t, "  deny_fingerprints: []")
	prefix, _, _ := strings.Cut(clientJA4(t, s, addr), "_")
	s2, addr2 := startHandshakeServer(t, "  deny_fingerprints: [\"ja4:"+prefix+"*\"]")
	if _, _, err := tlsGet(addr2, "/"); err == nil {
		t.Fatal("a client matching the denied prefix completed a handshake")
	}
	if st := s2.Handshake(); st.Refused != 1 {
		t.Errorf("refused %d, want 1", st.Refused)
	}
}

// refuse_banned turns an existing ban into a refusal one layer down.
// The ban is earned the ordinary way, through a honeypot.
func TestHandshakeRefusesABannedClient(t *testing.T) {
	s, addr := startHandshakeServer(t, "  refuse_banned: true")

	// Loopback earns itself a ban by reading a decoy.
	if code, _, err := tlsGet(addr, "/.env"); err != nil || code != 200 {
		t.Fatalf("decoy: %d %v", code, err)
	}
	bl := s.Bans()
	if bl == nil {
		t.Fatal("no ban list")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !bl.Banned(mustAddr("127.0.0.1")) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !bl.Banned(mustAddr("127.0.0.1")) {
		t.Fatal("the decoy did not ban the client")
	}
	// The next connection does not get a handshake at all.
	if _, _, err := tlsGet(addr, "/"); err == nil {
		t.Fatal("a banned client completed a handshake")
	}
	if st := s.Handshake(); st.Refused == 0 {
		t.Errorf("status %+v, want a refusal", st)
	}
}

// Without a handshake section nothing changes, and the hook is not
// even installed.
func TestHandshakeWithoutAPolicy(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "tls.test")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: tls
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: app, paths: [/], upstream: app}
`, cert, key, a.addr())
	s, _ := startServer(t, yaml)
	if code, _, err := tlsGet(s.Addrs()["tls"], "/"); err != nil || code != 200 {
		t.Fatalf("served: %d %v", code, err)
	}
	if st := s.Handshake(); st.Enabled {
		t.Errorf("status %+v, want no policy", st)
	}
	if got := s.RefuseHandshake(nil, tlsconf.Fingerprint{JA4: "anything"}); got != "" {
		t.Errorf("refused %q without a policy", got)
	}
}
