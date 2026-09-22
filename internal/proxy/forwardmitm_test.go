package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
)

// interceptClient proxies through addr and verifies the destination
// against pool, taking the server name from the destination itself —
// which is what a browser does, and what an interception proxy has to
// keep working.
func interceptClient(t *testing.T, addr string, pool *x509.CertPool) *http.Client {
	t.Helper()
	tr := &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// connectTunnel opens a CONNECT tunnel by hand and returns the raw
// connection, so a test can decide for itself what to send through it.
func connectTunnel(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("connect: %q", strings.TrimSpace(line))
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("connect headers: %v", err)
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	if br.Buffered() > 0 {
		t.Fatalf("%d bytes buffered after the CONNECT head", br.Buffered())
	}
	return c
}

// TestForwardIntercept covers the whole of TLS interception: a client
// that trusts the proxy's CA reaches a real origin through it, the same
// client trusting only the origin's CA does not (which is the proof
// that the connection really was terminated), bypass_hosts wins over
// hosts, a destination whose own certificate does not verify is refused
// rather than forged, a handshake whose name disagrees with the tunnel
// is refused, and a tunnel that is not TLS at all is passed through
// untouched.
func TestForwardIntercept(t *testing.T) {
	dir := t.TempDir()
	mitmDir := t.TempDir()
	originCA := testutil.WriteCA(t, dir)
	proxyCA := testutil.WriteCA(t, mitmDir)
	proxyKey := proxyCA.WriteKey(t, mitmDir)

	// The origin is named "localhost" so that the name in the CONNECT
	// and the name in the handshake agree, as they do in the field.
	origin := tlsOrigin(t, "localhost", originCA, dir)
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))

	// A second origin with a certificate signed by nobody the proxy
	// trusts.
	selfCert, selfKey := testutil.WriteCert(t, dir, "localhost")
	pair, err := tls.LoadX509KeyPair(selfCert, selfKey)
	if err != nil {
		t.Fatal(err)
	}
	selfLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = selfLn.Close() })
	go func() {
		for {
			c, err := selfLn.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	_, selfPort, _ := net.SplitHostPort(selfLn.Addr().String())

	echo := echoServer(t, "")
	_, echoPort, _ := net.SplitHostPort(echo)

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: mitm
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s, %s, %s]
        allow_private: true
        idle_timeout: 5s
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
    - name: socks
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        idle_timeout: 5s
        socks5: true
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
    - name: bypassed
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        idle_timeout: 5s
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
          bypass_hosts: ["localhost"]
logging: {access: {enabled: false}}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, originPort, selfPort, echoPort, proxyCA.Path, proxyKey, originCA.Path,
		originPort, proxyCA.Path, proxyKey, originCA.Path,
		originPort, proxyCA.Path, proxyKey, originCA.Path)

	s, _ := startServer(t, yaml)
	mitmAddr := s.Addrs()["mitm"]
	socksAddr := s.Addrs()["socks"]
	bypassAddr := s.Addrs()["bypassed"]
	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(proxyCA.Cert)
	originPool := x509.NewCertPool()
	originPool.AddCert(originCA.Cert)

	t.Run("client trusting the proxy CA reaches the origin", func(t *testing.T) {
		c := interceptClient(t, mitmAddr, proxyPool)
		resp, err := c.Get("https://localhost:" + originPort + "/seen")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "localhost:/seen" {
			t.Fatalf("got %d %q", resp.StatusCode, body)
		}
		// The certificate the client verified is not the origin's: it
		// carries the origin's name, signed by the proxy.
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
			t.Fatal("no peer certificate")
		}
		leaf := resp.TLS.PeerCertificates[0]
		if err := leaf.CheckSignatureFrom(proxyCA.Cert); err != nil {
			t.Fatalf("leaf was not signed by the proxy CA: %v", err)
		}
		if err := leaf.VerifyHostname("localhost"); err != nil {
			t.Fatalf("forged leaf does not carry the origin's name: %v", err)
		}
		if n := s.stats.Intercepted.Load(); n == 0 {
			t.Fatal("intercepted counter did not move")
		}
	})

	t.Run("client trusting only the origin CA is refused", func(t *testing.T) {
		// This is the whole point: interception is visible to the
		// client, because the client does not trust what it is handed.
		c := interceptClient(t, mitmAddr, originPool)
		if resp, err := c.Get("https://localhost:" + originPort + "/"); err == nil {
			_ = resp.Body.Close()
			t.Fatal("a client that does not trust the proxy CA got through")
		}
	})

	t.Run("bypass_hosts wins over hosts", func(t *testing.T) {
		// Nothing is terminated, so the client verifies the origin's own
		// certificate end to end and the proxy's CA is irrelevant.
		c := interceptClient(t, bypassAddr, originPool)
		resp, err := c.Get("https://localhost:" + originPort + "/bypassed")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "localhost:/bypassed" {
			t.Fatalf("body %q", body)
		}
		if err := resp.TLS.PeerCertificates[0].CheckSignatureFrom(originCA.Cert); err != nil {
			t.Fatalf("a bypassed destination was intercepted: %v", err)
		}
	})

	t.Run("an origin that does not verify is refused, not forged", func(t *testing.T) {
		before := s.stats.InterceptRefused.Load()
		c := interceptClient(t, mitmAddr, proxyPool)
		resp, err := c.Get("https://localhost:" + selfPort + "/")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("an unverifiable origin was reached through the proxy")
		}
		if s.stats.InterceptRefused.Load() == before {
			t.Fatal("refusal counter did not move")
		}
	})

	t.Run("a handshake for another name is refused", func(t *testing.T) {
		before := s.stats.InterceptRefused.Load()
		c := connectTunnel(t, mitmAddr, "localhost:"+originPort)
		tc := tls.Client(c, &tls.Config{
			ServerName: "elsewhere.test", RootCAs: proxyPool, MinVersion: tls.VersionTLS12,
		})
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tc.Handshake(); err == nil {
			t.Fatal("a handshake naming a host the tunnel did not name was answered")
		}
		if s.stats.InterceptRefused.Load() == before {
			t.Fatal("refusal counter did not move")
		}
	})

	t.Run("a SOCKS tunnel is intercepted too", func(t *testing.T) {
		// Otherwise asking for the same destination in the other
		// protocol on the same port walks past the policy.
		port, _ := strconv.Atoi(originPort)
		c, code := socksDial(t, socksAddr, "localhost", port, "", "")
		if code != 0 {
			t.Fatalf("socks reply %d", code)
		}
		tc := tls.Client(c, &tls.Config{
			ServerName: "localhost", RootCAs: proxyPool, MinVersion: tls.VersionTLS12,
		})
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			t.Fatalf("handshake through SOCKS: %v", err)
		}
		if err := tc.ConnectionState().PeerCertificates[0].CheckSignatureFrom(proxyCA.Cert); err != nil {
			t.Fatalf("a SOCKS tunnel was not intercepted: %v", err)
		}
		_ = tc.Close()
	})

	t.Run("a tunnel that is not TLS is passed through", func(t *testing.T) {
		before := s.stats.InterceptPassed.Load()
		c := connectTunnel(t, mitmAddr, "localhost:"+echoPort)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, "SSH-2.0-not-tls\r\n"); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len("SSH-2.0-not-tls\r\n"))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != "SSH-2.0-not-tls\r\n" {
			t.Fatalf("echo %q", buf)
		}
		if s.stats.InterceptPassed.Load() == before {
			t.Fatal("passed-through counter did not move")
		}
	})
}

// TestForwardInterceptYARA proves the point of decrypting at all: a rule
// written against the plaintext sees what the client sent inside TLS,
// and the connection carrying it is cut.
func TestForwardInterceptYARA(t *testing.T) {
	dir := t.TempDir()
	mitmDir := t.TempDir()
	originCA := testutil.WriteCA(t, dir)
	proxyCA := testutil.WriteCA(t, mitmDir)
	proxyKey := proxyCA.WriteKey(t, mitmDir)
	origin := tlsOrigin(t, "localhost", originCA, dir)
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: mitm
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        idle_timeout: 5s
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
          yara:
            rules_file: %s
            directions: [client]
logging: {access: {enabled: false}}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, originPort, proxyCA.Path, proxyKey, originCA.Path, rulesFile(t))

	s, _ := startServer(t, yaml)
	addr := s.Addrs()["mitm"]
	pool := x509.NewCertPool()
	pool.AddCert(proxyCA.Cert)

	c := interceptClient(t, addr, pool)
	if resp, err := c.Get("https://localhost:" + originPort + "/clean"); err != nil {
		t.Fatalf("a clean request through the intercepting proxy failed: %v", err)
	} else {
		_ = resp.Body.Close()
	}
	before := s.stats.YARAMatches.Load()
	resp, err := c.Post("https://localhost:"+originPort+"/upload", "text/plain",
		strings.NewReader("here is the TOP-SECRET-MARKER leaving the estate"))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a body a rule names went through")
	}
	if s.stats.YARAMatches.Load() == before {
		t.Fatal("no match was recorded over the decrypted stream")
	}
}
