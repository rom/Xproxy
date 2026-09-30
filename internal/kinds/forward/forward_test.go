package forward

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// tlsOrigin is an HTTPS server for one name, answering its name.
func tlsOrigin(t *testing.T, name string, ca *testutil.CA, dir string) *httptest.Server {
	t.Helper()
	cert, key := ca.Issue(t, dir, name)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s:%s", name, r.URL.Path)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// forwardClient is an http.Client that uses the listener as its proxy.
func forwardClient(t *testing.T, proxyAddr string, pool *x509.CertPool, user, pass string) *http.Client {
	t.Helper()
	pu := &url.URL{Scheme: "http", Host: proxyAddr}
	if user != "" {
		pu.User = url.UserPassword(user, pass)
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "origin.test", MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(tr.CloseIdleConnections) // drops the tunnels the transport keeps
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// TestForwardProxy exercises CONNECT tunnels and plain relays through a
// kind: forward listener, the destination policy (ports, private
// addresses, deny and allow lists), proxy authentication, the tunnel
// bound, counters and the reload of the users file.
func TestForwardProxy(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	origin := tlsOrigin(t, "origin.test", ca, dir)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Host", r.Host)
		w.Header().Set("X-Saw-Proxy-Connection", r.Header.Get("Proxy-Connection"))
		w.Header().Set("Via-Seen", r.Header.Get("Via"))
		fmt.Fprintf(w, "plain:%s:%s", r.Method, r.URL.Path)
	}))
	t.Cleanup(plain.Close)
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	_, plainPort, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))

	hash, err := passwd.HashWithIterations("correct horse battery", 1000)
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(dir, "proxy.htpasswd")
	if err := os.WriteFile(users, []byte("alice:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The origins listen on loopback, so the test enables allow_private and
	// uses the deny list to prove refusals; the "closed" listener keeps the
	// default (private refused).
	yaml := `
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s, %s, 9]
        allow_private: true
        deny: ["*.denied.test", "10.0.0.0/8"]
        max_tunnels: 2
        idle_timeout: 2s
    - name: authed
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        allow: ["localhost", "127.0.0.1"]
        auth: {users_file: %s, realm: lab}
    - name: closed
      address: "127.0.0.1:0"
      kind: forward
      forward: {}
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`
	yaml = fmt.Sprintf(yaml, originPort, plainPort, originPort, users)
	s := proxytest.Start(t, yaml)
	fwd := s.Addrs()["fwd"]
	authed := s.Addrs()["authed"]
	closed := s.Addrs()["closed"]
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	t.Run("connect tunnel end to end", func(t *testing.T) {
		c := forwardClient(t, fwd, pool, "", "")
		resp, err := c.Get("https://localhost:" + originPort + "/tunnel")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "origin.test:/tunnel" {
			t.Fatalf("got %d %q", resp.StatusCode, body)
		}
	})
	t.Run("plain relay strips hop by hop and adds Via", func(t *testing.T) {
		c := forwardClient(t, fwd, pool, "", "")
		req, _ := http.NewRequest("GET", "http://localhost:"+plainPort+"/p?x=1", nil)
		req.Header.Set("Proxy-Connection", "keep-alive")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "plain:GET:/p" {
			t.Fatalf("got %d %q", resp.StatusCode, body)
		}
		if resp.Header.Get("X-Saw-Proxy-Connection") != "" {
			t.Fatalf("hop by hop header relayed: %v", resp.Header)
		}
		if resp.Header.Get("Via") != "1.1 xproxy" || resp.Header.Get("Via-Seen") != "1.1 xproxy" {
			t.Fatalf("Via not added both ways: %v", resp.Header)
		}
		if resp.Header.Get("X-Origin-Host") != "localhost:"+plainPort {
			t.Fatalf("origin saw host %q", resp.Header.Get("X-Origin-Host"))
		}
	})
	t.Run("policy refusals", func(t *testing.T) {
		c := forwardClient(t, fwd, pool, "", "")
		cases := []struct {
			url  string
			want int
		}{
			{"http://localhost:1/port-not-listed", 403},
			{"http://x.denied.test:" + plainPort + "/deny-name", 403},
			{"http://10.1.2.3:" + plainPort + "/deny-cidr", 403},
			{"https://localhost:1/", 403},
			{"http://nonexistent.invalid:" + plainPort + "/", 403},
		}
		for _, tc := range cases {
			resp, err := c.Get(tc.url)
			if err != nil {
				if strings.HasPrefix(tc.url, "https://") && strings.Contains(err.Error(), "Forbidden") {
					continue // CONNECT refused: the transport reports the proxy status
				}
				t.Fatalf("%s: %v", tc.url, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("%s: got %d want %d", tc.url, resp.StatusCode, tc.want)
			}
		}
		// A request that is not proxy shaped.
		resp, _ := proxytest.Get(t, "http://"+fwd+"/origin-form")
		if resp.StatusCode != 400 {
			t.Fatalf("origin-form request: got %d", resp.StatusCode)
		}
		// The default policy refuses private destinations.
		cc := forwardClient(t, closed, pool, "", "")
		resp, err := cc.Get("http://127.0.0.1:" + plainPort + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("private destination on default policy: got %d", resp.StatusCode)
		}
	})
	t.Run("proxy authentication", func(t *testing.T) {
		anon := forwardClient(t, authed, pool, "", "")
		resp, err := anon.Get("https://localhost:" + originPort + "/")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("tunnel without credentials: got %d", resp.StatusCode)
		}
		if !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Fatalf("expected 407, got %v", err)
		}
		// Raw request to inspect the challenge header.
		conn, err := net.Dial("tcp", authed)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		fmt.Fprintf(conn, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", originPort, originPort)
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := conn.Read(buf)
		head := string(buf[:n])
		if !strings.HasPrefix(head, "HTTP/1.1 407") || !strings.Contains(head, `Proxy-Authenticate: Basic realm="lab"`) {
			t.Fatalf("challenge: %q", head)
		}
		bad := forwardClient(t, authed, pool, "alice", "wrong")
		if resp, err := bad.Get("https://localhost:" + originPort + "/"); err == nil {
			_ = resp.Body.Close()
			t.Fatal("wrong password accepted")
		}
		good := forwardClient(t, authed, pool, "alice", "correct horse battery")
		resp, err = good.Get("https://localhost:" + originPort + "/authed")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "origin.test:/authed" {
			t.Fatalf("got %q", body)
		}
		// Not on the allow list even with credentials.
		resp, err = good.Get("http://[::1]:" + originPort + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("destination outside the allow list: %d", resp.StatusCode)
		}
		// Reload with a rotated users file: the old password stops working
		// (the verification cache is dropped) and the new one works.
		hash2, _ := passwd.HashWithIterations("new passphrase here", 1000)
		if err := os.WriteFile(users, []byte("bob:"+hash2+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Parse([]byte(yaml))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Reload(cfg); err != nil {
			t.Fatal(err)
		}
		good.Transport.(*http.Transport).CloseIdleConnections() // force a new CONNECT
		if resp, err := good.Get("https://localhost:" + originPort + "/"); err == nil {
			_ = resp.Body.Close()
			t.Fatal("removed user still accepted after reload")
		}
		bob := forwardClient(t, authed, pool, "bob", "new passphrase here")
		resp, err = bob.Get("https://localhost:" + originPort + "/bob")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		// A broken users file makes the reload fail as a whole.
		if err := os.WriteFile(users, []byte("garbage\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), "forward auth") {
			t.Fatalf("reload with a bad users file: %v", err)
		}
	})
	t.Run("tunnel bound and early data", func(t *testing.T) {
		// The bound this subtest is about is two tunnels, so it can
		// only mean anything once the earlier subtests' tunnels have
		// wound down. Waiting a fixed span and carrying on regardless
		// is how that becomes a flake: under load the bound is
		// already spent, the first open() is refused, and the failure
		// names the wrong thing.
		eventually(t, 15*time.Second, "the earlier subtests' tunnels to wind down",
			func() bool { return s.Stats().ForwardTunnelsOpen == 0 })
		open := func() net.Conn {
			conn, err := net.Dial("tcp", fwd)
			if err != nil {
				t.Fatal(err)
			}
			// Early bytes after the CONNECT head must reach the origin.
			fmt.Fprintf(conn, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", plainPort, plainPort)
			buf := make([]byte, 1024)
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _ := conn.Read(buf)
			if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") {
				t.Fatalf("connect: %q", buf[:n])
			}
			return conn
		}
		a, b := open(), open()
		defer func() { _ = a.Close(); _ = b.Close() }()
		third, err := net.Dial("tcp", fwd)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = third.Close() }()
		fmt.Fprintf(third, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", plainPort, plainPort)
		buf := make([]byte, 1024)
		_ = third.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := third.Read(buf)
		if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 503") {
			t.Fatalf("third tunnel over the bound: %q", buf[:n])
		}
		fmt.Fprintf(a, "GET /early HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		data, _ := io.ReadAll(a)
		if !strings.Contains(string(data), "plain:GET:/early") {
			t.Fatalf("through tunnel: %q", data)
		}
		// Idle tunnels close after idle_timeout.
		_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := b.Read(buf); err == nil {
			t.Fatal("idle tunnel stayed open")
		}
	})
	sn := s.Stats()
	if sn.ForwardTunnels < 4 || sn.ForwardDenied < 5 || sn.ForwardAuthFailed < 3 || sn.ForwardRejected != 1 || sn.ForwardBytesOut == 0 {
		t.Fatalf("counters: %+v", sn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// The error matters as much as the gauge. A shutdown that ran out of time
	// and one that drained cleanly leave the same number behind once the
	// listener has closed what was left, so a test that read only the gauge
	// would report "tunnels open after shutdown" for a timeout -- which sends
	// somebody looking at the accounting rather than at the drain.
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if sn := s.Stats(); sn.ForwardTunnelsOpen != 0 {
		t.Fatalf("tunnels open after a drained shutdown: %d", sn.ForwardTunnelsOpen)
	}
}

// TestForwardConnectH2 tunnels a CONNECT request over an HTTP/2 stream
// on a TLS forward listener: the stream carries a request to a plain
// origin and its response back, and the tunnel is counted.
func TestForwardConnectH2(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "proxy.test")
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain:%s", r.URL.Path)
	}))
	t.Cleanup(plain.Close)
	_, plainPort, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))
	yaml := `
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      protocols: [h1, h2]
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      forward:
        ports: [%s]
        allow_private: true
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`
	s := proxytest.Start(t, fmt.Sprintf(yaml, cert, key, plainPort))
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "proxy.test", MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}
	pr, pw := io.Pipe()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: s.Addrs()["fwd"]}, Host: "localhost:" + plainPort, Body: pr, Header: http.Header{}}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 {
		t.Fatalf("connect over h2: %d %s", resp.StatusCode, resp.Proto)
	}
	go func() {
		_, _ = fmt.Fprintf(pw, "GET /via-h2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	}()
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), "plain:/via-h2") {
		t.Fatalf("through the h2 tunnel: %q", data)
	}
	_ = pw.Close()
	eventually(t, 15*time.Second, "the h2 tunnel to be counted closed",
		func() bool { return s.Stats().ForwardTunnelsOpen == 0 })
	if sn := s.Stats(); sn.ForwardTunnels != 1 || sn.ForwardTunnelsOpen != 0 || sn.ForwardBytesOut == 0 {
		t.Fatalf("counters: %+v", sn)
	}
	// A refused destination over h2 is a plain 403 on the stream.
	req = &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: s.Addrs()["fwd"]}, Host: "localhost:1", Body: http.NoBody, Header: http.Header{}}
	resp, err = tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("refused over h2: %d", resp.StatusCode)
	}
}

// eventually retries ok until it holds or d passes. A tunnel's close is
// recorded by the goroutine that was pumping it, after the client has
// already seen the connection end, so a test that reads the counter the
// instant it closes its end is racing that goroutine. On an idle
// machine it wins; under the load of the whole suite it does not, which
// is what a flake is. Waiting for the condition rather than for a fixed
// span is the fix, and saying what was waited for is what makes the
// failure readable when the condition never holds.
func eventually(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if ok() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s and it did not happen", d, what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
