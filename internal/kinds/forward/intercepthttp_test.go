package forward

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The rules that could only ever have covered the plain path, deciding inside a
// tunnel.
//
// This is the whole point of reading HTTP in there, so the test is written as
// the comparison that matters: the same proxy, the same rules, the same request,
// with intercept.http on and off. With it off the POST goes through, because a
// tunnel says nothing about a method. With it on the POST is refused, and the
// client is told so on the connection it believes is end to end.
func TestTheEgressRulesDecideInsideATunnel(t *testing.T) {
	dir := t.TempDir()
	mitmDir := t.TempDir()
	originCA := testutil.WriteCA(t, dir)
	proxyCA := testutil.WriteCA(t, mitmDir)
	proxyKey := proxyCA.WriteKey(t, mitmDir)
	origin := tlsOriginHandler(t, "localhost", originCA, dir, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/binary" {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		_, _ = fmt.Fprintf(w, "origin:%s:%s", r.Method, r.URL.Path)
	})
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))

	// Two listeners, identical but for intercept.http.
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: read
      address: "127.0.0.1:0"
      kind: forward
      forward: &fwd
        ports: [%s]
        allow_private: true
        sni: enforce
        categories:
          - name: local
            hosts: ["localhost"]
        rules:
          - name: no-executables-back
            action: deny
            response_types: ["application/octet-stream"]
            comment: "CR-7"
          - name: no-uploads
            action: deny
            categories: [local]
            methods: [POST, PUT]
            comment: "CR-7"
          - name: reads-are-fine
            action: allow
            methods: [GET, HEAD]
          - name: tunnels-are-fine
            action: allow
            categories: [local]
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
          http: on
    - name: bytes
      address: "127.0.0.1:0"
      kind: forward
      forward:
        <<: *fwd
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
          http: off
logging: {access: {enabled: false}}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, originPort, proxyCA.Path, proxyKey, originCA.Path, proxyCA.Path, proxyKey, originCA.Path)
	s := proxytest.Start(t, yaml)
	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(proxyCA.Cert)

	// through opens a tunnel, handshakes with the forged certificate, and makes
	// one request inside it.
	through := func(t *testing.T, listener, method, path string, body io.Reader) *http.Response {
		t.Helper()
		c := connectTunnel(t, s.Addrs()[listener], "localhost:"+originPort)
		tc := tls.Client(c, &tls.Config{ServerName: "localhost", RootCAs: proxyPool,
			MinVersion: tls.VersionTLS12})
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			t.Fatalf("handshake inside the tunnel: %v", err)
		}
		t.Cleanup(func() { _ = tc.Close() })
		req, err := http.NewRequestWithContext(t.Context(), method,
			"https://localhost:"+originPort+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "text/plain")
		}
		if err := req.Write(tc); err != nil {
			t.Fatalf("writing the request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tc), req)
		if err != nil {
			t.Fatalf("reading the response: %v", err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("a read inside the tunnel is allowed", func(t *testing.T) {
		resp := through(t, "read", "GET", "/page", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "origin:GET:/page") {
			t.Errorf("body %q: the request did not reach the origin", b)
		}
	})

	t.Run("an upload inside the tunnel is refused", func(t *testing.T) {
		before := s.Counters().RefusalCounts()["forward"]["rule_deny"]
		resp := through(t, "read", "POST", "/page", strings.NewReader("payload"))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "rule_deny") {
			t.Errorf("the refusal does not name the reason: %q", b)
		}
		if strings.Contains(string(b), "origin:POST") {
			t.Error("the request reached the origin")
		}
		if got := s.Counters().RefusalCounts()["forward"]["rule_deny"]; got <= before {
			t.Errorf("rule_deny did not move: %d", got)
		}
	})

	t.Run("a response the rules refuse on the way back", func(t *testing.T) {
		resp := through(t, "read", "GET", "/binary", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(b), "origin:GET:/binary") {
			t.Error("the body was relayed before the policy refused it")
		}
	})

	t.Run("with http off the same upload goes through", func(t *testing.T) {
		// Which is the finding #241 could only document: a tunnel says nothing
		// about a method, so the rule naming one decides nothing here.
		resp := through(t, "bytes", "POST", "/page", strings.NewReader("payload"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want the origin's 200", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "origin:POST:/page") {
			t.Errorf("body %q", b)
		}
	})

	t.Run("the counters say which tunnels were read", func(t *testing.T) {
		sn := s.Stats()
		// Three went through the listener that reads; the fourth went through
		// the one with http off, which is why it is not counted here.
		if sn.InterceptRequests < 3 {
			t.Errorf("%d requests read inside tunnels, want at least 3", sn.InterceptRequests)
		}
		if sn.InterceptBytesOnly < 1 {
			t.Errorf("%d tunnels relayed as bytes, want at least the one with http off", sn.InterceptBytesOnly)
		}
	})

	t.Run("the inventory says which listener reads", func(t *testing.T) {
		// Whether a rule that needs a visible request will ever decide is the
		// one thing a status view of this policy is for, so it is in the view
		// rather than only in the configuration: these two listeners have the
		// same rules and differ in whether anything reads them.
		seen := map[string]*proxy.EgressStatus{}
		for _, v := range s.ListenersReport().Listeners {
			seen[v.Name] = v.Egress
		}
		read, bytes := seen["read"], seen["bytes"]
		if read == nil || bytes == nil {
			t.Fatalf("the view carries no egress section: %+v", seen)
		}
		if read.Rules != 4 || read.RequestOnly != 3 {
			t.Errorf("read: %d rules, %d needing a request; want 4 and 3", read.Rules, read.RequestOnly)
		}
		if !read.Reading {
			t.Error("the listener with http: on does not say it reads")
		}
		if bytes.Reading {
			t.Error("the listener with http: off says it reads")
		}
		if bytes.RequestOnly != read.RequestOnly {
			t.Errorf("bytes: %d rules needing a request, want the same %d -- the rules are the same",
				bytes.RequestOnly, read.RequestOnly)
		}
	})

	t.Run("a Host naming another name is refused", func(t *testing.T) {
		// The SNI check one layer up: the tunnel was opened to localhost and the
		// handshake named localhost, and then the request asks for somewhere
		// else. Under sni: enforce that is the same answer.
		before := s.Counters().RefusalCounts()["forward"]["host_mismatch"]
		c := connectTunnel(t, s.Addrs()["read"], "localhost:"+originPort)
		tc := tls.Client(c, &tls.Config{ServerName: "localhost", RootCAs: proxyPool,
			MinVersion: tls.VersionTLS12})
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tc.Close() }()
		if _, err := io.WriteString(tc, "GET /page HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
		if got := s.Counters().RefusalCounts()["forward"]["host_mismatch"]; got <= before {
			t.Errorf("host_mismatch did not move: %d", got)
		}
	})
}

// tlsOriginHandler is tlsOrigin with a handler of the caller's own, so a test
// can decide what the origin says about each path.
func tlsOriginHandler(t *testing.T, name string, ca *testutil.CA, dir string,
	h http.HandlerFunc) *httptest.Server {
	t.Helper()
	cert, key := ca.Issue(t, dir, name)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// A tunnel whose plaintext is not HTTP is relayed rather than answered with a
// 400, because a database or an SSH session inside TLS is a thing that happens.
func TestATunnelThatIsNotHTTPIsStillRelayed(t *testing.T) {
	dir := t.TempDir()
	mitmDir := t.TempDir()
	originCA := testutil.WriteCA(t, dir)
	proxyCA := testutil.WriteCA(t, mitmDir)
	proxyKey := proxyCA.WriteKey(t, mitmDir)

	// A TLS server that speaks a line protocol of its own.
	cert, key := originCA.Issue(t, dir, "localhost")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				b := make([]byte, 64)
				n, _ := c.Read(b)
				_, _ = c.Write(append([]byte("ECHO "), b[:n]...))
			}()
		}
	}()
	_, originPort, _ := net.SplitHostPort(ln.Addr().String())

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: read
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        categories:
          - name: local
            hosts: ["localhost"]
        rules:
          - name: no-uploads
            action: deny
            methods: [POST]
          - name: everything-else
            action: allow
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
          http: on
logging: {access: {enabled: false}}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, originPort, proxyCA.Path, proxyKey, originCA.Path)
	s := proxytest.Start(t, yaml)
	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(proxyCA.Cert)

	c := connectTunnel(t, s.Addrs()["read"], "localhost:"+originPort)
	tc := tls.Client(c, &tls.Config{ServerName: "localhost", RootCAs: proxyPool,
		MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	if _, err := io.WriteString(tc, "HELLO\n"); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, err := tc.Read(b)
	if err != nil {
		t.Fatalf("reading the line protocol's answer: %v", err)
	}
	if !strings.HasPrefix(string(b[:n]), "ECHO HELLO") {
		t.Errorf("answer %q: the stream was not relayed", b[:n])
	}
	if sn := s.Stats(); sn.InterceptBytesOnly < 1 {
		t.Errorf("%d tunnels relayed as bytes, want the one that was not HTTP", sn.InterceptBytesOnly)
	}
}

// An upgrade through a tunnel that is being read as HTTP.
//
// Past a 101 the connection stops being request-and-response, so the reader has
// to stop reading it that way and relay what follows. This is the path most
// likely to break a site if it is wrong -- a WebSocket through an intercepting
// proxy is ordinary traffic -- and the assertion is that the frames arrive
// unchanged in both directions after the switch.
func TestAnUpgradeThroughAReadTunnelKeepsWorking(t *testing.T) {
	dir := t.TempDir()
	mitmDir := t.TempDir()
	originCA := testutil.WriteCA(t, dir)
	proxyCA := testutil.WriteCA(t, mitmDir)
	proxyKey := proxyCA.WriteKey(t, mitmDir)

	// An origin that answers 101 and then echoes bytes, which is what an
	// upgraded connection looks like from here whatever is framed on it.
	origin := tlsOriginHandler(t, "localhost", originCA, dir, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "line" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = c.Close() }()
		if _, err := io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: line\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			return
		}
		b := make([]byte, 64)
		n, err := c.Read(b)
		if err != nil {
			return
		}
		_, _ = c.Write(append([]byte("ECHO "), b[:n]...))
	})
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: read
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        rules:
          - name: no-uploads
            action: deny
            methods: [POST]
          - name: everything-else
            action: allow
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
          http: on
logging: {access: {enabled: false}}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, originPort, proxyCA.Path, proxyKey, originCA.Path)
	s := proxytest.Start(t, yaml)
	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(proxyCA.Cert)

	c := connectTunnel(t, s.Addrs()["read"], "localhost:"+originPort)
	tc := tls.Client(c, &tls.Config{ServerName: "localhost", RootCAs: proxyPool,
		MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	if _, err := io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: localhost:"+originPort+
		"\r\nUpgrade: line\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading the upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	// And now it is not HTTP any more.
	if _, err := io.WriteString(tc, "HELLO\n"); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, err := br.Read(b)
	if err != nil {
		t.Fatalf("reading what came back after the switch: %v", err)
	}
	if !strings.HasPrefix(string(b[:n]), "ECHO HELLO") {
		t.Errorf("after the upgrade the stream carried %q", b[:n])
	}
}

// A stream rule still sees everything when the tunnel is read as HTTP.
//
// The byte relay fed the whole decrypted stream to YARA. Reading the stream as
// HTTP must not quietly narrow that to the bodies, or turning on a policy
// feature would have turned off a detection one -- so the scanning sits on the
// reads rather than on the message bodies, and this is the assertion that keeps
// it there.
func TestStreamRulesStillSeeAReadTunnel(t *testing.T) {
	dir := t.TempDir()
	mitmDir := t.TempDir()
	originCA := testutil.WriteCA(t, dir)
	proxyCA := testutil.WriteCA(t, mitmDir)
	proxyKey := proxyCA.WriteKey(t, mitmDir)
	var reached atomic.Int64
	origin := tlsOriginHandler(t, "localhost", originCA, dir, func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, "ordinary")
	})
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))

	// One rule, on a header the request carries: a match in the head is the
	// case a body-only scan would miss.
	rules := filepath.Join(dir, "stream.yar")
	if err := os.WriteFile(rules, []byte(`rule marker { strings: $a = "X-Planted: tripwire" condition: $a }`), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: read
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        rules:
          - name: no-uploads
            action: deny
            methods: [POST]
          - name: everything-else
            action: allow
        intercept:
          ca_cert_file: %s
          ca_key_file: %s
          ca_file: %s
          hosts: ["localhost"]
          http: on
          yara: {rules_file: %s, action: close}
logging: {access: {enabled: false}}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, originPort, proxyCA.Path, proxyKey, originCA.Path, rules)
	s := proxytest.Start(t, yaml)
	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(proxyCA.Cert)

	before := s.Stats().YARAMatches
	c := connectTunnel(t, s.Addrs()["read"], "localhost:"+originPort)
	tc := tls.Client(c, &tls.Config{ServerName: "localhost", RootCAs: proxyPool,
		MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	_, _ = io.WriteString(tc, "GET /page HTTP/1.1\r\nHost: localhost:"+originPort+
		"\r\nX-Planted: tripwire\r\n\r\n")
	// The connection ends on the match, so the read ends too. That it ends is
	// half the assertion: the match is seen while the head is being parsed, and
	// a parser that looks ahead past what it needs takes the error the read
	// returned and throws it away -- after which nothing stopped this tunnel
	// and the client waited out its own deadline for an answer. So the read is
	// given far longer than the proxy should need, and how long it actually
	// took is checked.
	_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
	started := time.Now()
	_, _ = io.ReadAll(tc)
	if took := time.Since(started); took > 5*time.Second {
		t.Errorf("the client's read ended after %v: the match did not end the tunnel", took)
	}
	eventually(t, 5*time.Second, "the stream rule to match", func() bool {
		return s.Stats().YARAMatches > before
	})
	// And the other half: a match in a head means the head is not relayed,
	// which is what the same rule did when this tunnel was bytes. The origin
	// was dialled -- that happens before any of this -- and never asked
	// anything.
	if n := reached.Load(); n != 0 {
		t.Errorf("the origin saw %d requests: the matched head was relayed anyway", n)
	}
}

// The first-line check answers from what the client already sent.
//
// A client writes its first line in one go and then waits for an answer, so the
// line is there to be read and nothing follows it. A check that asks for one
// byte more than it has waits out its whole deadline before deciding -- which is
// a second of latency added to every intercepted connection, correct in its
// answer and wrong in every other way. Both answers are asserted here, and so
// is the promptness.
func TestTheFirstLineCheckDoesNotWaitForBytesNobodyIsSending(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first string
		want  bool
	}{
		{"a request line", "GET /page HTTP/1.1\r\n", true},
		{"a line protocol", "HELLO\n", false},
		{"an older request line", "POST /x HTTP/1.0\r\n", true},
		{"a method nobody here has heard of", "PROPFIND /c HTTP/1.1\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			go func() { _, _ = io.WriteString(client, tc.first) }()
			br := bufio.NewReaderSize(server, 4096)
			started := time.Now()
			got := looksLikeHTTP1(br, server, 10*time.Second)
			if took := time.Since(started); took > 2*time.Second {
				t.Errorf("deciding took %v: it waited for a byte nobody is sending", took)
			}
			if got != tc.want {
				t.Errorf("looksLikeHTTP1(%q) = %v, want %v", tc.first, got, tc.want)
			}
		})
	}
}
