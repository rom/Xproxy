package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/testutil"
)

// backend records what it receives.
type backend struct {
	srv   *httptest.Server
	hits  atomic.Int64
	last  atomic.Pointer[http.Request]
	delay time.Duration
}

func newBackend(t *testing.T, name string) *backend {
	b := &backend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		r2 := r.Clone(context.Background())
		body, _ := io.ReadAll(r.Body)
		r2.Header.Set("X-Test-Body", string(body))
		b.last.Store(r2)
		if b.delay > 0 {
			time.Sleep(b.delay)
		}
		w.Header().Set("Server", "secret-backend/9")
		w.Header().Set("X-Backend", name)
		if r.URL.Path == "/status/503" {
			w.WriteHeader(503)
			return
		}
		fmt.Fprintf(w, "%s:%s", name, r.URL.Path)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *backend) addr() string { return strings.TrimPrefix(b.srv.URL, "http://") }

func startServer(t *testing.T, yaml string) (*Server, string) {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	s, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s, "http://" + s.Addrs()["main"]
}

func get(t *testing.T, url string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Add(hdr[i], hdr[i+1])
		}
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const baseYAML = `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
  limits:
    max_body_bytes: 64
logging:
  directory: /tmp
rate_limits:
  - name: tiny
    rate: 1
    burst: 2
  - name: pit
    rate: 1
    burst: 1
    action: tarpit
    tarpit_delay: 300ms
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
  - name: ab
    balancer: round_robin
    retries: 1
    endpoints: [{address: "%s"}, {address: "%s"}]
  - name: dead
    endpoints: [{address: "127.0.0.1:1"}]
  - name: sticky
    affinity: {cookie_name: S}
    endpoints: [{address: "%s"}, {address: "%s"}]
routes:
  - name: api
    hosts: [api.test]
    paths: [/v1]
    strip_prefix: /v1
    upstream: a
    request_headers: {set: {X-Added: yes}, remove: [X-Secret]}
    response_headers: {set: {X-Resp: yes}}
  - name: lb
    hosts: [lb.test]
    upstream: ab
  - name: dead
    hosts: [dead.test]
    upstream: dead
  - name: limited
    hosts: [limited.test]
    rate_limits: [tiny]
    upstream: a
  - name: pit
    hosts: [pit.test]
    rate_limits: [pit]
    upstream: a
  - name: acl
    hosts: [acl.test]
    deny_cidrs: [127.0.0.0/8]
    upstream: a
  - name: ws
    hosts: [ws.test]
    upstream: a
  - name: sticky
    hosts: [sticky.test]
    upstream: sticky
  - name: redirect
    hosts: [redir.test]
    redirect: {to: https://example.com/, status: 302}
  - name: respond
    hosts: [static.test]
    respond: {status: 418, body: teapot}
  - name: post
    hosts: [post.test]
    methods: [POST]
    upstream: a
`

func TestProxyBasics(t *testing.T) {
	a, b := newBackend(t, "a"), newBackend(t, "b")
	s, url := startServer(t, fmt.Sprintf(baseYAML, a.addr(), a.addr(), b.addr(), a.addr(), b.addr()))

	// Routing, strip prefix, header ops, server header removal.
	resp, body := get(t, url+"/v1/users?x=1", "Host", "api.test", "X-Secret", "s")
	if resp.StatusCode != 200 || body != "a:/users" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Server") != "" || resp.Header.Get("X-Resp") != "yes" || resp.Header.Get("X-Request-Id") == "" {
		t.Fatalf("headers: %v", resp.Header)
	}
	last := a.last.Load()
	if last.Header.Get("X-Added") != "yes" || last.Header.Get("X-Secret") != "" {
		t.Fatalf("request header ops: %v", last.Header)
	}
	if last.Header.Get("X-Forwarded-For") != "127.0.0.1" || last.Header.Get("X-Real-Ip") != "127.0.0.1" || last.Host != "api.test" {
		t.Fatalf("forwarding headers: %v host=%s", last.Header, last.Host)
	}
	if last.Header.Get("X-Forwarded-Proto") != "http" {
		t.Fatalf("proto: %v", last.Header)
	}

	// Untrusted peer XFF is not forwarded.
	get(t, url+"/v1/x", "Host", "api.test", "X-Forwarded-For", "6.6.6.6")
	if xff := a.last.Load().Header.Get("X-Forwarded-For"); xff != "127.0.0.1" {
		t.Fatalf("forged XFF passed through: %q", xff)
	}

	// Path traversal cannot escape the route; /v1/../v1/x routes to api.
	resp, _ = get(t, url+"/v1/../nothing", "Host", "api.test")
	if resp.StatusCode != 404 {
		t.Fatalf("traversal: %d", resp.StatusCode)
	}

	// No route.
	resp, _ = get(t, url+"/", "Host", "unknown.test")
	if resp.StatusCode != 404 {
		t.Fatalf("no route: %d", resp.StatusCode)
	}
	// Method filter.
	resp, _ = get(t, url+"/", "Host", "post.test")
	if resp.StatusCode != 404 {
		t.Fatalf("method filter: %d", resp.StatusCode)
	}

	// Round robin across two backends.
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		_, body := get(t, url+"/", "Host", "lb.test")
		seen[body[:1]]++
	}
	if seen["a"] != 2 || seen["b"] != 2 {
		t.Fatalf("round robin: %v", seen)
	}

	// Dead upstream -> 502, then fast.
	resp, _ = get(t, url+"/", "Host", "dead.test")
	if resp.StatusCode != 502 {
		t.Fatalf("dead: %d", resp.StatusCode)
	}

	// Rate limit: burst 2 then 429.
	for i := 0; i < 2; i++ {
		if resp, _ := get(t, url+"/", "Host", "limited.test"); resp.StatusCode != 200 {
			t.Fatalf("limited %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ = get(t, url+"/", "Host", "limited.test")
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("rate limit: %d %v", resp.StatusCode, resp.Header)
	}

	// Tarpit: second request is delayed then 429.
	get(t, url+"/", "Host", "pit.test")
	start := time.Now()
	resp, _ = get(t, url+"/", "Host", "pit.test")
	if resp.StatusCode != 429 || time.Since(start) < 250*time.Millisecond {
		t.Fatalf("tarpit: %d after %v", resp.StatusCode, time.Since(start))
	}

	// ACL.
	resp, _ = get(t, url+"/", "Host", "acl.test")
	if resp.StatusCode != 403 {
		t.Fatalf("acl: %d", resp.StatusCode)
	}

	// WebSocket refused unless enabled.
	resp, _ = get(t, url+"/", "Host", "ws.test", "Connection", "Upgrade", "Upgrade", "websocket")
	if resp.StatusCode != 403 {
		t.Fatalf("ws: %d", resp.StatusCode)
	}

	// Redirect and respond.
	resp, _ = get(t, url+"/", "Host", "redir.test")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "https://example.com/" {
		t.Fatalf("redirect: %d %v", resp.StatusCode, resp.Header)
	}
	resp, body = get(t, url+"/", "Host", "static.test")
	if resp.StatusCode != 418 || body != "teapot" {
		t.Fatalf("respond: %d %q", resp.StatusCode, body)
	}

	// Body limit.
	req, _ := http.NewRequest("POST", url+"/", strings.NewReader(strings.Repeat("x", 100)))
	req.Host = "post.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("body limit: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", url+"/", strings.NewReader("small"))
	req.Host = "post.test"
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 || a.last.Load().Header.Get("X-Test-Body") != "small" {
		t.Fatalf("post: %d", resp.StatusCode)
	}

	// Sticky sessions.
	resp, body = get(t, url+"/", "Host", "sticky.test")
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "S" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatalf("no affinity cookie: %v", resp.Header)
	}
	first := body[:1]
	for i := 0; i < 4; i++ {
		_, body := get(t, url+"/", "Host", "sticky.test", "Cookie", "S="+cookie.Value)
		if body[:1] != first {
			t.Fatalf("affinity broken: %s vs %s", body, first)
		}
	}

	// Long URI.
	resp, _ = get(t, url+"/"+strings.Repeat("a", 9000), "Host", "api.test")
	if resp.StatusCode != 414 {
		t.Fatalf("uri: %d", resp.StatusCode)
	}

	st := s.Stats()
	if st.Requests == 0 || st.DeniedRateLimit != 1 || st.Tarpitted != 1 || st.DeniedACL != 1 || st.DeniedWebSocket != 1 || st.DeniedBodySize != 1 || st.DeniedURILength != 1 {
		t.Fatalf("stats: %+v", st)
	}
	ups := s.Upstreams()
	if len(ups["ab"]) != 2 || ups["a"][0].Requests == 0 {
		t.Fatalf("upstream stats: %v", ups)
	}
}

func TestRetryOnDeadEndpoint(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    retries: 1
    endpoints: [{address: "127.0.0.1:1"}, {address: "%s"}]
    outlier_ejection: {consecutive_failures: 1, base_ejection_time: 1m, max_ejection_percent: 50}
routes:
  - name: r
    upstream: u
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	for i := 0; i < 4; i++ {
		resp, body := get(t, url+"/x")
		if resp.StatusCode != 200 || body != "a:/x" {
			t.Fatalf("retry %d: %d %q", i, resp.StatusCode, body)
		}
	}
	ups := s.Upstreams()["u"]
	if !ups[0].Ejected {
		t.Fatalf("dead endpoint not ejected: %+v", ups)
	}
	// POST is not replayed.
	req, _ := http.NewRequest("POST", url+"/p", strings.NewReader("body"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 { // dead endpoint is ejected so it goes to a
		t.Fatalf("post after ejection: %d", resp.StatusCode)
	}
}

func TestReload(t *testing.T) {
	a, b := newBackend(t, "a"), newBackend(t, "b")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: u
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	if _, body := get(t, url+"/"); body != "a:/" {
		t.Fatal(body)
	}
	cfg2, err := config.Parse([]byte(fmt.Sprintf(yaml, b.addr())))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg2); err != nil {
		t.Fatal(err)
	}
	if _, body := get(t, url+"/"); body != "b:/" {
		t.Fatal(body)
	}
	// Listener change is refused.
	cfg3, _ := config.Parse([]byte(strings.Replace(fmt.Sprintf(yaml, b.addr()), "127.0.0.1:0", "127.0.0.1:1", 1)))
	if err := s.Reload(cfg3); err == nil {
		t.Fatal("listener change accepted")
	}
	if s.Stats().Reloads != 1 || s.Stats().ReloadFailures != 1 {
		t.Fatalf("%+v", s.Stats())
	}
}

func TestTLSAndRedirect(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "tls.test")
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
      redirect_to_https: true
    - name: tls
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
        min_version: "1.3"
upstreams:
  - name: u
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: u
`
	s, url := startServer(t, fmt.Sprintf(yaml, cert, key, a.addr()))
	resp, _ := get(t, url+"/p?q=1", "Host", "tls.test")
	if resp.StatusCode != 308 || resp.Header.Get("Location") != "https://tls.test/p?q=1" {
		t.Fatalf("redirect: %d %v", resp.StatusCode, resp.Header)
	}
	tlsAddr := s.Addrs()["tls"]
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "tls.test"}, ForceAttemptHTTP2: true}
	c := &http.Client{Transport: tr}
	resp, err := c.Get("https://" + tlsAddr + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "a:/x" || resp.ProtoMajor != 2 || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("tls: %q proto=%s ver=%x", body, resp.Proto, resp.TLS.Version)
	}
	if a.last.Load().Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatal("proto header")
	}
	// TLS 1.2 refused.
	tr12 := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}}
	if _, err := (&http.Client{Transport: tr12}).Get("https://" + tlsAddr + "/"); err == nil {
		t.Fatal("TLS 1.2 accepted with min 1.3")
	}
}

func TestConnectionLimits(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  limits: {max_connections: 2, max_connections_per_ip: 2, max_concurrent_requests: 1}
upstreams:
  - name: u
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: u
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	a.delay = 300 * time.Millisecond
	addr := strings.TrimPrefix(url, "http://")
	buf := make([]byte, 64)

	// Concurrency: with one request in flight the second gets 503.
	c1, _ := net.Dial("tcp", addr)
	c2, _ := net.Dial("tcp", addr)
	fmt.Fprintf(c1, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	time.Sleep(50 * time.Millisecond)
	fmt.Fprintf(c2, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := c2.Read(buf)
	if !strings.Contains(string(buf[:n]), "503") {
		t.Fatalf("concurrency: %q", buf[:n])
	}
	c1.Close()
	c2.Close()
	time.Sleep(400 * time.Millisecond)

	// Connections: two idle connections fill the table, the third is dropped
	// immediately.
	i1, _ := net.Dial("tcp", addr)
	i2, _ := net.Dial("tcp", addr)
	defer i1.Close()
	defer i2.Close()
	time.Sleep(50 * time.Millisecond)
	c3, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	_, err = c3.Read(buf)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("third connection was not dropped: err=%v after %v", err, time.Since(start))
	}
	c3.Close()
	if st := s.Stats(); st.RejectedConns != 1 || st.DeniedConcurrency != 1 || st.OpenConnections != 2 {
		t.Fatalf("%+v", st)
	}
}

func TestSlowHeaderTimeout(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  limits: {read_header_timeout: 200ms}
upstreams:
  - name: u
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: u
`
	_, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	c, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n")
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	buf := make([]byte, 128)
	n, _ := c.Read(buf)
	if time.Since(start) > time.Second {
		t.Fatal("slowloris connection not closed in time")
	}
	if n > 0 && !strings.Contains(string(buf[:n]), "408") {
		t.Fatalf("unexpected response %q", buf[:n])
	}
}
