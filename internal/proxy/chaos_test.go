package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/testutil"
)

// Chaos tests: the proxy must keep serving through the failures an
// operator sees in production. Each test asserts continuity (no client
// error where the design promises none), bounded recovery and no leak.

// TestChaosReloadStorm applies many concurrent reloads while clients hit
// the proxy: every request must succeed, and the old generations must be
// torn down afterwards.
func TestChaosReloadStorm(t *testing.T) {
	backend := newBackend(t, "a")
	base := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
  shutdown_timeout: 200ms
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
routes:
  - name: %s
    paths: ["/"]
    upstream: app
`
	s, url := startServer(t, fmt.Sprintf(base, backend.addr(), "r0"))
	cfgs := make([]*config.Config, 4)
	for i := range cfgs {
		cfgs[i] = mustParse(t, fmt.Sprintf(base, backend.addr(), fmt.Sprintf("r%d", i)))
	}
	g0 := goruntime.NumGoroutine()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var served, failed atomic.Int64
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Timeout: 5 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := c.Get(url + "/x")
				if err != nil {
					failed.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 {
					failed.Add(1)
				} else {
					served.Add(1)
				}
			}
		}()
	}
	var rw sync.WaitGroup
	for r := 0; r < 10; r++ {
		rw.Add(1)
		go func(r int) {
			defer rw.Done()
			for i := 0; i < 20; i++ {
				if err := s.Reload(cfgs[(r+i)%len(cfgs)]); err != nil {
					t.Error(err)
				}
			}
		}(r)
	}
	rw.Wait()
	close(stop)
	wg.Wait()
	if failed.Load() != 0 || served.Load() == 0 {
		t.Fatalf("served %d failed %d during 200 reloads", served.Load(), failed.Load())
	}
	if s.Generation() < 200 {
		t.Fatalf("generation %d", s.Generation())
	}
	// A leak of one goroutine per generation would show as hundreds; the
	// tolerance covers idle client connections and other tests' goroutines
	// winding down in the same process (the gate runs every package's
	// tests with coverage instrumentation).
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	for goruntime.NumGoroutine() > g0+40 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := goruntime.NumGoroutine(); n > g0+40 {
		t.Fatalf("goroutines %d after storm (baseline %d): old generations not drained", n, g0)
	}
	t.Logf("served %d requests through 200 reloads, generation %d", served.Load(), s.Generation())
}

// flakyRelay forwards TCP to a backend while up and refuses (closes) every
// connection while down, including established ones.
type flakyRelay struct {
	ln   net.Listener
	to   string
	up   atomic.Bool
	mu   sync.Mutex
	open []net.Conn
}

func newFlakyRelay(t *testing.T, to string) *flakyRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &flakyRelay{ln: ln, to: to}
	r.up.Store(true)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !r.up.Load() {
				_ = c.Close()
				continue
			}
			u, err := net.Dial("tcp", to)
			if err != nil {
				_ = c.Close()
				continue
			}
			r.mu.Lock()
			r.open = append(r.open, c, u)
			r.mu.Unlock()
			go func() { _, _ = io.Copy(u, c); _ = u.Close() }()
			go func() { _, _ = io.Copy(c, u); _ = c.Close() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); r.setUp(false) })
	return r
}

func (r *flakyRelay) setUp(up bool) {
	r.up.Store(up)
	if !up {
		r.mu.Lock()
		for _, c := range r.open {
			_ = c.Close()
		}
		r.open = nil
		r.mu.Unlock()
	}
}

func (r *flakyRelay) addr() string { return r.ln.Addr().String() }

// TestChaosUpstreamFlap flaps one of two endpoints while clients send
// idempotent requests: retries and health checks must keep every request
// successful except those already mid-response on the dying endpoint, and
// the endpoint must recover once it is stable.
func TestChaosUpstreamFlap(t *testing.T) {
	a := newBackend(t, "a")
	b := newBackend(t, "b")
	relay := newFlakyRelay(t, a.addr())
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
logging:
  access: {enabled: false}
upstreams:
  - name: app
    retries: 1
    health_check: {path: /healthz, interval: 500ms, timeout: 200ms, healthy_threshold: 1, unhealthy_threshold: 1}
    outlier_ejection: {consecutive_failures: 1, base_ejection_time: 300ms, max_ejection_percent: 50}
    endpoints:
      - {address: %s}
      - {address: %s}
routes:
  - name: all
    paths: ["/"]
    upstream: app
`
	s, url := startServer(t, fmt.Sprintf(yaml, relay.addr(), b.addr()))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var served, failed atomic.Int64
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Timeout: 5 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := c.Get(url + "/x")
				if err != nil {
					failed.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == 200 {
					served.Add(1)
				} else {
					failed.Add(1)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}
	for i := 0; i < 6; i++ {
		relay.setUp(i%2 == 1)
		time.Sleep(300 * time.Millisecond)
	}
	relay.setUp(true)
	close(stop)
	wg.Wait()
	// A request whose response had already started on the endpoint when
	// it died cannot be retried (the client has seen part of it), so at
	// most one failure per client per down transition is acceptable;
	// everything else must be absorbed by retries and health state.
	if maxFailed := int64(4 * 3); failed.Load() > maxFailed || served.Load() < 100 {
		t.Fatalf("served %d failed %d while an endpoint flapped (at most %d in-flight failures allowed)", served.Load(), failed.Load(), maxFailed)
	}
	if st := s.Upstreams()["app"]; st[0].Errors == 0 {
		t.Fatalf("no endpoint errors recorded although the endpoint flapped: %+v", st)
	}
	// Recovery: the flapped endpoint is healthy and not ejected again.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := s.Upstreams()["app"]
		if st[0].Healthy && !st[0].Ejected {
			t.Logf("served %d, endpoint errors %d, ejections %d, recovered", served.Load(), st[0].Errors, st[0].Ejections)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("endpoint did not recover: %+v", s.Upstreams()["app"])
}

// TestChaosUpstreamDiesMidResponse: the backend sends headers and part of
// the body, then its connection dies. The client sees a truncated
// response, the proxy neither hangs nor leaks, and the next request works.
func TestChaosUpstreamDiesMidResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\npartial-body-")
				time.Sleep(50 * time.Millisecond)
				_ = c.Close() // dies mid body
			}()
		}
	}()
	b := newBackend(t, "b")
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
logging:
  access: {enabled: false}
upstreams:
  - name: dying
    endpoints:
      - {address: %s}
  - name: good
    endpoints:
      - {address: %s}
routes:
  - name: dying
    paths: [/die]
    upstream: dying
  - name: good
    paths: ["/"]
    upstream: good
`
	s, url := startServer(t, fmt.Sprintf(yaml, ln.Addr().String(), b.addr()))
	c := &http.Client{Timeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := c.Get(url + "/die")
		if err != nil {
			return // connection level error is acceptable
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err == nil && len(body) == 100000 {
			t.Error("client received a complete body from a dead upstream")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request to the dying upstream hung")
	}
	resp, body := get(t, url+"/ok")
	if resp.StatusCode != 200 || body != "b:/ok" {
		t.Fatalf("after the failure: %d %q", resp.StatusCode, body)
	}
	if s.Stats().Requests < 2 {
		t.Fatalf("requests %d", s.Stats().Requests)
	}
}

// TestChaosLogDiskFull: every log file is /dev/full, so each write fails
// with ENOSPC. Requests must still be served, and the failures counted.
func TestChaosLogDiskFull(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full not available")
	}
	backend := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
logging:
  directory: /dev
  access: {file: full}
  error: {file: full}
  security: {file: full}
  audit: {file: full}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
routes:
  - name: all
    paths: ["/"]
    upstream: app
`
	cfg := mustParse(t, fmt.Sprintf(yaml, backend.addr()))
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logs)
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
		logs.Close()
	})
	url := "http://" + s.Addrs()["main"]
	for i := 0; i < 5; i++ {
		resp, body := get(t, url+"/x")
		if resp.StatusCode != 200 || body != "a:/x" {
			t.Fatalf("request %d with a full log disk: %d %q", i, resp.StatusCode, body)
		}
	}
	resp, _ := get(t, url+"/../etc/passwd")
	_ = resp
	if got := s.Stats().LogWriteErrors; got < 5 {
		t.Fatalf("log_write_errors = %d", got)
	}
	var mb strings.Builder
	if err := s.WriteMetrics(&mb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mb.String(), "xproxy_log_write_errors_total ") {
		t.Fatal("metric missing")
	}
}

// TestChaosCertificateRotation: the certificate files are replaced while
// the listener serves; reload-certs swaps them for new handshakes, and the
// expiry is visible in the metrics before and after.
func TestChaosCertificateRotation(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "tls.test")
	backend := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners:
    - name: tls
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
routes:
  - name: all
    paths: ["/"]
    upstream: app
`
	s, _ := startServer(t, fmt.Sprintf(yaml, cert, key, backend.addr()))
	addr := s.Addrs()["tls"]
	leaf := func() []byte {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "tls.test"}) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0].Raw
	}
	before := leaf()
	exp := s.CertificateExpiry()["tls"]
	if time.Until(exp) < 50*time.Minute || time.Until(exp) > 70*time.Minute {
		t.Fatalf("expiry %v", exp)
	}
	var mb strings.Builder
	if err := s.WriteMetrics(&mb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mb.String(), `xproxy_certificate_expiry_seconds{listener="tls"}`) {
		t.Fatal("expiry metric missing")
	}
	// Replace the files in place (as a renewal hook would) and reload.
	if err := os.MkdirAll(filepath.Join(dir, "new"), 0o700); err != nil {
		t.Fatal(err)
	}
	newCert, newKey := testutil.WriteCert(t, filepath.Join(dir, "new"), "tls.test")
	for _, p := range [][2]string{{newCert, cert}, {newKey, key}} {
		data, err := os.ReadFile(p[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p[1], data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if string(leaf()) != string(before) {
		t.Fatal("certificate changed before reload")
	}
	if err := s.ReloadCertificates(); err != nil {
		t.Fatal(err)
	}
	if string(leaf()) == string(before) {
		t.Fatal("certificate not swapped after reload")
	}
	// A broken file must not take the listener down: reload fails, the
	// previous certificate keeps serving.
	if err := os.WriteFile(cert, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.ReloadCertificates(); err == nil {
		t.Fatal("reload with a broken certificate succeeded")
	}
	if len(leaf()) == 0 {
		t.Fatal("no certificate served after a failed reload")
	}
}
