package upstream

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// socketServer serves HTTP on a Unix domain socket in a temporary
// directory and answers with its own path, so a test can tell which
// socket answered.
func socketServer(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xpsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// Short path: a Unix socket address is bounded at about a hundred
	// bytes, and a long temporary directory plus a long name overruns it
	// with an error that says nothing useful.
	path := filepath.Join(dir, name)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ //nolint:gosec // a test server; the timeouts are the proxy's business
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "socket:%s:%s:%s", name, r.Host, r.URL.Path)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return path
}

// A pool of socket endpoints reaches them, and what the service sees is
// the client's own Host rather than the synthetic authority the URL
// needed: a backend that routes on Host must keep working behind a
// socket.
func TestSocketEndpointIsReached(t *testing.T) {
	path := socketServer(t, "a.sock")
	c := testCfg("round_robin", "unix:"+path)
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	e := p.endpoints()[0]
	if e.Socket() != path {
		t.Fatalf("socket %q, want %q", e.Socket(), path)
	}
	if e.URLHost() == e.Address {
		t.Fatal("a socket endpoint must wear a synthetic authority in a URL, not its own address")
	}
	if !strings.HasSuffix(e.URLHost(), ".socket.invalid:80") {
		t.Fatalf("authority %q: it must be unresolvable, so that a dialler which ignored the socket fails loudly", e.URLHost())
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+e.URLHost()+"/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.example" // what a client asked for
	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 128)
	n, _ := resp.Body.Read(buf)
	if got := string(buf[:n]); got != "socket:a.sock:app.example:/hello" {
		t.Fatalf("got %q", got)
	}
}

// Two sockets in one pool are two endpoints, each dialled at its own
// path: the authority has to be derived from the path, or one would
// answer for the other.
func TestTwoSocketEndpointsStaySeparate(t *testing.T) {
	a := socketServer(t, "a.sock")
	b := socketServer(t, "b.sock")
	c := testCfg("round_robin", "unix:"+a)
	c.Endpoints = append(c.Endpoints, config.Endpoint{Address: "unix:" + b, Weight: 1})
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		if e == nil {
			t.Fatal("no endpoint")
		}
		req, err := http.NewRequest(http.MethodGet, "http://"+e.URLHost()+"/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := p.Transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 128)
		n, _ := resp.Body.Read(buf)
		_ = resp.Body.Close()
		parts := strings.Split(string(buf[:n]), ":")
		if len(parts) > 1 {
			seen[parts[1]] = true
		}
	}
	if !seen["a.sock"] || !seen["b.sock"] {
		t.Fatalf("round robin over two sockets reached %v", seen)
	}
}

// A tcp health check on a socket endpoint connects to the socket. A
// probe that dialled a port instead would be proving something about a
// path nothing uses.
func TestSocketEndpointHealthCheck(t *testing.T) {
	dir, err := os.MkdirTemp("", "xpsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	c := testCfg("round_robin", "unix:"+path)
	c.HealthCheck = l4HealthCheck("tcp")
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	p.Start()
	defer p.Stop()
	e := p.endpoints()[0]
	waitHealthy(t, e, true, "a listening socket")
	_ = ln.Close()
	_ = os.Remove(path)
	waitHealthy(t, e, false, "a socket that is gone")
}

// The authority is stable for a path and different between paths, which
// is what keeps net/http's idle connection pool from mixing two
// backends.
func TestSocketAuthorityIsStableAndDistinct(t *testing.T) {
	a1 := urlAuthority("/run/app.sock")
	a2 := urlAuthority("/run/app.sock")
	b := urlAuthority("/run/other.sock")
	if a1 != a2 {
		t.Fatalf("the same path produced %q and %q", a1, a2)
	}
	if a1 == b {
		t.Fatalf("two paths produced the same authority %q", a1)
	}
}

// A path that is not a socket address is not one: the prefix alone does
// not make it one.
func TestSocketPathParsing(t *testing.T) {
	for _, c := range []struct {
		in   string
		path string
		ok   bool
	}{
		{"unix:/run/app.sock", "/run/app.sock", true},
		{"unix:", "", false},
		{"127.0.0.1:8080", "", false},
		{"/run/app.sock", "", false},
	} {
		path, ok := SocketPath(c.in)
		if ok != c.ok || path != c.path {
			t.Errorf("SocketPath(%q) = %q, %v; want %q, %v", c.in, path, ok, c.path, c.ok)
		}
	}
}

// A socket endpoint and a host endpoint in one pool both work, which is
// the migration case: a service moving from a port to a socket.
func TestSocketAndHostEndpointsTogether(t *testing.T) {
	path := socketServer(t, "mix.sock")
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { //nolint:gosec // test server
		fmt.Fprint(w, "host")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(tcpLn) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := testCfg("round_robin", "unix:"+path)
	c.Endpoints = append(c.Endpoints, config.Endpoint{Address: tcpLn.Addr().String(), Weight: 1})
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	answers := map[string]bool{}
	for i := 0; i < 4; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		req, err := http.NewRequest(http.MethodGet, "http://"+e.URLHost()+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := p.Transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("endpoint %s: %v", e.Address, err)
		}
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		_ = resp.Body.Close()
		answers[strings.Split(string(buf[:n]), ":")[0]] = true
	}
	if !answers["socket"] || !answers["host"] {
		t.Fatalf("a mixed pool answered %v", answers)
	}
}
