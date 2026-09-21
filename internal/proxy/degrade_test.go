package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The slow lane. What matters is that the client is served correctly —
// there is nothing to report as broken and nothing to tune against —
// and that it takes the time the level says.

const degradeYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  limits: {max_tarpits: 16}
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
degradation:
  levels:
%s
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: trap, paths: [/.env], honeypot: {decoy: env, mark: 1h}}
  - {name: app, paths: [/], upstream: app}
`

func TestDegradationShapesTheMarked(t *testing.T) {
	a := newBackend(t, "a")
	levels := `    - name: marked
      marked: true
      bytes_per_second: 4096
      close: true`
	s, url := startServer(t, fmt.Sprintf(degradeYAML, levels, a.addr()))

	// An unmarked client is untouched: full speed, keep-alive intact.
	start := time.Now()
	resp, body := get(t, url+"/page", "X-Forwarded-For", "198.51.100.30")
	if resp.StatusCode != 200 || body == "" {
		t.Fatalf("clean client: %d %q", resp.StatusCode, body)
	}
	if resp.Close {
		t.Error("a clean client had its connection closed")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("a clean request took %s", took)
	}
	if n := s.Stats().Degraded; n != 0 {
		t.Errorf("degraded %d clean requests", n)
	}

	// The same client, once it has touched a decoy.
	if resp, _ := get(t, url+"/.env", "X-Forwarded-For", "198.51.100.31"); resp.StatusCode != 200 {
		t.Fatalf("decoy: %d", resp.StatusCode)
	}
	resp, body = get(t, url+"/page", "X-Forwarded-For", "198.51.100.31")
	if resp.StatusCode != 200 {
		t.Fatalf("marked client: %d", resp.StatusCode)
	}
	// Served, correctly: the body is the one the origin wrote.
	if !strings.Contains(body, "a:/page") {
		t.Errorf("the marked client got %q, want the real answer", body)
	}
	// Go's client reports this as Close rather than a header: the
	// server sends Connection: close and the transport records that the
	// connection is not reusable, which is the property that costs the
	// scanner a handshake per request.
	if !resp.Close {
		t.Error("the marked client kept its connection")
	}
	if n := s.Stats().Degraded; n != 1 {
		t.Errorf("degraded = %d, want 1", n)
	}
	if st := s.Degradation(); len(st) != 1 || st[0].Applied != 1 || st[0].Name != "marked" {
		t.Errorf("status %+v", st)
	}
}

// The shaping is the point: a body that would arrive instantly takes
// the time the rate implies.
func TestDegradationRateIsReal(t *testing.T) {
	big := strings.Repeat("x", 64<<10)
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, big)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	levels := `    - name: slow
      client_cidrs: ["198.51.100.40/32"]
      bytes_per_second: 32768`
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
degradation:
  levels:
%s
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: app, paths: [/], upstream: app}
`, levels, ln.Addr().String())
	_, url := startServer(t, yaml)

	// The fast lane first, as the control.
	start := time.Now()
	_, body := get(t, url+"/big", "X-Forwarded-For", "198.51.100.41")
	fast := time.Since(start)
	if len(body) != len(big) {
		t.Fatalf("clean client got %d bytes, want %d", len(body), len(big))
	}

	start = time.Now()
	_, body = get(t, url+"/big", "X-Forwarded-For", "198.51.100.40")
	slow := time.Since(start)
	if len(body) != len(big) {
		t.Fatalf("shaped client got %d bytes, want the whole body", len(body))
	}
	// 64 KiB at 32 KiB/s is about two seconds, less the first second's
	// allowance: the assertion is that it is slower by a margin no
	// scheduler noise explains, not that it is exactly one second.
	if slow < 500*time.Millisecond {
		t.Errorf("the shaped response took %s (clean: %s), which is not shaped", slow, fast)
	}
	if slow > 10*time.Second {
		t.Errorf("the shaped response took %s, far past the rate", slow)
	}
}

func TestDegradationDelayHoldsTheResponse(t *testing.T) {
	a := newBackend(t, "a")
	levels := `    - name: held
      client_cidrs: ["198.51.100.50/32"]
      delay: 300ms`
	_, url := startServer(t, fmt.Sprintf(degradeYAML, levels, a.addr()))
	start := time.Now()
	if resp, _ := get(t, url+"/page", "X-Forwarded-For", "198.51.100.50"); resp.StatusCode != 200 {
		t.Fatalf("held request: %d", resp.StatusCode)
	}
	if took := time.Since(start); took < 250*time.Millisecond {
		t.Errorf("the held response took %s, want the configured 300ms", took)
	}
	start = time.Now()
	if resp, _ := get(t, url+"/page", "X-Forwarded-For", "198.51.100.51"); resp.StatusCode != 200 {
		t.Fatal("clean request")
	}
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Errorf("a clean request was held for %s", took)
	}
}

// The first level that admits the request decides, so the narrow one
// goes first.
func TestDegradationFirstLevelWins(t *testing.T) {
	a := newBackend(t, "a")
	levels := `    - name: narrow
      client_cidrs: ["198.51.100.60/32"]
      bytes_per_second: 4096
    - name: wide
      client_cidrs: ["198.51.100.0/24"]
      bytes_per_second: 65536`
	s, url := startServer(t, fmt.Sprintf(degradeYAML, levels, a.addr()))
	if resp, _ := get(t, url+"/page", "X-Forwarded-For", "198.51.100.60"); resp.StatusCode != 200 {
		t.Fatal("request")
	}
	st := s.Degradation()
	if len(st) != 2 || st[0].Applied != 1 || st[1].Applied != 0 {
		t.Errorf("levels %+v, want the narrow one to have taken it", st)
	}
}
