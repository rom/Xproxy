package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	goruntime "runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
)

// scaleYAML generates a configuration with `hosts` virtual hosts spread
// over `ups` upstreams of `per` endpoints each. Endpoint addresses are
// distinct loopback addresses (127.x.y.z all reach the backend bound on
// the wildcard address), so the proxy sees `ups*per` distinct endpoints.
func scaleYAML(hosts, ups, per, port int, health bool) string {
	var b strings.Builder
	b.WriteString("version: 1\nserver:\n  listeners:\n    - name: main\n      address: \"127.0.0.1:0\"\n")
	b.WriteString("logging:\n  access: {enabled: false}\n")
	b.WriteString("upstreams:\n")
	n := 0
	for u := 0; u < ups; u++ {
		fmt.Fprintf(&b, "  - name: u%d\n    balancer: round_robin\n", u)
		if health {
			b.WriteString("    health_check: {path: /healthz, interval: 2s, timeout: 500ms}\n")
		}
		b.WriteString("    endpoints:\n")
		for e := 0; e < per; e++ {
			n++
			fmt.Fprintf(&b, "      - {address: \"127.%d.%d.%d:%d\"}\n", 1+n/65536, (n/256)%256, 1+n%255, port)
		}
	}
	b.WriteString("routes:\n")
	for h := 0; h < hosts; h++ {
		fmt.Fprintf(&b, "  - name: r%d\n    hosts: [site-%d.example.test]\n    paths: [\"/\", \"/api/\"]\n    upstream: u%d\n", h, h, h%ups)
	}
	return b.String()
}

// scaleBackend runs the backend in a child process (this test binary with
// XPROXY_SCALE_BACKEND set, see TestScaleBackendProcess) so that the
// proxy's idle upstream connections and the backend's accepted sockets do
// not share one descriptor limit. The child binds the wildcard address so
// every 127.x.y.z endpoint reaches it, and echoes the Host header.
func scaleBackend(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScaleBackendProcess$") //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(), "XPROXY_SCALE_BACKEND=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })
	var port int
	if _, err := fmt.Fscanf(stdout, "port %d\n", &port); err != nil {
		t.Fatalf("backend did not report its port: %v", err)
	}
	return port
}

// TestScaleBackendProcess is the child of scaleBackend; it is a no-op in a
// normal test run.
func TestScaleBackendProcess(t *testing.T) {
	if os.Getenv("XPROXY_SCALE_BACKEND") == "" {
		t.Skip("backend helper")
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("X-Backend-Host", r.Host)
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	fmt.Printf("port %d\n", ln.Addr().(*net.TCPAddr).Port)
	_, _ = io.Copy(io.Discard, os.Stdin) // until the parent closes our stdin
	_ = srv.Close()
}

func raiseFDLimit(t *testing.T, want uint64) {
	t.Helper()
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Cur >= want {
		return
	}
	rl.Cur = min(want, rl.Max)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		t.Skipf("cannot raise the file descriptor limit to %d: %v", want, err)
	}
	if rl.Cur < want {
		t.Skipf("file descriptor hard limit %d is below %d", rl.Max, want)
	}
}

func fds() int { return openFDs() }

func heapInUse() uint64 {
	goruntime.GC()
	var ms goruntime.MemStats
	goruntime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// TestScale loads a large configuration, checks routing across it,
// reloads it, reads the management views and drives traffic, reporting
// timings and sizes. The default size runs in every test run; set
// XPROXY_SCALE=full for the 1.0 target (1000 hosts, 10 000 endpoints),
// which needs a raised file descriptor limit and a few seconds more.
func TestScale(t *testing.T) {
	hosts, ups, per := 100, 50, 20
	load := 2 * time.Second
	if os.Getenv("XPROXY_SCALE") == "full" {
		hosts, ups, per = 1000, 500, 20
		load = 5 * time.Second
	} else if testing.Short() {
		t.Skip("short mode")
	}
	endpoints := ups * per
	raiseFDLimit(t, uint64(endpoints+4096)) //nolint:gosec // test sizes

	port := scaleBackend(t)
	yaml := scaleYAML(hosts, ups, per, port, true)
	t.Logf("configuration: %d hosts, %d upstreams, %d endpoints, %d KiB of YAML", hosts, ups, endpoints, len(yaml)/1024)

	base := heapInUse()
	g0 := goruntime.NumGoroutine()

	t0 := time.Now()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	parse := time.Since(t0)

	t0 = time.Now()
	s, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	start := time.Since(t0)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	loaded := heapInUse()
	t.Logf("parse+validate %v, build+start %v, heap %d MiB (+%d MiB), goroutines %d (+%d), fds %d",
		parse.Round(time.Millisecond), start.Round(time.Millisecond), loaded>>20, (loaded-base)>>20, goruntime.NumGoroutine(), goruntime.NumGoroutine()-g0, fds())
	if parse+start > 20*time.Second {
		t.Fatalf("load took %v", parse+start)
	}
	if got := goruntime.NumGoroutine() - g0; got > 3*endpoints+500 {
		t.Fatalf("goroutines grew by %d for %d endpoints", got, endpoints)
	}

	addr := s.Addrs()["main"]
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256, MaxIdleConns: 256}}
	req := func(host, path string) (*http.Response, error) {
		r, _ := http.NewRequestWithContext(context.Background(), "GET", "http://"+addr+path, nil)
		r.Host = host
		return client.Do(r)
	}
	// Routing across the whole table: first, middle, last and a miss.
	for _, h := range []int{0, hosts / 2, hosts - 1} {
		host := fmt.Sprintf("site-%d.example.test", h)
		resp, err := req(host, "/api/x")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("X-Backend-Host") != host {
			t.Fatalf("host %s: %d %q", host, resp.StatusCode, resp.Header.Get("X-Backend-Host"))
		}
	}
	resp, err := req("nope.example.test", "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unknown host: %d", resp.StatusCode)
	}

	// Management views.
	t0 = time.Now()
	ub, _ := json.Marshal(s.Upstreams())
	t.Logf("upstreams view: %d KiB in %v", len(ub)/1024, time.Since(t0).Round(time.Millisecond))
	t0 = time.Now()
	var mb strings.Builder
	if err := s.WriteMetrics(&mb); err != nil {
		t.Fatal(err)
	}
	t.Logf("metrics exposition with endpoint series: %d KiB, %d lines in %v", mb.Len()/1024, strings.Count(mb.String(), "\n"), time.Since(t0).Round(time.Millisecond))

	// Reload with one route renamed and endpoint series off: a full
	// generation rebuild.
	yaml2 := strings.Replace(yaml, "name: r0\n", "name: r0-renamed\n", 1) + "metrics:\n  endpoint_series: false\n"
	cfg2, err := config.Parse([]byte(yaml2))
	if err != nil {
		t.Fatal(err)
	}
	t0 = time.Now()
	if err := s.Reload(cfg2); err != nil {
		t.Fatal(err)
	}
	reload := time.Since(t0)
	t.Logf("reload %v, generation %d, fds %d", reload.Round(time.Millisecond), s.Generation(), fds())
	t0 = time.Now()
	mb.Reset()
	if err := s.WriteMetrics(&mb); err != nil {
		t.Fatal(err)
	}
	t.Logf("metrics exposition without endpoint series: %d KiB, %d lines in %v", mb.Len()/1024, strings.Count(mb.String(), "\n"), time.Since(t0).Round(time.Millisecond))
	if reload > 20*time.Second {
		t.Fatalf("reload took %v", reload)
	}
	deadline := time.Now().Add(15 * time.Second)
	for goruntime.NumGoroutine()-g0 > 3*endpoints+500 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := goruntime.NumGoroutine() - g0; got > 3*endpoints+500 {
		t.Fatalf("goroutines after reload: +%d (old generation not drained)", got)
	}

	// Throughput: keep-alive workers over random hosts.
	workers := 4 * goruntime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	var count atomic.Int64
	var mu sync.Mutex
	var lat []time.Duration
	stop := time.Now().Add(load)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4}}
			var local []time.Duration
			for time.Now().Before(stop) {
				host := fmt.Sprintf("site-%d.example.test", rand.IntN(hosts)) //nolint:gosec // load pattern
				r, _ := http.NewRequestWithContext(context.Background(), "GET", "http://"+addr+"/", nil)
				r.Host = host
				st := time.Now()
				resp, err := c.Do(r)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 {
					t.Errorf("status %d", resp.StatusCode)
					return
				}
				count.Add(1)
				if len(local) < 20000 {
					local = append(local, time.Since(st))
				}
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(lat) == 0 {
		t.Fatalf("no requests completed (%d counted)", count.Load())
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration { return lat[int(float64(len(lat)-1)*p)] }
	rps := float64(count.Load()) / load.Seconds()
	t.Logf("throughput: %.0f req/s over %v with %d workers on %d cores; latency p50 %v p90 %v p99 %v",
		rps, load, workers, goruntime.GOMAXPROCS(0), pct(0.5).Round(10*time.Microsecond), pct(0.9).Round(10*time.Microsecond), pct(0.99).Round(10*time.Microsecond))
	if count.Load() < 100 {
		t.Fatalf("only %d requests completed", count.Load())
	}
	after := heapInUse()
	t.Logf("heap after load %d MiB, goroutines %d, fds %d, stats: requests %d, 2xx %d, no_healthy %d, upstream_errors %d",
		after>>20, goruntime.NumGoroutine(), fds(), s.Stats().Requests, s.Stats().Responses2xx, s.Stats().UpstreamNoHealthy, s.Stats().UpstreamErrors)
	if s.Stats().UpstreamNoHealthy != 0 {
		t.Fatalf("health checks marked endpoints unhealthy: %d requests found none", s.Stats().UpstreamNoHealthy)
	}
}
