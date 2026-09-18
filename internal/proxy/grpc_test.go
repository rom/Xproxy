package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/upstream"
)

// grpcBackend is a hand rolled gRPC server over h2c: an echo method, a
// failing method, a slow method and the standard health service.
func grpcBackend(t *testing.T, serving *atomic.Bool) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		w.Header().Add("Trailer", "Grpc-Message")
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case upstream.HealthCheckPath:
			st := 2 // NOT_SERVING
			if serving.Load() {
				st = 1
			}
			w.WriteHeader(200)
			_, _ = w.Write(upstream.EncodeHealthCheckResponse(st))
			w.Header().Set("Grpc-Status", "0")
		case "/echo.Echo/Say":
			w.Header().Set("X-Served-By", "backend")
			w.WriteHeader(200)
			_, _ = w.Write(body)
			w.Header().Set("Grpc-Status", "0")
		case "/echo.Echo/Fail":
			w.Header().Set("Grpc-Status", "5")
			w.Header().Set("Grpc-Message", "not found")
			w.WriteHeader(200)
		case "/echo.Echo/Slow":
			select {
			case <-time.After(500 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(200)
			w.Header().Set("Grpc-Status", "0")
		default:
			w.Header().Set("Grpc-Status", "12")
			w.WriteHeader(200)
		}
	})
	srv := httptest.NewUnstartedServer(h)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func h2cClient() *http.Client {
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func grpcCall(t *testing.T, c *http.Client, url string, msg []byte, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(upstream.FrameGRPC(msg)))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

// TestGRPC routes gRPC requests by service over h2c on both sides,
// relays trailers, answers proxy errors as gRPC statuses, honours the
// client's grpc-timeout, counts statuses, and ejects a backend whose
// health service reports NOT_SERVING.
func TestGRPC(t *testing.T) {
	var serving atomic.Bool
	serving.Store(true)
	be := grpcBackend(t, &serving)
	yaml := `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0", h2c: true}
logging:
  access: {enabled: false}
upstreams:
  - name: echo
    h2c: true
    endpoints: [{address: %s}]
    health_check: {type: grpc, interval: 500ms, timeout: 300ms, healthy_threshold: 1, unhealthy_threshold: 1}
routes:
  - name: web
    hosts: [web.test]
    paths: [/]
    respond: {status: 200, body: web}
  - name: echo
    grpc: {services: [echo.Echo]}
    upstream: echo
    timeout: 2s
`
	s, base := startServer(t, fmt.Sprintf(yaml, strings.TrimPrefix(be.URL, "http://")))
	c := h2cClient()

	resp, body := grpcCall(t, c, base+"/echo.Echo/Say", []byte("hello"))
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 || !bytes.Equal(body, upstream.FrameGRPC([]byte("hello"))) ||
		resp.Trailer.Get("Grpc-Status") != "0" || resp.Header.Get("X-Served-By") != "backend" {
		t.Fatalf("echo: %d %s %q trailer=%v hdr=%v", resp.StatusCode, resp.Proto, body, resp.Trailer, resp.Header)
	}
	// A trailers-only error from the backend passes through.
	resp, _ = grpcCall(t, c, base+"/echo.Echo/Fail", nil)
	if resp.StatusCode != 200 || resp.Header.Get("Grpc-Status") != "5" {
		t.Fatalf("fail: %d %v", resp.StatusCode, resp.Header)
	}
	// An unknown service has no route: UNIMPLEMENTED as a gRPC status.
	resp, body = grpcCall(t, c, base+"/other.Svc/M", nil)
	if resp.StatusCode != 200 || resp.Header.Get("Grpc-Status") != "12" || len(body) != 0 || !strings.Contains(resp.Header.Get("Grpc-Message"), "404") {
		t.Fatalf("no route: %d %v %q", resp.StatusCode, resp.Header, body)
	}
	// A plain request to a gRPC path does not match the gRPC route.
	pr, err := c.Post(base+"/echo.Echo/Say", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = pr.Body.Close()
	if pr.StatusCode != 404 || pr.Header.Get("Grpc-Status") != "" {
		t.Fatalf("plain request on the gRPC path: %d %v", pr.StatusCode, pr.Header)
	}
	// The ordinary route still serves ordinary requests over h2c.
	req, _ := http.NewRequest(http.MethodGet, base+"/", nil)
	req.Host = "web.test"
	wr, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	wb, _ := io.ReadAll(wr.Body)
	_ = wr.Body.Close()
	if string(wb) != "web" || wr.ProtoMajor != 2 {
		t.Fatalf("web over h2c: %q %s", wb, wr.Proto)
	}
	// The client's deadline is shorter than the route timeout.
	resp, _ = grpcCall(t, c, base+"/echo.Echo/Slow", nil, "Grpc-Timeout", "100m")
	if resp.StatusCode != 200 || resp.Header.Get("Grpc-Status") != "4" {
		t.Fatalf("deadline: %d %v", resp.StatusCode, resp.Header)
	}
	sn := s.Stats()
	if sn.GRPCStatus[0] != 1 || sn.GRPCStatus[5] != 1 || sn.GRPCStatus[12] != 0 {
		t.Fatalf("status counters: %v", sn.GRPCStatus)
	}
	// Health: the backend reports NOT_SERVING and is ejected.
	serving.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !s.Upstreams()["echo"][0].Healthy {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s.Upstreams()["echo"][0].Healthy {
		t.Fatal("backend not ejected after NOT_SERVING")
	}
	resp, _ = grpcCall(t, c, base+"/echo.Echo/Say", []byte("x"))
	if resp.StatusCode != 200 || resp.Header.Get("Grpc-Status") != "14" {
		t.Fatalf("unavailable: %d %v", resp.StatusCode, resp.Header)
	}
	serving.Store(true)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !s.Upstreams()["echo"][0].Healthy {
		time.Sleep(50 * time.Millisecond)
	}
	if !s.Upstreams()["echo"][0].Healthy {
		t.Fatal("backend not restored after SERVING")
	}
}

func TestGRPCHelpers(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{{"100m", 100 * time.Millisecond}, {"2S", 2 * time.Second}, {"1H", time.Hour}, {"3M", 3 * time.Minute}, {"7u", 7 * time.Microsecond}, {"9n", 9}, {"x", 0}, {"", 0}, {"12", 0}, {"-1S", 0}, {"1234567890S", 0}} {
		if got := parseGRPCTimeout(tc.in); got != tc.want {
			t.Errorf("%q: got %s want %s", tc.in, got, tc.want)
		}
	}
	for status, code := range map[int]int{400: 3, 401: 16, 403: 7, 404: 12, 429: 8, 413: 8, 502: 14, 503: 14, 504: 4, 500: 13, 418: 2} {
		if c, _ := grpcCode(status); c != code {
			t.Errorf("%d: got %d want %d", status, c, code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Content-Type", "application/grpc-web")
	if isGRPC(r) {
		t.Fatal("grpc-web treated as gRPC")
	}
	r.Header.Set("Content-Type", "application/grpc+proto")
	if !isGRPC(r) {
		t.Fatal("grpc+proto not recognised")
	}
}
