package proxy

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestRouteTimeouts checks the named total timeout and the idle timeout
// on a streaming response.
func TestRouteTimeouts(t *testing.T) {
	// A backend that streams a byte, pauses past the idle timeout, then
	// would send more.
	slow := newBackend(t, "slow")
	slow.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("start"))
		if fl != nil {
			fl.Flush()
		}
		time.Sleep(2 * time.Second) // longer than the idle timeout
		_, _ = w.Write([]byte("end"))
	})
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}], timeouts: {response_header: 2s}}
routes:
  - {name: idle, paths: [/idle], upstream: app, timeouts: {idle: 300ms}}
  - {name: total, paths: [/total], upstream: app, timeouts: {total: 300ms}}
`, slow.addr())
	_, url := startServer(t, yaml)
	// Idle: the first bytes arrive, then the stall trips the idle timeout
	// and the read ends early with fewer bytes than the backend would send.
	resp, err := http.Get(url + "/idle")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if time.Since(start) > time.Second {
		t.Fatalf("idle timeout did not fire: read took %s", time.Since(start))
	}
	if string(body) == "startend" {
		t.Fatal("idle timeout did not cut the stream")
	}
	// Total: the whole exchange is bounded, so a slow backend is cut.
	start = time.Now()
	resp, err = http.Get(url + "/total")
	if err == nil {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if time.Since(start) > time.Second {
		t.Fatalf("total timeout did not fire: %s", time.Since(start))
	}
}
