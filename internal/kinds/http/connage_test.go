package http

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// An upstream connection past max_connection_age is not reused, and no
// request is cut to achieve that. The origin records the connections it
// is handed, so the assertion is on what the backend saw rather than on
// the proxy's own bookkeeping.
func TestUpstreamConnectionIsRetiredAtItsAge(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.RemoteAddr] = true
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	origin.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			seen[c.RemoteAddr().String()] = true
			mu.Unlock()
		}
	}
	origin.Start()
	defer origin.Close()
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(seen)
	}

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: o
    max_connection_age: 1s
    endpoints: [{address: %q}]
routes:
  - name: r
    upstream: o
`, strings.TrimPrefix(origin.URL, "http://"))
	s, url := startServer(t, yaml)

	// Two requests inside the age: one upstream connection between them,
	// which is the keep-alive this bound exists to interrupt.
	for i := 0; i < 2; i++ {
		if resp, _ := get(t, url+"/a"); resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
	if n := count(); n != 1 {
		t.Fatalf("the origin saw %d connections for two requests inside the age", n)
	}
	time.Sleep(1100 * time.Millisecond)

	// This one runs on the aged connection and succeeds -- retiring must
	// never cut an exchange -- and retires it at the end.
	if resp, body := get(t, url+"/b"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("the request on an aged connection failed: %d %q", resp.StatusCode, body)
	}
	eventually(t, 5*time.Second, "the aged connection to be retired", func() bool {
		return s.Pools()["o"].Name == "o" && count() >= 1
	})
	// The next request cannot reuse it, so the origin sees a second
	// connection.
	if resp, _ := get(t, url+"/c"); resp.StatusCode != 200 {
		t.Fatal("the request after the retirement failed")
	}
	eventually(t, 5*time.Second, "a fresh upstream connection", func() bool { return count() >= 2 })
}

// Without the bound, the keep-alive connection is reused: the test above
// only means something if this one holds.
func TestUpstreamConnectionIsReusedWithoutTheBound(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	origin.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			seen[c.RemoteAddr().String()] = true
			mu.Unlock()
		}
	}
	origin.Start()
	defer origin.Close()

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: o
    endpoints: [{address: %q}]
routes:
  - name: r
    upstream: o
`, strings.TrimPrefix(origin.URL, "http://"))
	_, url := startServer(t, yaml)
	for i := 0; i < 3; i++ {
		if resp, _ := get(t, url+"/a"); resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("the origin saw %d connections for three requests with no age bound", n)
	}
}
