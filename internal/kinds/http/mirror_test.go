package http

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMirror copies requests to a second upstream without affecting the
// client: same path rules and headers plus the marker, bodies buffered
// up to the bound, methods filtered, copies in flight bounded, a slow or
// failing mirror invisible to the client.
func TestMirror(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "live:%s:%s:%d:%s", r.Method, r.URL.Path, len(b), r.Header.Get(mirrorHeader))
	}))
	t.Cleanup(live.Close)
	type seen struct {
		method, path, marker, host, id string
		body                           []byte
	}
	var mu sync.Mutex
	var copies []seen
	var slow atomic.Bool
	release := make(chan struct{})
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		copies = append(copies, seen{r.Method, r.URL.Path, r.Header.Get(mirrorHeader), r.Host, r.Header.Get("X-Request-Id"), b})
		mu.Unlock()
		if slow.Load() {
			<-release
		}
		w.WriteHeader(500) // never reaches the client
	}))
	t.Cleanup(shadow.Close)
	yaml := `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
  limits: {max_body_bytes: 1000000}
logging:
  access: {enabled: false}
upstreams:
  - name: live
    endpoints: [{address: %s}]
  - name: shadow
    endpoints: [{address: %s}]
routes:
  - name: api
    paths: [/api/]
    upstream: live
    strip_prefix: /api
    host_header: api.internal
    mirror: {upstream: shadow, max_body_bytes: 64, methods: [GET, POST], max_in_flight: 2, timeout: 2s}
`
	s, base := startServer(t, fmt.Sprintf(yaml, strings.TrimPrefix(live.URL, "http://"), strings.TrimPrefix(shadow.URL, "http://")))
	wait := func(n int) []seen {
		t.Helper()
		for i := 0; i < 100; i++ {
			mu.Lock()
			c := append([]seen(nil), copies...)
			mu.Unlock()
			if len(c) >= n {
				return c
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("mirror did not receive %d copies", n)
		return nil
	}
	resp, body := get(t, base+"/api/users?x=1")
	if resp.StatusCode != 200 || body != "live:GET:/users:0:" {
		t.Fatalf("live: %d %q", resp.StatusCode, body)
	}
	c := wait(1)
	if c[0].method != "GET" || c[0].path != "/users" || c[0].marker != "1" || c[0].host != "api.internal" || c[0].id == "" {
		t.Fatalf("copy: %+v", c[0])
	}
	// A body is delivered to both.
	pr, err := http.Post(base+"/api/items", "text/plain", strings.NewReader("hello mirror"))
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := io.ReadAll(pr.Body)
	_ = pr.Body.Close()
	if string(pb) != "live:POST:/items:12:" {
		t.Fatalf("live post: %q", pb)
	}
	c = wait(2)
	if !bytes.Equal(c[1].body, []byte("hello mirror")) {
		t.Fatalf("copy body: %q", c[1].body)
	}
	// Over the body bound: proxied in full, not mirrored.
	big := strings.Repeat("x", 100)
	pr, err = http.Post(base+"/api/big", "text/plain", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	pb, _ = io.ReadAll(pr.Body)
	_ = pr.Body.Close()
	if string(pb) != "live:POST:/big:100:" {
		t.Fatalf("live big: %q", pb)
	}
	// Method not listed: not mirrored.
	req, _ := http.NewRequest(http.MethodDelete, base+"/api/items/1", nil)
	dr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = dr.Body.Close()
	time.Sleep(50 * time.Millisecond)
	if c := wait(2); len(c) != 2 {
		t.Fatalf("unexpected copies: %+v", c)
	}
	// In-flight bound: with the mirror stalled, the third copy is dropped
	// and the client never waits.
	slow.Store(true)
	for i := 0; i < 3; i++ {
		start := time.Now()
		resp, _ := get(t, fmt.Sprintf(base+"/api/slow/%d", i))
		if resp.StatusCode != 200 || time.Since(start) > time.Second {
			t.Fatalf("client affected by a slow mirror: %d after %s", resp.StatusCode, time.Since(start))
		}
	}
	wait(4)
	sn := s.Stats()
	if sn.MirrorSent != 4 || sn.MirrorDropped != 1 || sn.MirrorSkipped != 1 {
		t.Fatalf("counters: sent %d dropped %d skipped %d failed %d", sn.MirrorSent, sn.MirrorDropped, sn.MirrorSkipped, sn.MirrorFailed)
	}
	close(release)
	// A dead mirror is counted as failed, still invisible.
	shadow.Close()
	resp, _ = get(t, base+"/api/after")
	if resp.StatusCode != 200 {
		t.Fatal("client affected by a dead mirror")
	}
	// The mirror copy is made after the client has its response, so
	// the counter lands on another goroutine's schedule: wait for it
	// rather than for a span that happens to be long enough here.
	eventually(t, 15*time.Second, "the failed mirror copy to be counted",
		func() bool { return s.Stats().MirrorFailed != 0 })
	if s.Stats().MirrorFailed != 1 {
		t.Fatalf("failed copies: %d", s.Stats().MirrorFailed)
	}
}
