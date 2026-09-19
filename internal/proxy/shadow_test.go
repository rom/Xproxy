package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const shadowYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: live
    endpoints: [{address: "%s"}]
  - name: shadow
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: live
    mirror:
      upstream: shadow
      diff:
        headers: [Content-Type]
        max_body_bytes: 65536
`

// handler answers with a fixed status, content type and body.
func fixed(status int, ctype, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if ctype != "" {
			w.Header().Set("Content-Type", ctype)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

// waitStat polls a snapshot value until it reaches want or the deadline.
func waitStat(t *testing.T, s *Server, get func(Snapshot) uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if get(s.Stats()) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("stat did not reach %d: %d", want, get(s.Stats()))
}

func TestShadowDiff(t *testing.T) {
	live := httptest.NewServer(fixed(200, "application/json", "hello world"))
	defer live.Close()
	// Same status and content type but a different body.
	shadow := httptest.NewServer(fixed(200, "application/json", "HELLO WORLD"))
	defer shadow.Close()

	s, url := startServer(t, fmt.Sprintf(shadowYAML,
		live.Listener.Addr().String(), shadow.Listener.Addr().String()))

	resp, body := get(t, url+"/x")
	if resp.StatusCode != 200 || body != "hello world" {
		t.Fatalf("live response: %d %q", resp.StatusCode, body)
	}
	waitStat(t, s, func(sn Snapshot) uint64 { return sn.MirrorDiffBody }, 1)
	if st := s.Stats(); st.MirrorDiffStatus != 0 || st.MirrorDiffHeader != 0 {
		t.Fatalf("unexpected status/header diff: %+v", st)
	}
}

func TestShadowMatchAndStatus(t *testing.T) {
	live := httptest.NewServer(fixed(200, "text/plain", "same"))
	defer live.Close()
	shadow := httptest.NewServer(fixed(200, "text/plain", "same"))
	defer shadow.Close()

	s, url := startServer(t, fmt.Sprintf(shadowYAML,
		live.Listener.Addr().String(), shadow.Listener.Addr().String()))

	if resp, _ := get(t, url+"/x"); resp.StatusCode != 200 {
		t.Fatalf("live: %d", resp.StatusCode)
	}
	waitStat(t, s, func(sn Snapshot) uint64 { return sn.MirrorDiffMatch }, 1)

	// Reload with a shadow that answers a different status.
	statusShadow := httptest.NewServer(fixed(500, "text/plain", "same"))
	defer statusShadow.Close()
	cfg := mustParse(t, fmt.Sprintf(shadowYAML,
		live.Listener.Addr().String(), statusShadow.Listener.Addr().String()))
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get(t, url+"/x"); resp.StatusCode != 200 {
		t.Fatalf("live after reload: %d", resp.StatusCode)
	}
	waitStat(t, s, func(sn Snapshot) uint64 { return sn.MirrorDiffStatus }, 1)
}
