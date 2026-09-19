package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const retryYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: pool
    balancer: round_robin
    retries: 2
    retry_on: [%s]
    endpoints: [{address: "%s"}, {address: "%s"}]
routes:
  - name: r
    upstream: pool
`

func TestRetryOnStatus(t *testing.T) {
	var badHits, badPosts atomic.Int64
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badHits.Add(1)
		if r.Method == http.MethodPost {
			badPosts.Add(1)
		}
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(503)
		_, _ = w.Write([]byte("bad gateway body"))
	}))
	t.Cleanup(bad.Close)
	good := newBackend(t, "good")
	s, url := startServer(t, fmt.Sprintf(retryYAML, `"503", "5xx"`, strings.TrimPrefix(bad.URL, "http://"), good.addr()))

	// Every GET succeeds although half the picks land on the failing
	// endpoint first.
	for i := 0; i < 8; i++ {
		if resp, body := get(t, url+"/x"); resp.StatusCode != 200 || body != "good:/x" {
			t.Fatalf("request %d: %d %q", i, resp.StatusCode, body)
		}
	}
	if badHits.Load() == 0 {
		t.Fatal("failing endpoint never tried")
	}
	st := s.Stats()
	if st.UpstreamStatusRetries == 0 || st.UpstreamRetries != st.UpstreamStatusRetries {
		t.Fatalf("retry counters %+v", st)
	}
	// A POST is not replayable: whichever endpoint answers, answers.
	posts, bad503 := 0, 0
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequest(http.MethodPost, url+"/x", strings.NewReader("data"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		posts++
		if resp.StatusCode == 503 {
			bad503++
		}
	}
	if bad503 == 0 || badPosts.Load() != int64(bad503) {
		t.Fatalf("posts retried: %d of %d returned 503, failing endpoint saw %d posts", bad503, posts, badPosts.Load())
	}

	// Without retry_on the client sees the 503s again.
	cfg := mustParse(t, fmt.Sprintf(retryYAML, "", strings.TrimPrefix(bad.URL, "http://"), good.addr()))
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	saw503 := false
	for i := 0; i < 8 && !saw503; i++ {
		resp, _ := get(t, url+"/x")
		saw503 = resp.StatusCode == 503
	}
	if !saw503 {
		t.Fatal("503 retried without retry_on")
	}

	// The budget is finite: with one retry and both endpoints failing the
	// last response comes through with its body.
	cfg = mustParse(t, fmt.Sprintf(retryYAML, `"5xx"`, strings.TrimPrefix(bad.URL, "http://"), good.addr()))
	cfg.Upstreams[0].Endpoints = cfg.Upstreams[0].Endpoints[:1] // only the failing endpoint remains
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if resp, body := get(t, url+"/x"); resp.StatusCode != 503 || body != "bad gateway body" || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("exhausted budget: %d %q %v", resp.StatusCode, body, resp.Header)
	}
}
