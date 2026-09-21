package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Deceiving is the sharpest tool here, and its failure mode is a real
// client quietly receiving nonsense. These tests are mostly about who
// does *not* get the lie.

const deceiveYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: trap, paths: [/.env], honeypot: {decoy: env, mark: 1h}}
  - name: api
    paths: [/api]
    upstream: app
    deceive:
      marked: true
      status: 200
      body: '{"items":[],"total":0}'
      content_type: application/json
  - {name: app, paths: [/], upstream: app}
`

func TestDeceiveOnlyTheDistrusted(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(deceiveYAML, a.addr()))

	// An ordinary client gets the origin, on the same route.
	before := a.hits.Load()
	resp, body := get(t, url+"/api/things", "X-Forwarded-For", "198.51.100.70")
	if resp.StatusCode != 200 || !strings.Contains(body, "a:/api/things") {
		t.Fatalf("clean client: %d %q", resp.StatusCode, body)
	}
	if a.hits.Load() != before+1 {
		t.Error("the clean request did not reach the origin")
	}
	if n := s.Stats().Deceived; n != 0 {
		t.Errorf("deceived %d clean requests", n)
	}

	// A client that read a decoy gets a plausible answer instead, and
	// the origin is never asked.
	if resp, _ := get(t, url+"/.env", "X-Forwarded-For", "198.51.100.71"); resp.StatusCode != 200 {
		t.Fatalf("decoy: %d", resp.StatusCode)
	}
	before = a.hits.Load()
	resp, body = get(t, url+"/api/things", "X-Forwarded-For", "198.51.100.71")
	if resp.StatusCode != 200 {
		t.Fatalf("deceived client: %d", resp.StatusCode)
	}
	if body != `{"items":[],"total":0}` {
		t.Errorf("body %q, want the configured answer", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
	if a.hits.Load() != before {
		t.Error("a deceived request reached the origin")
	}
	if n := s.Stats().Deceived; n != 1 {
		t.Errorf("deceived = %d, want 1", n)
	}
	// Nothing in the answer says it is one.
	for _, h := range []string{"X-Deceived", "X-Honeypot", "Warning"} {
		if v := resp.Header.Get(h); v != "" {
			t.Errorf("the deceptive answer carries %s: %q", h, v)
		}
	}
	// The operator sees it.
	st := s.Deceptions()
	if len(st) != 1 || st[0].Route != "api" || st[0].Served != 1 {
		t.Errorf("status %+v", st)
	}
	// The route's other clients are still served by the origin.
	before = a.hits.Load()
	if _, body := get(t, url+"/api/things", "X-Forwarded-For", "198.51.100.72"); !strings.Contains(body, "a:/api") {
		t.Error("another client was deceived")
	}
	if a.hits.Load() != before+1 {
		t.Error("the other client did not reach the origin")
	}
}

// A write from a deceived client is discarded: the point of the
// feature, and the reason its conditions are worth being sure of.
func TestDeceivedWritesNeverReachTheOrigin(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(deceiveYAML, a.addr()))
	if resp, _ := get(t, url+"/.env", "X-Forwarded-For", "198.51.100.73"); resp.StatusCode != 200 {
		t.Fatal("decoy")
	}
	before := a.hits.Load()
	req, _ := http.NewRequest("POST", url+"/api/orders", strings.NewReader(`{"amount":1000000}`))
	req.Header.Set("X-Forwarded-For", "198.51.100.73")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status %d, want an answer that does not look like a refusal", resp.StatusCode)
	}
	if a.hits.Load() != before {
		t.Error("a deceived write reached the origin")
	}
	if n := s.Stats().Deceived; n != 1 {
		t.Errorf("deceived = %d", n)
	}
}

// A decoy body and a method narrowing, and the other half: a route
// without deceive is untouched by all of it.
func TestDeceiveNarrowing(t *testing.T) {
	a := newBackend(t, "a")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - name: api
    paths: [/api]
    upstream: app
    deceive:
      client_cidrs: ["203.0.113.0/24"]
      methods: [POST]
      decoy: swagger
  - {name: app, paths: [/], upstream: app}
`, a.addr())
	s, url := startServer(t, yaml)

	// The named network, but a method the deception does not cover.
	before := a.hits.Load()
	if _, body := get(t, url+"/api/x", "X-Forwarded-For", "203.0.113.9"); !strings.Contains(body, "a:/api/x") {
		t.Error("a GET was deceived although only POST is named")
	}
	if a.hits.Load() != before+1 {
		t.Error("the GET did not reach the origin")
	}
	// The named network and the named method.
	req, _ := http.NewRequest("POST", url+"/api/x", strings.NewReader("{}"))
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	body := string(raw)
	if !strings.Contains(body, "swagger") && !strings.Contains(body, "openapi") && !strings.Contains(body, "paths") {
		t.Errorf("the decoy body was not served: %q", body[:min(len(body), 120)])
	}
	if n := s.Stats().Deceived; n != 1 {
		t.Errorf("deceived = %d, want the POST only", n)
	}
	// A route without a deceive block is untouched.
	if _, body := get(t, url+"/page", "X-Forwarded-For", "203.0.113.9"); !strings.Contains(body, "a:/page") {
		t.Error("a route without deceive answered with a lie")
	}
}
