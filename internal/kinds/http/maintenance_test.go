package http

import (
	"fmt"
	"io"
	"net/http"
	"testing"
)

func TestMaintenanceMode(t *testing.T) {
	a := newBackend(t, "a")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
maintenance:
  enabled: true
  status: 503
  retry_after: 120s
  message: down for now
  allow_cidrs: [192.0.2.0/24]
  allow_header: "X-Bypass: let-me-in"
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: health, paths: [/healthz], upstream: app, maintenance: false}
  - {name: app, paths: [/], upstream: app}
`, a.addr())
	s, url := startServer(t, yaml)
	get := func(path string, hdr ...string) (int, string) {
		r, _ := http.NewRequest("GET", url+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	// On by config: an ordinary client is held with 503 and Retry-After.
	before := a.hits.Load()
	if code, body := get("/page", "X-Forwarded-For", "203.0.113.1"); code != 503 || body == "" || a.hits.Load() != before {
		t.Fatalf("held request: %d %q", code, body)
	}
	// The allowlisted network is served.
	if code, _ := get("/page", "X-Forwarded-For", "192.0.2.5"); code != 200 {
		t.Fatalf("allow_cidrs: %d", code)
	}
	// The bypass header is served.
	if code, _ := get("/page", "X-Forwarded-For", "203.0.113.1", "X-Bypass", "let-me-in"); code != 200 {
		t.Fatalf("allow_header: %d", code)
	}
	// The exempt route (maintenance: false) is served.
	if code, _ := get("/healthz", "X-Forwarded-For", "203.0.113.1"); code != 200 {
		t.Fatalf("exempt route: %d", code)
	}
	// Toggle it off at runtime: everything is served.
	off := false
	if state, configured := s.Maintenance(&off); state || !configured {
		t.Fatalf("toggle off: %v %v", state, configured)
	}
	if code, _ := get("/page", "X-Forwarded-For", "203.0.113.1"); code != 200 {
		t.Fatalf("after toggle off: %d", code)
	}
	// And back on.
	on := true
	s.Maintenance(&on)
	if code, _ := get("/page", "X-Forwarded-For", "203.0.113.1"); code != 503 {
		t.Fatalf("after toggle on: %d", code)
	}
}
