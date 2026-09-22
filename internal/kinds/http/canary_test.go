package http

import (
	"fmt"
	"testing"
)

func TestCanaryRouting(t *testing.T) {
	stable, canary := newBackend(t, "stable"), newBackend(t, "canary")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: app
    canary: {header: X-Canary, cookie: canary, values: ["1"]}
    endpoints:
      - {address: %q}
      - {address: %q, canary: true}
routes:
  - name: r
    upstream: app
`, stable.addr(), canary.addr())
	s, url := startServer(t, yaml)
	for i := 0; i < 4; i++ {
		if _, body := get(t, url+"/x"); body != "stable:/x" {
			t.Fatalf("plain request %d reached %q", i, body)
		}
	}
	if _, body := get(t, url+"/x", "X-Canary", "1"); body != "canary:/x" {
		t.Fatalf("header: %q", body)
	}
	if _, body := get(t, url+"/x", "X-Canary", "0"); body != "stable:/x" {
		t.Fatalf("header other value: %q", body)
	}
	if _, body := get(t, url+"/x", "Cookie", "canary=1"); body != "canary:/x" {
		t.Fatalf("cookie: %q", body)
	}
	ps := s.Pools()["app"]
	if ps.Canary == nil || ps.Canary.Requests != 2 || ps.Canary.Endpoints != 1 {
		t.Fatalf("pool status %+v", ps.Canary)
	}
	ups := s.Upstreams()["app"]
	if !ups[1].Canary || ups[0].Canary || ups[1].Requests != 2 || ups[0].Requests != 5 {
		t.Fatalf("endpoint stats %+v", ups)
	}
	// The canary goes away: its traffic falls back to the stable endpoint.
	canary.srv.Close()
	if resp, body := get(t, url+"/x", "X-Canary", "1"); resp.StatusCode != 200 || body != "stable:/x" {
		t.Fatalf("fallback: %d %q", resp.StatusCode, body)
	}
}
