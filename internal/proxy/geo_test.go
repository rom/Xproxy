package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestGeoPolicy: routes allow or deny by country from a CSV table, unknown
// addresses follow the route's choice, a rate limit keyed on country
// shares one bucket per country, and denials are counted and logged.
func TestGeoPolicy(t *testing.T) {
	backend := newBackend(t, "a")
	csv := filepath.Join(t.TempDir(), "geo.csv")
	// Loopback has no country; give the test addresses countries through
	// trusted proxy forwarding.
	if err := os.WriteFile(csv, []byte("192.0.2.0/24,SE\n198.51.100.0/24,RU\n203.0.113.0/24,NO\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
logging:
  access: {enabled: false}
trusted_proxies: [127.0.0.0/8]
geoip: {csv: %s}
rate_limits:
  - {name: per-country, key: country, rate: 0.001, burst: 2}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
routes:
  - name: nordic
    paths: [/nordic/]
    geo: {allow: [se, "NO"], unknown: deny}
    upstream: app
  - name: open
    paths: [/open/]
    geo: {deny: [RU]}
    upstream: app
  - name: limited
    paths: [/limited/]
    rate_limits: [per-country]
    upstream: app
`
	s, url := startServer(t, fmt.Sprintf(yaml, csv, backend.addr()))
	from := func(ip, path string) int {
		resp, _ := get(t, url+path, "X-Forwarded-For", ip)
		return resp.StatusCode
	}
	if c := from("192.0.2.5", "/nordic/x"); c != 200 {
		t.Fatalf("SE on nordic: %d", c)
	}
	if c := from("203.0.113.5", "/nordic/x"); c != 200 {
		t.Fatalf("NO on nordic: %d", c)
	}
	if c := from("198.51.100.5", "/nordic/x"); c != 403 {
		t.Fatalf("RU on nordic: %d", c)
	}
	if c := from("10.9.9.9", "/nordic/x"); c != 403 {
		t.Fatalf("unknown on nordic (unknown: deny): %d", c)
	}
	if c := from("10.9.9.9", "/open/x"); c != 200 {
		t.Fatalf("unknown on open (unknown: allow): %d", c)
	}
	if c := from("198.51.100.5", "/open/x"); c != 403 {
		t.Fatalf("RU on open: %d", c)
	}
	if c := from("192.0.2.5", "/open/x"); c != 200 {
		t.Fatalf("SE on open: %d", c)
	}
	// Two SE addresses share the SE bucket (burst 2): third SE request
	// is limited while a NO address still passes.
	if from("192.0.2.1", "/limited/x") != 200 || from("192.0.2.2", "/limited/x") != 200 {
		t.Fatal("SE burst")
	}
	if c := from("192.0.2.3", "/limited/x"); c != 429 {
		t.Fatalf("third SE request: %d", c)
	}
	if c := from("203.0.113.1", "/limited/x"); c != 200 {
		t.Fatalf("NO after SE exhausted: %d", c)
	}
	st := s.Stats()
	if st.DeniedGeo != 3 {
		t.Fatalf("denied_geo %d", st.DeniedGeo)
	}
	gs := s.GeoIP()
	if gs == nil || gs.Lookups == 0 || gs.Unknown == 0 {
		t.Fatalf("geoip status %+v", gs)
	}
}
