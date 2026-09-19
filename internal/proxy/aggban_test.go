package proxy

import (
	"fmt"
	"strings"
	"testing"
)

const aggBanYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
bans:
  action: reject
  exempt_cidrs: [192.0.2.0/24]
  triggers:
    - {name: sweep, reasons: [waf], aggregate: net, net_v4: 24, threshold: 4, min_sources: 2, window: 1m, duration: 1h}
waf:
  default_mode: block
  profiles:
    - name: default
      crs: {paranoia_level: 1}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: app
    hosts: [app.test]
    upstream: a
`

// TestNetworkAggregateBan spreads WAF denies over addresses of one /24:
// the network is banned once enough distinct sources contributed, a fresh
// address in it is refused, neighbours outside it and exempt networks are
// not.
func TestNetworkAggregateBan(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(aggBanYAML, a.addr()))
	attack := func(ip string) int {
		resp, _ := getAs(t, url+"/?id=1%27%20OR%20%271%27=%271", "app.test", ip)
		return resp.StatusCode
	}
	// Four denies from one address: one source only, no ban yet.
	for i := 0; i < 4; i++ {
		if code := attack("198.51.100.1"); code != 403 {
			t.Fatalf("attack %d: %d", i, code)
		}
	}
	if resp, _ := getAs(t, url+"/", "app.test", "198.51.100.77", "User-Agent", "Mozilla/5.0"); resp.StatusCode != 200 {
		t.Fatalf("network banned on one source: %d", resp.StatusCode)
	}
	// A second address of the network completes the aggregate.
	attack("198.51.100.2")
	resp, _ := getAs(t, url+"/", "app.test", "198.51.100.77", "User-Agent", "Mozilla/5.0")
	if resp.StatusCode != 403 {
		t.Fatalf("fresh address of the banned network served: %d", resp.StatusCode)
	}
	if resp, _ := getAs(t, url+"/", "app.test", "198.51.101.1", "User-Agent", "Mozilla/5.0"); resp.StatusCode != 200 {
		t.Fatalf("neighbouring network affected: %d", resp.StatusCode)
	}
	var found bool
	for _, e := range s.Bans().Entries() {
		if e.Target == "198.51.100.0/24" && strings.HasPrefix(e.Source, "trigger:sweep") {
			found = true
		}
	}
	if !found {
		t.Fatalf("network entry missing: %+v", s.Bans().Entries())
	}
	// The exempt network is never banned however many sources.
	for i := 1; i <= 6; i++ {
		attack(fmt.Sprintf("192.0.2.%d", i))
	}
	if resp, _ := getAs(t, url+"/", "app.test", "192.0.2.99", "User-Agent", "Mozilla/5.0"); resp.StatusCode != 200 {
		t.Fatalf("exempt network banned: %d", resp.StatusCode)
	}
	// A fingerprint ban placed by hand lists and lifts like any other.
	if _, err := s.Bans().Ban("ja4:t13d0403h1_000000000000_000000000000", 3600e9, "tool"); err != nil {
		t.Fatal(err)
	}
	if err := s.Bans().Unban("ja4:t13d0403h1_000000000000_000000000000"); err != nil {
		t.Fatal(err)
	}
}
