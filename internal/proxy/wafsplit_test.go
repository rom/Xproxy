package proxy

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

const gradualYAML = `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
trusted_proxies: [127.0.0.0/8]
waf:
  default_mode: detect
  profiles:
    - name: default
      crs: {paranoia_level: 1}
upstreams:
  - name: app
    endpoints: [{address: %s}]
routes:
  - {name: canary, hosts: [canary.test], upstream: app, waf: {mode: block, block_percent: 0, block_cidrs: [192.0.2.0/24]}}
  - {name: half, hosts: [half.test], upstream: app, waf: {mode: block, block_percent: 50}}
  - {name: full, hosts: [full.test], upstream: app, waf: {mode: block}}
`

func TestWAFGradualEnforcement(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(gradualYAML, a.addr()))
	attack := url + "/items?id=1%27%20OR%20%271%27=%271"
	// Test mode: only the canary prefix is enforced, everyone else is in detect.
	if resp, _ := getAs(t, attack, "canary.test", "192.0.2.10"); resp.StatusCode != 403 {
		t.Fatalf("canary client: %d", resp.StatusCode)
	}
	if resp, _ := getAs(t, attack, "canary.test", "198.51.100.10"); resp.StatusCode != 200 {
		t.Fatalf("other client in test mode: %d", resp.StatusCode)
	}
	// Full enforcement.
	if resp, _ := getAs(t, attack, "full.test", "198.51.100.10"); resp.StatusCode != 403 {
		t.Fatalf("full: %d", resp.StatusCode)
	}
	// Half: a stable split by address, roughly half of many clients.
	blocked := 0
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)
		resp, _ := getAs(t, attack, "half.test", ip)
		resp2, _ := getAs(t, attack, "half.test", ip)
		if resp.StatusCode != resp2.StatusCode {
			t.Fatalf("client %s saw two behaviours: %d then %d", ip, resp.StatusCode, resp2.StatusCode)
		}
		if resp.StatusCode == 403 {
			blocked++
		}
	}
	if blocked < 60 || blocked > 140 {
		t.Fatalf("blocked %d of 200 clients at 50%%", blocked)
	}
	rep := s.WAF(5)
	byRoute := map[string]WAFRoute{}
	for _, r := range rep.Routes {
		byRoute[r.Route] = r
	}
	if c := byRoute["canary"]; c.Mode != "block" || c.BlockPercent != 0 || len(c.BlockCIDRs) != 1 {
		t.Fatalf("canary status %+v", c)
	}
	if h := byRoute["half"]; h.BlockPercent != 50 || len(h.BlockCIDRs) != 0 {
		t.Fatalf("half status %+v", h)
	}
	if f := byRoute["full"]; f.BlockPercent != 100 {
		t.Fatalf("full status %+v", f)
	}
	if rep.Blocked == 0 || rep.Detected == 0 {
		t.Fatalf("counters blocked %d detected %d", rep.Blocked, rep.Detected)
	}
	// The split itself is deterministic and honours the bounds.
	pct := 30
	sw := &splitWAF{percent: pct}
	on := 0
	for i := 0; i < 1000; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 7})
		if sw.enforced(ip) {
			on++
		}
	}
	if on < 220 || on > 380 {
		t.Fatalf("30%% split enforced %d of 1000", on)
	}
	zero := 0
	sw = &splitWAF{percent: zero}
	if sw.enforced(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("0% enforced someone")
	}
	sw = &splitWAF{percent: 100}
	if !sw.enforced(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("100% left someone out")
	}
	// Validation.
	for _, snippet := range []string{
		"{mode: block, block_percent: 101}",
		"{mode: detect, block_percent: 10}",
		"{mode: block, block_cidrs: [nope]}",
		"{mode: detect, block_cidrs: [192.0.2.0/24]}",
	} {
		y := fmt.Sprintf(gradualYAML, "127.0.0.1:1")
		y = y[:len(y)-len("  - {name: full, hosts: [full.test], upstream: app, waf: {mode: block}}\n")] + "  - {name: bad, hosts: [bad.test], upstream: app, waf: " + snippet + "}\n"
		if _, err := config.Parse([]byte(y)); err == nil {
			t.Errorf("accepted %s", snippet)
		}
	}
}
