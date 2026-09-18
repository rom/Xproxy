package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const defenceYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
rate_limits:
  - {name: tiny, rate: 1, burst: 2}
bans:
  action: drop
  exempt_cidrs: [192.0.2.200/32]
  triggers:
    - {name: waf-repeat, reasons: [waf], threshold: 2, window: 1m, duration: 1h}
    - {name: any, threshold: 4, window: 1m, duration: 1h}
waf:
  default_mode: block
  request_body_limit: 4096
  inspect_responses: true
  response_body_limit: 4096
  profiles:
    - name: default
      crs: {paranoia_level: 1}
    - name: custom
      directives: |
        SecRule REQUEST_HEADERS:X-Evil "@streq yes" "id:100001,phase:1,deny,status:406,msg:'evil header'"
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: blocked
    hosts: [block.test]
    upstream: a
  - name: detect
    hosts: [detect.test]
    waf: {mode: detect}
    upstream: a
  - name: off
    hosts: [off.test]
    waf: {mode: off}
    upstream: a
  - name: custom
    hosts: [custom.test]
    waf: {profile: custom}
    upstream: a
  - name: limited
    hosts: [limited.test]
    rate_limits: [tiny]
    waf: {mode: off}
    upstream: a
`

// getAs sends a request that appears to come from ip via a trusted proxy.
func getAs(t *testing.T, url, host, ip string, hdr ...string) (*http.Response, string) {
	t.Helper()
	return get(t, url, append([]string{"Host", host, "X-Forwarded-For", ip}, hdr...)...)
}

func TestWAFIntegration(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(defenceYAML, a.addr()))

	// Blocked route: SQL injection is denied, clean request passes.
	resp, _ := getAs(t, url+"/items?id=1%27%20OR%20%271%27=%271", "block.test", "192.0.2.1")
	if resp.StatusCode != 403 {
		t.Fatalf("sqli: %d", resp.StatusCode)
	}
	resp, body := getAs(t, url+"/items?page=2", "block.test", "192.0.2.1", "User-Agent", "Mozilla/5.0")
	if resp.StatusCode != 200 || body != "a:/items" {
		t.Fatalf("clean: %d %q", resp.StatusCode, body)
	}

	// Detect route: attack passes but is counted.
	resp, _ = getAs(t, url+"/?q=<script>alert(1)</script>", "detect.test", "192.0.2.2")
	if resp.StatusCode != 200 {
		t.Fatalf("detect: %d", resp.StatusCode)
	}
	// Off route: attack passes uncounted.
	resp, _ = getAs(t, url+"/?q=<script>alert(1)</script>", "off.test", "192.0.2.3")
	if resp.StatusCode != 200 {
		t.Fatalf("off: %d", resp.StatusCode)
	}
	// Custom profile.
	resp, _ = getAs(t, url+"/", "custom.test", "192.0.2.4", "X-Evil", "yes")
	if resp.StatusCode != 406 {
		t.Fatalf("custom: %d", resp.StatusCode)
	}
	// Body inspection with the body still reaching the upstream.
	req, _ := http.NewRequest("POST", url+"/login", strings.NewReader("user=alice&pass=secret"))
	req.Host = "block.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "192.0.2.5")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 200 || a.last.Load().Header.Get("X-Test-Body") != "user=alice&pass=secret" {
		t.Fatalf("post through waf: %d body=%q", r2.StatusCode, a.last.Load().Header.Get("X-Test-Body"))
	}
	req, _ = http.NewRequest("POST", url+"/login", strings.NewReader("user=x&pass=' UNION SELECT password FROM users--"))
	req.Host = "block.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "192.0.2.6")
	r2, _ = http.DefaultClient.Do(req)
	r2.Body.Close()
	if r2.StatusCode != 403 {
		t.Fatalf("body sqli: %d", r2.StatusCode)
	}

	st := s.Stats()
	if st.DeniedWAF != 3 || st.WAFDetected != 1 {
		t.Fatalf("stats: waf denied %d detected %d", st.DeniedWAF, st.WAFDetected)
	}
}

func TestBanIntegration(t *testing.T) {
	a := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(defenceYAML, a.addr()))

	// Two WAF denies from the same client trigger a ban; the third request
	// is refused before routing even on a WAF-off route.
	for i := 0; i < 2; i++ {
		resp, _ := getAs(t, url+"/?id=1%27%20OR%20%271%27=%271", "block.test", "198.51.100.1")
		if resp.StatusCode != 403 {
			t.Fatalf("attack %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ := getAs(t, url+"/", "off.test", "198.51.100.1", "User-Agent", "Mozilla/5.0")
	if resp.StatusCode != 403 {
		t.Fatalf("banned client not refused: %d", resp.StatusCode)
	}
	resp, _ = getAs(t, url+"/", "off.test", "198.51.100.2", "User-Agent", "Mozilla/5.0")
	if resp.StatusCode != 200 {
		t.Fatalf("other client affected: %d", resp.StatusCode)
	}

	// Exempt client is never banned.
	for i := 0; i < 5; i++ {
		getAs(t, url+"/?id=1%27%20OR%20%271%27=%271", "block.test", "192.0.2.200")
	}
	resp, _ = getAs(t, url+"/", "off.test", "192.0.2.200", "User-Agent", "Mozilla/5.0")
	if resp.StatusCode != 200 {
		t.Fatalf("exempt client banned: %d", resp.StatusCode)
	}

	// The catch-all trigger counts rate limit denies.
	for i := 0; i < 6; i++ {
		getAs(t, url+"/", "limited.test", "198.51.100.3")
	}
	if !s.Bans().Banned(mustAddr("198.51.100.3")) {
		t.Fatal("rate limit denies did not trigger the ban")
	}
	if st := s.Stats(); st.BansActive != 2 || st.DeniedBan == 0 {
		t.Fatalf("stats: %+v", st)
	}

	// Manual ban and unban via the list.
	if _, err := s.Bans().Ban("198.51.100.0/24", time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	resp, _ = getAs(t, url+"/", "off.test", "198.51.100.77", "User-Agent", "Mozilla/5.0")
	if resp.StatusCode != 403 {
		t.Fatalf("cidr ban: %d", resp.StatusCode)
	}
	if err := s.Bans().Unban("198.51.100.0/24"); err != nil {
		t.Fatal(err)
	}
	resp, _ = getAs(t, url+"/", "off.test", "198.51.100.77", "User-Agent", "Mozilla/5.0")
	if resp.StatusCode != 200 {
		t.Fatalf("after unban: %d", resp.StatusCode)
	}
}

func TestBanDropsConnectionAtAccept(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
bans: {action: drop}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: a
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	if _, err := s.Bans().Ban("127.0.0.1/32", time.Hour, "self"); err == nil {
		t.Fatal("expected refusal of loopback ban; adjust test if policy changes")
	}
	// Loopback cannot be banned by policy, so exercise the accept hook
	// directly through the limiter's callback.
	if s.connLimiter.Banned(mustAddr("127.0.0.1")) {
		t.Fatal("unbanned address reported banned")
	}
	if _, err := s.Bans().Ban("203.0.113.9", time.Hour, "x"); err != nil {
		t.Fatal(err)
	}
	if !s.connLimiter.Banned(mustAddr("203.0.113.9")) {
		t.Fatal("accept hook does not see the ban")
	}
	resp, _ := get(t, url+"/")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

func TestBansSurviveReload(t *testing.T) {
	a := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
bans: {action: reject}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: a
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	if _, err := s.Bans().Ban("203.0.113.50", time.Hour, "x"); err != nil {
		t.Fatal(err)
	}
	cfg2 := mustParse(t, fmt.Sprintf(yaml, a.addr()))
	if err := s.Reload(cfg2); err != nil {
		t.Fatal(err)
	}
	resp, _ := getAs(t, url+"/", "x", "203.0.113.50")
	if resp.StatusCode != 403 {
		t.Fatalf("ban lost on reload: %d", resp.StatusCode)
	}
	// Removing the bans section drops the list.
	cfg3 := mustParse(t, strings.Replace(fmt.Sprintf(yaml, a.addr()), "bans: {action: reject}\n", "", 1))
	if err := s.Reload(cfg3); err != nil {
		t.Fatal(err)
	}
	if s.Bans() != nil {
		t.Fatal("ban list should be gone")
	}
	resp, _ = getAs(t, url+"/", "x", "203.0.113.50")
	if resp.StatusCode != 200 {
		t.Fatalf("after removing bans: %d", resp.StatusCode)
	}
}
