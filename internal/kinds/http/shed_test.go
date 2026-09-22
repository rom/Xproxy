package http

import (
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/challenge"
)

const shedYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  limits: {max_concurrent_requests: 100}
trusted_proxies: [127.0.0.0/8]
shedding:
  target_latency: 50ms
  window: 2s
  low: 0.4
  normal: 0.7
  high: 0.9
  hysteresis: 0.1
challenge:
  difficulty: 8
  title: Checking your browser
  exempt_cidrs: [192.0.2.250/32]
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - {name: low,      hosts: [low.test],      priority_class: low,      upstream: a}
  - {name: normal,   hosts: [normal.test],   priority_class: normal,   upstream: a}
  - {name: high,     hosts: [high.test],     priority_class: high,     upstream: a}
  - {name: critical, hosts: [critical.test], priority_class: critical, upstream: a}
  - {name: gated,    hosts: [gated.test],    challenge: {mode: always}, upstream: a}
  - {name: onload,   hosts: [onload.test],   challenge: {mode: load, level: 0.5}, priority_class: critical, upstream: a}
`

func TestAdaptiveShedding(t *testing.T) {
	backend := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(shedYAML, backend.addr()))
	if eng(s).shedder.Load() == nil {
		t.Fatal("shedder not created")
	}
	// Healthy: everything admitted.
	for _, h := range []string{"low.test", "normal.test", "high.test", "critical.test"} {
		if resp, _ := getAs(t, url+"/", h, "198.51.100.1"); resp.StatusCode != 200 {
			t.Fatalf("%s healthy: %d", h, resp.StatusCode)
		}
	}
	// Backend degrades to 3x the target for longer than the window, so the
	// window holds only slow samples: level 1, all but critical shed.
	backend.delay = 150 * time.Millisecond
	for i := 0; i < 15; i++ {
		getAs(t, url+"/", "critical.test", "198.51.100.1")
	}
	if lvl := eng(s).shedder.Load().Level(); lvl < 0.9 {
		t.Fatalf("level %v after slow responses", lvl)
	}
	for _, h := range []string{"low.test", "normal.test", "high.test"} {
		resp, _ := getAs(t, url+"/", h, "198.51.100.1")
		if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("%s under load: %d %v", h, resp.StatusCode, resp.Header)
		}
	}
	if resp, _ := getAs(t, url+"/", "critical.test", "198.51.100.1"); resp.StatusCode != 200 {
		t.Fatalf("critical shed: %d", resp.StatusCode)
	}
	st := s.Stats()
	if st.Shed != 3 || st.LoadLevel < 0.9 || len(st.SheddingClasses) != 3 {
		t.Fatalf("stats %+v", st)
	}
	// Recovery: backend fast again; once the window drains classes return.
	backend.delay = 0
	time.Sleep(2500 * time.Millisecond)
	for _, h := range []string{"low.test", "normal.test", "high.test"} {
		if resp, _ := getAs(t, url+"/", h, "198.51.100.1"); resp.StatusCode != 200 {
			t.Fatalf("%s after recovery: %d", h, resp.StatusCode)
		}
	}
}

// solveChallenge fetches the page, solves it and returns the cookie.
func solveChallenge(t *testing.T, url, host, ip string) *http.Cookie {
	t.Helper()
	resp, body := getAs(t, url+"/shop?x=1", host, ip)
	if resp.StatusCode != 503 || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("challenge page: %d %v", resp.StatusCode, resp.Header)
	}
	i := strings.Index(body, `data-nonce="`)
	if i < 0 {
		t.Fatalf("no nonce: %s", body)
	}
	nonce := body[i+len(`data-nonce="`):]
	nonce = nonce[:strings.IndexByte(nonce, '"')]
	counter := challenge.Solve(nonce, 8)
	form := neturl.Values{"nonce": {nonce}, "counter": {counter}, "r": {"/shop?x=1"}}
	req, _ := http.NewRequest("POST", url+challenge.VerifyPath, strings.NewReader(form.Encode()))
	req.Host = host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", ip)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	vr, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, vr.Body)
	vr.Body.Close()
	if vr.StatusCode != 303 || vr.Header.Get("Location") != "/shop?x=1" {
		t.Fatalf("verify: %d %v", vr.StatusCode, vr.Header)
	}
	for _, ck := range vr.Cookies() {
		if ck.Name == "XPCHAL" {
			return ck
		}
	}
	t.Fatal("no cookie")
	return nil
}

func TestChallengeGate(t *testing.T) {
	backend := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(shedYAML, backend.addr()))
	// Script is served on any host.
	if resp, body := get(t, url+challenge.ScriptPath, "Host", "whatever.test"); resp.StatusCode != 200 || !strings.Contains(body, "sha256Prefix") {
		t.Fatalf("script: %d", resp.StatusCode)
	}
	// Unverified client is challenged; exempt client is not.
	cookie := solveChallenge(t, url, "gated.test", "198.51.100.20")
	if resp, _ := getAs(t, url+"/", "gated.test", "192.0.2.250"); resp.StatusCode != 200 {
		t.Fatalf("exempt: %d", resp.StatusCode)
	}
	// With the cookie the route is reachable; from another IP it is not.
	resp, body := getAs(t, url+"/shop?x=1", "gated.test", "198.51.100.20", "Cookie", "XPCHAL="+cookie.Value)
	if resp.StatusCode != 200 || body != "a:/shop" {
		t.Fatalf("verified: %d %q", resp.StatusCode, body)
	}
	if resp, _ := getAs(t, url+"/", "gated.test", "198.51.100.21", "Cookie", "XPCHAL="+cookie.Value); resp.StatusCode != 503 {
		t.Fatalf("cookie from another ip accepted: %d", resp.StatusCode)
	}
	// Bad proof is logged as a security event and counted.
	form := neturl.Values{"nonce": {"junk"}, "counter": {"1"}}
	req, _ := http.NewRequest("POST", url+challenge.VerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "198.51.100.22")
	fr, _ := http.DefaultClient.Do(req)
	fr.Body.Close()
	if fr.StatusCode != 403 {
		t.Fatalf("bad proof: %d", fr.StatusCode)
	}
	st := s.Stats()
	if st.ChallengesIssued != 2 || st.ChallengesPassed != 1 || st.ChallengesFailed != 1 { // page, verified, then the foreign-ip request got a page
		t.Fatalf("stats %+v", st)
	}

	// Load mode: open while calm, challenged under load, verified passes.
	if resp, _ := getAs(t, url+"/", "onload.test", "198.51.100.30"); resp.StatusCode != 200 {
		t.Fatalf("onload calm: %d", resp.StatusCode)
	}
	backend.delay = 150 * time.Millisecond
	for i := 0; i < 15; i++ {
		getAs(t, url+"/", "critical.test", "198.51.100.1")
	}
	if resp, _ := getAs(t, url+"/", "onload.test", "198.51.100.30"); resp.StatusCode != 503 {
		t.Fatalf("onload under load: %d", resp.StatusCode)
	}
	backend.delay = 0
	ck := solveChallenge(t, url, "onload.test", "198.51.100.30")
	if resp, _ := getAs(t, url+"/", "onload.test", "198.51.100.30", "Cookie", "XPCHAL="+ck.Value); resp.StatusCode != 200 {
		t.Fatalf("onload verified under load: %d", resp.StatusCode)
	}
}
