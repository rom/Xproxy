package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/challenge"
)

const captchaYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
challenge:
  difficulty: 8
  captcha:
    provider: hcaptcha
    site_key: 10000000-ffff-ffff-ffff-000000000001
    secret_file: %s
    verify_url: %s
rate_limits:
  - {name: per-device, key: device, rate: 1000, burst: 1000}
filters:
  - name: accounts
    kind: account_guard
    options:
      endpoints:
        - name: login
          class: login
          paths: [/login]
          identity: {form: user}
          steps:
            - {action: captcha, ip: 1}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - {name: login, hosts: [shop.test], paths: [/login], methods: [POST], upstream: a, filters: [accounts], rate_limits: [per-device]}
  - {name: shop,  hosts: [shop.test], upstream: a}
  - {name: gated, hosts: [gated.test], challenge: {mode: always}, upstream: a}
`

// TestCaptchaTier drives a captcha verdict from the account guard through
// the challenge page, the provider verification and the tiered cookie.
func TestCaptchaTier(t *testing.T) {
	backend := newBackend(t, "a")
	backend.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, "a:"+r.URL.Path)
	})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer provider.Close()
	secretFile := filepath.Join(t.TempDir(), "hcaptcha.secret")
	if err := os.WriteFile(secretFile, []byte("0x0000000000000000000000000000000000000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, url := startServer(t, fmt.Sprintf(captchaYAML, secretFile, provider.URL, backend.addr()))
	ip := "198.51.100.40"
	login := func(cookie string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", url+"/login", strings.NewReader("user=anna&pw=x"))
		req.Host = "shop.test"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", ip)
		if cookie != "" {
			req.Header.Set("Cookie", "XPCHAL="+cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(body)
	}
	// The first attempt fails at the upstream; the second reaches the
	// captcha step and gets the widget page.
	if resp, _ := login(""); resp.StatusCode != 401 {
		t.Fatalf("first attempt: %d", resp.StatusCode)
	}
	resp, body := login("")
	if resp.StatusCode != 503 || !strings.Contains(body, `class="h-captcha"`) || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "js.hcaptcha.com") {
		t.Fatalf("captcha page: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	// A proof of work cookie (earned on a gated route) is not enough for
	// a captcha verdict.
	proof := solveChallenge(t, url, "gated.test", ip)
	if resp, body := login(proof.Value); resp.StatusCode != 503 || !strings.Contains(body, "h-captcha") {
		t.Fatalf("proof accepted for captcha: %d", resp.StatusCode)
	}
	// Solve the captcha: post the provider token with the page's nonce
	// and a device identifier.
	i := strings.Index(body, `data-nonce="`)
	nonce := body[i+len(`data-nonce="`):]
	nonce = nonce[:strings.IndexByte(nonce, '"')]
	form := neturl.Values{"nonce": {nonce}, "h-captcha-response": {"tok"}, "r": {"/login"}, "device": {strings.Repeat("ab", 32)}}
	req, _ := http.NewRequest("POST", url+challenge.VerifyPath, strings.NewReader(form.Encode()))
	req.Host = "shop.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", ip)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	vr, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, vr.Body)
	vr.Body.Close()
	if vr.StatusCode != 303 {
		t.Fatalf("captcha verify: %d", vr.StatusCode)
	}
	var cookie string
	for _, ck := range vr.Cookies() {
		if ck.Name == "XPCHAL" {
			cookie = ck.Value
		}
	}
	if resp, _ := login(cookie); resp.StatusCode != 401 {
		t.Fatalf("captcha verified attempt: %d", resp.StatusCode)
	}
	st := s.Stats()
	if st.CaptchasPassed != 1 || st.ChallengesPassed != 2 {
		t.Fatalf("stats %+v", st)
	}
	// The device identifier keys the rate limit and is logged.
	lr := s.rt.Load()
	rl := lr.rateLimits["per-device"]
	if rl == nil {
		t.Fatal("rate limit missing")
	}
	r := httptest.NewRequest("POST", "http://shop.test/login", nil)
	r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: cookie})
	stt := &reqState{clientIP: mustAddr(ip)}
	stt.chalTier, stt.device = s.challenger.Load().Check(r, stt.clientIP)
	if key := s.rateKey(rl.cfg, r, stt); key != "dev:"+strings.Repeat("ab", 8) {
		t.Fatalf("device key %q", key)
	}
	stt.device = ""
	if key := s.rateKey(rl.cfg, r, stt); key != "ip:"+ip {
		t.Fatalf("device fallback %q", key)
	}
}
