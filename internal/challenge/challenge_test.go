package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/secret"
)

func cfg() *config.Challenge {
	return &config.Challenge{Difficulty: 10, TTL: config.Duration(time.Hour), CookieName: "XPCHAL", Title: "Checking your browser", ExemptCIDRs: []string{"10.0.0.0/8"}}
}

// nr is a bare request for cookie issuance in tests that do not exercise
// JA4 binding.
func nr() *http.Request { return httptest.NewRequest("GET", "/", nil) }

func extractNonce(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `data-nonce="`)
	if i < 0 {
		t.Fatalf("no nonce in page: %s", body)
	}
	rest := body[i+len(`data-nonce="`):]
	return rest[:strings.IndexByte(rest, '"')]
}

func TestFlow(t *testing.T) {
	c, err := New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.1")
	req := httptest.NewRequest("GET", "http://example.com/shop?item=1", nil)
	if c.Verified(req, ip) {
		t.Fatal("verified without cookie")
	}
	rec := httptest.NewRecorder()
	c.Serve(rec, req, ip)
	if rec.Code != 503 || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("page: %d %v", rec.Code, rec.Header())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-return="/shop?item=1"`) || !strings.Contains(body, `data-difficulty="10"`) {
		t.Fatalf("page data: %s", body)
	}
	nonce := extractNonce(t, body)
	counter := Solve(nonce, 10)

	post := func(n, cnt, ret string, from netip.Addr) *httptest.ResponseRecorder {
		form := url.Values{"nonce": {n}, "counter": {cnt}, "r": {ret}}
		r := httptest.NewRequest("POST", "http://example.com"+VerifyPath, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		c.Verify(w, r, from, false)
		return w
	}
	// Wrong proof, wrong IP, then success. The wrong counter is looked
	// up rather than assumed: at difficulty 10 one counter in a
	// thousand solves the nonce by chance, and a test that fails once a
	// thousand runs is a test nobody believes.
	wrong := ""
	for i := 0; wrong == ""; i++ {
		if s := strconv.Itoa(i); !Solves(nonce, s, 10) {
			wrong = s
		}
	}
	if w := post(nonce, wrong, "/shop?item=1", ip); w.Code != 403 {
		t.Fatalf("wrong proof: %d", w.Code)
	}
	if w := post(nonce, counter, "/shop?item=1", netip.MustParseAddr("203.0.113.2")); w.Code != 403 {
		t.Fatalf("other ip: %d", w.Code)
	}
	w := post(nonce, counter, "/shop?item=1", ip)
	if w.Code != 303 || w.Header().Get("Location") != "/shop?item=1" {
		t.Fatalf("verify: %d %v", w.Code, w.Header())
	}
	var cookie *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "XPCHAL" {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie: %+v", cookie)
	}
	// Replay of the same nonce is refused.
	if w := post(nonce, counter, "/", ip); w.Code != 403 {
		t.Fatalf("replay: %d", w.Code)
	}
	// Cookie verifies for the same IP only.
	req.AddCookie(cookie)
	if !c.Verified(req, ip) {
		t.Fatal("cookie not accepted")
	}
	if c.Verified(req, netip.MustParseAddr("203.0.113.2")) {
		t.Fatal("cookie accepted from another ip")
	}
	// Expired cookie.
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if c.Verified(req, ip) {
		t.Fatal("expired cookie accepted")
	}
	c.now = time.Now
	// Tampered cookie.
	bad := *cookie
	bad.Value = bad.Value[:len(bad.Value)-2] + "AA"
	req2 := httptest.NewRequest("GET", "http://example.com/", nil)
	req2.AddCookie(&bad)
	if c.Verified(req2, ip) {
		t.Fatal("tampered cookie accepted")
	}
	if !c.Exempt(netip.MustParseAddr("10.9.9.9")) || c.Exempt(ip) {
		t.Fatal("exempt")
	}
	issued, passed, failed, _ := c.Stats()
	if issued != 1 || passed != 1 || failed != 3 {
		t.Fatalf("stats %d %d %d", issued, passed, failed)
	}
}

func TestVerifyInputs(t *testing.T) {
	c, _ := New(cfg())
	ip := netip.MustParseAddr("203.0.113.1")
	w := httptest.NewRecorder()
	c.Verify(w, httptest.NewRequest("GET", VerifyPath, nil), ip, false)
	if w.Code != 405 {
		t.Fatal("GET accepted")
	}
	post := func(form url.Values) int {
		r := httptest.NewRequest("POST", VerifyPath, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		c.Verify(w, r, ip, false)
		return w.Code
	}
	if post(url.Values{"nonce": {"x"}, "counter": {"abc"}}) != 400 {
		t.Fatal("non numeric counter")
	}
	if post(url.Values{"nonce": {"not-a-nonce"}, "counter": {"1"}}) != 403 {
		t.Fatal("garbage nonce")
	}
	if post(url.Values{"nonce": {strings.Repeat("A", 100)}, "counter": {"1"}}) != 403 {
		t.Fatal("long nonce")
	}
	// Expired nonce.
	c.now = func() time.Time { return time.Now().Add(-20 * time.Minute) }
	old := c.newNonce(ip, "example.test", c.now())
	c.now = time.Now
	if post(url.Values{"nonce": {old}, "counter": {Solve(old, 10)}}) != 403 {
		t.Fatal("expired nonce accepted")
	}
	// Open redirect attempts are neutralised.
	for _, r := range []string{"//evil.com/", "/\\evil.com", "http://evil.com", "", VerifyPath + "?x"} {
		if safeReturn(r) != "/" {
			t.Fatalf("return %q accepted", r)
		}
	}
	if safeReturn("/ok/path?q=1") != "/ok/path?q=1" {
		t.Fatal("valid return rejected")
	}
}

func TestPersistentKey(t *testing.T) {
	c := cfg()
	c.SecretFile = filepath.Join(t.TempDir(), "k")
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.1")
	val := a.issueCookie(nr(), ip, time.Now(), TierProof, nil, 0)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: val})
	if !b.Verified(r, ip) {
		t.Fatal("cookie from first instance rejected by second with same key file")
	}
}

func TestKeyRotation(t *testing.T) {
	c := cfg()
	c.SecretFile = filepath.Join(t.TempDir(), "k")
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.1")
	old := a.issueCookie(nr(), ip, time.Now(), TierProof, nil, 0)
	if _, err := secret.Rotate(c.SecretFile, 1); err != nil {
		t.Fatal(err)
	}
	a.Reconfigure(c) // a reload picks the new ring up
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: old})
	if !a.Verified(r, ip) {
		t.Fatal("cookie from before the rotation rejected")
	}
	fresh := a.issueCookie(nr(), ip, time.Now(), TierProof, nil, 0)
	if fresh == old {
		t.Fatal("primary key did not change")
	}
	// A second rotation with keep 0 drops the original key.
	if _, err := secret.Rotate(c.SecretFile, 0); err != nil {
		t.Fatal(err)
	}
	a.Reconfigure(c)
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: old})
	if a.Verified(r, ip) {
		t.Fatal("cookie under a dropped key accepted")
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: fresh})
	if a.Verified(r, ip) {
		t.Fatal("cookie under the second dropped key accepted")
	}
}

func TestProofDefinition(t *testing.T) {
	// The Go and JavaScript sides must agree: SHA-256 over nonce ":" counter,
	// leading zero bits of the digest.
	n := "abc"
	cnt := Solve(n, 12)
	sum := sha256.Sum256([]byte(n + ":" + cnt))
	if leadingZeroBits(sum[:]) < 12 || !Solves(n, cnt, 12) || Solves(n, cnt, 30) {
		t.Fatal("proof definition")
	}
	if leadingZeroBits([]byte{0, 0x0f}) != 12 || leadingZeroBits([]byte{0x80}) != 0 || leadingZeroBits([]byte{0, 0}) != 16 {
		t.Fatal("leadingZeroBits")
	}
}

func TestScriptSHA256MatchesGo(t *testing.T) {
	// Lightweight consistency check of the embedded script: it must contain
	// the round constants and the verification form fields the Go side
	// expects.
	s := string(script)
	for _, needle := range []string{"0x428a2f98", "0xc67178f2", `add("nonce", nonce)`, `add("counter", String(found))`, `add("r", ret)`, `add("device", device)`, `add("signals", signals)`, "xproxyCaptchaDone", "sha256Hex", "webdriver", "$cdc_"} {
		if !strings.Contains(s, needle) {
			t.Fatalf("script missing %q", needle)
		}
	}
}

func TestTiersAndDevice(t *testing.T) {
	c, err := New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.1")
	now := time.Now()
	// A proof cookie with a device, a captcha cookie, a legacy cookie and
	// a cookie with no device.
	dev := parseDevice("0123456789abcdef0123456789abcdef")
	cases := []struct {
		value  string
		tier   int
		device string
	}{
		{c.issueCookie(nr(), ip, now, TierProof, dev, 0), TierProof, "0123456789abcdef"},
		{c.issueCookie(nr(), ip, now, TierCaptcha, dev, 0), TierCaptcha, "0123456789abcdef"},
		{c.issueCookie(nr(), ip, now, TierProof, nil, 0), TierProof, ""},
		{legacyCookie(c, ip, now), TierProof, ""},
		{tieredCookie(c, ip, now, TierCaptcha, dev), TierCaptcha, "0123456789abcdef"},
	}
	for i, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: tc.value})
		tier, device := c.Check(r, ip)
		if tier != tc.tier || device != tc.device || !c.Verified(r, ip) {
			t.Fatalf("case %d: tier %d device %q", i, tier, device)
		}
		if tier2, _ := c.Check(r, netip.MustParseAddr("203.0.113.9")); tier2 != TierNone {
			t.Fatalf("case %d: accepted from another address", i)
		}
	}
	// A tier byte outside the range is refused even with a valid MAC.
	forged := c.issueCookie(nr(), ip, now, 7, dev, 0)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: forged})
	if tier, _ := c.Check(r, ip); tier != TierNone {
		t.Fatal("tier 7 accepted")
	}
	// Device parsing: too short, odd, non hex, and a full hash truncated.
	for _, bad := range []string{"", "abc", "0123456789abcde", "zz23456789abcdef", strings.Repeat("a", 66)} {
		if parseDevice(bad) != nil {
			t.Fatalf("device %q accepted", bad)
		}
	}
	if got := parseDevice(strings.Repeat("ab", 32)); len(got) != deviceLen {
		t.Fatalf("device length %d", len(got))
	}
	// The device posted with a proof lands in the cookie; a request
	// without one gets a cookie without a device.
	rec := httptest.NewRecorder()
	c.Serve(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip)
	if !strings.Contains(rec.Body.String(), `data-device="1"`) {
		t.Fatal("page does not ask for a device id")
	}
	nonce := extractNonce(t, rec.Body.String())
	form := url.Values{"nonce": {nonce}, "counter": {Solve(nonce, 10)}, "r": {"/x"}, "device": {strings.Repeat("cd", 32)}, "signals": {"webdriver,bogus,zero_window"}}
	req := httptest.NewRequest("POST", "http://example.com"+VerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	if ok, reason := c.Verify(w, req, ip, true); !ok {
		t.Fatalf("verify: %s", reason)
	}
	ck := w.Result().Cookies()[0]
	if !ck.Secure {
		t.Fatal("cookie not secure on TLS")
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(ck)
	if tier, device := c.Check(r, ip); tier != TierProof || device != strings.Repeat("cd", 8) {
		t.Fatalf("device cookie: %d %q", tier, device)
	}
	if got := c.Inspect(r, ip); strings.Join(got.Automation, ",") != "webdriver,zero_window" {
		t.Fatalf("automation markers %v", got.Automation)
	}
	// Devices off: the page does not ask and the cookie carries none.
	off := cfg()
	f := false
	off.Device = &f
	c.Reconfigure(off)
	rec = httptest.NewRecorder()
	c.Serve(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip)
	if strings.Contains(rec.Body.String(), `data-device`) {
		t.Fatal("page asks for a device id with devices off")
	}
}

func TestJA4Binding(t *testing.T) {
	conf := cfg()
	conf.BindJA4 = true
	c, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.7")
	now := time.Now()
	// Issue a cookie for a client fingerprinted "t13d1516h2_abc".
	issue := httptest.NewRequest("GET", "/", nil)
	issue = issue.WithContext(WithJA4(issue.Context(), "t13d1516h2_abc"))
	value := c.issueCookie(issue, ip, now, TierProof, nil, 0)

	withJA4 := func(ja4 string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: value})
		if ja4 != "" {
			r = r.WithContext(WithJA4(r.Context(), ja4))
		}
		return r
	}
	// Same fingerprint: accepted.
	if tier, _ := c.Check(withJA4("t13d1516h2_abc"), ip); tier != TierProof {
		t.Fatal("cookie refused for the same fingerprint")
	}
	// A different TLS client (stolen cookie replay): refused, same address.
	if tier, _ := c.Check(withJA4("t13d1516h2_xyz"), ip); tier != TierNone {
		t.Fatal("cookie accepted from a different fingerprint")
	}
	// No fingerprint at all is also a mismatch.
	if tier, _ := c.Check(withJA4(""), ip); tier != TierNone {
		t.Fatal("cookie accepted without a fingerprint")
	}
	// With binding off the fingerprint is irrelevant.
	off, _ := New(cfg())
	v2 := off.issueCookie(issue, ip, now, TierProof, nil, 0)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: v2})
	r = r.WithContext(WithJA4(r.Context(), "anything"))
	if tier, _ := off.Check(r, ip); tier != TierProof {
		t.Fatal("binding off but fingerprint mattered")
	}
}

// tieredCookie builds a cookie in the tiered format before automation
// markers (exp, tier, device, mac under "cookie2").
func tieredCookie(c *Challenger, ip netip.Addr, now time.Time, tier int, device []byte) string {
	buf := make([]byte, 8+1+deviceLen, 8+1+deviceLen+macLen)
	binary.BigEndian.PutUint64(buf, uint64(now.Add(c.ttl).Unix())) //nolint:gosec // positive time
	buf[8] = byte(tier)
	copy(buf[9:], device)
	buf = append(buf, c.mac([]byte("cookie2"), buf[:8+1+deviceLen], c.ipBytes(ip))...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// legacyCookie builds a cookie in the format before tiers.
func legacyCookie(c *Challenger, ip netip.Addr, now time.Time) string {
	buf := make([]byte, 8, 8+macLen)
	binary.BigEndian.PutUint64(buf, uint64(now.Add(c.ttl).Unix())) //nolint:gosec // positive time
	buf = append(buf, c.mac([]byte("cookie"), buf[:8], c.ipBytes(ip))...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func TestCaptcha(t *testing.T) {
	var lastForm url.Values
	answer := `{"success":true,"score":0.9,"hostname":"example.com"}`
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		lastForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, answer)
	}))
	defer provider.Close()
	secretFile := filepath.Join(t.TempDir(), "turnstile.secret")
	if err := os.WriteFile(secretFile, []byte("0x4AAAAAAA_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := cfg()
	conf.Captcha = &config.Captcha{Provider: "turnstile", SiteKey: "0x4AAAAAAA_site", SecretFile: secretFile, VerifyURL: provider.URL, Timeout: config.Duration(2 * time.Second), Mode: "escalation", MinScore: 0.5}
	c, err := New(conf)
	// The routes of this deployment. The request host is not an
	// allowlist: the client chooses it, so comparing the provider's
	// hostname against it only asked the attacker to be consistent.
	if c != nil {
		c.SetRouteHosts([]string{"example.com", "www.example.com:8443"})
	}
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasCaptcha() {
		t.Fatal("captcha not loaded")
	}
	ip := netip.MustParseAddr("203.0.113.1")
	// Escalation mode: a plain page keeps the proof of work; a captcha
	// page renders the widget with the provider's script and CSP.
	rec := httptest.NewRecorder()
	c.ServeTier(rec, httptest.NewRequest("GET", "http://example.com/login", nil), ip, false)
	if body := rec.Body.String(); strings.Contains(body, "cf-turnstile") || !strings.Contains(body, `id="bar"`) {
		t.Fatalf("plain page: %s", body)
	}
	rec = httptest.NewRecorder()
	c.ServeTier(rec, httptest.NewRequest("GET", "http://example.com/login", nil), ip, true)
	body := rec.Body.String()
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(body, `class="cf-turnstile" data-sitekey="0x4AAAAAAA_site"`) || !strings.Contains(body, `data-captcha="turnstile"`) ||
		!strings.Contains(body, "https://challenges.cloudflare.com/turnstile/v0/api.js") || !strings.Contains(csp, "script-src 'self' https://challenges.cloudflare.com") || !strings.Contains(csp, "frame-src https://challenges.cloudflare.com") {
		t.Fatalf("captcha page: %s\n%s", csp, body)
	}
	nonce := extractNonce(t, body)
	post := func(fields url.Values) (*httptest.ResponseRecorder, string) {
		fields.Set("nonce", nonce)
		fields.Set("r", "/login")
		req := httptest.NewRequest("POST", "http://example.com"+VerifyPath, strings.NewReader(fields.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		_, reason := c.Verify(w, req, ip, false)
		return w, reason
	}
	// A rejected token, a low score, an unreachable provider, then success.
	answer = `{"success":false,"error-codes":["invalid-input-response"]}`
	if w, reason := post(url.Values{"cf-turnstile-response": {"tok1"}}); w.Code != 403 || reason != "captcha rejected" {
		t.Fatalf("rejected token: %d %s", w.Code, reason)
	}
	answer = `{"success":true,"score":0.1}`
	if w, reason := post(url.Values{"cf-turnstile-response": {"tok2"}}); w.Code != 403 || reason != "captcha score" {
		t.Fatalf("low score: %d %s", w.Code, reason)
	}
	answer = `{"success":true,"score":0.9,"hostname":"example.com"}`
	// A token without a counter is not a proof attempt (no 400), and a
	// nonce is not burnt by a provider failure.
	w, reason := post(url.Values{"cf-turnstile-response": {"tok3"}, "device": {strings.Repeat("ef", 32)}})
	if w.Code != 303 || reason != "" {
		t.Fatalf("captcha pass: %d %s", w.Code, reason)
	}
	if lastForm.Get("secret") != "0x4AAAAAAA_secret" || lastForm.Get("response") != "tok3" || lastForm.Get("remoteip") != "203.0.113.1" {
		t.Fatalf("provider form %v", lastForm)
	}
	ck := w.Result().Cookies()[0]
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(ck)
	if tier, device := c.Check(r, ip); tier != TierCaptcha || device != strings.Repeat("ef", 8) {
		t.Fatalf("captcha cookie: %d %q", tier, device)
	}
	// The nonce is used up.
	if w, _ := post(url.Values{"cf-turnstile-response": {"tok4"}}); w.Code != 403 {
		t.Fatalf("replay: %d", w.Code)
	}
	// A proof still works alongside (a plain page's nonce).
	rec = httptest.NewRecorder()
	c.Serve(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip)
	nonce = extractNonce(t, rec.Body.String())
	if w, reason := post(url.Values{"counter": {Solve(nonce, 10)}}); w.Code != 303 {
		t.Fatalf("proof with captcha configured: %d %s", w.Code, reason)
	}
	issued, passed, failed, captcha := c.Stats()
	if issued != 3 || passed != 2 || failed != 3 || captcha != 1 {
		t.Fatalf("stats %d %d %d %d", issued, passed, failed, captcha)
	}
	// Hostname binding: a token the provider says was solved on another
	// host is refused; the configured allowlist overrides the request
	// host; the check can be turned off.
	answer = `{"success":true,"score":0.9,"hostname":"evil.example"}`
	rec = httptest.NewRecorder()
	c.ServeTier(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip, true)
	nHost := extractNonce(t, rec.Body.String())
	postHost := func(fields url.Values, host string) (*httptest.ResponseRecorder, string) {
		fields.Set("nonce", nHost)
		fields.Set("r", "/x")
		req := httptest.NewRequest("POST", "http://"+host+VerifyPath, strings.NewReader(fields.Encode()))
		req.Host = host
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		_, reason := c.Verify(w, req, ip, false)
		return w, reason
	}
	if w, reason := postHost(url.Values{"cf-turnstile-response": {"t"}}, "example.com"); w.Code != 403 || reason != "captcha hostname" {
		t.Fatalf("wrong hostname accepted: %d %s", w.Code, reason)
	}
	// With no allowlist at all — neither the CAPTCHA's own hostnames nor
	// a route host — the check fails closed rather than trusting the
	// request host.
	c.SetRouteHosts(nil)
	if w, reason := postHost(url.Values{"cf-turnstile-response": {"t"}}, "evil.example"); w.Code != 403 {
		t.Fatalf("no allowlist accepted a token: %d %s", w.Code, reason)
	}
	c.SetRouteHosts([]string{"example.com"})
	// Reconfigure with an allowlist that includes the reported host.
	conf.Captcha.Hostnames = []string{"evil.example"}
	c.Reconfigure(conf)
	rec = httptest.NewRecorder()
	c.ServeTier(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip, true)
	nHost = extractNonce(t, rec.Body.String())
	if w, reason := postHost(url.Values{"cf-turnstile-response": {"t"}}, "example.com"); w.Code != 303 {
		t.Fatalf("allowlisted hostname rejected: %d %s", w.Code, reason)
	}
	// The nonce binds the verify request to the host the page was served
	// on: a token farmed on evil.example cannot be redeemed by posting with
	// Host: evil.example, whatever the provider reports.
	conf.Captcha.Hostnames = nil
	c.Reconfigure(conf)
	rec = httptest.NewRecorder()
	c.ServeTier(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip, true)
	nHost = extractNonce(t, rec.Body.String())
	if w, reason := postHost(url.Values{"cf-turnstile-response": {"t"}}, "evil.example"); w.Code != 403 || reason != "bad nonce signature" {
		t.Fatalf("nonce redeemed on another host: %d %s", w.Code, reason)
	}
	if w, reason := postHost(url.Values{"cf-turnstile-response": {"t"}}, "example.com"); w.Code != 403 || reason != "captcha hostname" {
		t.Fatalf("token solved elsewhere accepted: %d %s", w.Code, reason)
	}
	// Turn the check off: a missing hostname passes.
	off := false
	conf.Captcha.Hostnames = nil
	conf.Captcha.HostnameCheck = &off
	answer = `{"success":true,"score":0.9}`
	c.Reconfigure(conf)
	rec = httptest.NewRecorder()
	c.ServeTier(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip, true)
	nHost = extractNonce(t, rec.Body.String())
	if w, _ := postHost(url.Values{"cf-turnstile-response": {"t"}}, "example.com"); w.Code != 303 {
		t.Fatalf("hostname check off still rejected: %d", w.Code)
	}
	conf.Captcha.HostnameCheck = nil

	// Mode always renders the widget on every page; the provider being
	// down fails closed with its own reason.
	conf.Captcha.Mode = "always"
	c.Reconfigure(conf)
	rec = httptest.NewRecorder()
	c.Serve(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip)
	if !strings.Contains(rec.Body.String(), "cf-turnstile") {
		t.Fatal("mode always without the widget")
	}
	nonce = extractNonce(t, rec.Body.String())
	provider.Close()
	if w, reason := post(url.Values{"cf-turnstile-response": {"tok5"}}); w.Code != 403 || reason != "captcha unreachable" {
		t.Fatalf("provider down: %d %s", w.Code, reason)
	}
	// Other providers carry their own script, class and CSP origins.
	for name, want := range map[string][]string{
		"hcaptcha":  {"h-captcha", "https://js.hcaptcha.com/1/api.js", "frame-src https://*.hcaptcha.com", "connect-src https://*.hcaptcha.com"},
		"recaptcha": {"g-recaptcha", "https://www.google.com/recaptcha/api.js", "https://www.gstatic.com/recaptcha/"},
	} {
		conf.Captcha.Provider = name
		c.Reconfigure(conf)
		rec = httptest.NewRecorder()
		c.Serve(rec, httptest.NewRequest("GET", "http://example.com/x", nil), ip)
		out := rec.Body.String() + "\n" + rec.Header().Get("Content-Security-Policy")
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q", name, w)
			}
		}
	}
	// A missing secret file refuses construction; an empty one too.
	conf.Captcha.SecretFile = filepath.Join(t.TempDir(), "missing")
	if _, err := New(conf); err == nil {
		t.Fatal("missing secret accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	conf.Captcha.SecretFile = empty
	if _, err := New(conf); err == nil {
		t.Fatal("empty secret accepted")
	}
}

// With cookie_scope: host a pass covers only the host that issued it.
// The nonce is host-bound already, so without this a client solves the
// cheapest host's challenge and spends the cookie on the host that asks
// for the most work — the two hosts behind one proxy that differ in
// difficulty are exactly why the setting exists.
func TestHostScopedCookieDoesNotTravel(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.7")
	now := time.Now()
	req := func(host, value string) *http.Request {
		r := httptest.NewRequest("GET", "http://"+host+"/", nil)
		r.Host = host
		if value != "" {
			r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: value})
		}
		return r
	}
	for _, scope := range []string{"shared", "host"} {
		conf := cfg()
		conf.CookieScope = scope
		c, err := New(conf)
		if err != nil {
			t.Fatal(err)
		}
		value := c.issueCookie(req("cheap.test", ""), ip, now, TierProof, nil, 0)
		if tier, _ := c.Check(req("cheap.test", value), ip); tier != TierProof {
			t.Fatalf("%s: the pass was refused on its own host", scope)
		}
		tier, _ := c.Check(req("dear.test", value), ip)
		switch scope {
		case "host":
			if tier != TierNone {
				t.Fatal("a pass earned on the cheap host was accepted on the dear one")
			}
		default:
			if tier != TierProof {
				t.Fatal("a shared pass was refused on a second host")
			}
		}
	}
}

// The replay table used to be global: one client solving challenges
// could fill all 65,536 slots with its own nonces, and every other
// client's verification was refused from then on. It is partitioned per
// client address now, entries expire at the nonce's own time plus its
// TTL rather than at the moment it was solved, and verification itself
// is rate limited per address.
func TestNonceTableIsPartitionedPerClient(t *testing.T) {
	c, err := New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	greedy := netip.MustParseAddr("198.51.100.1")
	other := netip.MustParseAddr("198.51.100.2")
	key := func(n int) [macLen]byte {
		var k [macLen]byte
		k[0], k[1], k[2] = byte(n), byte(n>>8), byte(n>>16)
		return k
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := now.Add(nonceTTL).Unix()
	filled := 0
	for i := 0; i < maxSeenPerIP+10; i++ {
		if err := c.markUsed(key(i), greedy, exp, now); err == nil {
			filled++
		}
	}
	if filled != maxSeenPerIP {
		t.Fatalf("one client held %d of the table, want its quota of %d", filled, maxSeenPerIP)
	}
	// Everybody else still verifies.
	if err := c.markUsed(key(1_000_000), other, exp, now); err != nil {
		t.Fatalf("another client was refused: %v", err)
	}
	// The quota comes back with the nonces, at the nonce's own expiry.
	later := now.Add(nonceTTL + time.Second)
	if err := c.markUsed(key(2_000_000), greedy, later.Add(nonceTTL).Unix(), later); err != nil {
		t.Fatalf("the quota did not come back after the nonces expired: %v", err)
	}
}

// Each verification costs a MAC, a proof check and, with a CAPTCHA
// configured, a request to the provider — all before anything about the
// client is known.
func TestVerifyIsRateLimitedPerClient(t *testing.T) {
	c, err := New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("198.51.100.9")
	post := func() int {
		r := httptest.NewRequest("POST", "http://example.com"+VerifyPath, strings.NewReader("nonce=x&counter=1"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		c.Verify(w, r, ip, false)
		return w.Code
	}
	limited := false
	for i := 0; i < verifyBurst+5; i++ {
		if post() == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("verification was not rate limited")
	}
	// Another client is unaffected.
	r := httptest.NewRequest("POST", "http://example.com"+VerifyPath, strings.NewReader("nonce=x&counter=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	c.Verify(w, r, netip.MustParseAddr("198.51.100.10"), false)
	if w.Code == 429 {
		t.Fatal("one client's rate limit reached another")
	}
}
