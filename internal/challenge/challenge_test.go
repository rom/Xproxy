package challenge

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func cfg() *config.Challenge {
	return &config.Challenge{Difficulty: 10, TTL: config.Duration(time.Hour), CookieName: "XPCHAL", Title: "Checking your browser", ExemptCIDRs: []string{"10.0.0.0/8"}}
}

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
	// Wrong proof, wrong IP, then success.
	if w := post(nonce, "1", "/shop?item=1", ip); w.Code != 403 {
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
	issued, passed, failed := c.Stats()
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
	old := c.newNonce(ip, c.now())
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
	val := a.issueCookie(ip, time.Now())
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "XPCHAL", Value: val})
	if !b.Verified(r, ip) {
		t.Fatal("cookie from first instance rejected by second with same key file")
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
	for _, needle := range []string{"0x428a2f98", "0xc67178f2", `add("nonce", nonce)`, `add("counter", String(found))`, `add("r", ret)`} {
		if !strings.Contains(s, needle) {
			t.Fatalf("script missing %q", needle)
		}
	}
}
