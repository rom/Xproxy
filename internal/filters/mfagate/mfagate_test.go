package mfagate

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
	"github.com/rom/xproxy/internal/mfa"
)

func build(t *testing.T, extra map[string]any) (*gate, []byte) {
	t.Helper()
	dir := t.TempDir()
	secret, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "mfa")
	if err := os.WriteFile(file, []byte("alice:"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := map[string]any{
		"file":               file,
		"cookie_secret_file": filepath.Join(dir, "cookie.key"),
	}
	for k, v := range extra {
		opts[k] = v
	}
	f, err := filtertest.Build("mfa", "staff-mfa", opts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	g, ok := f.(*gate)
	if !ok {
		t.Fatalf("build returned %T", f)
	}
	raw, err := mfa.ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	return g, raw
}

// run drives one request with an identity attached, as the data plane
// does after an authenticating filter has run.
func run(t *testing.T, g *gate, r *http.Request, user string) filter.Verdict {
	t.Helper()
	ctx, id := filter.WithIdentity(context.Background())
	if user != "" {
		filter.SetIdentity(ctx, "basic", user)
	}
	_ = id
	in := g.Begin(ctx, &filter.Info{Route: "test"})
	return in.Request(r.WithContext(ctx))
}

func get(path string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "https://app.example.test"+path, nil)
	return r
}

func post(path string, form url.Values) *http.Request {
	body := form.Encode()
	r, _ := http.NewRequest(http.MethodPost, "https://app.example.test"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ContentLength = int64(len(body))
	return r
}

func code(t *testing.T, secret []byte) string {
	t.Helper()
	c, err := mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// setCookie returns the cookie a verdict set, if any.
func setCookie(v filter.Verdict) *http.Cookie {
	if v.Response == nil {
		return nil
	}
	cs := (&http.Response{Header: v.Response.Header}).Cookies()
	if len(cs) == 0 {
		return nil
	}
	return cs[0]
}

// TestChallengeAndVerify walks the whole flow: a request with an
// identity and no factor gets the form, the posted code sets a cookie,
// and the next request goes through.
func TestChallengeAndVerify(t *testing.T) {
	g, secret := build(t, nil)

	v := run(t, g, get("/reports?q=1"), "alice")
	if !v.Deny || v.Status != http.StatusUnauthorized || v.Response == nil {
		t.Fatalf("challenge: %+v", v)
	}
	body, _ := io.ReadAll(v.Response.Body)
	page := string(body)
	for _, want := range []string{"One-time code", `name="code"`, `name="next"`, "/reports?q=1"} {
		if !strings.Contains(page, want) {
			t.Fatalf("%q missing from the challenge page", want)
		}
	}

	v = run(t, g, post("/reports?xproxy_mfa=verify", url.Values{
		"code": {code(t, secret)}, "next": {"/reports?q=1"},
	}), "alice")
	if !v.Deny || v.Status != http.StatusFound {
		t.Fatalf("verify: %+v", v)
	}
	c := setCookie(v)
	if c == nil || !c.HttpOnly || !c.Secure {
		t.Fatalf("cookie: %+v", c)
	}
	if loc := v.Response.Header.Get("Location"); loc != "/reports?q=1" {
		t.Fatalf("location %q", loc)
	}

	next := get("/reports?q=1")
	next.AddCookie(c)
	if v := run(t, g, next, "alice"); v.Deny {
		t.Fatalf("a verified session should pass: %+v", v)
	}
}

// A cookie is bound to the user it was issued for: presenting it as
// somebody else is worth nothing.
func TestCookieBoundToUser(t *testing.T) {
	g, secret := build(t, nil)
	v := run(t, g, post("/x?xproxy_mfa=verify", url.Values{"code": {code(t, secret)}}), "alice")
	c := setCookie(v)
	if c == nil {
		t.Fatal("no cookie")
	}
	// The same cookie, a different identity: challenged again.
	r := get("/x")
	r.AddCookie(c)
	if v := run(t, g, r, "bob"); !v.Deny {
		t.Fatal("alice's cookie let bob through")
	}
	// And a tampered value is not a cookie.
	tampered := *c
	tampered.Value = c.Value[:len(c.Value)-4] + "AAAA"
	r2 := get("/x")
	r2.AddCookie(&tampered)
	if v := run(t, g, r2, "alice"); !v.Deny {
		t.Fatal("a tampered cookie was accepted")
	}
}

// A wrong code is answered with the same page as a replayed one and as
// a name that never enrolled: telling them apart is how an attacker
// learns which accounts are worth attacking.
func TestFailuresLookAlike(t *testing.T) {
	g, secret := build(t, nil)
	pages := map[string]bool{}
	read := func(v filter.Verdict) string {
		if v.Response == nil {
			t.Fatalf("no page: %+v", v)
		}
		b, _ := io.ReadAll(v.Response.Body)
		return string(b)
	}
	wrong := run(t, g, post("/x?xproxy_mfa=verify", url.Values{"code": {"000000"}}), "alice")
	pages[read(wrong)] = true

	used := code(t, secret)
	if v := run(t, g, post("/x?xproxy_mfa=verify", url.Values{"code": {used}}), "alice"); !v.Deny || v.Status != http.StatusFound {
		t.Fatalf("first use should verify: %+v", v)
	}
	replay := run(t, g, post("/x?xproxy_mfa=verify", url.Values{"code": {used}}), "alice")
	pages[read(replay)] = true

	// bob is not enrolled, so the gate refuses him; the page is the
	// same one.
	unknown := run(t, g, post("/x?xproxy_mfa=verify", url.Values{"code": {"000000"}}), "bob")
	pages[read(unknown)] = true

	if len(pages) != 1 {
		t.Fatalf("failures are distinguishable: %d different pages", len(pages))
	}
}

// A request with no identity is refused rather than challenged: a
// second factor with no first factor is a prompt with no account.
func TestNoIdentity(t *testing.T) {
	g, _ := build(t, nil)
	v := run(t, g, get("/x"), "")
	if !v.Deny || v.Status != http.StatusUnauthorized || v.Response != nil {
		t.Fatalf("no identity: %+v", v)
	}
	if !strings.Contains(v.Detail, "after the one that authenticates") {
		t.Fatalf("detail: %q", v.Detail)
	}
}

// require_enrolment: false lets an unenrolled user through, which is
// what the warning in validation is about.
func TestOptionalEnrolment(t *testing.T) {
	g, _ := build(t, map[string]any{"require_enrolment": false})
	if v := run(t, g, get("/x"), "bob"); v.Deny {
		t.Fatalf("bob should pass with require_enrolment false: %+v", v)
	}
	if v := run(t, g, get("/x"), "alice"); !v.Deny {
		t.Fatal("alice is enrolled and should still be challenged")
	}
}

// The redirect target stays on this site.
func TestSafeNext(t *testing.T) {
	g, secret := build(t, nil)
	for _, bad := range []string{"//evil.example", "https://evil.example/x", "/x\r\nSet-Cookie: a=b", "\\\\evil"} {
		v := run(t, g, post("/x?xproxy_mfa=verify", url.Values{
			"code": {code(t, secret)}, "next": {bad},
		}), "alice")
		if v.Response == nil {
			continue
		}
		if loc := v.Response.Header.Get("Location"); loc != "/" && loc != "" {
			t.Fatalf("%q became %q", bad, loc)
		}
		// Only the first code verifies; the rest are replays, which is
		// fine — the point is the target.
	}
}

// Lockout stops guessing.
func TestLockout(t *testing.T) {
	g, secret := build(t, map[string]any{"max_failures": 3, "window": "1m", "lockout": "1h"})
	for i := 0; i < 3; i++ {
		run(t, g, post("/x?xproxy_mfa=verify", url.Values{"code": {"000000"}}), "alice")
	}
	if v := run(t, g, post("/x?xproxy_mfa=verify", url.Values{"code": {code(t, secret)}}), "alice"); v.Status != http.StatusUnauthorized {
		t.Fatalf("a locked user should not verify: %+v", v)
	}
}

func TestOptionsRefused(t *testing.T) {
	dir := t.TempDir()
	cases := []map[string]any{
		{},
		{"file": filepath.Join(dir, "missing")},
		{"file": filepath.Join(dir, "missing"), "cookie_secret_file": filepath.Join(dir, "k")},
	}
	for i, opts := range cases {
		if _, err := filtertest.Build("mfa", "x", opts); err == nil {
			t.Errorf("case %d should not build", i)
		}
	}
	// A world readable enrolment file holds every second factor.
	file := filepath.Join(dir, "mfa")
	secret, _ := mfa.NewSecret()
	if err := os.WriteFile(file, []byte("alice:"+secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := filtertest.Build("mfa", "x", map[string]any{
		"file": file, "cookie_secret_file": filepath.Join(dir, "k"),
	}); err == nil {
		t.Error("a world readable enrolment file should not build")
	}
}
