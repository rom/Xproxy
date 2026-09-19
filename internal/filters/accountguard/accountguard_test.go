package accountguard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

type fakeEvents struct {
	mu        sync.Mutex
	published []filter.Event
	subs      map[string][]func(filter.Event)
}

func (f *fakeEvents) Publish(e filter.Event) {
	f.mu.Lock()
	f.published = append(f.published, e)
	f.mu.Unlock()
}

func (f *fakeEvents) Subscribe(kind string, fn func(filter.Event)) {
	if f.subs == nil {
		f.subs = map[string][]func(filter.Event){}
	}
	f.subs[kind] = append(f.subs[kind], fn)
}

func (f *fakeEvents) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.published)
}

func build(t *testing.T, opts filter.Options, ev filter.Events) *guard {
	t.Helper()
	k, _ := filter.Lookup("account_guard")
	if err := k.Validate(opts); err != nil {
		t.Fatal(err)
	}
	f, err := k.New("accounts", opts, filter.Env{Events: ev})
	if err != nil {
		t.Fatal(err)
	}
	return f.(*guard)
}

var loginOpts = filter.Options{
	"endpoints": []any{map[string]any{
		"name": "login", "class": "login", "paths": []any{"/api/login"},
		"identity": map[string]any{"json": "user.name", "form": "username"},
		"failure":  map[string]any{"statuses": []any{401}, "body_regex": `"ok":false`},
		"steps": []any{
			map[string]any{"action": "delay", "delay": "50ms", "pair": 3},
			map[string]any{"action": "challenge", "pair": 5, "ip_accounts": 10, "account_ips": 5},
			map[string]any{"action": "block", "duration": "15m", "pair": 8, "ip": 40, "ip_accounts": 30},
		},
		"distributed": map[string]any{"ips": 20, "events": 60},
	}},
}

func login(ip, user string) (*http.Request, filter.Info) {
	r := httptest.NewRequest("POST", "http://app.example.com/api/login", strings.NewReader(`{"user":{"name":"`+user+`"},"password":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	return r, filter.Info{ClientIP: netip.MustParseAddr(ip), Path: "/api/login", Method: "POST"}
}

func attempt(g *guard, ip, user string, status int, verified bool) (filter.Verdict, *instance) {
	r, info := login(ip, user)
	info.ChallengeVerified = verified
	in := g.Begin(context.Background(), &info).(*instance)
	v := in.Request(r)
	if !v.Deny && status > 0 {
		in.Response(&http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))})
	}
	return v, in
}

func TestLoginLadder(t *testing.T) {
	ev := &fakeEvents{}
	g := build(t, loginOpts, ev)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	const ip, user = "203.0.113.5", "Anna@Example.com"
	for i := 0; i < 3; i++ {
		if v, in := attempt(g, ip, user, 401, false); v.Deny || in.action != "" {
			t.Fatalf("attempt %d: %+v action %q", i, v, in.action)
		}
	}
	// Three failures on the pair: the fourth attempt is delayed.
	start := time.Now()
	v, in := attempt(g, ip, user, 401, false)
	if v.Deny || in.action != "delay" || in.by != "pair" || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("delay step: %+v action %q by %q", v, in.action, in.by)
	}
	attempt(g, ip, user, 401, false) // fifth failure
	v, in = attempt(g, ip, user, 401, false)
	if !v.Deny || !v.Challenge || v.Reason != Reason || in.action != "challenge" || in.counts.pair != 5 {
		t.Fatalf("challenge step: %+v counts %s", v, in.counts)
	}
	// A verified client passes the challenge step and keeps failing.
	for i := 0; i < 3; i++ {
		if v, _ := attempt(g, ip, user, 401, true); v.Deny {
			t.Fatalf("verified attempt %d denied: %+v", i, v)
		}
	}
	v, in = attempt(g, ip, user, 401, true)
	if !v.Deny || v.Challenge || v.Status != 429 || in.action != "block" || !strings.Contains(v.Detail, "login:block:pair") {
		t.Fatalf("block step: %+v", v)
	}
	if ev.count() != 1 || !strings.HasPrefix(ev.published[0].Key, "accounts|login|pair|pair|"+ip+"|") {
		t.Fatalf("block not published: %+v", ev.published)
	}
	// Blocked while the block lasts, whatever the client sends; another
	// account from the same address is not blocked.
	if v, in := attempt(g, ip, user, 200, true); !v.Deny || in.outcome != "blocked" || !strings.Contains(v.Detail, "blocked:pair") {
		t.Fatalf("blocked request: %+v", v)
	}
	if v, _ := attempt(g, ip, "other@example.com", 200, false); v.Deny {
		t.Fatalf("other account blocked: %+v", v)
	}
	now = now.Add(16 * time.Minute)
	if v, in := attempt(g, ip, user, 200, false); v.Deny || in.outcome != "success" {
		t.Fatalf("after the block: %+v outcome %q", v, in.outcome)
	}
	// Identity is case folded and hashed; the log never carries it.
	attrs := in.End()
	joined := strings.ToLower(strings.Join(func() []string {
		var s []string
		for _, a := range attrs {
			s = append(s, strings.ToLower(strings.TrimSpace(strings.Trim(strings.ReplaceAll(strings.ReplaceAll(strconvQuote(a), `"`, ""), "\n", ""), " "))))
		}
		return s
	}(), " "))
	if strings.Contains(joined, "anna") || !strings.Contains(joined, "account_hash") || !strings.Contains(joined, hashIdentity("anna@example.com")) {
		t.Fatalf("attrs %v", attrs)
	}
	// A body failure (2xx with the error marker) counts; a success
	// clears the account and pair counters.
	r, info := login(ip, user)
	in = g.Begin(context.Background(), &info).(*instance)
	in.Request(r)
	in.Response(&http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"ok":false}`)), ContentLength: -1})
	if in.outcome != "failure" || in.counts.pair != 1 {
		t.Fatalf("body failure: %q %s", in.outcome, in.counts)
	}
	attempt(g, ip, user, 401, false)
	if _, in := attempt(g, ip, user, 302, false); in.outcome != "success" || in.counts.pair != 0 || in.counts.account != 0 || in.counts.ip != 2 {
		t.Fatalf("success reset: %q %s", in.outcome, in.counts)
	}
}

func strconvQuote(a any) string {
	switch v := a.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func TestCredentialStuffing(t *testing.T) {
	g := build(t, loginOpts, nil)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	const ip = "203.0.113.7"
	// One address, many accounts, one failure each: no pair or account
	// threshold fires, ip_accounts does.
	for i := 0; i < 10; i++ {
		if v, _ := attempt(g, ip, "u"+strconv.Itoa(i)+"@example.com", 401, false); v.Deny {
			t.Fatalf("account %d denied: %+v", i, v)
		}
	}
	v, in := attempt(g, ip, "u99@example.com", 401, false)
	if !v.Deny || !v.Challenge || in.by != "ip_accounts" || in.counts.ipAccounts != 10 {
		t.Fatalf("stuffing: %+v by %q counts %s", v, in.by, in.counts)
	}
	// One account, many addresses (password spraying against one user
	// or a distributed brute force): account_ips fires.
	for i := 0; i < 5; i++ {
		attempt(g, "198.51.100."+strconv.Itoa(i+1), "victim@example.com", 401, false)
	}
	v, in = attempt(g, "198.51.100.200", "victim@example.com", 401, false)
	if !v.Deny || in.by != "account_ips" || in.counts.accountIPs != 5 {
		t.Fatalf("spraying: %+v by %q counts %s", v, in.by, in.counts)
	}
	// The window resets the counts.
	now = now.Add(11 * time.Minute)
	if v, in := attempt(g, ip, "u99@example.com", 401, false); v.Deny || in.counts.ipAccounts != 1 || in.counts.ip != 1 {
		t.Fatalf("after window: %+v %s", v, in.counts)
	}
}

func TestDistributedCampaign(t *testing.T) {
	ev := &fakeEvents{}
	g := build(t, loginOpts, ev)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	// Thirty addresses, two failures each on distinct accounts: every
	// address stays under its own thresholds.
	for i := 0; i < 30; i++ {
		ip := "192.0.2." + strconv.Itoa(i+1)
		for j := 0; j < 2; j++ {
			if v, _ := attempt(g, ip, "a"+strconv.Itoa(i*2+j)+"@example.com", 401, false); v.Deny {
				t.Fatalf("early deny %d/%d: %+v", i, j, v)
			}
		}
	}
	tbl := g.cfg.Endpoints[0].table
	if tbl.campaignUntil.IsZero() || ev.count() != 1 || !strings.HasSuffix(ev.published[0].Key, "|campaign|campaign") {
		t.Fatalf("campaign not detected: until %v events %+v", tbl.campaignUntil, ev.published)
	}
	// A fresh address is now challenged; a verified client passes.
	v, in := attempt(g, "203.0.113.99", "fresh@example.com", 401, false)
	if !v.Deny || !v.Challenge || in.by != "campaign" || !in.campaign {
		t.Fatalf("campaign challenge: %+v by %q", v, in.by)
	}
	if v, _ := attempt(g, "203.0.113.99", "fresh@example.com", 200, true); v.Deny {
		t.Fatalf("verified during campaign: %+v", v)
	}
	// Campaign state expires with its duration (the window).
	now = now.Add(11 * time.Minute)
	if v, in := attempt(g, "203.0.113.98", "x@example.com", 401, false); v.Deny || in.campaign {
		t.Fatalf("campaign did not expire: %+v", v)
	}
	// A peer's block and campaign events apply locally.
	fn := ev.subs[EventKind][0]
	fn(filter.Event{Kind: EventKind, Key: "accounts|login|ip|ip|203.0.113.50", Until: now.Add(time.Hour)})
	if v, in := attempt(g, "203.0.113.50", "y@example.com", 200, false); !v.Deny || in.outcome != "blocked" {
		t.Fatalf("peer block not applied: %+v", v)
	}
	fn(filter.Event{Kind: EventKind, Key: "accounts|login|campaign|campaign", Until: now.Add(time.Hour)})
	if v, in := attempt(g, "203.0.113.51", "z@example.com", 401, false); !v.Deny || !in.campaign {
		t.Fatalf("peer campaign not applied: %+v", v)
	}
	// Events for another filter or endpoint are ignored.
	fn(filter.Event{Kind: EventKind, Key: "other|login|ip|ip|203.0.113.52", Until: now.Add(time.Hour)})
	fn(filter.Event{Kind: EventKind, Key: "accounts|nope|ip|ip|203.0.113.52", Until: now.Add(time.Hour)})
	if v, _ := attempt(g, "203.0.113.52", "w@example.com", 200, true); v.Deny {
		t.Fatalf("foreign event applied: %+v", v)
	}
}

func TestRegisterResetScrape(t *testing.T) {
	g := build(t, filter.Options{
		"disposable_domains": []any{"throwaway.example"},
		"endpoints": []any{
			map[string]any{"name": "signup", "class": "register", "paths": []any{"/signup"}, "identity": map[string]any{"form": "email"}, "disposable": "challenge"},
			map[string]any{"name": "reset", "class": "reset", "paths": []any{"/reset"}, "identity": map[string]any{"query": "email"}},
			map[string]any{"name": "catalogue", "class": "scrape", "paths": []any{"/products/*"},
				"steps": []any{map[string]any{"action": "block", "ip_paths": 5}}},
			map[string]any{"name": "cart", "class": "cart", "paths": []any{"/cart/add"}, "identity": map[string]any{"header": "X-Session"},
				"steps": []any{map[string]any{"action": "log", "account": 2}, map[string]any{"action": "block", "account": 4, "duration": "1m"}}},
		},
	}, nil)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	post := func(ip, path, body, ctype string, hdr ...string) (filter.Verdict, *instance) {
		r := httptest.NewRequest("POST", "http://app.example.com"+path, strings.NewReader(body))
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		u := r.URL
		info := filter.Info{ClientIP: netip.MustParseAddr(ip), Path: u.Path, Method: "POST"}
		in := g.Begin(context.Background(), &info).(*instance)
		return in.Request(r), in
	}
	// Disposable addresses are challenged, including subdomains of a
	// listed domain and operator additions.
	if v, in := post("203.0.113.1", "/signup", "email=bob%40mail.mailinator.com", "application/x-www-form-urlencoded"); !v.Deny || !v.Challenge || in.by != "disposable_email" {
		t.Fatalf("disposable: %+v", v)
	}
	if v, _ := post("203.0.113.1", "/signup", "email=bob%40throwaway.example", "application/x-www-form-urlencoded"); !v.Deny {
		t.Fatalf("operator disposable: %+v", v)
	}
	// Registration: the default ladder challenges the second request
	// for the same address (the account count), whatever the source
	// address (each request counts itself).
	if v, _ := post("203.0.113.10", "/signup", "email=same%40example.com", "application/x-www-form-urlencoded"); v.Deny {
		t.Fatalf("first signup: %+v", v)
	}
	if v, in := post("203.0.113.12", "/signup", "email=same%40example.com", "application/x-www-form-urlencoded"); !v.Deny || !v.Challenge || in.by != "account" {
		t.Fatalf("repeat registration: %+v by %q", v, in.by)
	}
	// Reset identity from the query string.
	r := httptest.NewRequest("POST", "http://app.example.com/reset?email=Who%40example.com", nil)
	info := filter.Info{ClientIP: netip.MustParseAddr("203.0.113.20"), Path: "/reset", Method: "POST"}
	in := g.Begin(context.Background(), &info).(*instance)
	in.Request(r)
	if in.hash != hashIdentity("who@example.com") || in.counts.account != 1 {
		t.Fatalf("reset identity: %q %s", in.hash, in.counts)
	}
	// Scraping: distinct paths per address on a prefix endpoint.
	for i := 0; i < 4; i++ {
		rr := httptest.NewRequest("GET", "http://app.example.com/products/"+strconv.Itoa(i), nil)
		inf := filter.Info{ClientIP: netip.MustParseAddr("203.0.113.30"), Path: rr.URL.Path, Method: "GET"}
		if v := g.Begin(context.Background(), &inf).Request(rr); v.Deny {
			t.Fatalf("product %d: %+v", i, v)
		}
	}
	rr := httptest.NewRequest("GET", "http://app.example.com/products/5", nil)
	inf := filter.Info{ClientIP: netip.MustParseAddr("203.0.113.30"), Path: "/products/5", Method: "GET"}
	if v := g.Begin(context.Background(), &inf).Request(rr); !v.Deny || !strings.Contains(v.Detail, "ip_paths") {
		t.Fatalf("scrape: %+v", v)
	}
	// A POST to the catalogue does not match the GET endpoint.
	if v, in := post("203.0.113.30", "/products/6", "", ""); v.Deny || in.ep != nil {
		t.Fatalf("method mismatch matched: %+v", v)
	}
	// Cart: identity from a header, log step then block by account.
	for i := 0; i < 3; i++ {
		v, in := post("203.0.113.4"+strconv.Itoa(i), "/cart/add", "", "", "X-Session", "s1")
		if v.Deny {
			t.Fatalf("cart %d: %+v", i, v)
		}
		if i >= 1 && in.action != "log" {
			t.Fatalf("cart %d action %q", i, in.action)
		}
	}
	if v, _ := post("203.0.113.44", "/cart/add", "", "", "X-Session", "s1"); !v.Deny || v.Status != 429 {
		t.Fatalf("hoarding: %+v", v)
	}
	if v, _ := post("203.0.113.44", "/cart/add", "", "", "X-Session", "s2"); v.Deny {
		t.Fatalf("other session blocked: %+v", v)
	}
}

func TestCaptchaAction(t *testing.T) {
	g := build(t, filter.Options{"endpoints": []any{
		map[string]any{"name": "login", "class": "login", "paths": []any{"/api/login"}, "identity": map[string]any{"json": "user.name"},
			"steps":       []any{map[string]any{"action": "challenge", "pair": 1}, map[string]any{"action": "captcha", "pair": 2}},
			"distributed": map[string]any{"ips": 2, "events": 4, "action": "captcha"}},
	}}, nil)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	attempt(g, "203.0.113.1", "a@example.com", 401, false)
	// One failure: the challenge step; a proof cookie passes it.
	v, in := attempt(g, "203.0.113.1", "a@example.com", 401, true)
	if v.Deny || in.action != "challenge" {
		t.Fatalf("challenge step with proof: %+v %q", v, in.action)
	}
	// Two failures: the captcha step; a proof cookie is not enough, a
	// captcha cookie is.
	v, in = attempt(g, "203.0.113.1", "a@example.com", 401, true)
	if !v.Deny || !v.Challenge || !v.Captcha || in.action != "captcha" || !strings.Contains(v.Detail, "login:captcha:pair") {
		t.Fatalf("captcha step: %+v", v)
	}
	r, info := login("203.0.113.1", "a@example.com")
	info.ChallengeVerified, info.CaptchaVerified = true, true
	if v := g.Begin(context.Background(), &info).Request(r); v.Deny {
		t.Fatalf("captcha verified denied: %+v", v)
	}
	// A campaign with a captcha action outranks a challenge step.
	for i := 0; i < 4; i++ {
		attempt(g, "203.0.113."+strconv.Itoa(10+i), "b"+strconv.Itoa(i)+"@example.com", 401, false)
	}
	v, in = attempt(g, "203.0.113.50", "c@example.com", 401, true)
	if !v.Deny || !v.Captcha || in.by != "campaign" {
		t.Fatalf("campaign captcha: %+v by %q", v, in.by)
	}
}

func TestIdentityAndBodies(t *testing.T) {
	g := build(t, filter.Options{"max_body_bytes": 64, "endpoints": []any{map[string]any{
		"name": "login", "class": "login", "paths": []any{"/login"}, "identity": map[string]any{"json": "email", "form": "email"}}}}, nil)
	run := func(body, ctype string) (*instance, string) {
		r := httptest.NewRequest("POST", "http://app.example.com/login", strings.NewReader(body))
		r.Header.Set("Content-Type", ctype)
		info := filter.Info{ClientIP: netip.MustParseAddr("203.0.113.1"), Path: "/login", Method: "POST"}
		in := g.Begin(context.Background(), &info).(*instance)
		in.Request(r)
		got, _ := io.ReadAll(r.Body)
		return in, string(got)
	}
	if in, body := run(`{"email":" Anna@Example.com "}`, "application/json"); in.hash != hashIdentity("anna@example.com") || body != `{"email":" Anna@Example.com "}` {
		t.Fatalf("json: %q %q", in.hash, body)
	}
	if in, body := run("email=b%40example.com&pw=1", "application/x-www-form-urlencoded; charset=utf-8"); in.hash != hashIdentity("b@example.com") || body != "email=b%40example.com&pw=1" {
		t.Fatalf("form: %q %q", in.hash, body)
	}
	big := `{"email":"c@example.com","pad":"` + strings.Repeat("x", 100) + `"}`
	if in, body := run(big, "application/json"); in.hash != "" || body != big {
		t.Fatalf("oversize: %q len %d", in.hash, len(body))
	}
	if in, body := run("<x/>", "text/xml"); in.hash != "" || body != "<x/>" {
		t.Fatalf("other type: %q %q", in.hash, body)
	}
	if in, _ := run(`{"email":42}`, "application/json"); in.hash != hashIdentity("42") {
		t.Fatalf("number identity: %q", in.hash)
	}
	if in, _ := run(`not json`, "application/json"); in.hash != "" {
		t.Fatalf("bad json: %q", in.hash)
	}
}

func TestDelaySlots(t *testing.T) {
	g := build(t, filter.Options{"max_delayed": 1, "endpoints": []any{map[string]any{
		"name": "x", "class": "custom", "paths": []any{"/x"}, "steps": []any{map[string]any{"action": "delay", "delay": "100ms", "ip": 1}}}}}, nil)
	info := filter.Info{ClientIP: netip.MustParseAddr("203.0.113.1"), Path: "/x", Method: "GET"}
	g.delaying.Store(1) // one holder already
	start := time.Now()
	r := httptest.NewRequest("GET", "http://a/x", nil)
	if v := g.Begin(context.Background(), &info).Request(r); v.Deny || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("slot exhaustion did not skip the delay: %+v", v)
	}
	if g.skipped.Total() != 1 {
		t.Fatalf("skipped %d", g.skipped.Total())
	}
	g.delaying.Store(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if v := g.Begin(ctx, &info).Request(r); v.Deny || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("cancelled context held the delay: %+v", v)
	}
}

func TestValidateOptions(t *testing.T) {
	ep := func(m map[string]any) filter.Options {
		base := map[string]any{"name": "e", "class": "login", "paths": []any{"/l"}, "identity": map[string]any{"json": "u"}}
		for k, v := range m {
			base[k] = v
		}
		return filter.Options{"endpoints": []any{base}}
	}
	bad := []filter.Options{
		{},
		ep(map[string]any{"class": "nope"}),
		ep(map[string]any{"paths": []any{"l"}}),
		ep(map[string]any{"identity": map[string]any{}}),
		ep(map[string]any{"count": "sometimes"}),
		ep(map[string]any{"count": "requests", "failure": map[string]any{"statuses": []any{401}}}),
		ep(map[string]any{"failure": map[string]any{"statuses": []any{99}}}),
		ep(map[string]any{"failure": map[string]any{"body_regex": "("}}),
		ep(map[string]any{"window": "1s"}),
		ep(map[string]any{"steps": []any{map[string]any{"action": "block"}}}),
		ep(map[string]any{"steps": []any{map[string]any{"action": "nuke", "ip": 1}}}),
		ep(map[string]any{"disposable": "captcha", "identity": map[string]any{}, "class": "custom", "steps": []any{map[string]any{"action": "log", "ip": 1}}}),
		ep(map[string]any{"steps": []any{map[string]any{"action": "delay", "delay": "1m", "ip": 1}}}),
		ep(map[string]any{"distributed": map[string]any{"ips": 1, "events": 1}}),
		ep(map[string]any{"distributed": map[string]any{"ips": 10, "events": 5}}),
		ep(map[string]any{"disposable": "maybe"}),
		ep(map[string]any{"class": "custom", "identity": map[string]any{}, "steps": []any{}}),
		{"endpoints": []any{map[string]any{"name": "a", "class": "custom", "paths": []any{"/a"}, "steps": []any{map[string]any{"action": "log", "ip": 1}}}, map[string]any{"name": "a", "class": "custom", "paths": []any{"/b"}, "steps": []any{map[string]any{"action": "log", "ip": 1}}}}},
		{"block_status": 200, "endpoints": []any{map[string]any{"name": "a", "class": "scrape", "paths": []any{"/a"}}}},
		{"disposable_domains": []any{"Bad.Example"}, "endpoints": []any{map[string]any{"name": "a", "class": "scrape", "paths": []any{"/a"}}}},
	}
	for i, o := range bad {
		if _, err := filtertest.Build("account_guard", "a", o); err == nil {
			t.Errorf("options %d accepted: %v", i, o)
		}
	}
	// Defaults per class and a passing custom endpoint.
	f, err := filtertest.Build("account_guard", "a", filter.Options{"endpoints": []any{
		map[string]any{"name": "l", "class": "login", "paths": []any{"/l"}, "identity": map[string]any{"json": "u"}},
		map[string]any{"name": "r", "class": "register", "paths": []any{"/r"}, "identity": map[string]any{"json": "u"}},
		map[string]any{"name": "p", "class": "reset", "paths": []any{"/p"}, "identity": map[string]any{"json": "u"}},
		map[string]any{"name": "c", "class": "cart", "paths": []any{"/c"}},
		map[string]any{"name": "s", "class": "scrape", "paths": []any{"/s/*"}},
		map[string]any{"name": "x", "class": "custom", "paths": []any{"/x"}, "methods": []any{"put"}, "steps": []any{map[string]any{"action": "log", "ip": 1}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	g := f.(*guard)
	if e := g.cfg.Endpoints[0]; !e.failures || len(e.Steps) != 3 || e.Distributed == nil || !e.Failure.statuses[401] || e.window != 10*time.Minute {
		t.Fatalf("login defaults: %+v", e)
	}
	if e := g.cfg.Endpoints[4]; e.failures || !e.methods["GET"] || len(e.prefixes) != 1 || e.Distributed != nil {
		t.Fatalf("scrape defaults: %+v", e)
	}
	if e := g.cfg.Endpoints[5]; !e.methods["PUT"] || len(e.methods) != 1 {
		t.Fatalf("custom methods: %+v", e.methods)
	}
	if g.match("/s/anything", "GET") == nil || g.match("/s", "GET") != nil || g.match("/x", "PUT") == nil || g.match("/x", "POST") != nil {
		t.Fatal("matching")
	}
	// An unmatched request is untouched and logs nothing.
	res := filtertest.Run(f, httptest.NewRequest("GET", "http://a/other", nil), &http.Response{StatusCode: 200})
	if res.Request.Deny || res.Attrs != nil {
		t.Fatalf("unmatched: %+v", res)
	}
}
