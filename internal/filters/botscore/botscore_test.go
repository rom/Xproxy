package botscore

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func build(t *testing.T, opts filter.Options) *scorer {
	t.Helper()
	f, err := filtertest.Build("bot_score", "bots", opts)
	if err != nil {
		t.Fatal(err)
	}
	return f.(*scorer)
}

func req(ua string, headers ...string) *http.Request {
	r, _ := http.NewRequest("GET", "http://h.example.test/page", nil)
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"

func TestSignals(t *testing.T) {
	s := build(t, filter.Options{"deny_at": 80, "challenge_at": 50, "header": "X-Bot-Score"})
	run := func(r *http.Request, info filter.Info) (filter.Verdict, int) {
		in := s.Begin(nil, &info).(*instance) //nolint:staticcheck // nil context is fine for the scorer
		v := in.Request(r)
		return v, in.score
	}
	browser := filter.Info{ClientIP: netip.MustParseAddr("198.51.100.1"), Path: "/page", TLS: true, JA4: "t13d1516h2_8daaf6152771_b0da82dd1658", ALPN: []string{"h2", "http/1.1"}}

	if v, score := run(req(chromeUA, "Accept", "text/html", "Accept-Language", "sv"), browser); v.Deny || score != 0 {
		t.Fatalf("browser scored %d: %+v", score, v)
	}
	r := req("curl/8.4.0")
	v, score := run(r, browser)
	if score != 40 || v.Deny || r.Header.Get("X-Bot-Score") != "40" {
		t.Fatalf("curl scored %d, header %q, verdict %+v", score, r.Header.Get("X-Bot-Score"), v)
	}
	if v, score := run(req(""), browser); score != 30 || v.Deny {
		t.Fatalf("missing ua scored %d", score)
	}
	// Browser user agent without browser headers on a non-browser hello:
	// 25 + 35 = 60 -> challenge (client not verified).
	scripted := browser
	scripted.JA4 = "t13d0403h1_000000000000_000000000000"
	scripted.ALPN = []string{"http/1.1"}
	v, score = run(req(chromeUA), scripted)
	if score != 60 || !v.Deny || !v.Challenge {
		t.Fatalf("mismatch scored %d: %+v", score, v)
	}
	verified := scripted
	verified.ChallengeVerified = true
	if v, _ := run(req(chromeUA), verified); v.Deny {
		t.Fatalf("verified client challenged again: %+v", v)
	}
	// A client marked by a honeypot (here or on a peer) scores 40 on an
	// otherwise clean browser request.
	marked := browser
	marked.HoneypotMarked = true
	if v, score := run(req(chromeUA, "Accept", "text/html", "Accept-Language", "sv"), marked); score != 40 || v.Deny || v.Challenge {
		t.Fatalf("honeypot marked scored %d: %+v", score, v)
	}
	// Allow and deny lists override everything.
	s2 := build(t, filter.Options{"deny_at": 80, "ja4_deny": []any{scripted.JA4}, "ja4_allow": []any{browser.JA4}})
	in := s2.Begin(nil, &scripted).(*instance) //nolint:staticcheck // see above
	if v := in.Request(req(chromeUA, "Accept", "*/*", "Accept-Language", "en")); !v.Deny || v.Challenge || in.score != 100 || !strings.Contains(v.Detail, "ja4_deny") {
		t.Fatalf("ja4_deny: %+v score %d", v, in.score)
	}
	in = s2.Begin(nil, &browser).(*instance) //nolint:staticcheck // see above
	if v := in.Request(req("curl/8")); v.Deny || in.score != 0 {
		t.Fatalf("ja4_allow: %+v score %d", v, in.score)
	}
}

func TestBehaviour(t *testing.T) {
	s := build(t, filter.Options{"deny_at": 80, "window": "60s", "rate_per_window": 20})
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.9")
	info := filter.Info{ClientIP: ip, TLS: true, JA4: "t13d1516h2_8daaf6152771_b0da82dd1658", ALPN: []string{"h2"}}
	// Regular one second cadence, many distinct paths, mostly 404s.
	var last *instance
	for i := 0; i < 24; i++ {
		now = now.Add(time.Second)
		info.Path = "/p" + strings.Repeat("x", i%60)
		in := s.Begin(nil, &info).(*instance) //nolint:staticcheck // scorer ignores the context
		in.Request(req(chromeUA, "Accept", "text/html", "Accept-Language", "en"))
		in.Response(&http.Response{StatusCode: 404})
		last = in
	}
	joined := strings.Join(last.signals, ",")
	for _, want := range []string{"error_rate", "regular_interval", "high_rate"} {
		if !strings.Contains(joined, want) {
			t.Errorf("signal %s missing from %q", want, joined)
		}
	}
	if last.score < 65 {
		t.Fatalf("score %d", last.score)
	}
	attrs := last.End()
	if len(attrs) != 4 || attrs[0] != "bot_score" {
		t.Fatalf("attrs %v", attrs)
	}
	// After the window the history resets.
	now = now.Add(2 * time.Minute)
	in := s.Begin(nil, &info).(*instance) //nolint:staticcheck // see above
	in.Request(req(chromeUA, "Accept", "text/html", "Accept-Language", "en"))
	if in.score != 0 {
		t.Fatalf("score after window %d (%v)", in.score, in.signals)
	}
	// Bursts are not "regular".
	if regularInterval([]time.Time{now, now, now, now, now, now, now, now, now}) {
		t.Fatal("burst counted as regular")
	}
}

func TestValidateOptions(t *testing.T) {
	bad := []filter.Options{
		{"deny_at": 101},
		{"deny_at": 50, "challenge_at": 60},
		{"window": "1s"},
		{"rate_per_window": 0},
		{"header": "bad header"},
		{"weights": map[string]any{"nope": 1}},
		{"weights": map[string]any{"ua_bot": 200}},
		{"ja4_deny": []any{"x"}},
		{"bogus": true},
	}
	for i, o := range bad {
		if _, err := filtertest.Build("bot_score", "b", o); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := filtertest.Build("bot_score", "b", nil); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
}

func TestDeviceSignals(t *testing.T) {
	s := build(t, filter.Options{"deny_at": 90, "device_addresses": 3})
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	base := filter.Info{TLS: true, JA4: "t13d1516h2_8daaf6152771_b0da82dd1658", ALPN: []string{"h2"}, Path: "/p", DeviceID: "0123456789abcdef"}
	clean := func() *http.Request { return req(chromeUA, "Accept", "text/html", "Accept-Language", "sv") }
	// A device seen from one or two addresses is nothing; from three it
	// is shared.
	for i, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		info := base
		info.ClientIP = netip.MustParseAddr(ip)
		in := s.Begin(nil, &info).(*instance) //nolint:staticcheck // scorer ignores the context
		if v := in.Request(clean()); v.Deny || in.score != 0 {
			t.Fatalf("address %d scored %d: %v", i, in.score, in.signals)
		}
	}
	info := base
	info.ClientIP = netip.MustParseAddr("198.51.100.3")
	in := s.Begin(nil, &info).(*instance) //nolint:staticcheck // see above
	in.Request(clean())
	if in.score != 25 || strings.Join(in.signals, ",") != "device_shared" {
		t.Fatalf("shared device: %d %v", in.score, in.signals)
	}
	// Automation markers from the cookie weigh 45 on an otherwise clean
	// browser; together with a shared device the client is denied.
	info.Automation = []string{"webdriver"}
	in = s.Begin(nil, &info).(*instance) //nolint:staticcheck // see above
	v := in.Request(clean())
	if in.score != 70 || v.Deny {
		t.Fatalf("automation: %d %v %+v", in.score, in.signals, v)
	}
	if v := s.Begin(nil, &info).Request(req("curl/8")); !v.Deny { //nolint:staticcheck // see above
		t.Fatalf("automation plus curl not denied: %+v", v)
	}
	// The window resets the device's addresses; a request without a
	// device never counts.
	now = now.Add(2 * time.Minute)
	in = s.Begin(nil, &info).(*instance) //nolint:staticcheck // see above
	in.Request(clean())
	if strings.Contains(strings.Join(in.signals, ","), "device_shared") {
		t.Fatalf("device window did not reset: %v", in.signals)
	}
	none := base
	none.DeviceID = ""
	none.ClientIP = netip.MustParseAddr("198.51.100.9")
	if s.observeDevice(none.DeviceID, none.ClientIP) || len(s.devices) != 1 {
		t.Fatal("empty device tracked")
	}
	attrs := in.attrs()
	if attrs[len(attrs)-2] != "device" || attrs[len(attrs)-1] != "0123456789abcdef" {
		t.Fatalf("attrs %v", attrs)
	}
	if _, err := filtertest.Build("bot_score", "b", filter.Options{"device_addresses": 1}); err == nil {
		t.Fatal("device_addresses 1 accepted")
	}
}
