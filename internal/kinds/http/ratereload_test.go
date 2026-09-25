package http

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// limitedGet is one request to the limited route, as the status code.
func limitedGet(t *testing.T, url string) int {
	t.Helper()
	resp, _ := get(t, url, "Host", "limited.test")
	return resp.StatusCode
}

const rateReloadYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
rate_limits:
  - {name: tiny, rate: %s, burst: 2}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: limited
    hosts: [limited.test]
    rate_limits: [tiny]
    upstream: a
`

// A rate limit is state, and a reload must not reset it.
//
// This is the case that matters operationally: a reload is something an
// operator does *because* something is going on, and if every reload hands
// the client being limited a fresh bucket then a limit can be defeated by
// anyone who can make the proxy reload -- or simply lost at the worst
// moment.
func TestARateLimitSurvivesAReload(t *testing.T) {
	a := newBackend(t, "a")
	yaml := fmt.Sprintf(rateReloadYAML, "0.001", a.addr())
	s, url := startServer(t, yaml)

	// Spend the burst: two pass, the third is refused.
	drain := func() (allowed int) {
		for i := 0; i < 3; i++ {
			code := limitedGet(t, url)
			if code == http.StatusTooManyRequests {
				return i
			}
			allowed = i + 1
		}
		return allowed
	}
	if got := drain(); got != 2 {
		t.Fatalf("the burst allowed %d requests, want 2", got)
	}

	// The same configuration, reloaded. At 0.001 tokens per second
	// nothing refills in the life of this test, so anything allowed
	// afterwards came from a bucket that was thrown away.
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if code := limitedGet(t, url); code != http.StatusTooManyRequests {
		t.Errorf("the reload refilled the bucket: %d", code)
	}

	// A reload that *changes* the bound starts again, because a level
	// measured in the old rate's tokens says nothing about the new one.
	cfg2, err := config.Parse([]byte(fmt.Sprintf(rateReloadYAML, "50", a.addr())))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg2); err != nil {
		t.Fatal(err)
	}
	if code := limitedGet(t, url); code == http.StatusTooManyRequests {
		t.Error("a changed rate kept the old bucket")
	}
}

// The shape comparison itself: the bounds and the key decide, the rest of
// a policy does not.
func TestWhatCountsAsTheSameRateLimit(t *testing.T) {
	base := &config.RateLimit{Name: "x", Key: "client_ip", Rate: 10, Burst: 20}
	same := func(f func(*config.RateLimit)) bool {
		c := *base
		f(&c)
		return sameRateLimitShape(base, &c)
	}
	// The decision, not the counting: these keep the buckets.
	if !same(func(c *config.RateLimit) { c.Action = "tarpit" }) {
		t.Error("the action should not reset the buckets")
	}
	if !same(func(c *config.RateLimit) { c.TarpitDelay = config.Duration(1) }) {
		t.Error("the tarpit delay should not reset the buckets")
	}
	if !same(func(c *config.RateLimit) { c.Distributed = "exact" }) {
		t.Error("the cluster semantics should not reset the buckets")
	}
	// The counting: these must.
	for name, f := range map[string]func(*config.RateLimit){
		"the rate":      func(c *config.RateLimit) { c.Rate = 11 },
		"the burst":     func(c *config.RateLimit) { c.Burst = 21 },
		"the algorithm": func(c *config.RateLimit) { c.Algorithm = "sliding_window" },
		"the limit":     func(c *config.RateLimit) { c.Limit = 5 },
		"the window":    func(c *config.RateLimit) { c.Window = config.Duration(1) },
		"the key":       func(c *config.RateLimit) { c.Key = "jwt:sub" },
		"the v4 prefix": func(c *config.RateLimit) { c.NetV4 = 16 },
		"the v6 prefix": func(c *config.RateLimit) { c.NetV6 = 32 },
	} {
		if same(f) {
			t.Errorf("%s changed and the buckets were kept", name)
		}
	}
	if sameRateLimitShape(nil, base) || sameRateLimitShape(base, nil) {
		t.Error("a missing policy is not the same policy")
	}
}
