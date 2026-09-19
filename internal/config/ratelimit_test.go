package config

import (
	"strings"
	"testing"
	"time"
)

func TestRateLimitAlgorithms(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
rate_limits:
  - %s
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: r, upstream: u, rate_limits: [p]}
`
	cfg, err := parseNoFiles([]byte(strings.Replace(base, "%s", `{name: p, algorithm: sliding_window, limit: 100}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if rl := cfg.RateLimits[0]; rl.Window.D() != time.Second || rl.Burst != 0 || rl.Distributed != "approximate" {
		t.Fatalf("defaults %+v", rl)
	}
	cfg, err = parseNoFiles([]byte(strings.Replace(base, "%s", `{name: p, rate: 10}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if rl := cfg.RateLimits[0]; rl.Algorithm != "token_bucket" || rl.Burst != 10 || rl.Window != 0 {
		t.Fatalf("token bucket defaults %+v", rl)
	}
	bad := map[string]string{
		`{name: p, algorithm: leaky, rate: 1}`:                         "algorithm: must be token_bucket or sliding_window",
		`{name: p, algorithm: sliding_window}`:                         "limit: must be between",
		`{name: p, algorithm: sliding_window, limit: 5, window: 10ms}`: "window: must be between 100ms and 24h",
		`{name: p, algorithm: sliding_window, limit: 5, rate: 1}`:      "rate and burst belong to algorithm token_bucket",
		`{name: p, rate: 1, limit: 5}`:                                 "limit and window belong to algorithm sliding_window",
		`{name: p, rate: 1, distributed: shared}`:                      "distributed: must be approximate or exact",
		`{name: p, rate: 1, distributed: exact}`:                       "exact needs a cluster section",
	}
	for c, want := range bad {
		_, err := parseNoFiles([]byte(strings.Replace(base, "%s", c, 1)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v want %q", c, err, want)
		}
	}
}
