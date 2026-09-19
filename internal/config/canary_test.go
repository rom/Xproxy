package config

import (
	"strings"
	"testing"
)

func TestCanaryValidation(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: app
    %s
routes:
  - name: r
    upstream: app
`
	ok := "canary: {header: X-Canary, percent: 5}\n    endpoints: [{address: 127.0.0.1:1}, {address: 127.0.0.1:2, canary: true}]"
	cfg, err := Parse([]byte(strings.Replace(base, "%s", ok, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Upstreams[0].Endpoints[1].Canary || cfg.Upstreams[0].Canary.Percent != 5 {
		t.Fatalf("parsed %+v", cfg.Upstreams[0])
	}
	bad := []struct{ snippet, want string }{
		{"endpoints: [{address: 127.0.0.1:1, canary: true}]", "set without a canary section"},
		{"canary: {}\n    endpoints: [{address: 127.0.0.1:1}, {address: 127.0.0.1:2, canary: true}]", "header, cookie or percent"},
		{"canary: {percent: 120}\n    endpoints: [{address: 127.0.0.1:1}, {address: 127.0.0.1:2, canary: true}]", "canary.percent"},
		{"canary: {header: 'X Y'}\n    endpoints: [{address: 127.0.0.1:1}, {address: 127.0.0.1:2, canary: true}]", "not a header name"},
		{"canary: {cookie: 'a=b'}\n    endpoints: [{address: 127.0.0.1:1}, {address: 127.0.0.1:2, canary: true}]", "not a cookie name"},
		{"canary: {header: X}\n    endpoints: [{address: 127.0.0.1:1, canary: true}, {address: 127.0.0.1:2, canary: true}]", "every endpoint is a canary"},
		{"canary: {header: X}\n    endpoints: [{address: 127.0.0.1:1}]", "no endpoint is marked"},
	}
	for _, c := range bad {
		_, err := Parse([]byte(strings.Replace(base, "%s", c.snippet, 1)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.snippet, err, c.want)
		}
	}
}
