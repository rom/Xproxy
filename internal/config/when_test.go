package config

import (
	"strings"
	"testing"
)

func TestWhenConfig(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - name: r
    upstream: u
    path_regex: ['/items/(?P<id>[0-9]+)']
    %s
`
	ok := []string{
		`when: 'method in ["GET", "HEAD"] && client_ip in cidr("10.0.0.0/8")'`,
		`when: 'capture("id") != "" and hour < 6'`,
		`request_headers: {set: {X-Beta: "1"}, when: 'query("beta") == "1"'}`,
		`response_headers: {remove: [Server], when: 'not has_header("X-Debug")'}`,
	}
	for _, c := range ok {
		if _, err := parseNoFiles([]byte(strings.Replace(base, "%s", c, 1))); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	bad := map[string]string{
		`when: 'bogus == 1'`:                               "routes[0].when: unknown variable",
		`when: 'header("X") =='`:                           "routes[0].when: unexpected end",
		`when: 'capture("nope") == "1"'`:                   "routes[0].when: capture",
		`request_headers: {set: {X: "1"}, when: 'nope()'}`: "routes[0].request_headers.when: unknown function",
		`response_headers: {when: 'path matches "("'}`:     "routes[0].response_headers.when: pattern",
	}
	for c, want := range bad {
		_, err := parseNoFiles([]byte(strings.Replace(base, "%s", c, 1)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v want %q", c, err, want)
		}
	}
}
