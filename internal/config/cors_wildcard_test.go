package config

import (
	"strings"
	"testing"
)

// TestCORSWildcardOrigins: a wildcard origin must be a whole leading label
// ("https://*.example.com"); a bare "https://*example.com" would also admit
// evilexample.com and is refused, as is "*" combined with credentials.
func TestCORSWildcardOrigins(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "10.0.0.1:80"}]
routes:
  - name: r
    upstream: u
    cors: {allow_origins: [%s]%s}
`
	ok := []string{`"https://*.example.com"`, `"https://app.example.com"`, `"*"`}
	for _, o := range ok {
		if _, err := parseNoFiles([]byte(strings.Replace(strings.Replace(base, "%s", o, 1), "%s", "", 1))); err != nil {
			t.Errorf("%s rejected: %v", o, err)
		}
	}
	bad := map[string]string{
		`"https://*example.com"`:    "",
		`"https://a.*.example.com"`: "",
		`"https://*.*.example.com"`: "",
		`"https://*."`:              "",
		`"https://*.example.com/x"`: "",
		`"*"`:                       ", allow_credentials: true",
	}
	for o, extra := range bad {
		y := strings.Replace(strings.Replace(base, "%s", o, 1), "%s", extra, 1)
		if _, err := parseNoFiles([]byte(y)); err == nil {
			t.Errorf("%s%s accepted", o, extra)
		}
	}
}
