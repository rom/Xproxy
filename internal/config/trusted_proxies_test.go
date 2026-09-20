package config

import (
	"strings"
	"testing"
)

// TestTrustedProxiesRefusesEverything: an all-address prefix would let any
// client choose its own address through X-Forwarded-For; it is refused.
func TestTrustedProxiesRefusesEverything(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [%s]
upstreams:
  - name: u
    endpoints: [{address: "10.0.0.1:80"}]
routes:
  - {name: r, upstream: u}
`
	for _, bad := range []string{`"0.0.0.0/0"`, `"::/0"`, `"10.0.0.0/8", "::/0"`} {
		if _, err := parseNoFiles([]byte(strings.Replace(base, "%s", bad, 1))); err == nil || !strings.Contains(err.Error(), "every client") {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
	if _, err := parseNoFiles([]byte(strings.Replace(base, "%s", `"10.0.0.0/8", "fd00::/8"`, 1))); err != nil {
		t.Fatalf("ordinary prefixes rejected: %v", err)
	}
}
