package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxytest"
)

// A resolver is where a domain feed earns its keep: the query for a name
// somebody else attributed is the first thing a compromised machine does, and
// it happens before any connection an address list could match.
//
// What this pins down: a listed name is refused, so is every name under it, a
// list that only logs answers normally, an unlisted name is untouched -- and a
// policy zone's passthru rule exempts a name from the lists as well, which is
// the one place an operator can write "this resolves whatever a feed says".
func TestAnImportedListDecidesAQueryName(t *testing.T) {
	upstream := fakeUpstream(t)
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked.txt")
	if err := os.WriteFile(blocked, []byte("evil-feed.test\nexempt.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noted := filepath.Join(dir, "noted.txt")
	if err := os.WriteFile(noted, []byte("noted.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zone := filepath.Join(dir, "feed.rpz")
	body := `$TTL 60
$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
@ NS ns.rpz.local.
exempt.test.rpz.local. CNAME rpz-passthru.
`
	if err := os.WriteFile(zone, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["%s"]
        rpz:
          refresh: 0
          zones:
            - {name: feed, file: %s}
logging:
  access: {enabled: false}
threat_intel:
  lists:
    - {name: bad-names, kind: domain, file: %s, action: block}
    - {name: noted-names, kind: domain, file: %s, action: log}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - {name: r, upstream: app}
`, upstream, zone, blocked, noted)
	s := proxytest.Start(t, yaml)
	addr := s.Addrs()["resolver"]
	lookup := func(name string) ([]string, error) {
		t.Helper()
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return r.LookupHost(ctx, name)
	}
	// The listed name, and a name under it: refused, answered the way the
	// operator's own block list is answered, which here is the default.
	for _, name := range []string{"evil-feed.test", "c2.evil-feed.test"} {
		if _, err := lookup(name); err == nil || !strings.Contains(err.Error(), "no such host") {
			t.Errorf("%s: %v, want NXDOMAIN", name, err)
		}
	}
	// A list that only logs is not a block: the name resolves.
	if ips, err := lookup("noted.test"); err != nil || len(ips) != 1 || ips[0] != "192.0.2.7" {
		t.Errorf("a log-only list refused a name: %v %v", ips, err)
	}
	// A name nothing lists is untouched.
	if ips, err := lookup("ordinary.test"); err != nil || len(ips) != 1 {
		t.Errorf("an unlisted name: %v %v", ips, err)
	}
	// And the exemption: the name is in a blocking list and in a passthru
	// rule, and the rule wins. An exemption that covered the policy zones but
	// not the lists would be an exemption nobody can reason about.
	if ips, err := lookup("exempt.test"); err != nil || len(ips) != 1 || ips[0] != "192.0.2.7" {
		t.Errorf("a passthru rule did not exempt the name from the lists: %v %v", ips, err)
	}
	// The counters: one match per query the resolver sent (A and AAAA), and
	// the blocked ones counted apart from the noted one.
	c := s.Counters()
	if c.ThreatIntelMatched.Load() < 4 {
		t.Errorf("threat_intel_matched %d, want at least the four blocked queries", c.ThreatIntelMatched.Load())
	}
	if c.ThreatIntelBlocked.Load() < 4 {
		t.Errorf("threat_intel_blocked %d", c.ThreatIntelBlocked.Load())
	}
	if st := s.DNS(); len(st) != 1 || st[0].Blocked < 4 {
		t.Errorf("the listener's blocked count: %+v", st)
	}
}
