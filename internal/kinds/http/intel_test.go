package http

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// End to end: an imported list, the three actions, and the route that is
// exempt from all of it.
func TestAnImportedListDecidesWhatItsActionSays(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(list, []byte("# a feed\n127.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	quiet := filepath.Join(dir, "log.txt")
	if err := os.WriteFile(quiet, []byte("127.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := newBackend(t, "app")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
threat_intel:
  refresh: 0
  lists:
    - {name: watched, file: %s, action: log}
routes:
  - {name: app, hosts: [app.test], upstream: app}
  - {name: health, hosts: [health.test], upstream: app, threat_intel: false}
`, b.addr(), quiet)
	srv, url := startServer(t, yaml)
	get := func(host string) int {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, url+"/x", nil)
		r.Host = host
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// A list that only logs serves the request, and counts it.
	if code := get("app.test"); code != http.StatusOK {
		t.Errorf("a logged match answered %d, want 200", code)
	}
	if srv.Stats().ThreatIntelMatched != 1 {
		t.Errorf("matches counted: %d", srv.Stats().ThreatIntelMatched)
	}
	if srv.Stats().ThreatIntelBlocked != 0 {
		t.Error("a list that only logs blocked something")
	}
	// The exempt route is not even matched against.
	if code := get("health.test"); code != http.StatusOK {
		t.Errorf("the exempt route answered %d", code)
	}
	if got := srv.Stats().ThreatIntelMatched; got != 1 {
		t.Errorf("the exempt route was matched: %d", got)
	}
	// The status names the list, with the entries it read and the hits.
	st := srv.Stats().ThreatLists
	if len(st) != 1 || st[0].Name != "watched" || st[0].Entries != 1 || st[0].Hits != 1 {
		t.Errorf("status: %+v", st)
	}
	// refresh: 0 on this listener, so nothing is watching the files; the
	// status says which it is, because "the feed changed and nothing
	// happened" is otherwise unanswerable.
	if srv.Stats().ThreatIntelWatching {
		t.Error("a listener with refresh: 0 started a refresh loop")
	}

	// And a list that blocks refuses the request, hands the ban list a
	// reason and says so in the status.
	blocking := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
bans:
  triggers:
    - {name: intel, reasons: [threat_intel], threshold: 1, window: 1m, duration: 1m}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
threat_intel:
  lists:
    - {name: denied, file: %s, action: block}
routes:
  - {name: app, upstream: app}
`, b.addr(), list)
	srv2, url2 := startServer(t, blocking)
	r, _ := http.NewRequest(http.MethodGet, url2+"/x", nil)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a blocking list answered %d, want 403", resp.StatusCode)
	}
	if srv2.Stats().ThreatIntelBlocked != 1 {
		t.Errorf("blocks counted: %d", srv2.Stats().ThreatIntelBlocked)
	}
	// The second listener takes the default refresh, so its files are
	// watched and the status says so.
	if !srv2.Stats().ThreatIntelWatching {
		t.Error("the default refresh did not start a loop")
	}
	// The block is a deny event with the threat_intel reason, so the
	// trigger above has something to escalate on.
	if active, _ := srv2.Bans().Stats(); active == 0 {
		t.Error("the block did not reach the ban list")
	}
}

// A list is an import, so an unreadable one fails the load rather than
// matching nothing.
func TestAListThatCannotBeReadFailsTheLoad(t *testing.T) {
	b := newBackend(t, "app")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
threat_intel:
  lists:
    - {name: missing, file: /nonexistent/threat-list.txt}
routes:
  - {name: app, upstream: app}
`, b.addr())
	// The loader refuses it, because a configured path that is not there
	// is a configuration error.
	if _, err := config.Parse([]byte(yaml)); err == nil {
		t.Error("the loader accepted a list file that is not there")
	}
	// And the server refuses it again, for a configuration assembled
	// without the file checks -- a translator, a test, a push from a
	// fleet controller. Reading the file is what proves it is a list.
	cfg, err := config.ParseWith([]byte(yaml), false)
	if err != nil {
		t.Fatalf("config without file checks: %v", err)
	}
	if _, err := proxy.New(cfg, logging.Discard()); err == nil {
		t.Error("a server with an unreadable list was built")
	}
}
