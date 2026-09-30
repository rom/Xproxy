package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/forward" // a second edge kind in the inventory
	_ "github.com/rom/xproxy/internal/kinds/http"    // the data plane the views report on
	_ "github.com/rom/xproxy/internal/kinds/modbus"  // a plant kind, so the OT views have a listener
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
)

// The page is six hundred lines of JavaScript that nothing has ever run.
// Every view reads a document the management API produced and indexes into
// it, so a renamed field, a list that is null rather than empty or a helper
// called with the wrong shape is a card that throws -- in one view, which
// is exactly where nobody looks until an operator needs it.
//
// So: start a real data plane and a real management server, ask it for
// every document the page fetches, and render every view against what came
// back. The fixtures are the API's own output rather than hand-written
// JSON, which is the point: a field renamed in Go fails here.
//
// What this does not do is check what the page *looks* like. It checks that
// every view runs to completion and puts something on the page, against
// real documents, which is the failure this repository could otherwise not
// see at all.

// apiPathsThePageReads is the /api paths app.js fetches, as literals.
var apiFetch = regexp.MustCompile(`'(/api/[a-z0-9/_-]+)`)

func TestEveryViewRendersAgainstTheRealManagementAPI(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the page's own rendering is not exercised")
	}
	dir := t.TempDir()
	yaml := `version: 1
server:
  listeners:
    - {name: web, address: "127.0.0.1:0"}
    - {name: watching, address: "127.0.0.1:0", policy: {mode: shadow}}
    - {name: egress, address: "127.0.0.1:0", kind: forward, forward: {allow: ["example.com"]}}
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        upstream: plc
        anomaly: {enabled: true, action: alert}
bans: {action: reject}
# The sections the OT and security views report on, so their tables render
# against real documents rather than the not-configured path.
access:
  ledger: ` + filepath.Join(dir, "access.log") + `
  approvals: 1
  max_duration: 4h
asset_inventory: {enabled: true}
virtual_patches:
  - id: cve-2024-1234
    description: a patch, so the table has a row
    paths: [/legacy/]
    status: 404
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:9"}]}
  - {name: plc, endpoints: [{address: "127.0.0.1:9"}]}
routes:
  - name: r
    paths: ["/"]
    upstream: u
    websocket: true
    websocket_guard: {max_frame_bytes: 65536}
    deceive: {status: 200, body: "nothing here", marked: true}
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	// Some state, so the row renderers are exercised rather than only the
	// empty-list paths: a refusal, a shadow decision and a ban.
	p.Counters().Refuse("http", "waf")
	p.Counters().WouldRefuse("modbus", "modbus_function")
	if bl := p.Bans(); bl != nil {
		if _, err := bl.Ban("203.0.113.9", time.Hour, "a test"); err != nil {
			t.Fatal(err)
		}
	}

	sock := filepath.Join(dir, "m.sock")
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })

	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: sock, UsersFile: writeUsers(t, dir), ConfigFile: cfgPath})
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatalf("login: %d", st)
	}

	// Every path the page reads, answered by the real API through the real
	// pass-through. A path the page completes with a value (/api/logs/ plus
	// the stream) is left out: the fixture keys are literals.
	js := staticFile(t, "app.js")
	paths := map[string]bool{}
	for _, mm := range apiFetch.FindAllStringSubmatch(js, -1) {
		if !strings.HasSuffix(mm[1], "/") {
			paths[mm[1]] = true
		}
	}
	ordered := make([]string, 0, len(paths))
	for p := range paths {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)

	fixtures := map[string]json.RawMessage{}
	answered := 0
	for _, path := range ordered {
		st, body := c.do(http.MethodGet, path, nil, true)
		if st != 200 {
			continue // the view's "not configured" path, which is also worth rendering
		}
		if !json.Valid(body) {
			// /api/active-config is YAML and /api/metrics is text; both are
			// read as text by the page, so they are quoted into the fixture.
			body, _ = json.Marshal(string(body))
		}
		fixtures[path] = body
		answered++
	}
	if answered < 20 {
		t.Fatalf("only %d of %d paths answered; the pass-through is not wired", answered, len(ordered))
	}
	// The views worth exercising are the ones with data behind them, and a
	// fixture that quietly went missing would leave a view rendering its
	// not-configured path and the test still passing. So the documents the
	// configuration above provides are required to be here.
	for _, must := range []string{"/api/status", "/api/stats", "/api/listeners", "/api/policy",
		"/api/access", "/api/assets", "/api/patches", "/api/deceive", "/api/websocket",
		"/api/sessions", "/api/bans", "/api/upstreams", "/api/quotas"} {
		if _, ok := fixtures[must]; !ok {
			t.Errorf("%s did not answer, so the view that reads it was rendered empty", must)
		}
	}
	fixturePath := filepath.Join(dir, "fixtures.json")
	b, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, b, 0o600); err != nil {
		t.Fatal(err)
	}

	appPath := filepath.Join(dir, "app.js")
	if err := os.WriteFile(appPath, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), node, "testdata/render.js", appPath, fixturePath)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("rendering the page failed: %v", err)
	}
}
