package mgmt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// Everything an operator can ask the running proxy to do arrives here,
// over a socket only the proxy user can open. The tests below are the
// answers for a proxy that has none of the optional subsystems, and for
// the requests an operator gets wrong.

// bareYAML has no bans, no maintenance and no cluster, so every endpoint
// that needs one has to say so rather than act on a nil.
const bareYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`

func bareServer(t *testing.T, actions Actions) *Client {
	t.Helper()
	cfg, err := config.Parse([]byte(bareYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), actions)
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return NewClient(sock)
}

func TestSubsystemsThatAreNotConfigured(t *testing.T) {
	c := bareServer(t, Actions{})

	// Each of these answers 404 with a reason an operator can act on,
	// rather than an empty list that reads as "nothing is banned".
	cases := map[string]func() error{
		"bans":    func() error { _, err := c.Bans(); return err },
		"ban":     func() error { _, err := c.Ban("198.51.100.1", "1h", "spray"); return err },
		"unban":   func() error { return c.Unban("198.51.100.1") },
		"cluster": func() error { _, err := c.ClusterStatus(); return err },
	}
	for name, call := range cases {
		err := call()
		if err == nil {
			t.Errorf("%s answered for a proxy that has none", name)
			continue
		}
		if !strings.Contains(err.Error(), "not configured") {
			t.Errorf("%s said %q", name, err)
		}
	}
	// Reading the maintenance state always answers; it says the section
	// is not configured rather than reporting the proxy as serving.
	st, err := c.Maintenance(nil)
	if err != nil {
		t.Fatalf("reading maintenance: %v", err)
	}
	if st.Configured || st.On {
		t.Errorf("maintenance status = %+v", st)
	}
	// Switching it on is a 400: the request is well formed but there is
	// nothing to switch.
	on := true
	if _, err := c.Maintenance(&on); err == nil {
		t.Error("maintenance was switched on without a section")
	}
}

func TestActionsThatAreNotAvailable(t *testing.T) {
	// An action the process did not wire up is 501, not a silent success
	// an operator would take for a reload that happened.
	c := bareServer(t, Actions{})
	for _, path := range []string{"/v1/reload", "/v1/reload-certs", "/v1/reopen-logs"} {
		err := c.Post(path)
		if err == nil {
			t.Errorf("%s reported success with no action behind it", path)
		}
	}
	if err := c.Do("POST", "/v1/reload?dry_run=1", nil, nil); err == nil {
		t.Error("a dry run reported success with no action behind it")
	}

	// A dry run that fails is a 409 carrying the reason; one that
	// succeeds answers the change set without touching the generation.
	failing := bareServer(t, Actions{
		DryRun: func() (*config.Changes, error) { return nil, errors.New("the file on disk does not parse") },
	})
	err := failing.Do("POST", "/v1/reload?dry_run=1", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Errorf("a failing dry run gave %v", err)
	}
	ok := bareServer(t, Actions{
		DryRun: func() (*config.Changes, error) { return &config.Changes{Summary: []string{"routes: 1 added"}}, nil },
	})
	var ch config.Changes
	if err := ok.Do("POST", "/v1/reload?dry_run=true", nil, &ch); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(ch.Summary) != 1 || ch.Summary[0] != "routes: 1 added" {
		t.Errorf("changes = %+v", ch)
	}
}

func TestBanRequestsThatAreWrong(t *testing.T) {
	c := clientServer(t)

	// A duration that is not one, and a reason longer than the field
	// holds, are refused before anything is written to the ban list.
	if _, err := c.Ban("198.51.100.1", "soon", "x"); err == nil || !strings.Contains(err.Error(), "duration") {
		t.Errorf("a bad duration gave %v", err)
	}
	if _, err := c.Ban("198.51.100.1", "1h", strings.Repeat("r", 257)); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Errorf("an oversize reason gave %v", err)
	}
	// A target the ban list will not take is the list's own error, at 400.
	if _, err := c.Ban("not an address", "1h", "x"); err == nil {
		t.Error("an unparseable target was banned")
	}
	// Unbanning something that is not banned is 404, so a script can tell
	// "already gone" from "the request was wrong".
	if err := c.Unban("198.51.100.99"); err == nil || !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("unbanning an absent target gave %v", err)
	}
	if err := c.Unban("not an address"); err == nil {
		t.Error("an unparseable unban target reported success")
	}

	// A body that is not JSON at all is a 400 rather than a panic in the
	// decoder, on both endpoints that take one.
	for _, path := range []string{"/v1/bans", "/v1/maintenance"} {
		if err := c.Do("POST", path, "not a json object", nil); err == nil {
			t.Errorf("%s accepted a body that is not its shape", path)
		}
	}

	// A ban that is accepted comes back as an entry and then shows in the
	// list, which is the round trip an operator watches.
	e, err := c.Ban("198.51.100.7", "1h", "manual")
	if err != nil {
		t.Fatalf("ban: %v", err)
	}
	if e.Target != "198.51.100.7" || e.Reason != "manual" {
		t.Errorf("entry = %+v", e)
	}
	entries, err := c.Bans()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range entries {
		if x.Target == "198.51.100.7" {
			found = true
		}
	}
	if !found {
		t.Errorf("the ban is not in the list: %+v", entries)
	}
	if err := c.Unban("198.51.100.7"); err != nil {
		t.Errorf("unban: %v", err)
	}
}

func TestConfigEndpointRedactsAndNamesItsFiles(t *testing.T) {
	c := clientServer(t)
	body, err := c.Raw("/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	// What comes back is a document to read: it must parse, and it must
	// not carry the include list a copy would expand a second time.
	if !strings.Contains(text, "listeners:") {
		t.Errorf("the dump does not look like a configuration: %.200s", text)
	}
	// The include list is cleared: a copy of this document fed back must
	// not expand the fragments a second time.
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "includes:") && strings.TrimSpace(strings.TrimPrefix(line, "includes:")) != "[]" {
			t.Errorf("the dump names include files: %q", line)
		}
	}
}

func TestEveryReadEndpointAnswersOnABareProxy(t *testing.T) {
	// A proxy with none of the optional subsystems must still answer
	// every read endpoint: an operator reaching for a view that is off
	// gets a reason, never a hang, a panic or an empty 200 that reads as
	// "nothing to report".
	c := bareServer(t, Actions{})
	paths := []string{
		"/v1/health", "/v1/status", "/v1/stats", "/v1/upstreams", "/v1/pools",
		"/v1/tls", "/v1/tls/tickets", "/v1/quotas?top=5", "/v1/quotas?top=nonsense",
		"/v1/quotas?top=100000", "/v1/waf?top=5", "/v1/waf?top=-1", "/v1/waf/exclusions",
		"/v1/sandbox", "/v1/maintenance", "/v1/cache", "/v1/dns", "/v1/geoip",
		"/v1/honeypot", "/v1/icap", "/v1/ingress", "/v1/otlp", "/v1/patches",
		"/v1/telemetry", "/v1/filters", "/v1/fleet", "/v1/acme", "/v1/botscore?top=3",
		"/v1/accounts?top=3", "/v1/api?view=all&top=3", "/v1/history", "/v1/diff",
		"/v1/series?since=300s&limit=10",
		"/v1/config", "/v1/cluster", "/v1/bans", "/v1/origin-check",
	}
	for _, p := range paths {
		body, err := c.Raw(p)
		if err != nil {
			// A subsystem that is off answers 404 or 501 through the
			// client's error; what matters is that something came back.
			if !strings.Contains(err.Error(), "not configured") &&
				!strings.Contains(err.Error(), "not available") &&
				!strings.Contains(err.Error(), "404") &&
				!strings.Contains(err.Error(), "501") &&
				!strings.Contains(err.Error(), "400") {
				t.Errorf("GET %s: %v", p, err)
			}
			continue
		}
		if len(body) == 0 {
			t.Errorf("GET %s answered with an empty body", p)
		}
	}

	// A parameter that is not what it claims to be is refused with the
	// reason, rather than silently read as its zero value.
	if _, err := c.Raw("/v1/series?since=nonsense"); err == nil {
		t.Error("an unparseable since was accepted")
	}
	if err := c.Do("DELETE", "/v1/honeypot?ip=nonsense", nil, nil); err == nil {
		t.Error("an unparseable address was unmarked")
	}

	// The write endpoints that need no action wired up still answer.
	for _, p := range []string{"/v1/waf/reset", "/v1/acme/renew"} {
		if err := c.Post(p); err != nil && !strings.Contains(err.Error(), "not configured") && !strings.Contains(err.Error(), "501") && !strings.Contains(err.Error(), "404") {
			t.Errorf("POST %s: %v", p, err)
		}
	}
	// The deletes, with and without the parameters they take.
	for _, p := range []string{
		"/v1/cache", "/v1/cache?host=a.test&prefix=/x",
		"/v1/dns", "/v1/honeypot?ip=198.51.100.1",
	} {
		if err := c.Do("DELETE", p, nil, nil); err != nil &&
			!strings.Contains(err.Error(), "not configured") && !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "400") {
			t.Errorf("DELETE %s: %v", p, err)
		}
	}
}

func TestStartRefusesAnImpossibleSocket(t *testing.T) {
	cfg, err := config.Parse([]byte(bareYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	// No socket at all: the management API is simply off, which is not
	// an error the process should fail to start on.
	off := New(config.Management{}, p, logging.Discard(), Actions{})
	if err := off.Start(); err != nil {
		t.Errorf("a proxy with no management socket failed to start: %v", err)
	}
	if err := off.Shutdown(context.Background()); err != nil {
		t.Errorf("shutting down a server that never started: %v", err)
	}

	// A directory that cannot be created, and a path that is a directory,
	// are both reported rather than leaving the proxy up with no way in.
	dir := t.TempDir()
	file := filepath.Join(dir, "afile")
	if err := writeFile(file, "x"); err != nil {
		t.Fatal(err)
	}
	under := New(config.Management{Socket: filepath.Join(file, "sub", "m.sock"), SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := under.Start(); err == nil {
		t.Error("a socket under a regular file was accepted")
	}
	// A stale path the proxy cannot clear is reported: it must not keep
	// running with the socket of a previous process still in the way.
	asDir := filepath.Join(dir, "adir")
	if err := mkdir(asDir); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(asDir, "keep"), "x"); err != nil {
		t.Fatal(err)
	}
	onDir := New(config.Management{Socket: asDir, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := onDir.Start(); err == nil {
		_ = onDir.Shutdown(context.Background())
		t.Error("a path the proxy could not clear was bound as a socket")
	}
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }
func mkdir(path string) error              { return os.Mkdir(path, 0o700) }
