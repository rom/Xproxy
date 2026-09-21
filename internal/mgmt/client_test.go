package mgmt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
)

// The client is the only way anything reaches the management API, and
// every operator command and the web GUI go through one of its methods.
// These tests call each of them against a real server on a real socket,
// so that a path typo or a shape mismatch between the two sides cannot
// hide behind a type that happens to decode from anything.

// The configuration turns on the optional subsystems whose endpoints
// would otherwise answer "not configured" before the handler runs.
const clientYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
bans: {action: reject}
api_inventory: {zombie_after: 720h}
maintenance: {enabled: false, status: 503, message: "back soon"}
cache: {max_bytes: 1048576}
virtual_patches:
  - id: cve-2026-1
    description: a patch
    methods: [POST]
    paths: [/admin]
    action: block
filters:
  - name: score
    kind: bot_score
    options: {}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u, filters: [score]}
`

// clientServer starts a management server on a socket and returns a
// client for it.
func clientServer(t *testing.T) *Client {
	t.Helper()
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{
		Reload:      func() error { return nil },
		ReloadCerts: func() error { return nil },
		ReopenLogs:  func() error { return nil },
		Sandbox:     func() *sandbox.Status { return &sandbox.Status{Platform: "linux"} },
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return NewClient(sock)
}

// TestClientMethods calls every typed method once. The assertion is
// deliberately weak — these are transport wrappers, and what is being
// tested is that each one names a path the server serves and decodes
// what it answers.
func TestClientMethods(t *testing.T) {
	c := clientServer(t)

	if _, err := c.Status(); err != nil {
		t.Errorf("Status: %v", err)
	}
	if _, err := c.Patches(); err != nil {
		t.Errorf("Patches: %v", err)
	}
	if _, err := c.Upstreams(); err != nil {
		t.Errorf("Upstreams: %v", err)
	}
	if _, err := c.Filters(); err != nil {
		t.Errorf("Filters: %v", err)
	}
	if _, err := c.BotScore(10); err != nil {
		t.Errorf("BotScore: %v", err)
	}
	if _, err := c.Metrics(); err != nil {
		t.Errorf("Metrics: %v", err)
	}
	for _, view := range []string{"", "all", "shadow", "zombie", "versions", "documented", "undocumented"} {
		if _, err := c.APIInventory(view, 20); err != nil {
			t.Errorf("APIInventory(%q): %v", view, err)
		}
	}
	skeleton, err := c.APISkeleton("undocumented", 20, "Discovered")
	if err != nil {
		t.Errorf("APISkeleton: %v", err)
	} else if !strings.Contains(string(skeleton), "openapi:") {
		t.Errorf("the skeleton is not an OpenAPI document: %.80s", skeleton)
	}
	if _, err := c.CachePurge("example.com", "/assets"); err != nil {
		t.Errorf("CachePurge: %v", err)
	}
	if _, err := c.OriginCheck("", "", ""); err != nil {
		t.Errorf("OriginCheck: %v", err)
	}
	if b, err := c.Raw("/v1/status"); err != nil || len(b) == 0 {
		t.Errorf("Raw: %v %d bytes", err, len(b))
	}

	// The subsystems this configuration leaves off must answer with an
	// error the caller can print, not with an empty view that reads as
	// "nothing is wrong".
	for name, call := range map[string]func() error{
		"ClusterStatus": func() error { _, err := c.ClusterStatus(); return err },

		"ACME": func() error { _, err := c.ACME(); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s answered without the subsystem configured", name)
		}
	}
	// These answer an empty view rather than an error: the subsystem
	// exists in every build and simply has nothing to report.
	if _, err := c.ICAP(); err != nil {
		t.Errorf("ICAP: %v", err)
	}
	if _, err := c.FleetStatus(); err != nil {
		t.Errorf("FleetStatus: %v", err)
	}
	if _, err := c.Accounts(10); err != nil {
		t.Errorf("Accounts: %v", err)
	}
}

// TestMaintenanceRoundTrip covers the one method that both reads and
// writes: the runtime override an operator flips during a deployment.
func TestMaintenanceRoundTrip(t *testing.T) {
	c := clientServer(t)
	st, err := c.Maintenance(nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.On {
		t.Fatal("maintenance is active before anyone asked for it")
	}
	on := true
	if st, err = c.Maintenance(&on); err != nil {
		t.Fatal(err)
	}
	if !st.On {
		t.Fatalf("maintenance did not come on: %+v", st)
	}
	// And it is really on, not just reported so by the response.
	if st, err = c.Maintenance(nil); err != nil || !st.On {
		t.Fatalf("a second read says %+v (%v)", st, err)
	}
	off := false
	if st, err = c.Maintenance(&off); err != nil || st.On {
		t.Fatalf("maintenance did not go off: %+v (%v)", st, err)
	}
}

// TestClientErrors covers the failure paths of the transport itself:
// no server, a server that answers an error, and an endpoint that does
// not exist. Each must produce a message an operator can act on.
func TestClientErrors(t *testing.T) {
	absent := NewClient(filepath.Join(t.TempDir(), "none.sock"))
	err := absent.Post("/v1/reload")
	if err == nil {
		t.Fatal("a call to a socket that is not there succeeded")
	}
	if !strings.Contains(err.Error(), "management API") {
		t.Fatalf("the error does not say what failed: %v", err)
	}
	if _, err := absent.Status(); err == nil {
		t.Fatal("Status against no server succeeded")
	}

	c := clientServer(t)
	if err := c.Do("GET", "/v1/no-such-endpoint", nil, nil); err == nil {
		t.Fatal("an unknown endpoint answered")
	}
	// A method the endpoint does not take.
	if err := c.Do("PUT", "/v1/status", nil, nil); err == nil {
		t.Fatal("PUT on a read-only endpoint answered")
	}
	// A body that is not valid for the endpoint.
	if err := c.Do("POST", "/v1/maintenance", map[string]any{"on": "yes please"}, nil); err == nil {
		t.Fatal("a string where a boolean belongs was accepted")
	}
}

// TestActionErrorsReachTheCaller requires an action that fails on the
// server to reach the client as its own message, not as a bare status
// code: "reload failed: line 7" is the whole diagnosis.
func TestActionErrorsReachTheCaller(t *testing.T) {
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{
		Reload:      func() error { return errors.New("xproxy.yaml:7: unknown field frobnicate") },
		ReloadCerts: func() error { return errors.New("cert.pem: no such file") },
		ReopenLogs:  func() error { return errors.New("log directory is read-only") },
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Shutdown(context.Background()) }()
	c := NewClient(sock)
	for path, want := range map[string]string{
		"/v1/reload":       "frobnicate",
		"/v1/reload-certs": "no such file",
		"/v1/logs/reopen":  "read-only",
	} {
		err := c.Post(path)
		if err == nil {
			t.Errorf("%s reported success though the action failed", path)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: the message lost the reason: %v", path, err)
		}
	}
}

// TestUnconfiguredActionsAreRefused covers a server built without the
// action callbacks at all, which is how the proxy runs when a feature
// is compiled out or not wired: the endpoint must refuse rather than
// answer success for something nobody did.
func TestUnconfiguredActionsAreRefused(t *testing.T) {
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Shutdown(context.Background()) }()
	c := NewClient(sock)
	for _, path := range []string{"/v1/reload", "/v1/reload-certs", "/v1/logs/reopen"} {
		if err := c.Post(path); err == nil {
			t.Errorf("%s answered success with no action behind it", path)
		}
	}
}

// TestSocketIsNotWorldAccessible pins the permissions of the socket
// itself. Anything that can connect to it can ban an address, purge
// the cache and read the running configuration.
func TestSocketIsNotWorldAccessible(t *testing.T) {
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, mode := range []string{"0600", "0660"} {
		sock := filepath.Join(dir, "m"+mode+".sock")
		m := New(config.Management{Socket: sock, SocketMode: mode}, p, logging.Discard(), Actions{})
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(sock)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o007 != 0 {
			t.Fatalf("the socket is mode %v: anything on this host can control the proxy", st.Mode().Perm())
		}
		_ = m.Shutdown(context.Background())
	}
}

// TestShutdownIsIdempotent covers stopping a server twice and stopping
// one that never started, which is what a failed start does on the way
// out.
func TestShutdownIsIdempotent(t *testing.T) {
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
	// The socket is gone, so the next start can bind.
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("the socket was left behind")
	}
	never := New(config.Management{Socket: filepath.Join(t.TempDir(), "x.sock")}, p, logging.Discard(), Actions{})
	if err := never.Shutdown(ctx); err != nil {
		t.Fatalf("shutting down a server that never started: %v", err)
	}
}

// TestStatsAndConfigEndpoints covers the two endpoints an operator
// reaches for first, and the redaction the configuration dump does.
// The dump travels further than the file on disk — into a ticket, a
// chat, a bug report — so the credential a route sends to its origin
// must not be in it.
func TestStatsAndConfigEndpoints(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
    request_headers:
      set: {X-Origin-Token: "s3cret-origin-token"}
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Shutdown(context.Background()) }()
	if got := m.Addr(); got != sock {
		t.Fatalf("Addr is %q, want the socket path", got)
	}
	c := NewClient(sock)

	var stats map[string]any
	if err := c.Do("GET", "/v1/stats", nil, &stats); err != nil {
		t.Fatal(err)
	}
	if _, ok := stats["requests"]; !ok {
		t.Fatalf("the statistics carry no request count: %v", stats)
	}

	dump, err := c.Raw("/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dump), "version: 1") {
		t.Fatalf("the dump is not a configuration:\n%.200s", dump)
	}
	if strings.Contains(string(dump), "s3cret-origin-token") {
		t.Fatal("the configuration dump carries the origin credential in the clear")
	}
	if !strings.Contains(string(dump), "X-Origin-Token") {
		t.Fatal("redaction removed the header name as well as its value")
	}
}

// TestAuditRecordsTheCaller requires every management action to reach
// the audit log with the identity of whoever asked. A control plane
// without that is a control plane nobody can review after an incident.
func TestAuditRecordsTheCaller(t *testing.T) {
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	var buf syncBuffer
	logs := logging.Discard()
	logs.Audit = slog.New(slog.NewJSONHandler(&buf, nil))
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logs, Actions{
		Reload: func() error { return nil },
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Shutdown(context.Background()) }()
	c := NewClient(sock)
	if err := c.Post("/v1/reload"); err != nil {
		t.Fatal(err)
	}
	if err := c.Do("POST", "/v1/bans", map[string]any{"target": "203.0.113.9", "duration": "10m", "reason": "test"}, nil); err != nil {
		t.Fatal(err)
	}
	// The two handlers whose response carries data audit separately,
	// after the work rather than around it.
	if err := c.Do("DELETE", "/v1/honeypot?ip=203.0.113.9", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Do("DELETE", "/v1/dns", nil, nil); err != nil {
		t.Logf("dns purge without a dns listener: %v", err)
	}
	line := buf.String()
	if !strings.Contains(line, `"action":"honeypot_unmark"`) {
		t.Fatalf("the honeypot unmark was not audited:\n%s", line)
	}
	if !strings.Contains(line, `"action":"reload"`) {
		t.Fatalf("the reload was not audited:\n%s", line)
	}
	for _, field := range []string{"peer_uid", "peer_gid", "peer_pid", "peer_known"} {
		if !strings.Contains(line, field) {
			t.Fatalf("the audit entry has no %s:\n%s", field, line)
		}
	}
	// The peer credentials are the calling process's own, since the
	// test is on the other end of the socket.
	if !strings.Contains(line, fmt.Sprintf(`"peer_uid":%d`, os.Getuid())) {
		t.Fatalf("the audit entry names another uid:\n%s", line)
	}
}

// syncBuffer is a bytes.Buffer safe for the logger's goroutine and the
// test's.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestStartRefusesToStealASocket covers the check that stops a second
// process from taking over a live control plane. A stale socket file
// from a crash is removed and reused; one with a server behind it is
// not, because binding over it would silently take every operator's
// next command.
func TestStartRefusesToStealASocket(t *testing.T) {
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "m.sock")
	first := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Shutdown(context.Background()) }()

	second := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	err = second.Start()
	if err == nil {
		_ = second.Shutdown(context.Background())
		t.Fatal("a second server bound over a live socket")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("the error does not say what happened: %v", err)
	}
	// The first server is still the one answering.
	if _, err := NewClient(sock).Status(); err != nil {
		t.Fatalf("the live server stopped answering: %v", err)
	}

	// A stale file with nothing behind it is cleaned up and reused,
	// which is what a crash leaves.
	stale := filepath.Join(dir, "stale.sock")
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	third := New(config.Management{Socket: stale, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := third.Start(); err != nil {
		t.Fatalf("a stale socket file was not reused: %v", err)
	}
	_ = third.Shutdown(context.Background())

	// No socket configured is not an error: the control plane is off.
	off := New(config.Management{}, p, logging.Discard(), Actions{})
	if err := off.Start(); err != nil {
		t.Fatalf("an empty socket path: %v", err)
	}
	if off.Addr() != "" {
		t.Fatalf("a disabled server reports the address %q", off.Addr())
	}
}

// TestSeriesQuery covers the sampled series endpoint, whose arguments
// come straight off a command line.
func TestSeriesQuery(t *testing.T) {
	c := clientServer(t)
	for _, q := range []string{"", "?since=5m", "?since=1h&limit=10", "?limit=0",
		"?since=" + time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)} {
		var resp SeriesResponse
		if err := c.Do("GET", "/v1/series"+q, nil, &resp); err != nil {
			t.Errorf("/v1/series%s: %v", q, err)
		}
	}
	for _, q := range []string{"?since=yesterday", "?since=5", "?limit=-1", "?limit=100001", "?limit=lots"} {
		if err := c.Do("GET", "/v1/series"+q, nil, nil); err == nil {
			t.Errorf("/v1/series%s was accepted", q)
		}
	}
}

// TestMetricsAccessList covers the scrape listener's source filter and
// the aggregation behind it: the listener has no rate limit and no ban
// ladder, so one log record per refusal would let anybody who can route
// to the port drive the log volume.
func TestMetricsAccessList(t *testing.T) {
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	var buf syncBuffer
	logs := logging.Discard()
	logs.Error = slog.New(slog.NewJSONHandler(&buf, nil))
	ml, err := NewMetricsListener(config.Metrics{Listen: "127.0.0.1:0", AllowCIDRs: []string{"10.0.0.0/8"}}, p, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ml.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ml.Shutdown(context.Background()) }()

	url := "http://" + ml.Addr() + "/metrics"
	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 20; i++ {
		resp, err := client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a request from outside the allow list got %d", resp.StatusCode)
		}
	}
	// Twenty refusals, far fewer than twenty records.
	if n := strings.Count(buf.String(), "refused by the metrics access list"); n > 5 {
		t.Fatalf("20 refusals produced %d log records; they are meant to aggregate", n)
	}
	// An endpoint this listener does not serve is not there at all.
	resp, err := client.Get("http://" + ml.Addr() + "/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the scrape listener served /v1/status with %d", resp.StatusCode)
	}
}

// TestMetricsListenerWithoutAccessList covers the open form, which is
// what a listener on a private interface uses.
func TestMetricsListenerWithoutAccessList(t *testing.T) {
	cfg, err := config.Parse([]byte(clientYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	ml, err := NewMetricsListener(config.Metrics{Listen: "127.0.0.1:0"}, p, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := ml.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ml.Shutdown(context.Background()) }()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + ml.Addr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "xproxy_") {
		t.Fatalf("the exposition carries no xproxy metrics:\n%.200s", body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("content type %q", got)
	}
	// Shutting down twice, and shutting down one that never started.
	if err := ml.Shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
	never, err := NewMetricsListener(config.Metrics{}, p, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := never.Start(); err != nil {
		t.Fatalf("a listener with no address: %v", err)
	}
	if err := never.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutting it down: %v", err)
	}
}
