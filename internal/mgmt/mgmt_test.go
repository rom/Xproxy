package mgmt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/http" // the data plane the management views report on
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/testutil"
)

func TestBanAPI(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
bans: {action: reject}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
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
	defer m.Shutdown(context.Background())
	c := NewClient(sock)
	es, err := c.Bans()
	if err != nil || len(es) != 0 {
		t.Fatalf("empty list: %v %v", es, err)
	}
	e, err := c.Ban("203.0.113.7", "1h", "scanner")
	if err != nil || e.Target != "203.0.113.7" || e.Source != "manual" {
		t.Fatalf("ban: %+v %v", e, err)
	}
	if _, err := c.Ban("127.0.0.1", "1h", "x"); err == nil {
		t.Fatal("loopback ban accepted")
	}
	if _, err := c.Ban("203.0.113.8", "soon", "x"); err == nil {
		t.Fatal("bad duration accepted")
	}
	es, _ = c.Bans()
	if len(es) != 1 {
		t.Fatalf("list: %+v", es)
	}
	if err := c.Unban("203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if err := c.Unban("203.0.113.7"); err == nil {
		t.Fatal("second unban should fail")
	}
	st, _ := c.Status()
	if st.Stats.BansTotal != 1 || st.Stats.BansActive != 0 {
		t.Fatalf("stats: %+v", st.Stats)
	}
}

func TestManagementAPI(t *testing.T) {
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
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	reloads := 0
	rolled := ""
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{
		Reload:      func() error { reloads++; return nil },
		ReloadCerts: func() error { return errors.New("boom") },
		DryRun: func() (*config.Changes, error) {
			return &config.Changes{From: "active", To: "file", Summary: []string{"routes: 1 added"}, Changes: []config.Change{{Section: "routes", Name: "n", Kind: "added"}}}, nil
		},
		History:  func() ([]config.Entry, error) { return []config.Entry{{ID: "x-gen1", Generation: 1}}, nil },
		Rollback: func(id string) error { rolled = id; return nil },
		Diff: func(from, to string) (*config.Changes, error) {
			if to == "missing" {
				return nil, errors.New("no such entry")
			}
			return &config.Changes{From: from, To: to, Same: true}, nil
		},
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", err, st)
	}
	c := NewClient(sock)
	s, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.Routes != 1 || s.Upstreams != 1 || s.PID != os.Getpid() {
		t.Fatalf("%+v", s)
	}
	if err := c.Post("/v1/reload"); err != nil || reloads != 1 {
		t.Fatalf("reload: %v %d", err, reloads)
	}
	var ch config.Changes
	if err := c.Do("POST", "/v1/reload?dry_run=1", nil, &ch); err != nil || reloads != 1 || len(ch.Changes) != 1 || ch.Changes[0].Name != "n" {
		t.Fatalf("dry run: %v %d %+v", err, reloads, ch)
	}
	var entries []config.Entry
	if err := c.Do("GET", "/v1/history", nil, &entries); err != nil || len(entries) != 1 || entries[0].ID != "x-gen1" {
		t.Fatalf("history: %v %+v", err, entries)
	}
	if err := c.Post("/v1/rollback?id=x-gen1"); err != nil || rolled != "x-gen1" {
		t.Fatalf("rollback: %v %q", err, rolled)
	}
	if err := c.Do("GET", "/v1/diff?from=active&to=x-gen1", nil, &ch); err != nil || !ch.Same || ch.To != "x-gen1" {
		t.Fatalf("diff: %v %+v", err, ch)
	}
	if err := c.Do("GET", "/v1/diff", nil, &ch); err != nil || ch.From != "active" || ch.To != "file" {
		t.Fatalf("diff defaults: %v %+v", err, ch)
	}
	if err := c.Do("GET", "/v1/diff?to=missing", nil, &ch); err == nil {
		t.Fatal("diff error not propagated")
	}
	if err := c.Post("/v1/reload-certs"); err == nil || err.Error() != "boom" {
		t.Fatalf("error propagation: %v", err)
	}
	if err := c.Post("/v1/logs/reopen"); err == nil {
		t.Fatal("nil action should be 501")
	}
	b, err := c.Raw("/v1/upstreams")
	if err != nil {
		t.Fatal(err)
	}
	var ups map[string][]any
	if json.Unmarshal(b, &ups) != nil || len(ups["u"]) != 1 {
		t.Fatalf("upstreams: %s", b)
	}
	b, _ = c.Raw("/v1/config")
	if len(b) == 0 {
		t.Fatal("config empty")
	}
	b, err = c.Raw("/v1/quotas?top=3")
	if err != nil || !strings.Contains(string(b), `"routes"`) || !strings.Contains(string(b), `"rate_limits"`) {
		t.Fatalf("quotas: %v %s", err, b)
	}
	if b, err = c.Raw("/v1/pools"); err != nil || !strings.Contains(string(b), `"u"`) {
		t.Fatalf("pools: %v %s", err, b)
	}
	if b, err = c.Raw("/v1/telemetry"); err != nil || !strings.Contains(string(b), `"traces": null`) || !strings.Contains(string(b), `"logs": null`) {
		t.Fatalf("telemetry: %v %s", err, b)
	}
	if b, err = c.Raw("/v1/tls"); err != nil || strings.TrimSpace(string(b)) != "{}" {
		t.Fatalf("tls: %v %s", err, b)
	}
	if _, err = c.Raw("/v1/tls/tickets"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("tls tickets without the section: %v", err)
	}
	if b, err = c.Raw("/v1/waf?top=5"); err != nil || !strings.Contains(string(b), `"enabled": false`) || !strings.Contains(string(b), `"rules": []`) {
		t.Fatalf("waf: %v %s", err, b)
	}
	if b, err = c.Raw("/v1/waf/exclusions"); err != nil || !strings.Contains(string(b), "(no proposals)") {
		t.Fatalf("waf exclusions: %v %s", err, b)
	}
	if err := c.Post("/v1/waf/reset"); err != nil {
		t.Fatalf("waf reset: %v", err)
	}
	if b, err = c.Raw("/v1/honeypot"); err != nil || !strings.Contains(string(b), `"marks_dropped": 0`) {
		t.Fatalf("honeypot: %v %s", err, b)
	}
	if _, err := c.Raw("/v1/sandbox"); err == nil {
		t.Fatal("sandbox status without the action should be 404")
	}
	if st, err := c.Status(); err != nil || st.Sandbox != nil {
		t.Fatalf("status sandbox: %+v %v", st, err)
	}
	// Cluster is not configured in this server.
	if _, err := c.ClusterStatus(); err == nil {
		t.Fatal("cluster status should be unavailable")
	}
	// Bans are not configured in this server.
	if _, err := c.Bans(); err == nil {
		t.Fatal("bans should be unavailable")
	}
	// Second start on the same socket is refused.
	m2 := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m2.Start(); err == nil {
		t.Fatal("in-use socket accepted")
	}
}

func TestMetricsEndpoints(t *testing.T) {
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
	defer m.Shutdown(context.Background())
	c := NewClient(sock)
	b, err := c.Metrics()
	if err != nil || !strings.Contains(string(b), "xproxy_requests_total 0") {
		t.Fatalf("metrics: %v %s", err, b)
	}
	sr, err := c.Series(time.Hour, 10)
	if err != nil || sr.IntervalSeconds != 10 || len(sr.Names) == 0 {
		t.Fatalf("series: %v %+v", err, sr)
	}
	if _, err := c.Raw("/v1/series?since=bogus"); err == nil {
		t.Fatal("bad since accepted")
	}
}

func TestMetricsListener(t *testing.T) {
	cfg, _ := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
`))
	p, _ := proxy.New(cfg, logging.Discard())
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	srvCert, srvKey := ca.Issue(t, dir, "metrics.test")
	cliCert, cliKey := ca.Issue(t, dir, "prometheus")

	// Plain listener with an allow list that excludes the caller.
	ml, err := NewMetricsListener(config.Metrics{Listen: "127.0.0.1:0", AllowCIDRs: []string{"10.0.0.0/8"}}, p, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := ml.Start(); err != nil {
		t.Fatal(err)
	}
	defer ml.Shutdown(context.Background())
	resp, err := http.Get("http://" + ml.Addr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("acl: %d", resp.StatusCode)
	}

	// TLS with client certificates: no certificate is refused, a valid one
	// is served; other paths are 404.
	ml2, err := NewMetricsListener(config.Metrics{Listen: "127.0.0.1:0", TLS: &config.MetricsTLS{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: ca.Path}}, p, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := ml2.Start(); err != nil {
		t.Fatal(err)
	}
	defer ml2.Shutdown(context.Background())
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "metrics.test", MinVersion: tls.VersionTLS12}}}
	if resp, err := noCert.Get("https://" + ml2.Addr() + "/metrics"); err == nil {
		resp.Body.Close()
		t.Fatal("served without client certificate")
	}
	pair, _ := tls.LoadX509KeyPair(cliCert, cliKey)
	withCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "metrics.test", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}}
	resp, err = withCert.Get("https://" + ml2.Addr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "xproxy_build_info") {
		t.Fatalf("mtls metrics: %d", resp.StatusCode)
	}
	resp, _ = withCert.Get("https://" + ml2.Addr() + "/v1/status")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("management API exposed on metrics listener: %d", resp.StatusCode)
	}
	// Disabled listener is a no-op.
	ml3, _ := NewMetricsListener(config.Metrics{}, p, logging.Discard())
	if err := ml3.Start(); err != nil || ml3.Addr() != "" {
		t.Fatal("disabled listener")
	}
}

// Without sandbox.strict a hardening mechanism that never took effect
// was a line in the start-up log and nothing else, and nothing watches
// a start-up log. The process is still serving, so health stays ok, but
// it says what is missing.
func TestHealthReportsDegradedHardening(t *testing.T) {
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
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	status := &sandbox.Status{Enabled: true, Mechanism: []sandbox.Mechanism{
		{Name: "seccomp", State: sandbox.StateApplied},
		{Name: "landlock", State: sandbox.StateUnavailable, Detail: "kernel too old"},
	}}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{
		Sandbox: func() *sandbox.Status { return status },
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	get := func() healthResult {
		t.Helper()
		var res healthResult
		if err := NewClient(sock).Do("GET", "/v1/health", nil, &res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := get()
	if !res.OK || !res.Degraded || len(res.Reasons) != 1 || !strings.Contains(res.Reasons[0], "landlock") {
		t.Fatalf("health: %+v", res)
	}
	// Everything applied: plain ok, no noise.
	status.Mechanism[1].State = sandbox.StateApplied
	if res := get(); !res.OK || res.Degraded || len(res.Reasons) != 0 {
		t.Fatalf("health with the sandbox intact: %+v", res)
	}
}

// The live session table over the socket: a bastion operator asks who is
// on, closes one by name and a set by filter, and every closure is in the
// audit log. The sessions are registered directly on the table here,
// because what is being tested is the management plane and not any one
// protocol's handshake.
func TestSessionAPIListsAndCloses(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.log")
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging:
  directory: %s
  audit: {file: audit.log}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
`, dir)))
	if err != nil {
		t.Fatal(err)
	}
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	p, err := proxy.New(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logs, Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	c := NewClient(sock)

	if got, err := c.Sessions(); err != nil || len(got) != 0 {
		t.Fatalf("empty table: %+v %v", got, err)
	}
	table := p.Sessions()
	closed := make(chan string, 4)
	mk := func(kind, listener, user, client string) *sessions.Session {
		s := table.Register(sessions.Info{Kind: kind, Listener: listener, Client: client},
			func() { closed <- kind + "/" + user })
		s.Annotate(user, "10.1.0.4:22", "shell")
		return s
	}
	ssh1 := mk("ssh", "bastion", "alice", "10.0.0.9:5001")
	mk("ssh", "bastion", "bob", "10.0.0.9:5002")
	mk("vnc", "desks", "alice", "10.0.0.9:5003")

	live, err := c.Sessions()
	if err != nil || len(live) != 3 {
		t.Fatalf("listed %+v %v", live, err)
	}
	if live[0].ID != ssh1.ID || live[0].User != "alice" || live[0].Target != "10.1.0.4:22" {
		t.Fatalf("oldest first, annotated: %+v", live[0])
	}

	// By name.
	got, err := c.KillSessions(ssh1.ID, "", "", "")
	if err != nil || len(got) != 1 || got[0].ID != ssh1.ID {
		t.Fatalf("kill by id: %+v %v", got, err)
	}
	if name := <-closed; name != "ssh/alice" {
		t.Fatalf("closed %q", name)
	}
	if !ssh1.Killed() {
		t.Error("the session does not know an operator closed it")
	}
	// A name that is not there, and a name already closed, are both not
	// a closure: an operator repeating the command is told the truth.
	if _, err := c.KillSessions("0011223344556677", "", "", ""); err == nil {
		t.Error("a session nobody registered was closed")
	}
	if _, err := c.KillSessions(ssh1.ID, "", "", ""); err == nil {
		t.Error("a session already closing was closed again")
	}
	// A request that names nothing is refused rather than treated as
	// "everything": the filter is what makes this safe to expose.
	if _, err := c.KillSessions("", "", "", ""); err == nil {
		t.Error("a request naming no session closed something")
	}
	// By login, across kinds.
	got, err = c.KillSessions("", "", "", "alice")
	if err != nil || len(got) != 1 || got[0].Kind != "vnc" {
		t.Fatalf("kill by user: %+v %v", got, err)
	}
	if name := <-closed; name != "vnc/alice" {
		t.Fatalf("closed %q", name)
	}
	// Bob is still on, because nothing matched him.
	if st := table.Status(); st.Killed != 2 || st.Live != 3 {
		t.Errorf("status %+v", st)
	}

	// Every closure is in the audit log, with the session named.
	b, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"session_kill", ssh1.ID, "\"user\":\"alice\"", "\"kind\":\"vnc\""} {
		if !strings.Contains(string(b), want) {
			t.Errorf("audit log has no %s:\n%s", want, b)
		}
	}
}

// The shadow report over the socket: what the listeners in shadow mode
// would have refused, worst first, and the reset an operator runs after
// fixing the policy.
func TestPolicyReportListsWhatWouldHaveBeenRefused(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
policy: {mode: shadow}
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: r, upstream: u}
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
	defer m.Shutdown(context.Background())
	c := NewClient(sock)

	rep, err := c.PolicyReport()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Entries) != 0 || rep.Status.Entries != 0 {
		t.Fatalf("a fresh ledger: %+v", rep)
	}
	for i := 0; i < 3; i++ {
		p.Shadow().Record("modbus", "line-2", "rule_deny", "setpoints", "unit 2 write 40010")
	}
	p.Shadow().Record("ssh", "operators", "command_refused", "", "rm -rf /")

	rep, err = c.PolicyReport()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Entries) != 2 || rep.Entries[0].Count != 3 || rep.Entries[0].Kind != "modbus" {
		t.Fatalf("report %+v", rep.Entries)
	}
	if rep.Status.Recorded != 4 || rep.Status.Entries != 2 {
		t.Fatalf("status %+v", rep.Status)
	}
	if rep.Entries[0].Rule != "setpoints" || rep.Entries[0].Sample == "" {
		t.Errorf("the entry lost the rule or the example: %+v", rep.Entries[0])
	}
	// The reset, which is what an operator runs after fixing the policy
	// so the next week's report is about the new one.
	if err := c.ResetPolicyReport(); err != nil {
		t.Fatal(err)
	}
	rep, err = c.PolicyReport()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Entries) != 0 || rep.Status.Recorded != 0 {
		t.Fatalf("after the reset: %+v", rep)
	}
}
