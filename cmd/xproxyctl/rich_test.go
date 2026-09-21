package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
	"github.com/rom/xproxy/internal/secret"
)

// The table views of the control tool only exist when the subsystem
// behind them is configured: with no virtual patches there is no patch
// table, and the branch that renders one never runs. This harness
// turns those subsystems on, so the tables themselves are covered
// rather than only the "not configured" lines.

const richYAML = `version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
bans:
  action: reject
  triggers: [{name: waf, reasons: [waf], threshold: 3, window: 1m, duration: 1h}]
waf:
  default_mode: block
  default_profile: custom
  profiles:
    - {name: custom, directives: "SecRule REQUEST_HEADERS:X-Evil \"@streq yes\" \"id:100001,phase:1,deny,status:406,msg:'evil header'\""}
api_inventory:
  zombie_after: 720h
maintenance:
  enabled: false
  status: 503
  message: "back soon"
cache:
  max_bytes: 1048576
virtual_patches:
  - id: cve-2026-1
    description: "a patch"
    enabled: true
    methods: [POST]
    paths: [/admin]
    action: block
    status: 403
filters:
  - name: guard
    kind: account_guard
    options:
      endpoints:
        - name: login
          class: login
          paths: [/login]
          identity: {form: user}
          failure: {statuses: [401]}
  - name: score
    kind: bot_score
    options: {}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u, filters: [guard, score]}
  - {name: hp, paths: [/wp-admin], honeypot: {decoy: wp-login}}
`

// richHarness is harness with a configuration that enables the optional
// subsystems, and with history and a rollback that work.
func richHarness(t *testing.T) (sock, cfgPath string) {
	t.Helper()
	cfg, err := config.Parse([]byte(richYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sock = filepath.Join(dir, "m.sock")
	cfgPath = filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(richYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{
		Reload:      func() error { return nil },
		ReloadCerts: func() error { return nil },
		ReopenLogs:  func() error { return nil },
		DryRun:      func() (*config.Changes, error) { return config.Diff(cfg, cfg, "active", "file"), nil },
		Diff:        func(a, b string) (*config.Changes, error) { return config.Diff(cfg, cfg, a, b), nil },
		History: func() ([]config.Entry, error) {
			return []config.Entry{
				{ID: "20260920-100000", Generation: 1, Applied: now.Add(-time.Hour), Source: "file", Note: "first", Size: 1024},
				{ID: "20260920-110000", Generation: 2, Applied: now, Source: "reload", Size: 2048},
			}, nil
		},
		Rollback: func(id string) error {
			if id == "20260920-100000" {
				return nil
			}
			return config.ErrNoHistory
		},
		Sandbox: func() *sandbox.Status {
			return &sandbox.Status{Platform: "linux", Enabled: false,
				Mechanism: []sandbox.Mechanism{{Name: "landlock", State: sandbox.StateUnavailable, Detail: "kernel"}}}
		},
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return sock, cfgPath
}

// TestRichViews runs every view whose table needs a configured
// subsystem behind it.
func TestRichViews(t *testing.T) {
	sock, cfgPath := richHarness(t)
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"patches"}, 0, "cve-2026-1"},
		{[]string{"-json", "patches"}, 0, `"cve-2026-1"`},
		{[]string{"accounts"}, 0, "login"},
		{[]string{"-json", "accounts"}, 0, "{"},
		{[]string{"botscore"}, 0, ""},
		{[]string{"-json", "botscore"}, 0, "{"},
		{[]string{"api"}, 0, ""},
		{[]string{"api", "all"}, 0, ""},
		{[]string{"api", "shadow"}, 0, ""},
		{[]string{"api", "zombie"}, 0, ""},
		{[]string{"api", "versions"}, 0, ""},
		{[]string{"api", "documented"}, 0, ""},
		{[]string{"-json", "api"}, 0, "{"},
		{[]string{"honeypot"}, 0, ""},
		{[]string{"-json", "honeypot"}, 0, "{"},
		{[]string{"cache"}, 0, ""},
		{[]string{"-json", "cache"}, 0, "{"},
		{[]string{"maintenance"}, 0, ""},
		{[]string{"maintenance", "on"}, 0, ""},
		{[]string{"maintenance"}, 0, ""},
		{[]string{"maintenance", "off"}, 0, ""},
		{[]string{"maintenance", "sideways"}, 2, "usage"},
		{[]string{"history"}, 0, "20260920-110000"},
		{[]string{"-json", "history"}, 0, `"generation"`},
		{[]string{"rollback", "20260920-100000"}, 0, ""},
		{[]string{"rollback", "nosuch"}, 1, "history"},
		{[]string{"status"}, 0, "generation"},
		{[]string{"status"}, 0, "sandbox"},
		{[]string{"filters"}, 0, "guard"},
		{[]string{"-json", "filters"}, 0, "{"},
		{[]string{"stats"}, 0, "requests"},
		{[]string{"waf"}, 0, "PROFILE"},
		{[]string{"waf", "rules", "-top", "3"}, 0, ""},
		{[]string{"bans"}, 0, "TARGET"},
		{[]string{"metrics"}, 0, "xproxy_"},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			code, out, errOut := runCmd(t, sock, cfgPath, c.args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, c.code, out, errOut)
			}
			where := out
			if c.code != 0 {
				where = errOut
			}
			if c.want != "" && !strings.Contains(where, c.want) {
				t.Fatalf("output lacks %q\nstdout: %s\nstderr: %s", c.want, out, errOut)
			}
		})
	}
}

// TestRotateSecret covers the keyring rotation command, which writes a
// file an operator's filters read: it must keep the old keys so that
// sessions minted with them still open, and refuse to grow without
// bound.
func TestRotateSecret(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "cookie.key")
	sock, cfgPath := richHarness(t)
	for i := 0; i < 5; i++ {
		code, out, errOut := runCmd(t, sock, cfgPath, "rotate-secret", "-keep", "3", key)
		if code != 0 {
			t.Fatalf("rotation %d: exit %d %s%s", i, code, out, errOut)
		}
	}
	// -keep 3 means three previous keys beside the primary: sessions
	// minted with the keys that are still in the ring keep opening,
	// and the ones older than that stop. A ring that never dropped a
	// key would keep every revoked one valid forever.
	ring, err := secret.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	if ring.Len() != 4 {
		t.Fatalf("the keyring holds %d keys after five rotations with -keep 3", ring.Len())
	}
	st, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the keyring is mode %v; it holds session keys", st.Mode().Perm())
	}
	code, _, errOut := runCmd(t, sock, cfgPath, "rotate-secret")
	if code != 2 || !strings.Contains(errOut, "usage") {
		t.Fatalf("rotate-secret without a path: %d %q", code, errOut)
	}
	code, _, _ = runCmd(t, sock, cfgPath, "rotate-secret", filepath.Join(dir, "no", "such", "dir", "k"))
	if code == 0 {
		t.Fatal("rotation into a missing directory succeeded")
	}
}
