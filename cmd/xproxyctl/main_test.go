package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
	"github.com/rom/xproxy/internal/testutil"
)

const testYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
bans: {action: reject}
waf:
  default_mode: block
  default_profile: custom
  profiles:
    - {name: custom, directives: "SecRule REQUEST_HEADERS:X-Evil \"@streq yes\" \"id:100001,phase:1,deny,status:406,msg:'evil header'\""}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`

// harness starts a proxy and management server on a temporary socket and
// returns the socket path, a configuration file path and a stop function.
func harness(t *testing.T) (sock, cfgPath string) {
	t.Helper()
	cfg, err := config.Parse([]byte(testYAML))
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
	if err := os.WriteFile(cfgPath, []byte(testYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{
		Reload:      func() error { reloads++; return nil },
		ReloadCerts: func() error { return nil },
		ReopenLogs:  func() error { return nil },
		DryRun:      func() (*config.Changes, error) { return config.Diff(cfg, cfg, "active", "file"), nil },
		Diff:        func(a, b string) (*config.Changes, error) { return config.Diff(cfg, cfg, a, b), nil },
		History:     func() ([]config.Entry, error) { return nil, config.ErrNoHistory },
		Rollback:    func(string) error { return config.ErrNoHistory },
		Sandbox: func() *sandbox.Status {
			return &sandbox.Status{Platform: "linux", Enabled: true, AppliedAt: time.Now(), Landlocked: true, LandlockABI: 5,
				ReadPaths: []string{"/etc/xproxy"}, WritePaths: []string{"/var/log/xproxy"},
				Mechanism: []sandbox.Mechanism{{Name: "landlock", State: sandbox.StateApplied, Detail: "ABI 5"}, {Name: "seccomp", State: sandbox.StateUnavailable, Detail: "no"}}}
		},
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return sock, cfgPath
}

func runCmd(t *testing.T, sock, cfgPath string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{"-socket", sock, "-config", cfgPath}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestCommands(t *testing.T) {
	sock, cfgPath := harness(t)
	certPath, _ := testutil.WriteCert(t, t.TempDir(), "example.com")
	cases := []struct {
		args []string
		code int
		want string // substring of stdout (code 0) or stderr (otherwise)
	}{
		{[]string{"version"}, 0, "xproxyctl"},
		{[]string{"validate"}, 0, "OK (1 listeners, 1 upstreams, 1 routes)"},
		{[]string{"status"}, 0, "generation"},
		{[]string{"status"}, 0, "sandbox applied landlock"},
		{[]string{"-json", "status"}, 0, `"generation"`},
		{[]string{"stats"}, 0, "requests"},
		{[]string{"upstreams"}, 0, "127.0.0.1:1"},
		{[]string{"quotas", "-top", "3"}, 0, "ROUTE"},
		{[]string{"-json", "quotas"}, 0, `"rate_limits"`},
		{[]string{"waf"}, 0, "PROFILE"},
		{[]string{"waf", "rules"}, 0, "no rule matches recorded"},
		{[]string{"waf", "proposals"}, 0, "no exclusion proposals"},
		{[]string{"waf", "exclusions"}, 0, "(no proposals)"},
		{[]string{"waf", "reset"}, 0, "reset"},
		{[]string{"waf", "bogus"}, 2, "usage: xproxyctl waf"},
		{[]string{"sandbox"}, 0, "landlock   applied      ABI 5"},
		{[]string{"sandbox"}, 0, "read   /etc/xproxy"},
		{[]string{"-json", "sandbox"}, 0, `"landlock_abi": 5`},
		{[]string{"tls"}, 0, ""},
		{[]string{"schema"}, 0, `"$schema"`},
		{[]string{"completion", "bash"}, 0, "complete -F _xproxyctl xproxyctl"},
		{[]string{"completion", "zsh"}, 0, "#compdef xproxyctl xproxy"},
		{[]string{"completion", "fish"}, 0, "complete -c xproxyctl -n 'not __fish_seen_subcommand_from"},
		{[]string{"completion", "tcsh"}, 2, "usage: xproxyctl completion"},
		{[]string{"help"}, 0, "rotate-secret [-keep N] FILE"},
		{[]string{"telemetry"}, 0, ""},
		{[]string{"config"}, 0, "version: 1"},
		{[]string{"reload"}, 0, "reloaded"},
		{[]string{"reload", "-dry-run"}, 0, ""},
		{[]string{"diff"}, 0, ""},
		{[]string{"-json", "diff"}, 0, "{"},
		{[]string{"history"}, 1, "history"},
		{[]string{"rollback", "nope"}, 1, "history"},
		{[]string{"rollback"}, 2, "usage"},
		{[]string{"reload-certs"}, 0, ""},
		{[]string{"reopen-logs"}, 0, ""},
		{[]string{"bans"}, 0, "TARGET"},
		{[]string{"ban", "-duration", "10m", "-reason", "test", "203.0.113.7"}, 0, "banned 203.0.113.7"},
		{[]string{"bans"}, 0, "203.0.113.7"},
		{[]string{"-json", "bans"}, 0, `"target"`},
		{[]string{"ban"}, 2, "usage: xproxyctl ban"},
		{[]string{"ban", "127.0.0.1"}, 1, ""},
		{[]string{"unban", "203.0.113.7"}, 0, "unbanned"},
		{[]string{"unban"}, 2, "usage: xproxyctl unban"},
		{[]string{"cluster"}, 1, ""},
		{[]string{"acme"}, 1, ""},
		{[]string{"metrics"}, 0, "xproxy_"},
		{[]string{"series", "-since", "1m", "-last", "5"}, 0, ""},
		{[]string{"filters"}, 0, ""},
		{[]string{"spki"}, 2, "usage: xproxyctl spki"},
		{[]string{"spki", certPath}, 0, "# example.com, expires"},
		{[]string{"spki", filepath.Join(t.TempDir(), "missing.pem")}, 1, ""},
		{[]string{"htpasswd"}, 2, "usage: xproxyctl htpasswd"},
		{[]string{"tail"}, 2, "usage"},
		{[]string{"tui"}, 1, ""},
		{[]string{"nonsense"}, 2, "usage"},
		{[]string{}, 2, "usage"},
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

// The remaining commands answer from optional subsystems that this
// harness does not configure; they must fail cleanly (exit 1 with an
// error line) or print an empty view, never panic or hang.
func TestOptionalSubsystems(t *testing.T) {
	sock, cfgPath := harness(t)
	for _, cmd := range []string{"icap", "geoip", "cache", "honeypot", "dns", "ingress", "otlp"} {
		t.Run(cmd, func(t *testing.T) {
			code, out, errOut := runCmd(t, sock, cfgPath, cmd)
			if code != 0 && code != 1 {
				t.Fatalf("exit %d\n%s%s", code, out, errOut)
			}
			if code == 1 && !strings.Contains(errOut, "error:") {
				t.Fatalf("failure without an error line: %q", errOut)
			}
		})
	}
}

func TestUnreachableSocket(t *testing.T) {
	code, _, errOut := runCmd(t, filepath.Join(t.TempDir(), "none.sock"), "", "status")
	if code != 1 || !strings.Contains(errOut, "error:") {
		t.Fatalf("exit %d %q", code, errOut)
	}
}

func TestHtpasswd(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users")
	var out, errOut bytes.Buffer
	if code := htpasswd(file, "alice", strings.NewReader("correct horse battery\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "alice:") {
		t.Fatalf("users file: %s", data)
	}
	// A second user is appended, an existing one replaced.
	if code := htpasswd(file, "bob", strings.NewReader("hunter22hunter22\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if code := htpasswd(file, "alice", strings.NewReader("a new long password\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	data, _ = os.ReadFile(file)
	if strings.Count(string(data), "alice:") != 1 || strings.Count(string(data), "bob:") != 1 {
		t.Fatalf("users file after updates:\n%s", data)
	}
	if code := htpasswd(file, "carol", strings.NewReader("short\n"), &out, &errOut); code == 0 {
		t.Fatal("short password accepted")
	}
}

func TestSandboxSummary(t *testing.T) {
	if s := sandboxSummary(&sandbox.Status{}); s != "disabled" {
		t.Fatalf("disabled: %q", s)
	}
	st := &sandbox.Status{Enabled: true, Mechanism: []sandbox.Mechanism{{Name: "a", State: sandbox.StateApplied}, {Name: "b", State: sandbox.StateFailed}}}
	if s := sandboxSummary(st); s != "applied a  b=failed" {
		t.Fatalf("summary: %q", s)
	}
}

// TestCommandTable checks that the command table (usage, help and
// completion) and the dispatch in run agree, and that the bash script
// parses.
func TestCommandTable(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start, end := strings.Index(body, "switch fs.Arg(0) {"), 0
	if start >= 0 {
		end = strings.Index(body[start:], "\n}\n")
	}
	if start < 0 || end < 0 {
		t.Fatal("dispatch switch not found in main.go")
	}
	body = body[start : start+end]
	dispatched := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\tcase ("[^"]+"(?:, )?)+:`).FindAllString(body, -1) {
		for _, name := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m, -1) {
			dispatched[name[1]] = true
		}
	}
	listed := map[string]bool{}
	for _, c := range commandTable {
		listed[c.name] = true
		if !dispatched[c.name] {
			t.Errorf("%s listed but not dispatched", c.name)
		}
		if strings.Contains(c.summary, ":") {
			t.Errorf("%s: summary with a colon breaks the zsh script", c.name)
		}
	}
	for name := range dispatched {
		if !listed[name] {
			t.Errorf("%s dispatched but not listed", name)
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(bashCompletion())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bash -n: %v %s", err, out)
		}
	}
	if zsh, err := exec.LookPath("zsh"); err == nil {
		cmd := exec.Command(zsh, "-n")
		cmd.Stdin = strings.NewReader(zshCompletion())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("zsh -n: %v %s", err, out)
		}
	}
}
