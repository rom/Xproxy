package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/paths"
)

// estate is a configuration with a listener of every role, which is the
// shape the split has to get right: one file describing the whole
// estate, three daemons each taking their share of it.
const estate = `
version: 1
server:
  listeners:
    - {name: web, address: "127.0.0.1:0"}
    - {name: l4, address: "127.0.0.1:0", kind: tcp, tcp: {default: u}}
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: u
        host_keys: [/dev/null]
        authorized_keys: /dev/null
        upstream_key_file: /dev/null
        upstream_known_hosts: /dev/null
    - {name: mail, address: "127.0.0.1:0", kind: smtp, smtp: {upstream: u}}
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`

// TestOwnTakesOnlyItsShare: every daemon reads the whole file, and each
// binds a disjoint part of it. Between them they bind all of it, so no
// listener is silently nobody's.
func TestOwnTakesOnlyItsShare(t *testing.T) {
	cfg, err := config.Parse([]byte(estate))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, role := range listener.Roles() {
		mine := own(role, cfg, nil)
		for _, lc := range mine.Server.Listeners {
			if !role.Serves(lc.Kind) {
				t.Errorf("%s kept %q, which is kind %q", role.Daemon(), lc.Name, lc.Kind)
			}
			if other, dup := seen[lc.Name]; dup {
				t.Errorf("listener %q is bound by both %s and %s", lc.Name, other, role.Daemon())
			}
			seen[lc.Name] = role.Daemon()
		}
		if len(mine.Server.Listeners) == 0 {
			t.Errorf("%s took nothing", role.Daemon())
		}
		// The file it was given is not modified: the next daemon, and
		// the history and diff views, still see the whole estate.
		if len(cfg.Server.Listeners) != 4 {
			t.Fatal("own modified the configuration it was given")
		}
	}
	if len(seen) != len(cfg.Server.Listeners) {
		t.Errorf("%d of %d listeners were claimed: %v", len(seen), len(cfg.Server.Listeners), seen)
	}
	if seen["web"] != "xproxy" || seen["l4"] != "xproxy" || seen["bastion"] != "xgate" || seen["mail"] != "xrelay" {
		t.Errorf("listeners went to the wrong daemons: %v", seen)
	}
}

// TestSplitCounts is what -validate prints: the whole file checked, and
// how much of it this daemon would serve.
func TestSplitCounts(t *testing.T) {
	cfg, err := config.Parse([]byte(estate))
	if err != nil {
		t.Fatal(err)
	}
	for role, want := range map[listener.Role]int{
		listener.RoleEdge: 2, listener.RoleGate: 1, listener.RoleRelay: 1,
	} {
		mine, theirs := split(role, cfg)
		if mine != want || mine+theirs != len(cfg.Server.Listeners) {
			t.Errorf("%s: %d mine, %d theirs, want %d of %d", role.Daemon(), mine, theirs, want, len(cfg.Server.Listeners))
		}
	}
}

// TestValidateAndVersion: the two things a daemon does without binding
// anything, for each of the three.
func TestValidateAndVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "estate.yaml")
	if err := os.WriteFile(path, []byte(estate), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, role := range listener.Roles() {
		if code := Run(role, []string{"-version"}); code != 0 {
			t.Errorf("%s -version: %d", role.Daemon(), code)
		}
		if code := Run(role, []string{"-config", path, "-validate"}); code != 0 {
			t.Errorf("%s -validate: %d", role.Daemon(), code)
		}
		// A file that does not exist fails rather than starting on
		// nothing.
		if code := Run(role, []string{"-config", filepath.Join(dir, "absent.yaml"), "-validate"}); code != 1 {
			t.Errorf("%s on a missing file: %d", role.Daemon(), code)
		}
	}
}

// TestConfigFileDefaults: each daemon reads a file of its own, because
// the management socket, the metrics address and the log directory are
// exactly what two processes cannot share.
func TestConfigFileDefaults(t *testing.T) {
	seen := map[string]bool{}
	for _, role := range listener.Roles() {
		p := paths.ConfigFileFor(role.Daemon())
		if seen[p] {
			t.Errorf("%s shares its default configuration file: %s", role.Daemon(), p)
		}
		seen[p] = true
		if !strings.HasPrefix(p, paths.ConfigDir) {
			t.Errorf("%s reads %s, outside %s", role.Daemon(), p, paths.ConfigDir)
		}
	}
	if paths.ConfigFileFor("xproxy") != paths.ConfigFile {
		t.Error("the edge daemon's default file moved; existing installations read it")
	}
}
