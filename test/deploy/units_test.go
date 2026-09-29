// Package deploy checks the unit files, sysusers and tmpfiles entries
// shipped under deploy/ against each other, so the three daemons can
// actually start side by side on one host. Nothing here runs systemd:
// these are the invariants that hold between the files, which is where
// a split into three units goes wrong.
package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// the daemon units and the user each runs as.
var daemons = map[string]string{
	"xproxy.service": "xproxy",
	"xgate.service":  "xgate",
	"xrelay.service": "xrelay",
	"xot.service":    "xot",
}

// configDir is the directory they all read their configuration from.
const configDir = "/etc/xproxy"

const configGroup = "xproxy-config"

func read(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// systemd chowns a ConfigurationDirectory to the unit's own User and
// Group on every start. Three units declaring the same one is three
// daemons taking /etc/xproxy from each other in turn, and at 0750 the
// two that did not start last cannot read their configuration at all --
// a deployment that works until the second daemon is restarted. The
// directory is created by tmpfiles.d instead, owned by the group they
// share.
func TestNoDaemonClaimsTheSharedConfigurationDirectory(t *testing.T) {
	for unit := range daemons {
		body := read(t, "deploy", "systemd", unit)
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ConfigurationDirectory=") {
				t.Errorf("%s declares %q: systemd would chown %s to this unit's user on every start, locking the other daemons out", unit, line, configDir)
			}
		}
		// It still has to be able to read it.
		if !strings.Contains(body, "ReadOnlyPaths="+configDir) && !strings.Contains(body, "ReadWritePaths="+configDir) {
			t.Errorf("%s does not admit %s through the sandbox", unit, configDir)
		}
	}
}

// Every daemon that reads the shared directory must be a member of the
// group that owns it, or it cannot enter it at 0750.
func TestEveryDaemonIsInTheConfigGroup(t *testing.T) {
	sysusers := read(t, "deploy", "sysusers", "xproxy.conf")
	if !regexp.MustCompile(`(?m)^g\s+` + configGroup + `\s`).MatchString(sysusers) {
		t.Fatalf("sysusers does not create the %s group", configGroup)
	}
	for unit, user := range daemons {
		member := regexp.MustCompile(`(?m)^m\s+` + user + `\s+` + configGroup + `\s*$`)
		if !member.MatchString(sysusers) {
			t.Errorf("%s runs as %q, which sysusers does not put in %s: it could not read %s", unit, user, configGroup, configDir)
		}
	}
}

// And the directory has to exist with that group before any of them
// starts, which is what the tmpfiles entry is for.
func TestTmpfilesCreatesTheConfigDirectory(t *testing.T) {
	conf := read(t, "deploy", "tmpfiles", "xproxy-config.conf")
	want := regexp.MustCompile(`(?m)^d\s+` + configDir + `\s+0750\s+root\s+` + configGroup + `\s`)
	if !want.MatchString(conf) {
		t.Errorf("the tmpfiles entry does not create %s as 0750 root:%s:\n%s", configDir, configGroup, conf)
	}
	// It is only shipped if it is installed.
	mk := read(t, "Makefile")
	if !strings.Contains(mk, "deploy/tmpfiles/xproxy-config.conf") {
		t.Error("the Makefile does not install deploy/tmpfiles/xproxy-config.conf")
	}
}

// The unit's own user must not be the one that owns the directory
// either: the point of the shared group is that no single daemon owns
// what all three read.
func TestNoDaemonOwnsTheSharedConfigurationDirectory(t *testing.T) {
	spec := read(t, "deploy", "rpm", "xproxy.spec")
	owner := regexp.MustCompile(`%dir\s+%attr\(0750,\s*root,\s*([A-Za-z0-9_-]+)\)\s+%\{_sysconfdir\}/xproxy\b`)
	m := owner.FindStringSubmatch(spec)
	if m == nil {
		t.Fatal("the spec does not own /etc/xproxy with an explicit owner")
	}
	if m[1] != configGroup {
		t.Errorf("the spec owns %s as root:%s, want root:%s", configDir, m[1], configGroup)
	}
}
