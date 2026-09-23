package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The spec is written once and then forgotten, so what it ships drifts
// behind what the tree builds: it packaged only xproxy for as long as
// there had been three daemons. These check that everything the source
// install ships reaches the RPM too -- not that the two are identical,
// but that nothing new is silently left out of the packaged path.

func spec(t *testing.T) string {
	t.Helper()
	return read(t, "deploy", "rpm", "xproxy.spec")
}

// Every daemon binary the Makefile builds is installed and packaged.
func TestEveryDaemonIsPackaged(t *testing.T) {
	s := spec(t)
	for _, bin := range []string{"xproxy", "xgate", "xrelay", "xproxyctl", "xproxy-admin", "xproxy-fleet"} {
		if !strings.Contains(read(t, "Makefile"), "-o $(BIN)/"+bin+" ") {
			t.Errorf("the Makefile no longer builds %s; this list is stale", bin)
			continue
		}
		if !strings.Contains(s, "bin/"+bin+" ") {
			t.Errorf("the spec does not install bin/%s", bin)
		}
		if !strings.Contains(s, "%{_bindir}/"+bin+"\n") {
			t.Errorf("the spec installs bin/%s but no %%files section owns it", bin)
		}
	}
}

// Every shipped unit and socket reaches the packaged path. A unit the
// spec does not install is a daemon that cannot be started from the
// RPM, which is only discovered on the host.
func TestEveryUnitIsPackaged(t *testing.T) {
	s := spec(t)
	dir := filepath.Join("..", "..", "deploy", "systemd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".service") && !strings.HasSuffix(n, ".socket")) {
			continue
		}
		if !strings.Contains(s, n) {
			t.Errorf("deploy/systemd/%s is not installed by the spec", n)
		}
		if !strings.Contains(s, "%{_unitdir}/"+n) {
			t.Errorf("deploy/systemd/%s is installed but no %%files section owns it", n)
		}
	}
}

// The tmpfiles entries create the two directories no single daemon can
// own. The source install ships them; so must the RPM, or a packaged
// three-daemon host has neither a configuration directory they share
// nor a cluster socket directory.
func TestTmpfilesArePackaged(t *testing.T) {
	s := spec(t)
	dir := filepath.Join("..", "..", "deploy", "tmpfiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no tmpfiles entries at all")
	}
	for _, e := range entries {
		if !strings.Contains(s, "deploy/tmpfiles/"+e.Name()) {
			t.Errorf("deploy/tmpfiles/%s is not installed by the spec", e.Name())
		}
		if !strings.Contains(s, "%{_tmpfilesdir}/"+e.Name()) {
			t.Errorf("deploy/tmpfiles/%s is installed but no %%files section owns it", e.Name())
		}
	}
}

// Each daemon reads its own file in the shared directory, and the unit
// names that path. An example the package does not ship is a daemon
// that starts with no configuration at all.
func TestEachDaemonShipsItsExampleConfiguration(t *testing.T) {
	s := spec(t)
	for _, d := range []string{"xproxy", "xgate", "xrelay"} {
		unit := read(t, "deploy", "systemd", d+".service")
		want := configDir + "/" + d + ".yaml"
		if !strings.Contains(unit, want) {
			t.Errorf("%s.service does not read %s; this list is stale", d, want)
		}
		if _, err := os.Stat(filepath.Join("..", "..", "deploy", "config", d+".yaml")); err != nil {
			t.Errorf("no example configuration for %s: %v", d, err)
		}
		if !strings.Contains(s, "deploy/config/"+d+".yaml") {
			t.Errorf("the spec does not install deploy/config/%s.yaml", d)
		}
		// It belongs to the shared group, like the directory.
		owned := "%config(noreplace) %attr(0640,root," + configGroup + ") %{_sysconfdir}/xproxy/" + d + ".yaml"
		if !strings.Contains(s, owned) {
			t.Errorf("the spec does not own %s.yaml as root:%s", d, configGroup)
		}
	}
}
