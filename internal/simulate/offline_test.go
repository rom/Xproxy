package simulate

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// The table in offline.go is the security argument of this package: it says,
// section by section, what a simulation does with a configuration. An argument
// with a hole in it is worth less than no argument, and the hole this would grow
// is a section added to the configuration later and simulated live because
// nobody remembered this file.
//
// So the table has to name every top-level section, and this fails when it does
// not. The fix when it fails is to decide what a simulation should do with the
// new section and write it down -- which is thirty seconds of thought and the
// only moment anybody will have it.
func TestEverySectionHasATreatment(t *testing.T) {
	ct := reflect.TypeOf(config.Config{})
	var missing []string
	inConfig := map[string]bool{}
	for i := 0; i < ct.NumField(); i++ {
		tag := ct.Field(i).Tag.Get("yaml")
		key, _, _ := strings.Cut(tag, ",")
		if key == "" || key == "-" {
			continue
		}
		inConfig[key] = true
		if _, ok := sections[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("the simulation's section table does not say what to do with: %s\n"+
			"Decide: keep it (it is policy), copy its state file, switch it off (it reaches "+
			"outside this process), or replace it -- then add it to `sections` in offline.go.",
			strings.Join(missing, ", "))
	}
	// And the other direction: a section in the table that the configuration
	// no longer has is a line nobody will ever read again.
	for _, name := range sectionNames() {
		if !inConfig[name] {
			t.Errorf("the table mentions %q, which the configuration does not have", name)
		}
	}
}

// Everything that reaches outside this process is switched off, and the report
// says which. A simulation that quietly left one on would be the one thing this
// package must not do.
func TestEverythingOutwardIsSwitchedOff(t *testing.T) {
	var outward []string
	for name, how := range sections {
		if how == switchOff {
			outward = append(outward, name)
		}
	}
	if len(outward) < 10 {
		t.Fatalf("only %d outward sections; the table has lost some", len(outward))
	}
	// Each one, present on its own, has to come back switched off.
	for _, tc := range []struct {
		section string
		yaml    string
	}{
		{"cluster", `cluster: {node_id: a, listen: "unix:/run/c.sock", peers: ["unix:/run/d.sock"]}`},
		{"capture", `capture: {enabled: true, directory: /tmp}`},
		{"icap", `icap: {services: [{name: av, url: "icap://10.0.0.5:1344/avscan"}]}`},
		{"tracing", `tracing: {otlp: {endpoint: "https://10.0.0.6:4317"}}`},
		{"threat_intel", `threat_intel: {lists: [{name: bad, url: "https://example.com/l", action: block}]}`},
	} {
		cfg, err := config.Parse([]byte("version: 1\n" + tc.yaml + `
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
`))
		if err != nil {
			t.Errorf("%s: %v", tc.section, err)
			continue
		}
		_, rep, err := Offline(cfg, t.TempDir())
		if err != nil {
			t.Errorf("%s: %v", tc.section, err)
			continue
		}
		found := false
		for _, s := range rep.SwitchedOff {
			if s == tc.section {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was present and the report does not say it was switched off: %v",
				tc.section, rep.SwitchedOff)
		}
	}
}

// State the engine reads and writes is copied, so the run starts from what the
// estate has and writes nowhere near it. A ban that vanished would change a
// decision; a ban written back would change the estate.
func TestStateIsCopiedNotOpened(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(`version: 1
bans: {action: reject, state_file: ` + dir + `/bans.db}
access: {ledger: ` + dir + `/access.jsonl, approvals: 1}
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
`))
	if err != nil {
		t.Fatal(err)
	}
	simDir := t.TempDir()
	out, rep, err := Offline(cfg, simDir)
	if err != nil {
		t.Fatal(err)
	}
	if out.Bans.StateFile == cfg.Bans.StateFile {
		t.Error("the simulation would write the estate's ban state")
	}
	if out.Access.Ledger == cfg.Access.Ledger {
		t.Error("the simulation would write the estate's access ledger")
	}
	for _, p := range []string{out.Bans.StateFile, out.Access.Ledger} {
		if !strings.HasPrefix(p, simDir) {
			t.Errorf("%s is not inside the simulation's own directory", p)
		}
	}
	if len(rep.Copied) != 2 {
		t.Errorf("copied %v", rep.Copied)
	}
}

// Every upstream points at the sink, and the pool names are untouched: which
// pool a route uses is policy, and only where the pool is has changed.
func TestUpstreamsPointAtTheSink(t *testing.T) {
	cfg := parse(t, `version: 1
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}, {address: "10.0.0.2:8080"}], health_check: {path: /healthz}}
  - {name: api, endpoints: [{address: "10.0.0.3:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
  - {name: api, paths: ["/api/"], upstream: api}
`)
	r, err := Start(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	for _, u := range r.cfg.Upstreams {
		if len(u.Endpoints) != 1 {
			t.Errorf("%s has %d endpoints", u.Name, len(u.Endpoints))
		}
		if u.Endpoints[0].Address != r.sink.addr() {
			t.Errorf("%s points at %s, not the sink", u.Name, u.Endpoints[0].Address)
		}
		if u.HealthCheck != nil {
			t.Errorf("%s keeps a health check, which would make one run depend on another's timing", u.Name)
		}
	}
	names := []string{r.cfg.Upstreams[0].Name, r.cfg.Upstreams[1].Name}
	if !reflect.DeepEqual(names, []string{"app", "api"}) {
		t.Errorf("pool names %v: which pool a route uses is policy", names)
	}
}

// A directory that is not one is an error rather than a panic later.
func TestOfflineNeedsADirectory(t *testing.T) {
	cfg := parse(t, `version: 1
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
`)
	if _, _, err := Offline(cfg, "/nonexistent/simulation"); err == nil {
		t.Error("a missing directory was accepted")
	}
	if _, _, err := Offline(nil, t.TempDir()); err == nil {
		t.Error("no configuration was accepted")
	}
}
