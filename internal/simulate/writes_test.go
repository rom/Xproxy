package simulate

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// A configuration that writes in six places, all of them the estate's: a ban
// store, an access ledger, two inventories, a learning report and a session
// recording directory.
//
// Built in Go rather than parsed from YAML, because validation opens an ssh
// listener's host key and checks that its recording directory exists, and what
// is under test here is what Offline does with the paths rather than whether a
// bastion is configured correctly.
func writesConfig() *config.Config {
	on := true
	return &config.Config{
		Bans:           &config.Bans{StateFile: "/var/lib/xproxy/bans.db"},
		Access:         &config.Access{Ledger: "/var/lib/xproxy/access.jsonl"},
		AssetInventory: &config.AssetInventory{Enabled: true, StateFile: "/var/lib/xproxy/assets.json"},
		APIInventory:   &config.APIInventory{Enabled: &on, StateFile: "/var/lib/xproxy/apis.json"},
		Server: config.Server{Listeners: []config.Listener{
			{Name: "line1", Address: "10.20.0.4:502", Kind: "modbus", Modbus: &config.ModbusListener{
				Upstream: "plc",
				Learn:    &config.ModbusLearn{Enabled: true, File: "/var/lib/xproxy/learn/line1.yaml"},
			}},
			{Name: "bastion", Address: "10.0.0.2:22", Kind: "ssh", SSH: &config.SSHListener{
				Upstream:  "hosts",
				Recording: &config.SessionRecording{Enabled: &on, Directory: "/var/log/xgate/rec"},
			}},
		}},
		Upstreams: []config.Upstream{
			{Name: "plc", Endpoints: []config.Endpoint{{Address: "10.20.0.9:502"}}},
			{Name: "hosts", Endpoints: []config.Endpoint{{Address: "10.0.1.5:22"}}},
		},
	}
}

// Nothing a simulation writes may land in the estate's directories.
//
// The state files are the obvious half and were handled from the start. The
// outputs are the half that is easy to miss, because they change no decision:
// a learning report and a session recording are produced by the run rather than
// read by it, so nothing in the answer looks wrong when they go to the estate's
// paths. A learning report overwritten with a simulation's traffic is the worst
// of them, since somebody promotes those into a policy later.
//
// This walks the whole prepared configuration rather than checking the six
// fields by name: the point is that no path anywhere in it still points at the
// estate, including one a listener kind added after this was written.
func TestNothingIsWrittenOutsideTheSimulationDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg, rep, err := Offline(writesConfig(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths(reflect.ValueOf(cfg), 0) {
		if !strings.HasPrefix(p.value, "/var/lib/xproxy") && !strings.HasPrefix(p.value, "/var/log") {
			continue
		}
		t.Errorf("%s still points at the estate: %s", p.field, p.value)
	}
	// And the state a decision depends on was copied rather than abandoned.
	for _, want := range []string{"bans.state_file", "access.ledger",
		"asset_inventory.state_file", "api_inventory.state_file"} {
		found := false
		for _, c := range rep.Copied {
			if strings.HasPrefix(c, want+":") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not reported as copied: %v", want, rep.Copied)
		}
	}
	if len(rep.Notes) == 0 {
		t.Error("the report says nothing about the output paths it moved")
	}
	for _, f := range []string{
		filepath.Join(dir, "bans.state"), filepath.Join(dir, "access.jsonl"),
		filepath.Join(dir, "learning", "modbus.yaml"), filepath.Join(dir, "recordings"),
	} {
		if !strings.HasPrefix(f, dir) {
			t.Fatalf("%s is not under %s: this test is wrong", f, dir)
		}
	}
}

// The caller's configuration is not modified, including the parts reached
// through a pointer -- which is where a struct copy would have leaked.
func TestTheCallersConfigurationIsUntouchedThroughItsPointers(t *testing.T) {
	in := writesConfig()
	if _, _, err := Offline(in, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got := in.Bans.StateFile; got != "/var/lib/xproxy/bans.db" {
		t.Errorf("bans.state_file became %q", got)
	}
	if got := in.AssetInventory.StateFile; got != "/var/lib/xproxy/assets.json" {
		t.Errorf("asset_inventory.state_file became %q", got)
	}
	var learn, rec string
	for _, l := range in.Server.Listeners {
		if l.Modbus != nil && l.Modbus.Learn != nil {
			learn = l.Modbus.Learn.File
		}
		if l.SSH != nil && l.SSH.Recording != nil {
			rec = l.SSH.Recording.Directory
		}
	}
	if learn != "/var/lib/xproxy/learn/line1.yaml" {
		t.Errorf("the caller's learning report path became %q", learn)
	}
	if rec != "/var/log/xgate/rec" {
		t.Errorf("the caller's recording directory became %q", rec)
	}
}

// found is one string field that looks like a path, and where it was.
type found struct {
	field string
	value string
}

// paths walks a configuration and returns every non-empty string field whose
// value starts with a slash, with the path of field names that reached it.
func paths(v reflect.Value, depth int) []found {
	if depth > maxWalkDepth || !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return paths(v.Elem(), depth+1)
	case reflect.Slice, reflect.Array:
		var out []found
		for i := range v.Len() {
			out = append(out, paths(v.Index(i), depth+1)...)
		}
		return out
	case reflect.Map:
		var out []found
		for _, k := range v.MapKeys() {
			out = append(out, paths(v.MapIndex(k), depth+1)...)
		}
		return out
	case reflect.Struct:
		var out []found
		t := v.Type()
		for i := range v.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			if f.Type.Kind() == reflect.String {
				if s := v.Field(i).String(); strings.HasPrefix(s, "/") {
					out = append(out, found{field: t.Name() + "." + f.Name, value: s})
				}
				continue
			}
			out = append(out, paths(v.Field(i), depth+1)...)
		}
		return out
	default:
		return nil
	}
}

// And the walk itself has to be able to see those fields, or the test above
// would pass by looking at nothing. Asserted against the configuration before
// it is prepared, where the estate's paths are still in place.
func TestTheWalkSeesTheEstatesPaths(t *testing.T) {
	var estate int
	for _, p := range paths(reflect.ValueOf(writesConfig()), 0) {
		if strings.HasPrefix(p.value, "/var/") {
			estate++
		}
	}
	if estate < 6 {
		t.Errorf("the walk found %d of the estate's paths, not the six in the file", estate)
	}
}
