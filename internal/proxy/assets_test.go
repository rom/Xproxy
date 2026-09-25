package proxy

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
)

// inventoryProxy is a server with an inventory and nothing else.
func inventoryProxy(t *testing.T, section string) *Server {
	t.Helper()
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
` + section))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A kind writes observations unconditionally. The engine decides whether an
// inventory exists, so that a listener carries no conditional around a call it
// makes on every exchange.
func TestObservingWithoutAnInventoryIsANoOp(t *testing.T) {
	s := inventoryProxy(t, "")
	if s.Assets() != nil {
		t.Fatal("an inventory nobody asked for")
	}
	if _, ok := s.AssetCounts(); ok {
		t.Fatal("counts without an inventory")
	}
	if s.AssetReport() != nil {
		t.Fatal("a summary without an inventory")
	}
	s.ObserveAsset(assets.Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.1")})
	if s.Stats().Assets != nil {
		t.Fatal("the status view reports an inventory that does not exist")
	}
	if s.stats.AssetObservations.Load() != 0 {
		t.Fatal("an observation was counted with nowhere to put it")
	}
}

func TestTheInventoryReachesTheMetricsAndTheStatusView(t *testing.T) {
	s := inventoryProxy(t, "\nasset_inventory:\n  enabled: true\n")
	if s.Assets() == nil {
		t.Fatal("no inventory")
	}
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.20"), Hardware: []byte{0, 0x0f, 0xbb, 1, 2, 3},
		Server: true, Units: []int{1}, Funcs: []int{3}})
	// An observation that names nothing identifiable is refused rather than
	// making a record with no identity in it.
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1"})

	sum := s.Stats().Assets
	if sum == nil || sum.Assets != 1 || sum.Refused != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	if sum.Frozen {
		t.Fatal("a baseline nobody took")
	}
	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"xproxy_assets 1",
		"xproxy_assets_baseline_frozen 0",
		"xproxy_asset_observations_total 1",
		`xproxy_assets_by_role{role="plc"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from the exposition", want)
		}
	}
	// And with no inventory the families are absent rather than zero, so a
	// dashboard does not show an estate of nothing to somebody who never
	// asked for one.
	buf.Reset()
	if err := inventoryProxy(t, "").WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "xproxy_assets") {
		t.Error("asset metrics without an inventory")
	}
}

// A role the estate did not list is a finding on every observation, not once at
// first sighting: a device that keeps behaving like something it should not be
// is a thing that keeps happening.
func TestAnUnexpectedRoleIsCountedEveryTime(t *testing.T) {
	s := inventoryProxy(t, "\nasset_inventory:\n  enabled: true\n  roles: [plc, rtu]\n")
	ws := assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.5"), Hardware: []byte{0xaa, 0xbb, 0xcc, 1, 2, 3},
		Units: []int{1}, Funcs: []int{3, 6, 16}}
	s.ObserveAsset(ws)
	s.ObserveAsset(ws)
	if n := s.stats.AssetUnexpected.Load(); n != 2 {
		t.Fatalf("unexpected role counted %d times, want 2", n)
	}
	// The controller is on the list, so it is not a finding at all.
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.20"), Hardware: []byte{0, 0x0f, 0xbb, 1, 2, 3},
		Server: true, Units: []int{1}, Funcs: []int{3}})
	if n := s.stats.AssetUnexpected.Load(); n != 2 {
		t.Fatalf("a listed role raised a finding: %d", n)
	}
}

// An estate that named no roles has said nothing about what it expects, so
// nothing can be unexpected.
func TestWithoutARoleListNothingIsUnexpected(t *testing.T) {
	s := inventoryProxy(t, "\nasset_inventory:\n  enabled: true\n")
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.5"), Hardware: []byte{0xaa, 0xbb, 0xcc, 1, 2, 3},
		Units: []int{1}, Funcs: []int{3, 6, 16}})
	if n := s.stats.AssetUnexpected.Load(); n != 0 {
		t.Fatalf("a finding against a list nobody wrote: %d", n)
	}
}

// The state file is what stops a restart reporting the whole estate as new,
// which is the fastest way there is to teach an operator to ignore an alert.
func TestTheInventorySurvivesARestartThroughItsStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	section := "\nasset_inventory:\n  enabled: true\n  state_file: " + path + "\n"
	s := inventoryProxy(t, section)
	s.ObserveAsset(assets.Observation{Proto: "dhcp", Listener: "leases",
		Addr: netip.MustParseAddr("10.30.4.9"), Hardware: []byte{0, 0x11, 0x85, 1, 2, 3},
		Hostname: "press-2"})
	k := s.assets.Load()
	if k == nil {
		t.Fatal("no keeper")
	}
	// stop writes one last time: an inventory whose final minutes were lost
	// would report those devices as new on the next start.
	k.stop()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no state file: %v", err)
	}
	again := inventoryProxy(t, section)
	a, ok := again.Assets().Get("10.30.4.9")
	if !ok {
		t.Fatal("the device did not come back")
	}
	if a.Hostname != "press-2" {
		t.Fatalf("read back: %+v", a)
	}
}

// A state file that will not read is a warning, not a refusal to start. An
// inventory is a record, and refusing to carry traffic over one would make the
// record more important than the traffic.
func TestAnUnreadableStateFileDoesNotStopTheProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := inventoryProxy(t, "\nasset_inventory:\n  enabled: true\n  state_file: "+path+"\n")
	if s.Assets() == nil {
		t.Fatal("no inventory")
	}
	if n := s.Assets().Len(); n != 0 {
		t.Fatalf("assets from a broken file: %d", n)
	}
}

// A vendor file is the opposite case: it is configuration, it is named in the
// file, and a list an operator trusted which silently dropped half its entries
// is worse than one that would not load.
func TestAMalformedVendorFileRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("00:1b:1b Siemens AG\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgOf := func(path string) string {
		return "\nasset_inventory:\n  enabled: true\n  vendor_file: " + path + "\n"
	}
	s := inventoryProxy(t, cfgOf(good))
	s.ObserveAsset(assets.Observation{Proto: "dhcp", Listener: "leases",
		Addr: netip.MustParseAddr("10.30.4.9"), Hardware: []byte{0, 0x1b, 0x1b, 1, 2, 3}})
	a, ok := s.Assets().Get("10.30.4.9")
	if !ok || a.Vendor != "Siemens AG" {
		t.Fatalf("vendor: %+v", a)
	}
	for name, body := range map[string]string{
		"bad.txt":     "00:1b:1b Siemens AG\nnot-a-prefix\n",
		"missing.txt": "",
	} {
		path := filepath.Join(dir, name)
		if body != "" {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
` + cfgOf(path)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg, logging.Discard()); err == nil {
			t.Errorf("%s: started anyway", name)
		}
	}
}

// A role nothing can be classified as must always be expected, whatever the
// estate listed. Otherwise every device the evidence does not identify -- which
// on a quiet segment is most of them, at first -- raises a finding, and a
// detection that fires on everything is one an operator turns off.
func TestUnknownIsAlwaysExpectedEvenWhenTheEstateDidNotListIt(t *testing.T) {
	s := inventoryProxy(t, "\nasset_inventory:\n  enabled: true\n  roles: [plc]\n")
	// An address and nothing else: identifiable, and classifiable as nothing.
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.9.9")})
	sum := s.Stats().Assets
	if sum == nil || sum.Unknown != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	if n := s.stats.AssetUnexpected.Load(); n != 0 {
		t.Fatalf("an unclassifiable device raised %d findings against a list it cannot be on", n)
	}
	// The listed role is still not a finding, and an unlisted one still is.
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.20"), Hardware: []byte{0, 0x0f, 0xbb, 1, 2, 3},
		Server: true, Units: []int{1}, Funcs: []int{3}})
	if n := s.stats.AssetUnexpected.Load(); n != 0 {
		t.Fatalf("a listed role raised a finding: %d", n)
	}
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.5"), Hardware: []byte{0xaa, 0xbb, 0xcc, 1, 2, 3},
		Units: []int{1}, Funcs: []int{3, 6, 16}})
	if n := s.stats.AssetUnexpected.Load(); n != 1 {
		t.Fatalf("an unlisted role raised %d findings, want 1", n)
	}
}

// A state file that cannot be written is the failure that makes every other
// alert wrong, because the next restart reports the whole estate as new. It has
// to be counted, or nobody finds out until then.
func TestAStateFileThatCannotBeWrittenIsCounted(t *testing.T) {
	// A path inside a directory that does not exist. The inventory is still
	// kept in memory -- refusing to carry traffic over a record would make the
	// record more important than the traffic -- so the only way anybody learns
	// is the counter and the warning.
	path := filepath.Join(t.TempDir(), "no-such-directory", "assets.json")
	s := inventoryProxy(t, "\nasset_inventory:\n  enabled: true\n  state_file: "+path+"\n")
	if s.Assets() == nil {
		t.Fatal("no inventory")
	}
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.20"), Hardware: []byte{0, 0x0f, 0xbb, 1, 2, 3},
		Server: true, Units: []int{1}, Funcs: []int{3}})
	k := s.assets.Load()
	if k == nil {
		t.Fatal("no keeper")
	}
	k.stop() // writes one last time, and fails
	if n := s.stats.AssetSaveFailures.Load(); n == 0 {
		t.Fatal("a save that could not happen was not counted")
	}
	// And the failure reaches the exposition, because that is where an alert
	// on it lives.
	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "xproxy_asset_save_failures_total 1") {
		t.Error("the save failure is not in the metrics")
	}
}
