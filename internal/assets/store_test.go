package assets

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAnInventorySurvivesARestart, because one that started empty would report
// the whole estate as new on every upgrade -- which is the fastest way to teach
// an operator to ignore it.
func TestAnInventorySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assets.json")
	inv, c := newInv(t, Options{})
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"),
		Hardware: hw("08:00:06:11:22:33"), Server: true, Units: []int{1, 2},
		Hostname: "plc-1", Listener: "plant"})
	c.add(time.Minute)
	inv.Observe(Observation{Proto: "iec104", Addr: netip.MustParseAddr("10.0.0.6"), Server: true})
	if err := inv.Save(path); err != nil {
		t.Fatal(err)
	}
	// The file is not world-readable: an inventory names every device on a
	// network and what each one is.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	// And it is readable by a person, which is most of the value.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"plc-1", "08:00:06:11:22:33", "\"role\": \"plc\"", "Siemens"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the file does not mention %q", want)
		}
	}

	next, _ := newInv(t, Options{})
	n, err := next.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || next.Len() != 2 {
		t.Fatalf("loaded %d, holding %d", n, next.Len())
	}
	a, ok := next.Get("08:00:06:11:22:33")
	if !ok {
		t.Fatal("the asset is not reachable by hardware address after a load")
	}
	if a.Hostname != "plc-1" || a.Class.Role != RolePLC || len(a.Units) != 2 {
		t.Errorf("the restored asset is %+v", a)
	}
	if _, ok := next.Get("10.0.0.5"); !ok {
		t.Error("the asset is not reachable by address after a load")
	}
	// A device that is answering now beats the record of it from before.
	next2, _ := newInv(t, Options{})
	next2.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"),
		Hardware: hw("08:00:06:11:22:33"), Hostname: "plc-1-renamed", Server: true})
	if _, err := next2.Load(path); err != nil {
		t.Fatal(err)
	}
	live, _ := next2.Get("08:00:06:11:22:33")
	if live.Hostname != "plc-1-renamed" {
		t.Errorf("the file overwrote a device that is answering now: %q", live.Hostname)
	}
}

// TestTheBaselineSurvivesARestartToo: one that did not would silently turn the
// detection off on every upgrade, which is worse than never having had one.
func TestTheBaselineSurvivesARestartToo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	inv, c := newInv(t, Options{})
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"), Server: true})
	inv.Freeze()
	if err := inv.Save(path); err != nil {
		t.Fatal(err)
	}
	next, _ := newInv(t, Options{})
	if _, err := next.Load(path); err != nil {
		t.Fatal(err)
	}
	if n, frozen := next.Frozen(); !frozen || n != 1 {
		t.Fatalf("baseline %d frozen=%v", n, frozen)
	}
	c.add(time.Minute)
	if a := next.Observe(Observation{Proto: "modbus",
		Addr: netip.MustParseAddr("10.0.0.5"), Server: true}); a.New {
		t.Error("a device in the restored baseline was reported as new")
	}
	if a := next.Observe(Observation{Proto: "modbus",
		Addr: netip.MustParseAddr("10.0.0.99"), Server: true}); !a.New {
		t.Error("a device outside the restored baseline was not reported as new")
	}
	// A baseline that names a device this process has already seen before the
	// load clears the new flag on it, because the baseline is the estate's own
	// statement about what belongs.
	third, _ := newInv(t, Options{})
	third.Freeze()
	a := third.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"), Server: true})
	if !a.New {
		t.Fatal("an unknown device against an empty baseline is not new")
	}
	if _, err := third.Load(path); err != nil {
		t.Fatal(err)
	}
	if got, _ := third.Get("10.0.0.5"); got.New {
		t.Error("the restored baseline did not clear the new flag")
	}
}

func TestWhatTheStoreRefusesToRead(t *testing.T) {
	inv, _ := newInv(t, Options{})
	for what, body := range map[string]string{
		"nothing":         ``,
		"not JSON":        `{`,
		"a newer format":  `{"version": 99, "assets": []}`,
		"an older format": `{"version": 0, "assets": []}`,
	} {
		if _, err := inv.Read(strings.NewReader(body)); err == nil {
			t.Errorf("%s was read", what)
		}
	}
	// A record with no identifier is skipped rather than failing the load: one
	// unusable line should not cost an operator the whole inventory.
	n, err := inv.Read(strings.NewReader(`{"version":1,"assets":[{"id":""},null,{"id":"10.0.0.5"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || inv.Len() != 1 {
		t.Fatalf("loaded %d, holding %d", n, inv.Len())
	}
	// The bound holds on a load as well as on an observation.
	small, _ := newInv(t, Options{Max: 1})
	if _, err := small.Read(strings.NewReader(
		`{"version":1,"assets":[{"id":"a"},{"id":"b"},{"id":"c"}]}`)); err != nil {
		t.Fatal(err)
	}
	if small.Len() != 1 {
		t.Errorf("%d assets past a bound of 1", small.Len())
	}
}

// TestLoadingNothingIsNotAFailure: no file yet is the ordinary first run.
func TestLoadingNothingIsNotAFailure(t *testing.T) {
	inv, _ := newInv(t, Options{})
	n, err := inv.Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil || n != 0 {
		t.Fatalf("loaded %d: %v", n, err)
	}
	// A path that cannot be read at all is a failure, because an operator who
	// configured one is owed the reason.
	dir := t.TempDir()
	if _, err := inv.Load(dir); err == nil {
		t.Error("a directory loaded as an inventory")
	}
	// Saving nowhere is a no-op rather than an error, so that a listener with no
	// state file configured needs no special case.
	if err := inv.Save(""); err != nil {
		t.Errorf("saving to no path: %v", err)
	}
	if err := inv.Save(filepath.Join(dir, "no", "such", "dir", "a.json")); err == nil {
		t.Error("saving into a directory that does not exist succeeded")
	}
}
