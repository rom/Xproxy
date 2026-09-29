package mgmt

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/csaf"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// inventoryServer is a management server whose proxy keeps an inventory, with
// a handful of devices in it.
func inventoryServer(t *testing.T, section string) (*Client, *proxy.Server) {
	t.Helper()
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
` + section))
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
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return NewClient(sock), p
}

const inventoryOn = `
asset_inventory:
  enabled: true
`

// A controller, a workstation and a printer, each recognisable by what it does
// rather than by what it says.
func seedAssets(p *proxy.Server) {
	p.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.20"), Hardware: []byte{0x00, 0x0f, 0xbb, 1, 2, 3},
		Server: true, Units: []int{1}, Funcs: []int{3}})
	p.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.5"), Hardware: []byte{0xaa, 0xbb, 0xcc, 1, 2, 3},
		Units: []int{1}, Funcs: []int{3, 6, 16}})
	p.ObserveAsset(assets.Observation{Proto: "dhcp", Listener: "leases",
		Addr: netip.MustParseAddr("10.30.4.9"), Hardware: []byte{0x00, 0x11, 0x85, 1, 2, 3},
		Hostname: "press-2", VendorClass: "HP LaserJet"})
}

func TestTheInventoryIsReadThroughTheControlPlane(t *testing.T) {
	c, p := inventoryServer(t, inventoryOn)
	seedAssets(p)
	rep, err := c.Assets(AssetQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary == nil || rep.Summary.Assets != 3 {
		t.Fatalf("summary: %+v", rep.Summary)
	}
	if len(rep.Assets) != 3 || rep.Matched != 3 {
		t.Fatalf("assets: %d matched %d", len(rep.Assets), rep.Matched)
	}
	// known_roles is what a filter may name, and a caller that has to guess
	// the spelling of a role is one that will guess wrong.
	if len(rep.Roles) == 0 || rep.Roles[0] != "unknown" {
		t.Fatalf("roles: %v", rep.Roles)
	}
}

func TestWithoutAnInventoryEveryAssetCallIsRefused(t *testing.T) {
	c, _ := inventoryServer(t, "")
	if _, err := c.Assets(AssetQuery{}); err == nil {
		t.Fatal("list answered without an inventory")
	}
	if _, err := c.FreezeAssets(); err == nil {
		t.Fatal("freeze answered without an inventory")
	}
	if _, err := c.ThawAssets(); err == nil {
		t.Fatal("thaw answered without an inventory")
	}
}

func TestADeviceIsLookedUpByWhateverALogLineCarried(t *testing.T) {
	c, p := inventoryServer(t, inventoryOn)
	seedAssets(p)
	for _, key := range []string{"00:0f:bb:01:02:03", "10.30.10.20"} {
		a, err := c.Asset(key)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if a.Hardware != "00:0f:bb:01:02:03" {
			t.Fatalf("%s: found %q", key, a.Hardware)
		}
	}
	if _, err := c.Asset("10.99.99.99"); err == nil {
		t.Fatal("an address nothing was seen at answered")
	}
}

func TestTheFiltersNarrowAndATypoIsRefused(t *testing.T) {
	c, p := inventoryServer(t, inventoryOn)
	seedAssets(p)
	// A role that is not a role must not read as "no devices": that answer
	// is indistinguishable from a clean estate, which is the wrong reply to
	// a misspelling.
	if _, err := c.Assets(AssetQuery{Role: "plk"}); err == nil {
		t.Fatal("an unknown role was accepted as a filter")
	}
	// By role, which is the filter a segmentation review uses: show me
	// everything on this wire that is classified as a controller.
	rep, err := c.Assets(AssetQuery{Role: "plc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Assets) != 1 || rep.Assets[0].Hardware != "00:0f:bb:01:02:03" {
		t.Fatalf("by role: %+v", rep.Assets)
	}
	// A role nothing is classified as answers an empty list rather than an
	// error: the role is real, so the question is well formed and the answer
	// is that there are none.
	if rep, err = c.Assets(AssetQuery{Role: "voip_phone"}); err != nil || len(rep.Assets) != 0 {
		t.Fatalf("by an absent role: %d %v", len(rep.Assets), err)
	}
	// And the spelling is not case-sensitive, because a role in a log line is
	// not necessarily the spelling somebody types.
	if rep, err = c.Assets(AssetQuery{Role: "PLC"}); err != nil || len(rep.Assets) != 1 {
		t.Fatalf("by an upper-case role: %d %v", len(rep.Assets), err)
	}
	rep, err = c.Assets(AssetQuery{Proto: "dhcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Assets) != 1 || rep.Assets[0].Hostname != "press-2" {
		t.Fatalf("by protocol: %+v", rep.Assets)
	}
	if rep, err = c.Assets(AssetQuery{Listener: "line1"}); err != nil || len(rep.Assets) != 2 {
		t.Fatalf("by listener: %d %v", len(rep.Assets), err)
	}
	if rep, err = c.Assets(AssetQuery{Proto: "modbus", Top: 1}); err != nil {
		t.Fatal(err)
	}
	// The cut is reported, because an operator reading the top 1 of 2 needs
	// to know there was a second.
	if len(rep.Assets) != 1 || rep.Matched != 2 {
		t.Fatalf("top: %d of %d", len(rep.Assets), rep.Matched)
	}
	if _, err := c.Assets(AssetQuery{Top: -1}); err == nil {
		t.Fatal("a negative count was accepted")
	}
}

func TestFreezingTheBaselineMakesTheNextDeviceNew(t *testing.T) {
	c, p := inventoryServer(t, inventoryOn)
	seedAssets(p)
	res, err := c.FreezeAssets()
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res["baseline_size"].(float64); n != 3 {
		t.Fatalf("freeze: %+v", res)
	}
	// Nothing is new yet: everything here was here when the baseline was
	// taken.
	rep, err := c.Assets(AssetQuery{New: true})
	if err != nil || len(rep.Assets) != 0 {
		t.Fatalf("new before: %d %v", len(rep.Assets), err)
	}
	p.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.99"), Hardware: []byte{0xde, 0xad, 0xbe, 1, 2, 3},
		Server: true, Units: []int{7}, Funcs: []int{3}})
	if rep, err = c.Assets(AssetQuery{New: true}); err != nil || len(rep.Assets) != 1 {
		t.Fatalf("new after: %d %v", len(rep.Assets), err)
	}
	if rep.Assets[0].Hardware != "de:ad:be:01:02:03" {
		t.Fatalf("new: %+v", rep.Assets[0])
	}
	if !rep.Summary.Frozen || rep.Summary.Baseline != 3 || rep.Summary.New != 1 {
		t.Fatalf("summary: %+v", rep.Summary)
	}
	// And forgetting it puts the estate back to having no opinion.
	if _, err := c.ThawAssets(); err != nil {
		t.Fatal(err)
	}
	if rep, err = c.Assets(AssetQuery{New: true}); err != nil || len(rep.Assets) != 0 {
		t.Fatalf("new after thaw: %d %v", len(rep.Assets), err)
	}
	if rep.Summary.Frozen {
		t.Fatalf("still frozen: %+v", rep.Summary)
	}
}

func TestAnAddressTakenOverIsFoundByTheChangedFilter(t *testing.T) {
	c, p := inventoryServer(t, inventoryOn)
	seedAssets(p)
	if rep, err := c.Assets(AssetQuery{Changed: true}); err != nil || len(rep.Assets) != 0 {
		t.Fatalf("changed before: %d %v", len(rep.Assets), err)
	}
	// A hardware address nobody has seen, at an address another record
	// already holds. Two devices, one address, over time.
	p.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.20"), Hardware: []byte{0x11, 0x22, 0x33, 4, 5, 6},
		Server: true, Units: []int{1}, Funcs: []int{3}})
	rep, err := c.Assets(AssetQuery{Changed: true})
	if err != nil {
		t.Fatal(err)
	}
	// The finding is on the record that lost the address, because the new
	// device gets a record of its own and the old one would otherwise just
	// stop appearing.
	if len(rep.Assets) != 1 || rep.Assets[0].Hardware != "00:0f:bb:01:02:03" {
		t.Fatalf("changed: %+v", rep.Assets)
	}
	if rep.Assets[0].Changes[0].What != assets.ChangeAddrTaken {
		t.Fatalf("change: %+v", rep.Assets[0].Changes)
	}
}

// The advisory view over the control plane.
//
// The state filter is the query an operator actually runs -- "give me the ones
// nobody has assessed" is a different job from "give me the ones that are
// affected" -- so a state that is not a state is refused rather than answering
// with an empty list, which would read as "the estate is clean".
func TestTheAdvisoryViewOverTheSocket(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssa.json"), []byte(mgmtAdvisory), 0o600); err != nil {
		t.Fatal(err)
	}
	c, p := inventoryServer(t, inventoryOn+
		"  advisories:\n    enabled: true\n    sources:\n      - name: test\n        directory: "+dir+"\n")
	p.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.21"), Hardware: []byte{0x00, 0x1b, 0x1b, 1, 2, 3},
		Server: true, Units: []int{1}, Funcs: []int{3},
		Maker: "Siemens", Model: "SIMATIC S7-1200 CPU 1212C", Firmware: "V4.2.1"})

	rep, err := c.Advisories("", true)
	if err != nil {
		t.Fatalf("advisories: %v", err)
	}
	if rep.Counts.Documents != 1 {
		t.Errorf("%d documents", rep.Counts.Documents)
	}
	if len(rep.Advisories) != 1 || rep.Advisories[0].ID != "SSA-MGMT" {
		t.Errorf("the documents themselves were not returned: %+v", rep.Advisories)
	}
	var affected int
	for _, one := range rep.Assessments {
		if one.State == csaf.StateAffected {
			affected++
		}
	}
	if affected != 1 {
		t.Errorf("%d devices affected, want the controller below the bound", affected)
	}

	// One state at a time.
	got, err := c.Advisories(csaf.StateAffected, false)
	if err != nil {
		t.Fatalf("filtered: %v", err)
	}
	if len(got.Assessments) != 1 {
		t.Errorf("%d affected devices with the filter", len(got.Assessments))
	}
	if len(got.Advisories) != 0 {
		t.Error("the documents were returned without being asked for")
	}
	// And a state that is not a state.
	if _, err := c.Advisories("probably-fine", false); err == nil {
		t.Error("a state nobody defined was accepted, so a typo would read as a clean estate")
	}
}

// Without the section the endpoint says so rather than answering for an estate
// nobody asked about.
func TestTheAdvisoryViewWithoutAdvisories(t *testing.T) {
	c, _ := inventoryServer(t, inventoryOn)
	if _, err := c.Advisories("", false); err == nil {
		t.Error("an advisory view with no advisories configured")
	}
}

const mgmtAdvisory = `{
  "document": {"category": "csaf_security_advisory", "csaf_version": "2.0",
    "title": "A test advisory", "publisher": {"category": "vendor", "name": "Siemens ProductCERT"},
    "tracking": {"id": "SSA-MGMT", "status": "final", "version": "1",
      "current_release_date": "2024-02-13T00:00:00Z"}},
  "product_tree": {"branches": [{"category": "vendor", "name": "Siemens", "branches": [
    {"category": "product_name", "name": "SIMATIC S7-1200 CPU family", "branches": [
      {"category": "product_version_range", "name": "vers:all/<V4.5",
       "product": {"product_id": "P1", "name": "SIMATIC S7-1200 < V4.5"}}]}]}]},
  "vulnerabilities": [{"cve": "CVE-2024-22222",
    "product_status": {"known_affected": ["P1"]},
    "scores": [{"products": ["P1"], "cvss_v3": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]}]
}`
