package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
)

const inventoryYAML = `
version: 1
asset_inventory:
  enabled: true
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`

// inventoryHarness is a daemon with an inventory, and the devices in it.
func inventoryHarness(t *testing.T) (sock, cfgPath string, p *proxy.Server) {
	t.Helper()
	cfg, err := config.Parse([]byte(inventoryYAML))
	if err != nil {
		t.Fatal(err)
	}
	if p, err = proxy.New(cfg, logging.Discard()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sock = filepath.Join(dir, "m.sock")
	cfgPath = filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(inventoryYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	p.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.20"), Hardware: []byte{0x00, 0x0f, 0xbb, 1, 2, 3},
		Server: true, Units: []int{1}, Funcs: []int{3}})
	p.ObserveAsset(assets.Observation{Proto: "dhcp", Listener: "leases",
		Addr: netip.MustParseAddr("10.30.4.9"), Hardware: []byte{0x00, 0x11, 0x85, 1, 2, 3},
		Hostname: "press-2", VendorClass: "HP LaserJet"})
	return sock, cfgPath, p
}

func TestTheAssetsViewShowsTheEstateAndOneDevice(t *testing.T) {
	sock, cfgPath, _ := inventoryHarness(t)
	for _, tc := range []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"assets"}, 0, []string{"2 devices", "no baseline", "00:0f:bb:01:02:03", "press-2", "modbus/1"}},
		{[]string{"assets", "-proto", "dhcp"}, 0, []string{"press-2"}},
		{[]string{"assets", "-listener", "line1"}, 0, []string{"00:0f:bb:01:02:03"}},
		// The evidence for the guess is the point of the long form: an
		// inventory an engineer cannot argue with is one whose wrong
		// entries survive for years.
		{[]string{"assets", "-long"}, 0, []string{"because", "confidence", "answered 1"}},
		{[]string{"assets", "show", "10.30.4.9"}, 0, []string{"press-2", "HP LaserJet"}},
		{[]string{"-json", "assets"}, 0, []string{`"summary"`, `"known_roles"`}},
		// A role that is not a role, and a device nothing has seen: both
		// are errors rather than an empty list, because an empty list
		// reads as "the estate is clean".
		{[]string{"assets", "-role", "plk"}, 1, []string{"not a known role"}},
		{[]string{"assets", "show", "10.99.99.99"}, 1, []string{"no asset"}},
		{[]string{"assets", "bogus"}, 2, []string{"usage: xproxyctl assets"}},
	} {
		code, out, errOut := runCmd(t, sock, cfgPath, tc.args...)
		if code != tc.code {
			t.Errorf("%v: code %d, want %d (%s)", tc.args, code, tc.code, errOut)
			continue
		}
		got := out
		if tc.code != 0 {
			got = errOut
		}
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%v: %q missing from:\n%s", tc.args, want, got)
			}
		}
	}
}

func TestFreezingAndForgettingTheBaselineFromTheCommandLine(t *testing.T) {
	sock, cfgPath, p := inventoryHarness(t)
	code, out, errOut := runCmd(t, sock, cfgPath, "assets", "baseline")
	if code != 0 || !strings.Contains(out, "baseline frozen: 2 devices") {
		t.Fatalf("freeze: %d %q %q", code, out, errOut)
	}
	p.ObserveAsset(assets.Observation{Proto: "tftp", Listener: "boot",
		Addr: netip.MustParseAddr("10.30.0.77"), BootFile: "ap-firmware.bin"})
	if code, out, errOut = runCmd(t, sock, cfgPath, "assets", "-new"); code != 0 ||
		!strings.Contains(out, "10.30.0.77") {
		t.Fatalf("new: %d %q %q", code, out, errOut)
	}
	if !strings.Contains(out, "baseline 2, new 1") {
		t.Fatalf("summary: %q", out)
	}
	if code, out, errOut = runCmd(t, sock, cfgPath, "assets", "baseline", "-forget"); code != 0 ||
		!strings.Contains(out, "baseline forgotten") {
		t.Fatalf("forget: %d %q %q", code, out, errOut)
	}
	if code, out, _ = runCmd(t, sock, cfgPath, "assets", "-new"); code != 0 ||
		!strings.Contains(out, "no device matched") {
		t.Fatalf("after forget: %d %q", code, out)
	}
}

// A device chooses its own host name, and a terminal interprets what is
// written to it. A proxy that let a device retitle an operator's window would
// be a strange place to keep a security inventory.
func TestADeviceCannotWriteEscapeSequencesIntoTheView(t *testing.T) {
	sock, cfgPath, p := inventoryHarness(t)
	p.ObserveAsset(assets.Observation{Proto: "dhcp", Listener: "leases",
		Addr:     netip.MustParseAddr("10.30.4.66"),
		Hardware: []byte{0x66, 0x66, 0x66, 1, 2, 3},
		Hostname: "\x1b]0;owned\x07\x1b[2J", VendorClass: "a\x07b"})
	for _, args := range [][]string{{"assets"}, {"assets", "-long"}, {"assets", "show", "10.30.4.66"}} {
		_, out, errOut := runCmd(t, sock, cfgPath, args...)
		// The device has to be in the output, or the test proves only that
		// a view showing nothing shows no escape sequences.
		if !strings.Contains(out, "10.30.4.66") {
			t.Fatalf("%v: the device is not in the view: %q %q", args, out, errOut)
		}
		if strings.ContainsAny(out, "\x1b\x07") {
			t.Errorf("%v: control bytes reached the terminal: %q", args, out)
		}
	}
}

// The advisory view from the command line.
//
// The summary is checked as well as the rows, because the useful output of a
// first run is the *shape* of the exposure: how many devices an advisory names,
// and how many nobody can assess yet. A table of the affected ones alone is a
// number nobody can act on without the size of the gap beside it.
func TestTheAdvisoryViewFromTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssa.json"), []byte(ctlAdvisory), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := strings.Replace(inventoryYAML, "  enabled: true\n",
		"  enabled: true\n  advisories:\n    enabled: true\n    sources:\n"+
			"      - name: productcert\n        directory: "+dir+"\n", 1)
	sock, cfgPath, p := advisoryHarness(t, yaml)

	// A controller below the bound, and one whose firmware nobody can compare.
	p.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.31"), Hardware: []byte{0x00, 0x1b, 0x1b, 1, 1, 1},
		Server: true, Units: []int{1}, Funcs: []int{3},
		Maker: "Siemens", Model: "SIMATIC S7-1200 CPU 1212C", Firmware: "V4.2.1"})
	p.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.10.32"), Hardware: []byte{0x00, 0x1b, 0x1b, 2, 2, 2},
		Server: true, Units: []int{1}, Funcs: []int{3},
		Maker: "Siemens", Model: "SIMATIC S7-1200 CPU 1214C", Firmware: "Rel. 04.03"})

	for _, tc := range []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"assets", "advisories"}, 0, []string{
			"1 advisories", "affected 1", "not_assessed 1",
			"productcert:", "SSA-CTL", "V4.5", "critical 9.1"}},
		{[]string{"assets", "advisories", "-state", "not_assessed"}, 0, []string{
			"not_assessed", "Rel. 04.03"}},
		{[]string{"assets", "advisories", "-long"}, 0, []string{
			"compared", "versions", "remedy", "Update to V4.5"}},
		{[]string{"assets", "advisories", "-documents"}, 0, []string{
			"SSA-CTL", "Siemens ProductCERT", "2024-02-13"}},
		{[]string{"-json", "assets", "advisories"}, 0, []string{`"state"`, `"advisories"`}},
		// A state that is not a state, because an empty answer to a typo
		// reads as "the estate is clean".
		{[]string{"assets", "advisories", "-state", "probably-fine"}, 1, []string{"state:"}},
	} {
		code, out, errOut := runCmd(t, sock, cfgPath, tc.args...)
		if code != tc.code {
			t.Errorf("%v: code %d, want %d (%s)", tc.args, code, tc.code, errOut)
			continue
		}
		got := out
		if tc.code != 0 {
			got = errOut
		}
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%v: %q missing from:\n%s", tc.args, want, got)
			}
		}
	}
}

// Without the section, the command says so rather than printing an empty table
// that reads as an estate with nothing against it.
func TestTheAdvisoryViewWithoutAdvisoriesConfigured(t *testing.T) {
	sock, cfgPath, _ := inventoryHarness(t)
	code, _, errOut := runCmd(t, sock, cfgPath, "assets", "advisories")
	if code == 0 {
		t.Fatal("the advisory view answered with no advisories configured")
	}
	if !strings.Contains(errOut, "advisory matching is not configured") {
		t.Errorf("error %q", errOut)
	}
}

// advisoryHarness is inventoryHarness with a configuration of its own.
func advisoryHarness(t *testing.T, yaml string) (sock, cfgPath string, p *proxy.Server) {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if p, err = proxy.New(cfg, logging.Discard()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sock = filepath.Join(dir, "m.sock")
	cfgPath = filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return sock, cfgPath, p
}

const ctlAdvisory = `{
  "document": {"category": "csaf_security_advisory", "csaf_version": "2.0",
    "title": "Denial of service in SIMATIC S7-1200 CPUs",
    "publisher": {"category": "vendor", "name": "Siemens ProductCERT"},
    "tracking": {"id": "SSA-CTL", "status": "final", "version": "1",
      "current_release_date": "2024-02-13T00:00:00Z"}},
  "product_tree": {"branches": [{"category": "vendor", "name": "Siemens", "branches": [
    {"category": "product_name", "name": "SIMATIC S7-1200 CPU family", "branches": [
      {"category": "product_version_range", "name": "vers:all/<V4.5",
       "product": {"product_id": "P1", "name": "SIMATIC S7-1200 < V4.5"}},
      {"category": "product_version", "name": "V4.5",
       "product": {"product_id": "P2", "name": "SIMATIC S7-1200 V4.5"}}]}]}]},
  "vulnerabilities": [{"cve": "CVE-2024-33333",
    "product_status": {"known_affected": ["P1"], "fixed": ["P2"]},
    "scores": [{"products": ["P1"], "cvss_v3": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}],
    "remediations": [{"category": "vendor_fix", "details": "Update to V4.5 or later",
      "product_ids": ["P1"]}]}]
}`
