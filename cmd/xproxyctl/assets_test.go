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
