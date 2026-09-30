package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
)

// The packs view and the signing tooling from the command line.
//
// The signing half never opens the management socket, and the test says so by
// running it with no daemon at all: signing a pack directory happens on a
// release host or a configuration-management run, not on the machine serving a
// plant.

const ctlPack = `pack: 1
id: test-ctl-pack
revision: 3
name: A walk then a write
summary: An address that enumerated the register space and then wrote to it.
technique: T0861
kinds: [modbus]
severity: high
enforcement: alert
references: ["the test for the packs view"]
detect:
  window: 10m
  signals:
    - name: the-walk
      reasons: [unit_not_allowed]
      count: 2
    - name: the-write
      reasons: [read_only]
`

// packsHarness signs a pack directory the way an estate would, then starts a
// daemon that loads it.
func packsHarness(t *testing.T) (sock, cfgPath string) {
	t.Helper()
	dir := t.TempDir()
	packDir := filepath.Join(dir, "packs")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "p.yaml"), []byte(ctlPack), 0o600); err != nil {
		t.Fatal(err)
	}
	// keygen and sign, through the command, with no socket in sight.
	prefix := filepath.Join(dir, "plant")
	if code, out, errOut := runCmd(t, "", "", "packs", "keygen", "-name", "plant", "-out", prefix); code != 0 {
		t.Fatalf("keygen: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := runCmd(t, "", "", "packs", "sign",
		"-key", prefix+".key", "-name", "plant", packDir); code != 0 {
		t.Fatalf("sign: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := runCmd(t, "", "", "packs", "verify",
		"-key", prefix+".pub", "-name", "plant", packDir); code != 0 ||
		!strings.Contains(out, "1 packs verify under plant") {
		t.Fatalf("verify: %d %q %q", code, out, errOut)
	}

	yaml := "version: 1\npacks:\n  directory: " + packDir +
		"\n  keys:\n    - {name: plant, file: " + prefix + ".pub}\n" +
		"server:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\n" +
		"upstreams:\n  - {name: u, endpoints: [{address: \"127.0.0.1:1\"}]}\n" +
		"routes:\n  - {name: r, upstream: u}\n"
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
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
	return sock, cfgPath
}

func TestThePacksViewShowsWhatIsInForceAndWhoSignedIt(t *testing.T) {
	sock, cfgPath := packsHarness(t)
	for _, tc := range []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"packs"}, 0, []string{"1 packs, alert only", "test-ctl-pack", "T0861", "high", "plant"}},
		// The severity filter narrows the table and leaves the header alone:
		// "one pack is loaded and none of them is critical" is the true
		// answer, and hiding the count would make it read as "no packs".
		{[]string{"packs", "show", "test-ctl-pack"}, 0, []string{
			"revision 3", "T0861 (ics, collection)", "the-walk then the-write",
			"signed by plant", "enumerated the register space"}},
		{[]string{"-json", "packs"}, 0, []string{`"status"`, `"signer": "plant"`}},
		// A severity that is not one, and a pack nobody loaded.
		{[]string{"packs", "-severity", "urgent"}, 2, []string{"info, low, medium, high or critical"}},
		{[]string{"packs", "show", "nothing"}, 1, []string{"no pack"}},
		// Nothing is held, so there is nothing to release, and saying so is
		// better than reporting success.
		{[]string{"packs", "release", "10.40.9.9"}, 1, []string{"no pack is holding"}},
		{[]string{"packs", "release"}, 2, []string{"usage: xproxyctl packs"}},
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
	code, out, errOut := runCmd(t, sock, cfgPath, "packs", "-severity", "critical")
	if code != 0 {
		t.Fatalf("-severity critical: %d %q", code, errOut)
	}
	if !strings.Contains(out, "1 packs, alert only") {
		t.Errorf("the header stopped saying how many packs are loaded:\n%s", out)
	}
	if strings.Contains(out, "test-ctl-pack") {
		t.Errorf("a high pack survived -severity critical:\n%s", out)
	}
}

// The command's verify refuses what the loader refuses, on a file with no
// daemon anywhere near it -- which is the case an operator handed a directory
// actually has.
func TestVerifyRefusesAnEditedPack(t *testing.T) {
	dir := t.TempDir()
	packDir := filepath.Join(dir, "packs")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(packDir, "p.yaml")
	if err := os.WriteFile(path, []byte(ctlPack), 0o600); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(dir, "plant")
	if code, _, e := runCmd(t, "", "", "packs", "keygen", "-name", "plant", "-out", prefix); code != 0 {
		t.Fatal(e)
	}
	if code, _, e := runCmd(t, "", "", "packs", "sign",
		"-key", prefix+".key", "-name", "plant", packDir); code != 0 {
		t.Fatal(e)
	}
	if err := os.WriteFile(path,
		[]byte(strings.Replace(ctlPack, "count: 2", "count: 1", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCmd(t, "", "", "packs", "verify",
		"-key", prefix+".pub", "-name", "plant", packDir)
	if code == 0 {
		t.Fatalf("an edited pack verified: %q", out)
	}
	if !strings.Contains(errOut, "does not verify") {
		t.Errorf("the error does not say the file changed: %q", errOut)
	}
	// And the signature file alone is not enough: the key has to be one the
	// caller names, so a directory signed by somebody else fails too.
	other := filepath.Join(dir, "other")
	if code, _, e := runCmd(t, "", "", "packs", "keygen", "-name", "other", "-out", other); code != 0 {
		t.Fatal(e)
	}
	if code, _, _ = runCmd(t, "", "", "packs", "verify",
		"-key", other+".pub", "-name", "other", packDir); code == 0 {
		t.Error("a directory signed by another key verified")
	}
}
