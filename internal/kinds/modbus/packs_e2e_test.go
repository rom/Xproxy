package modbus_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/packs"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A behaviour pack end to end through a real relay: the pack is a signed file in
// a directory, the daemon loads it at start, a master's traffic trips it, and the
// master is then held out of the plant until the pack's window is over.
//
// It is here rather than in internal/packs because what is worth proving is the
// wiring: that the events a *kind* produces are the events a pack sees, that the
// attributes it reads (the client address and the protocol) are the ones the
// kinds actually write, and that the quarantine reaches the admission path.

// The pack. Two signals, a short window, and `enforcement: deny` so the
// quarantine half is exercised as well as the alert half.
const e2ePack = `pack: 1
id: test-read-only-storm
revision: 1
name: Writes on a read-only listener, repeatedly
summary: >-
  A master refused several times for writing on a read-only listener. One is a
  misconfigured client; five inside a minute is something trying the address
  space.
technique: T0835
kinds: [modbus]
severity: high
enforcement: deny
references: ["the test that proves a pack reaches the admission path"]
detect:
  window: 2m
  signals:
    - name: writes-on-a-read-only-listener
      reasons: [read_only]
      count: 3
`

// packDir writes the pack and its signature, and returns the directory and the
// public key in the form a configuration carries.
func packDir(t *testing.T, body string) (dir, pubKey string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"+packs.SigExt),
		[]byte(packs.Sign("plant", priv, []byte(body))), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, base64.StdEncoding.EncodeToString(pub)
}

const packYAML = `
version: 1
packs:
  directory: %q
  enforce: %v
  keys:
    - {name: plant, key: %q}
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        upstream: plc
        read_only: true
        default_action: allow
logging: {access: {enabled: false}}
upstreams:
  - {name: plc, endpoints: [{address: %q}]}
`

// localhost is the address the relay sees for a loopback master, which is what a
// pack keys on.
func localhost(t *testing.T) netip.Addr {
	t.Helper()
	return netip.MustParseAddr("127.0.0.1")
}

func TestAPackReachesTheAdmissionPath(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dir, key := packDir(t, e2ePack)
	s := proxytest.Start(t, fmt.Sprintf(packYAML, dir, true, key, dev.addr()))
	addr := proxytest.Addr(t, s, "plant")

	// The pack loaded, and the daemon says which and in what mode.
	rep := s.PackReport()
	if rep.Status.Packs != 1 || !rep.Status.Enforcing {
		t.Fatalf("pack status %+v", rep.Status)
	}
	if got := rep.Packs[0]; got.ID != "test-read-only-storm" || got.Signer != "plant" {
		t.Fatalf("pack %+v", got)
	}

	// Three refused writes on a read-only listener. Each is a security event
	// with reason modbus_read_only, which is the pack's signal.
	m := dialMaster(t, addr, wire.FramingTCP)
	for i := 0; i < 3; i++ {
		p, err := m.ask(1, setPoint)
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if p.Exception == 0 {
			t.Fatalf("write %d was carried on a read-only listener", i)
		}
	}
	if got := dev.regs[400]; got != 0 {
		t.Fatalf("a write reached the device on a read-only listener: %d", got)
	}
	awaitModbus(t, s, func(sn proxy.Snapshot) bool {
		return sn.PackMatches["test-read-only-storm/high"] >= 1
	}, "the pack to report")

	// And now the master is held out: a fresh connection is refused at
	// admission, on this listener and on every other one of this daemon,
	// with the pack named.
	if _, held := s.Packs().Quarantined(localhost(t)); !held {
		t.Fatal("the pack reported and did not hold the actor out")
	}
	// The relay accepts and then closes, so the refusal shows up on the first
	// request rather than on the dial.
	m2 := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m2.ask(1, readTwo); err == nil {
		t.Fatal("a quarantined master was served")
	}
	if sn := s.Stats(); sn.Refusals["modbus"]["pack_quarantine"] == 0 {
		t.Errorf("the quarantine was not counted under its own reason: %v", sn.Refusals["modbus"])
	}

	// An operator lifts it, and the master is served again.
	if !s.ReleasePack(localhost(t)) {
		t.Fatal("nothing to release")
	}
	m3 := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m3.ask(1, readTwo); err != nil {
		t.Fatalf("a released master is still refused: %v", err)
	}
}

// With enforce off, the same traffic reports and nothing is held: the pack's own
// declaration is necessary and not sufficient.
func TestAPackWithoutEnforcementOnlyReports(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dir, key := packDir(t, e2ePack)
	s := proxytest.Start(t, fmt.Sprintf(packYAML, dir, false, key, dev.addr()))
	addr := proxytest.Addr(t, s, "plant")

	m := dialMaster(t, addr, wire.FramingTCP)
	for i := 0; i < 3; i++ {
		_, _ = m.ask(1, setPoint)
	}
	awaitModbus(t, s, func(sn proxy.Snapshot) bool {
		return sn.PackMatches["test-read-only-storm/high"] >= 1
	}, "the pack to report")
	if _, held := s.Packs().Quarantined(localhost(t)); held {
		t.Error("a pack quarantined an actor with packs.enforce off")
	}
	if sn := s.Stats(); sn.Refusals["modbus"]["pack_quarantine"] != 0 {
		t.Error("something was refused as a quarantine with enforcement off")
	}
	// And the master is still served.
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("a reported master was cut off: %v", err)
	}
}

// A pack directory whose signature does not verify stops the daemon, rather than
// starting it with a detection missing.
func TestAnUnverifiablePackStopsTheDaemon(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dir, key := packDir(t, e2ePack)
	// Edit the pack after it was signed.
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"),
		[]byte(strings.Replace(e2ePack, "count: 3", "count: 1", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	err := proxytest.StartError(t, fmt.Sprintf(packYAML, dir, true, key, dev.addr()))
	if err == nil {
		t.Fatal("a daemon started on a pack whose signature does not verify")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("the error does not say the file changed: %v", err)
	}
}
