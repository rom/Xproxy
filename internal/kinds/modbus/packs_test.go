package modbus_test

import (
	"os"
	"strings"
	"testing"

	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The shipped behaviour packs, driven through the relay.
//
// A pack is configuration, and configuration that nobody runs is a document
// of intentions. These tests take the file as it ships, point it at a
// fabricated device, and send the traffic the tool the pack is named after
// would have sent -- so "this pack detects FrostyGoop's write" is a claim
// somebody checked rather than a claim somebody made.
//
// Two substitutions are made and no others: the upstream's address becomes
// the test device's, and the network the pack uses for the host whose
// behaviour is under test becomes the loopback. The rules are the file's own.

// pack loads a pack, points it at a device, and returns the listener address.
func pack(t *testing.T, file, listener string, dev *plc, clients ...string) (*proxy.Server, string) {
	t.Helper()
	b, err := os.ReadFile("../../../examples/ot/packs/" + file) //nolint:gosec // a file in this repository
	if err != nil {
		t.Fatalf("read the pack: %v", err)
	}
	doc := string(b)
	for _, net := range clients {
		if !strings.Contains(doc, net) {
			t.Fatalf("%s does not mention %s, so the substitution would test nothing", file, net)
		}
		doc = strings.ReplaceAll(doc, net, "127.0.0.1/32")
	}
	// The listener binds a plant address in the file; a test binds a port
	// the kernel chooses.
	doc = replaceListenAddress(t, doc, file)
	if !strings.Contains(doc, ":502\"") {
		t.Fatalf("%s names no device endpoint to replace", file)
	}
	doc = strings.Replace(doc, deviceOf(t, doc), dev.addr(), 1)
	s := proxytest.Start(t, doc)
	return s, proxytest.Addr(t, s, listener)
}

// replaceListenAddress puts the listener on a loopback port the kernel picks.
func replaceListenAddress(t *testing.T, doc, file string) string {
	t.Helper()
	for _, addr := range []string{"10.40.0.10:502", "10.30.0.10:502"} {
		if strings.Contains(doc, addr) {
			return strings.Replace(doc, addr, "127.0.0.1:0", 1)
		}
	}
	t.Fatalf("%s has no listener address this test knows", file)
	return doc
}

// deviceOf is the pack's upstream endpoint, which the test replaces with the
// fabricated device's address.
func deviceOf(t *testing.T, doc string) string {
	t.Helper()
	for _, addr := range []string{"10.40.9.11:502", "10.30.9.21:502"} {
		if strings.Contains(doc, addr) {
			return addr
		}
	}
	t.Fatal("the pack names no upstream endpoint this test knows")
	return ""
}

// FrostyGoop wrote holding registers on heating controllers with ordinary
// Modbus. There is no signature for that, so the pack is about the shape: a
// host writing where this estate does not write.
func TestTheFrostyGoopPackRefusesTheWrite(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	// The historian's network is the one under test: it reads, and the pack
	// says it never writes.
	s, addr := pack(t, "frostygoop-modbus.yaml", "heating-controllers", dev, "10.40.2.0/24")

	m := dialMaster(t, addr, wire.FramingTCP)

	// What the historian does all day.
	if _, err := m.ask(1, []byte{3, 0x00, 0x64, 0x00, 0x02}); err != nil {
		t.Fatalf("the historian's read was refused: %v", err)
	}

	// And the write FrostyGoop made: a flow temperature register, a
	// plausible value, from the host that only ever read.
	p, err := m.ask(1, []byte{16, 0x01, 0x90, 0x00, 0x01, 2, 0x00, 0x28})
	if err != nil {
		t.Fatalf("the write: %v", err)
	}
	if !p.IsException || p.Exception != wire.ExIllegalFunction {
		t.Fatalf("the write was answered %+v, want an illegal-function exception", p)
	}
	awaitModbus(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["modbus"]["rule_deny"] >= 1
	}, "the pack's deny rule refused the write")
	if _, ok := dev.saw(16); ok {
		t.Error("the write reached the heating controller")
	}
}

// PIPEDREAM's Schneider module speaks UMAS inside function code 90, which is
// where a Modicon is stopped and where its program is rewritten.
func TestThePipedreamPackRefusesTheUMASStopAndTheProgramTransfer(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	// The engineering network is the one under test: the pack allows it the
	// UMAS reads and nothing that changes the controller.
	s, addr := pack(t, "pipedream-modbus.yaml", "modicon-cell", dev, "10.30.1.0/24")

	m := dialMaster(t, addr, wire.FramingTCP)
	for _, c := range []struct {
		what string
		pdu  []byte
	}{
		{"stop_plc", []byte{0x5A, 0x21, 0x41}},
		{"start_plc", []byte{0x5A, 0x21, 0x40}},
		{"upload_block", []byte{0x5A, 0x21, 0x31}},
		{"download_block", []byte{0x5A, 0x21, 0x34}},
		{"write_io_object", []byte{0x5A, 0x21, 0x71}},
		// A command the table has no name for: published research is not a
		// specification, so the pack denies the unreadable ones too.
		{"an unnamed UMAS command", []byte{0x5A, 0x21, 0x90}},
	} {
		p, err := m.ask(1, c.pdu)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if !p.IsException || p.Exception != wire.ExIllegalFunction {
			t.Fatalf("%s was answered %+v, want an illegal-function exception", c.what, p)
		}
	}
	awaitModbus(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["modbus"]["rule_deny"] >= 6
	}, "the pack refused every UMAS command that changes the controller")
	if _, ok := dev.saw(0x5A); ok {
		t.Error("a UMAS frame reached the Modicon")
	}
}
