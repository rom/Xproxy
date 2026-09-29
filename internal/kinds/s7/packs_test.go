package s7

import (
	"os"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/s7"
)

// The shipped behaviour pack for a Stuxnet-shaped attack, driven through the
// relay.
//
// A pack is configuration, and configuration nobody runs is a document of
// intentions. This takes the file as it ships, points it at a fabricated CPU,
// and sends the operations the published analysis describes: read the program
// out, write one in, and write the data block that holds the parameters.
//
// Two substitutions are made and no others: the listener binds a loopback port
// the kernel picks instead of the plant address in the file, and the HMI
// network becomes the loopback so that a test can be the HMI. The rules are
// the file's own.
func stuxnetPack(t *testing.T, cpuAddr string) (*proxy.Server, string) {
	t.Helper()
	b, err := os.ReadFile("../../../examples/ot/packs/stuxnet-s7.yaml") //nolint:gosec // a file in this repository
	if err != nil {
		t.Fatalf("read the pack: %v", err)
	}
	doc := string(b)
	for _, sub := range [][2]string{
		{"10.20.0.10:102", "127.0.0.1:0"},
		{"10.20.1.0/24", "127.0.0.1/32"},
		{"10.20.9.41:102", cpuAddr},
	} {
		if !strings.Contains(doc, sub[0]) {
			t.Fatalf("the pack does not mention %s, so the substitution would test nothing", sub[0])
		}
		// Every occurrence: the file's own header comment names these
		// addresses, and replacing only the first would leave the rule that
		// matters pointing at a network no test can come from.
		doc = strings.ReplaceAll(doc, sub[0], sub[1])
	}
	s := proxytest.Start(t, doc)
	return s, proxytest.Addr(t, s, "line-controller")
}

func TestTheStuxnetPackRefusesTheProgramTransfer(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := stuxnetPack(t, p.addr())

	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	// What an HMI does, which the pack allows: a read of a data block it owns.
	cl.allowed(readJob(1, item(wire.TransportByte, 2, 100, wire.AreaDB, 0)))

	// And the transfer, in the order the analysis describes it: the program
	// out, then the program in. Both are refused, and the CPU sees neither.
	for _, c := range []struct {
		what  string
		frame []byte
	}{
		{"reading the cyclic block out", uploadJob(2, "OB", 1)},
		{"writing a block in", downloadJob(3, "OB", 1)},
		{"writing a function block in", downloadJob(4, "FC", 1)},
		{"stopping the CPU", stopJob(5)},
	} {
		if got := cl.refused(c.frame); got == nil {
			t.Fatalf("%s: no answer", c.what)
		}
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		// operation_denied is the deny list, which is what no rule widens:
		// the pack puts the four operations there rather than relying on a
		// rule, so that a later rule written for an integrator cannot carry
		// them by accident.
		return sn.Refusals["s7"]["operation_denied"] >= 4
	}, "the pack refused the transfers")

	for _, op := range []string{"upload", "download", "stop"} {
		if p.got(op) {
			t.Errorf("a %s reached the controller", op)
		}
	}
}

// And the data block the published analysis names, which an HMI writes to no
// more than it downloads a program.
func TestTheStuxnetPackRefusesTheParameterBlockWrite(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := stuxnetPack(t, p.addr())

	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	// The HMI's own setpoint block: allowed.
	cl.allowed(writeJob(1, item(wire.TransportByte, 2, 100, wire.AreaDB, 0), wire.TransportByte, []byte{0x00, 0x01}))

	// DB890: refused. On this kind the finding is the refusal reason rather
	// than a rule name -- an `s7` rule matches a session and bounds it, so
	// there is no rule that matches one write -- and the matched rule's
	// comment is what carries the technique onto the event.
	cl.refused(writeJob(2, item(wire.TransportByte, 2, 890, wire.AreaDB, 0), wire.TransportByte, []byte{0x00, 0x01}))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["s7"]["db_not_allowed"] >= 1
	}, "the pack refused the parameter block")
}
