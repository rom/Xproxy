package opcua

import (
	"os"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The shipped behaviour pack for PIPEDREAM's OPC UA module, driven through the
// relay.
//
// A pack is configuration, and configuration nobody runs is a document of
// intentions. This takes the file as it ships, points it at a fabricated
// server, and does what the module does: open a session, read the address
// space, and write a node value.
//
// Two substitutions are made and no others: the listener binds a loopback port
// the kernel picks instead of the plant address in the file, and the HMI
// network becomes the loopback. The rules are the file's own.
func pipedreamUAPack(t *testing.T, up *fakeServer) (*proxy.Server, string) {
	t.Helper()
	b, err := os.ReadFile("../../../examples/ot/packs/pipedream-opcua.yaml") //nolint:gosec // a file in this repository
	if err != nil {
		t.Fatalf("read the pack: %v", err)
	}
	doc := string(b)
	for _, sub := range [][2]string{
		{"10.60.0.10:4840", "127.0.0.1:0"},
		{"10.60.1.0/24", "127.0.0.1/32"},
		{"10.60.9.61:4840", up.addr()},
	} {
		if !strings.Contains(doc, sub[0]) {
			t.Fatalf("the pack does not mention %s, so the substitution would test nothing", sub[0])
		}
		doc = strings.ReplaceAll(doc, sub[0], sub[1])
	}
	s := proxytest.Start(t, doc)
	return s, proxytest.Addr(t, s, "plant-opcua")
}

func TestThePipedreamUAPackRefusesTheMethodCall(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := pipedreamUAPack(t, up)

	// The pack refuses SecurityPolicy None, and it refuses the encrypted mode
	// as well -- deliberately, because the service rules are silent on a
	// channel the relay cannot read. So a session under this pack is signed and
	// readable, and the module's usual one -- None with an anonymous token --
	// does not get this far.
	cl := dial(t, addr)
	if ch := cl.handshake("opc.tcp://127.0.0.1:4840"); ch.Type != wire.Acknowledge {
		t.Fatalf("the handshake answered %s", ch.Type)
	}
	if ch := cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign); ch.Type != wire.Message {
		t.Fatalf("the channel answered %s", ch.Type)
	}
	// Reading the address space: allowed, which is deliberate. Browsing and
	// reading are how every legitimate client finds anything, and a pack that
	// refused them would be a pack nobody installs.
	cl.service(wire.SvcRead, readBody(op(n(4, 100), wire.AttrValue)))
	if !up.sawService(wire.SvcRead) {
		t.Errorf("the read did not reach the server: %v", up.seen())
	}

	// A method call: refused by the pack's deny list, which no rule widens.
	// Calling a method is how an OPC UA server is made to do something that is
	// not a value write at all, and a plant's HMI does not need it.
	cl.service(wire.SvcCall, callBody(n(4, 100), n(4, 200), 0))
	awaitUARefusal(t, s, "service_denied")
	if up.sawService(wire.SvcCall) {
		t.Errorf("the call reached the server: %v", up.seen())
	}
}

// awaitUARefusal waits for one refusal reason to be counted.
func awaitUARefusal(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if s.Stats().Refusals["opcua"][reason] > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %s refusal was counted: %v", reason, s.Stats().Refusals["opcua"])
}
