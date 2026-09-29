package mms

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The shipped behaviour pack for Industroyer's IEC 61850 payload, driven
// through the relay.
//
// A pack is configuration, and configuration nobody runs is a document of
// intentions. This takes the file as it ships, points it at a fabricated IED,
// and sends what the payload sent: read the model, then write a control
// object.
//
// Two substitutions are made and no others: the listener binds a loopback port
// the kernel picks instead of the station address in the file, and the
// engineering network becomes the loopback so that a test can be the client
// whose behaviour the pack is about. The rules are the file's own.
func industroyerMMSPack(t *testing.T, ied *fakeIED) (*proxy.Server, string) {
	t.Helper()
	b, err := os.ReadFile("../../../examples/ot/packs/industroyer-mms.yaml") //nolint:gosec // a file in this repository
	if err != nil {
		t.Fatalf("read the pack: %v", err)
	}
	doc := string(b)
	for _, sub := range [][2]string{
		{"10.50.0.10:102", "127.0.0.1:0"},
		{"10.50.3.0/24", "127.0.0.1/32"},
		{"10.50.9.51:102", ied.addr()},
	} {
		if !strings.Contains(doc, sub[0]) {
			t.Fatalf("the pack does not mention %s, so the substitution would test nothing", sub[0])
		}
		// Every occurrence: the file's header comment names these addresses
		// too, and replacing only the first would leave the rule that matters
		// pointing at a network no test can come from.
		doc = strings.ReplaceAll(doc, sub[0], sub[1])
	}
	s := proxytest.Start(t, doc)
	return s, proxytest.Addr(t, s, "substation-ieds")
}

// The payload's own sequence: enumerate the model, then write the control
// object of what the names say is a breaker. The pack lets the first happen,
// because browsing is how every legitimate client finds anything, and refuses
// the second from a client that does not operate this station.
func TestTheIndustroyerMMSPackRefusesTheOperate(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := industroyerMMSPack(t, ied)

	cl := session(t, addr)

	// Reading the model: allowed, and recorded.
	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$ST$Pos$stVal")))
	ied.await(t, 1, "the read of the breaker's state")

	// And the write that moves it, which is what the payload did next.
	cl.service(writeBody(2, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	awaitRefusal(t, s, "service_class_not_allowed")
	if seen := ied.seen(); len(seen) != 1 {
		t.Errorf("the IED saw %v, want the read only", seen)
	}
}

// awaitRefusal waits for this kind to have counted a refusal for one reason.
//
// The reason is the pack's: the client under test is the engineering network,
// whose rule allows browse, read and session, so a control write is outside the
// service classes that rule permits. The pack's own rule name is on the
// security event; the counters are per reason.
func awaitRefusal(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if s.Stats().Refusals["mms"][reason] > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %s refusal was counted: %v", reason, s.Stats().Refusals["mms"])
}
