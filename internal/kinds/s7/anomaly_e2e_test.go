package s7

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/s7"
)

// The behavioural models on this kind, end to end. What is worth testing is the
// translation: that an operation reaches the models as a symbol, that a data
// block and byte reach them as a point, and that a write's span is what novelty
// about writes is keyed on.

const anomalyBase = "        upstream: cpu\n" +
	"        default_action: allow\n" +
	"        operations: [setup, read, write]\n" +
	"        anomaly:\n" +
	"          enabled: true\n" +
	"          settle: 0s\n" +
	"          talkers: {enabled: true, ready_after: 1s}\n"

func awaitS7(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the counters never said so: %+v", what, s.Stats().Refusals["s7"])
}

func TestTheModelsSeeTheOperationAndTheBlock(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, anomalyBase, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	// A read: an operation this station has not used. Nothing is refused,
	// because the default action of the detector is to alert.
	cl.allowed(readJob(2, item(wire.TransportByte, 8, 1, wire.AreaDB, 0)))
	awaitS7(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["s7"]["anomaly_new_symbol"] >= 1
	}, "a read this station has not made")

	// A write to a block it has not written: novel as an operation and as a
	// point, and the write still reaches the controller.
	cl.allowed(writeJob(3, item(wire.TransportByte, 1, 12, wire.AreaDB, 100),
		wire.TransportByte, []byte{1}))
	awaitS7(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["s7"]["anomaly_new_write_point"] >= 1
	}, "a write to a block this station has not written")
	if !p.got("write") {
		t.Error("an alerting detector kept the write from the controller")
	}

	// The same write again is novel in no way: the first occurrence was
	// recorded as it was reported.
	before := s.Stats().Refusals["s7"]["anomaly_new_write_point"]
	cl.allowed(writeJob(4, item(wire.TransportByte, 1, 12, wire.AreaDB, 100),
		wire.TransportByte, []byte{1}))
	if got := s.Stats().Refusals["s7"]["anomaly_new_write_point"]; got != before {
		t.Errorf("the second write to the same point was novel too: %d against %d", got, before)
	}
}

// With action: deny the first occurrence is refused, as the error class a
// password-protected CPU answers with, and the request never reaches the
// controller.
//
// Only the write-point model is on here, and deliberately: with the symbol
// model on and no settling window the *first* novel symbol is the handshake
// itself, so `action: deny` and `settle: 0s` together refuse the negotiation.
// That is correct and it is what the configuration warning about `settle: 0s`
// says it would be -- it is just not what this test is about.
func TestTheModelsCanBeAskedToRefuseTheFirstOccurrence(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, anomalyBase+
		"          action: deny\n"+
		"          novelty: {symbols: false, burst: 0}\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	pdu := cl.refused(writeJob(2, item(wire.TransportByte, 1, 12, wire.AreaDB, 100),
		wire.TransportByte, []byte{1}))
	if pdu.ErrClass != accessFault {
		t.Errorf("the client was told error class %#x, not an access fault", pdu.ErrClass)
	}
	if p.got("write") {
		t.Error("the refused write reached the controller")
	}
	// And the retry goes through, which is the documented limit of deny: the
	// first attempt is a hard stop and an operator's attention, not a block.
	cl.allowed(writeJob(3, item(wire.TransportByte, 1, 12, wire.AreaDB, 100),
		wire.TransportByte, []byte{1}))
	if !p.got("write") {
		t.Error("the retry was refused as well")
	}
}
