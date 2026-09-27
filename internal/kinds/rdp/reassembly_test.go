package rdp

import (
	"testing"

	"github.com/rom/xproxy/internal/rdp"
)

// The three reassembly buffers are separate, and this is the test that says so.
//
// A session collects up to three virtual channel messages at once: the
// redirection announcement coming up from the client, and a drdynvc message in
// each direction. They arrive on their own goroutines, so all three can be half
// collected at the same moment -- and one buffer shared between any two of them
// would splice one message onto another and hand a peer something neither side
// sent.
//
// It is a unit test rather than an end-to-end one because nothing over the wire
// lets a test say "now, while the other is half collected": the interleaving has
// to be constructed.
func TestTheReassemblyBuffersDoNotShareState(t *testing.T) {
	t.Parallel()
	se := &session{t: &server{}}
	half := func(msg []byte, at int) (rdp.ChannelChunk, rdp.ChannelChunk) {
		total := uint32(len(msg))
		return rdp.ChannelChunk{Total: total, Flags: rdp.ChannelFlagFirst, Data: msg[:at]},
			rdp.ChannelChunk{Total: total, Flags: rdp.ChannelFlagLast, Data: msg[at:]}
	}
	up := []byte("UPWARD-MESSAGE")
	down := []byte("DOWNWARD-MESSAGE")
	upFirst, upLast := half(up, 4)
	downFirst, downLast := half(down, 6)

	// Start both, interleaved, and finish them in the other order.
	if _, done, _ := se.reassembleUp(upFirst); done {
		t.Fatal("the upward message finished on its first chunk")
	}
	if _, done, _ := se.reassembleDown(downFirst); done {
		t.Fatal("the downward message finished on its first chunk")
	}
	gotDown, done, reason := se.reassembleDown(downLast)
	if !done || reason != "" {
		t.Fatalf("the downward message did not finish: done=%v reason=%q", done, reason)
	}
	if string(gotDown) != string(down) {
		t.Errorf("downward came back %q, want %q", gotDown, down)
	}
	gotUp, done, reason := se.reassembleUp(upLast)
	if !done || reason != "" {
		t.Fatalf("the upward message did not finish: done=%v reason=%q", done, reason)
	}
	if string(gotUp) != string(up) {
		t.Errorf("upward came back %q, want %q", gotUp, up)
	}

	// And neither of them shares with the redirection channel's own buffer,
	// which is collected by the same session on the client's side.
	se.pending = []byte("DEVICE-ANNOUNCE-SO-FAR")
	if _, done, _ := se.reassembleDown(downFirst); done {
		t.Fatal("the downward message finished on its first chunk")
	}
	if string(se.pending) != "DEVICE-ANNOUNCE-SO-FAR" {
		t.Errorf("the redirection buffer was disturbed: %q", se.pending)
	}
	gotDown, done, _ = se.reassembleDown(downLast)
	if !done || string(gotDown) != string(down) {
		t.Errorf("the downward message was spliced with the redirection buffer: %q", gotDown)
	}
}
