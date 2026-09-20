package cluster

import "testing"

// TestDeliverOnlyFromAskedPeer: an owner's answer is accepted only from the
// peer the request went to; request ids are sequential, so another node
// could otherwise answer requests addressed to a different owner.
func TestDeliverOnlyFromAskedPeer(t *testing.T) {
	n := &Node{pending: map[uint64]pendingTake{}}
	asked, other := &peer{}, &peer{}
	ch := make(chan takeReply, 1)
	n.pending[7] = pendingTake{ch: ch, from: asked}
	yes := true
	n.deliver(&message{T: typeTook, Req: 7, Allowed: &yes}, other)
	select {
	case r := <-ch:
		t.Fatalf("answer from the wrong peer delivered: %+v", r)
	default:
	}
	if _, still := n.pending[7]; !still || n.ignored.Load() != 1 {
		t.Fatal("request dropped or the stray answer not counted")
	}
	n.deliver(&message{T: typeTook, Req: 7, Allowed: &yes}, asked)
	select {
	case r := <-ch:
		if !r.decided || !r.allowed {
			t.Fatalf("reply %+v", r)
		}
	default:
		t.Fatal("answer from the asked peer not delivered")
	}
}
