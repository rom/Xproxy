package limits

import "testing"

func TestTop(t *testing.T) {
	l := NewKeyedLimiter(10, 10, 100)
	for i := 0; i < 7; i++ {
		l.Allow("a")
	}
	for i := 0; i < 3; i++ {
		l.Allow("b")
	}
	l.Allow("c")
	top := l.Top(2)
	if len(top) != 2 || top[0].Key != "a" || top[0].Total != 7 || top[1].Key != "b" || top[1].Total != 3 {
		t.Fatalf("top %+v", top)
	}
	if top[0].Tokens < 2.9 || top[0].Tokens > 3.1 {
		t.Fatalf("tokens left for a: %v", top[0].Tokens)
	}
	if all := l.Top(0); len(all) != 3 || all[2].Key != "c" {
		t.Fatalf("all %+v", all)
	}
	// Flush (cluster gossip) resets the interval counters, not the totals.
	l.Flush(0)
	if l.Top(1)[0].Total != 7 {
		t.Fatal("flush cleared totals")
	}
}
