package main

import (
	"slices"
	"testing"

	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/proxy"
)

// TestLinkedKinds is the split, checked in the binary rather than in the
// prose about it: xot carries the plant's protocols and the ones the
// field equipment itself speaks, and nothing else. It is the check that
// matters most on this daemon, because "a binary with no mail parser in
// it" is the claim the whole thing rests on, and a stray blank import is
// how that quietly stops being true.
func TestLinkedKinds(t *testing.T) {
	// The roster is the one place that says which kinds this
	// daemon serves, so it is what this compares against: a list
	// written out again here would be one more thing to remember
	// when a kind is added, and forgetting it is how the check
	// stops checking.
	want := listener.KindsFor(listener.RoleOT)
	got := proxy.Registered()
	if !slices.Equal(got, want) {
		t.Fatalf("xot links %v, want %v", got, want)
	}
	for _, k := range got {
		if !listener.RoleOT.Serves(k) {
			t.Errorf("xot links kind %q, which no OT daemon serves", k)
		}
	}
}
