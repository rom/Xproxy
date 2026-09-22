package main

import (
	"slices"
	"testing"

	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/proxy"
)

// TestLinkedKinds is the split, checked in the binary rather than in the
// prose about it: xgate carries the protocol code of its own role and no
// other. A stray blank import is the way that quietly stops being true,
// and this is what catches one.
func TestLinkedKinds(t *testing.T) {
	want := []string{"ssh"}
	got := proxy.Registered()
	if !slices.Equal(got, want) {
		t.Fatalf("xgate links %v, want %v", got, want)
	}
	for _, k := range got {
		if !listener.RoleGate.Serves(k) {
			t.Errorf("xgate links kind %q, which belongs to another daemon", k)
		}
	}
}
