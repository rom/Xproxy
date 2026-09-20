package upstream

import (
	"fmt"
	"testing"
	"time"
)

// The hash ring used to place virtual_nodes * weight points per
// endpoint, so a pool of a hundred endpoints at weight 1000 built and
// sorted twelve million of them — on every discovery poll. Weights only
// matter in proportion, and the whole ring has a ceiling.
func TestRingPointsAreBounded(t *testing.T) {
	eps := make([]*Endpoint, 0, 100)
	for i := 0; i < 100; i++ {
		eps = append(eps, &Endpoint{Address: fmt.Sprintf("10.0.0.%d:80", i+1), Weight: 1000})
	}
	r := newRing(eps)
	if len(r.points) > maxRingPoints {
		t.Fatalf("%d ring points", len(r.points))
	}
	// Proportions survive: an endpoint with twice the weight gets about
	// twice the keys.
	two := []*Endpoint{{Address: "a:80", Weight: 100}, {Address: "b:80", Weight: 200}}
	r = newRing(two)
	if len(r.points) != 3*virtualNodes {
		t.Fatalf("weights 100 and 200 placed %d points, want %d", len(r.points), 3*virtualNodes)
	}
	counts := map[string]int{}
	now := time.Now()
	for i := 0; i < 3000; i++ {
		if e := r.pick(two, fmt.Sprint(i), nil, now); e != nil {
			counts[e.Address]++
		}
	}
	if counts["b:80"] < counts["a:80"] {
		t.Fatalf("the heavier endpoint took fewer keys: %v", counts)
	}
	// A single endpoint still gets a full ring.
	if r := newRing(eps[:1]); len(r.points) != virtualNodes*1000 && len(r.points) != virtualNodes {
		t.Fatalf("one endpoint placed %d points", len(r.points))
	}
}
