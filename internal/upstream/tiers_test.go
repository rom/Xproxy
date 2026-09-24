package upstream

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// tieredPool builds a pool from address/priority/zone triples.
func tieredPool(t *testing.T, nodeZone string, locality *config.Locality, eps ...config.Endpoint) *Pool {
	t.Helper()
	c := testCfg("round_robin", eps[0].Address)
	c.Endpoints = eps
	for i := range c.Endpoints {
		if c.Endpoints[i].Weight == 0 {
			c.Endpoints[i].Weight = 1
		}
	}
	c.NodeZone = nodeZone
	c.Locality = locality
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// picked collects what a pool offers over many picks.
func picked(p *Pool, n int) map[string]int {
	out := map[string]int{}
	for i := 0; i < n; i++ {
		if e, _ := p.Pick("", "", nil, CanaryAny); e != nil {
			out[e.Address]++
		}
	}
	return out
}

// The first tier carries the traffic and the second is untouched. This is
// how a failover pool is written: a backup endpoint is one in a later
// tier, not a special kind of endpoint.
func TestPriorityKeepsTheBackupIdle(t *testing.T) {
	p := tieredPool(t, "", nil,
		config.Endpoint{Address: "127.0.0.1:9001"},
		config.Endpoint{Address: "127.0.0.1:9002"},
		config.Endpoint{Address: "127.0.0.1:9003", Priority: 1},
	)
	got := picked(p, 60)
	if got["127.0.0.1:9003"] != 0 {
		t.Fatalf("the backup took %d picks: %v", got["127.0.0.1:9003"], got)
	}
	if got["127.0.0.1:9001"] == 0 || got["127.0.0.1:9002"] == 0 {
		t.Fatalf("the first tier did not carry the traffic: %v", got)
	}
}

// When the first tier has nothing available, the next one takes the
// traffic -- and hands it back when the first returns.
func TestPriorityFallsThroughAndBack(t *testing.T) {
	p := tieredPool(t, "", nil,
		config.Endpoint{Address: "127.0.0.1:9001"},
		config.Endpoint{Address: "127.0.0.1:9003", Priority: 1},
	)
	d := NewDrains()
	p.UseDrains(d)
	d.SetEndpoint(p.Cfg.Name, "127.0.0.1:9001", true)
	if got := picked(p, 20); got["127.0.0.1:9003"] != 20 {
		t.Fatalf("the second tier did not take over: %v", got)
	}
	d.SetEndpoint(p.Cfg.Name, "127.0.0.1:9001", false)
	if got := picked(p, 20); got["127.0.0.1:9003"] != 0 {
		t.Fatalf("the second tier kept traffic after the first returned: %v", got)
	}
}

// A retry that has used up the first tier falls to the next, rather than
// finding nothing: the tier is computed against what the request has
// already tried.
func TestPriorityFallsThroughOnRetry(t *testing.T) {
	p := tieredPool(t, "", nil,
		config.Endpoint{Address: "127.0.0.1:9001"},
		config.Endpoint{Address: "127.0.0.1:9003", Priority: 1},
	)
	first, _ := p.Pick("", "", nil, CanaryAny)
	if first.Address != "127.0.0.1:9001" {
		t.Fatalf("first pick %s", first.Address)
	}
	second, _ := p.Pick("", "", map[*Endpoint]bool{first: true}, CanaryAny)
	if second == nil || second.Address != "127.0.0.1:9003" {
		t.Fatalf("the retry did not fall to the next tier: %v", second)
	}
}

// Locality prefers this node's own zone and leaves the others alone --
// which is what keeps traffic off the links between sites.
func TestLocalityPrefersTheNodesOwnZone(t *testing.T) {
	p := tieredPool(t, "east", &config.Locality{PreferZone: true},
		config.Endpoint{Address: "127.0.0.1:9001", Zone: "east"},
		config.Endpoint{Address: "127.0.0.1:9002", Zone: "east"},
		config.Endpoint{Address: "127.0.0.1:9003", Zone: "west"},
	)
	got := picked(p, 60)
	if got["127.0.0.1:9003"] != 0 {
		t.Fatalf("a remote endpoint took %d picks: %v", got["127.0.0.1:9003"], got)
	}
	if got["127.0.0.1:9001"] == 0 || got["127.0.0.1:9002"] == 0 {
		t.Fatalf("the local zone did not carry the traffic: %v", got)
	}
}

// It is a preference, not a restriction: when the local zone is gone the
// other one takes the traffic, because a pool pinned to a zone would lose
// the service with the zone, which is the opposite of what zones are for.
func TestLocalityIsAPreferenceNotAPin(t *testing.T) {
	p := tieredPool(t, "east", &config.Locality{PreferZone: true},
		config.Endpoint{Address: "127.0.0.1:9001", Zone: "east"},
		config.Endpoint{Address: "127.0.0.1:9003", Zone: "west"},
	)
	d := NewDrains()
	p.UseDrains(d)
	d.SetEndpoint(p.Cfg.Name, "127.0.0.1:9001", true)
	if got := picked(p, 20); got["127.0.0.1:9003"] != 20 {
		t.Fatalf("the remaining zone did not take over: %v", got)
	}
}

// min_local keeps one surviving local endpoint from taking the whole
// load: below it, everything is used.
func TestLocalityMinLocalSpillsOver(t *testing.T) {
	p := tieredPool(t, "east", &config.Locality{PreferZone: true, MinLocal: 2},
		config.Endpoint{Address: "127.0.0.1:9001", Zone: "east"},
		config.Endpoint{Address: "127.0.0.1:9002", Zone: "east"},
		config.Endpoint{Address: "127.0.0.1:9003", Zone: "west"},
	)
	if got := picked(p, 60); got["127.0.0.1:9003"] != 0 {
		t.Fatalf("with two local endpoints available the remote one took %d: %v", got["127.0.0.1:9003"], got)
	}
	d := NewDrains()
	p.UseDrains(d)
	d.SetEndpoint(p.Cfg.Name, "127.0.0.1:9002", true)
	if got := picked(p, 60); got["127.0.0.1:9003"] == 0 {
		t.Fatalf("with one local endpoint left and min_local 2, the remote one took nothing: %v", got)
	}
}

// An endpoint with no zone is local to every zone: "somewhere unknown" is
// not a reason to send traffic across a site.
func TestAnEndpointWithNoZoneIsLocal(t *testing.T) {
	p := tieredPool(t, "east", &config.Locality{PreferZone: true},
		config.Endpoint{Address: "127.0.0.1:9001", Zone: "west"},
		config.Endpoint{Address: "127.0.0.1:9002"},
	)
	got := picked(p, 40)
	if got["127.0.0.1:9002"] == 0 {
		t.Fatalf("an endpoint with no zone was treated as remote: %v", got)
	}
	if got["127.0.0.1:9001"] != 0 {
		t.Fatalf("a remote endpoint was used while an unzoned one was available: %v", got)
	}
}

// A pool with neither policy pays nothing for either: no tiering is
// computed at all.
func TestAnOrdinaryPoolIsNotTiered(t *testing.T) {
	p := tieredPool(t, "east", nil,
		config.Endpoint{Address: "127.0.0.1:9001"},
		config.Endpoint{Address: "127.0.0.1:9002"},
	)
	if p.tiered {
		t.Fatal("a pool with no priority and no locality is tiered")
	}
	if got := picked(p, 40); len(got) != 2 {
		t.Fatalf("an ordinary pool did not use both endpoints: %v", got)
	}
	_ = time.Now
}
