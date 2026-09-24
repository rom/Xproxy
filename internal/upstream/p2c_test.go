package upstream

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// poolOf builds a pool with n endpoints on one balancer.
func poolOf(t *testing.T, balancer string, n int) *Pool {
	t.Helper()
	c := testCfg(balancer, "127.0.0.1:9001")
	for i := 2; i <= n; i++ {
		c.Endpoints = append(c.Endpoints, config.Endpoint{Address: "127.0.0.1:900" + string(rune('0'+i)), Weight: 1})
	}
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// p2c takes the better of two endpoints chosen at random, which is what
// keeps a fleet of proxies from all sending to the same "best" endpoint
// at once. With one endpoint deeply loaded, it is the one that is avoided.
func TestP2CAvoidsTheLoadedEndpoint(t *testing.T) {
	p := poolOf(t, "p2c", 3)
	eps := p.endpoints()
	busy := eps[0]
	for i := 0; i < 50; i++ {
		p.Begin(busy)
	}
	picks := map[string]int{}
	for i := 0; i < 300; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		if e == nil {
			t.Fatal("no endpoint")
		}
		picks[e.Address]++
	}
	if picks[busy.Address] > 60 {
		t.Fatalf("the loaded endpoint took %d of 300 picks: %v", picks[busy.Address], picks)
	}
	// And it is not starved either: p2c compares two, so a third of the
	// draws include it and it wins whenever its partner is worse. What
	// matters is that the others carry most of the work.
	if picks[eps[1].Address] == 0 || picks[eps[2].Address] == 0 {
		t.Fatalf("an idle endpoint took nothing: %v", picks)
	}
}

// With every endpoint equally loaded, p2c spreads the work rather than
// settling on one.
func TestP2CSpreadsWhenNothingIsBusier(t *testing.T) {
	p := poolOf(t, "p2c", 3)
	picks := map[string]int{}
	for i := 0; i < 300; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		picks[e.Address]++
	}
	for _, e := range p.endpoints() {
		if n := picks[e.Address]; n < 50 {
			t.Errorf("%s took only %d of 300 picks: %v", e.Address, n, picks)
		}
	}
}

// ewma reads latency, so a slow endpoint sheds work long before it is
// slow enough to be ejected -- which is the difference between shedding
// load away from a struggling machine and waiting for it to break.
func TestEWMAPrefersTheFasterEndpoint(t *testing.T) {
	p := poolOf(t, "ewma", 2)
	eps := p.endpoints()
	slow, fast := eps[0], eps[1]
	// Latency is recorded per response, as outlier detection sees it.
	for i := 0; i < 30; i++ {
		_, _ = slow.observeLatency(200 * time.Millisecond)
		_, _ = fast.observeLatency(10 * time.Millisecond)
	}
	picks := map[string]int{}
	for i := 0; i < 200; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		picks[e.Address]++
	}
	if picks[fast.Address] < picks[slow.Address] {
		t.Fatalf("the slower endpoint took more work: %v", picks)
	}
	if picks[slow.Address] > 20 {
		t.Fatalf("a twentyfold slower endpoint still took %d of 200: %v", picks[slow.Address], picks)
	}
}

// An endpoint with no samples is tried rather than starved by the fact
// that nothing is known about it: a recovered endpoint has to get a
// request before it can have a latency.
func TestEWMATriesAnEndpointItKnowsNothingAbout(t *testing.T) {
	p := poolOf(t, "ewma", 2)
	eps := p.endpoints()
	for i := 0; i < 30; i++ {
		_, _ = eps[0].observeLatency(50 * time.Millisecond)
	}
	fresh := eps[1]
	seen := false
	for i := 0; i < 50; i++ {
		if e, _ := p.Pick("", "", nil, CanaryAny); e == fresh {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatal("an endpoint with no latency sample was never tried")
	}
}

// A quiet pool, where nothing distinguishes the endpoints, is spread
// evenly rather than piled onto the first one.
func TestEWMASpreadsAQuietPool(t *testing.T) {
	p := poolOf(t, "ewma", 3)
	picks := map[string]int{}
	for i := 0; i < 300; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		picks[e.Address]++
	}
	for _, e := range p.endpoints() {
		if n := picks[e.Address]; n < 50 {
			t.Errorf("%s took only %d of 300 picks on a quiet pool: %v", e.Address, n, picks)
		}
	}
}

// Both balancers honour everything else about an endpoint: a drained one
// is not picked, and neither is one at its own bound.
func TestNewBalancersHonourAvailability(t *testing.T) {
	for _, name := range []string{"p2c", "ewma"} {
		p := poolOf(t, name, 2)
		d := NewDrains()
		p.UseDrains(d)
		out := p.endpoints()[0]
		d.SetEndpoint(p.Cfg.Name, out.Address, true)
		for i := 0; i < 50; i++ {
			if e, _ := p.Pick("", "", nil, CanaryAny); e == out {
				t.Fatalf("%s picked a drained endpoint", name)
			}
		}
	}
}
