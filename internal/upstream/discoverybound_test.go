package upstream

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// boundPool is a pool whose discovery will not install more than maxEP
// endpoints, with no health checks so that nothing else moves.
func boundPool(t *testing.T, maxEP int) (*Pool, *fakeLookup) {
	t.Helper()
	disc := &config.Discovery{Type: "dns", Name: "backend.example.", Port: 8080,
		Interval: config.Duration(time.Hour), Timeout: config.Duration(time.Second), Weight: 1, MaxEndpoints: maxEP}
	p, err := NewPool(upstreamCfg(disc), dlog)
	if err != nil {
		t.Fatal(err)
	}
	fl := &fakeLookup{}
	p.SetLookupForTest(fl)
	return p, fl
}

// ips returns n addresses in a deterministic order that is not the sorted one,
// so a test cannot pass by accident of the answer's order.
func ips(n int) []string {
	out := make([]string, 0, n)
	for i := n; i > 0; i-- {
		out = append(out, fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	return out
}

// A registry answer decides how many health check goroutines this process runs
// and how large the hash ring is, so it is bounded: the resolution is truncated
// rather than installed whole, and the truncation is counted where an operator
// can see it.
func TestAResolutionBeyondTheBoundIsTruncatedAndCounted(t *testing.T) {
	p, fl := boundPool(t, 3)
	fl.set("backend.example.", ips(9)...)
	p.Start()
	defer p.Stop()

	if got := len(p.Endpoints()); got != 3 {
		t.Errorf("installed %d endpoints, want 3: %v", got, addresses(p))
	}
	// The ones kept are the first by address, which is what the log line
	// tells the operator: they can tell from the answer which subset the
	// pool is serving without asking the proxy.
	want := "[10.0.0.1:8080 10.0.0.2:8080 10.0.0.3:8080]"
	if got := fmt.Sprint(addresses(p)); got != want {
		t.Errorf("kept %s, want the first three by address %s", got, want)
	}
	st := p.Status().Discovery
	if st.Truncations != 1 {
		t.Errorf("truncations = %d, want 1", st.Truncations)
	}
	// The answer still resolved, so this is not an error: the pool is
	// serving, on fewer endpoints than were announced.
	if st.Errors != 0 || st.LastError != "" {
		t.Errorf("a truncation was reported as a failed resolution: %d %q", st.Errors, st.LastError)
	}
}

// The subset has to be the same one every time. An unstable subset would remove
// and add endpoints on every interval -- losing their statistics, restarting
// their slow start ramps and rebuilding the hash ring each time -- which is a
// worse failure than serving fewer endpoints.
func TestTheTruncatedSubsetIsTheSameEveryTime(t *testing.T) {
	p, fl := boundPool(t, 4)
	fl.set("backend.example.", ips(9)...)
	p.Start()
	defer p.Stop()
	first := addresses(p)
	was := p.Status().Discovery.Changes

	// The same nine addresses, announced in a different order.
	rotated := ips(9)
	rotated = append(rotated[4:], rotated[:4]...)
	fl.set("backend.example.", rotated...)
	p.ResolveNowForTest()

	if got := addresses(p); fmt.Sprint(got) != fmt.Sprint(first) {
		t.Errorf("the subset moved: %v then %v", first, got)
	}
	if now := p.Status().Discovery.Changes; now != was {
		t.Errorf("a resolution of the same addresses churned the pool: changes %d then %d", was, now)
	}
	if got := p.Status().Discovery.Truncations; got != 2 {
		t.Errorf("truncations = %d, want 2 (both resolutions were truncated)", got)
	}
}

// Exactly at the bound is not over it.
func TestAResolutionAtTheBoundIsNotTruncated(t *testing.T) {
	p, fl := boundPool(t, 5)
	fl.set("backend.example.", ips(5)...)
	p.Start()
	defer p.Stop()
	if got := len(p.Endpoints()); got != 5 {
		t.Errorf("installed %d endpoints, want 5", got)
	}
	if got := p.Status().Discovery.Truncations; got != 0 {
		t.Errorf("truncations = %d, want 0", got)
	}
}

// A configuration built in code rather than loaded has no bound filled in by
// validation, and a bound that any path can reach unset is not a bound. So an
// unset one falls back to the documented default rather than to no limit.
func TestAnUnsetBoundIsTheDefaultRatherThanNone(t *testing.T) {
	p, fl := boundPool(t, 0)
	fl.set("backend.example.", ips(4)...)
	p.Start()
	defer p.Stop()
	if got := len(p.Endpoints()); got != 4 {
		t.Fatalf("installed %d endpoints, want 4", got)
	}
	d := p.disc
	if got := len(d.bound(make([]endpointSpec, config.DefaultDiscoveryMaxEndpoints+1))); got != config.DefaultDiscoveryMaxEndpoints {
		t.Errorf("an unset bound truncated to %d, want the default %d", got, config.DefaultDiscoveryMaxEndpoints)
	}
	if got := d.truncations.Load(); got != 1 {
		t.Errorf("truncations = %d, want 1", got)
	}
}
