package upstream

import (
	"net"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// A drained endpoint takes no new work. It is the decision that matters,
// not the measurement: the endpoint is perfectly healthy, and that is
// exactly the case where an operator needs this.
func TestDrainedEndpointIsNotPicked(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	c.Endpoints = append(c.Endpoints, config.Endpoint{Address: "127.0.0.1:9002", Weight: 1})
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDrains()
	p.UseDrains(d)
	if !d.SetEndpoint(c.Name, "127.0.0.1:9001", true) {
		t.Fatal("the endpoint was not found in a live pool")
	}
	for i := 0; i < 10; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		if e == nil {
			t.Fatal("no endpoint offered while one is in rotation")
		}
		if e.Address == "127.0.0.1:9001" {
			t.Fatal("a drained endpoint was picked")
		}
	}
	if st := p.Status(); st.Draining != 1 || st.Available != 1 {
		t.Errorf("status draining %d available %d, want 1 and 1", st.Draining, st.Available)
	}
	// And it comes back.
	d.SetEndpoint(c.Name, "127.0.0.1:9001", false)
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		seen[e.Address] = true
	}
	if !seen["127.0.0.1:9001"] {
		t.Fatal("a restored endpoint is still out of rotation")
	}
}

// Draining is not ejection: it does not touch the health state, so an
// operator looking at the status can still tell a machine they took out
// from one the proxy found broken.
func TestDrainingIsNotAHealthResult(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDrains()
	p.UseDrains(d)
	d.SetEndpoint(c.Name, "127.0.0.1:9001", true)
	e := p.endpoints()[0]
	if !e.Healthy() {
		t.Fatal("draining marked the endpoint unhealthy; the two must stay distinguishable")
	}
	if e.Available(time.Now()) {
		t.Fatal("a drained endpoint is available")
	}
	st := p.Stats()[0]
	if !st.Draining || !st.Healthy {
		t.Fatalf("status draining=%v healthy=%v, want true and true", st.Draining, st.Healthy)
	}
}

// A pool in maintenance offers nothing at all, which is the honest
// answer for a service that is deliberately away: the caller sees what
// it sees when every endpoint is unhealthy.
func TestPoolMaintenanceOffersNothing(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDrains()
	p.UseDrains(d)
	d.SetPool(c.Name, true)
	if e, _ := p.Pick("", "", nil, CanaryAny); e != nil {
		t.Fatalf("a pool in maintenance offered %s", e.Address)
	}
	if !p.Maintenance() {
		t.Fatal("the pool does not report maintenance")
	}
	d.SetPool(c.Name, false)
	if e, _ := p.Pick("", "", nil, CanaryAny); e == nil {
		t.Fatal("a pool taken out of maintenance still offers nothing")
	}
}

// The decision outlives the pool it was made about. A reload builds new
// pools, and an operator who drained a machine to patch it did not mean
// "until the next configuration change".
func TestADecisionSurvivesTheGeneration(t *testing.T) {
	d := NewDrains()
	build := func() *Pool {
		c := testCfg("round_robin", "127.0.0.1:9001")
		c.Endpoints = append(c.Endpoints, config.Endpoint{Address: "127.0.0.1:9002", Weight: 1})
		p, err := NewPool(c, nolog)
		if err != nil {
			t.Fatal(err)
		}
		p.UseDrains(d)
		return p
	}
	first := build()
	d.SetEndpoint(first.Cfg.Name, "127.0.0.1:9001", true)
	first.Stop() // the generation is retired

	second := build()
	for _, e := range second.endpoints() {
		if e.Address == "127.0.0.1:9001" && e.Available(time.Now()) {
			t.Fatal("the new generation forgot the drain")
		}
	}
	if st := second.Status(); st.Draining != 1 {
		t.Errorf("draining %d in the new generation, want 1", st.Draining)
	}
}

// The configuration can ask for a drain, and a decision made afterwards
// overrides it: the person who made that decision knew something the
// file did not.
func TestAnAPIDecisionOverridesTheFile(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	c.Endpoints[0].Drain = true
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDrains()
	p.UseDrains(d)
	if p.endpoints()[0].Available(time.Now()) {
		t.Fatal("an endpoint the file drains is in rotation")
	}
	d.SetEndpoint(c.Name, "127.0.0.1:9001", false)
	if !p.endpoints()[0].Available(time.Now()) {
		t.Fatal("a restore did not override the file")
	}
}

// A decision about something that is not there is recorded rather than
// refused: an endpoint may be about to arrive from discovery, and saying
// so is more useful than pretending either way.
func TestADecisionAboutNothingIsStillRecorded(t *testing.T) {
	d := NewDrains()
	if found := d.SetEndpoint("nowhere", "10.0.0.1:80", true); found {
		t.Fatal("a pool that does not exist reported a match")
	}
	got := d.Decisions()
	if !got.Endpoints["nowhere"]["10.0.0.1:80"] {
		t.Fatalf("the decision was not recorded: %+v", got)
	}
	if names := d.Names(); len(names) != 1 || names[0] != "nowhere" {
		t.Errorf("names %v", names)
	}
}

// A connection past max_connection_age is retired at the end of the
// exchange that found it, not at the age itself: closing at the age
// would cut a request that has done nothing wrong, and from inside a
// net.Conn an exchange in progress and an idle connection are both a
// blocked read.
func TestAgedConnectionIsRetiredOnceTheExchangeEnds(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	c.MaxConnectionAge = config.Duration(50 * time.Millisecond)
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer func() { _ = right.Close() }()
	conn := &agedConn{Conn: left, born: time.Now(), age: 50 * time.Millisecond}
	if p.AgedOut(conn) {
		t.Fatal("a fresh connection is already aged out")
	}
	if p.Retire(conn) {
		t.Fatal("a fresh connection was retired")
	}
	time.Sleep(80 * time.Millisecond)
	if !p.AgedOut(conn) {
		t.Fatal("a connection past its age does not report it")
	}
	if !p.Retire(conn) {
		t.Fatal("an aged connection was not retired")
	}
	// Retiring is once per connection, not once per request that
	// noticed, or the counter would say something else entirely.
	if p.Retire(conn) {
		t.Fatal("the same connection was retired twice")
	}
	if n := p.Retired.Load(); n != 1 {
		t.Fatalf("retired %d, want 1", n)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a retired connection is still open")
	}
}

// A connection this pool did not wrap is not its business.
func TestRetireIgnoresAForeignConnection(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer func() { _ = left.Close(); _ = right.Close() }()
	if p.Retire(left) || p.AgedOut(left) {
		t.Fatal("a connection the pool never wrapped was treated as aged")
	}
}

// An endpoint at its own concurrency bound is passed over, and the pool's
// other endpoints take the work. Holding work for one endpoint while
// others are idle is the opposite of balancing.
func TestEndpointConcurrencyBound(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	c.Endpoints[0].MaxConnections = 1
	c.Endpoints = append(c.Endpoints, config.Endpoint{Address: "127.0.0.1:9002", Weight: 1})
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	var bounded *Endpoint
	for _, e := range p.endpoints() {
		if e.Address == "127.0.0.1:9001" {
			bounded = e
		}
	}
	if bounded == nil {
		t.Fatal("endpoint missing")
	}
	if bounded.maxActive != 1 {
		t.Fatalf("the endpoint's bound is %d, want 1", bounded.maxActive)
	}
	p.Begin(bounded) // one in flight: the bound is reached
	for i := 0; i < 10; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		if e == nil {
			t.Fatal("no endpoint offered while one is free")
		}
		if e == bounded {
			t.Fatal("an endpoint at its bound was picked")
		}
	}
	p.End(bounded, false, 0)
	seen := false
	for i := 0; i < 10; i++ {
		if e, _ := p.Pick("", "", nil, CanaryAny); e == bounded {
			seen = true
		}
	}
	if !seen {
		t.Fatal("the endpoint never came back after its work finished")
	}
}

// The pool-wide default applies to every endpoint, and an endpoint that
// names its own replaces it: the small instance beside large ones is the
// case this exists for.
func TestPoolWideEndpointBoundAndOverride(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	c.MaxConnectionsPerEndpoint = 4
	c.Endpoints = append(c.Endpoints, config.Endpoint{Address: "127.0.0.1:9002", Weight: 1, MaxConnections: 1})
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"127.0.0.1:9001": 4, "127.0.0.1:9002": 1}
	for _, st := range p.Stats() {
		if st.MaxActive != want[st.Address] {
			t.Errorf("%s max_active %d, want %d", st.Address, st.MaxActive, want[st.Address])
		}
	}
}

// When every endpoint is at its bound the pool offers nothing, which is
// what the pool's queue and circuit breaker are there to answer.
func TestEveryEndpointAtItsBoundOffersNothing(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	c.MaxConnectionsPerEndpoint = 1
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	e := p.endpoints()[0]
	p.Begin(e)
	if got, _ := p.Pick("", "", nil, CanaryAny); got != nil {
		t.Fatalf("offered %s with every endpoint at its bound", got.Address)
	}
}
