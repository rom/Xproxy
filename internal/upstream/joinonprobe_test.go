package upstream

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// joinPool is a pool with one static endpoint, DNS discovery and active health
// checks whose interval is long enough that no probe fires unless a test makes
// one.
func joinPool(t *testing.T, static ...string) (*Pool, *fakeLookup) {
	t.Helper()
	disc := &config.Discovery{Type: "dns", Name: "backend.example.", Port: 8080,
		Interval: config.Duration(time.Hour), Timeout: config.Duration(time.Second), Weight: 1}
	cfg := upstreamCfg(disc, static...)
	cfg.HealthCheck = &config.HealthCheck{Type: "tcp", Interval: config.Duration(time.Hour),
		Timeout: config.Duration(time.Millisecond), HealthyThreshold: 1, UnhealthyThreshold: 1}
	p, err := NewPool(cfg, dlog)
	if err != nil {
		t.Fatal(err)
	}
	fl := &fakeLookup{}
	p.SetLookupForTest(fl)
	return p, fl
}

func find(t *testing.T, p *Pool, addr string) *Endpoint {
	t.Helper()
	for _, e := range p.Endpoints() {
		if e.Address == addr {
			return e
		}
	}
	t.Fatalf("no endpoint %s in %v", addr, addresses(p))
	return nil
}

// An endpoint a registry announces while the pool is already serving has not
// been probed, and a registry announces an instance when its process starts
// rather than when it is ready. So it waits for a passing probe instead of
// taking traffic and failing it.
func TestAnAnnouncedEndpointWaitsForItsFirstProbe(t *testing.T) {
	p, fl := joinPool(t, "10.9.9.9:8080")
	fl.set("backend.example.", "10.0.0.1")
	p.Start()
	defer p.Stop()

	fl.set("backend.example.", "10.0.0.1", "10.0.0.2")
	p.ResolveNowForTest()

	e := find(t, p, "10.0.0.2:8080")
	if e.Healthy() {
		t.Error("a just-announced endpoint reports healthy before any probe")
	}
	if e.Available(time.Now()) {
		t.Error("a just-announced endpoint is eligible for traffic before any probe")
	}
	// The endpoints that were already serving are untouched.
	for _, addr := range []string{"10.0.0.1:8080", "10.9.9.9:8080"} {
		if !find(t, p, addr).Available(time.Now()) {
			t.Errorf("%s stopped being available", addr)
		}
	}
	// And a passing probe lets it in, through the same path a recovering
	// endpoint takes.
	e.healthy.Store(true)
	if !e.Available(time.Now()) {
		t.Error("a probed endpoint is still not available")
	}
}

// The exception, and the reason it exists: when nothing else can carry the
// traffic, an unprobed endpoint is better than none. Waiting would blackhole
// the pool for a whole interval, which is the same reasoning that makes an
// endpoint present at process start begin optimistic.
func TestAnAnnouncedEndpointDoesNotWaitWhenItIsTheOnlyOne(t *testing.T) {
	p, fl := joinPool(t)
	// Discovery resolves to nothing usable at first, so the pool starts with
	// one endpoint and then loses it.
	fl.set("backend.example.", "10.0.0.1")
	p.Start()
	defer p.Stop()
	gone := find(t, p, "10.0.0.1:8080")
	gone.healthy.Store(false)

	// Now the only other endpoint is unhealthy, so the announcement has to
	// serve immediately.
	fl.set("backend.example.", "10.0.0.1", "10.0.0.2")
	p.ResolveNowForTest()
	e := find(t, p, "10.0.0.2:8080")
	if !e.Healthy() {
		t.Error("the only usable endpoint was made to wait for a probe")
	}
}

// A draining endpoint is a decision rather than a measurement, so it does not
// count as somebody who can carry the traffic: a pool whose other members are
// all being taken out of service needs the new one now.
func TestADrainingEndpointDoesNotCountAsAvailable(t *testing.T) {
	p, fl := joinPool(t)
	fl.set("backend.example.", "10.0.0.1")
	p.Start()
	defer p.Stop()
	find(t, p, "10.0.0.1:8080").draining.Store(true)

	fl.set("backend.example.", "10.0.0.1", "10.0.0.2")
	p.ResolveNowForTest()
	if !find(t, p, "10.0.0.2:8080").Healthy() {
		t.Error("the new endpoint waited while every other one was draining")
	}
}

// Without active checks there is no probe to wait for, so an announcement
// serves at once -- otherwise it would never serve at all.
func TestWithoutHealthChecksAnAnnouncementServesAtOnce(t *testing.T) {
	disc := &config.Discovery{Type: "dns", Name: "backend.example.", Port: 8080,
		Interval: config.Duration(time.Hour), Timeout: config.Duration(time.Second), Weight: 1}
	p, err := NewPool(upstreamCfg(disc, "10.9.9.9:8080"), dlog)
	if err != nil {
		t.Fatal(err)
	}
	fl := &fakeLookup{}
	fl.set("backend.example.", "10.0.0.1")
	p.SetLookupForTest(fl)
	p.Start()
	defer p.Stop()

	fl.set("backend.example.", "10.0.0.1", "10.0.0.2")
	p.ResolveNowForTest()
	if !find(t, p, "10.0.0.2:8080").Available(time.Now()) {
		t.Error("an announcement waited for a probe that will never run")
	}
}

// The endpoints a pool is built with still start optimistic: at process start
// nothing has been probed, and waiting would serve nothing at all for an
// interval.
func TestTheEndpointsAPoolStartsWithDoNotWait(t *testing.T) {
	p, fl := joinPool(t, "10.9.9.9:8080")
	fl.set("backend.example.", "10.0.0.1")
	p.Start()
	defer p.Stop()
	for _, addr := range []string{"10.0.0.1:8080", "10.9.9.9:8080"} {
		if !find(t, p, addr).Available(time.Now()) {
			t.Errorf("%s was made to wait for a probe at start", addr)
		}
	}
}

// An address that leaves and comes back is a new endpoint, and gets the same
// treatment as any other announcement -- its old health state is not a
// statement about the process now listening there.
func TestAnAddressThatComesBackIsProbedAgain(t *testing.T) {
	p, fl := joinPool(t, "10.9.9.9:8080")
	fl.set("backend.example.", "10.0.0.1", "10.0.0.2")
	p.Start()
	defer p.Stop()
	if !find(t, p, "10.0.0.2:8080").Available(time.Now()) {
		t.Fatal("an endpoint present at start was not available")
	}

	fl.set("backend.example.", "10.0.0.1")
	p.ResolveNowForTest()
	fl.set("backend.example.", "10.0.0.1", "10.0.0.2")
	p.ResolveNowForTest()
	if find(t, p, "10.0.0.2:8080").Healthy() {
		t.Error("an address that came back kept the standing of the one that left")
	}
}

// Waiting for a probe is only tolerable if the probe is soon. Every health
// loop starts with a jitter of up to one interval, so that a thousand
// endpoints do not probe in lockstep -- but an endpoint that is out of the
// pool until its first probe would then be out for up to a whole interval,
// which for a five minute interval is an instance a registry announced and
// the proxy ignored for five minutes. So an announced endpoint probes at once
// and takes the jitter from its second probe onwards.
func TestAnAnnouncedEndpointIsProbedAtOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}

	disc := &config.Discovery{Type: "dns", Name: "backend.example.", Port: n,
		Interval: config.Duration(time.Hour), Timeout: config.Duration(time.Second), Weight: 1}
	cfg := upstreamCfg(disc, "10.9.9.9:"+port)
	cfg.HealthCheck = &config.HealthCheck{Type: "tcp", Interval: config.Duration(time.Hour),
		Timeout: config.Duration(time.Second), HealthyThreshold: 1, UnhealthyThreshold: 1, MaxConcurrent: 4}
	p, err := NewPool(cfg, nolog)
	if err != nil {
		t.Fatal(err)
	}
	fl := &fakeLookup{}
	fl.set("backend.example.")
	p.SetLookupForTest(fl)
	p.Start()
	defer p.Stop()

	fl.set("backend.example.", "127.0.0.1")
	p.ResolveNowForTest()
	e := find(t, p, "127.0.0.1:"+port)
	if e.Healthy() {
		t.Fatal("the announcement did not wait for a probe, so this proves nothing")
	}
	// An hour of jitter would leave it unhealthy here; a probe run at once
	// reaches the listener in milliseconds.
	waitHealthy(t, e, true, "an announced endpoint whose port accepts")
}
