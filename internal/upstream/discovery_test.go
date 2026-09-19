package upstream

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

var dlog = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeLookup answers from fixed tables and can fail on demand.
type fakeLookup struct {
	mu   sync.Mutex
	ips  map[string][]string
	srv  map[string][]*net.SRV
	fail error
}

func (f *fakeLookup) set(name string, ips ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ips == nil {
		f.ips = map[string][]string{}
	}
	f.ips[name] = ips
}

func (f *fakeLookup) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	out := make([]net.IPAddr, 0, len(f.ips[host]))
	for _, s := range f.ips[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

func (f *fakeLookup) LookupSRV(_ context.Context, _, _, name string) (string, []*net.SRV, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return "", nil, f.fail
	}
	return name, f.srv[name], nil
}

func upstreamCfg(disc *config.Discovery, static ...string) *config.Upstream {
	u := &config.Upstream{Name: "u", Scheme: "http", Balancer: "round_robin", Discovery: disc, MaxIdleConnsPerHost: 2,
		Timeouts: config.UpstreamTimeout{Connect: config.Duration(time.Second), ResponseHeader: config.Duration(time.Second), Idle: config.Duration(time.Second), Total: config.Duration(time.Second)}}
	for _, a := range static {
		u.Endpoints = append(u.Endpoints, config.Endpoint{Address: a, Weight: 1})
	}
	return u
}

func addresses(p *Pool) []string {
	out := make([]string, 0, len(p.Endpoints()))
	for _, e := range p.Endpoints() {
		out = append(out, e.Address)
	}
	sort.Strings(out)
	return out
}

func TestDiscoveryDNS(t *testing.T) {
	disc := &config.Discovery{Type: "dns", Name: "backend.example.", Port: 8080, Interval: config.Duration(time.Hour), Timeout: config.Duration(time.Second), Weight: 2}
	p, err := NewPool(upstreamCfg(disc, "10.9.9.9:8080"), dlog)
	if err != nil {
		t.Fatal(err)
	}
	fl := &fakeLookup{}
	fl.set("backend.example.", "10.0.0.1", "10.0.0.2")
	p.SetLookupForTest(fl)
	p.Start()
	defer p.Stop()
	if got := addresses(p); len(got) != 3 || got[0] != "10.0.0.1:8080" || got[2] != "10.9.9.9:8080" {
		t.Fatalf("after start: %v", got)
	}
	// Traffic on a discovered endpoint, then a change: the surviving
	// endpoint keeps its object and counters, the gone one disappears.
	var kept *Endpoint
	for _, e := range p.Endpoints() {
		if e.Address == "10.0.0.2:8080" {
			kept = e
			if !e.Discovered || e.Weight != 2 {
				t.Fatalf("discovered endpoint %+v", e)
			}
		}
	}
	p.Begin(kept)
	p.End(kept, false, 0)
	fl.set("backend.example.", "10.0.0.2", "10.0.0.3")
	p.ResolveNowForTest()
	if got := addresses(p); len(got) != 3 || got[0] != "10.0.0.2:8080" || got[1] != "10.0.0.3:8080" {
		t.Fatalf("after change: %v", got)
	}
	for _, e := range p.Endpoints() {
		if e.Address == "10.0.0.2:8080" && (e != kept || e.requests.Load() != 1) {
			t.Fatal("surviving endpoint was replaced")
		}
	}
	st := p.Status()
	if st.Discovery == nil || st.Discovery.Endpoints != 2 || st.Discovery.Changes != 2 || st.Discovery.Resolutions != 2 || st.Discovery.Errors != 0 {
		t.Fatalf("discovery status %+v", st.Discovery)
	}
	// A failure keeps the set and is counted.
	fl.mu.Lock()
	fl.fail = errors.New("SERVFAIL")
	fl.mu.Unlock()
	p.ResolveNowForTest()
	if got := addresses(p); len(got) != 3 {
		t.Fatalf("failed resolution changed the set: %v", got)
	}
	if st := p.Status(); st.Discovery.Errors != 1 || st.Discovery.LastError == "" {
		t.Fatalf("error not recorded: %+v", st.Discovery)
	}
	// Static endpoint is never removed; picks reach discovered endpoints.
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		seen[e.Address] = true
	}
	if len(seen) != 3 {
		t.Fatalf("picks %v", seen)
	}
}

func TestDiscoverySRV(t *testing.T) {
	disc := &config.Discovery{Type: "srv", Name: "_http._tcp.svc.example.", Interval: config.Duration(time.Hour), Timeout: config.Duration(time.Second), Weight: 1}
	p, err := NewPool(upstreamCfg(disc), dlog)
	if err != nil {
		t.Fatal(err)
	}
	fl := &fakeLookup{srv: map[string][]*net.SRV{"_http._tcp.svc.example.": {
		{Target: "a.example.", Port: 8081, Priority: 10, Weight: 60},
		{Target: "b.example.", Port: 8082, Priority: 10, Weight: 40},
		{Target: "backup.example.", Port: 9000, Priority: 20, Weight: 1},
	}}}
	fl.set("a.example.", "10.1.0.1")
	fl.set("b.example.", "10.1.0.2", "10.1.0.3")
	fl.set("backup.example.", "10.1.0.9")
	p.SetLookupForTest(fl)
	p.Start()
	defer p.Stop()
	got := addresses(p)
	if len(got) != 3 || got[0] != "10.1.0.1:8081" || got[1] != "10.1.0.2:8082" || got[2] != "10.1.0.3:8082" {
		t.Fatalf("srv endpoints: %v (backup priority must be excluded)", got)
	}
	for _, e := range p.Endpoints() {
		if e.Address == "10.1.0.1:8081" && e.Weight != 60 || e.Address == "10.1.0.2:8082" && e.Weight != 40 {
			t.Fatalf("weights %s=%d", e.Address, e.Weight)
		}
	}
	// Hash balancer rebuilds its ring on change.
	hp, _ := NewPool(func() *config.Upstream { u := upstreamCfg(disc); u.Balancer = "hash"; return u }(), dlog)
	hp.SetLookupForTest(fl)
	hp.Start()
	defer hp.Stop()
	e1, _ := hp.Pick("key", "", nil, CanaryAny)
	fl.set("a.example.", "10.1.0.1")
	fl.set("b.example.", "10.1.0.2")
	hp.ResolveNowForTest()
	if len(hp.Endpoints()) != 2 {
		t.Fatalf("ring pool endpoints %v", addresses(hp))
	}
	e2, _ := hp.Pick("key", "", nil, CanaryAny)
	if e2 == nil || (e1.Address != "10.1.0.3:8082" && e2 != e1) {
		t.Fatalf("hash stability: before %v after %v", e1, e2)
	}
}

func TestSlowStart(t *testing.T) {
	u := upstreamCfg(nil, "10.0.0.1:80", "10.0.0.2:80")
	u.SlowStart = config.Duration(10 * time.Second)
	p, err := NewPool(u, dlog)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return now }
	eps := p.Endpoints()
	a, b := eps[0], eps[1]
	if a.ramp(now) != 1 || b.ramp(now) != 1 {
		t.Fatal("endpoints present at start must not ramp")
	}
	// b recovers: the ramp runs from 10 % to 100 % over 10 s.
	b.startRamp(now)
	if r := b.ramp(now); r < 0.09 || r > 0.11 {
		t.Fatalf("ramp at start %v", r)
	}
	if r := b.ramp(now.Add(5 * time.Second)); r < 0.54 || r > 0.56 {
		t.Fatalf("ramp half way %v", r)
	}
	if r := b.ramp(now.Add(10 * time.Second)); r != 1 || b.readyNS.Load() != 0 {
		t.Fatalf("ramp at the end %v (ready %d)", r, b.readyNS.Load())
	}
	// Round robin with a deterministic coin: at 10 % b keeps one pick in
	// ten, the rest go to a.
	b.startRamp(now)
	seq, i := []float64{0.05, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5}, 0
	p.randFloat = func() float64 { v := seq[i%len(seq)]; i++; return v }
	counts := map[*Endpoint]int{}
	for n := 0; n < 200; n++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		counts[e]++
	}
	if counts[b] == 0 || counts[b] > 30 || counts[a] < 170 {
		t.Fatalf("slow start shares a=%d b=%d", counts[a], counts[b])
	}
	// With only b available the ramp never blocks it.
	a.healthy.Store(false)
	for n := 0; n < 5; n++ {
		if e, _ := p.Pick("", "", nil, CanaryAny); e != b {
			t.Fatal("ramping endpoint refused although alone")
		}
	}
	a.healthy.Store(true)
	// Weighted balancer scales the weight instead.
	if w := b.effectiveWeight(now); w != 1 {
		t.Fatalf("effective weight at 10 %% of weight 1: %d", w)
	}
	b.Weight = 100
	if w := b.effectiveWeight(now.Add(5 * time.Second)); w < 50 || w > 60 {
		t.Fatalf("effective weight half way %d", w)
	}
	// Ejection schedules the ramp from the ejection's end.
	u.OutlierEjection = &config.OutlierEjection{ConsecutiveFailures: 1, BaseEjectionTime: config.Duration(30 * time.Second), MaxEjectionPercent: 100}
	p.End(a, true, 0)
	if a.readyNS.Load() != now.Add(30*time.Second).UnixNano() {
		t.Fatalf("ramp start after ejection %d", a.readyNS.Load())
	}
	if st := p.Stats(); st[0].Ramp != 0.1 && st[0].Ramp != 1 {
		t.Fatalf("stats ramp %v", st[0].Ramp)
	}
	if p.Status().SlowStart != "10s" {
		t.Fatalf("status %+v", p.Status())
	}
}
