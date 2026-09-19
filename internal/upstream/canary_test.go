package upstream

import (
	"net/http"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func TestCanary(t *testing.T) {
	c := testCfg("round_robin", "a:1", "b:1", "c:1")
	c.Endpoints[2].Canary = true
	c.Canary = &config.Canary{Header: "x-canary", Cookie: "beta", Values: []string{"1", "on"}}
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	a, b, cn := p.endpoints()[0], p.endpoints()[1], p.endpoints()[2]
	req := func(kv ...string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		for i := 0; i+1 < len(kv); i += 2 {
			r.Header.Add(kv[i], kv[i+1])
		}
		return r
	}
	if m := p.CanaryMode(req()); m != CanaryAvoid {
		t.Fatalf("plain request: %v", m)
	}
	if m := p.CanaryMode(req("X-Canary", "1")); m != CanaryOnly {
		t.Fatalf("header: %v", m)
	}
	if m := p.CanaryMode(req("X-Canary", "2")); m != CanaryAvoid {
		t.Fatalf("header with other value: %v", m)
	}
	if m := p.CanaryMode(req("Cookie", "beta=on; x=1")); m != CanaryOnly {
		t.Fatalf("cookie: %v", m)
	}
	if m := p.CanaryMode(req("Cookie", "beta=off")); m != CanaryAvoid {
		t.Fatalf("cookie with other value: %v", m)
	}
	// Avoid never picks the canary; Only always does.
	for i := 0; i < 6; i++ {
		if e, _ := p.Pick("", "", nil, CanaryAvoid); e == cn {
			t.Fatal("ordinary traffic reached the canary")
		}
		if e, _ := p.Pick("", "", nil, CanaryOnly); e != cn {
			t.Fatalf("canary traffic reached %s", e.Address)
		}
	}
	// Fallback: with the canary unavailable, canary traffic goes to the rest;
	// with the rest unavailable, ordinary traffic goes to the canary.
	cn.healthy.Store(false)
	if e, _ := p.Pick("", "", nil, CanaryOnly); e == nil || e == cn {
		t.Fatalf("no fallback from the canary: %v", e)
	}
	cn.healthy.Store(true)
	a.healthy.Store(false)
	b.healthy.Store(false)
	if e, _ := p.Pick("", "", nil, CanaryAvoid); e != cn {
		t.Fatalf("no fallback to the canary: %v", e)
	}
	st := p.Status()
	if st.Canary == nil || st.Canary.Endpoints != 1 || st.Canary.Fallbacks != 2 || st.Canary.Requests < 7 || st.Canary.Header != "X-Canary" {
		t.Fatalf("status %+v", st.Canary)
	}
	// fallback: false refuses instead.
	off := false
	c.Canary.Fallback = &off
	p, _ = NewPool(c, nolog)
	p.endpoints()[0].healthy.Store(false)
	p.endpoints()[1].healthy.Store(false)
	if e, _ := p.Pick("", "", nil, CanaryAvoid); e != nil {
		t.Fatalf("fallback off still fell back to %s", e.Address)
	}
	// A pure percentage split selects roughly the share.
	c.Canary = &config.Canary{Percent: 50}
	p, _ = NewPool(c, nolog)
	only := 0
	for i := 0; i < 2000; i++ {
		if p.CanaryMode(req()) == CanaryOnly {
			only++
		}
	}
	if only < 800 || only > 1200 {
		t.Fatalf("50 %% split gave %d of 2000", only)
	}
	// Without a policy the mode is Any and canary flags are inert.
	c.Canary = nil
	p, _ = NewPool(c, nolog)
	if p.CanaryMode(req("X-Canary", "1")) != CanaryAny {
		t.Fatal("mode without policy")
	}
	seen := map[*Endpoint]bool{}
	for i := 0; i < 6; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		seen[e] = true
	}
	if len(seen) != 3 {
		t.Fatalf("canary excluded without a policy: %d endpoints", len(seen))
	}
	_ = time.Now
}
