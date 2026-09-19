package upstream

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/secret"
)

func testCfg(bal string, addrs ...string) *config.Upstream {
	c := &config.Upstream{Name: "t", Balancer: bal, Scheme: "http",
		Timeouts:            config.UpstreamTimeout{Connect: config.Duration(time.Second), ResponseHeader: config.Duration(time.Second), Idle: config.Duration(time.Second), Total: config.Duration(time.Second)},
		MaxIdleConnsPerHost: 2}
	for _, a := range addrs {
		c.Endpoints = append(c.Endpoints, config.Endpoint{Address: a, Weight: 1})
	}
	return c
}

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestRoundRobin(t *testing.T) {
	p, err := NewPool(testCfg("round_robin", "a:1", "b:1", "c:1"), nolog)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := 0; i < 6; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		got = append(got, e.Address)
	}
	if s := strings.Join(got, ","); s != "a:1,b:1,c:1,a:1,b:1,c:1" {
		t.Fatal(s)
	}
	p.endpoints()[1].healthy.Store(false)
	got = got[:0]
	for i := 0; i < 4; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		got = append(got, e.Address)
	}
	if s := strings.Join(got, ","); s != "a:1,c:1,a:1,c:1" {
		t.Fatal(s)
	}
	p.endpoints()[0].healthy.Store(false)
	p.endpoints()[2].healthy.Store(false)
	if e, _ := p.Pick("", "", nil, CanaryAny); e != nil {
		t.Fatal("all down should return nil")
	}
}

func TestWeighted(t *testing.T) {
	c := testCfg("weighted", "a:1", "b:1")
	c.Endpoints[0].Weight = 3
	p, _ := NewPool(c, nolog)
	count := map[string]int{}
	var seq []string
	for i := 0; i < 8; i++ {
		e, _ := p.Pick("", "", nil, CanaryAny)
		count[e.Address]++
		seq = append(seq, e.Address[:1])
	}
	if count["a:1"] != 6 || count["b:1"] != 2 {
		t.Fatal(count)
	}
	if s := strings.Join(seq, ""); strings.Contains(s, "aaaa") {
		t.Fatalf("not smooth: %s", s)
	}
}

func TestLeastConn(t *testing.T) {
	p, _ := NewPool(testCfg("least_conn", "a:1", "b:1"), nolog)
	e1, _ := p.Pick("", "", nil, CanaryAny)
	p.Begin(e1)
	e2, _ := p.Pick("", "", nil, CanaryAny)
	if e1 == e2 {
		t.Fatal("least_conn picked busy endpoint")
	}
	p.Begin(e2)
	p.End(e1, false)
	e3, _ := p.Pick("", "", nil, CanaryAny)
	if e3 != e1 {
		t.Fatal("least_conn should prefer idle endpoint")
	}
}

func TestHashRing(t *testing.T) {
	p, _ := NewPool(testCfg("hash", "a:1", "b:1", "c:1", "d:1"), nolog)
	first := map[string]string{}
	for i := 0; i < 200; i++ {
		k := "key" + string(rune(i))
		e, _ := p.Pick(k, "", nil, CanaryAny)
		first[k] = e.Address
	}
	// Stable.
	for k, want := range first {
		if e, _ := p.Pick(k, "", nil, CanaryAny); e.Address != want {
			t.Fatal("unstable hash")
		}
	}
	// Remove one endpoint: only its keys should move.
	p.endpoints()[0].healthy.Store(false)
	moved := 0
	for k, want := range first {
		e, _ := p.Pick(k, "", nil, CanaryAny)
		if want == "a:1" {
			if e.Address == "a:1" {
				t.Fatal("picked unhealthy")
			}
		} else if e.Address != want {
			moved++
		}
	}
	if moved != 0 {
		t.Fatalf("%d keys moved that should not have", moved)
	}
}

func TestAffinity(t *testing.T) {
	c := testCfg("round_robin", "a:1", "b:1")
	c.Affinity = &config.Affinity{CookieName: "S", TTL: config.Duration(time.Hour)}
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	e, cookie := p.Pick("", "", nil, CanaryAny)
	if cookie == "" {
		t.Fatal("no cookie issued")
	}
	for i := 0; i < 5; i++ {
		e2, c2 := p.Pick("", cookie, nil, CanaryAny)
		if e2 != e || c2 != "" {
			t.Fatal("affinity not honoured")
		}
	}
	// Tampered cookie is ignored.
	bad := cookie[:len(cookie)-2] + "AA"
	if _, c2 := p.Pick("", bad, nil, CanaryAny); c2 == "" {
		t.Fatal("tampered cookie accepted")
	}
	// Expired cookie is ignored.
	p.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, c2 := p.Pick("", cookie, nil, CanaryAny); c2 == "" {
		t.Fatal("expired cookie accepted")
	}
	// Unavailable endpoint falls through to the balancer.
	p.now = time.Now
	e.healthy.Store(false)
	e3, c3 := p.Pick("", cookie, nil, CanaryAny)
	if e3 == e || c3 == "" {
		t.Fatal("cookie to unhealthy endpoint should re-balance")
	}
	if p.aff.verify("", time.Now()) != -1 || p.aff.verify(strings.Repeat("A", 100), time.Now()) != -1 {
		t.Fatal("garbage accepted")
	}
}

func TestAffinityRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aff")
	c := testCfg("round_robin", "a:1", "b:1")
	c.Affinity = &config.Affinity{CookieName: "s", TTL: config.Duration(time.Hour), SecretFile: path}
	p1, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	e, cookie := p1.Pick("", "", nil, CanaryAny)
	if _, err := secret.Rotate(path, 1); err != nil {
		t.Fatal(err)
	}
	p2, err := NewPool(c, nolog) // a reload builds new pools from the rotated ring
	if err != nil {
		t.Fatal(err)
	}
	if e2, fresh := p2.Pick("", cookie, nil, CanaryAny); e2.Address != e.Address || fresh != "" {
		t.Fatalf("old cookie not honoured after rotation: %v %q", e2, fresh)
	}
	if _, err := secret.Rotate(path, 0); err != nil {
		t.Fatal(err)
	}
	p3, _ := NewPool(c, nolog)
	if _, fresh := p3.Pick("", cookie, nil, CanaryAny); fresh == "" {
		t.Fatal("cookie under a dropped key still accepted")
	}
}

func TestOutlierEjection(t *testing.T) {
	c := testCfg("round_robin", "a:1", "b:1")
	c.OutlierEjection = &config.OutlierEjection{ConsecutiveFailures: 2, BaseEjectionTime: config.Duration(time.Minute), MaxEjectionPercent: 50}
	p, _ := NewPool(c, nolog)
	a := p.endpoints()[0]
	p.Begin(a)
	p.End(a, true)
	if !a.Available(time.Now()) {
		t.Fatal("ejected too early")
	}
	p.Begin(a)
	p.End(a, true)
	if a.Available(time.Now()) {
		t.Fatal("not ejected")
	}
	// Max 50%: b may not be ejected too.
	b := p.endpoints()[1]
	for i := 0; i < 3; i++ {
		p.Begin(b)
		p.End(b, true)
	}
	if !b.Available(time.Now()) {
		t.Fatal("max_ejection_percent violated")
	}
	if !a.Available(time.Now().Add(2 * time.Minute)) {
		t.Fatal("ejection did not expire")
	}
}

func TestActiveHealthCheck(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hc" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	c := testCfg("round_robin", strings.TrimPrefix(srv.URL, "http://"))
	c.HealthCheck = &config.HealthCheck{Path: "/hc", Interval: config.Duration(500 * time.Millisecond), Timeout: config.Duration(200 * time.Millisecond), HealthyThreshold: 1, UnhealthyThreshold: 2, ExpectedStatus: []int{200}}
	p, _ := NewPool(c, nolog)
	p.Start()
	defer p.Stop()
	e := p.endpoints()[0]
	status.Store(500)
	wait := func(want bool) {
		deadline := time.Now().Add(5 * time.Second)
		for e.Healthy() != want && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if e.Healthy() != want {
			t.Fatalf("healthy=%v, want %v", e.Healthy(), want)
		}
	}
	wait(false)
	status.Store(200)
	wait(true)
	st := p.Stats()
	if len(st) != 1 || !st[0].Healthy {
		t.Fatal(st)
	}
}
