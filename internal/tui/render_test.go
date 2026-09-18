package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/upstream"
	"github.com/rom/xproxy/internal/waf"
)

func sample() Data {
	now := time.Unix(1_700_000_000, 0)
	return Data{
		At: now,
		Status: &mgmt.Status{Version: "1.2.3", PID: 42, Generation: 3, Routes: 5, Upstreams: 2,
			Listeners: map[string]string{"main": "127.0.0.1:443", "main/udp": "127.0.0.1:443"},
			Stats:     proxy.Snapshot{Requests: 1234567, Responses2xx: 1200000, OpenConnections: 17, LoadLevel: 0.42, SheddingClasses: []string{"low"}, BytesOut: 5 << 30, UptimeSeconds: 3700},
			Sandbox:   &sandbox.Status{Enabled: true, Mechanism: []sandbox.Mechanism{{Name: "landlock", State: sandbox.StateApplied}, {Name: "seccomp", State: sandbox.StateUnavailable}}}},
		Upstreams: map[string][]upstream.Stats{"web": {{Address: "10.0.0.1:8080", Weight: 1, Healthy: true, Requests: 10}, {Address: "10.0.0.2:8080", Weight: 2, Healthy: false, Ejected: true}}},
		Bans:      []ban.Entry{{Target: "203.0.113.5", Until: now.Add(time.Hour), Source: "manual", Count: 1, Reason: "scanner"}, {Target: "198.51.100.0/24", Until: now.Add(2 * time.Hour), Source: "peer:n2", Count: 2, Reason: "waf"}},
		Cluster:   &cluster.Status{NodeID: "n1", Listen: "10.0.0.1:7946", Peers: []cluster.PeerStatus{{Address: "10.0.0.2:7946", Connected: true, ConnectedAt: now.Add(-time.Minute)}, {Address: "10.0.0.3:7946", LastError: "dial timeout"}}, Inbound: []cluster.InboundStatus{{Remote: "10.0.0.2:5555", NodeID: "n2", CertName: "n2", LastSeen: now}}},
		Series: &mgmt.SeriesResponse{IntervalSeconds: 10, Names: []string{"requests", "denied", "load_level"}, Points: []mgmt.SeriesPoint{
			{Time: now.Add(-30 * time.Second), Values: []float64{10, 0, 0.1}}, {Time: now.Add(-20 * time.Second), Values: []float64{50, 5, 0.5}}, {Time: now.Add(-10 * time.Second), Values: []float64{100, 1, 0.9}}, {Time: now, Values: []float64{25, 0, 0.2}}}},
		LogLines: []string{`{"time":"2026-09-18T12:00:00.000Z","level":"WARN","msg":"security","stream":"security","action":"deny","reason":"waf","client_ip":"203.0.113.9","method":"GET","host":"a.test","path":"/x"}`,
			`{"time":"2026-09-18T12:00:01.000Z","level":"WARN","msg":"client banned","stream":"security","target":"203.0.113.9","reason":"waf"}`},
		Pools: map[string]upstream.PoolStatus{"web": {Name: "web", Balancer: "round_robin", Endpoints: 2, Available: 1,
			Circuit: &upstream.CircuitStatus{State: "half_open", Failures: 3, Opens: 2, Rejected: 40},
			Queue:   &upstream.QueueStatus{MaxConcurrent: 100, InFlight: 7, QueueSize: 50, Waiting: 2, Queued: 30, Timeouts: 1},
			Canary:  &upstream.CanaryStatus{Header: "X-Canary", Percent: 5, Endpoints: 1, Requests: 12, Fallbacks: 1}}},
		Quotas: &proxy.QuotaReport{Generation: 3,
			Tenants:    []proxy.TenantQuota{{Tenant: "shop", Routes: 2, Requests: 900, Denied: 3, BytesOut: 4096}},
			Routes:     []proxy.RouteQuota{{Route: "shop-web", Tenant: "shop", Upstream: "web", Requests: 900, Status2xx: 890, Status4xx: 7, Status5xx: 3, RateLimited: 2, BytesOut: 4096}},
			RateLimits: []proxy.PolicyQuota{{Policy: "api", Key: "client_ip", Rate: 10, Burst: 20, Keys: 3, Allowed: 500, Denied: 9, Top: []limits.KeyUsage{{Key: "203.0.113.9", Total: 300}}}}},
		WAF: &proxy.WAFReport{Enabled: true, Profiles: []waf.ProfileStatus{{Name: "default", Modes: []string{"block"}, CRS: "embedded", Version: "4250", RuleFiles: 21}},
			Routes: []proxy.WAFRoute{{Route: "shop-web", Profile: "default", Mode: "block"}},
			Report: waf.Report{Requests: 900, Blocked: 4, Detected: 1, TotalRules: 2,
				Rules:    []waf.RuleStat{{ID: 942100, Matches: 4, Blocks: 4, Severity: "critical", Message: "SQL Injection Attack Detected via libinjection", LastSeen: now}},
				Learning: &waf.LearningReport{Enabled: true, MinHits: 5, Entries: 3, MaxEntries: 10000, Proposals: []waf.Proposal{{Rule: 941100, Target: "ARGS:body", Route: "posts", Hits: 12, Clients: 4, Message: "XSS", Directive: "SecRule ..."}}}}},
		TLS: map[string][]tlsconf.CertInfo{"main": {{Names: []string{"a.test", "www.a.test"}, Issuer: "Example CA", NotAfter: time.Now().Add(20 * 24 * time.Hour), Managed: true,
			OCSP: tlsconf.OCSPStatus{Status: "good"}, CT: tlsconf.CTStatus{Required: 2, Verified: 2, OK: true}}}},
		Telemetry: &mgmt.TelemetryView{Traces: &tracing.Status{Enabled: true, Sampled: 10, Sent: 9, Failed: 1}},
		DNS:       []dns.Status{{Listener: "dns", Queries: 100, QueriesUDP: 80, QueriesTCP: 20, CacheHits: 60, Blocked: 5, DNSSEC: &dns.DNSSECStatus{Enabled: true, Secure: 40, Bogus: 1}}},
		Errors:    map[string]string{},
	}
}

func TestRenderAllViewsFit(t *testing.T) {
	d := sample()
	for v := View(0); v < viewCount; v++ {
		for _, size := range [][2]int{{80, 24}, {120, 40}, {40, 8}} {
			st := State{View: v, Width: size[0], Height: size[1], Refresh: 2 * time.Second}
			for _, sty := range []Style{Plain, ANSI} {
				lines := Render(d, st, sty)
				if len(lines) != size[1] {
					t.Fatalf("view %d %v: %d lines for height %d", v, size, len(lines), size[1])
				}
				for i, l := range lines {
					if visibleLen(l) > size[0] {
						t.Fatalf("view %d %v line %d too wide (%d): %q", v, size, i, visibleLen(l), l)
					}
				}
			}
		}
	}
}

func TestRenderContent(t *testing.T) {
	d := sample()
	st := State{View: ViewOverview, Width: 120, Height: 32, Refresh: 2 * time.Second}
	out := strings.Join(Render(d, st, Plain), "\n")
	for _, want := range []string{"xproxy 1.2.3", "1234567", "shedding: low", "5.0 GiB", "req/s", "gen 3", "listener main ", "sandbox    landlock  seccomp=unavailable", "traces sampled 10 sent 9 failed 1", "dns dns ", "dnssec secure 40 insecure 0 bogus 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("overview missing %q:\n%s", want, out)
		}
	}
	st.View = ViewUpstreams
	out = strings.Join(Render(d, st, Plain), "\n")
	if !strings.Contains(out, "10.0.0.2:8080") || !strings.Contains(out, "NO") || !strings.Contains(out, "YES") {
		t.Fatalf("upstreams:\n%s", out)
	}
	if !strings.Contains(out, "circuit half_open failures 3 opens 2 rejected 40") || !strings.Contains(out, "in flight 7/100 queued 2/50") || !strings.Contains(out, "canary 5% requests 12 fallbacks 1") {
		t.Fatalf("pool line:\n%s", out)
	}
	st.View = ViewRoutes
	out = strings.Join(Render(d, st, Plain), "\n")
	for _, want := range []string{"shop-web", "TENANT", "shop ", "203.0.113.9=300", "4.0 KiB"} {
		if !strings.Contains(out, want) {
			t.Fatalf("routes missing %q:\n%s", want, out)
		}
	}
	st.View = ViewWAF
	out = strings.Join(Render(d, st, Plain), "\n")
	for _, want := range []string{"requests 900  blocked 4  detected 1", "learning on  min hits 5", "default          block", "embedded", "4250", "942100", "libinjection", "941100", "ARGS:body", "shop-web=default/block"} {
		if !strings.Contains(out, want) {
			t.Fatalf("waf missing %q:\n%s", want, out)
		}
	}
	st.View = ViewTLS
	out = strings.Join(Render(d, st, Plain), "\n")
	for _, want := range []string{"main", "a.test,www.a.test", "Example CA", "acme", "good", "2/2", "20d"} {
		if !strings.Contains(out, want) {
			t.Fatalf("tls missing %q:\n%s", want, out)
		}
	}
	// Views without data.
	empty := Data{At: d.At, Status: d.Status, Errors: map[string]string{}}
	for _, v := range []View{ViewRoutes, ViewWAF, ViewTLS, ViewUpstreams} {
		st.View = v
		if lines := Render(empty, st, Plain); len(lines) != st.Height {
			t.Fatalf("empty view %d: %d lines", v, len(lines))
		}
	}
	st.View, st.Selected = ViewBans, 1
	out = strings.Join(Render(d, st, Plain), "\n")
	if !strings.Contains(out, "> 198.51.100.0/24") || !strings.Contains(out, "peer:n2") || !strings.Contains(out, "u unban") {
		t.Fatalf("bans:\n%s", out)
	}
	st.View = ViewCluster
	out = strings.Join(Render(d, st, Plain), "\n")
	if !strings.Contains(out, "node n1") || !strings.Contains(out, "dial timeout") || !strings.Contains(out, "INBOUND") {
		t.Fatalf("cluster:\n%s", out)
	}
	st.View = ViewGraphs
	out = strings.Join(Render(d, st, Plain), "\n")
	if !strings.Contains(out, "requests") || !strings.Contains(out, "▁") || !strings.Contains(out, "█") || !strings.Contains(out, "(max 100)") {
		t.Fatalf("graphs:\n%s", out)
	}
	st.View = ViewLog
	out = strings.Join(Render(d, st, Plain), "\n")
	if !strings.Contains(out, "12:00:00 deny waf 203.0.113.9 GET a.test /x") || !strings.Contains(out, "client banned 203.0.113.9") {
		t.Fatalf("log:\n%s", out)
	}
	// Errors are shown; missing status is handled.
	d.Errors["cluster"] = "connection refused"
	d.Status = nil
	st.View = ViewOverview
	out = strings.Join(Render(d, st, Plain), "\n")
	if !strings.Contains(out, "management API unavailable") || !strings.Contains(out, "! cluster: connection refused") {
		t.Fatalf("errors:\n%s", out)
	}
	// Prompt and message lines.
	st.Prompt, st.Input = "ban <address>:", "1.2.3.4"
	out = Render(d, st, Plain)[st.Height-1]
	if !strings.Contains(out, "ban <address>: 1.2.3.4_") {
		t.Fatalf("prompt: %q", out)
	}
}

func TestHelpers(t *testing.T) {
	if visibleLen("\x1b[31mred\x1b[0m") != 3 || clip("abcdef", 4) != "abc…" || clip("\x1b[1mabcdef\x1b[0m", 4) != "\x1b[1mabc…\x1b[0m" {
		t.Fatal("ansi helpers")
	}
	if pad("a", "b", 5) != "a   b" || visibleLen(pad("aaaa", "bbbb", 5)) > 5 {
		t.Fatal("pad")
	}
	if humanBytes(1023) != "1023 B" || humanBytes(1536) != "1.5 KiB" || fmtNum(1500) != "1.5k" || fmtNum(2) != "2" || fmtNum(0.5) != "0.50" {
		t.Fatal("formatting")
	}
	if got := sparkRow("x", nil, 5, Plain); !strings.HasPrefix(got, "x") {
		t.Fatal("empty spark")
	}
}

func TestKeys(t *testing.T) {
	d := sample()
	st := State{Refresh: 2 * time.Second}
	var banned, unbanned string
	act := Actions{
		Ban:   func(target, dur, reason string) error { banned = target + "/" + dur + "/" + reason; return nil },
		Unban: func(target string) error { unbanned = target; return errors.New("nope") },
	}
	if q, _ := handleKey(&st, []byte("q"), &d, act); !q {
		t.Fatal("q should quit")
	}
	handleKey(&st, []byte("\t"), &d, act)
	handleKey(&st, []byte("\t"), &d, act)
	if st.View != ViewBans {
		t.Fatalf("tab: %v", st.View)
	}
	handleKey(&st, []byte("5"), &d, act)
	if st.View != ViewGraphs {
		t.Fatal("digit")
	}
	handleKey(&st, []byte("\x1b[Z"), &d, act)
	if st.View != ViewCluster {
		t.Fatal("shift-tab")
	}
	if _, r := handleKey(&st, []byte("+"), &d, act); !r || st.Refresh != 4*time.Second {
		t.Fatal("interval up")
	}
	handleKey(&st, []byte("-"), &d, act)
	handleKey(&st, []byte("-"), &d, act)
	handleKey(&st, []byte("-"), &d, act)
	if st.Refresh != 500*time.Millisecond {
		t.Fatalf("interval floor %v", st.Refresh)
	}
	handleKey(&st, []byte("p"), &d, act)
	if !st.Paused {
		t.Fatal("pause")
	}
	// Ban prompt with input, backspace and submit.
	handleKey(&st, []byte("3"), &d, act)
	handleKey(&st, []byte("b"), &d, act)
	if st.Prompt == "" {
		t.Fatal("no prompt")
	}
	for _, ch := range "10.0.0.9 2h scannerX" {
		handleKey(&st, []byte(string(ch)), &d, act)
	}
	handleKey(&st, []byte("\x7f"), &d, act)
	if _, r := handleKey(&st, []byte("\r"), &d, act); !r || banned != "10.0.0.9/2h/scanner" || st.Prompt != "" || st.Message != "banned 10.0.0.9 for 2h" {
		t.Fatalf("ban: %q %q %q", banned, st.Prompt, st.Message)
	}
	// Unban with confirmation and an error from the API.
	handleKey(&st, []byte("j"), &d, act)
	handleKey(&st, []byte("u"), &d, act)
	handleKey(&st, []byte("y"), &d, act)
	handleKey(&st, []byte("\r"), &d, act)
	if unbanned != "198.51.100.0/24" || !strings.HasPrefix(st.Message, "unban failed") {
		t.Fatalf("unban: %q %q", unbanned, st.Message)
	}
	// Escape cancels a prompt.
	handleKey(&st, []byte("u"), &d, act)
	handleKey(&st, []byte("\x1b"), &d, act)
	if st.Prompt != "" || st.Message != "cancelled" {
		t.Fatal("escape")
	}
}

type fakeSource struct{ d Data }

func (f fakeSource) Fetch(context.Context) Data { return f.d }

func TestRunRequiresTerminal(t *testing.T) {
	r, w, _ := osPipe(t)
	defer r.Close()
	defer w.Close()
	if err := Run(fakeSource{sample()}, Actions{}, Options{In: r}); err == nil {
		t.Fatal("expected an error without a terminal")
	}
}
