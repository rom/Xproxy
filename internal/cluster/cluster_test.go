package cluster

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/testutil"
)

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeRates records reports and serves queued flushes.
type fakeRates struct {
	mu      sync.Mutex
	pending map[string]map[string]float64
	reports []report
	decided []string
}

type report struct {
	peer, policy string
	reports      []limits.PeerReport
}

func (f *fakeRates) Flush(int) map[string]map[string]float64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.pending
	f.pending = nil
	return out
}

func (f *fakeRates) Report(peer, policy string, rs []limits.PeerReport) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, report{peer, policy, rs})
}

// Decide answers exact requests: policy "exact" allows keys that do not
// start with "deny" and records the call; other policies are unknown.
func (f *fakeRates) Decide(policy, key string, n float64) (bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decided = append(f.decided, policy+"/"+key)
	if policy != "exact" {
		return false, false
	}
	return !strings.HasPrefix(key, "deny"), true
}

func (f *fakeRates) queue(policy, key string, n float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending == nil {
		f.pending = map[string]map[string]float64{}
	}
	if f.pending[policy] == nil {
		f.pending[policy] = map[string]float64{}
	}
	f.pending[policy][key] += n
}

func (f *fakeRates) got() []report {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]report(nil), f.reports...)
}

type testNode struct {
	node  *Node
	rates *fakeRates
	bans  *ban.List
	addr  string
}

func clusterCfg(id, cert, key, ca string, peers []string, allowed ...string) *config.Cluster {
	return &config.Cluster{
		NodeID: id, Listen: "127.0.0.1:0", Peers: peers,
		TLS:            config.ClusterTLS{CertFile: cert, KeyFile: key, CAFile: ca, AllowedNames: allowed},
		GossipInterval: config.Duration(100 * time.Millisecond),
		PeerStale:      config.Duration(time.Second), MaxKeysPerReport: 100,
	}
}

func startNode(t *testing.T, cfg *config.Cluster) *testNode {
	t.Helper()
	rates := &fakeRates{}
	n, err := New(cfg, rates, nolog)
	if err != nil {
		t.Fatal(err)
	}
	bl, err := ban.New(&config.Bans{MaxEntries: 1000, Action: "reject"}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	n.AttachBans(bl)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n.Start(ln)
	t.Cleanup(func() { n.Stop(); bl.Close() })
	return &testNode{node: n, rates: rates, bans: bl, addr: ln.Addr().String()}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestTwoNodes(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	ac, ak := ca.Issue(t, dir, "node-a")
	bc, bk := ca.Issue(t, dir, "node-b")

	a := startNode(t, clusterCfg("a", ac, ak, ca.Path, nil))
	b := startNode(t, clusterCfg("b", bc, bk, ca.Path, []string{a.addr}))
	a.node.Reconfigure(clusterCfg("a", ac, ak, ca.Path, []string{b.addr}))

	waitFor(t, "connections", func() bool { return a.node.ConnectedPeers() == 1 && b.node.ConnectedPeers() == 1 })

	// Bans propagate both ways, including a snapshot to a late joiner.
	if _, err := a.bans.Ban("203.0.113.10", time.Hour, "from-a"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "ban a->b", func() bool { return b.bans.Banned(netip.MustParseAddr("203.0.113.10")) })
	// The source is the peer's certificate name ("node-a"), not the node
	// id it announced ("a"): the certificate is authenticated and the
	// announced id is not, so only the certificate name makes the audit
	// trail something a rogue peer cannot write in another node's name.
	for _, e := range b.bans.Entries() {
		if e.Target == "203.0.113.10" && e.Source != "peer:node-a" {
			t.Fatalf("source %q", e.Source)
		}
	}
	if err := a.bans.Unban("203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unban a->b", func() bool { return !b.bans.Banned(netip.MustParseAddr("203.0.113.10")) })

	// Rates: consumption queued on a reaches b as a rate.
	a.rates.queue("per-ip", "198.51.100.1", 20)
	waitFor(t, "rates a->b", func() bool { return len(b.rates.got()) > 0 })
	r := b.rates.got()[0]
	if r.peer != "node-a" || r.policy != "per-ip" || len(r.reports) != 1 || r.reports[0].Key != "198.51.100.1" || r.reports[0].Rate < 50 {
		t.Fatalf("report %+v", r)
	}

	// Late joiner receives the ban snapshot.
	if _, err := b.bans.Ban("203.0.113.11", time.Hour, "from-b"); err != nil {
		t.Fatal(err)
	}
	cc, ck := ca.Issue(t, dir, "node-c")
	c := startNode(t, clusterCfg("c", cc, ck, ca.Path, nil))
	b.node.Reconfigure(clusterCfg("b", bc, bk, ca.Path, []string{a.addr, c.addr}))
	waitFor(t, "snapshot b->c", func() bool { return c.bans.Banned(netip.MustParseAddr("203.0.113.11")) })

	st := a.node.Status()
	if st.NodeID != "a" || len(st.Peers) != 1 || !st.Peers[0].Connected || len(st.Inbound) != 1 || st.Inbound[0].NodeID != "b" || st.BansSent < 2 || st.RatesSent < 1 {
		t.Fatalf("status %+v", st)
	}

	// Dropping a peer from the configuration closes it.
	b.node.Reconfigure(clusterCfg("b", bc, bk, ca.Path, []string{c.addr}))
	waitFor(t, "peer removed", func() bool { return len(a.node.Status().Inbound) == 0 })
}

func TestEvents(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	ac, ak := ca.Issue(t, dir, "node-a")
	bc, bk := ca.Issue(t, dir, "node-b")

	a := startNode(t, clusterCfg("a", ac, ak, ca.Path, nil))
	b := startNode(t, clusterCfg("b", bc, bk, ca.Path, nil))
	var mu sync.Mutex
	var got []Event
	var peers []string
	b.node.OnEvent(func(e Event, peer string) {
		mu.Lock()
		got = append(got, e)
		peers = append(peers, peer)
		mu.Unlock()
	})
	a.node.Reconfigure(clusterCfg("a", ac, ak, ca.Path, []string{b.addr}))
	waitFor(t, "connection", func() bool { return a.node.ConnectedPeers() == 1 })

	until := time.Now().Add(time.Hour).Truncate(time.Second)
	a.node.PublishEvent(Event{Kind: "honeypot_mark", Key: "203.0.113.5", Route: "wp", Until: until})
	a.node.PublishEvent(Event{Kind: "", Key: "x", Until: until})                               // no kind: dropped
	a.node.PublishEvent(Event{Kind: "k", Key: "", Until: until})                               // no key: dropped
	a.node.PublishEvent(Event{Kind: "k", Key: "expired", Until: time.Now().Add(-time.Second)}) // in the past: dropped
	a.node.PublishEvent(Event{Kind: "forever", Key: "y", Until: time.Now().Add(10 * 365 * 24 * time.Hour)})
	waitFor(t, "events a->b", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 })
	mu.Lock()
	defer mu.Unlock()
	// peers[0] is the certificate name, as for bans above.
	if got[0].Kind != "honeypot_mark" || got[0].Key != "203.0.113.5" || got[0].Route != "wp" || !got[0].Until.Equal(until) || peers[0] != "node-a" {
		t.Fatalf("event %+v from %q", got[0], peers[0])
	}
	if got[1].Until.After(time.Now().Add(maxEventTTL)) {
		t.Fatalf("lifetime not clamped: %v", got[1].Until)
	}
	// Counters are updated after the send returns, so wait for them.
	waitFor(t, "sent counter", func() bool { return a.node.Status().EventsSent == 2 })
	waitFor(t, "received counter", func() bool { return b.node.Status().EventsRecv == 2 })

	// share_events: false silences both directions.
	off := false
	cfg := clusterCfg("a", ac, ak, ca.Path, []string{b.addr})
	cfg.ShareEvents = &off
	a.node.Reconfigure(cfg)
	a.node.PublishEvent(Event{Kind: "k", Key: "z", Until: until})
	time.Sleep(300 * time.Millisecond)
	if len(got) != 2 {
		t.Fatalf("event sent while sharing is off: %+v", got)
	}
}

func TestRejectsUnauthenticated(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	ac, ak := ca.Issue(t, dir, "node-a")
	a := startNode(t, clusterCfg("a", ac, ak, ca.Path, nil, "node-a", "node-b"))

	// No client certificate.
	conn, err := tls.Dial("tcp", a.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // test
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write([]byte(`{"t":"ping"}` + "\n"))
		if err == nil {
			_, err = conn.Read(make([]byte, 1))
		}
		conn.Close()
		if err == nil {
			t.Fatal("connection without client certificate survived")
		}
	}
	// Certificate from another CA.
	other := testutil.WriteCA(t, dir)
	oc, ok := other.Issue(t, dir, "node-b")
	cert, _ := tls.LoadX509KeyPair(oc, ok)
	conn, err = tls.Dial("tcp", a.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}) //nolint:gosec // test
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write([]byte(`{"t":"ping"}` + "\n"))
		if err == nil {
			_, err = conn.Read(make([]byte, 1))
		}
		conn.Close()
		if err == nil {
			t.Fatal("foreign CA accepted")
		}
	}
	// Right CA, wrong name.
	xc, xk := ca.Issue(t, dir, "node-x")
	x := startNode(t, clusterCfg("x", xc, xk, ca.Path, []string{a.addr}))
	time.Sleep(500 * time.Millisecond)
	if x.node.ConnectedPeers() != 0 && len(a.node.Status().Inbound) != 0 {
		t.Fatal("peer outside allowed_names accepted")
	}
	waitFor(t, "rejection counted", func() bool { return a.node.Status().Rejected >= 2 })
}

func TestProtocolErrors(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	ac, ak := ca.Issue(t, dir, "node-a")
	bc, bk := ca.Issue(t, dir, "node-b")
	a := startNode(t, clusterCfg("a", ac, ak, ca.Path, nil))
	cert, _ := tls.LoadX509KeyPair(bc, bk)
	dial := func() *tls.Conn {
		c, err := tls.Dial("tcp", a.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		return c
	}
	expectClosed := func(c *tls.Conn, payload string) {
		t.Helper()
		if _, err := c.Write([]byte(payload)); err != nil {
			return
		}
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatalf("connection survived %q", payload)
		}
		c.Close()
	}
	expectClosed(dial(), "not json\n")
	expectClosed(dial(), `{"t":"rates","rates":{}}`+"\n")                     // before hello
	expectClosed(dial(), `{"t":"hello","node":"b","ver":99}`+"\n")            // wrong version
	expectClosed(dial(), `{"t":"hello","node":"b","ver":1}{"t":"nope"}`+"\n") // unknown type after hello on one line is bad json
	// An unknown type after hello is skipped and counted so that a newer
	// peer's messages do not tear the channel down.
	c := dial()
	if _, err := c.Write([]byte(`{"t":"hello","node":"b","ver":1}` + "\n" + `{"t":"bogus"}` + "\n" + `{"t":"ping"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "ignored message counted", func() bool { return a.node.Status().Ignored == 1 })
	if _, err := c.Write([]byte(`{"t":"ping"}` + "\n")); err != nil {
		t.Fatalf("connection closed after an unknown type: %v", err)
	}
	c.Close()
	// Oversized line.
	c = dial()
	big := make([]byte, MaxMessageBytes+10)
	for i := range big {
		big[i] = 'a'
	}
	expectClosed(c, string(big)+"\n")
	// Valid session with rates and bans is accepted and applied.
	c = dial()
	msgs := `{"t":"hello","node":"b","ver":1}` + "\n" +
		`{"t":"rates","interval_ms":1000,"rates":{"p":{"k":5}}}` + "\n" +
		`{"t":"bans","bans":[{"target":"203.0.113.77","until":"2999-01-01T00:00:00Z","reason":"x"}],"removed":["203.0.113.78"]}` + "\n"
	if _, err := c.Write([]byte(msgs)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "applied", func() bool {
		return len(a.rates.got()) == 1 && a.bans.Banned(netip.MustParseAddr("203.0.113.77"))
	})
	c.Close()
}

func TestExactTake(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	certA, keyA := ca.Issue(t, dir, "n1")
	certB, keyB := ca.Issue(t, dir, "n2")
	cfgA := clusterCfg("n1", certA, keyA, ca.Path, nil)
	cfgA.ExactTimeout = config.Duration(300 * time.Millisecond)
	a := startNode(t, cfgA)
	cfgB := clusterCfg("n2", certB, keyB, ca.Path, []string{a.addr})
	cfgB.ExactTimeout = config.Duration(300 * time.Millisecond)
	b := startNode(t, cfgB)
	cfgA2 := clusterCfg("n1", certA, keyA, ca.Path, []string{b.addr})
	cfgA2.ExactTimeout = config.Duration(300 * time.Millisecond)
	a.node.Reconfigure(cfgA2)
	// Both learn the other's id from the hello answer.
	waitFor(t, "membership", func() bool {
		return len(a.node.Members()) == 2 && len(b.node.Members()) == 2
	})
	if a.node.Owner("k") != b.node.Owner("k") {
		t.Fatalf("owners disagree: %s vs %s", a.node.Owner("k"), b.node.Owner("k"))
	}
	// Find keys owned by each side, and a "deny" key owned by B.
	var ownedByB, ownedByA, denyKey string
	for i := 0; ownedByA == "" || ownedByB == "" || denyKey == ""; i++ {
		k := "key" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		if a.node.Owner(k) == "n2" {
			ownedByB = k
		} else {
			ownedByA = k
		}
		if d := "deny" + k; a.node.Owner(d) == "n2" {
			denyKey = d
		}
	}
	// A asks B for B's key: B's rate source decides.
	allowed, decided := a.node.Take("exact", ownedByB, 1)
	if !decided || !allowed {
		t.Fatalf("take %s: allowed=%v decided=%v", ownedByB, allowed, decided)
	}
	b.rates.mu.Lock()
	served := append([]string(nil), b.rates.decided...)
	b.rates.mu.Unlock()
	if len(served) != 1 || served[0] != "exact/"+ownedByB {
		t.Fatalf("owner decided %v", served)
	}
	if allowed, decided := a.node.Take("exact", denyKey, 1); !decided || allowed {
		t.Fatalf("denied key: allowed=%v decided=%v", allowed, decided)
	}
	// A key owned locally is not asked.
	if _, decided := a.node.Take("exact", ownedByA, 1); decided {
		t.Fatal("locally owned key was asked of a peer")
	}
	// An unknown policy is undecided: the asker falls back.
	if _, decided := a.node.Take("nope", ownedByB, 1); decided {
		t.Fatal("unknown policy decided")
	}
	st := a.node.Status()
	if st.ExactAsked != 3 || st.ExactDecided != 2 || st.ExactFallbacks != 1 || len(st.Members) != 2 {
		t.Fatalf("status %+v", st)
	}
	if bs := b.node.Status(); bs.ExactServed != 3 {
		t.Fatalf("owner status %+v", bs)
	}
	// A stopped owner: the take times out into a local decision.
	b.node.Stop()
	waitFor(t, "peer gone", func() bool { return len(a.node.Members()) == 1 })
	if _, decided := a.node.Take("exact", ownedByB, 1); decided {
		t.Fatal("take decided without an owner")
	}
}
