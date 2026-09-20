package proxy

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
)

const clusterYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
rate_limits:
  - {name: shared, rate: 10, burst: 10}
bans: {action: reject}
cluster:
  node_id: %s
  listen: "127.0.0.1:0"
  peers: [%s]
  gossip_interval: 100ms
  peer_stale: 2s
  tls: {cert_file: %s, key_file: %s, ca_file: %s}
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: wp
    paths: [/wp-login.php]
    honeypot: {decoy: wp-login, mark: 1h}
  - name: r
    rate_limits: [shared]
    upstream: a
`

func TestClusterSharesLimitsAndBans(t *testing.T) {
	backend := newBackend(t, "a")
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	ac, ak := ca.Issue(t, dir, "node-a")
	bc, bk := ca.Issue(t, dir, "node-b")

	a, urlA := startServer(t, fmt.Sprintf(clusterYAML, "a", "", ac, ak, ca.Path, backend.addr()))
	b, urlB := startServer(t, fmt.Sprintf(clusterYAML, "b", "", bc, bk, ca.Path, backend.addr()))
	if a.Cluster() == nil || b.Cluster() == nil {
		t.Fatal("cluster not created")
	}
	// Peers learn each other's addresses through a reload.
	if err := a.Reload(mustParse(t, fmt.Sprintf(clusterYAML, "a", `"`+b.Cluster().Addr()+`"`, ac, ak, ca.Path, backend.addr()))); err != nil {
		t.Fatal(err)
	}
	if err := b.Reload(mustParse(t, fmt.Sprintf(clusterYAML, "b", `"`+a.Cluster().Addr()+`"`, bc, bk, ca.Path, backend.addr()))); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (a.Cluster().ConnectedPeers() != 1 || b.Cluster().ConnectedPeers() != 1) {
		time.Sleep(20 * time.Millisecond)
	}
	if st := a.Stats(); st.ClusterPeers != 1 || st.ClusterConnected != 1 {
		t.Fatalf("cluster stats %+v", st)
	}

	// Client X exhausts its burst on A. B learns that X is consuming the
	// full rate and stops refilling X's bucket, so after B's own burst X is
	// denied on B where a lone node would have refilled.
	client := "198.51.100.5"
	for i := 0; i < 10; i++ {
		if resp, _ := getAs(t, urlA+"/", "x", client); resp.StatusCode != 200 {
			t.Fatalf("A request %d: %d", i, resp.StatusCode)
		}
	}
	time.Sleep(400 * time.Millisecond) // several gossip intervals
	for i := 0; i < 10; i++ {
		if resp, _ := getAs(t, urlB+"/", "x", client); resp.StatusCode != 200 {
			t.Fatalf("B burst %d: %d", i, resp.StatusCode)
		}
	}
	time.Sleep(600 * time.Millisecond) // a lone node would refill 6 tokens here
	if resp, _ := getAs(t, urlB+"/", "x", client); resp.StatusCode != 429 {
		t.Fatalf("B should hold X's bucket at zero while A reports consumption, got %d", resp.StatusCode)
	}
	// A different client is unaffected on B.
	if resp, _ := getAs(t, urlB+"/", "x", "198.51.100.6"); resp.StatusCode != 200 {
		t.Fatalf("other client on B: %d", resp.StatusCode)
	}
	// After the reports go stale, X refills again on B.
	time.Sleep(2500 * time.Millisecond)
	if resp, _ := getAs(t, urlB+"/", "x", client); resp.StatusCode != 200 {
		t.Fatalf("B did not recover after peer reports went stale: %d", resp.StatusCode)
	}

	// Bans propagate.
	if _, err := a.Bans().Ban("203.0.113.99", time.Hour, "shared"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !b.Bans().Banned(mustAddr("203.0.113.99")) {
		time.Sleep(20 * time.Millisecond)
	}
	if resp, _ := getAs(t, urlB+"/", "x", "203.0.113.99"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ban did not reach B: %d", resp.StatusCode)
	}

	// Honeypot marks propagate, and so does forgetting one.
	if resp, _ := getAs(t, urlA+"/wp-login.php", "x", "203.0.113.50"); resp.StatusCode != 200 {
		t.Fatalf("decoy: %d", resp.StatusCode)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !b.marks.marked(mustAddr("203.0.113.50"), time.Now()) {
		time.Sleep(20 * time.Millisecond)
	}
	marksB := b.HoneypotMarks()
	if len(marksB) != 1 || marksB[0].Address != "203.0.113.50" || marksB[0].Route != "peer:node-a/wp" || time.Until(marksB[0].Expires) < 50*time.Minute {
		t.Fatalf("mark did not reach B: %+v", marksB)
	}
	if !a.UnmarkHoneypot(mustAddr("203.0.113.50")) {
		t.Fatal("unmark on A")
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && b.marks.marked(mustAddr("203.0.113.50"), time.Now()) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(b.HoneypotMarks()) != 0 {
		t.Fatalf("unmark did not reach B: %+v", b.HoneypotMarks())
	}

	// Cluster listen changes are refused on reload.
	bad := mustParse(t, fmt.Sprintf(clusterYAML, "a", "", ac, ak, ca.Path, backend.addr()))
	bad.Cluster.Listen = "127.0.0.1:1"
	if err := a.Reload(bad); err == nil {
		t.Fatal("cluster listen change accepted on reload")
	}
	if st := a.Cluster().Status(); st.BansSent < 1 || st.RatesSent < 1 || st.EventsSent < 2 {
		t.Fatalf("status %+v", st)
	}
}
