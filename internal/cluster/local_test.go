package cluster

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/config"
)

// localCfg is a Unix socket cluster node: no certificate anywhere.
func localCfg(id, socket string, peers []string, uids ...int) *config.Cluster {
	c := &config.Cluster{
		NodeID: id, Listen: config.UnixSocketPrefix + socket, Peers: peers,
		GossipInterval: config.Duration(100 * time.Millisecond),
		PeerStale:      config.Duration(time.Second), MaxKeysPerReport: 100,
	}
	if len(uids) > 0 {
		c.Local = &config.ClusterLocal{AllowUIDs: uids}
	}
	return c
}

func startLocal(t *testing.T, cfg *config.Cluster) *testNode {
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
	path, _ := config.UnixSocket(cfg.Listen)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	n.Start(ln)
	t.Cleanup(func() { n.Stop(); bl.Close() })
	return &testNode{node: n, rates: rates, bans: bl, addr: cfg.Listen}
}

// TestLocalClusterSharesBans is what the split needs from the cluster: a
// client the gate bans is banned at the edge, between daemons on one
// machine, with no certificate to issue and none to rotate.
func TestLocalClusterSharesBans(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.sock")
	b := filepath.Join(dir, "b.sock")
	na := startLocal(t, localCfg("xgate", a, []string{config.UnixSocketPrefix + b}))
	nb := startLocal(t, localCfg("xproxy", b, []string{config.UnixSocketPrefix + a}))

	waitFor(t, "peers connected", func() bool {
		return na.node.ConnectedPeers() == 1 && nb.node.ConnectedPeers() == 1
	})

	if _, err := na.bans.Ban("198.51.100.9", time.Hour, "ssh_denied"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the ban to reach the other daemon", func() bool {
		return nb.bans.Banned(netip.MustParseAddr("198.51.100.9"))
	})

	// The peer is named by the kernel, not by what it announced: the
	// status carries the uid the connection was made from.
	st := nb.node.Status()
	if !st.Local {
		t.Error("status does not say the cluster is local")
	}
	if len(st.Inbound) == 0 {
		t.Fatal("no inbound connection in the status")
	}
	in := st.Inbound[0]
	if in.UID == nil || *in.UID != os.Getuid() {
		t.Errorf("uid = %v, want %d", in.UID, os.Getuid())
	}
	if in.CertName != "" {
		t.Errorf("a local peer reported a certificate name %q", in.CertName)
	}
	if !strings.HasPrefix(in.Remote, "unix:uid=") {
		t.Errorf("remote = %q", in.Remote)
	}
}

// TestLocalClusterRefusesUnlistedUID: allow_uids is read from the
// socket, so a peer cannot talk its way past it. The test asks for a uid
// this process does not have, which is every connection it will see.
func TestLocalClusterRefusesUnlistedUID(t *testing.T) {
	if !peerCredAvailable {
		t.Skip("peer credentials are not available on this platform")
	}
	dir := t.TempDir()
	a := filepath.Join(dir, "a.sock")
	b := filepath.Join(dir, "b.sock")
	// The listener allows only a uid nobody here has.
	other := os.Getuid() + 1000
	nb := startLocal(t, localCfg("xproxy", b, nil, other))
	na := startLocal(t, localCfg("xgate", a, []string{config.UnixSocketPrefix + b}))

	waitFor(t, "the connection to be refused", func() bool {
		return nb.node.Status().Rejected > 0
	})
	if _, err := na.bans.Ban("198.51.100.10", time.Hour, "ssh_denied"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if nb.bans.Banned(netip.MustParseAddr("198.51.100.10")) {
		t.Fatal("a refused peer's ban was applied")
	}
	if len(nb.node.Status().Inbound) != 0 {
		t.Fatal("a refused peer is in the inbound list")
	}
}

// TestLocalClusterNeedsNoTLS: a node whose addresses are sockets builds
// without a certificate, which is the whole point of it.
func TestLocalClusterNeedsNoTLS(t *testing.T) {
	cfg := localCfg("xrelay", "/tmp/unused.sock", nil)
	if _, err := New(cfg, &fakeRates{}, nolog); err != nil {
		t.Fatalf("a local node wanted a certificate: %v", err)
	}
	// And one that asks for a uid check on a platform that cannot make
	// it is refused at start rather than admitting everything.
	cfg.Local = &config.ClusterLocal{AllowUIDs: []int{1}}
	_, err := New(cfg, &fakeRates{}, nolog)
	if peerCredAvailable && err != nil {
		t.Fatalf("allow_uids was refused where it is supported: %v", err)
	}
	if !peerCredAvailable && err == nil {
		t.Fatal("allow_uids was accepted where peer credentials are unavailable")
	}
}
