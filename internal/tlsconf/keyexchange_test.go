package tlsconf

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

// handshake runs one real TLS handshake against a server built from cfg
// and returns the client's view of it.
func handshake(t *testing.T, cfg *config.TLS, clientGroups []tls.CurveID) tls.ConnectionState {
	t.Helper()
	tc, _, err := Server(cfg, []config.Protocol{config.ProtocolH1})
	if err != nil {
		t.Fatalf("server config: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.(*tls.Conn).Handshake()
		_ = c.Close()
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // a self-signed certificate written by the test
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   clientGroups,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	st := conn.ConnectionState()
	_ = conn.Close()
	<-done
	return st
}

func serverCfg(t *testing.T, groups ...string) *config.TLS {
	t.Helper()
	dir := t.TempDir()
	c, k := testutil.WriteCert(t, dir, "a.test")
	return &config.TLS{Certificates: []config.Certificate{{CertFile: c, KeyFile: k}},
		MinVersion: "1.3", ClientAuth: "none", KeyExchange: groups}
}

// TestDefaultIsPostQuantum is the point of the whole feature. Go offers
// the hybrid on its own, but only while CurvePreferences is unset, and
// this package sets it — so the default list has to carry the hybrid
// itself or the proxy silently stops offering post-quantum security.
func TestDefaultIsPostQuantum(t *testing.T) {
	st := handshake(t, serverCfg(t), nil)
	if st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated %s, want X25519MLKEM768", config.GroupName(st.CurveID))
	}
	if !config.IsPostQuantum(st.CurveID) {
		t.Fatal("the default handshake is not post-quantum")
	}
}

// TestClassicalClientStillConnects: the hybrid is an addition, not a
// requirement. A client that cannot do it negotiates a classical group.
func TestClassicalClientStillConnects(t *testing.T) {
	st := handshake(t, serverCfg(t), []tls.CurveID{tls.X25519, tls.CurveP256})
	if st.CurveID != tls.X25519 {
		t.Fatalf("negotiated %s, want X25519", config.GroupName(st.CurveID))
	}
	if config.IsPostQuantum(st.CurveID) {
		t.Fatal("a classical-only client reported as post-quantum")
	}
}

// TestConfiguredListIsTheAcceptedSet: naming groups replaces the whole
// list, which is what makes the knob a knob — and the trap it exists to
// make visible. Note what the list is: the set the server will accept.
// In TLS 1.3 the client sends a key share, and the server takes the
// first offered share it accepts rather than forcing its own favourite
// with a retry, so a server that accepts several groups usually ends up
// on the client's first choice.
func TestConfiguredListIsTheAcceptedSet(t *testing.T) {
	// One group only, so the answer cannot depend on the client: a
	// client with no P-256 key share is sent a retry and comes back
	// with one.
	st := handshake(t, serverCfg(t, "P-256"), nil)
	if st.CurveID != tls.CurveP256 {
		t.Fatalf("negotiated %s, want P-256", config.GroupName(st.CurveID))
	}
	// With both offered, the client's own preference decides, and the
	// handshake still completes.
	st = handshake(t, serverCfg(t, "P-256", "X25519"), []tls.CurveID{tls.X25519})
	if st.CurveID != tls.X25519 {
		t.Fatalf("negotiated %s, want the client's X25519", config.GroupName(st.CurveID))
	}
	// And a client that offers only what the server does not.
	cfg := serverCfg(t, "P-384")
	tc, _, err := Server(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.CurvePreferences) != 1 || tc.CurvePreferences[0] != tls.CurveP384 {
		t.Fatalf("CurvePreferences = %v", tc.CurvePreferences)
	}
}

func TestUnknownGroupIsRefused(t *testing.T) {
	cfg := serverCfg(t, "X25519", "Curve25519")
	if _, _, err := Server(cfg, nil); err == nil {
		t.Fatal("unknown group accepted")
	}
	if _, _, err := Client(&config.UpstreamTLS{MinVersion: "1.2", KeyExchange: []string{"kyber"}}); err == nil {
		t.Fatal("unknown upstream group accepted")
	}
}

// TestUpstreamDefaultsToHybrid: traffic from the proxy to the origin is
// recorded by the same adversary as traffic to the proxy.
func TestUpstreamDefaultsToHybrid(t *testing.T) {
	tc, _, err := Client(&config.UpstreamTLS{MinVersion: "1.3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.CurvePreferences) == 0 || tc.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("upstream groups = %v", tc.CurvePreferences)
	}
	tc, _, err = Client(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.CurvePreferences) == 0 || tc.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("upstream groups without a tls section = %v", tc.CurvePreferences)
	}
}

func TestGroupNames(t *testing.T) {
	for name, want := range map[string]tls.CurveID{
		"X25519MLKEM768": tls.X25519MLKEM768, "X25519": tls.X25519,
		"P-256": tls.CurveP256, "P-384": tls.CurveP384, "P-521": tls.CurveP521,
	} {
		got, ok := config.KeyExchangeID(name)
		if !ok || got != want {
			t.Errorf("KeyExchangeID(%q) = %v, %v", name, got, ok)
		}
		if n := config.GroupName(want); n != name {
			t.Errorf("GroupName(%v) = %q, want %q", want, n, name)
		}
	}
	// A group this build does not know is still identifiable in a log.
	if n := config.GroupName(tls.CurveID(0x1234)); n != "group-4660" {
		t.Errorf("unknown group name = %q", n)
	}
	if n := config.GroupName(0); n != "" {
		t.Errorf("zero group name = %q", n)
	}
	if !config.HasPostQuantum([]string{"X25519", "X25519MLKEM768"}) ||
		config.HasPostQuantum([]string{"X25519", "P-256"}) {
		t.Error("HasPostQuantum")
	}
	// The listener addresses the handshake test opened are gone by now;
	// this is only here to keep net imported for the helper above.
	var _ net.Addr
}
