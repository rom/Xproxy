package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

var tlog = slog.New(slog.NewTextHandler(io.Discard, nil))

func ticketsAt(t *testing.T, file string, now time.Time, rotate time.Duration) *Tickets {
	t.Helper()
	tk, err := NewTickets(&config.SessionTickets{SecretFile: file, Rotate: config.Duration(rotate)}, tlog)
	if err != nil {
		t.Fatal(err)
	}
	tk.now = func() time.Time { return now }
	tk.mu.Lock()
	tk.derive(tk.currentEpoch())
	tk.mu.Unlock()
	return tk
}

// serve runs one TLS accept with the given config and reports whether the
// session resumed.
func serve(t *testing.T, tc *tls.Config) (addr string, resumed chan bool, stop func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tc)
	if err != nil {
		t.Fatal(err)
	}
	resumed = make(chan bool, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					resumed <- false
					return
				}
				resumed <- tc.ConnectionState().DidResume
				_, _ = io.WriteString(c, "ok")
			}()
		}
	}()
	return ln.Addr().String(), resumed, func() { _ = ln.Close() }
}

func TestTicketsResumeAcrossNodes(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testutil.WriteCert(t, dir, "tickets.test")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := os.ReadFile(certFile)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	secretFile := filepath.Join(dir, "tickets.keyring")
	now := time.Unix(1_700_000_000, 0)
	rotate := time.Hour

	// Two "nodes" with the same master secret at the same time.
	nodeA := ticketsAt(t, secretFile, now, rotate)
	nodeB := ticketsAt(t, secretFile, now, rotate)
	if nodeA.Fingerprint() != nodeB.Fingerprint() || nodeA.Fingerprint() == "" {
		t.Fatalf("fingerprints differ: %s %s", nodeA.Fingerprint(), nodeB.Fingerprint())
	}
	if st := nodeA.Status(); st.Keys != 2 || st.MasterKeys != 1 || st.Epoch != now.UnixNano()/int64(rotate) {
		t.Fatalf("status %+v", st)
	}
	tcA := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	tcB := tcA.Clone()
	nodeA.Attach(tcA)
	nodeB.Attach(tcB)
	addrA, resA, stopA := serve(t, tcA)
	defer stopA()
	addrB, resB, stopB := serve(t, tcB)
	defer stopB()

	client := &tls.Config{RootCAs: roots, ServerName: "tickets.test", ClientSessionCache: tls.NewLRUClientSessionCache(8), MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	dial := func(addr string, res chan bool) bool {
		t.Helper()
		c, err := tls.Dial("tcp", addr, client)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(c)
		_ = c.Close()
		return <-res
	}
	if dial(addrA, resA) {
		t.Fatal("first handshake resumed")
	}
	if !dial(addrA, resA) {
		t.Fatal("second handshake to the same node did not resume")
	}
	if !dial(addrB, resB) {
		t.Fatal("ticket from node A did not resume on node B with the same master secret")
	}

	// A second client keeps a ticket from the first epoch, untouched by the
	// rotations below (a resumed handshake refreshes the ticket under the
	// current key, so the first client's ticket follows the rotations).
	client2 := client.Clone()
	client2.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	c2, err := tls.Dial("tcp", addrA, client2)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(c2)
	_ = c2.Close()
	<-resA

	// Node B moves into the next epoch: the previous epoch's key is kept,
	// so the ticket still resumes.
	nodeB.now = func() time.Time { return now.Add(rotate) }
	nodeB.Tick()
	if st := nodeB.Status(); st.Rotations != 1 || st.Epoch != nodeA.Status().Epoch+1 {
		t.Fatalf("rotation %+v", st)
	}
	if !dial(addrB, resB) {
		t.Fatal("previous epoch ticket refused after one rotation")
	}
	// Two epochs later the first epoch's ticket is gone.
	nodeA.now = func() time.Time { return now.Add(2 * rotate) }
	nodeA.Tick()
	cA, _ := tls.Dial("tcp", addrA, client2)
	_, _ = io.ReadAll(cA)
	_ = cA.Close()
	if <-resA {
		t.Fatal("ticket two epochs old resumed")
	}

	// Peer fingerprints: agreement and mismatch are recorded.
	if !nodeA.PeerFingerprint("n2", nodeA.Fingerprint()) || nodeA.PeerFingerprint("n3", "deadbeef") {
		t.Fatal("peer fingerprint comparison")
	}
	if st := nodeA.Status(); len(st.MismatchedPeers) != 1 || st.MismatchedPeers[0] != "n3" || st.Peers["n2"] != st.Fingerprint {
		t.Fatalf("peer status %+v", st)
	}
	// A rotation notifies.
	var got string
	nodeA.OnRotate = func(fp string) { got = fp }
	nodeA.now = func() time.Time { return now.Add(3 * rotate) }
	nodeA.Tick()
	if got == "" || got != nodeA.Fingerprint() {
		t.Fatalf("rotation callback %q", got)
	}
	// Start and Stop are idempotent.
	nodeA.Start()
	nodeA.Start()
	nodeA.Stop()
	nodeA.Stop()
	var none *Tickets
	none.Attach(nil)
	none.Tick()
	if none.Status() != nil || none.Fingerprint() != "" || !none.PeerFingerprint("x", "y") {
		t.Fatal("nil tickets")
	}
	_ = net.IPv4zero
}
