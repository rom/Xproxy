package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

// Every peer connection is mutually authenticated with the cluster's
// own authority. These are the options that decide who may join, and
// the accessors an operator reads afterwards.

func TestBuildTLS(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	certFile, keyFile := ca.Issue(t, dir, "node-a")
	caFile := filepath.Join(dir, "ca.pem")
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, cli, err := buildTLS(&config.ClusterTLS{CertFile: certFile, KeyFile: keyFile, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	// Both sides demand TLS 1.3, present the node's certificate, and
	// speak only the cluster protocol.
	for name, c := range map[string]*tls.Config{"server": srv, "client": cli} {
		if c.MinVersion != tls.VersionTLS13 {
			t.Errorf("%s minimum version %#x", name, c.MinVersion)
		}
		if len(c.Certificates) != 1 {
			t.Errorf("%s has %d certificates", name, len(c.Certificates))
		}
		if len(c.NextProtos) != 1 || c.NextProtos[0] != "xproxy-cluster/1" {
			t.Errorf("%s ALPN %v", name, c.NextProtos)
		}
		if c.InsecureSkipVerify {
			t.Errorf("%s skips verification", name)
		}
	}
	// The server demands a client certificate signed by the cluster CA.
	if srv.ClientAuth != tls.RequireAndVerifyClientCert || srv.ClientCAs == nil {
		t.Errorf("client authentication: %v", srv.ClientAuth)
	}
	if cli.RootCAs == nil {
		t.Error("the client does not pin the cluster authority")
	}
	// With no allowed_names every certificate the CA signed is accepted.
	if err := srv.VerifyConnection(tls.ConnectionState{}); err != nil {
		t.Errorf("an empty allow list refused a peer: %v", err)
	}

	// With allowed_names only those names pass, by common name or by a
	// subject alternative name, and a connection with no certificate is
	// refused rather than allowed through.
	srv, _, err = buildTLS(&config.ClusterTLS{CertFile: certFile, KeyFile: keyFile, CAFile: caFile, AllowedNames: []string{"node-a", "node-b"}})
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafOf(t, certFile)
	if err := srv.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Errorf("a listed peer was refused: %v", err)
	}
	other, _ := ca.Issue(t, dir, "node-z")
	if err := srv.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafOf(t, other)}}); err == nil {
		t.Error("a peer that is not in allowed_names was accepted")
	}
	if err := srv.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Error("a connection with no certificate was accepted")
	}

	// Files that are not what they claim.
	bad := map[string]config.ClusterTLS{
		"a certificate that is not there": {CertFile: filepath.Join(dir, "none.crt"), KeyFile: keyFile, CAFile: caFile},
		"a key that is not there":         {CertFile: certFile, KeyFile: filepath.Join(dir, "none.key"), CAFile: caFile},
		"a certificate that is not one":   {CertFile: notPEM, KeyFile: notPEM, CAFile: caFile},
		"a CA that is not there":          {CertFile: certFile, KeyFile: keyFile, CAFile: filepath.Join(dir, "none.pem")},
		"a CA with no certificates":       {CertFile: certFile, KeyFile: keyFile, CAFile: notPEM},
	}
	for name, cfg := range bad {
		if _, _, err := buildTLS(&cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestNodeAccessors covers the small surface the management view and
// the filters read.
func TestNodeAccessors(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	certFile, keyFile := ca.Issue(t, dir, "node-a")
	caFile := filepath.Join(dir, "ca.pem")
	n := startNode(t, clusterCfg("node-a", certFile, keyFile, caFile, nil))
	if n.node.ID() != "node-a" {
		t.Errorf("id %q", n.node.ID())
	}
	if n.node.Addr() == "" {
		t.Error("a started node has no address")
	}
	// A node that was never started has no address rather than panicking.
	idle, err := New(clusterCfg("node-idle", certFile, keyFile, caFile, nil), &fakeRates{}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if idle.Addr() != "" {
		t.Errorf("an unstarted node reports %q", idle.Addr())
	}
	if idle.ID() != "node-idle" {
		t.Errorf("id %q", idle.ID())
	}
	idle.Stop()

	// The event hook can be installed and removed; removing it means no
	// callback, not a nil dereference on the next event.
	got := make(chan Event, 4)
	n.node.OnEvent(func(e Event, _ string) { got <- e })
	n.node.OnEvent(nil)
	n.node.OnEvent(func(e Event, _ string) { got <- e })

	// Take with no peers decides nothing: the caller falls back to the
	// local limiter rather than failing open.
	allowed, decided := n.node.Take("policy", "key", 1)
	if decided {
		t.Errorf("a node with no peers decided: allowed=%v", allowed)
	}
	// A key this node owns is also decided locally.
	if _, decided := n.node.Take("policy", n.node.ID(), 1); decided {
		t.Error("a key this node owns was sent to a peer")
	}
}

// leafOf reads the leaf certificate of a PEM file.
func leafOf(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		t.Fatalf("%s is not PEM", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
