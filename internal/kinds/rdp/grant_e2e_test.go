package rdp_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/rdp"
)

// grantGateway is an RDP gateway that admits nothing without a live grant.
func grantGateway(t *testing.T, d *desktop, extra string) (*proxy.Server, string, string) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "access.log")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desks
      address: "127.0.0.1:0"
      kind: rdp
      rdp:
        upstream: farm
        require_grant: true
%s
logging: {access: {enabled: false}}
upstreams:
  - name: farm
    endpoints: [{address: %s}]
access:
  ledger: %s
`, extra, d.addr(), ledger)
	s := proxytest.Start(t, yaml)
	return s, proxytest.Addr(t, s, "desks"), ledger
}

func grantFor(t *testing.T, s *proxy.Server, subject, target string, window time.Duration) *access.Grant {
	t.Helper()
	g, err := s.Access().Request(access.Request{Subject: subject, Listener: "desks", Target: target,
		Reason: "patch the app server", By: "carol", Expires: time.Now().Add(window)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Access().Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	return g
}

// RDP carries the person in one packet, once, and that packet arrives after the
// desktop has been dialled -- so this gateway cannot refuse before the target is
// reached. What it can do, and does, is refuse before the credential goes any
// further: the desktop sees a connection and never the person's name or
// password.
func TestWithoutAGrantTheCredentialNeverReachesTheDesktop(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr, _ := grantGateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")

	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("LAB", "alice", "her-password")
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().Refusals["rdp"]["no_grant"] == 1 })
	if info := d.credential(); info != nil {
		t.Errorf("the credential reached the desktop as %q", info.Username)
	}
}

// With a grant somebody else approved, the credential goes through and the use
// is recorded against the grant.
func TestWithAGrantTheDesktopOpens(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr, _ := grantGateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	g := grantFor(t, s, "alice", "farm", time.Hour)

	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("LAB", "alice", "her-password")
	waitFor(t, "the credential to arrive", func() bool { return d.credential() != nil })
	waitFor(t, "the use to be recorded", func() bool {
		v, ok := s.Access().Get(g.ID)
		return ok && v.Uses == 1
	})
}

// A grant for another machine is refused rather than moved: the desktop this
// session reached is the only one it can be about, because the credential
// arrives after the dial.
func TestAGrantForAnotherDesktopIsRefused(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr, _ := grantGateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	grantFor(t, s, "alice", "10.255.255.1:3389", time.Hour)

	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("LAB", "alice", "her-password")
	waitFor(t, "the refusal to name the target", func() bool {
		return s.Stats().Refusals["rdp"]["grant_wrong_target"] == 1
	})
	if info := d.credential(); info != nil {
		t.Errorf("the credential reached a desktop the grant did not name: %q", info.Username)
	}
}
