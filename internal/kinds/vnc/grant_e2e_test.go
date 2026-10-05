package vnc_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/rfb"
)

// grantGateway is a VNC gateway that admits nothing without a live grant. It
// offers MS-Logon II because that is one of the two security types whose
// credential carries a name, and a grant names a person.
func grantGateway(t *testing.T, tg *target, extra string) (*proxy.Server, string) {
	t.Helper()
	return grantGatewayForEndpoints(t, "[{address: "+tg.addr()+"}]", extra)
}

func grantGatewayForEndpoints(t *testing.T, endpoints, extra string) (*proxy.Server, string) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "access.log")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desktops
      address: "127.0.0.1:0"
      kind: vnc
      vnc:
        upstream: screens
        require_grant: true
%s
logging: {access: {enabled: false}}
upstreams:
  - name: screens
    endpoints: %s
access:
  ledger: %s
`, extra, endpoints, ledger)
	s := proxytest.Start(t, yaml)
	return s, proxytest.Addr(t, s, "desktops")
}

// An endpoint grant is authority for that desktop only. The pool may offer a
// different desktop first, but the gateway must skip it rather than turning a
// valid grant into access to whichever endpoint the balancer selects.
func TestEndpointGrantPinsTheDesktop(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "gate.pw")
	write(t, pw, "gate-secret")
	other := startTarget(t, &target{desktop: "hmi-other"})
	authorized := startTarget(t, &target{desktop: "hmi-authorized"})
	endpoints := fmt.Sprintf("[{address: %s}, {address: %s}]", other.addr(), authorized.addr())
	s, addr := grantGatewayForEndpoints(t, endpoints,
		"        security_types: [mslogon2]\n        password_file: "+pw)
	grantFor(t, s, "LAB\\alice", authorized.addr(), time.Hour)

	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecMSLogon2})
	cl.msLogon("LAB\\alice", "gate-secret")
	if ok, why := cl.result(); !ok {
		t.Fatalf("refused: %s", why)
	}
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	si, err := rfb.ReadServerInit(cl.c)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if si.Name != "hmi-authorized" {
		t.Errorf("desktop %q, want hmi-authorized", si.Name)
	}
	if got := other.seen(); len(got) != 0 {
		t.Errorf("the ungranted desktop was reached: %q", got)
	}
}

func grantFor(t *testing.T, s *proxy.Server, subject, target string, window time.Duration) *access.Grant {
	t.Helper()
	g, err := s.Access().Request(access.Request{Subject: subject, Listener: "desktops", Target: target,
		Reason: "look at the HMI", By: "carol", Expires: time.Now().Add(window)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Access().Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	return g
}

// The password proves somebody knows the gateway's secret; the grant says
// whether this person may be at this desktop now. Without one the desktop is
// never dialled.
func TestWithoutAGrantTheDesktopIsNeverDialled(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{desktop: "hmi-1"})
	s, addr := grantGateway(t, tg, "        security_types: [mslogon2]\n        password_file: "+pw)

	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecMSLogon2})
	cl.msLogon("LAB\\alice", "gate-secret")
	if ok, _ := cl.result(); !ok {
		t.Fatal("the password itself was refused, so this proves nothing about grants")
	}
	// The refusal comes after ClientInit, which is the last thing the client
	// sends before the desktop would be dialled.
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().Refusals["vnc"]["no_grant"] == 1 })
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the desktop was reached with no grant: %q", got)
	}
}

// With a grant the session opens and the desktop's own name comes back, which
// is the proof that the target was reached.
func TestWithAGrantTheDesktopAnswers(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{desktop: "hmi-1"})
	s, addr := grantGateway(t, tg, "        security_types: [mslogon2]\n        password_file: "+pw)
	g := grantFor(t, s, "LAB\\alice", "screens", time.Hour)

	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecMSLogon2})
	cl.msLogon("LAB\\alice", "gate-secret")
	if ok, why := cl.result(); !ok {
		t.Fatalf("refused: %s", why)
	}
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	si, err := rfb.ReadServerInit(cl.c)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if si.Name != "hmi-1" {
		t.Errorf("desktop %q, want hmi-1", si.Name)
	}
	waitFor(t, "the use to be recorded", func() bool {
		v, ok := s.Access().Get(g.ID)
		return ok && v.Uses == 1
	})
}
