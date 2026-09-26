package vnc_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/rfb"
)

// authzGateway is a VNC gateway under the estate's authorisation policy. It
// offers MS-Logon II because that is a security type whose credential carries a
// name, and a rule about people needs one.
func authzGateway(t *testing.T, tg *target, extra, policy string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desktops
      address: "127.0.0.1:0"
      kind: vnc
      vnc:
        upstream: screens
%s
logging: {access: {enabled: false}}
upstreams:
  - name: screens
    endpoints: [{address: %s}]
authorization:
%s
`, extra, tg.addr(), policy))
	return s, proxytest.Addr(t, s, "desktops")
}

// The password proves somebody knows the gateway's secret; the policy says
// whether this person may be at this desktop at all. A person no rule covers
// never reaches the desktop.
func TestAPolicyRefusesBeforeTheDesktopIsDialled(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{desktop: "hmi-1"})
	s, addr := authzGateway(t, tg, "        security_types: [mslogon2]\n        password_file: "+pw,
		`  rules:
    - {name: engineers, allow: true, users: ["LAB\\bob"]}
`)

	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecMSLogon2})
	cl.msLogon("LAB\\alice", "gate-secret")
	if ok, _ := cl.result(); !ok {
		t.Fatal("the password itself was refused, so this proves nothing about the policy")
	}
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().Refusals["vnc"]["authorization"] == 1 })
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the desktop was reached by somebody no rule covers: %q", got)
	}
}

// And the desktop's own name comes back for the person a rule does name, which
// is the proof the target was reached.
func TestAPolicyAdmitsThePersonItNamesOnVNC(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{desktop: "hmi-1"})
	_, addr := authzGateway(t, tg, "        security_types: [mslogon2]\n        password_file: "+pw,
		`  rules:
    - {name: engineers, allow: true, users: ["LAB\\alice"], targets: [screens]}
`)

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
}
