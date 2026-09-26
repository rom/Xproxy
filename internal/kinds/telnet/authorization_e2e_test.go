package telnet_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// authzGateway is a telnet gateway under the estate's authorisation policy. The
// factor prompt is what gives the policy a name to decide about: telnet carries
// no identity of its own, so a listener with no factor has nothing for a rule
// about people to match.
func authzGateway(t *testing.T, mfaFile, policy string) (*proxy.Server, string, *targetTelnet) {
	t.Helper()
	tg := startTarget(t)
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        upstream: kit
        mfa: {file: %s}
logging: {access: {enabled: false}}
upstreams:
  - name: kit
    endpoints: [{address: %s}]
authorization:
%s
`, mfaFile, tg.addr(), policy))
	return s, s.Addrs()["legacy"], tg
}

// A policy that does not cover the person refuses before the equipment is
// dialled -- which on a telnet device matters more than anywhere else, because
// the equipment has no authentication worth the name behind this gateway.
func TestAPolicyRefusesBeforeTheEquipmentIsDialled(t *testing.T) {
	file, secret := enrol(t, "alice")
	s, addr, tg := authzGateway(t, file, `  rules:
    - {name: field-engineers, allow: true, users: [bob]}
`)

	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	c.readUntil("code: ")
	c.write([]byte(totp(t, secret) + "\r\n"))
	if out := c.readUntil("not authorised"); !strings.Contains(out, "not authorised") {
		t.Errorf("the refusal did not say why: %q", out)
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the equipment was reached by somebody no rule covers: %q", got)
	}
	if n := s.Stats().Refusals["telnet"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["telnet"])
	}
}

// And a rule that does cover them admits: the policy is a decision, not a wall.
func TestAPolicyAdmitsThePersonItNames(t *testing.T) {
	file, secret := enrol(t, "alice")
	_, addr, tg := authzGateway(t, file, `  rules:
    - {name: operators, allow: true, users: [alice], actions: [connect]}
`)

	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	c.readUntil("code: ")
	c.write([]byte(totp(t, secret) + "\r\n"))
	if out := c.readUntil("target ready"); !strings.Contains(out, "target ready") {
		t.Errorf("a session the policy allows did not open: %q", out)
	}
	if !tg.waitSeen(t, []byte{}) {
		t.Error("the equipment saw nothing")
	}
}

// A shadowed policy records and admits, which is how an estate reads a policy
// against the traffic a plant actually carries before it decides anything.
func TestAShadowedPolicyRecordsAndAdmitsOnTelnet(t *testing.T) {
	file, secret := enrol(t, "alice")
	s, addr, tg := authzGateway(t, file, `  shadow: true
  rules:
    - {name: field-engineers, allow: true, users: [bob]}
`)

	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	c.readUntil("code: ")
	c.write([]byte(totp(t, secret) + "\r\n"))
	if out := c.readUntil("target ready"); !strings.Contains(out, "target ready") {
		t.Errorf("a shadowed policy refused a session: %q", out)
	}
	if !tg.waitSeen(t, []byte{}) {
		t.Error("the equipment saw nothing, so the session was not really admitted")
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "telnet" && e.Reason == "authorization" {
			found = true
			if !strings.Contains(e.Sample, "alice") {
				t.Errorf("shadow entry sample %q, want the subject in it", e.Sample)
			}
		}
	}
	if !found {
		t.Errorf("no shadow entry for the refusal: %+v", s.Shadow().Report())
	}
	if n := s.Stats().Refusals["telnet"]["authorization"]; n != 0 {
		t.Errorf("a shadowed refusal was counted as a refusal: %d", n)
	}
}
